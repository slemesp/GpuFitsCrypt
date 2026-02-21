/*
 * ghash_kernel.cu – Parallel GHASH via tree reduction on GPU.
 *
 * Background
 * ----------
 * The standard GHASH recurrence is inherently sequential:
 *
 *     Y_i = (Y_{i-1} XOR X_i) * H,   Y_0 = 0
 *
 * Expanding the recurrence over m blocks yields the equivalent dot product:
 *
 *     GHASH_H(X_1, …, X_m) = X_1*H^m  XOR  X_2*H^(m-1)  XOR  …  XOR  X_m*H^1
 *
 * This form allows all m field multiplications to be computed independently
 * (Phase 2 below), collapsing the O(m) sequential dependency chain into
 * O(log m) parallel reduction steps.
 *
 * GPU Parallelisation Strategy
 * ----------------------------
 * Phase 1 – Power precomputation
 *     A single warp computes H^1, H^2, …, H^m using a parallel prefix
 *     product with log2(m) rounds of __shfl_sync, storing results in
 *     device memory `d_h_powers`.
 *
 * Phase 2 – Independent partial products  (one thread per input block)
 *     thread_i  computes  partial[i] = X_i * H^(m - i)
 *     The m threads are scheduled in a 1-D grid with BLOCK_SIZE threads
 *     per CUDA block.  Threads within a block load their X_i and H^k
 *     from global memory and call gf128_mul_device().
 *
 * Phase 3 – XOR tree reduction  (warp-level then inter-block)
 *     Each CUDA block reduces its BLOCK_SIZE partial products to a single
 *     128-bit value using shared-memory XOR in log2(BLOCK_SIZE) rounds,
 *     synchronised with __syncthreads().  A second kernel pass reduces
 *     the per-block results until a single 128-bit output remains.
 *
 * GF(2^128) Representation
 * ------------------------
 * Each field element is stored as two 64-bit unsigned integers (hi, lo),
 * where bit 63 of `hi` is the coefficient of x^0 (MSB-first, matching
 * the GCM specification in NIST SP 800-38D).
 *
 * Compilation
 * -----------
 *     nvcc -O3 -arch=sm_80 -c ghash_kernel.cu -o ghash_kernel.o
 */

#include <stdint.h>
#include <cuda_runtime.h>

#define BLOCK_SIZE 256

/* GF(2^128) element: hi = bits 127..64, lo = bits 63..0 (MSB = x^0 coeff). */
typedef struct { uint64_t hi; uint64_t lo; } gf128_t;

/* Reduction polynomial R for GCM: 0xE1000000000000000000000000000000 */
__device__ __constant__ gf128_t GCM_R = { 0xE100000000000000ULL, 0x0000000000000000ULL };

/* -------------------------------------------------------------------------
 * Device: multiply two GF(2^128) elements.
 * Algorithm from NIST SP 800-38D, Section 6.3.
 * ------------------------------------------------------------------------- */
__device__ gf128_t gf128_mul_device(gf128_t x, gf128_t y)
{
    gf128_t z = {0, 0};
    gf128_t v = x;

    for (int i = 0; i < 128; ++i) {
        /* Test bit (127 - i) of y: start from MSB. */
        int bit_idx = 127 - i;
        uint64_t y_bit = (bit_idx >= 64)
            ? ((y.hi >> (bit_idx - 64)) & 1ULL)
            : ((y.lo >> bit_idx) & 1ULL);

        if (y_bit) {
            z.hi ^= v.hi;
            z.lo ^= v.lo;
        }

        /* Multiply v by x (right-shift in MSB-first representation). */
        int lsb = (int)(v.lo & 1ULL);
        v.lo = (v.lo >> 1) | (v.hi << 63);
        v.hi >>= 1;
        if (lsb) {
            v.hi ^= GCM_R.hi;
            v.lo ^= GCM_R.lo;
        }
    }
    return z;
}

/* -------------------------------------------------------------------------
 * Device: XOR two GF(2^128) elements.
 * ------------------------------------------------------------------------- */
__device__ __forceinline__ gf128_t gf128_xor(gf128_t a, gf128_t b)
{
    return {a.hi ^ b.hi, a.lo ^ b.lo};
}

/* -------------------------------------------------------------------------
 * Phase 2 kernel: compute partial products in parallel.
 *
 * Each thread i computes  partial[i] = blocks[i] * h_powers[m - i].
 *
 * Grid:  ceil(m / BLOCK_SIZE) blocks × BLOCK_SIZE threads.
 * Input:
 *   d_blocks   – m input blocks (128-bit each).
 *   d_h_powers – precomputed H^1 … H^m (index 0 = H^1).
 *   m          – number of input blocks.
 * Output:
 *   d_partial  – m partial products.
 * ------------------------------------------------------------------------- */
__global__ void ghash_partial_products(
    const gf128_t * __restrict__ d_blocks,
    const gf128_t * __restrict__ d_h_powers,
    gf128_t       * __restrict__ d_partial,
    int m)
{
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= m) return;
    /* block[i] (0-indexed) is multiplied by H^(m - i). */
    d_partial[i] = gf128_mul_device(d_blocks[i], d_h_powers[m - 1 - i]);
}

/* -------------------------------------------------------------------------
 * Phase 3 kernel: parallel XOR tree reduction within a CUDA block.
 *
 * Reduces BLOCK_SIZE (or fewer) partial products to one value stored in
 * d_out[blockIdx.x].  A second kernel invocation reduces the per-block
 * outputs until a single result remains.
 *
 * Input:  d_in  – array of n elements.
 * Output: d_out – array of ceil(n / blockDim.x) elements.
 * ------------------------------------------------------------------------- */
__global__ void ghash_reduce(
    const gf128_t * __restrict__ d_in,
    gf128_t       * __restrict__ d_out,
    int n)
{
    __shared__ gf128_t sdata[BLOCK_SIZE];

    int tid = threadIdx.x;
    int idx = blockIdx.x * blockDim.x + tid;

    sdata[tid] = (idx < n) ? d_in[idx] : gf128_t{0, 0};
    __syncthreads();

    /* Binary tree XOR reduction over shared memory. */
    for (int stride = blockDim.x / 2; stride > 0; stride >>= 1) {
        if (tid < stride) {
            sdata[tid] = gf128_xor(sdata[tid], sdata[tid + stride]);
        }
        __syncthreads();
    }

    if (tid == 0) {
        d_out[blockIdx.x] = sdata[0];
    }
}

/* -------------------------------------------------------------------------
 * Host entry point: full parallel GHASH.
 *
 * Orchestrates Phases 2 and 3.  Phase 1 (power precomputation) is expected
 * to be performed before calling this function, with `d_h_powers` already
 * populated on-device.
 *
 * Parameters:
 *   d_blocks   – device pointer to m GHASH input blocks.
 *   d_h_powers – device pointer to H^1 … H^m (index 0 = H^1).
 *   m          – number of blocks.
 *   d_result   – device pointer to a single gf128_t output.
 * ------------------------------------------------------------------------- */
extern "C" void ghash_parallel_gpu(
    const gf128_t *d_blocks,
    const gf128_t *d_h_powers,
    int m,
    gf128_t *d_result)
{
    gf128_t *d_partial = nullptr;
    cudaMalloc(&d_partial, m * sizeof(gf128_t));

    /* Phase 2: independent partial products. */
    int grid2 = (m + BLOCK_SIZE - 1) / BLOCK_SIZE;
    ghash_partial_products<<<grid2, BLOCK_SIZE>>>(d_blocks, d_h_powers, d_partial, m);

    /* Phase 3: iterative XOR tree reduction. */
    gf128_t *d_in  = d_partial;
    gf128_t *d_tmp = nullptr;
    int n = m;

    while (n > 1) {
        int grid3 = (n + BLOCK_SIZE - 1) / BLOCK_SIZE;
        cudaMalloc(&d_tmp, grid3 * sizeof(gf128_t));
        ghash_reduce<<<grid3, BLOCK_SIZE>>>(d_in, d_tmp, n);
        if (d_in != d_partial) cudaFree(d_in);
        d_in = d_tmp;
        n    = grid3;
    }

    cudaMemcpy(d_result, d_in, sizeof(gf128_t), cudaMemcpyDeviceToDevice);
    if (d_in != d_partial) cudaFree(d_in);
    cudaFree(d_partial);
}
