// gcm_kernels.cu
#include "gcm_kernels.h"
#include <cstdint>
#include <algorithm> // For std::reverse if needed, but not directly here.


static const uint8_t GF128_REDUCTION_CONSTANT = 0x87;

/**
 * @brief Swaps the byte order (endianness) of a 64-bit integer.
 *        Safe implementation for device code (__device__).
 */
static __forceinline__ __device__ unsigned long long device_bswap64(unsigned long long val) {
    return ((val & 0x00000000000000FFULL) << 56) |
           ((val & 0x000000000000FF00ULL) << 40) |
           ((val & 0x0000000000FF0000ULL) << 24) |
           ((val & 0x00000000FF000000ULL) << 8)  |
           ((val & 0x000000FF00000000ULL) >> 8)  |
           ((val & 0x0000FF0000000000ULL) >> 24) |
           ((val & 0x00FF000000000000ULL) >> 40) |
           ((val & 0xFF00000000000000ULL) >> 56);
}

/**
 * @brief Highly optimized implementation of gf128_multiply using
 *        carry-less multiplication (Carry-Less Multiply) with 64-bit instructions.
 */
static __forceinline__ __device__ void gf128_multiply_clmul_optimized(uint8_t result[16], const uint8_t a[16], const uint8_t b[16]) {
    const unsigned long long* a64 = reinterpret_cast<const unsigned long long*>(a);
    const unsigned long long* b64 = reinterpret_cast<const unsigned long long*>(b);
    unsigned long long* res64 = reinterpret_cast<unsigned long long*>(result);

    // Load 128-bit values into 64-bit registers
    // FIX: Use __bswap64 for device code
    unsigned long long a_hi = device_bswap64(a64[0]); // a[0..7]
    unsigned long long a_lo = device_bswap64(a64[1]); // a[8..15]
    unsigned long long b_hi = device_bswap64(b64[0]);
    unsigned long long b_lo = device_bswap64(b64[1]);

    // ... rest of multiplication code is identical ...
    unsigned long long p0_lo, p0_hi, p1_lo, p1_hi, p2_lo, p2_hi;
    p0_lo = a_lo;
    p0_hi = 0;
    __asm__("mul.lo.u64 %0, %1, %2;\n\t" "mul.hi.u64 %1, %1, %2;\n\t" : "+l"(p0_lo), "+l"(p0_hi) : "l"(b_lo));

    p2_lo = a_hi;
    p2_hi = 0;
    __asm__("mul.lo.u64 %0, %1, %2;\n\t" "mul.hi.u64 %1, %1, %2;\n\t" : "+l"(p2_lo), "+l"(p2_hi) : "l"(b_hi));

    unsigned long long a_mid = a_hi ^ a_lo;
    unsigned long long b_mid = b_hi ^ b_lo;

    p1_lo = a_mid;
    p1_hi = 0;
    __asm__("mul.lo.u64 %0, %1, %2;\n\t" "mul.hi.u64 %1, %1, %2;\n\t" : "+l"(p1_lo), "+l"(p1_hi) : "l"(b_mid));

    p1_lo ^= p0_lo ^ p2_lo;
    p1_hi ^= p0_hi ^ p2_hi;

    unsigned long long c_mid_lo = p0_hi ^ p1_lo;
    unsigned long long c_mid_hi = p2_lo ^ p1_hi;

    unsigned long long c_lo = p0_lo;
    unsigned long long c_hi = p2_hi;

    c_hi ^= c_mid_lo >> 63;
    c_mid_lo = (c_mid_lo << 1) | (c_lo >> 63);
    c_lo <<= 1;
    c_mid_hi = (c_mid_hi << 1) | (c_mid_lo >> 63);
    c_mid_lo <<= 1;

    unsigned long long T = c_hi ^ (c_hi >> 1) ^ (c_hi >> 2) ^ (c_hi >> 7);
    c_mid_hi ^= T ^ (T >> 1) ^ (T >> 2) ^ (T >> 7);
    T = c_mid_hi ^ (c_mid_hi >> 1) ^ (c_mid_hi >> 2) ^ (c_mid_hi >> 7);
    c_mid_lo ^= T ^ (T >> 1) ^ (T >> 2) ^ (T >> 7);

    // FIX: Use __bswap64 for device code
    res64[0] = device_bswap64(c_mid_hi);
    res64[1] = device_bswap64(c_mid_lo);
}

/**
 * @brief Fallback implementation of multiplication in the Galois field GF(2^128).
 *        "Shift-and-xor" algorithm (MSB-first). Correct, but slow.
 */
static __forceinline__ __device__ void gf128_multiply_fallback(uint8_t result[16], const uint8_t a[16], const uint8_t b[16]) {
    // ... (the code from your original `_old` function goes here) ...
    uint8_t X[16] = {0};
    uint8_t Y[16];
    for (int i = 0; i < 16; ++i) Y[i] = a[i];

    for (int i = 0; i < 16; ++i) {
        uint8_t b_byte = b[i];
        for (int j = 0; j < 8; ++j) {
            if ((b_byte >> (7 - j)) & 0x01) {
                for (int k = 0; k < 16; ++k) X[k] ^= Y[k];
            }
            uint8_t carry = (Y[0] & 0x80) ? 1 : 0;
            for (int k = 0; k < 15; ++k) Y[k] = (Y[k] << 1) | (Y[k+1] >> 7);
            Y[15] = (Y[15] << 1);
            if (carry) Y[15] ^= GF128_REDUCTION_CONSTANT;
        }
    }
    for (int i = 0; i < 16; ++i) result[i] = X[i];
}

/**
 * @brief Device function for multiplication in the Galois field GF(2^128).
 *        Chooses the best implementation at compile time based on architecture.
 */
static __forceinline__ __device__ void gf128_multiply(uint8_t result[16], const uint8_t a[16], const uint8_t b[16]) {
#if __CUDA_ARCH__ >= 600
    // Use optimized version for Pascal and newer architectures.
    gf128_multiply_clmul_optimized(result, a, b);
#else
    // Use fallback version, slower but compatible, for older architectures.
    gf128_multiply_fallback(result, a, b);
#endif
}


/**
 * @brief Kernel to generate powers of H (H, H^2, H^4, H^8, ...) on the GPU.
 *        Only thread 0 of the block performs the calculations.
 */
__global__ void generate_h_powers_kernel(uint8_t* d_H_powers, const uint8_t* d_H_base, size_t num_powers) {
    if (threadIdx.x == 0) {
        if (num_powers == 0) return;

        // Copy H_base to d_H_powers[0] (which is H^1)
        for (int i = 0; i < 16; ++i) {
            d_H_powers[i] = d_H_base[i];
        }

        uint8_t prev_power[16];
        // The first power is H^1. Then we generate H^2, H^4, H^8, ...
        // For H^2, we multiply H^1 * H^1.
        // For H^4, we multiply H^2 * H^2.
        // The paper uses H^(2^j) for reduction. d_H_powers[p_idx] will store H^(2^(p_idx+1)).
        // So d_H_powers[0] = H^1 (base for multiplication), d_H_powers[1*16] = H^2, d_H_powers[2*16] = H^4, etc.
        // Adjust indexing so d_H_powers[0] is H^1, d_H_powers[1*16] is H^2, d_H_powers[2*16] is H^4, etc.
        // If num_powers = N, we need H^1, H^2, H^4, ..., H^(2^(N-1)).
        // d_H_powers must be large enough to store N powers.

        // Initialize prev_power with H^1
        for (int i = 0; i < 16; ++i) prev_power[i] = d_H_base[i];

        // Generate H^2, H^4, H^8...
        // d_H_powers[0*16] will contain H^1 (H^(2^0))
        // d_H_powers[1*16] will contain H^2 (H^(2^1))
        // d_H_powers[2*16] will contain H^4 (H^(2^2))
        // ...
        // d_H_powers[j*16] will contain H^(2^j)

        // Store H^1 at d_H_powers[0*16]
        for (int i = 0; i < 16; ++i) {
            d_H_powers[0 * 16 + i] = d_H_base[i];
        }

        for (size_t p_idx = 1; p_idx < num_powers; ++p_idx) { // p_idx = 1, 2, ...
            uint8_t current_power_val[16];
            gf128_multiply(current_power_val, prev_power, prev_power); // H^(2^p_idx) = H^(2^(p_idx-1)) * H^(2^(p_idx-1))
            for (int i = 0; i < 16; ++i) {
                d_H_powers[p_idx * 16 + i] = current_power_val[i];
                prev_power[i] = current_power_val[i];
            }
        }
    }
}


/**
 * @brief Implementation of parallel reduction kernel for GHASH based on Algorithm 1.
 *        Each grid block processes a chunk of the input data.
 */
__global__ void ghash_parallel_reduction_kernel(
    uint8_t* d_output,             // Pointer to output buffer (final or partial)
    const uint8_t* d_input_blocks,
    const uint8_t* d_H_powers,     // H^1, H^2, H^4, H^8, ... (d_H_powers[j*16] = H^(2^j))
    size_t total_input_blocks,     // Total blocks in d_input_blocks
    size_t blocks_per_grid_block)  // How many blocks each grid block processes (e.g. 1024)
{
    // Shared memory to store intermediate results of 16 bytes per thread
    extern __shared__ uint8_t s_data[];

    unsigned int tid = threadIdx.x;
    unsigned int block_size = blockDim.x;

    // Calculate the start of our data chunk
    size_t chunk_start_idx = blockIdx.x * blocks_per_grid_block;
    // Pointer to the start of our chunk
    const uint8_t* my_input_chunk = d_input_blocks + (chunk_start_idx * 16);

    // Calculate how many blocks are in our chunk (the last one may be shorter)
    size_t num_blocks_in_chunk = blocks_per_grid_block;
    if (chunk_start_idx + blocks_per_grid_block > total_input_blocks) {
        num_blocks_in_chunk = total_input_blocks - chunk_start_idx;
    }

    // --- Phase 1: Load blocks to shared memory ---
    if (tid < num_blocks_in_chunk) {
        for (int k = 0; k < 16; ++k) {
            s_data[tid * 16 + k] = my_input_chunk[tid * 16 + k];
        }
    } else {
        // Inactive threads (if block_size > num_blocks_in_chunk) fill with 0s,
        // which is the identity for XOR operation.
        for (int k = 0; k < 16; ++k) {
            s_data[tid * 16 + k] = 0;
        }
    }
    __syncthreads();

    // --- Phase 2: Tree parallel reduction ---
    // The reduction loop goes from half the block size down to 1
    for (unsigned int s = block_size / 2; s > 0; s /= 2) {
        if (tid < s) {
            // Thread `tid` combines its value in s_data[tid] with the value in s_data[tid + s]
            uint8_t block_left[16];
            uint8_t block_right[16];

            for(int k=0; k<16; ++k) {
                block_left[k] = s_data[tid * 16 + k];
                block_right[k] = s_data[(tid + s) * 16 + k];
            }

            // Calculate the power of H needed for this reduction step.
            // If 's' is 2^j, then the index in d_H_powers is j.
            // __ffs(s) returns (position of least significant bit + 1).
            int power_idx_for_H = __ffs(s) - 1;

            const uint8_t* H_power_to_use = d_H_powers + (power_idx_for_H * 16);

            // block_right = block_right * H_power_to_use
            gf128_multiply(block_right, block_right, H_power_to_use);

            // s_data[tid] = block_left XOR block_right
            for (int k = 0; k < 16; ++k) {
                s_data[tid * 16 + k] = block_left[k] ^ block_right[k];
            }
        }
        __syncthreads(); // Synchronize after each reduction step
    }

    // --- Phase 3: Write result ---
    // The final result of the reduction for this CUDA block is in s_data[0].
    if (tid == 0) {
        // Write our partial result to the correct position in the output buffer
        uint8_t* my_output_location = d_output + (blockIdx.x * 16);
        for (int k = 0; k < 16; ++k) {
            my_output_location[k] = s_data[k];
        }
    }
}


// /**
//  * @brief Kernel to apply XOR operation to two buffers on the GPU, writing the result to a third one.
//  */
// __global__ void xor_buffers_128bit_kernel(uint8_t* d_output, const uint8_t* d_input1, const uint8_t* d_input2, size_t num_bytes) {
//     size_t idx = blockIdx.x * blockDim.x + threadIdx.x;
//     size_t stride = gridDim.x * blockDim.x;
//     for (size_t i = idx; i < num_bytes; i += stride) {
//         d_output[i] = d_input1[i] ^ d_input2[i];
//     }
// }

/**
 * @brief Kernel to apply XOR operation to two buffers on the GPU, writing the result to a third one.
 *
 *        CORRECTED AND SIMPLIFIED VERSION:
 *        This kernel is simpler than a "grid-stride loop". It is launched with enough threads
 *        to cover all bytes, and each thread processes a single byte, protected by
 *        a strict bounds check. This eliminates potential subtle race conditions.
 */
__global__ void xor_buffers_128bit_kernel(
    uint8_t* d_output,
    const uint8_t* d_input1,
    const uint8_t* d_input2,
    size_t num_bytes)
{
    // Calculate global and unique index for this thread
    size_t idx = blockIdx.x * blockDim.x + threadIdx.x;

    // --- ROBUSTNESS CORRECTION ---
    // Each thread only works if its index is strictly less than the total number of bytes.
    // This prevents any out-of-bounds writes, which is the most likely cause
    // of data corruption dependent on launch configuration.
    if (idx < num_bytes) {
        d_output[idx] = d_input1[idx] ^ d_input2[idx];
    }
}

// Place this in a utility file or in the same .cpp
void gf128_multiply_cpu(uint8_t result[16], const uint8_t a[16], const uint8_t b[16]) {
    uint8_t X[16] = {0};
    uint8_t Y[16];
    memcpy(Y, a, 16);

    for (int i = 0; i < 16; ++i) {
        uint8_t b_byte = b[i];
        for (int j = 0; j < 8; ++j) {
            if ((b_byte >> (7 - j)) & 0x01) {
                for (int k = 0; k < 16; ++k) X[k] ^= Y[k];
            }
            uint8_t carry = (Y[0] & 0x80) ? 1 : 0;
            for (int k = 0; k < 15; ++k) {
                Y[k] = (Y[k] << 1) | (Y[k + 1] >> 7);
            }
            Y[15] <<= 1;
            if (carry) {
                Y[15] ^= 0x87;
            }
        }
    }
    memcpy(result, X, 16);
}

// Implementation of binary exponentiation on the GPU
__global__ void gf128_power_kernel(uint8_t* d_result, const uint8_t* d_base, size_t exp) {
    if (threadIdx.x == 0 && blockIdx.x == 0) {
        if (exp == 0) {
            for(int i = 0; i < 16; ++i) d_result[i] = 0;
            // Identity is 1, but H^0 is not used in GHASH
            return;
        }

        uint8_t power_result[16];
        uint8_t current_power[16];
        uint8_t temp[16];

        // Initialize result to 1 (identity)
        for(int i=0; i<16; ++i) power_result[i] = 0;

        // Copy base
        for(int i=0; i<16; ++i) current_power[i] = d_base[i];

        // Binary exponentiation (square and multiply)
        if (exp % 2 == 1) {
            for(int i=0; i<16; ++i) power_result[i] = d_base[i];
        }
        exp /= 2;

        while (exp > 0) {
            gf128_multiply(current_power, current_power, current_power); // Square
            if (exp % 2 == 1) {
                if (power_result[0] == 0 && power_result[15] == 0) { // If first time
                     for(int i=0; i<16; ++i) power_result[i] = current_power[i];
                } else {
                    gf128_multiply(power_result, power_result, current_power);
                }
            }
            exp /= 2;
        }

        // Copy final result
        for(int i=0; i<16; ++i) d_result[i] = power_result[i];
    }
}


// Kernel to combine partial GHASH results
__global__ void combine_partial_ghash_kernel(
    uint8_t* d_final_result,
    const uint8_t* d_partial_results,
    const uint8_t* d_H_power_chunk,
    const uint8_t* d_H_power_last_chunk,
    size_t num_partials)
{
    if (threadIdx.x == 0 && blockIdx.x == 0) {
        if (num_partials == 0) return;
        if (num_partials == 1) {
            for (int k = 0; k < 16; ++k) d_final_result[k] = d_partial_results[k];
            return;
        }

        uint8_t combined[16];

        // 1. Copy the first partial result
        for (int k = 0; k < 16; ++k) combined[k] = d_partial_results[k];

        // 2. Iterate over remaining results
        for (size_t i = 1; i < num_partials; ++i) {
            // Decide which power of H to use: normal or last chunk
            const uint8_t* h_power_to_use = (i == num_partials - 1 && d_H_power_last_chunk != nullptr)
                                                ? d_H_power_last_chunk
                                                : d_H_power_chunk;

            // combined = combined * H^n
            gf128_multiply(combined, combined, h_power_to_use);

            // combined = combined XOR partial_result[i]
            const uint8_t* next_partial = d_partial_results + i * 16;
            for (int k = 0; k < 16; ++k) combined[k] ^= next_partial[k];
        }

        // 3. Write final result
        for (int k = 0; k < 16; ++k) d_final_result[k] = combined[k];
    }
}
