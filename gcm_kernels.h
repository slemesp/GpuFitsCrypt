// gcm_kernels.h
#ifndef GCM_KERNELS_H
#define GCM_KERNELS_H

#include "cuda_runtime.h"
#include <cstdint>

/**
 * @brief Device function for multiplication in the Galois field GF(2^128).
 *        This is the fundamental primitive for GHASH, a bit-level operation.
 * @param result Pointer to a 16-byte array where the result will be stored.
 * @param a First 16-byte operand.
 * @param b Second 16-byte operand.
 */
static __forceinline__ __device__ void gf128_multiply(uint8_t result[16], const uint8_t a[16], const uint8_t b[16]);

/**
 * @brief Parallel reduction kernel for GHASH.
 *        Implements Algorithm 1 from JaeSeok Lee's paper.
 *
 * @param d_output Pointer to GPU memory where the final hash result will be written (16 bytes).
 * @param d_input_blocks Pointer to input data in GPU (AAD concatenated with ciphertext).
 * @param d_H_powers Pointer to precomputed powers of the hash key H (H, H^2, H^4, H^8...).
 * @param num_input_blocks The total number of 16-byte blocks in d_input.
 */
__global__ void ghash_parallel_reduction_kernel(
    uint8_t *d_output, // Pointer to output buffer (final or partial)
    const uint8_t *d_input_blocks,
    const uint8_t *d_H_powers,
    size_t total_input_blocks, // Total blocks in d_input_blocks
    size_t blocks_per_grid_block
);

/**
 * @brief Kernel to generate powers of H (H, H^2, H^4, H^8, ...) on the GPU.
 *        Only thread 0 of the block performs the calculations.
 * @param d_H_powers Pointer to GPU memory where the powers will be stored.
 * @param d_H_base Pointer to the base hash key H (16 bytes).
 * @param num_powers The number of powers to generate (e.g., for log2(num_blocks)).
 */
__global__ void generate_h_powers_kernel(uint8_t *d_H_powers, const uint8_t *d_H_base, size_t num_powers);


/**
 * @brief Kernel to apply XOR operation to two buffers on the GPU, writing the result to a third one.
 * @param d_output Pointer to the output buffer.
 * @param d_input1 Pointer to the first input buffer.
 * @param d_input2 Pointer to the second input buffer.
 * @param num_bytes Number of bytes to process.
 */
__global__ void xor_buffers_128bit_kernel(uint8_t *d_output, const uint8_t *d_input1, const uint8_t *d_input2,
                                          size_t num_bytes);

void gf128_multiply_cpu(uint8_t result[16], const uint8_t a[16], const uint8_t b[16]);

// void gf128_power_cpu(uint8_t result[16], const uint8_t h[16], size_t n);

// New kernel to calculate H^exp on the GPU
__global__ void gf128_power_kernel(uint8_t *d_result, const uint8_t *d_base, size_t exp);

// New kernel to combine partial GHASH results
__global__ void combine_partial_ghash_kernel(
    uint8_t *d_final_result,
    const uint8_t *d_partial_results,
    const uint8_t *d_H_power_chunk, // H^(normal chunk size)
    const uint8_t *d_H_power_last_chunk, // H^(last chunk size, if different)
    size_t num_partials);
#endif // GCM_KERNELS_H
