// gpu_utils.h
#ifndef GPU_UTILS_H
#define GPU_UTILS_H

#include <vector>
#include <cstdint> // For uint32_t, uint8_t

// Structure to pass GPU pointers and manage them easily
struct GpuWorkloadPointers
{
    uint8_t* d_io = nullptr;
    uint32_t* d_keystream = nullptr;
    uint32_t* d_nonce_packed = nullptr;
    uint32_t* d_aes_key_exp = nullptr;
    float kernel_elapsed_ms = 0.0f; // Kernel execution time in ms (if enabled)
};

__global__ void swap_endianness_kernel(uint8_t* data, size_t num_elements, int bytes_per_element);
/**
 * @brief CUDA kernel to swap endianness of a data buffer in-place.
 * @param data Pointer to the data buffer in GPU.
 * @param num_elements Total number of elements (pixels) to process.
 * @param bytes_per_element Number of bytes per element (2, 4 or 8).
 */
__global__ void swap_endianness_kernel(uint8_t* data, size_t num_elements, int bytes_per_element);

GpuWorkloadPointers launch_header_decryption_async(
    const unsigned char* h_input_buffer,
    unsigned char* h_output_buffer,
    size_t buffer_size_bytes,
    const std::vector<uint8_t>& nonce_vec,
    uint32_t* p_h_aes_key_exp_header,
    cudaStream_t stream,
    bool enable_kernel_timing = false);

GpuWorkloadPointers launch_data_decryption_async(
    const unsigned char* h_input_buffer,
    unsigned char* h_output_buffer,
    const std::vector<uint8_t>& nonce_vec,
    uint32_t* p_d_aes_key_exp_data,
    long original_data_size,
    size_t padded_data_size,
    int original_bitpix,
    cudaStream_t stream,
    bool enable_kernel_timing = false);


#endif // GPU_UTILS_H
