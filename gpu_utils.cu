// gpu_utils.cu
#include "gpu_utils.h"          // Declaration of processDataWithGPU
#include "lib_internal_utils.h" // For GFC_LOG and UTIL_NONCE_SIZE_BYTES
#include "aes.h"                // For pack_nonce and declaration of aes128_encrypt_gpu_repeat_coalesced
// // #include "kernel.h"             // For threadSizeBS, REPEATBS (compile-time constant definitions)

#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <cstring>   // For memcpy
#include <stdexcept> // For std::runtime_error
#include <algorithm> // For std::min (used in printFirstBytesAsChars if it were here)
#include <vector>    // For std::vector

// --- Error Macro Specific to This File (or use a global one) ---
#ifndef CHECK_CUDA_ERROR_GPU_UTILS
#define CHECK_CUDA_ERROR_GPU_UTILS(err, msg) \
if (err != cudaSuccess) { \
char log_msg[512]; \
snprintf(log_msg, sizeof(log_msg), "CUDA Error in gpu_utils: %s - %s (%d)", msg, cudaGetErrorString(err), err); \
GFC_LOG(GFC_LOG_LEVEL_ERROR, log_msg); \
throw std::runtime_error(log_msg); \
}
#endif

// --- CUDA Kernels Used by processDataWithGPU ---

// XOR kernel (if not already defined in another common_kernels.cu)
// Renamed to avoid collisions if there's another version.
__global__ void xor_buffers_kernel_for_gpu_utils(
    uint32_t *output,
    const uint32_t *buffer_a,
    const uint32_t *buffer_b,
    size_t n_words) {
    size_t idx = (size_t) blockIdx.x * blockDim.x + threadIdx.x;
    size_t stride = (size_t) gridDim.x * blockDim.x;

    for (size_t i = idx; i < n_words; i += stride) {
        output[i] = buffer_a[i] ^ buffer_b[i];
    }
}

__global__ void xor_transposed_keystream_kernel(
    uint32_t *output,
    const uint32_t *buffer_a,
    const uint32_t *keystream_buffer,
    size_t n_words,
    size_t aes_grid_total_threads) {
    size_t i = (size_t) blockIdx.x * blockDim.x + threadIdx.x;
    size_t stride = (size_t) gridDim.x * blockDim.x;

    for (; i < n_words; i += stride) {
        // ----- Detransposition logic that DOES work with the unpacking_word_prmt layout ---

        // 1. Which word is it within the 32-word block that each thread generates in each iteration?
        size_t word_in_block32 = (i / aes_grid_total_threads) % 32;

        // 2. Which thread generated this word?
        size_t aes_tid = i % aes_grid_total_threads;

        // 3. In which iteration j of the REPEATBS loop was it generated?
        size_t j_iter = i / (32 * aes_grid_total_threads);

        // 4. Calculate the base offset for that iteration j.
        size_t base_for_iter = j_iter * 32 * aes_grid_total_threads;

        // 5. Calculate the final transposed index.
        size_t transposed_idx = base_for_iter + (word_in_block32 * aes_grid_total_threads) + aes_tid;

        output[i] = buffer_a[i] ^ keystream_buffer[transposed_idx];
    }
}

// --- Implementation of processDataWithGPU ---
bool processDataWithGPU(
    std::vector<uint8_t> &data_buffer,
    const std::vector<uint8_t> &nonce_bytes,
    uint32_t *h_aes_key_exp,
    float &out_gpu_milliseconds,
    size_t &out_original_data_size,
    GpuProcessingType processing_type,
    int original_bitpix,
    size_t final_padded_size_bytes) {
    // --- Initial checks (unchanged) ---
    if (nonce_bytes.size() != UTIL_NONCE_SIZE_BYTES) {
        GFC_LOG(GFC_LOG_LEVEL_ERROR, "processDataWithGPU: Incorrect nonce size.");
        return false;
    }
    if (data_buffer.empty()) {
        out_gpu_milliseconds = 0;
        out_original_data_size = 0;
        if (processing_type == GpuProcessingType::ImageData && final_padded_size_bytes > 0) {
            data_buffer.assign(final_padded_size_bytes, 0);
        }
        return true;
    }

    // --- 1. Initialize ALL resources to nullptr. This is the key to safety. ---
    cudaEvent_t start_event = nullptr;
    cudaEvent_t stop_event = nullptr;
    uint32_t *d_data_io = nullptr;
    uint32_t *d_keystream = nullptr;
    uint32_t *d_nonce_packed = nullptr;
    uint32_t *d_aes_key_exp_gpu_ptr = nullptr;

    try {
        cudaError_t err = cudaSuccess; // Local error variable for the try block

        // --- 2. Size and parameter preparation (your original logic) ---
        out_original_data_size = data_buffer.size();
        size_t size_padded_to_4_bytes = ((out_original_data_size + 3) / 4) * 4;
        if (size_padded_to_4_bytes > out_original_data_size) {
            data_buffer.resize(size_padded_to_4_bytes, 0);
        }
        size_t dataSizeWords = size_padded_to_4_bytes / 4;
        size_t gpu_buffer_alloc_size = (processing_type == GpuProcessingType::ImageData && final_padded_size_bytes > 0)
                                           ? final_padded_size_bytes
                                           : size_padded_to_4_bytes;

        uint32_t h_nonce_packed[32] = {0};
        memcpy(h_nonce_packed, nonce_bytes.data(), UTIL_NONCE_SIZE_BYTES);
        pack_nonce(h_nonce_packed, h_nonce_packed);

        size_t totalBlocksAES = (dataSizeWords == 0) ? 0 : ((dataSizeWords + 3) / 4);
        size_t blocksPerThreadPerLaunchKernelAES = (size_t) 8 * REPEATBS;
        size_t neededThreadsForAES = (totalBlocksAES + blocksPerThreadPerLaunchKernelAES - 1) /
                                      blocksPerThreadPerLaunchKernelAES;
        unsigned int numBlocksGridAES = (neededThreadsForAES + threadSizeBS - 1) / threadSizeBS;
        size_t aes_total_threads = (size_t) numBlocksGridAES * threadSizeBS;
        size_t wordsPerThreadTotalOutputAES = (size_t) 8 * 4 * REPEATBS;
        size_t keystreamBufferSizeWords = aes_total_threads * wordsPerThreadTotalOutputAES;
        if (dataSizeWords > 0 && keystreamBufferSizeWords < dataSizeWords) {
            keystreamBufferSizeWords = dataSizeWords;
        } else if (keystreamBufferSizeWords == 0 && dataSizeWords > 0) {
            keystreamBufferSizeWords = dataSizeWords;
        } else if (keystreamBufferSizeWords == 0) {
            keystreamBufferSizeWords = 1;
        }
        size_t keystreamBufferSizeBytes = keystreamBufferSizeWords * sizeof(uint32_t);

        // --- 3. Allocation of ALL resources ---
        err = cudaEventCreate(&start_event);
        CHECK_CUDA_ERROR_GPU_UTILS(err, "EventCreate start");
        err = cudaEventCreate(&stop_event);
        CHECK_CUDA_ERROR_GPU_UTILS(err, "EventCreate stop");
        err = cudaMalloc((void **) &d_data_io, gpu_buffer_alloc_size);
        CHECK_CUDA_ERROR_GPU_UTILS(err, "Malloc d_data_io");
        err = cudaMalloc((void **) &d_keystream, keystreamBufferSizeBytes);
        CHECK_CUDA_ERROR_GPU_UTILS(err, "Malloc d_keystream");
        err = cudaMalloc((void **) &d_nonce_packed, 32 * sizeof(uint32_t));
        CHECK_CUDA_ERROR_GPU_UTILS(err, "Malloc d_nonce_packed");
        err = cudaMalloc((void **) &d_aes_key_exp_gpu_ptr, 352 * sizeof(uint32_t));
        CHECK_CUDA_ERROR_GPU_UTILS(err, "Malloc d_aes_key_exp_gpu_ptr");

        // --- 4. Execution logic (Copies, Kernels, etc.) ---
        err = cudaMemcpy(d_data_io, data_buffer.data(), size_padded_to_4_bytes, cudaMemcpyHostToDevice);
        CHECK_CUDA_ERROR_GPU_UTILS(err, "Memcpy d_data_io H->D");
        err = cudaMemcpy(d_nonce_packed, h_nonce_packed, 32 * sizeof(uint32_t), cudaMemcpyHostToDevice);
        CHECK_CUDA_ERROR_GPU_UTILS(err, "Memcpy d_nonce_packed H->D");
        err = cudaMemcpy(d_aes_key_exp_gpu_ptr, h_aes_key_exp, 352 * sizeof(uint32_t), cudaMemcpyHostToDevice);
        CHECK_CUDA_ERROR_GPU_UTILS(err, "Memcpy d_aes_key_exp_gpu_ptr H->D");

        err = cudaEventRecord(start_event);
        CHECK_CUDA_ERROR_GPU_UTILS(err, "EventRecord start");

        if (numBlocksGridAES > 0 && dataSizeWords > 0) {
            aes128_encrypt_gpu_repeat_coalesced<<<numBlocksGridAES, threadSizeBS>>>(
                d_keystream, nullptr, d_aes_key_exp_gpu_ptr, d_nonce_packed);
            err = cudaGetLastError();
            CHECK_CUDA_ERROR_GPU_UTILS(err, "AES kernel");
        }
        if (dataSizeWords > 0) {
            unsigned int xorBlockSize = 256;
            unsigned int xorGridSize = (dataSizeWords + xorBlockSize - 1) / xorBlockSize;
            xor_transposed_keystream_kernel<<<xorGridSize, xorBlockSize>>>(
                d_data_io, d_data_io, d_keystream, dataSizeWords, aes_total_threads);
            err = cudaGetLastError();
            CHECK_CUDA_ERROR_GPU_UTILS(err, "XOR kernel");
        }
        if (processing_type == GpuProcessingType::ImageData) {
            int bytes_per_pixel = (original_bitpix != 0) ? (std::abs(original_bitpix) / 8) : 0;
            if (bytes_per_pixel > 1 && out_original_data_size > 0) {
                size_t num_elements = out_original_data_size / bytes_per_pixel;
                unsigned int threads_per_block = 256;
                unsigned int grid_size = (num_elements + threads_per_block - 1) / threads_per_block;
                swap_endianness_kernel<<<grid_size, threads_per_block>>>(
                    (uint8_t *) d_data_io, num_elements, bytes_per_pixel);
                err = cudaGetLastError();
                CHECK_CUDA_ERROR_GPU_UTILS(err, "Endian Swap kernel");
            }
            if (gpu_buffer_alloc_size > out_original_data_size) {
                size_t padding_start_offset = out_original_data_size;
                size_t padding_byte_count = gpu_buffer_alloc_size - padding_start_offset;
                err = cudaMemsetAsync((uint8_t *) d_data_io + padding_start_offset, 0, padding_byte_count);
                CHECK_CUDA_ERROR_GPU_UTILS(err, "cudaMemsetAsync for padding");
            }
        }

        err = cudaEventRecord(stop_event);
        CHECK_CUDA_ERROR_GPU_UTILS(err, "EventRecord stop");
        err = cudaEventSynchronize(stop_event);
        CHECK_CUDA_ERROR_GPU_UTILS(err, "EventSynchronize");
        err = cudaEventElapsedTime(&out_gpu_milliseconds, start_event, stop_event);
        CHECK_CUDA_ERROR_GPU_UTILS(err, "EventElapsedTime");

        data_buffer.resize(gpu_buffer_alloc_size);
        err = cudaMemcpy(data_buffer.data(), d_data_io, gpu_buffer_alloc_size, cudaMemcpyDeviceToHost);
        CHECK_CUDA_ERROR_GPU_UTILS(err, "Memcpy result D->H");
    } catch (const std::runtime_error &e) {
        // --- 5. ERROR CAPTURE BLOCK ---
        // This block executes if any CHECK_CUDA_ERROR_GPU_UTILS fails.
        // We will clean up all resources that may have been created.
        if (d_data_io) { cudaFree(d_data_io); }
        if (d_keystream) { cudaFree(d_keystream); }
        if (d_nonce_packed) { cudaFree(d_nonce_packed); }
        if (d_aes_key_exp_gpu_ptr) { cudaFree(d_aes_key_exp_gpu_ptr); }
        if (start_event) cudaEventDestroy(start_event);
        if (stop_event) cudaEventDestroy(stop_event);

        // Try to clean up any pending errors in the context
        cudaGetLastError();

        return false; // Indicate failure to the caller.
    }

    // --- 6. FINAL CLEANUP (ONLY IF SUCCESSFUL) ---
    // If the 'try' block completed without exceptions, execution reaches here.
    if (d_data_io) { cudaFree(d_data_io); }
    if (d_keystream) { cudaFree(d_keystream); }
    if (d_nonce_packed) { cudaFree(d_nonce_packed); }
    if (d_aes_key_exp_gpu_ptr) { cudaFree(d_aes_key_exp_gpu_ptr); }
    if (start_event) cudaEventDestroy(start_event);
    if (stop_event) cudaEventDestroy(stop_event);
    GFC_LOG(GFC_LOG_LEVEL_DEBUG, "processDataWithGPU: GPU resources freed successfully.");

    return true; // Indicate success.
}

// ==========================================================================================
// STEP 1: NEW ASYNCHRONOUS HELPER FUNCTIONS
// ==========================================================================================

/**
 * @brief (V2) Launches header decryption work on a specific stream,
 *        writing the result directly to a host output buffer.
 *
 * @param h_input_buffer Pointer to the HOST buffer containing encrypted data (read from ENCHDR).
 * @param h_output_buffer Pointer to the HOST buffer where the decrypted result will be written.
 *                        This pointer must point to a valid and sufficiently large memory region.
 *                        For optimal performance, it should be pinned memory.
 * @param buffer_size_bytes The size in bytes of the header data to process.
 * @param nonce_vec The 96-byte vector containing the nonce for the header.
 * @param p_h_aes_key_exp_header Pointer to the expanded AES key for the header.
 * @param stream The CUDA stream on which all operations will be enqueued.
 * @param enable_kernel_timing If true, measures kernel execution time with cudaEvent.
 * @return GpuWorkloadPointers Structure with the allocated device pointers. The caller
 *         is responsible for synchronizing the stream and freeing these pointers.
 *
 * Usage:
 *   // In the main function:
 *   // unsigned char* final_buffer = ... (allocated with cudaMallocHost)
 *   // std::vector<uint8_t> encrypted_header_data = ...
 *   launch_header_decryption_async(
 *       encrypted_header_data.data(), // Input
 *       final_buffer,                 // Output (header section)
 *       encrypted_header_data.size(),
 *       ...
 *   );
 */
GpuWorkloadPointers launch_header_decryption_async(
    const unsigned char *h_input_buffer,
    unsigned char *h_output_buffer,
    size_t buffer_size_bytes,
    const std::vector<uint8_t> &nonce_vec,
    uint32_t *p_h_aes_key_exp_header,
    cudaStream_t stream,
    bool enable_kernel_timing) {
    GpuWorkloadPointers pointers = {};
    if (!h_input_buffer || !h_output_buffer || buffer_size_bytes == 0 || !p_h_aes_key_exp_header) {
        return pointers;
    }

    GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(LibAPI-Streams-V2) Launching Header work on stream...");

    // 1. Calculate kernel parameters (based on data size)
    size_t header_size_words = (buffer_size_bytes + 3) / 4;
    size_t totalBlocksAES = (header_size_words > 0) ? ((header_size_words + 3) / 4) : 0;
    size_t blocksPerThread = (size_t) 8 * REPEATBS;
    size_t neededThreads = (totalBlocksAES > 0) ? ((totalBlocksAES + blocksPerThread - 1) / blocksPerThread) : 0;
    unsigned int numBlocksGrid = (neededThreads > 0) ? ((neededThreads + threadSizeBS - 1) / threadSizeBS) : 0;
    size_t aes_grid_total_threads = (size_t) numBlocksGrid * threadSizeBS;

    size_t keystream_words = (size_t) numBlocksGrid * threadSizeBS * blocksPerThread * 4;
    if (keystream_words < header_size_words) keystream_words = header_size_words;

    // 2. Prepare Nonce
    uint32_t h_nonce_packed[32] = {0};
    memcpy(h_nonce_packed, nonce_vec.data(), UTIL_NONCE_SIZE_BYTES);
    pack_nonce(h_nonce_packed, h_nonce_packed);

    // 3. Allocate GPU memory asynchronously
    cudaMallocAsync((void **) &pointers.d_io, buffer_size_bytes, stream);
    cudaMallocAsync((void **) &pointers.d_keystream, keystream_words * sizeof(uint32_t), stream);
    cudaMallocAsync((void **) &pointers.d_nonce_packed, 32 * sizeof(uint32_t), stream);
    cudaMallocAsync((void **) &pointers.d_aes_key_exp, 352 * sizeof(uint32_t), stream);

    // 4. Copy input data to device (Host -> Device)
    cudaMemcpyAsync(pointers.d_io, h_input_buffer, buffer_size_bytes, cudaMemcpyHostToDevice, stream);
    cudaMemcpyAsync(pointers.d_nonce_packed, h_nonce_packed, 32 * sizeof(uint32_t), cudaMemcpyHostToDevice, stream);
    cudaMemcpyAsync(pointers.d_aes_key_exp, p_h_aes_key_exp_header, 352 * sizeof(uint32_t), cudaMemcpyHostToDevice,
                    stream);

    // 5. Launch decryption kernels
    cudaEvent_t start = nullptr, stop = nullptr;
    if (enable_kernel_timing) {
        cudaEventCreate(&start);
        cudaEventCreate(&stop);
        cudaEventRecord(start, stream);
    }

    if (numBlocksGrid > 0) {
        // Generate Keystream
        aes128_encrypt_gpu_repeat_coalesced<<<numBlocksGrid, threadSizeBS, 0, stream>>>(
            pointers.d_keystream, nullptr, pointers.d_aes_key_exp, pointers.d_nonce_packed);

        // Apply XOR with keystream to decrypt
        unsigned int xor_threads = 256;
        unsigned int xor_blocks = (header_size_words + xor_threads - 1) / xor_threads;
        xor_transposed_keystream_kernel<<<xor_blocks, xor_threads, 0, stream>>>(
            (uint32_t *) pointers.d_io,
            (const uint32_t *) pointers.d_io,
            pointers.d_keystream,
            header_size_words,
            aes_grid_total_threads
        );
    }

    if (enable_kernel_timing) {
        cudaEventRecord(stop, stream);
        cudaEventSynchronize(stop);
        float ms = 0;
        cudaEventElapsedTime(&ms, start, stop);
        pointers.kernel_elapsed_ms = ms;
        cudaEventDestroy(start);
        cudaEventDestroy(stop);
    }

    // 6. Copy result directly to host output buffer (Device -> Host)
    // THIS IS THE KEY CHANGE! We write the result DIRECTLY to the host output buffer.
    cudaMemcpyAsync(h_output_buffer, pointers.d_io, buffer_size_bytes, cudaMemcpyDeviceToHost, stream);

    return pointers;
}

/**
 * @brief (V2) Launches the complete image data decryption pipeline on a stream:
 *        1. Decrypts (AES-CTR)
 *        2. Changes Endianness (if necessary)
 *        3. Applies zero padding (if necessary)
 *        The result is written directly to a host output buffer.
 *
 * @param h_input_buffer Pointer to the HOST buffer with encrypted data (read from BINTABLE).
 *                       Should be pinned memory for optimal performance.
 * @param h_output_buffer Pointer to the HOST buffer where the final result will be written (decrypted,
 *                        with corrected endianness and padding). Must point to a valid memory region
 *                        of size `padded_data_size`. Ideally, pinned memory.
 * @param nonce_vec The 96-byte vector containing the nonce for the data.
 * @param p_d_aes_key_exp_data Pointer to the expanded AES key for the data.
 * @param original_data_size The actual size of the image data, without padding.
 * @param padded_data_size The final size of the data including padding to FITS_BLOCK_SIZE.
 * @param original_bitpix The original BITPIX value, used to determine endianness.
 * @param stream The CUDA stream on which all operations will be enqueued.
 * @param enable_kernel_timing If true, measures kernel execution time with cudaEvent.
 * @return GpuWorkloadPointers Structure with the allocated device pointers.
 */
GpuWorkloadPointers launch_data_decryption_async(
    const unsigned char *h_input_buffer,
    unsigned char *h_output_buffer,
    const std::vector<uint8_t> &nonce_vec,
    uint32_t *p_d_aes_key_exp_data,
    long original_data_size,
    size_t padded_data_size,
    int original_bitpix,
    cudaStream_t stream,
    bool enable_kernel_timing) {
    GpuWorkloadPointers pointers = {};
    if (!h_input_buffer || !h_output_buffer || original_data_size == 0 || !p_d_aes_key_exp_data) {
        return pointers;
    }

    GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(LibAPI-Streams-V2) Launching Data pipeline on stream (Decrypt->Endian->Pad)...");

    // 1. Calculate kernel parameters
    size_t data_size_words = (original_data_size + 3) / 4;
    size_t totalBlocksAES = (data_size_words > 0) ? ((data_size_words + 3) / 4) : 0;
    size_t blocksPerThread = (size_t) 8 * REPEATBS;
    size_t neededThreads = (totalBlocksAES > 0) ? ((totalBlocksAES + blocksPerThread - 1) / blocksPerThread) : 0;
    unsigned int numBlocksGrid = (neededThreads > 0) ? ((neededThreads + threadSizeBS - 1) / threadSizeBS) : 0;
    size_t aes_grid_total_threads = (size_t) numBlocksGrid * threadSizeBS;

    size_t keystream_words = (size_t) numBlocksGrid * threadSizeBS * blocksPerThread * 4;
    if (keystream_words < data_size_words) keystream_words = data_size_words;

    // 2. Prepare Nonce
    uint32_t h_nonce_packed[32] = {0};
    memcpy(h_nonce_packed, nonce_vec.data(), UTIL_NONCE_SIZE_BYTES);
    pack_nonce(h_nonce_packed, h_nonce_packed);

    // 3. Allocate GPU memory. The IO buffer must have the final size with padding.
    cudaMallocAsync((void **) &pointers.d_io, padded_data_size, stream);
    cudaMallocAsync((void **) &pointers.d_keystream, keystream_words * sizeof(uint32_t), stream);
    cudaMallocAsync((void **) &pointers.d_nonce_packed, 32 * sizeof(uint32_t), stream);
    cudaMallocAsync((void **) &pointers.d_aes_key_exp, 352 * sizeof(uint32_t), stream);

    // 4. Copy input data (Host -> Device). We only copy the original bytes.
    cudaMemcpyAsync(pointers.d_io, h_input_buffer, original_data_size, cudaMemcpyHostToDevice, stream);
    cudaMemcpyAsync(pointers.d_nonce_packed, h_nonce_packed, 32 * sizeof(uint32_t), cudaMemcpyHostToDevice, stream);
    cudaMemcpyAsync(pointers.d_aes_key_exp, p_d_aes_key_exp_data, 352 * sizeof(uint32_t), cudaMemcpyHostToDevice,
                    stream);

    // 5. Launch the kernel pipeline
    cudaEvent_t start = nullptr, stop = nullptr;
    if (enable_kernel_timing) {
        cudaEventCreate(&start);
        cudaEventCreate(&stop);
        cudaEventRecord(start, stream);
    }

    if (numBlocksGrid > 0) {
        // 5a. Generate Keystream
        aes128_encrypt_gpu_repeat_coalesced<<<numBlocksGrid, threadSizeBS, 0, stream>>>(
            pointers.d_keystream, nullptr, pointers.d_aes_key_exp, pointers.d_nonce_packed);

        // 5b. Decrypt with XOR
        unsigned int xor_threads = 256;
        unsigned int xor_blocks = (data_size_words + xor_threads - 1) / xor_threads;
        xor_transposed_keystream_kernel<<<xor_blocks, xor_threads, 0, stream>>>(
            (uint32_t *) pointers.d_io, (const uint32_t *) pointers.d_io, pointers.d_keystream,
            data_size_words, aes_grid_total_threads);
    }

    // 5c. Change Endianness (if applicable)
    int bytes_per_pixel = (original_bitpix != 0) ? (std::abs(original_bitpix) / 8) : 0;
    if (bytes_per_pixel > 1) {
        size_t num_elements = original_data_size / bytes_per_pixel;
        unsigned int threads_per_block = 256;
        unsigned int grid_size = (num_elements + threads_per_block - 1) / threads_per_block;
        swap_endianness_kernel<<<grid_size, threads_per_block, 0, stream>>>(
            (uint8_t *) pointers.d_io, num_elements, bytes_per_pixel);
    }

    // 5d. Apply zero padding (if applicable)
    if (padded_data_size > (size_t) original_data_size) {
        size_t padding_offset = original_data_size;
        size_t padding_size = padded_data_size - original_data_size;
        cudaMemsetAsync((uint8_t *) pointers.d_io + padding_offset, 0, padding_size, stream);
    }

    if (enable_kernel_timing) {
        cudaEventRecord(stop, stream);
        cudaEventSynchronize(stop);
        float ms = 0;
        cudaEventElapsedTime(&ms, start, stop);
        pointers.kernel_elapsed_ms = ms;
        cudaEventDestroy(start);
        cudaEventDestroy(stop);
    }

    // 6. Copy the final processed result (Device -> Host) directly to the output buffer
    cudaMemcpyAsync(h_output_buffer, pointers.d_io, padded_data_size, cudaMemcpyDeviceToHost, stream);

    return pointers;
}

/**
 * @brief CUDA kernel to change endianness of a data buffer in-place.
 * @param data Pointer to the data buffer in GPU.
 * @param num_elements Total number of elements (pixels) to process.
 * @param bytes_per_element Number of bytes per element (2, 4 or 8).
 */
__global__ void swap_endianness_kernel(uint8_t *data, size_t num_elements, int bytes_per_element) {
    size_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= num_elements) return;
    uint8_t *p_element = data + (idx * bytes_per_element);
    if (bytes_per_element == 2) {
        uint8_t temp = p_element[0];
        p_element[0] = p_element[1];
        p_element[1] = temp;
    } else if (bytes_per_element == 4) {
        uint8_t t0 = p_element[0], t1 = p_element[1];
        p_element[0] = p_element[3];
        p_element[1] = p_element[2];
        p_element[2] = t1;
        p_element[3] = t0;
    } else if (bytes_per_element == 8) {
        uint8_t t0 = p_element[0], t1 = p_element[1], t2 = p_element[2], t3 = p_element[3];
        p_element[0] = p_element[7];
        p_element[1] = p_element[6];
        p_element[2] = p_element[5];
        p_element[3] = p_element[4];
        p_element[4] = t3;
        p_element[5] = t2;
        p_element[6] = t1;
        p_element[7] = t0;
    }
}
