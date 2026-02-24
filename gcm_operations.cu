// gcm_operations.cpp
#include "gcm_operations.h"
#include "gcm_kernels.h"    // For calling GHASH kernels and helper functions
#include "aes.h"            // For aes128_encrypt_gpu_repeat_coalesced and pack_nonce
#include "lib_internal_utils.h" // For logs, UTIL_NONCE_SIZE_BYTES
#include <cstring>          // For memcmp
#include <stdexcept>        // For std::runtime_error
#include <cmath>            // For std::ceil, std::log2
#include <vector>           // For std::vector


// Helper to convert to big-endian if host is little-endian
// Only for uint32_t, for 64-bit length it is done byte by byte
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __bswap_32(x) \
    ((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) | \
     (((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))
#else
#define __bswap_32(x) (x)
#endif


// An RAII template for CUDA memory management
template<typename T>
struct CudaManagedBuffer {
    T *ptr = nullptr;
    size_t size_bytes = 0;
    std::string name = "";
    cudaStream_t stream = 0;

    CudaManagedBuffer() = default;

    CudaManagedBuffer(size_t bytes, cudaStream_t s = 0, const std::string &n = "") : size_bytes(bytes), name(n),
        stream(s) {
        if (size_bytes > 0) {
            cudaError_t err = cudaMallocAsync(&ptr, size_bytes, stream);
            if (err != cudaSuccess) {
                GFC_LOG(GFC_LOG_LEVEL_ERROR, "CUDA MallocAsync failed for %s (%zu bytes): %s", name.c_str(), size_bytes,
                        cudaGetErrorString(err));
                throw std::runtime_error("cudaMallocAsync failed.");
            }
            GFC_LOG(GFC_LOG_LEVEL_TRACE, "Allocated %s: %zu bytes", name.c_str(), size_bytes);
        }
    }

    ~CudaManagedBuffer() {
        if (ptr) {
            cudaError_t err = cudaFreeAsync(ptr, stream);
            if (err != cudaSuccess) {
                GFC_LOG(GFC_LOG_LEVEL_ERROR, "CUDA FreeAsync failed for %s: %s", name.c_str(), cudaGetErrorString(err));
            } else {
                GFC_LOG(GFC_LOG_LEVEL_TRACE, "Freed %s", name.c_str());
            }
        }
    }

    CudaManagedBuffer(const CudaManagedBuffer &) = delete;

    CudaManagedBuffer &operator=(const CudaManagedBuffer &) = delete;

    CudaManagedBuffer(CudaManagedBuffer &&other) noexcept : ptr(other.ptr), size_bytes(other.size_bytes),
                                                            name(std::move(other.name)), stream(other.stream) {
        other.ptr = nullptr;
        other.size_bytes = 0;
    }

    CudaManagedBuffer &operator=(CudaManagedBuffer &&other) noexcept {
        if (this != &other) {
            if (ptr) { cudaFreeAsync(ptr, stream); }
            ptr = other.ptr;
            size_bytes = other.size_bytes;
            name = std::move(other.name);
            stream = other.stream;
            other.ptr = nullptr;
            other.size_bytes = 0;
        }
        return *this;
    }

    T *get() const { return ptr; }
    operator T *() const { return ptr; }
};


// Function to calculate grid and block dimensions for AES kernels
void calculate_aes_kernel_params(size_t total_data_bytes,
                                 size_t &out_num_blocks_grid,
                                 size_t &out_thread_size_bs,
                                 size_t &out_aes_grid_total_threads,
                                 size_t &out_keystream_buffer_size_words) {
    // 1. Define constants based on compilation and kernel architecture.
    const size_t thread_block_size = threadSizeBS; // Threads per GPU block (e.g., 64, 128)
    const size_t repeat_factor = REPEATBS;         // Iterations of the kernel's inner loop

    // The kernel `aes128_encrypt_gpu_repeat_coalesced` processes 8 AES blocks of 128 bits (128 bytes) per EACH iteration.
    const size_t bytes_per_thread_per_call = 8 * 16 * repeat_factor;

    // 2. Calculate total threads needed to cover all data.
    // Use integer division with ceiling to ensure full coverage.
    size_t needed_threads = (total_data_bytes == 0)
                                ? 0
                                : (total_data_bytes + bytes_per_thread_per_call - 1) / bytes_per_thread_per_call;

    // 3. Calculate CUDA grid launch parameters.
    out_thread_size_bs = thread_block_size;
    out_num_blocks_grid = (needed_threads == 0)
                              ? 0
                              : (needed_threads + out_thread_size_bs - 1) / out_thread_size_bs;

    // Total threads that will actually be launched.
    out_aes_grid_total_threads = out_num_blocks_grid * out_thread_size_bs;

    // 4. Calculate required keystream buffer size.
    // Must be large enough to hold output from ALL launched threads,
    // not just needed ones, as all will write to memory.
    size_t required_keystream_bytes = out_aes_grid_total_threads * bytes_per_thread_per_call;

    // Convert to 32-bit words (uint32_t)
    out_keystream_buffer_size_words = (required_keystream_bytes + 3) / 4;

    // Ensure buffer is never smaller than original data (case of very small data)
    size_t data_size_words = (total_data_bytes + 3) / 4;
    if (out_keystream_buffer_size_words < data_size_words) {
        out_keystream_buffer_size_words = data_size_words;
    }

    // Guarantee minimum size to avoid allocating 0.
    if (out_keystream_buffer_size_words == 0) {
        out_keystream_buffer_size_words = 4; // Minimum for 1 AES block
    }
}


GcmEncryptionResult gcmEncrypt(
    const std::vector<uint8_t> &plaintext,
    const std::vector<uint8_t> &aad,
    const uint32_t *key_exp,
    const std::vector<uint8_t> &nonce,
    cudaStream_t stream) {
    GcmEncryptionResult result;
    result.success = false;
    GFC_LOG(GFC_LOG_LEVEL_INFO, "Starting GCM encryption on GPU...");

    if (nonce.size() != UTIL_NONCE_SIZE_BYTES) {
        GFC_LOG(GFC_LOG_LEVEL_ERROR, "GCM Encrypt: Incorrect Nonce size.");
        return result;
    }

    try {
        // --- 1. INITIAL PREPARATION (Derivation of H, Keys, Nonce) ---
        size_t padded_plaintext_size = ((plaintext.size() + 15) / 16) * 16;
        size_t padded_aad_size = ((aad.size() + 15) / 16) * 16;

        CudaManagedBuffer<uint32_t> d_key_exp_gpu(352 * sizeof(uint32_t), stream, "d_key_exp_gpu");
        cudaMemcpyAsync(d_key_exp_gpu.get(), key_exp, 352 * sizeof(uint32_t), cudaMemcpyHostToDevice, stream);

        CudaManagedBuffer<uint8_t> d_H(16, stream, "d_H");
        {
            CudaManagedBuffer<uint32_t> d_zero_nonce_packed(32 * sizeof(uint32_t), stream);
            cudaMemsetAsync(d_zero_nonce_packed.get(), 0, 32 * sizeof(uint32_t), stream);
            size_t num_blocks_grid_H, thread_size_bs_H, aes_grid_total_threads_H, keystream_buffer_size_words_H;
            calculate_aes_kernel_params(16, num_blocks_grid_H, thread_size_bs_H, aes_grid_total_threads_H,
                                        keystream_buffer_size_words_H);
            CudaManagedBuffer<uint32_t> d_keystream_H(keystream_buffer_size_words_H * sizeof(uint32_t), stream);
            aes128_encrypt_gpu_repeat_coalesced<<<num_blocks_grid_H, thread_size_bs_H, 0, stream>>>(
                d_keystream_H.get(), nullptr, d_key_exp_gpu.get(), d_zero_nonce_packed.get());
            cudaMemcpyAsync(d_H.get(), d_keystream_H.get(), 16, cudaMemcpyDeviceToDevice, stream);
        }

        size_t max_ghash_blocks = (padded_aad_size + padded_plaintext_size + 16) / 16;
        size_t num_h_powers = (max_ghash_blocks > 0) ? std::ceil(std::log2(max_ghash_blocks)) + 1 : 1;
        CudaManagedBuffer<uint8_t> d_H_powers(num_h_powers * 16, stream, "d_H_powers");
        generate_h_powers_kernel<<<1, 1, 0, stream>>>(d_H_powers.get(), d_H.get(), num_h_powers);

        // --- 1.5. EXPLICIT CALCULATION OF E_k(J0) FOR TAG ---
        CudaManagedBuffer<uint8_t> d_EK_J0(16, stream, "d_EK_J0");
        {
            uint32_t h_nonce_J0_packed[32] = {0};
            memcpy(h_nonce_J0_packed, nonce.data(), nonce.size());
            pack_nonce(h_nonce_J0_packed, h_nonce_J0_packed); // Prepares J0 (counter=1)

            CudaManagedBuffer<uint32_t> d_nonce_J0_packed(32 * sizeof(uint32_t), stream, "d_nonce_J0_packed");
            cudaMemcpyAsync(d_nonce_J0_packed.get(), h_nonce_J0_packed, 32 * sizeof(uint32_t), cudaMemcpyHostToDevice, stream);

            size_t num_blocks_grid_J0, thread_size_bs_J0, aes_grid_total_threads_J0, keystream_buffer_size_words_J0;
            calculate_aes_kernel_params(16, num_blocks_grid_J0, thread_size_bs_J0, aes_grid_total_threads_J0, keystream_buffer_size_words_J0);
            CudaManagedBuffer<uint32_t> d_keystream_J0_temp(keystream_buffer_size_words_J0 * sizeof(uint32_t), stream, "d_keystream_J0_temp");

            aes128_encrypt_gpu_repeat_coalesced<<<num_blocks_grid_J0, thread_size_bs_J0, 0, stream>>>(
                d_keystream_J0_temp.get(), nullptr, d_key_exp_gpu.get(), d_nonce_J0_packed.get());

            cudaMemcpyAsync(d_EK_J0.get(), d_keystream_J0_temp.get(), 16, cudaMemcpyDeviceToDevice, stream);
        }

        // --- 2. CTR ENCRYPTION (STARTING FROM J1) ---
        CudaManagedBuffer<uint8_t> d_plaintext(plaintext.size(), stream, "d_plaintext");
        CudaManagedBuffer<uint8_t> d_ciphertext(plaintext.size(), stream, "d_ciphertext");
        CudaManagedBuffer<uint32_t> d_nonce_packed(32 * sizeof(uint32_t), stream, "d_nonce_packed");

        cudaMemcpyAsync(d_plaintext.get(), plaintext.data(), plaintext.size(), cudaMemcpyHostToDevice, stream);
        uint32_t h_nonce_packed[32] = {0};
        memcpy(h_nonce_packed, nonce.data(), nonce.size());
        pack_nonce(h_nonce_packed, h_nonce_packed);

        uint32_t *counter_ptr = h_nonce_packed + 3;
        *counter_ptr = __bswap_32(__bswap_32(*counter_ptr) + 1);

        cudaMemcpyAsync(d_nonce_packed.get(), h_nonce_packed, 32 * sizeof(uint32_t), cudaMemcpyHostToDevice, stream);

        size_t num_blocks_grid, thread_size_bs, aes_grid_total_threads, keystream_buffer_size_words;
        calculate_aes_kernel_params(plaintext.size(), num_blocks_grid, thread_size_bs, aes_grid_total_threads,
                                    keystream_buffer_size_words);
        CudaManagedBuffer<uint32_t> d_keystream(keystream_buffer_size_words * sizeof(uint32_t), stream, "d_keystream");

        if (!plaintext.empty()) {
            aes128_encrypt_gpu_repeat_coalesced<<<num_blocks_grid, thread_size_bs, 0, stream>>>(
                d_keystream.get(), nullptr, d_key_exp_gpu.get(), d_nonce_packed.get());

            // --- CORRECTED XOR KERNEL LAUNCH LOGIC ---
            const size_t data_size = plaintext.size();
            const int threads_per_block = 256; // A common and efficient value
            const int blocks_per_grid = (data_size + threads_per_block - 1) / threads_per_block;

            xor_buffers_128bit_kernel<<<blocks_per_grid, threads_per_block, 0, stream>>>(
                d_ciphertext,
                d_plaintext,
                (uint8_t *) d_keystream.get(),
                data_size
            );
        }

        // --- 3. GHASH BUFFER PREPARATION (OPTIMIZED WITH PINNED MEMORY) ---
        size_t ghash_buffer_size = padded_aad_size + padded_plaintext_size + 16;
        CudaManagedBuffer<uint8_t> d_ghash_input(ghash_buffer_size, stream, "d_ghash_input");

        size_t host_part_size = padded_aad_size + 16;
        CudaPinnedHostBuffer<uint8_t> h_pinned_part(host_part_size);
        uint8_t *h_pinned_ptr = h_pinned_part.get();
        memset(h_pinned_ptr, 0, host_part_size);

        if (!aad.empty()) {
            memcpy(h_pinned_ptr, aad.data(), aad.size());
        }

        uint64_t aad_len_bits = aad.size() * 8ULL;
        uint64_t plaintext_len_bits = plaintext.size() * 8ULL;
        uint8_t *len_bytes_ptr = h_pinned_ptr + padded_aad_size;
        for (int i = 0; i < 8; ++i) {
            len_bytes_ptr[i] = (aad_len_bits >> (56 - i * 8)) & 0xFF;
            len_bytes_ptr[8 + i] = (plaintext_len_bits >> (56 - i * 8)) & 0xFF;
        }

        cudaMemsetAsync(d_ghash_input.get(), 0, ghash_buffer_size, stream);
        cudaMemcpyAsync(d_ghash_input.get(), h_pinned_ptr, padded_aad_size, cudaMemcpyHostToDevice, stream);
        if (!plaintext.empty()) {
            cudaMemcpyAsync(d_ghash_input.get() + padded_aad_size, d_ciphertext.get(), plaintext.size(),
                            cudaMemcpyDeviceToDevice, stream);
        }
        cudaMemcpyAsync(d_ghash_input.get() + padded_aad_size + padded_plaintext_size, len_bytes_ptr, 16,
                        cudaMemcpyHostToDevice, stream);

        // --- 4. GHASH CALCULATION (FINAL AND OPTIMIZED LOGIC) ---
        CudaManagedBuffer<uint8_t> d_ghash_result(16, stream, "d_ghash_result");
        size_t num_ghash_input_blocks = ghash_buffer_size / 16;
        int max_threads_per_block;
        cudaDeviceGetAttribute(&max_threads_per_block, cudaDevAttrMaxThreadsPerBlock, 0);

        if (num_ghash_input_blocks == 0) {
            cudaMemsetAsync(d_ghash_result.get(), 0, 16, stream);
        } else if (num_ghash_input_blocks <= max_threads_per_block) {
            unsigned int ghash_threads = 1;
            while (ghash_threads < num_ghash_input_blocks) ghash_threads *= 2;
            size_t shared_mem_size = ghash_threads * 16;

            ghash_parallel_reduction_kernel<<<1, ghash_threads, shared_mem_size, stream>>>(
                d_ghash_result.get(), d_ghash_input.get(), d_H_powers.get(), num_ghash_input_blocks,
                num_ghash_input_blocks);
        } else {
            const size_t blocks_per_chunk = max_threads_per_block;
            size_t grid_size = (num_ghash_input_blocks + blocks_per_chunk - 1) / blocks_per_chunk;

            CudaManagedBuffer<uint8_t> d_partial_results(grid_size * 16, stream, "d_partial_results");
            size_t shared_mem_size = blocks_per_chunk * 16;

            ghash_parallel_reduction_kernel<<<grid_size, blocks_per_chunk, shared_mem_size, stream>>>(
                d_partial_results.get(), d_ghash_input.get(), d_H_powers.get(), num_ghash_input_blocks,
                blocks_per_chunk);

            CudaManagedBuffer<uint8_t> d_H_power_chunk(16, stream, "d_H_power_chunk");
            gf128_power_kernel<<<1, 1, 0, stream>>>(d_H_power_chunk.get(), d_H.get(), blocks_per_chunk);

            uint8_t *d_H_power_last_chunk_ptr = nullptr;
            CudaManagedBuffer<uint8_t> d_H_power_last_chunk;
            size_t last_chunk_size = num_ghash_input_blocks % blocks_per_chunk;
            if (last_chunk_size != 0 && grid_size > 1) {
                d_H_power_last_chunk = CudaManagedBuffer<uint8_t>(16, stream, "d_H_power_last_chunk");
                gf128_power_kernel<<<1, 1, 0, stream>>>(d_H_power_last_chunk.get(), d_H.get(), last_chunk_size);
                d_H_power_last_chunk_ptr = d_H_power_last_chunk.get();
            }

            combine_partial_ghash_kernel<<<1, 1, 0, stream>>>(
                d_ghash_result.get(), d_partial_results.get(), d_H_power_chunk.get(), d_H_power_last_chunk_ptr,
                grid_size);
        }

        // --- 5. FINAL TAG CALCULATION AND RESULT COPY ---
        CudaManagedBuffer<uint8_t> d_auth_tag(16, stream, "d_auth_tag");
        xor_buffers_128bit_kernel<<<1, 16, 0, stream>>>(d_auth_tag.get(), d_ghash_result.get(), d_EK_J0.get(), 16);

        result.ciphertext.resize(plaintext.size());
        if (!plaintext.empty()) {
            cudaMemcpyAsync(result.ciphertext.data(), d_ciphertext.get(), plaintext.size(), cudaMemcpyDeviceToHost,
                            stream);
        }
        result.auth_tag.resize(16);
        cudaMemcpyAsync(result.auth_tag.data(), d_auth_tag.get(), 16, cudaMemcpyDeviceToHost, stream);

        cudaStreamSynchronize(stream);
        result.success = true;
    } catch (const std::runtime_error &e) {
        GFC_LOG(GFC_LOG_LEVEL_ERROR, "Exception in gcmEncrypt: %s", e.what());
        result.success = false;
    }
    return result;
}

// Compatibility implementation for std::vector
GcmDecryptionResult gcmDecrypt(
    const std::vector<uint8_t> &ciphertext,
    const std::vector<uint8_t> &aad,
    const std::vector<uint8_t> &auth_tag_from_file,
    const uint32_t *key_exp,
    const std::vector<uint8_t> &nonce,
    cudaStream_t stream,
    bool enable_kernel_timing) {

    return gcmDecrypt(
        ciphertext.data(),
        ciphertext.size(),
        aad,
        auth_tag_from_file,
        key_exp,
        nonce,
        stream,
        enable_kernel_timing
    );
}

// Optimized implementation with raw pointers
GcmDecryptionResult gcmDecrypt(
    const uint8_t* ciphertext_ptr,
    size_t ciphertext_size,
    const std::vector<uint8_t> &aad,
    const std::vector<uint8_t> &auth_tag_from_file,
    const uint32_t *key_exp,
    const std::vector<uint8_t> &nonce,
    cudaStream_t stream,
    bool enable_kernel_timing) {

    GcmDecryptionResult result;
    result.success = false;
    result.isAuthenticated = false;
    result.kernel_elapsed_ms = 0.0f;

    if (nonce.size() != UTIL_NONCE_SIZE_BYTES || auth_tag_from_file.size() != 16) {
        GFC_LOG(GFC_LOG_LEVEL_ERROR, "GCM Decrypt: Incorrect Nonce or Auth Tag size.");
        return result;
    }

    cudaEvent_t start = nullptr, stop = nullptr;
    if (enable_kernel_timing) {
        cudaEventCreate(&start);
        cudaEventCreate(&stop);
        cudaEventRecord(start, stream);
    }

    try {
        // --- 1. INITIAL PREPARATION (Derivation of H, Keys, Nonce) ---
        size_t padded_ciphertext_size = ((ciphertext_size + 15) / 16) * 16;
        size_t padded_aad_size = ((aad.size() + 15) / 16) * 16;

        CudaManagedBuffer<uint32_t> d_key_exp_gpu(352 * sizeof(uint32_t), stream, "d_key_exp_gpu");
        cudaMemcpyAsync(d_key_exp_gpu.get(), key_exp, 352 * sizeof(uint32_t), cudaMemcpyHostToDevice, stream);

        CudaManagedBuffer<uint8_t> d_H(16, stream, "d_H");
        {
            CudaManagedBuffer<uint32_t> d_zero_nonce_packed(32 * sizeof(uint32_t), stream);
            cudaMemsetAsync(d_zero_nonce_packed.get(), 0, 32 * sizeof(uint32_t), stream);
            size_t num_blocks_grid_H, thread_size_bs_H, aes_grid_total_threads_H, keystream_buffer_size_words_H;
            calculate_aes_kernel_params(16, num_blocks_grid_H, thread_size_bs_H, aes_grid_total_threads_H,
                                        keystream_buffer_size_words_H);
            CudaManagedBuffer<uint32_t> d_keystream_H(keystream_buffer_size_words_H * sizeof(uint32_t), stream);
            aes128_encrypt_gpu_repeat_coalesced<<<num_blocks_grid_H, thread_size_bs_H, 0, stream>>>(
                d_keystream_H.get(), nullptr, d_key_exp_gpu.get(), d_zero_nonce_packed.get());
            cudaMemcpyAsync(d_H.get(), d_keystream_H.get(), 16, cudaMemcpyDeviceToDevice, stream);
        }

        size_t max_ghash_blocks = (padded_aad_size + padded_ciphertext_size + 16) / 16;
        size_t num_h_powers = (max_ghash_blocks > 0) ? std::ceil(std::log2(max_ghash_blocks)) + 1 : 1;
        CudaManagedBuffer<uint8_t> d_H_powers(num_h_powers * 16, stream, "d_H_powers");
        generate_h_powers_kernel<<<1, 1, 0, stream>>>(d_H_powers.get(), d_H.get(), num_h_powers);

        // --- 1.5. EXPLICIT CALCULATION OF E_k(J0) FOR TAG VERIFICATION ---
        CudaManagedBuffer<uint8_t> d_EK_J0(16, stream, "d_EK_J0");
        {
            uint32_t h_nonce_J0_packed[32] = {0};
            memcpy(h_nonce_J0_packed, nonce.data(), nonce.size());
            pack_nonce(h_nonce_J0_packed, h_nonce_J0_packed);

            CudaManagedBuffer<uint32_t> d_nonce_J0_packed(32 * sizeof(uint32_t), stream, "d_nonce_J0_packed");
            cudaMemcpyAsync(d_nonce_J0_packed.get(), h_nonce_J0_packed, 32 * sizeof(uint32_t), cudaMemcpyHostToDevice, stream);

            size_t num_blocks_grid_J0, thread_size_bs_J0, aes_grid_total_threads_J0, keystream_buffer_size_words_J0;
            calculate_aes_kernel_params(16, num_blocks_grid_J0, thread_size_bs_J0, aes_grid_total_threads_J0, keystream_buffer_size_words_J0);
            CudaManagedBuffer<uint32_t> d_keystream_J0_temp(keystream_buffer_size_words_J0 * sizeof(uint32_t), stream, "d_keystream_J0_temp");

            aes128_encrypt_gpu_repeat_coalesced<<<num_blocks_grid_J0, thread_size_bs_J0, 0, stream>>>(
                d_keystream_J0_temp.get(), nullptr, d_key_exp_gpu.get(), d_nonce_J0_packed.get());

            cudaMemcpyAsync(d_EK_J0.get(), d_keystream_J0_temp.get(), 16, cudaMemcpyDeviceToDevice, stream);
        }

        // --- 2. GENERATE KEYSTREAM (STARTING FROM J1) AND PREPARE DATA ---
        CudaManagedBuffer<uint8_t> d_ciphertext(ciphertext_size, stream, "d_ciphertext");
        CudaManagedBuffer<uint8_t> d_plaintext(ciphertext_size, stream, "d_plaintext");
        CudaManagedBuffer<uint32_t> d_nonce_packed(32 * sizeof(uint32_t), stream, "d_nonce_packed");

        // OPTIMIZED COPY: If ciphertext_ptr is pinned memory, this will be very fast (direct DMA)
        cudaMemcpyAsync(d_ciphertext.get(), ciphertext_ptr, ciphertext_size, cudaMemcpyHostToDevice, stream);

        uint32_t h_nonce_packed[32] = {0};
        memcpy(h_nonce_packed, nonce.data(), nonce.size());
        pack_nonce(h_nonce_packed, h_nonce_packed);

        uint32_t *counter_ptr = h_nonce_packed + 3;
        *counter_ptr = __bswap_32(__bswap_32(*counter_ptr) + 1);

        cudaMemcpyAsync(d_nonce_packed.get(), h_nonce_packed, 32 * sizeof(uint32_t), cudaMemcpyHostToDevice, stream);

        size_t num_blocks_grid, thread_size_bs, aes_grid_total_threads, keystream_buffer_size_words;
        calculate_aes_kernel_params(ciphertext_size, num_blocks_grid, thread_size_bs, aes_grid_total_threads,
                                    keystream_buffer_size_words);
        CudaManagedBuffer<uint32_t> d_keystream(keystream_buffer_size_words * sizeof(uint32_t), stream, "d_keystream");

        if (ciphertext_size > 0) {
            aes128_encrypt_gpu_repeat_coalesced<<<num_blocks_grid, thread_size_bs, 0, stream>>>(
                d_keystream.get(), nullptr, d_key_exp_gpu.get(), d_nonce_packed.get());
        }

        // --- 3. GHASH BUFFER PREPARATION (OPTIMIZED WITH PINNED MEMORY) ---
        size_t ghash_buffer_size = padded_aad_size + padded_ciphertext_size + 16;
        CudaManagedBuffer<uint8_t> d_ghash_input(ghash_buffer_size, stream, "d_ghash_input");

        size_t host_part_size = padded_aad_size + 16;
        CudaPinnedHostBuffer<uint8_t> h_pinned_part(host_part_size);
        uint8_t *h_pinned_ptr = h_pinned_part.get();
        memset(h_pinned_ptr, 0, host_part_size);

        if (!aad.empty()) {
            memcpy(h_pinned_ptr, aad.data(), aad.size());
        }

        uint64_t aad_len_bits = aad.size() * 8ULL;
        uint64_t ciphertext_len_bits = ciphertext_size * 8ULL;
        uint8_t *len_bytes_ptr = h_pinned_ptr + padded_aad_size;
        for (int i = 0; i < 8; ++i) {
            len_bytes_ptr[i] = (aad_len_bits >> (56 - i * 8)) & 0xFF;
            len_bytes_ptr[8 + i] = (ciphertext_len_bits >> (56 - i * 8)) & 0xFF;
        }

        cudaMemsetAsync(d_ghash_input.get(), 0, ghash_buffer_size, stream);
        cudaMemcpyAsync(d_ghash_input.get(), h_pinned_ptr, padded_aad_size, cudaMemcpyHostToDevice, stream);
        if (ciphertext_size > 0) {
            cudaMemcpyAsync(d_ghash_input.get() + padded_aad_size, d_ciphertext.get(), ciphertext_size,
                            cudaMemcpyDeviceToDevice, stream);
        }
        cudaMemcpyAsync(d_ghash_input.get() + padded_aad_size + padded_ciphertext_size, len_bytes_ptr, 16,
                        cudaMemcpyHostToDevice, stream);

        // --- 4. GHASH CALCULATION (FINAL AND OPTIMIZED LOGIC) ---
        CudaManagedBuffer<uint8_t> d_recalculated_ghash_result(16, stream, "d_recalculated_ghash_result");
        size_t num_ghash_input_blocks = ghash_buffer_size / 16;
        int max_threads_per_block;
        cudaDeviceGetAttribute(&max_threads_per_block, cudaDevAttrMaxThreadsPerBlock, 0);

        if (num_ghash_input_blocks == 0) {
            cudaMemsetAsync(d_recalculated_ghash_result.get(), 0, 16, stream);
        } else if (num_ghash_input_blocks <= max_threads_per_block) {
            unsigned int ghash_threads = 1;
            while (ghash_threads < num_ghash_input_blocks) ghash_threads *= 2;
            size_t shared_mem_size = ghash_threads * 16;

            ghash_parallel_reduction_kernel<<<1, ghash_threads, shared_mem_size, stream>>>(
                d_recalculated_ghash_result.get(), d_ghash_input.get(), d_H_powers.get(), num_ghash_input_blocks,
                num_ghash_input_blocks);
        } else {
            const size_t blocks_per_chunk = max_threads_per_block;
            size_t grid_size = (num_ghash_input_blocks + blocks_per_chunk - 1) / blocks_per_chunk;

            CudaManagedBuffer<uint8_t> d_partial_results(grid_size * 16, stream, "d_partial_results");
            size_t shared_mem_size = blocks_per_chunk * 16;

            ghash_parallel_reduction_kernel<<<grid_size, blocks_per_chunk, shared_mem_size, stream>>>(
                d_partial_results.get(), d_ghash_input.get(), d_H_powers.get(), num_ghash_input_blocks,
                blocks_per_chunk);

            CudaManagedBuffer<uint8_t> d_H_power_chunk(16, stream, "d_H_power_chunk");
            gf128_power_kernel<<<1, 1, 0, stream>>>(d_H_power_chunk.get(), d_H.get(), blocks_per_chunk);

            uint8_t *d_H_power_last_chunk_ptr = nullptr;
            CudaManagedBuffer<uint8_t> d_H_power_last_chunk;
            size_t last_chunk_size = num_ghash_input_blocks % blocks_per_chunk;
            if (last_chunk_size != 0 && grid_size > 1) {
                d_H_power_last_chunk = CudaManagedBuffer<uint8_t>(16, stream, "d_H_power_last_chunk");
                gf128_power_kernel<<<1, 1, 0, stream>>>(d_H_power_last_chunk.get(), d_H.get(), last_chunk_size);
                d_H_power_last_chunk_ptr = d_H_power_last_chunk.get();
            }

            combine_partial_ghash_kernel<<<1, 1, 0, stream>>>(
                d_recalculated_ghash_result.get(), d_partial_results.get(), d_H_power_chunk.get(),
                d_H_power_last_chunk_ptr, grid_size);
        }

        // --- 5. TAG VERIFICATION AND FINAL DECRYPTION ---
        CudaManagedBuffer<uint8_t> d_recalculated_auth_tag(16, stream, "d_recalculated_auth_tag");
        xor_buffers_128bit_kernel<<<1, 16, 0, stream>>>(d_recalculated_auth_tag.get(),
                                                        d_recalculated_ghash_result.get(), d_EK_J0.get(), 16);

        std::vector<uint8_t> recalculated_tag_host(16);
        cudaMemcpyAsync(recalculated_tag_host.data(), d_recalculated_auth_tag.get(), 16, cudaMemcpyDeviceToHost,
                        stream);

        if (enable_kernel_timing) {
            cudaEventRecord(stop, stream);
            cudaEventSynchronize(stop);
            float ms = 0;
            cudaEventElapsedTime(&ms, start, stop);
            result.kernel_elapsed_ms = ms;
            cudaEventDestroy(start);
            cudaEventDestroy(stop);
        } else {
            cudaStreamSynchronize(stream);
        }

        if (memcmp(auth_tag_from_file.data(), recalculated_tag_host.data(), 16) == 0) {
            GFC_LOG(GFC_LOG_LEVEL_INFO, "GCM Verification Successful! Tag matches.");
            result.isAuthenticated = true;
            result.success = true;

            if (ciphertext_size > 0) {
                // --- CORRECTED XOR KERNEL LAUNCH LOGIC ---
                const size_t data_size = ciphertext_size;
                const int threads_per_block = 256;
                const int blocks_per_grid = (data_size + threads_per_block - 1) / threads_per_block;

                xor_buffers_128bit_kernel<<<blocks_per_grid, threads_per_block, 0, stream>>>(
                    d_plaintext,
                    d_ciphertext,
                    (uint8_t *) d_keystream.get(),
                    data_size
                );
            }
            result.plaintext.resize(ciphertext_size);

            std::vector<uint8_t> debug_keystream(32); // Copy first 32 bytes
            cudaMemcpy(debug_keystream.data(), d_keystream.get(), 32, cudaMemcpyDeviceToHost);

            if (ciphertext_size > 0) {
                cudaMemcpyAsync(result.plaintext.data(), d_plaintext.get(), ciphertext_size, cudaMemcpyDeviceToHost,
                                stream);
            }
            cudaStreamSynchronize(stream);
        } else {
            GFC_LOG(GFC_LOG_LEVEL_ERROR, "GCM VERIFICATION FAILED!!! Tag does NOT match.");
            result.isAuthenticated = false;
            result.plaintext.clear();
            result.success = false;
        }
    } catch (const std::runtime_error &e) {
        GFC_LOG(GFC_LOG_LEVEL_ERROR, "Exception in gcmDecrypt: %s", e.what());
        result.success = false;
        result.isAuthenticated = false;
        if (enable_kernel_timing) {
            cudaEventDestroy(start);
            cudaEventDestroy(stop);
        }
    }
    return result;
}
