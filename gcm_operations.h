// File: gcm_operations.h

#ifndef GCM_OPERATIONS_H
#define GCM_OPERATIONS_H

#include <vector>
#include <cstdint>
#include <stdexcept>

#include "cuda_runtime.h"

// Structure to return the GCM encryption result
struct GcmEncryptionResult {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> auth_tag; // The 16-byte tag
    bool success = false;
};

// Structure to return the GCM decryption result
struct GcmDecryptionResult {
    std::vector<uint8_t> plaintext;
    bool isAuthenticated = false; // The most important result: true if the tag matches
    bool success = false;
    float kernel_elapsed_ms = 0.0f; // Kernel execution time in ms (if enabled)
};

/**
 * @brief Performs a complete AES-128-GCM encryption operation on the GPU.
 *
 * @param plaintext The data to encrypt.
 * @param aad The Additional Authenticated Data (not encrypted, but authenticated).
 * @param key_exp Pointer to the expanded AES key (in host memory).
 * @param nonce The 12-byte (96-bit) nonce for this operation.
 * @param stream CUDA stream to enqueue operations (0 for default stream).
 * @return GcmEncryptionResult containing the ciphertext and authentication tag.
 */
GcmEncryptionResult gcmEncrypt(
    const std::vector<uint8_t> &plaintext,
    const std::vector<uint8_t> &aad,
    const uint32_t *key_exp,
    const std::vector<uint8_t> &nonce,
    cudaStream_t stream = 0
);

/**
 * @brief Performs a complete AES-128-GCM decryption and verification operation on the GPU.
 *        Overload for std::vector (compatibility).
 */
GcmDecryptionResult gcmDecrypt(
    const std::vector<uint8_t> &ciphertext,
    const std::vector<uint8_t> &aad,
    const std::vector<uint8_t> &auth_tag_from_file,
    const uint32_t *key_exp,
    const std::vector<uint8_t> &nonce,
    cudaStream_t stream = 0,
    bool enable_kernel_timing = false
);

/**
 * @brief Performs a complete AES-128-GCM decryption and verification operation on the GPU.
 *        Optimized version that accepts raw pointers (ideal for pinned memory).
 *
 * @param ciphertext_ptr Pointer to the ciphertext buffer.
 * @param ciphertext_size Size of the ciphertext in bytes.
 * @param aad The same AAD used during encryption.
 * @param auth_tag_from_file The 16-byte authentication tag read from the file.
 * @param key_exp Pointer to the expanded AES key (in host memory).
 * @param nonce The 12-byte (96-bit) nonce used in encryption.
 * @param stream CUDA stream to enqueue operations (0 for default stream).
 * @param enable_kernel_timing If true, measures kernel execution time with cudaEvent.
 * @return GcmDecryptionResult containing the plaintext and the authentication success flag.
 */
GcmDecryptionResult gcmDecrypt(
    const uint8_t* ciphertext_ptr,
    size_t ciphertext_size,
    const std::vector<uint8_t> &aad,
    const std::vector<uint8_t> &auth_tag_from_file,
    const uint32_t *key_exp,
    const std::vector<uint8_t> &nonce,
    cudaStream_t stream = 0,
    bool enable_kernel_timing = false
);


template<typename T>
struct CudaPinnedHostBuffer {
    T *ptr = nullptr;
    size_t size_bytes = 0;

    CudaPinnedHostBuffer(size_t bytes) : size_bytes(bytes) {
        if (size_bytes > 0) {
            cudaError_t err = cudaMallocHost(&ptr, size_bytes);
            if (err != cudaSuccess) {
                // In a real product, you would handle the error more gracefully
                throw std::runtime_error("cudaMallocHost failed.");
            }
        }
    }

    ~CudaPinnedHostBuffer() {
        if (ptr) {
            cudaFreeHost(ptr);
        }
    }

    // Prevent copies
    CudaPinnedHostBuffer(const CudaPinnedHostBuffer &) = delete;

    CudaPinnedHostBuffer &operator=(const CudaPinnedHostBuffer &) = delete;

    // Allow movement
    CudaPinnedHostBuffer(CudaPinnedHostBuffer &&other) noexcept : ptr(other.ptr), size_bytes(other.size_bytes) {
        other.ptr = nullptr;
    }

    CudaPinnedHostBuffer &operator=(CudaPinnedHostBuffer &&other) noexcept {
        if (this != &other) {
            if (ptr) cudaFreeHost(ptr);
            ptr = other.ptr;
            size_bytes = other.size_bytes;
            other.ptr = nullptr;
        }
        return *this;
    }

    T *get() const { return ptr; }
};

#endif // GCM_OPERATIONS_H
