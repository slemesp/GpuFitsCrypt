// File: kernel.cu
#include "cuda_runtime.h"
// #include "device_launch_parameters.h"

#include "libgpufitscrypt.h"
#include "lib_internal_utils.h"     // For GFC_LOG, helpers, UTIL_NONCE_SIZE_BYTES
#include "fits_crypto_operations.h" // For _from_file (used by the via_tempfile version)
#include "gpu_utils.h"              // For processDataWithGPU (used by the _to_ram_buffer version)

// // #include "kernel.h" // Your kernel.h declarations
#include "aes.h"    // For aes128_keyschedule_lut, pack_nonce
// #include "tables.h" // If needed
// #include "internal-aes.h" // If needed
#include <time.h>

#include <string>
#include <vector>
#include <cstdio>
#include <cstring>

#include <stdexcept>
#include <chrono>   // For std::chrono if used in temp file name generation
#include <random>   // <--- Added for Nonce generation

#include "gcm_operations.h"

// =======================================================
// === 1. COMPLETE CONTEXT DEFINITIONS                 ===
// =======================================================
// Decryption context
struct DecryptorContext {
    unsigned char *h_final_buffer_pinned;
    unsigned char *h_read_buffer_pinned;
    size_t max_output_size;
    size_t max_read_size;
    cudaStream_t streamH;
    cudaStream_t streamD;
    bool enable_kernel_timing; // Flag to enable kernel timing
};

// Encryption context
struct EncryptorContext {
    // Buffer to read the original header and image data from the input file
    unsigned char *h_input_data_buffer_pinned;
    // Buffer to prepare the header (converted to string) before encrypting
    unsigned char *h_header_work_buffer_pinned;
    size_t max_input_data_size;
    size_t max_header_work_size;
    cudaStream_t streamH;
    cudaStream_t streamD;
};

// ===================================================================
// === 2. FORWARD DECLARATIONS FOR UNIFIED INTERNAL FUNCTIONS      ===
// ===================================================================
// Unified internal function to decrypt (AES-256-CTR)
static FitsOperationResult decrypt_fits_internal(
    const char *encrypted_fits_path_cstr,
    const char *key_hex_header_cstr,
    const char *key_hex_data_cstr,
    DecryptorContext *ctx,
    bool use_context);

// Unified internal function to decrypt (AES-256-GCM)
static FitsOperationResult decrypt_fits_internal_gcm(
    const char *encrypted_fits_path_cstr,
    const char *key_hex_header_cstr,
    const char *key_hex_data_cstr,
    DecryptorContext *ctx,
    bool use_context);

// Unified internal function to encrypt (AES-256-CTR)
static FitsOperationResult encrypt_fits_internal(
    const char *input_fits_path_cstr,
    const char *output_encrypted_path_cstr,
    const char *key_hex_header_cstr,
    const char *key_hex_data_cstr,
    EncryptorContext *ctx,
    bool use_context);

// Unified internal function to encrypt (AES-256-GCM)
static FitsOperationResult encrypt_fits_internal_gcm(
    const char *input_fits_path_cstr,
    const char *output_encrypted_path_cstr,
    const char *key_hex_header_cstr,
    const char *key_hex_data_cstr,
    EncryptorContext *ctx,
    bool use_context);

// Internal function to encrypt from memory (GCM)
static FitsOperationResult encrypt_raw_gcm_internal(
    const char *output_path,
    const char *header_str, size_t header_len,
    const void *data_ptr, size_t data_len,
    int bitpix, int naxis, const long *naxes,
    const char *key_h, const char *key_d,
    EncryptorContext *ctx, bool use_context);

// =======================================================
// === 3. PUBLIC API IMPLEMENTATION (extern "C")      ===
// =======================================================
extern "C" {
void gfc_set_log_level(int level) {
    // Call the internal implementation that updates g_gfc_log_level_actual
    // gfc_set_log_level_impl is defined in lib_internal_utils.cpp
    // and g_gfc_log_level_actual is a global in lib_internal_utils.cpp
    gfc_set_log_level_impl(level);
}

int gfc_get_log_level() {
    // Call the internal implementation
    return gfc_get_log_level_impl();
}

// --- NEW PUBLIC API FOR ENCRYPTION ---
EncryptorContext *gfc_encrypt_context_create(size_t max_input_data_buffer_size, size_t max_header_work_buffer_size) {
    auto *ctx = new(std::nothrow) EncryptorContext();
    if (!ctx) {
        GFC_LOG(GFC_LOG_LEVEL_ERROR, "gfc_encrypt_context_create: Failed to allocate context structure.");
        return nullptr;
    }

    ctx->h_input_data_buffer_pinned = nullptr;
    ctx->h_header_work_buffer_pinned = nullptr;
    ctx->streamH = nullptr;
    ctx->streamD = nullptr;
    ctx->max_input_data_size = max_input_data_buffer_size;
    ctx->max_header_work_size = max_header_work_buffer_size;

    cudaError_t err;

    // --- FIRST ALLOCATION ---
    err = cudaMallocHost((void **) &ctx->h_input_data_buffer_pinned, max_input_data_buffer_size);
    if (err != cudaSuccess) {
        GFC_LOG(GFC_LOG_LEVEL_ERROR, "gfc_encrypt_context_create: cudaMallocHost failed for input_data (%zu bytes): %s", max_input_data_buffer_size, cudaGetErrorString(err));
        delete ctx;
        return nullptr;
    }

    // --- SECOND ALLOCATION ---
    err = cudaMallocHost((void **) &ctx->h_header_work_buffer_pinned, max_header_work_buffer_size);
    if (err != cudaSuccess) {
        GFC_LOG(GFC_LOG_LEVEL_ERROR, "gfc_encrypt_context_create: cudaMallocHost failed for header_work (%zu bytes): %s", max_header_work_buffer_size, cudaGetErrorString(err));
        cudaFreeHost(ctx->h_input_data_buffer_pinned);
        delete ctx;
        return nullptr;
    }

    cudaStreamCreate(&ctx->streamH);
    cudaStreamCreate(&ctx->streamD);

    return ctx;
}

void gfc_encrypt_context_destroy(EncryptorContext *ctx) {
    if (!ctx) return;
    if (ctx->h_input_data_buffer_pinned) cudaFreeHost(ctx->h_input_data_buffer_pinned);
    if (ctx->h_header_work_buffer_pinned) cudaFreeHost(ctx->h_header_work_buffer_pinned);
    if (ctx->streamH) cudaStreamDestroy(ctx->streamH);
    if (ctx->streamD) cudaStreamDestroy(ctx->streamD);
    delete ctx;
}

// Wrapper without context (original function, now calls the internal one)
FitsOperationResult gfc_encrypt_file_ctr_without_context(
    const char *input_fits_path_cstr,
    const char *output_encrypted_path_cstr,
    const char *key_hex_header_cstr,
    const char *key_hex_data_cstr) {
    return encrypt_fits_internal(input_fits_path_cstr, output_encrypted_path_cstr, key_hex_header_cstr,
                                 key_hex_data_cstr, nullptr, false);
}

// Wrapper WITH context (new public function)
FitsOperationResult gfc_encrypt_file_ctr(
    EncryptorContext *ctx,
    const char *input_fits_path_cstr,
    const char *output_encrypted_path_cstr,
    const char *key_hex_header_cstr,
    const char *key_hex_data_cstr) {
    return encrypt_fits_internal(input_fits_path_cstr, output_encrypted_path_cstr, key_hex_header_cstr,
                                 key_hex_data_cstr, ctx, true);
}


// --- PUBLIC API FOR DECRYPTION
DecryptorContext *gfc_context_create(size_t max_output_buffer_size, size_t max_read_buffer_size) {
    DecryptorContext *ctx = new(std::nothrow) DecryptorContext();
    if (!ctx) {
        GFC_LOG(GFC_LOG_LEVEL_ERROR, "gfc_context_create: Failed to allocate context structure.");
        return nullptr;
    }

    ctx->h_final_buffer_pinned = nullptr;
    ctx->h_read_buffer_pinned = nullptr;
    ctx->streamH = nullptr;
    ctx->streamD = nullptr;
    ctx->max_output_size = max_output_buffer_size;
    ctx->max_read_size = max_read_buffer_size;
    ctx->enable_kernel_timing = false; // Disabled by default

    cudaError_t err;
    err = cudaMallocHost((void **) &ctx->h_final_buffer_pinned, max_output_buffer_size);
    if (err != cudaSuccess) {
        GFC_LOG(GFC_LOG_LEVEL_ERROR, "gfc_context_create: cudaMallocHost failed for final_buffer (%zu bytes): %s", max_output_buffer_size, cudaGetErrorString(err));
        delete ctx;
        return nullptr;
    }

    err = cudaMallocHost((void **) &ctx->h_read_buffer_pinned, max_read_buffer_size);
    if (err != cudaSuccess) {
        GFC_LOG(GFC_LOG_LEVEL_ERROR, "gfc_context_create: cudaMallocHost failed for read_buffer (%zu bytes): %s", max_read_buffer_size, cudaGetErrorString(err));
        cudaFreeHost(ctx->h_final_buffer_pinned);
        delete ctx;
        return nullptr;
    }

    cudaStreamCreate(&ctx->streamH);
    cudaStreamCreate(&ctx->streamD);

    return ctx;
}

void gfc_context_destroy(DecryptorContext *ctx) {
    if (!ctx) {
        return;
    }
    if (ctx->h_final_buffer_pinned) cudaFreeHost(ctx->h_final_buffer_pinned);
    if (ctx->h_read_buffer_pinned) cudaFreeHost(ctx->h_read_buffer_pinned);
    if (ctx->streamH) cudaStreamDestroy(ctx->streamH);
    if (ctx->streamD) cudaStreamDestroy(ctx->streamD);
    delete ctx;
}

void gfc_context_set_use_kernel_timing(DecryptorContext *ctx, bool enabled) {
    if (ctx) {
        ctx->enable_kernel_timing = enabled;
    }
}

void free_fits_operation_result(FitsOperationResult *result) {
    if (!result || !result->data_buffer) {
        return;
    }

    // For now, assume that if there was no error, the memory is pinned.
    // A more robust version could include a flag in the struct.
    if (result->error_code == 0) {
        GFC_LOG(GFC_LOG_LEVEL_DEBUG,
                "(LibAPI) Freeing pinned FitsOperationResult buffer (data at %p, size %zu) with cudaFreeHost.",
                result->data_buffer, result->buffer_size);
        cudaFreeHost(result->data_buffer);
    } else {
        // On error, or in the NO_KEY path, memory was allocated with malloc.
        GFC_LOG(GFC_LOG_LEVEL_DEBUG,
                "(LibAPI) Freeing standard FitsOperationResult buffer (data at %p, size %zu) with free.",
                result->data_buffer, result->buffer_size);
        free(result->data_buffer);
    }

    result->data_buffer = nullptr;
    result->buffer_size = 0;
}

// Wrapper without context
FitsOperationResult gfc_decrypt_frame_ctr_without_context(
    const char *encrypted_fits_path_cstr,
    const char *key_hex_header_cstr,
    const char *key_hex_data_cstr) {
    // Call the unified internal function
    return decrypt_fits_internal(encrypted_fits_path_cstr, key_hex_header_cstr, key_hex_data_cstr, nullptr, false);
}

// Wrapper WITH context
FitsOperationResult gfc_decrypt_frame_ctr(
    DecryptorContext *ctx,
    const char *encrypted_fits_path_cstr,
    const char *key_hex_header_cstr,
    const char *key_hex_data_cstr) {
    // Call the unified internal function
    return decrypt_fits_internal(encrypted_fits_path_cstr, key_hex_header_cstr, key_hex_data_cstr, ctx, true);
}

// --- NEW PUBLIC API FUNCTIONS FOR GCM ENCRYPTION ---
FitsOperationResult gfc_encrypt_file_without_context(
    const char *input_fits_path_cstr,
    const char *output_encrypted_path_cstr,
    const char *key_hex_header_cstr,
    const char *key_hex_data_cstr) {
    return encrypt_fits_internal_gcm(input_fits_path_cstr, output_encrypted_path_cstr, key_hex_header_cstr,
                                     key_hex_data_cstr, nullptr, false);
}

// // --- NEW PUBLIC API FUNCTIONS FOR GCM DECRYPTION ---
// FitsOperationResult gfc_decrypt_frame_ctr_without_context_gcm(
//     const char *encrypted_fits_path_cstr,
//     const char *key_hex_header_cstr,
//     const char *key_hex_data_cstr) {
//     return decrypt_fits_internal_gcm(encrypted_fits_path_cstr, key_hex_header_cstr, key_hex_data_cstr, nullptr, false);
// }

FitsOperationResult gfc_encrypt_file(
    EncryptorContext *ctx,
    const char *input_fits_path_cstr,
    const char *output_encrypted_path_cstr,
    const char *key_hex_header_cstr,
    const char *key_hex_data_cstr) {
    return encrypt_fits_internal_gcm(input_fits_path_cstr, output_encrypted_path_cstr, key_hex_header_cstr,
                                     key_hex_data_cstr, ctx, true);
}


FitsOperationResult gfc_decrypt_frame(
    DecryptorContext *ctx,
    const char *encrypted_fits_path_cstr,
    const char *key_hex_header_cstr,
    const char *key_hex_data_cstr) {
    return decrypt_fits_internal_gcm(encrypted_fits_path_cstr, key_hex_header_cstr, key_hex_data_cstr, ctx, true);
}

FitsOperationResult gfc_encrypt_frame(
    EncryptorContext *ctx,
    const char *output_path,
    const char *header_str, size_t header_len,
    const void *data_ptr, size_t data_len,
    int bitpix, int naxis, const long *naxes,
    const char *key_h, const char *key_d
) {
    return encrypt_raw_gcm_internal(output_path, header_str, header_len, data_ptr, data_len, bitpix, naxis, naxes, key_h, key_d, ctx, ctx != nullptr);
}

} // End of extern "C"

// ===================================================================
// === 4. COMPLETE IMPLEMENTATION OF UNIFIED INTERNAL FUNCTION     ===
// ===================================================================
// Helper to compute time difference in seconds
static double get_time_diff_s(struct timespec *start, struct timespec *end) {
    return (end->tv_sec - start->tv_sec) + (end->tv_nsec - start->tv_nsec) / 1e9;
}

// Full internal implementation for ENCRYPTION
static FitsOperationResult encrypt_fits_internal(
    const char *input_fits_path_cstr,
    const char *output_encrypted_path_cstr,
    const char *key_hex_header_cstr,
    const char *key_hex_data_cstr,
    EncryptorContext *ctx,
    bool use_context) {
    struct timespec t_start_total, t_end_total;
    clock_gettime(CLOCK_MONOTONIC, &t_start_total);

    // 1. Initialize the result and local resources
    FitsOperationResult result = {nullptr, 0, -401, 0, ""};
    strncpy(result.error_message, "Initial error in encryption (internal).", sizeof(result.error_message) - 1);

    // NOTE: For this refactor, the `encrypt_fits_file` function still manages
    // its own internal memory. Therefore, we do not use the context buffers
    // (`ctx->h_input_data_buffer_pinned`, etc.) directly here.
    // However, we do manage CUDA streams, laying the groundwork for a future
    // optimization where `encrypt_fits_file` can accept pre-allocated buffers.
    cudaStream_t streamH = nullptr, streamD = nullptr;

    if (use_context) {
        if (!ctx) {
            snprintf(result.error_message, sizeof(result.error_message),
                     "Internal error: context was expected but is NULL.");
            result.error_code = -502; // Specific error code for context encryption
            return result;
        }
        // "Borrow" streams from the context
        streamH = ctx->streamH;
        streamD = ctx->streamD;
    } else {
        // Create streams only for this operation
        cudaStreamCreate(&streamH);
        cudaStreamCreate(&streamD);
    }

    GFC_LOG(GFC_LOG_LEVEL_INFO, "🔒 (LibAPI) Starting encryption of '%s' to '%s' (Context: %s)",
            input_fits_path_cstr, output_encrypted_path_cstr, use_context ? "Yes" : "No");

    // 2. Validate input arguments
    if (!input_fits_path_cstr || !output_encrypted_path_cstr || !key_hex_header_cstr || !key_hex_data_cstr) {
        snprintf(result.error_message, sizeof(result.error_message), "One or more path/key arguments are NULL.");
        result.error_code = -402;
        // Resource cleanup if not using context
        if (!use_context) {
            if (streamH) cudaStreamDestroy(streamH);
            if (streamD) cudaStreamDestroy(streamD);
        }
        return result;
    }

    // 3. Run the main encryption logic
    try {
        uint32_t h_aes_key_exp_header[352];
        uint32_t h_aes_key_exp_data[352];
        uint8_t key_bytes_h[16];
        uint8_t key_bytes_d[16];

        // Convert and expand AES keys
        if (!hex_string_to_bytes_util(key_hex_header_cstr, key_bytes_h, 16)) {
            throw std::runtime_error("Invalid hex header key.");
        }
        if (!hex_string_to_bytes_util(key_hex_data_cstr, key_bytes_d, 16)) {
            throw std::runtime_error("Invalid hex data key.");
        }

        aes128_keyschedule_lut(h_aes_key_exp_header, key_bytes_h);
        aes128_keyschedule_lut(h_aes_key_exp_data, key_bytes_d);

        // Call the worker function that does the heavy lifting
        bool success = encrypt_fits_file(
            input_fits_path_cstr,
            output_encrypted_path_cstr,
            h_aes_key_exp_header,
            h_aes_key_exp_data
        );

        if (!success) {
            // If the internal function fails, throw to be handled below
            throw std::runtime_error(
                "Internal encryption operation (encrypt_fits_file) failed. See logs for details.");
        }

        // If everything went well, set success code
        result.error_code = 0;
        strncpy(result.error_message, "Success (encryption to file).", sizeof(result.error_message) - 1);
    } catch (const std::runtime_error &e) {
        // Catch any exception and populate the result struct
        if (result.error_code >= 0) result.error_code = -400; // Generic error code for exceptions
        strncpy(result.error_message, e.what(), sizeof(result.error_message) - 1);
        GFC_LOG(GFC_LOG_LEVEL_ERROR, "(LibAPI-Encrypt) Exception: %s", e.what());
    }

    // 4. Resource cleanup
    // If we are NOT using a context, we must destroy the streams we created.
    if (!use_context) {
        if (streamH) cudaStreamDestroy(streamH);
        if (streamD) cudaStreamDestroy(streamD);
    }

    // 5. Finalize and return the result
    clock_gettime(CLOCK_MONOTONIC, &t_end_total);
    result.time_total_c_function_s = get_time_diff_s(&t_start_total, &t_end_total);

    return result;
}


static FitsOperationResult decrypt_fits_internal(
    const char *encrypted_fits_path_cstr,
    const char *key_hex_header_cstr,
    const char *key_hex_data_cstr,
    DecryptorContext *ctx,
    bool use_context) {
    struct timespec t_start_total, t_end_total;
    struct timespec t_start_section, t_end_section;
    clock_gettime(CLOCK_MONOTONIC, &t_start_total);

    FitsOperationResult result = {nullptr, 0, -999, 0, ""};
    result.time_total_c_function_s = 0.0;
    result.time_open_fits_file_s = 0.0;
    result.time_read_primary_hdu_meta_s = 0.0;
    result.time_data_section_read_s = 0.0;
    result.time_data_decryption_gpu_s = 0.0;
    result.time_data_decryption_gpu_kernel_s = 0.0;
    result.time_header_processing_s = 0.0;
    result.time_final_assembly_s = 0.0;
    strncpy(result.error_message, "Initial error (internal).", sizeof(result.error_message) - 1);

    unsigned char *h_final_buffer_pinned = nullptr;
    unsigned char *h_read_buffer_pinned = nullptr;
    cudaStream_t streamH = nullptr, streamD = nullptr;
    size_t max_output_size = 0, max_read_size = 0;
    bool enable_kernel_timing = false;

    if (use_context) {
        if (!ctx) {
            snprintf(result.error_message, sizeof(result.error_message),
                     "Internal error: context was expected but is NULL.");
            result.error_code = -302;
            return result;
        }
        h_final_buffer_pinned = ctx->h_final_buffer_pinned;
        h_read_buffer_pinned = ctx->h_read_buffer_pinned;
        streamH = ctx->streamH;
        streamD = ctx->streamD;
        max_output_size = ctx->max_output_size;
        max_read_size = ctx->max_read_size;
        enable_kernel_timing = ctx->enable_kernel_timing;
    } else {
        cudaStreamCreate(&streamH);
        cudaStreamCreate(&streamD);
    }

    if (!encrypted_fits_path_cstr) {
        snprintf(result.error_message, sizeof(result.error_message), "Input file path is NULL.");
        result.error_code = -1002;
        if (!use_context) {
            cudaStreamDestroy(streamH);
            cudaStreamDestroy(streamD);
        }
        return result;
    }

    uint32_t h_aes_key_exp_header_arr[352], h_aes_key_exp_data_arr[352];
    uint32_t *p_h_aes_key_exp_header = nullptr, *p_d_aes_key_exp_data = nullptr;

    bool no_header_key_input = (!key_hex_header_cstr || strcmp(key_hex_header_cstr, "NO_KEY") == 0 || strlen(
                                    key_hex_header_cstr) == 0);
    bool no_data_key_input = (!key_hex_data_cstr || strcmp(key_hex_data_cstr, "NO_KEY") == 0 || strlen(
                                  key_hex_data_cstr) == 0);

    if (!no_header_key_input) {
        uint8_t key_bytes_h[16];
        if (!hex_string_to_bytes_util(key_hex_header_cstr, key_bytes_h, 16)) {
            snprintf(result.error_message, sizeof(result.error_message), "Invalid hex header key.");
            result.error_code = -1003;
            if (!use_context) {
                cudaStreamDestroy(streamH);
                cudaStreamDestroy(streamD);
            }
            return result;
        }
        aes128_keyschedule_lut(h_aes_key_exp_header_arr, key_bytes_h);
        p_h_aes_key_exp_header = h_aes_key_exp_header_arr;
    }
    if (!no_data_key_input) {
        uint8_t key_bytes_d[16];
        if (!hex_string_to_bytes_util(key_hex_data_cstr, key_bytes_d, 16)) {
            snprintf(result.error_message, sizeof(result.error_message), "Invalid hex data key.");
            result.error_code = -1004;
            if (!use_context) {
                cudaStreamDestroy(streamH);
                cudaStreamDestroy(streamD);
            }
            return result;
        }
        aes128_keyschedule_lut(h_aes_key_exp_data_arr, key_bytes_d);
        p_d_aes_key_exp_data = h_aes_key_exp_data_arr;
    }

    if (no_header_key_input && no_data_key_input) {
        // Logic for when there are no keys: just read the file and return it as-is.
        std::vector<uint8_t> file_content_vec;
        if (!read_file_into_vector_util(encrypted_fits_path_cstr, file_content_vec, result.error_message,
                                        sizeof(result.error_message))) {
            result.error_code = -1010;
        } else if (file_content_vec.empty()) {
            result.data_buffer = nullptr;
            result.buffer_size = 0;
            result.error_code = -998; // <--- CHANGE: No keys provided
            strncpy(result.error_message, "Success (empty buffer).", sizeof(result.error_message) - 1);
        } else {
            result.data_buffer = (unsigned char *) malloc(file_content_vec.size());
            if (!result.data_buffer) {
                strncpy(result.error_message, "malloc failed for copy.", sizeof(result.error_message) - 1);
                result.error_code = -1011;
            } else {
                memcpy(result.data_buffer, file_content_vec.data(), file_content_vec.size());
                result.buffer_size = file_content_vec.size();
                result.error_code = -998; // <--- CHANGE: No keys provided
                strncpy(result.error_message, "Success (copy to RAM buffer).", sizeof(result.error_message) - 1);
            }
        }
        if (!use_context) {
            cudaStreamDestroy(streamH);
            cudaStreamDestroy(streamD);
        }
        clock_gettime(CLOCK_MONOTONIC, &t_end_total);
        result.time_total_c_function_s = get_time_diff_s(&t_start_total, &t_end_total);
        return result;
    }

    fitsfile *fptr_in = nullptr;
    int status = 0;
    char err_text[FLEN_ERRMSG];
    std::vector<uint8_t> enchdr_encrypted_bytes;
    GpuWorkloadPointers pointersH = {}, pointersD = {};

    try {
        clock_gettime(CLOCK_MONOTONIC, &t_start_section);
        if (fits_open_file(&fptr_in, encrypted_fits_path_cstr, READONLY, &status)) {
            fits_get_errstatus(status, err_text);
            throw std::runtime_error(std::string("FITS: Error opening input: ") + err_text);
        }
        clock_gettime(CLOCK_MONOTONIC, &t_end_section);
        result.time_open_fits_file_s = get_time_diff_s(&t_start_section, &t_end_section);

        clock_gettime(CLOCK_MONOTONIC, &t_start_section);
        fits_movabs_hdu(fptr_in, 1, NULL, &status);
        if (status) {
            fits_get_errstatus(status, err_text);
            throw std::runtime_error(std::string("FITS: Error movabs_hdu to HDU 1: ") + err_text);
        }
        std::vector<uint8_t> nonce_H_vec, nonce_D_vec;
        std::string enchdr_hex_str;
        int s_img_bitpix_orig_temp = 0, s_img_naxis_orig_temp = 0;
        long s_img_naxes_orig_temp[9];
        std::fill_n(s_img_naxes_orig_temp, 9, 1L);
        char *temp_longstr = nullptr;
        if (fits_read_key_longstr(fptr_in, "NONCE_H", &temp_longstr, NULL, &status) || !temp_longstr || !*
            temp_longstr) {
            if (temp_longstr) free(temp_longstr);
            throw std::runtime_error("FITS: Error or empty while reading NONCE_H");
        }
        nonce_H_vec = fitsStringToNonce_util(temp_longstr);
        free(temp_longstr);
        temp_longstr = nullptr;
        if (fits_read_key_longstr(fptr_in, "NONCE_D", &temp_longstr, NULL, &status) || !temp_longstr || !*
            temp_longstr) {
            if (temp_longstr) free(temp_longstr);
            throw std::runtime_error("FITS: Error or empty while reading NONCE_D");
        }
        nonce_D_vec = fitsStringToNonce_util(temp_longstr);
        free(temp_longstr);
        temp_longstr = nullptr;
        if (p_h_aes_key_exp_header) {
            if (fits_read_key_longstr(fptr_in, "ENCHDR", &temp_longstr, NULL, &status) || !temp_longstr || !*
                temp_longstr) {
                if (temp_longstr) free(temp_longstr);
                throw std::runtime_error("FITS: Error or empty while reading ENCHDR");
            }
            enchdr_hex_str = temp_longstr;
            free(temp_longstr);
            temp_longstr = nullptr;
            enchdr_encrypted_bytes = hex_string_to_bytes_vec_util(enchdr_hex_str);
        }
        if (fits_read_key(fptr_in, TINT, "ORIG_BPX", &s_img_bitpix_orig_temp, NULL, &status) || status)
            throw std::runtime_error("FITS: Missing ORIG_BPX");
        if (fits_read_key(fptr_in, TINT, "ORIG_NAX", &s_img_naxis_orig_temp, NULL, &status) || status)
            throw std::runtime_error("FITS: Missing ORIG_NAX");
        for (int i = 0; i < s_img_naxis_orig_temp; ++i) {
            char keyname[FLEN_KEYWORD];
            snprintf(keyname, sizeof(keyname), "ORIG_NA%d", i + 1);
            if (fits_read_key(fptr_in, TLONG, keyname, &s_img_naxes_orig_temp[i], NULL, &status) || status)
                throw std::runtime_error(std::string("FITS: Missing ") + keyname);
        }
        clock_gettime(CLOCK_MONOTONIC, &t_end_section);
        result.time_read_primary_hdu_meta_s = get_time_diff_s(&t_start_section, &t_end_section);

        clock_gettime(CLOCK_MONOTONIC, &t_start_section);
        size_t header_decrypted_size = p_h_aes_key_exp_header ? enchdr_encrypted_bytes.size() : FITS_BLOCK_SIZE;
        long data_original_size = 0;
        if (s_img_naxis_orig_temp > 0) {
            data_original_size = (long) (std::abs(s_img_bitpix_orig_temp) / 8);
            for (int i = 0; i < s_img_naxis_orig_temp; ++i) data_original_size *= s_img_naxes_orig_temp[i];
        }
        size_t data_padded_size = ((data_original_size + FITS_BLOCK_SIZE - 1) / FITS_BLOCK_SIZE) * FITS_BLOCK_SIZE;
        size_t required_output_size = header_decrypted_size + data_padded_size;
        result.buffer_size = required_output_size;

        if (use_context) {
            if (required_output_size > max_output_size || (size_t) data_original_size > max_read_size) {
                char msg[256];
                snprintf(msg, sizeof(msg), "Required size exceeds context capacity.");
                throw std::runtime_error(msg);
            }
        } else {
            if (required_output_size > 0) {
                cudaError_t err = cudaMallocHost((void **) &h_final_buffer_pinned, required_output_size);
                if (err != cudaSuccess) throw std::runtime_error("cudaMallocHost failed for final_buffer");
            }
        }

        // FIX: Zero-initialize buffer to prevent stale data
        if (h_final_buffer_pinned && required_output_size > 0) {
             memset(h_final_buffer_pinned, 0, required_output_size);
        }

        clock_gettime(CLOCK_MONOTONIC, &t_end_section);
        result.time_final_assembly_s = get_time_diff_s(&t_start_section, &t_end_section);

        struct timespec t_gpu_start, t_gpu_end;
        clock_gettime(CLOCK_MONOTONIC, &t_gpu_start);

        bool header_decryption_failed = false;
        if (p_h_aes_key_exp_header && !enchdr_encrypted_bytes.empty()) {
            pointersH = launch_header_decryption_async(
                enchdr_encrypted_bytes.data(), h_final_buffer_pinned, enchdr_encrypted_bytes.size(),
                nonce_H_vec, p_h_aes_key_exp_header, streamH, enable_kernel_timing);
        } else {
            header_decryption_failed = true;
        }

        bool data_decryption_failed = false;
        if (data_original_size > 0 && p_d_aes_key_exp_data) {
            if (!use_context) {
                cudaError_t err = cudaMallocHost((void **) &h_read_buffer_pinned, data_original_size);
                if (err != cudaSuccess) {
                    if (h_final_buffer_pinned) cudaFreeHost(h_final_buffer_pinned);
                    throw std::runtime_error("cudaMallocHost failed for read_buffer");
                }
            }

            clock_gettime(CLOCK_MONOTONIC, &t_start_section);
            int hdutype_data;

            fits_movrel_hdu(fptr_in, 1, &hdutype_data, &status);

            if (status || hdutype_data != BINARY_TBL)
                throw std::runtime_error("FITS: Data BINTABLE not found.");

            fits_read_col_byt(fptr_in, 1, 1, 1, data_original_size, 0, h_read_buffer_pinned, NULL, &status);

            if (status) {
                fits_get_errstatus(status, err_text);
                throw std::runtime_error(std::string("FITS: Error reading data column: ") + err_text);
            }
            clock_gettime(CLOCK_MONOTONIC, &t_end_section);
            result.time_data_section_read_s = get_time_diff_s(&t_start_section, &t_end_section);

            unsigned char *h_data_section_ptr = h_final_buffer_pinned + header_decrypted_size;
            pointersD = launch_data_decryption_async(
                h_read_buffer_pinned, h_data_section_ptr, nonce_D_vec, p_d_aes_key_exp_data,
                data_original_size, data_padded_size, s_img_bitpix_orig_temp, streamD, enable_kernel_timing);
        } else if (data_original_size > 0) {
            data_decryption_failed = true;
        }

        if (pointersH.d_io) cudaStreamSynchronize(streamH);
        if (pointersD.d_io) cudaStreamSynchronize(streamD);

        clock_gettime(CLOCK_MONOTONIC, &t_gpu_end);
        result.time_data_decryption_gpu_s = get_time_diff_s(&t_gpu_start, &t_gpu_end);

        // Sum kernel times if enabled
        if (enable_kernel_timing) {
            result.time_data_decryption_gpu_kernel_s = pointersD.kernel_elapsed_ms / 1000.0;
        }

        clock_gettime(CLOCK_MONOTONIC, &t_start_section);

        // Check header validity
        if (p_h_aes_key_exp_header && !header_decryption_failed) {
            unsigned char *decrypted_header_ptr = h_final_buffer_pinned;
            bool found_simple = (header_decrypted_size >= 8 && strncmp(reinterpret_cast<char *>(decrypted_header_ptr),
                                                                       "SIMPLE  =", 8) == 0);
            bool found_end = false;
            if (header_decrypted_size >= 80)
                for (size_t i = 0; (i + 80) <= header_decrypted_size; i += 80)
                    if (
                        strncmp(reinterpret_cast<char *>(decrypted_header_ptr + i), "END     ", 8) == 0) {
                        found_end = true;
                        break;
                    }
            if (!found_simple || !found_end) {
                header_decryption_failed = true;
            }
        }

        if (header_decryption_failed) {
            fitsfile *fptr_temp_hdr = nullptr;
            int h_status = 0;
            char *h_str = nullptr;
            void *mem_buffer = nullptr;
            size_t mem_size = 0;
            if (fits_create_memfile(&fptr_temp_hdr, &mem_buffer, &mem_size, 0, realloc, &h_status))
                throw
                        std::runtime_error("FITS Fallback: create_memfile failed.");
            if (fits_create_img(fptr_temp_hdr, s_img_bitpix_orig_temp, s_img_naxis_orig_temp, s_img_naxes_orig_temp,
                                &h_status))
                throw std::runtime_error("FITS Fallback: create_img failed.");
            int nkeys;
            if (fits_convert_hdr2str(fptr_temp_hdr, 1, NULL, 0, &h_str, &nkeys, &h_status))
                throw std::runtime_error(
                    "FITS Fallback: hdr2str failed.");
            size_t fallback_hdr_len = strlen(h_str);
            if (fallback_hdr_len > header_decrypted_size) fallback_hdr_len = header_decrypted_size;
            memcpy(h_final_buffer_pinned, h_str, fallback_hdr_len);
            if (header_decrypted_size > fallback_hdr_len)
                memset(h_final_buffer_pinned + fallback_hdr_len, ' ',
                       header_decrypted_size - fallback_hdr_len);
            if (h_str)
                fits_free_memory(h_str, &h_status);
            if (fptr_temp_hdr)
                fits_close_file(fptr_temp_hdr, &h_status);
            if (mem_buffer) free(mem_buffer);
        }

        if (data_original_size > 0 && p_d_aes_key_exp_data) {
            // No need to copy data, it was decrypted directly into h_final_buffer_pinned via h_data_section_ptr
            // Just handle padding if needed
            size_t total_written = header_decrypted_size + data_original_size;
            size_t total_padded = ((total_written + FITS_BLOCK_SIZE - 1) / FITS_BLOCK_SIZE) * FITS_BLOCK_SIZE;
            if (total_padded > total_written) {
                memset(h_final_buffer_pinned + total_written, 0, total_padded - total_written);
            }
        }

        // If data failed (missing key), ensure it is zeroed (already done by memset, but just to be explicit logic-wise)
        // In CTR, we can't detect "Wrong Key", so data_decryption_failed is only true if key was missing.
        // If key was present but wrong, CTR produces garbage, which we can't detect here.
        // So we only handle the "Missing Key" case for data.

        clock_gettime(CLOCK_MONOTONIC, &t_end_section);
        result.time_header_processing_s = get_time_diff_s(&t_start_section, &t_end_section);

        result.data_buffer = h_final_buffer_pinned;
        h_final_buffer_pinned = nullptr;

        // Determine final result code based on granular success
        if (header_decryption_failed && data_decryption_failed) {
             result.error_code = -999;
             result.warning_code = 3;
             strncpy(result.error_message, "Total failure: Header and Data corrupted/wrong key.", sizeof(result.error_message) - 1);
        } else if (header_decryption_failed) {
             result.error_code = 0;
             result.warning_code = 1;
             strncpy(result.error_message, "Partial: Header fallback, Data OK.", sizeof(result.error_message) - 1);
        } else if (data_decryption_failed) {
             result.error_code = 0;
             result.warning_code = 2;
             strncpy(result.error_message, "Partial: Header OK, Data failed (zeroed).", sizeof(result.error_message) - 1);
        } else {
             result.error_code = 0;
             result.warning_code = 0;
             strncpy(result.error_message, "Success (CTR).", sizeof(result.error_message) - 1);
        }

    } catch (const std::runtime_error &e) {
        if (result.error_code >= 0) result.error_code = -1099;
        strncpy(result.error_message, e.what(), sizeof(result.error_message) - 1);
        if (!use_context && h_final_buffer_pinned) {
            cudaFreeHost(h_final_buffer_pinned);
            h_final_buffer_pinned = nullptr;
        }
    }

    if (fptr_in) {
        int s = 0;
        fits_close_file(fptr_in, &s);
    }

    if (!use_context) {
        if (h_read_buffer_pinned) { cudaFreeHost(h_read_buffer_pinned); }
        if (streamH) { cudaStreamDestroy(streamH); }
        if (streamD) { cudaStreamDestroy(streamD); }
    }

    if (pointersH.d_io) cudaFree(pointersH.d_io);
    if (pointersH.d_keystream) cudaFree(pointersH.d_keystream);
    if (pointersH.d_nonce_packed) cudaFree(pointersH.d_nonce_packed);
    if (pointersH.d_aes_key_exp) cudaFree(pointersH.d_aes_key_exp);
    if (pointersD.d_io) cudaFree(pointersD.d_io);
    if (pointersD.d_keystream) cudaFree(pointersD.d_keystream);
    if (pointersD.d_nonce_packed) cudaFree(pointersD.d_nonce_packed);
    if (pointersD.d_aes_key_exp) cudaFree(pointersD.d_aes_key_exp);

    clock_gettime(CLOCK_MONOTONIC, &t_end_total);
    result.time_total_c_function_s = get_time_diff_s(&t_start_total, &t_end_total);

    GFC_LOG(GFC_LOG_LEVEL_DEBUG, "Finishing decrypt_fits_internal. Buffer size: %zu", result.buffer_size);
    return result;
}


// --- NEW INTERNAL ENCRYPTION FUNCTION (GCM) ---
static FitsOperationResult encrypt_fits_internal_gcm(
    const char *input_fits_path_cstr,
    const char *output_encrypted_path_cstr,
    const char *key_hex_header_cstr,
    const char *key_hex_data_cstr,
    EncryptorContext *ctx,
    bool use_context) {
    struct timespec t_start_total, t_end_total;
    clock_gettime(CLOCK_MONOTONIC, &t_start_total);

    FitsOperationResult result = {nullptr, 0, -401, 0, ""};
    strncpy(result.error_message, "Initial error in GCM encryption (internal).", sizeof(result.error_message) - 1);

    cudaStream_t streamH = nullptr, streamD = nullptr;

    if (use_context) {
        if (!ctx) {
            snprintf(result.error_message, sizeof(result.error_message),
                     "Internal error: context was expected but is NULL.");
            result.error_code = -502;
            return result;
        }
        streamH = ctx->streamH;
        streamD = ctx->streamD;
    } else {
        cudaStreamCreate(&streamH);
        cudaStreamCreate(&streamD);
    }

    GFC_LOG(GFC_LOG_LEVEL_INFO, "🔒 (LibAPI) Starting GCM encryption of '%s' to '%s' (Context: %s)",
            input_fits_path_cstr, output_encrypted_path_cstr, use_context ? "Yes" : "No");

    if (!input_fits_path_cstr || !output_encrypted_path_cstr || !key_hex_header_cstr || !key_hex_data_cstr) {
        snprintf(result.error_message, sizeof(result.error_message), "One or more path/key arguments are NULL.");
        result.error_code = -402;
        if (!use_context) {
            if (streamH) cudaStreamDestroy(streamH);
            if (streamD) cudaStreamDestroy(streamD);
        }
        return result;
    }

    try {
        uint32_t h_aes_key_exp_header[352];
        // AES-128 expands to 11 rounds * 4 words/round = 44 words * 4 bytes/word = 176 bytes. 352 is overkill but safe.
        uint32_t h_aes_key_exp_data[352];
        uint8_t key_bytes_h[16]; // 128 bits = 16 bytes
        uint8_t key_bytes_d[16];

        if (!hex_string_to_bytes_util(key_hex_header_cstr, key_bytes_h, 16)) {
            throw std::runtime_error("Invalid hex header key.");
        }
        if (!hex_string_to_bytes_util(key_hex_data_cstr, key_bytes_d, 16)) {
            throw std::runtime_error("Invalid hex data key.");
        }

        aes128_keyschedule_lut(h_aes_key_exp_header, key_bytes_h);
        aes128_keyschedule_lut(h_aes_key_exp_data, key_bytes_d);

        // *** CRITICAL CHANGE: Call the GCM encryption function ***
        bool success = encrypt_fits_file_gcm(
            input_fits_path_cstr,
            output_encrypted_path_cstr,
            h_aes_key_exp_header,
            h_aes_key_exp_data
        );

        if (!success) {
            throw std::runtime_error(
                "Internal GCM encryption operation (encrypt_fits_file_gcm) failed. See logs for details.");
        }

        result.error_code = 0;
        strncpy(result.error_message, "Success (GCM encryption to file).", sizeof(result.error_message) - 1);
    } catch (const std::runtime_error &e) {
        if (result.error_code >= 0) result.error_code = -400;
        strncpy(result.error_message, e.what(), sizeof(result.error_message) - 1);
        GFC_LOG(GFC_LOG_LEVEL_ERROR, "(LibAPI-Encrypt-GCM) Exception: %s", e.what());
    }

    if (!use_context) {
        if (streamH) cudaStreamDestroy(streamH);
        if (streamD) cudaStreamDestroy(streamD);
    }

    clock_gettime(CLOCK_MONOTONIC, &t_end_total);
    result.time_total_c_function_s = get_time_diff_s(&t_start_total, &t_end_total);

    return result;
}


// --- NEW INTERNAL DECRYPTION FUNCTION (GCM) ---
static FitsOperationResult decrypt_fits_internal_gcm(
    const char *encrypted_fits_path_cstr,
    const char *key_hex_header_cstr,
    const char *key_hex_data_cstr,
    DecryptorContext *ctx,
    bool use_context) {
    struct timespec t_start_total, t_end_total;
    struct timespec t_start_section, t_end_section;
    clock_gettime(CLOCK_MONOTONIC, &t_start_total);

    FitsOperationResult result = {nullptr, 0, -999, 0, ""};
    result.time_total_c_function_s = 0.0;
    result.time_open_fits_file_s = 0.0;
    result.time_read_primary_hdu_meta_s = 0.0;
    result.time_data_section_read_s = 0.0;
    result.time_data_decryption_gpu_s = 0.0;
    result.time_data_decryption_gpu_kernel_s = 0.0;
    result.time_header_processing_s = 0.0;
    result.time_final_assembly_s = 0.0;
    strncpy(result.error_message, "Initial error (internal GCM).", sizeof(result.error_message) - 1);

    unsigned char *h_final_buffer_pinned = nullptr;
    unsigned char *h_read_buffer_pinned = nullptr;
    cudaStream_t streamH = nullptr, streamD = nullptr;
    size_t max_output_size = 0, max_read_size = 0;
    bool enable_kernel_timing = false;

    if (use_context) {
        if (!ctx) {
            snprintf(result.error_message, sizeof(result.error_message), "Internal error: context was expected but is NULL.");
            result.error_code = -302;
            return result;
        }
        h_final_buffer_pinned = ctx->h_final_buffer_pinned;
        h_read_buffer_pinned = ctx->h_read_buffer_pinned;
        streamH = ctx->streamH;
        streamD = ctx->streamD;
        max_output_size = ctx->max_output_size;
        max_read_size = ctx->max_read_size;
        enable_kernel_timing = ctx->enable_kernel_timing;
    } else {
        cudaStreamCreate(&streamH);
        cudaStreamCreate(&streamD);
    }

    if (!encrypted_fits_path_cstr) {
        snprintf(result.error_message, sizeof(result.error_message), "Input file path is NULL.");
        result.error_code = -1002;
        if (!use_context) {
            cudaStreamDestroy(streamH);
            cudaStreamDestroy(streamD);
        }
        return result;
    }

    uint32_t h_aes_key_exp_header_arr[352], h_aes_key_exp_data_arr[352];
    uint32_t *p_h_aes_key_exp_header = nullptr, *p_d_aes_key_exp_data = nullptr;

    bool no_header_key_input = (!key_hex_header_cstr || strcmp(key_hex_header_cstr, "NO_KEY") == 0 || strlen(key_hex_header_cstr) == 0);
    bool no_data_key_input = (!key_hex_data_cstr || strcmp(key_hex_data_cstr, "NO_KEY") == 0 || strlen(key_hex_data_cstr) == 0);

    if (!no_header_key_input) {
        uint8_t key_bytes_h[16];
        if (!hex_string_to_bytes_util(key_hex_header_cstr, key_bytes_h, 16)) {
            snprintf(result.error_message, sizeof(result.error_message), "Invalid hex header key.");
            result.error_code = -1003;
            if (!use_context) { cudaStreamDestroy(streamH); cudaStreamDestroy(streamD); }
            return result;
        }
        aes128_keyschedule_lut(h_aes_key_exp_header_arr, key_bytes_h);
        p_h_aes_key_exp_header = h_aes_key_exp_header_arr;
    }
    if (!no_data_key_input) {
        uint8_t key_bytes_d[16];
        if (!hex_string_to_bytes_util(key_hex_data_cstr, key_bytes_d, 16)) {
            snprintf(result.error_message, sizeof(result.error_message), "Invalid hex data key.");
            result.error_code = -1004;
            if (!use_context) { cudaStreamDestroy(streamH); cudaStreamDestroy(streamD); }
            return result;
        }
        aes128_keyschedule_lut(h_aes_key_exp_data_arr, key_bytes_d);
        p_d_aes_key_exp_data = h_aes_key_exp_data_arr;
    }

    if (no_header_key_input && no_data_key_input) {
        // Logic for when there are no keys: just read the file and return it as-is.
        std::vector<uint8_t> file_content_vec;
        if (!read_file_into_vector_util(encrypted_fits_path_cstr, file_content_vec, result.error_message,
                                        sizeof(result.error_message))) {
            result.error_code = -1010;
        } else if (file_content_vec.empty()) {
            result.data_buffer = nullptr;
            result.buffer_size = 0;
            result.error_code = -998; // <--- CHANGE: No keys provided
            strncpy(result.error_message, "Success (empty buffer).", sizeof(result.error_message) - 1);
        } else {
            result.data_buffer = (unsigned char *) malloc(file_content_vec.size());
            if (!result.data_buffer) {
                strncpy(result.error_message, "malloc failed for copy.", sizeof(result.error_message) - 1);
                result.error_code = -1011;
            } else {
                memcpy(result.data_buffer, file_content_vec.data(), file_content_vec.size());
                result.buffer_size = file_content_vec.size();
                result.error_code = -998; // <--- CHANGE: No keys provided
                strncpy(result.error_message, "Success (copy to RAM buffer).", sizeof(result.error_message) - 1);
            }
        }
        if (!use_context) {
            cudaStreamDestroy(streamH);
            cudaStreamDestroy(streamD);
        }
        clock_gettime(CLOCK_MONOTONIC, &t_end_total);
        result.time_total_c_function_s = get_time_diff_s(&t_start_total, &t_end_total);
        return result;
    }

    fitsfile *fptr_in = nullptr;
    int status = 0;
    char err_text[FLEN_ERRMSG];
    std::vector<uint8_t> enchdr_encrypted_bytes;
    std::vector<uint8_t> encrypted_data_bytes_from_bintable;

    try {
        clock_gettime(CLOCK_MONOTONIC, &t_start_section);
        if (fits_open_file(&fptr_in, encrypted_fits_path_cstr, READONLY, &status)) {
            fits_get_errstatus(status, err_text);
            throw std::runtime_error(std::string("FITS: Error opening input: ") + err_text);
        }
        clock_gettime(CLOCK_MONOTONIC, &t_end_section);
        result.time_open_fits_file_s = get_time_diff_s(&t_start_section, &t_end_section);

        clock_gettime(CLOCK_MONOTONIC, &t_start_section);
        fits_movabs_hdu(fptr_in, 1, NULL, &status);
        if (status) {
            fits_get_errstatus(status, err_text);
            throw std::runtime_error(std::string("FITS: Error movabs_hdu to HDU 1: ") + err_text);
        }

        std::vector<uint8_t> nonce_H_vec, nonce_D_vec;
        std::string enchdr_hex_str, header_authtag_hex_str, data_authtag_hex_str;
        int s_img_bitpix_orig_temp = 0, s_img_naxis_orig_temp = 0;
        long s_img_naxes_orig_temp[9];
        std::fill_n(s_img_naxes_orig_temp, 9, 1L);
        char *temp_longstr = nullptr;

        if (fits_read_key_longstr(fptr_in, "NONCE_H", &temp_longstr, NULL, &status) || !temp_longstr || !*temp_longstr) { if (temp_longstr) free(temp_longstr); throw std::runtime_error("FITS: Error or empty while reading NONCE_H"); }
        nonce_H_vec = fitsStringToNonce_util(temp_longstr);
        free(temp_longstr); temp_longstr = nullptr;

        if (fits_read_key_longstr(fptr_in, "NONCE_D", &temp_longstr, NULL, &status) || !temp_longstr || !*temp_longstr) { if (temp_longstr) free(temp_longstr); throw std::runtime_error("FITS: Error or empty while reading NONCE_D"); }
        nonce_D_vec = fitsStringToNonce_util(temp_longstr);
        free(temp_longstr); temp_longstr = nullptr;

        if (p_h_aes_key_exp_header) {
            if (fits_read_key_longstr(fptr_in, "ENCHDR", &temp_longstr, NULL, &status) || !temp_longstr || !*temp_longstr) { if (temp_longstr) free(temp_longstr); throw std::runtime_error("FITS: Error or empty while reading ENCHDR"); }
            enchdr_hex_str = temp_longstr;
            free(temp_longstr); temp_longstr = nullptr;
            enchdr_encrypted_bytes = hex_string_to_bytes_vec_util(enchdr_hex_str);

            if (fits_read_key_longstr(fptr_in, "AUTHTAG_H", &temp_longstr, NULL, &status) || !temp_longstr || !*temp_longstr) { if (temp_longstr) free(temp_longstr); throw std::runtime_error("FITS: Error or empty while reading AUTHTAG_H"); }
            header_authtag_hex_str = temp_longstr;
            free(temp_longstr); temp_longstr = nullptr;
        }

        if (fits_read_key(fptr_in, TINT, "ORIG_BPX", &s_img_bitpix_orig_temp, NULL, &status) || status) throw std::runtime_error("FITS: Missing ORIG_BPX");
        if (fits_read_key(fptr_in, TINT, "ORIG_NAX", &s_img_naxis_orig_temp, NULL, &status) || status) throw std::runtime_error("FITS: Missing ORIG_NAX");
        for (int i = 0; i < s_img_naxis_orig_temp; ++i) {
            char keyname[FLEN_KEYWORD];
            snprintf(keyname, sizeof(keyname), "ORIG_NA%d", i + 1);
            if (fits_read_key(fptr_in, TLONG, keyname, &s_img_naxes_orig_temp[i], NULL, &status) || status) throw std::runtime_error(std::string("FITS: Missing ") + keyname);
        }

        if (p_d_aes_key_exp_data) {
            if (fits_read_key_longstr(fptr_in, "AUTHTAG_D", &temp_longstr, NULL, &status) || !temp_longstr || !*temp_longstr) { if (temp_longstr) free(temp_longstr); throw std::runtime_error("FITS: Error or empty while reading AUTHTAG_D"); }
            data_authtag_hex_str = temp_longstr;
            free(temp_longstr); temp_longstr = nullptr;
        }
        clock_gettime(CLOCK_MONOTONIC, &t_end_section);
        result.time_read_primary_hdu_meta_s = get_time_diff_s(&t_start_section, &t_end_section);

        clock_gettime(CLOCK_MONOTONIC, &t_start_section);

        size_t header_size_estimate = p_h_aes_key_exp_header ? enchdr_encrypted_bytes.size() : FITS_BLOCK_SIZE;
        long data_original_size = 0;
        if (s_img_naxis_orig_temp > 0) {
            data_original_size = (long) (std::abs(s_img_bitpix_orig_temp) / 8);
            for (int i = 0; i < s_img_naxis_orig_temp; ++i) data_original_size *= s_img_naxes_orig_temp[i];
        }

        const size_t FITS_BLOCK_SIZE = 2880;
        size_t header_padded_size = ((header_size_estimate + FITS_BLOCK_SIZE - 1) / FITS_BLOCK_SIZE) * FITS_BLOCK_SIZE;
        size_t data_padded_size = ((data_original_size + FITS_BLOCK_SIZE - 1) / FITS_BLOCK_SIZE) * FITS_BLOCK_SIZE;
        size_t required_output_size = header_padded_size + data_padded_size;
        result.buffer_size = required_output_size;

        if (use_context) {
            if (required_output_size > max_output_size || (size_t) data_original_size > max_read_size) {
                char msg[256];
                snprintf(msg, sizeof(msg), "Required size exceeds context capacity.");
                throw std::runtime_error(msg);
            }
        } else {
            if (required_output_size > 0) {
                cudaError_t err = cudaMallocHost((void **) &h_final_buffer_pinned, required_output_size);
                if (err != cudaSuccess) throw std::runtime_error("cudaMallocHost failed for final_buffer");
            }
        }

        // FIX: Zero-initialize buffer to prevent stale data
        if (h_final_buffer_pinned && required_output_size > 0) {
             memset(h_final_buffer_pinned, 0, required_output_size);
        }

        clock_gettime(CLOCK_MONOTONIC, &t_end_section);
        result.time_final_assembly_s = get_time_diff_s(&t_start_section, &t_end_section);

        struct timespec t_gpu_start, t_gpu_end;
        clock_gettime(CLOCK_MONOTONIC, &t_gpu_start);

        std::vector<uint8_t> header_decrypted_bytes;
        bool header_decryption_failed = false; // Flag to indicate header failure

        if (p_h_aes_key_exp_header && !enchdr_encrypted_bytes.empty()) {
            std::vector<uint8_t> header_aad; // Empty
            std::vector<uint8_t> tag_H_from_file = hex_string_to_bytes_vec_util(header_authtag_hex_str);

            GcmDecryptionResult header_res = gcmDecrypt(enchdr_encrypted_bytes, header_aad, tag_H_from_file, p_h_aes_key_exp_header, nonce_H_vec, streamH, enable_kernel_timing);

            if (!header_res.success) {
                GFC_LOG(GFC_LOG_LEVEL_ERROR, "GPU: GCM header decryption failed. Header fallback will be used.");
                header_decryption_failed = true;
                result.warning_code = 1; // Warning code for header fallback
            } else if (!header_res.isAuthenticated) {
                GFC_LOG(GFC_LOG_LEVEL_ERROR, "GCM VERIFICATION FAILURE in Header! Header fallback will be used.");
                header_decryption_failed = true;
                result.warning_code = 2; // Warning code for header integrity failure
            } else {
                header_decrypted_bytes.assign(header_res.plaintext.begin(), header_res.plaintext.end());
            }
        } else {
             // Missing key -> Treat as "failed" for status reporting (fallback used)
             header_decryption_failed = true;
        }

        std::vector<uint8_t> data_decrypted_bytes;
        float data_kernel_ms = 0.0f;
        bool data_decryption_failed = false;

        if (data_original_size > 0 && p_d_aes_key_exp_data) {
            if (!use_context) {
                cudaError_t err = cudaMallocHost((void **) &h_read_buffer_pinned, data_original_size);
                if (err != cudaSuccess) { if (h_final_buffer_pinned) cudaFreeHost(h_final_buffer_pinned); throw std::runtime_error("cudaMallocHost failed for read_buffer"); }
            }
            clock_gettime(CLOCK_MONOTONIC, &t_start_section);
            int hdutype_data;

            fits_movrel_hdu(fptr_in, 1, &hdutype_data, &status);

            if (status || hdutype_data != BINARY_TBL) throw std::runtime_error("FITS: Data BINTABLE not found.");

            fits_read_col_byt(fptr_in, 1, 1, 1, data_original_size, 0, h_read_buffer_pinned, NULL, &status);

            if (status) { fits_get_errstatus(status, err_text); throw std::runtime_error(std::string("FITS: Error reading data column: ") + err_text); }
            clock_gettime(CLOCK_MONOTONIC, &t_end_section);
            result.time_data_section_read_s = get_time_diff_s(&t_start_section, &t_end_section);

            std::vector<uint8_t> data_aad;
            data_aad.insert(data_aad.end(), nonce_D_vec.begin(), nonce_D_vec.end());
            std::string orig_bpx_str = std::to_string(s_img_bitpix_orig_temp);
            data_aad.insert(data_aad.end(), orig_bpx_str.begin(), orig_bpx_str.end());
            std::string orig_nax_str = std::to_string(s_img_naxis_orig_temp);
            data_aad.insert(data_aad.end(), orig_nax_str.begin(), orig_nax_str.end());
            for (int i = 0; i < s_img_naxis_orig_temp; ++i) {
                std::string orig_naxn_str = std::to_string(s_img_naxes_orig_temp[i]);
                data_aad.insert(data_aad.end(), orig_naxn_str.begin(), orig_naxn_str.end());
            }

            std::vector<uint8_t> tag_D_from_file = hex_string_to_bytes_vec_util(data_authtag_hex_str);

            GcmDecryptionResult data_res = gcmDecrypt(h_read_buffer_pinned, data_original_size, data_aad, tag_D_from_file, p_d_aes_key_exp_data, nonce_D_vec, streamD, enable_kernel_timing);

            if (!data_res.success) {
                GFC_LOG(GFC_LOG_LEVEL_ERROR, "GPU: GCM decryption failed for image data.");
                data_decryption_failed = true;
            } else if (!data_res.isAuthenticated) {
                GFC_LOG(GFC_LOG_LEVEL_ERROR, "GCM VERIFICATION FAILURE in Data! File is corrupt or tampered.");
                data_decryption_failed = true;
            } else {
                data_decrypted_bytes.assign(data_res.plaintext.begin(), data_res.plaintext.end());
                data_kernel_ms = data_res.kernel_elapsed_ms;
                swap_endianness_if_needed_util(data_decrypted_bytes.data(), data_decrypted_bytes.size(), s_img_bitpix_orig_temp);
            }
        } else if (data_original_size > 0 && !p_d_aes_key_exp_data) {
             // Missing data key -> treat as failure for granular access reporting
             data_decryption_failed = true;
        }

        clock_gettime(CLOCK_MONOTONIC, &t_gpu_end);
        result.time_data_decryption_gpu_s = get_time_diff_s(&t_gpu_start, &t_gpu_end);

        if (enable_kernel_timing) {
            result.time_data_decryption_gpu_kernel_s = data_kernel_ms / 1000.0;
        }

        clock_gettime(CLOCK_MONOTONIC, &t_start_section);

        if (p_h_aes_key_exp_header && !header_decryption_failed) {
            size_t header_actual_size = header_decrypted_bytes.size();
            header_padded_size = ((header_actual_size + FITS_BLOCK_SIZE - 1) / FITS_BLOCK_SIZE) * FITS_BLOCK_SIZE;

            memcpy(h_final_buffer_pinned, header_decrypted_bytes.data(), header_actual_size);

            if (header_padded_size > header_actual_size) {
                memset(h_final_buffer_pinned + header_actual_size, ' ', header_padded_size - header_actual_size);
            }
        } else {
            // If no header key was provided, fill with a basic FITS header (fallback)
            fitsfile *fptr_temp_hdr = nullptr;
            int h_status = 0;
            char *h_str = nullptr;
            void *mem_buffer = nullptr;
            size_t mem_size = 0;
            if (fits_create_memfile(&fptr_temp_hdr, &mem_buffer, &mem_size, 0, realloc, &h_status))
                throw
                        std::runtime_error("FITS Fallback: create_memfile failed.");
            if (fits_create_img(fptr_temp_hdr, s_img_bitpix_orig_temp, s_img_naxis_orig_temp, s_img_naxes_orig_temp,
                                &h_status))
                throw std::runtime_error("FITS Fallback: create_img failed.");
            int nkeys;
            if (fits_convert_hdr2str(fptr_temp_hdr, 1, NULL, 0, &h_str, &nkeys, &h_status))
                throw std::runtime_error(
                    "FITS Fallback: hdr2str failed.");
            size_t fallback_hdr_len = strlen(h_str);
            // Use FITS_BLOCK_SIZE as minimum for fallback
            size_t copy_len = fallback_hdr_len;

            memcpy(h_final_buffer_pinned, h_str, copy_len);
            // Pad with spaces to complete the block
            size_t padded_fallback = ((copy_len + FITS_BLOCK_SIZE - 1) / FITS_BLOCK_SIZE) * FITS_BLOCK_SIZE;
            if (padded_fallback > copy_len) {
                memset(h_final_buffer_pinned + copy_len, ' ', padded_fallback - copy_len);
            }

            if (h_str)
                fits_free_memory(h_str, &h_status);
            if (fptr_temp_hdr)
                fits_close_file(fptr_temp_hdr, &h_status);
            if (mem_buffer) free(mem_buffer);
        }

        if (data_original_size > 0 && !data_decryption_failed && !data_decrypted_bytes.empty()) {
            memcpy(h_final_buffer_pinned + header_padded_size, data_decrypted_bytes.data(), data_original_size);
            // Final FITS file padding
            size_t total_written = header_padded_size + data_original_size;
            size_t total_padded = ((total_written + FITS_BLOCK_SIZE - 1) / FITS_BLOCK_SIZE) * FITS_BLOCK_SIZE;
            if (total_padded > total_written) {
                memset(h_final_buffer_pinned + total_written, 0, total_padded - total_written);
            }
        }

        clock_gettime(CLOCK_MONOTONIC, &t_end_section);
        result.time_header_processing_s = get_time_diff_s(&t_start_section, &t_end_section);

        result.data_buffer = h_final_buffer_pinned;
        h_final_buffer_pinned = nullptr;

        // Determine final result code based on granular success
        if (header_decryption_failed && data_decryption_failed) {
             result.error_code = -999;
             result.warning_code = 3;
             strncpy(result.error_message, "Total failure: Header and Data corrupted/wrong key.", sizeof(result.error_message) - 1);
        } else if (header_decryption_failed) {
             result.error_code = 0;
             result.warning_code = 1;
             strncpy(result.error_message, "Partial: Header fallback, Data OK.", sizeof(result.error_message) - 1);
        } else if (data_decryption_failed) {
             result.error_code = 0;
             result.warning_code = 2;
             strncpy(result.error_message, "Partial: Header OK, Data failed (zeroed).", sizeof(result.error_message) - 1);
        } else {
             result.error_code = 0;
             result.warning_code = 0;
             strncpy(result.error_message, "Success (GCM).", sizeof(result.error_message) - 1);
        }

    } catch (const std::runtime_error &e) {
        if (result.error_code >= 0) result.error_code = -1099;
        strncpy(result.error_message, e.what(), sizeof(result.error_message) - 1);
        if (!use_context && h_final_buffer_pinned) {
            cudaFreeHost(h_final_buffer_pinned);
            h_final_buffer_pinned = nullptr;
        }
    }

    if (fptr_in) {
        int s = 0;
        fits_close_file(fptr_in, &s);
    }

    if (!use_context) {
        if (h_read_buffer_pinned) { cudaFreeHost(h_read_buffer_pinned); }
        if (streamH) { cudaStreamDestroy(streamH); }
        if (streamD) { cudaStreamDestroy(streamD); }
    }

    clock_gettime(CLOCK_MONOTONIC, &t_end_total);
    result.time_total_c_function_s = get_time_diff_s(&t_start_total, &t_end_total);
    GFC_LOG(GFC_LOG_LEVEL_DEBUG, "Finishing decrypt_fits_internal_gcm. Buffer size: %zu", result.buffer_size);
    return result;
}

// Internal function to encrypt from memory (GCM)
static FitsOperationResult encrypt_raw_gcm_internal(
    const char *output_path,
    const char *header_str, size_t header_len,
    const void *data_ptr, size_t data_len,
    int bitpix, int naxis, const long *naxes,
    const char *key_h, const char *key_d,
    EncryptorContext *ctx, bool use_context) {

    FitsOperationResult result = {nullptr, 0, -401, 0, ""};
    strncpy(result.error_message, "Initial error in RAW GCM encryption.", sizeof(result.error_message) - 1);

    cudaStream_t streamH = nullptr, streamD = nullptr;
    if (use_context && ctx) {
        streamH = ctx->streamH;
        streamD = ctx->streamD;
    } else {
        cudaStreamCreate(&streamH);
        cudaStreamCreate(&streamD);
    }

    try {
        // 1. Parse Keys
        uint32_t h_aes_key_exp_header[352], h_aes_key_exp_data[352];
        uint8_t key_bytes_h[16], key_bytes_d[16];
        if (!hex_string_to_bytes_util(key_h, key_bytes_h, 16)) throw std::runtime_error("Invalid Header Key");
        if (!hex_string_to_bytes_util(key_d, key_bytes_d, 16)) throw std::runtime_error("Invalid Data Key");
        aes128_keyschedule_lut(h_aes_key_exp_header, key_bytes_h);
        aes128_keyschedule_lut(h_aes_key_exp_data, key_bytes_d);

        // 2. Generate Nonces
        std::random_device rd;
        std::vector<uint8_t> nonce_H(12), nonce_D(12);
        for(int i=0; i<12; ++i) nonce_H[i] = static_cast<uint8_t>(rd());
        for(int i=0; i<12; ++i) nonce_D[i] = static_cast<uint8_t>(rd());

        // 3. Encrypt Header
        std::vector<uint8_t> header_vec(header_str, header_str + header_len);
        std::vector<uint8_t> aad_H; // Empty for header
        GcmEncryptionResult res_H = gcmEncrypt(header_vec, aad_H, h_aes_key_exp_header, nonce_H, streamH);
        if (!res_H.success) throw std::runtime_error("Header encryption failed");

        // 4. Encrypt Data
        std::vector<uint8_t> data_vec((const uint8_t*)data_ptr, (const uint8_t*)data_ptr + data_len);
        std::vector<uint8_t> aad_D;
        aad_D.insert(aad_D.end(), nonce_D.begin(), nonce_D.end());
        std::string s = std::to_string(bitpix); aad_D.insert(aad_D.end(), s.begin(), s.end());
        s = std::to_string(naxis); aad_D.insert(aad_D.end(), s.begin(), s.end());
        for(int i=0; i<naxis; i++) {
            s = std::to_string(naxes[i]); aad_D.insert(aad_D.end(), s.begin(), s.end());
        }
        GcmEncryptionResult res_D = gcmEncrypt(data_vec, aad_D, h_aes_key_exp_data, nonce_D, streamD);
        if (!res_D.success) throw std::runtime_error("Data encryption failed");

        // 5. Write FITS
        fitsfile *fptr = nullptr;
        int status = 0;
        remove(output_path); // Ensure clean start
        if (fits_create_file(&fptr, output_path, &status)) throw std::runtime_error("fits_create_file failed");

        // Primary HDU (Metadata)
        long naxes_dummy[2] = {0, 0};
        fits_create_img(fptr, 8, 0, naxes_dummy, &status);

        // Write Keywords
        std::string nonce_h_hex = bytesToHexString_util(nonce_H);
        std::string nonce_d_hex = bytesToHexString_util(nonce_D);
        std::string tag_h_hex = bytesToHexString_util(res_H.auth_tag);
        std::string tag_d_hex = bytesToHexString_util(res_D.auth_tag);
        std::string enchdr_hex = bytesToHexString_util(res_H.ciphertext);

        fits_write_key_longstr(fptr, "NONCE_H", nonce_h_hex.c_str(), "Header Nonce", &status);
        fits_write_key_longstr(fptr, "NONCE_D", nonce_d_hex.c_str(), "Data Nonce", &status);
        fits_write_key_longstr(fptr, "AUTHTAG_H", tag_h_hex.c_str(), "Header Auth Tag", &status);
        fits_write_key_longstr(fptr, "AUTHTAG_D", tag_d_hex.c_str(), "Data Auth Tag", &status);
        fits_write_key_longstr(fptr, "ENCHDR", enchdr_hex.c_str(), "Encrypted Header", &status);

        fits_write_key(fptr, TINT, "ORIG_BPX", &bitpix, "Original BITPIX", &status);
        fits_write_key(fptr, TINT, "ORIG_NAX", &naxis, "Original NAXIS", &status);
        for(int i=0; i<naxis; i++) {
            char k[16]; snprintf(k, 16, "ORIG_NA%d", i+1);
            fits_write_key(fptr, TLONG, k, (void*)&naxes[i], "Original Axis Len", &status);
        }

        // Binary Table for Data
        char tform[16]; snprintf(tform, 16, "%luB", data_len);
        char *ttype[] = {(char*)"COMPRESSED_DATA"};
        char *tform_arr[] = {tform};
        char *tunit[] = {(char*)""};

        // Create table with 1 row and 1 column
        fits_create_tbl(fptr, BINARY_TBL, 1, 1, ttype, tform_arr, tunit, "ENCRYPTED_DATA", &status);
        fits_write_col_byt(fptr, 1, 1, 1, data_len, res_D.ciphertext.data(), &status);

        fits_close_file(fptr, &status);
        if (status) throw std::runtime_error("FITS write failed");

        result.error_code = 0;
        strncpy(result.error_message, "Success (Raw Encrypt)", 255);

    } catch (const std::exception &e) {
        result.error_code = -500;
        strncpy(result.error_message, e.what(), 255);
    }

    if (!use_context) {
        cudaStreamDestroy(streamH);
        cudaStreamDestroy(streamD);
    }
    return result;
}
