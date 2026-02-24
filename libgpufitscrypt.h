#ifndef LIBGPUFITSCRYPT_H
#define LIBGPUFITSCRYPT_H

#include <stddef.h>
#include <stdbool.h> // For bool in C

#ifdef __cplusplus
extern "C" {

#endif

// =============================================================================
// == PUBLIC DATA STRUCTURES AND TYPES                                       ==
// =============================================================================

/**
 * @brief Structure to return the result of an operation.
 * Used for both encryption and decryption.
 * Contains the data buffer (if applicable), its size and status codes/messages,
 * along with detailed performance metrics.
 */
typedef struct {
    // --- Main output (mainly for decryption) ---
    unsigned char *data_buffer;
    // Pointer to the buffer with the decrypted FITS. NULL if error or in encryption mode.
    size_t buffer_size; // Size of 'data_buffer' buffer in bytes.

    // --- Operation status ---
    int error_code; // 0 for success, negative for library error.
    int warning_code; // >0 for non-critical warnings (e.g. header fallback).
    char error_message[256]; // Descriptive error or status message.

    // --- Performance metrics (in seconds) ---
    double time_total_c_function_s; // Total execution time of the API function.
    double time_open_fits_file_s; // Time for cfitsio: fits_open_file.
    double time_read_primary_hdu_meta_s; // Time to read metadata (NONCEs, ENCHDR, etc.).
    double time_data_section_read_s; // Time to read encrypted data column (fits_read_col_byt).
    double time_data_decryption_gpu_s; // Time for GPU operations (kernels, DtoH transfers).
    double time_data_decryption_gpu_kernel_s; // Exclusive time for kernel execution on GPU (without transfers).
    double time_header_processing_s; // Time to process/generate the final header.
    double time_final_assembly_s; // Time to allocate final memory and other assembly tasks.
} FitsOperationResult;


/**
 * @brief Opaque declarations for contexts.
 * The complete definition of these structures is internal to the library (in kernel.cu)
 * and should not be accessed directly by the user.
 */
struct EncryptorContext;
typedef struct EncryptorContext EncryptorContext;

struct DecryptorContext;
typedef struct DecryptorContext DecryptorContext;


// =============================================================================
// == CONFIGURATION AND LOGGING API                                          ==
// =============================================================================

void gfc_set_log_level(int level);

int gfc_get_log_level();


// =============================================================================
// == ENCRYPTION API                                                         ==
// =============================================================================

/**
 * @brief Encrypts a FITS file (without context).
 * Single operation that internally manages its own resources.
 */
FitsOperationResult gfc_encrypt_file_ctr_without_context(
    const char *input_fits_path_cstr,
    const char *output_encrypted_path_cstr,
    const char *key_hex_header_cstr,
    const char *key_hex_data_cstr
);

/**
 * @brief Creates a context for repeated encryption operations.
 * Pre-allocates pinned memory and CUDA streams to reduce latency.
 */
EncryptorContext *gfc_encrypt_context_create(size_t max_input_data_buffer_size, size_t max_header_work_buffer_size);

/**
 * @brief Destroys an encryption context and frees all its resources.
 */
void gfc_encrypt_context_destroy(EncryptorContext *ctx);

/**
 * @brief Encrypts a FITS file using a pre-created context.
 * Faster than gfc_encrypt_file_ctr_without_context for successive operations.
 */
    FitsOperationResult gfc_encrypt_file_ctr(
        EncryptorContext *ctx,
        const char *input_fits_path_cstr,
        const char *output_encrypted_path_cstr,
        const char *key_hex_header_cstr,
        const char *key_hex_data_cstr
    );

    FitsOperationResult gfc_encrypt_file(
        EncryptorContext *ctx,
        const char *input_fits_path_cstr,
        const char *output_encrypted_path_cstr,
        const char *key_hex_header_cstr,
        const char *key_hex_data_cstr
    );

/**
 * @brief Encrypts data directly from memory buffers (RAM) to a FITS file on disk.
 * Ideal for acquisition pipelines where the image is already in memory.
 *
 * @param ctx Encryption context (optional, can be NULL).
 * @param output_path Path where the encrypted FITS file will be saved.
 * @param header_str String with the complete FITS header (80 chars/card format).
 * @param header_len Header length in bytes.
 * @param data_ptr Pointer to the raw image data (pixels).
 * @param data_len Data size in bytes.
 * @param bitpix Original BITPIX value (needed for AAD).
 * @param naxis Original NAXIS value (needed for AAD).
 * @param naxes Array with axis dimensions (needed for AAD).
 * @param key_h Header key (Hex string).
 * @param key_d Data key (Hex string).
 */
    FitsOperationResult gfc_encrypt_frame(
        EncryptorContext *ctx,
        const char *output_path,
        const char *header_str, size_t header_len,
        const void *data_ptr, size_t data_len,
        int bitpix, int naxis, const long *naxes,
        const char *key_h, const char *key_d
    );


// =============================================================================
// == DECRYPTION API                                                         ==
// =============================================================================

/**
 * @brief Decrypts a FITS file to a memory buffer (without context).
 * Single operation that internally manages its own resources.
 */
FitsOperationResult gfc_decrypt_frame_ctr_without_context(
    const char *encrypted_fits_path_cstr,
    const char *key_hex_header_cstr,
    const char *key_hex_data_cstr
);

/**
 * @brief Frees the data buffer memory within a FitsOperationResult structure.
 * It is crucial to call this function to avoid memory leaks after a
 * successful call to gfc_decrypt_frame_ctr_without_context (non-context mode).
 */
void free_fits_operation_result(FitsOperationResult *result);

/**
 * @brief Creates a context for repeated decryption operations.
 * Pre-allocates pinned memory and CUDA streams to reduce latency.
 */
DecryptorContext *gfc_context_create(size_t max_output_buffer_size, size_t max_read_buffer_size);

/**
 * @brief Destroys a decryption context and frees all its resources.
 */
void gfc_context_destroy(DecryptorContext *ctx);

/**
 * @brief Enables or disables precise kernel timing measurement (cudaEvent) in the context.
 * Disabled by default to avoid overhead.
 * @param ctx The decryption context.
 * @param enabled true (1) to enable, false (0) to disable.
 */
void gfc_context_set_use_kernel_timing(DecryptorContext *ctx, bool enabled);

/**
 * @brief Decrypts a FITS file using a pre-created context.
 * Faster than gfc_decrypt_frame_ctr_without_context for successive operations. The returned buffer
 * is owned by the context and should not be freed by the user.
 */
    FitsOperationResult gfc_decrypt_frame_ctr(
        DecryptorContext *ctx,
        const char *encrypted_fits_path_cstr,
        const char *key_hex_header_cstr,
        const char *key_hex_data_cstr
    );
    FitsOperationResult gfc_decrypt_frame(
        DecryptorContext *ctx,
        const char *encrypted_fits_path_cstr,
        const char *key_hex_header_cstr,
        const char *key_hex_data_cstr
    );


#ifdef __cplusplus
} // extern "C"
#endif

#endif // LIBGPUFITSCRYPT_H
