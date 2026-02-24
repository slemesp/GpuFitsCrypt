// lib_internal_utils.h
#ifndef LIB_INTERNAL_UTILS_H
#define LIB_INTERNAL_UTILS_H

#include <iostream>
#include <string>
#include <vector>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <chrono>   // <--- Ensure it's available for std::chrono
#include <fitsio.h> // For BYTE_IMG etc. in get_cfitsio_datatype_from_bitpix_util

// --- Common Constants ---
// const size_t UTIL_NONCE_SIZE_BYTES = 128;
const size_t UTIL_NONCE_SIZE_BYTES = 12; // For AES-GCM (96 bits), standard IV size
const size_t FITS_BLOCK_SIZE = 2880;

// --- Logging Infrastructure ---
#ifndef GFC_LOG_LEVEL_NONE
    #define GFC_LOG_LEVEL_NONE 0
    #define GFC_LOG_LEVEL_ERROR 1
    #define GFC_LOG_LEVEL_WARNING 2
    #define GFC_LOG_LEVEL_INFO 2
    #define GFC_LOG_LEVEL_DEBUG 3
#endif

#ifndef GFC_LOG_LEVEL_TRACE
    #define GFC_LOG_LEVEL_TRACE 4
#endif

// --- Log Compilation Control ---
// If not defined externally, by default we allow everything (or DEBUG)
#ifndef GFC_MAX_LOG_LEVEL_COMPILE
#define GFC_MAX_LOG_LEVEL_COMPILE 4 // 4 = TRACE, 0 = NONE
#endif

// Global variable for log level. Defined in lib_internal_utils.cpp
extern int g_gfc_log_level_actual;

// Internal logging implementation functions. Defined in lib_internal_utils.cpp
void gfc_set_log_level_impl(int level);
int  gfc_get_log_level_impl();

#define GFC_LOG(level, fmt, ...) \
    do { \
        /* This check is constant at compile time. */ \
        /* The compiler will eliminate the entire block if the condition is false. */ \
        if (GFC_MAX_LOG_LEVEL_COMPILE >= level) { \
            if (g_gfc_log_level_actual >= level) { \
                char log_buffer_printf_macro[1024]; \
                snprintf(log_buffer_printf_macro, sizeof(log_buffer_printf_macro), fmt, ##__VA_ARGS__); \
                if (level == GFC_LOG_LEVEL_ERROR) { fprintf(stderr, "[GFC_ERROR] %s\n", log_buffer_printf_macro); fflush(stderr); } \
                else if (level == GFC_LOG_LEVEL_INFO) { fprintf(stdout, "[GFC_INFO] %s\n", log_buffer_printf_macro); fflush(stdout); } \
                else if (level == GFC_LOG_LEVEL_DEBUG) { fprintf(stdout, "[GFC_DEBUG] %s\n", log_buffer_printf_macro); fflush(stdout); } \
            } \
        } \
    } while (0)

// --- Helper Function Declarations (definitions in lib_internal_utils.cpp OR here if static inline) ---

// These go to .cpp
bool hex_string_to_bytes_util(const char* hex_str, uint8_t* byte_array, size_t byte_array_len);
bool read_file_into_vector_util(const std::string& filename, std::vector<uint8_t>& data_vec, char* error_msg_out, size_t error_msg_size);
void printNonce_util(const std::vector<uint8_t>& nonce_vec, const std::string& label);
int get_cfitsio_datatype_from_bitpix_util(int bitpix_val);
bool copyFile_util(const std::string& sourcePath, const std::string& destPath);

// --- static inline definitions for string/nonce helpers ---
static inline std::vector<uint8_t> hex_string_to_bytes_vec_util(const std::string& hex) {
    std::vector<uint8_t> bytes;
    if (hex.length() % 2 != 0) {
        GFC_LOG(GFC_LOG_LEVEL_ERROR, "hex_string_to_bytes_vec_util: Hex string must have even length: %s", hex.c_str());
        throw std::invalid_argument("Hex string must have even length.");
    }
    bytes.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        try {
            bytes.push_back(static_cast<uint8_t>(std::stoul(byteString, nullptr, 16)));
        } catch (const std::exception& e) {
            GFC_LOG(GFC_LOG_LEVEL_ERROR, "hex_string_to_bytes_vec_util: Error parsing '%s': %s", byteString.c_str(), e.what());
            throw;
        }
    }
    return bytes;
}

static inline std::vector<uint8_t> fitsStringToNonce_util(const char* fits_str_raw) {
    if (!fits_str_raw) {
        GFC_LOG(GFC_LOG_LEVEL_ERROR, "fitsStringToNonce_util: fits_str_raw is NULL");
        throw std::runtime_error("Input string for Nonce is NULL.");
    }
    std::string fits_str = fits_str_raw;
    if (fits_str.length() >= 2 && fits_str.front() == '\'' && fits_str.back() == '\'') {
        fits_str = fits_str.substr(1, fits_str.length() - 2);
    }
    if (fits_str.length() != UTIL_NONCE_SIZE_BYTES * 2) {
        GFC_LOG(GFC_LOG_LEVEL_ERROR, "fitsStringToNonce_util: Nonce string (without quotes) incorrect length. Expected: %zu, Got: %zu. String: '%s'", UTIL_NONCE_SIZE_BYTES * 2, fits_str.length(), fits_str.c_str());
        throw std::runtime_error("Nonce string with incorrect length.");
    }
    return hex_string_to_bytes_vec_util(fits_str);
}

static inline std::string bytesToHexString_util(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

static inline std::string nonceToFitsString_util(const std::vector<uint8_t>& nonce) {
    return "'" + bytesToHexString_util(nonce) + "'";
}




/**
 * @enum GpuProcessingType
 * @brief Defines the type of processing to perform on the GPU.
 *
 * Used so that the `processDataWithGPU` function can apply additional logic
 * (such as endianness swap and padding) only when necessary,
 * for example, for FITS image data, but not for a header.
 */
enum class GpuProcessingType {
    Generic,        // Original behavior: only decrypt.
    ImageData       // New behavior: decrypt, swap endianness and apply padding.
};


/** * @struct FitsOperationResult
 * @brief Structure containing the result of a FITS operation.
 *
 * This structure is used to return the decrypted data buffer,
 * its size, and error or warning codes.
 */
// --- GPU Function Declarations (definition in gpu_utils.cu) ---
// #include "gpu_utils.h" // Optional, or declare here:
bool processDataWithGPU(
    std::vector<uint8_t>& data_buffer,
    const std::vector<uint8_t>& nonce_bytes,
    uint32_t* h_aes_key_exp,
    float& out_gpu_milliseconds,
    size_t& out_original_data_size_for_throughput,
    GpuProcessingType processing_type,
    int original_bitpix,
    size_t final_padded_size_bytes
);

/**
 * @brief Swaps byte order (endianness) of a data buffer in-place on the CPU.
 *        The function only acts if bitpix corresponds to a multi-byte data type
 *        (e.g. 16, 32, -32, 64, -64).
 *
 * @param data Pointer to the start of the data buffer.
 * @param data_size_bytes Total size of the buffer in bytes.
 * @param bitpix The BITPIX value from the original FITS, which determines the size of each element.
 */
void swap_endianness_if_needed_util(uint8_t *data, size_t data_size_bytes, int bitpix);

#endif // LIB_INTERNAL_UTILS_H