// lib_internal_utils.cpp
#include "lib_internal_utils.h" // Includes static inline and declarations
#include <fitsio.h> // For BYTE_IMG, etc.
#include <cmath>      // For std::abs
#include <utility>    // For std::swap

// --- Global Logging Variable Definition ---
int g_gfc_log_level_actual = GFC_LOG_LEVEL_NONE; // Default initial value

// --- Logging Function Implementations ---
void gfc_set_log_level_impl(int level) {
    if (level >= GFC_LOG_LEVEL_NONE && level <= GFC_LOG_LEVEL_DEBUG) {
        g_gfc_log_level_actual = level;
    } else {
        GFC_LOG(GFC_LOG_LEVEL_ERROR, "Attempt to set invalid log level: %d. Keeping %d.", level, g_gfc_log_level_actual);
    }
}

int gfc_get_log_level_impl() {
    return g_gfc_log_level_actual;
}

// --- Other Helper Implementations (those that are not static inline) ---
bool hex_string_to_bytes_util(const char* hex_str, uint8_t* byte_array, size_t byte_array_len) {
    if (!hex_str) {
        GFC_LOG(GFC_LOG_LEVEL_ERROR, "hex_string_to_bytes_util: hex_str is NULL");
        return false;
    }
    size_t hex_len = strlen(hex_str);
    if (hex_len == 0 && byte_array_len == 0) return true;
    if (hex_len != byte_array_len * 2) {
         GFC_LOG(GFC_LOG_LEVEL_ERROR, "hex_string_to_bytes_util: Hex string length (%zu) is not double the expected for %zu bytes. Hex: '%s'", hex_len, byte_array_len, hex_str);
        return false;
    }
    for (size_t i = 0; i < byte_array_len; ++i) {
        unsigned int byte_val;
        if (sscanf(hex_str + 2 * i, "%2x", &byte_val) != 1) {
            GFC_LOG(GFC_LOG_LEVEL_ERROR, "hex_string_to_bytes_util: Failed to parse hex at position %zu of '%s'.", 2 * i, hex_str);
            return false;
        }
        byte_array[i] = static_cast<uint8_t>(byte_val);
    }
    return true;
}

bool read_file_into_vector_util(const std::string& filename, std::vector<uint8_t>& data_vec, char* error_msg_out, size_t error_msg_size) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        snprintf(error_msg_out, error_msg_size, "Could not open file: %s", filename.c_str());
        return false;
    }
    std::streamsize size = file.tellg();
    if (size < 0) {
        snprintf(error_msg_out, error_msg_size, "Error getting file size: %s", filename.c_str());
        file.close();
        return false;
    }
    if (size == 0) {
        GFC_LOG(GFC_LOG_LEVEL_DEBUG, "read_file_into_vector_util: File '%s' is empty.", filename.c_str());
        data_vec.clear(); // Ensure it's empty
        if(error_msg_out && error_msg_size > 0) strncpy(error_msg_out, "Success (empty file)", error_msg_size -1 );
        file.close();
        return true;
    }
    file.seekg(0, std::ios::beg);
    try {
        data_vec.resize(static_cast<size_t>(size));
    } catch (const std::bad_alloc& e) {
        snprintf(error_msg_out, error_msg_size, "Memory error resizing vector for file %s (size %lld)", filename.c_str(), static_cast<long long>(size));
        file.close();
        return false;
    }

    if (!file.read(reinterpret_cast<char*>(data_vec.data()), size)) {
        snprintf(error_msg_out, error_msg_size, "Error reading from file: %s", filename.c_str());
        file.close();
        return false;
    }
    file.close();
    if(error_msg_out && error_msg_size > 0) strncpy(error_msg_out, "Success", error_msg_size -1 );
    return true;
}

void printNonce_util(const std::vector<uint8_t>& nonce_vec, const std::string& label) {
    std::stringstream ss;
    ss << label << ": ";
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : nonce_vec) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    GFC_LOG(GFC_LOG_LEVEL_DEBUG, "%s", ss.str().c_str());
}

int get_cfitsio_datatype_from_bitpix_util(int bitpix_val) {
    switch (bitpix_val) {
    case BYTE_IMG: return TBYTE;
    case SHORT_IMG: return TSHORT;
    case LONG_IMG: return TLONG;
    case LONGLONG_IMG: return TLONGLONG;
    case FLOAT_IMG: return TFLOAT;
    case DOUBLE_IMG: return TDOUBLE;
    default:
        GFC_LOG(GFC_LOG_LEVEL_ERROR, "BITPIX not supported for conversion: %d", bitpix_val);
        throw std::runtime_error("BITPIX not supported for conversion to cfitsio_native_datatype: " + std::to_string(bitpix_val));
    }
}

bool copyFile_util(const std::string& sourcePath, const std::string& destPath) {
    GFC_LOG(GFC_LOG_LEVEL_INFO, "ℹ️ (Util) Copying '%s' to '%s'...", sourcePath.c_str(), destPath.c_str());
    if (sourcePath == destPath) {
        GFC_LOG(GFC_LOG_LEVEL_ERROR, "(Util) Error: Source and destination files are the same: %s", sourcePath.c_str());
        return false;
    }

    std::ifstream src(sourcePath, std::ios::binary);
    if (!src.is_open()) {
        GFC_LOG(GFC_LOG_LEVEL_ERROR, "(Util) Error: Could not open source file for copying: %s", sourcePath.c_str());
        return false;
    }
    std::ofstream dst(destPath, std::ios::binary | std::ios::trunc);
    if (!dst.is_open()) {
        GFC_LOG(GFC_LOG_LEVEL_ERROR, "(Util) Error: Could not create destination file for copying: %s", destPath.c_str());
        src.close();
        return false;
    }

    dst << src.rdbuf();

    bool success = true;
    if (src.bad() || (src.fail() && !src.eof())) {
        GFC_LOG(GFC_LOG_LEVEL_ERROR, "(Util) Error during source file read: %s", sourcePath.c_str());
        success = false;
    }
    if (dst.bad() || dst.fail()) {
        GFC_LOG(GFC_LOG_LEVEL_ERROR, "(Util) Error during destination file write: %s", destPath.c_str());
        success = false;
    }

    src.close();
    dst.close();

    if (success) {
        GFC_LOG(GFC_LOG_LEVEL_INFO, "(Util) ✅ Copy completed.");
    }
    return success;
}

void swap_endianness_if_needed_util(uint8_t *data, size_t data_size_bytes, int bitpix) {
    // Determine the number of bytes per element. If 1 or less, nothing to do.
    const int bytes_per_element = (bitpix != 0) ? (std::abs(bitpix) / 8) : 0;
    if (bytes_per_element <= 1) {
        return; // No swap needed for 8-bit or smaller data.
    }

    const size_t num_elements = data_size_bytes / bytes_per_element;

    for (size_t i = 0; i < num_elements; ++i) {
        // Get a pointer to the start of the current element
        uint8_t *p_element = data + (i * bytes_per_element);

        // Perform in-place swap
        switch (bytes_per_element) {
            case 2: // for BITPIX = 16
                std::swap(p_element[0], p_element[1]);
                break;
            case 4: // for BITPIX = 32 or -32
                std::swap(p_element[0], p_element[3]);
                std::swap(p_element[1], p_element[2]);
                break;
            case 8: // for BITPIX = 64 or -64
                std::swap(p_element[0], p_element[7]);
                std::swap(p_element[1], p_element[6]);
                std::swap(p_element[2], p_element[5]);
                std::swap(p_element[3], p_element[4]);
                break;
            default:
                // Do nothing for other element sizes
                break;
        }
    }
}