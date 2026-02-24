// aes_main.cu
#include "cuda_runtime.h"               // If CUDA API is used directly here (unlikely with the new structure)
#include "device_launch_parameters.h"   // If kernels are launched directly here (unlikely)

#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <stdexcept> // For std::runtime_error
#include <cstdint>   // For uint32_t, uint8_t
#include <cstring>   // For strcmp, etc.
#include <iomanip>   // For std::setw, std::setfill, std::hex, std::dec

// Project headers
#include "lib_internal_utils.h"     // For GFC_LOG, hex_string_to_bytes_util, etc.
#include "fits_crypto_operations.h" // For _to_file/_from_file
#include "aes.h"                    // For aes128_keyschedule_lut

// --- main ---
int main(int argc, char* argv[]) {
    // Set a log level for this executable (optional, can be different from the lib)
    // For GFC_LOG to work here, g_gfc_log_level_actual must be accessible (defined in lib_internal_utils.cpp)
    // and gfc_set_log_level_impl too.
    // If you prefer, this main can use std::cout/cerr directly.
    // Let's assume we want to use GFC_LOG:
    if (argc > 1 && strcmp(argv[argc-1], "--debuglog") == 0) {
        gfc_set_log_level_impl(GFC_LOG_LEVEL_DEBUG); // Use the impl directly
        argc--; // Consume the argument
        GFC_LOG(GFC_LOG_LEVEL_INFO, "(aes_main) DEBUG log level activated.");
    } else {
        gfc_set_log_level_impl(GFC_LOG_LEVEL_INFO); // Default level
    }


    if (argc < 4) {
        // Update this message to reflect only file operations
        GFC_LOG(GFC_LOG_LEVEL_ERROR, "Insufficient usage. Options:\n"
            "  %s <operation> <f_in> <f_out> <key_H_file|NO_KEY> <key_D_file|NO_KEY>\n"
            "Operations:\n"
            "  encrypt_hdr_data <f_in> <f_out> <f_key_H_hex_file> <f_key_D_hex_file>\n"
            "  encrypt_hdr_data_gcm <f_in> <f_out> <f_key_H_hex_file> <f_key_D_hex_file>\n"
            "  decrypt_hdr_data <f_in> <f_out> <f_key_H_hex_file|NO_KEY> <f_key_D_hex_file|NO_KEY>\n"
            "  (For _full or _data_only operations, you would need to add them here again if you want them in this executable)", argv[0]);
        return 1;
    }

    std::string operation = argv[1];
    std::string inputFile = argv[2];
    std::string outputFile = argv[3];
    std::string keyFileHeader_str, keyFileData_str;

    bool encrypt_op_mode = false;
    bool encrypt_gcm_mode = false;
    bool hdr_data_op_mode = false;

    if (operation == "encrypt_hdr_data") {
        encrypt_op_mode = true;
        hdr_data_op_mode = true;
        if (argc != 6) {
            GFC_LOG(GFC_LOG_LEVEL_ERROR, "encrypt_hdr_data requires <f_in> <f_out> <key_H_file> <key_D_file>");
            return 1;
        }
        keyFileHeader_str = argv[4];
        keyFileData_str = argv[5];
    } else if (operation == "encrypt_hdr_data_gcm") {
        encrypt_op_mode = true;
        encrypt_gcm_mode = true;
        hdr_data_op_mode = true;
        if (argc != 6) {
            GFC_LOG(GFC_LOG_LEVEL_ERROR, "encrypt_hdr_data_gcm requires <f_in> <f_out> <key_H_file> <key_D_file>");
            return 1;
        }
        keyFileHeader_str = argv[4];
        keyFileData_str = argv[5];
    } else if (operation == "decrypt_hdr_data") {
        encrypt_op_mode = false;
        hdr_data_op_mode = true;
        if (argc != 6) {
            GFC_LOG(GFC_LOG_LEVEL_ERROR, "decrypt_hdr_data requires <f_in> <f_out> <key_H_file|NO_KEY> <key_D_file|NO_KEY>");
            return 1;
        }
        keyFileHeader_str = argv[4];
        keyFileData_str = argv[5];
    } else {
        GFC_LOG(GFC_LOG_LEVEL_ERROR, "Invalid operation for 'aes_main': %s", operation.c_str());
        return 1;
    }

    // --- Read Key(s) ---
    // Use a lambda to read the key from a file and expand it
    auto readKeyHexFromFileAndExpand = [&](const std::string& key_filename, uint32_t* key_expansion_array) {
        std::ifstream key_stream(key_filename);
        if (!key_stream) {
            throw std::runtime_error("Error: Could not open key file: " + key_filename);
        }
        std::string key_hex_string;
        key_stream >> key_hex_string;
        key_stream.close();

        if (key_hex_string.length() != 32) {
            throw std::runtime_error("Error: The key in " + key_filename + " must have 32 hexadecimal characters (128 bits). Found: " + key_hex_string);
        }

        uint8_t key_bytes[16];
        if (!hex_string_to_bytes_util(key_hex_string.c_str(), key_bytes, 16)) { // Use the helper
             throw std::runtime_error("Error: Invalid format in hexadecimal key file " + key_filename);
        }
        
        aes128_keyschedule_lut(key_expansion_array, key_bytes); // Declared in aes.h
        GFC_LOG(GFC_LOG_LEVEL_INFO, "(aes_main) Key read and expanded from: %s", key_filename.c_str());
    };

    uint32_t h_aes_key_exp_H[352];
    uint32_t h_aes_key_exp_D[352];
    uint32_t* p_key_H = nullptr;
    uint32_t* p_key_D = nullptr;

    try {
        if (hdr_data_op_mode) {
            if (keyFileHeader_str != "NO_KEY" && !keyFileHeader_str.empty()) {
                readKeyHexFromFileAndExpand(keyFileHeader_str, h_aes_key_exp_H);
                p_key_H = h_aes_key_exp_H;
            } else {
                GFC_LOG(GFC_LOG_LEVEL_INFO, "(aes_main) Header key not provided (NO_KEY).");
            }
            if (keyFileData_str != "NO_KEY" && !keyFileData_str.empty()) {
                readKeyHexFromFileAndExpand(keyFileData_str, h_aes_key_exp_D);
                p_key_D = h_aes_key_exp_D;
            } else {
                GFC_LOG(GFC_LOG_LEVEL_INFO, "(aes_main) Data key not provided (NO_KEY).");
            }
        }
        // Logic for other modes would go here if you reimplement them in this executable
    } catch (const std::runtime_error& e) {
        GFC_LOG(GFC_LOG_LEVEL_ERROR, "(aes_main) Error processing keys: %s", e.what());
        return 1;
    }

    // --- CUDA Initialization (optional here if the called functions do it) ---
    // cudaDeviceProp deviceProp;
    // int deviceId = 0;
    // cudaGetDeviceProperties(&deviceProp, deviceId); // Error check
    // cudaSetDevice(deviceId); // Error check
    // GFC_LOG(GFC_LOG_LEVEL_INFO, "(aes_main) Using GPU: %s", deviceProp.name);
    // cudaDeviceSetSharedMemConfig(cudaSharedMemBankSizeEightByte); // Error check

    bool success = false;
    if (hdr_data_op_mode) {
        if (encrypt_op_mode) {
            if (!p_key_H || !p_key_D) {
                GFC_LOG(GFC_LOG_LEVEL_ERROR, "(aes_main) Error: 'encrypt_hdr_data' encryption requires both keys.");
                return 1;
            }
            if (encrypt_gcm_mode) {
                GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(aes_main) Calling encrypt_fits_file_gcm...");
                success = encrypt_fits_file_gcm(inputFile, outputFile, p_key_H, p_key_D);
            } else {
                GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(aes_main) Calling encrypt_fits_file...");
                success = encrypt_fits_file(inputFile, outputFile, p_key_H, p_key_D);
            }
        } else { // decrypt_op_mode
            GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(aes_main) Calling decryptFitsHeaderAndDataGPU_v3_from_file...");
            // success = decryptFitsHeaderAndDataGPU_v3_from_file(inputFile, outputFile, p_key_H, p_key_D);
        }
    } else {
        // Implement other modes if needed for the 'aes' executable
        GFC_LOG(GFC_LOG_LEVEL_ERROR, "(aes_main) Operation mode '%s' not fully implemented in this executable.", operation.c_str());
        return 1;
    }

    // cudaDeviceReset(); // Optional, depends on whether you want to keep the context alive

    if (success) {
        GFC_LOG(GFC_LOG_LEVEL_INFO, "\n(aes_main) Operation (%s) completed successfully.", operation.c_str());
        return 0;
    } else {
        GFC_LOG(GFC_LOG_LEVEL_ERROR, "\n(aes_main) Operation (%s) failed.", operation.c_str());
        return 1;
    }
}