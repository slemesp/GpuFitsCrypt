// File: fits_crypto_operations.cu
#include "fits_crypto_operations.h" // Contains declarations for functions in this file
#include "lib_internal_utils.h"     // For GFC_LOG, UTIL_NONCE_SIZE_BYTES, and all _util helpers
#include "aes.h"                    // For aes128_keyschedule_lut and pack_nonce
#include <fitsio.h>                  // For all cfitsio functions
#include <fstream>
#include <vector>
#include <string>
#include <stdexcept>
#include <set>
#include <cstring> // For strncpy, memcpy, etc.
#include <cstdio>  // For remove
#include <ctime>   // For time() and srand() (though srand() should be called once)
#include "gcm_operations.h"

bool encrypt_fits_file(
    const std::string &inputFile,
    const std::string &outputFile,
    uint32_t *h_aes_key_exp_header,
    uint32_t *h_aes_key_exp_data) {
    GFC_LOG(GFC_LOG_LEVEL_INFO, "🔒 (FITS_OP) Encrypting (v2-bintable to file) from: %s to %s", inputFile.c_str(),
            outputFile.c_str());

    fitsfile *fptr_in = nullptr, *fptr_out = nullptr;
    int status = 0;
    char err_text[FLEN_ERRMSG];
    float gpu_time_header_ms = 0, gpu_time_data_ms = 0;

    std::vector<uint8_t> nonce_H(UTIL_NONCE_SIZE_BYTES);
    std::vector<uint8_t> nonce_D(UTIL_NONCE_SIZE_BYTES);
    std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
    if (urandom) {
        urandom.read(reinterpret_cast<char *>(nonce_H.data()), nonce_H.size());
        urandom.read(reinterpret_cast<char *>(nonce_D.data()), nonce_D.size());
        urandom.close();
    } else {
        throw std::runtime_error("Could not open /dev/urandom to generate nonces");
    }

    printNonce_util(nonce_H, "(FITS_OP) Nonce Header (Encrypt v2-bintable)");
    printNonce_util(nonce_D, "(FITS_OP) Nonce Data   (Encrypt v2-bintable)");

    try {
        // --- 1. Open input file and find the HDU with data ---
        if (fits_open_file(&fptr_in, inputFile.c_str(), READONLY, &status)) {
            fits_get_errstatus(status, err_text);
            GFC_LOG(GFC_LOG_LEVEL_ERROR, "FITS: Error opening input '%s': %s", inputFile.c_str(), err_text);
            throw std::runtime_error(std::string("FITS: Error opening input: ") + err_text);
        }

        // ! CORRECT CHANGE: Logic to find the first HDU with image data
        int num_hdus = 0;
        fits_get_num_hdus(fptr_in, &num_hdus, &status);
        int image_hdu_num = -1;
        for (int i = 1; i <= num_hdus; ++i) {
            int hdutype, naxis_check;
            fits_movabs_hdu(fptr_in, i, &hdutype, &status);
            if (hdutype == IMAGE_HDU) {
                fits_get_img_dim(fptr_in, &naxis_check, &status);
                if (naxis_check > 0) {
                    image_hdu_num = i;
                    GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(FITS_OP) Found image HDU with data at HDU #%d.",
                            image_hdu_num);
                    break;
                }
            }
        }
        if (image_hdu_num == -1) {
            GFC_LOG(GFC_LOG_LEVEL_DEBUG,
                    "(FITS_OP) No image HDU with NAXIS>0 found. Using primary HDU (HDU #1) and assuming there is no image data.");
            image_hdu_num = 1; // Continue with HDU 1 for the header, but data will be 0
        }
        fits_movabs_hdu(fptr_in, image_hdu_num, NULL, &status);
        if (status) {
            fits_get_errstatus(status, err_text);
            GFC_LOG(GFC_LOG_LEVEL_ERROR, "FITS: Error moving to image HDU #%d: %s", image_hdu_num, err_text);
            throw std::runtime_error("FITS: Error movabs_hdu on input while reading header.");
        }

        int essential_bitpix, essential_naxis;
        long essential_naxes[9];
        std::fill_n(essential_naxes, 9, 1L);
        if (fits_get_img_param(fptr_in, 9, &essential_bitpix, &essential_naxis, essential_naxes, &status)) {
            fits_get_errstatus(status, err_text);
            GFC_LOG(GFC_LOG_LEVEL_ERROR, "FITS: Error get_img_param for '%s' (HDU #%d): %s", inputFile.c_str(),
                    image_hdu_num, err_text);
            throw std::runtime_error(std::string("FITS: Error get_img_param on input: ") + err_text);
        }
        GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(FITS_OP) Params read from HDU #%d: BITPIX=%d, NAXIS=%d", image_hdu_num,
                essential_bitpix, essential_naxis);

        // --- 2. Read and Prepare Original Header for ENCHDR ---
        GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(FITS_OP) Reading full header (from HDU #%d) for ENCHDR...", image_hdu_num);
        std::vector<uint8_t> header_original_bytes_to_encrypt;
        char *header_str_logical = nullptr;
        int nkeys_dummy;

        if (fits_convert_hdr2str(fptr_in, 0, NULL, 0, &header_str_logical, &nkeys_dummy, &status)) {
            fits_get_errstatus(status, err_text);
            GFC_LOG(GFC_LOG_LEVEL_ERROR, "FITS: Error fits_convert_hdr2str(0) in '%s': %s", inputFile.c_str(),
                    err_text);
            if (header_str_logical)
                fits_free_memory(header_str_logical, &status);
            throw std::runtime_error(std::string("FITS: Error converting header(0) to string: ") + err_text);
        }
        if (!header_str_logical) { throw std::runtime_error("FITS: Header (getpad=0) could not be read."); }

        header_original_bytes_to_encrypt.assign(header_str_logical, header_str_logical + strlen(header_str_logical));
        fits_free_memory(header_str_logical, &status);
        header_str_logical = nullptr;

        size_t current_hdr_size = header_original_bytes_to_encrypt.size();
        size_t padded_hdr_size = ((current_hdr_size + FITS_BLOCK_SIZE - 1) / FITS_BLOCK_SIZE) * FITS_BLOCK_SIZE;
        if (padded_hdr_size > current_hdr_size) {
            header_original_bytes_to_encrypt.resize(padded_hdr_size, ' ');
        }
        GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(FITS_OP) Header for ENCHDR prepared: %zu bytes.",
                header_original_bytes_to_encrypt.size());

        // // --- DEBUG LOGGING SECTION START ---
        // {
        //     // Use a block so variables are local and do not interfere
        //     size_t hdr_size_bytes_log = header_original_bytes_to_encrypt.size();
        //     size_t hdr_size_words_log = (hdr_size_bytes_log + 3) / 4;
        //
        //     size_t totalBlocksAES_hdr_log = (hdr_size_words_log > 0) ? ((hdr_size_words_log + 3) / 4) : 0;
        //     size_t blocksPerThread_log = (size_t)8 * REPEATBS;
        //     size_t neededThreads_log = (totalBlocksAES_hdr_log > 0)
        //                                    ? ((totalBlocksAES_hdr_log + blocksPerThread_log - 1) / blocksPerThread_log)
        //                                    : 0;
        //
        //     // threadsPerBlockAES must match the threadSizeBS macro
        //     unsigned int threadsPerBlockAES_log = threadSizeBS;
        //     unsigned int numBlocksGrid_hdr_log = (neededThreads_log > 0)
        //                                              ? ((neededThreads_log + threadsPerBlockAES_log - 1) /
        //                                                  threadsPerBlockAES_log)
        //                                              : 0;
        //
        //     size_t aes_grid_total_threads_hdr_log = (size_t)numBlocksGrid_hdr_log * threadsPerBlockAES_log;
        //
        //     GFC_LOG(GFC_LOG_LEVEL_ERROR,
        //             "[ENCRYPT-H] HdrSizeBytes: %zu, HdrSizeWords: %zu, TotalThreads: %zu, NumBlocksGrid: %u",
        //             hdr_size_bytes_log, hdr_size_words_log, aes_grid_total_threads_hdr_log, numBlocksGrid_hdr_log);
        // }
        // // --- DEBUG LOGGING SECTION END ---

        // --- 3. Encrypt Header for ENCHDR ---
        size_t original_header_size_tp;
        if (!processDataWithGPU(header_original_bytes_to_encrypt, nonce_H, h_aes_key_exp_header,
                                gpu_time_header_ms, original_header_size_tp, GpuProcessingType::Generic, 0, 0)) {
            throw std::runtime_error("GPU: Failed to encrypt full header");
        }
        std::string hex_encrypted_header_original = bytesToHexString_util(header_original_bytes_to_encrypt);
        GFC_LOG(GFC_LOG_LEVEL_INFO, "(FITS_OP) GPU header for ENCHDR encrypted in %.2f ms.", gpu_time_header_ms);


        // --- 4. Create Output File and Primary HDU (for encryption metadata) ---
        if (fits_create_file(&fptr_out, ("!" + outputFile).c_str(), &status)) {
            fits_get_errstatus(status, err_text);
            GFC_LOG(GFC_LOG_LEVEL_ERROR, "FITS: Error creating output '%s': %s", outputFile.c_str(), err_text);
            throw std::runtime_error(std::string("FITS: Error creating output: ") + err_text);
        }

        // Create primary HDU with NAXIS=0 (metadata only)
        // Use BITPIX=8 by convention, but it does not matter for NAXIS=0
        if (fits_create_img(fptr_out, BYTE_IMG, 0, nullptr, &status)) {
            fits_get_errstatus(status, err_text);
            GFC_LOG(GFC_LOG_LEVEL_ERROR, "FITS: Error create_img (NAXIS=0) in '%s': %s", outputFile.c_str(), err_text);
            throw std::runtime_error(std::string("FITS: Error create_img (NAXIS=0) in output: ") + err_text);
        }
        GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(FITS_OP) Primary HDU (NAXIS=0) created in output.");

        // Write NONCEs and ENCHDR in the primary HDU
        std::string nonce_h_fits_str = nonceToFitsString_util(nonce_H); // 192-char string
        std::string nonce_d_fits_str = nonceToFitsString_util(nonce_D); // 192-char string

        GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(FITS_OP) NONCE_H string (len %zu): %.30s...", nonce_h_fits_str.length(),
                nonce_h_fits_str.c_str());
        GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(FITS_OP) NONCE_D string (len %zu): %.30s...", nonce_d_fits_str.length(),
                nonce_d_fits_str.c_str());

        char comment_nonce_h[] = "Nonce for encrypted header (hex, long)";
        status = 0; // Reset status
        if (fits_write_key_longstr(fptr_out, "NONCE_H", const_cast<char *>(nonce_h_fits_str.c_str()), comment_nonce_h,
                                   &status)) {
            fits_get_errstatus(status, err_text);
            GFC_LOG(GFC_LOG_LEVEL_ERROR, "FITS: Error writing NONCE_H (longstr): %s", err_text);
            throw std::runtime_error(std::string("FITS: Error writing NONCE_H (longstr): ") + err_text);
        }

        char comment_nonce_d[] = "Nonce for data unit (hex, long)";
        status = 0; // Reset status
        if (fits_write_key_longstr(fptr_out, "NONCE_D", const_cast<char *>(nonce_d_fits_str.c_str()), comment_nonce_d,
                                   &status)) {
            fits_get_errstatus(status, err_text);
            GFC_LOG(GFC_LOG_LEVEL_ERROR, "FITS: Error writing NONCE_D (longstr): %s", err_text);
            throw std::runtime_error(std::string("FITS: Error writing NONCE_D (longstr): ") + err_text);
        }

        // ENCHDR already uses longstr, which is correct
        status = 0; // Reset status
        if (fits_write_key_longstr(fptr_out, "ENCHDR", const_cast<char *>(hex_encrypted_header_original.c_str()),
                                   "Original FITS header, encrypted (hex)", &status)) {
            fits_get_errstatus(status, err_text);
            GFC_LOG(GFC_LOG_LEVEL_ERROR, "FITS: Error writing ENCHDR (longstr): %s", err_text);
            throw std::runtime_error(std::string("FITS: Error writing ENCHDR (longstr): ") + err_text);
        }
        GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(FITS_OP) NONCE_H, NONCE_D, ENCHDR written using longstr.");

        // Save original BITPIX/NAXIS/NAXES in the primary HDU for decryption reference
        // This determines how to interpret the data AFTER decryption
        status = 0; // Reset status before a block of key updates
        if (fits_update_key(fptr_out, TINT, "ORIG_BPX", &essential_bitpix, "Original BITPIX of data", &status) ||
            fits_update_key(fptr_out, TINT, "ORIG_NAX", &essential_naxis, "Original NAXIS of data", &status)) {
            fits_get_errstatus(status, err_text);
            GFC_LOG(GFC_LOG_LEVEL_ERROR, "FITS: Error writing ORIG_BPX/ORIG_NAX: %s", err_text);
            throw std::runtime_error(std::string("FITS: Error writing ORIG_* parameters: ") + err_text);
        }
        for (int i = 0; i < essential_naxis; ++i) {
            char keyname[FLEN_KEYWORD];
            snprintf(keyname, sizeof(keyname), "ORIG_NA%d", i + 1);
            if (fits_update_key(fptr_out, TLONG, keyname, &essential_naxes[i], "Original NAXISn of data", &status)) {
                fits_get_errstatus(status, err_text);
                GFC_LOG(GFC_LOG_LEVEL_ERROR, "FITS: Error writing %s: %s", keyname, err_text);
                throw std::runtime_error(std::string("FITS: Error writing ORIG_NAn parameter: ") + err_text);
            }
        }
        GFC_LOG(GFC_LOG_LEVEL_DEBUG,
                "(FITS_OP) Encryption metadata and original params (BPX=%d, NAX=%d) written to primary HDU.",
                essential_bitpix, essential_naxis);

        // --- 5. Read and Encrypt Original Image Data ---
        long total_pixels = 1;
        if (essential_naxis == 0) total_pixels = 0;
        else
            for (int i = 0; i < essential_naxis; i++) {
                if (essential_naxes[i] <= 0) {
                    total_pixels = 0;
                    break;
                }
                total_pixels *= essential_naxes[i];
            }

        long bytes_per_pixel_native = (essential_bitpix != 0) ? std::abs(essential_bitpix) / 8 : 0;
        long data_unit_total_bytes = total_pixels * bytes_per_pixel_native;
        std::vector<uint8_t> data_buffer_host;

        if (data_unit_total_bytes > 0) {
            GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(FITS_OP) Processing %ld bytes of image data...", data_unit_total_bytes);
            data_buffer_host.resize(data_unit_total_bytes);
            long firstpixel_orig[9];
            std::fill_n(firstpixel_orig, 9, 1L);
            int original_cfitsio_datatype = get_cfitsio_datatype_from_bitpix_util(essential_bitpix);

            // Ensure we are in the correct HDU before reading pixels
            fits_movabs_hdu(fptr_in, image_hdu_num, NULL, &status);
            if (status) { throw std::runtime_error("FITS: Error movabs_hdu on input while reading image data."); }

            if (fits_read_pix(fptr_in, original_cfitsio_datatype, firstpixel_orig, total_pixels, NULL,
                              data_buffer_host.data(), NULL, &status)) {
                fits_get_errstatus(status, err_text);
                GFC_LOG(GFC_LOG_LEVEL_ERROR, "FITS: Error read_pix for '%s': %s", inputFile.c_str(), err_text);
                throw std::runtime_error(std::string("FITS: Error reading image data (input): ") + err_text);
            }
            GFC_LOG(GFC_LOG_LEVEL_DEBUG,
                    "(FITS_OP) Image data read from input (Little-Endian in RAM). Sending directly to GPU for encryption.");

            // ! CRITICAL CHANGE: ENDIANNESS SWAP REMOVED.
            // Data is encrypted as-is in host memory (Little-Endian),
            // which is the format the decryption function will produce before its own swap.

            size_t original_data_size_tp_gpu;
            if (!processDataWithGPU(data_buffer_host, nonce_D, h_aes_key_exp_data,
                                    gpu_time_data_ms, original_data_size_tp_gpu,
                                    GpuProcessingType::Generic, 0, 0)) {
                throw std::runtime_error("GPU: Failed to encrypt FITS data");
            }
            GFC_LOG(GFC_LOG_LEVEL_INFO, "(FITS_OP) GPU image data encrypted in %.2f ms.", gpu_time_data_ms);
        } else {
            GFC_LOG(GFC_LOG_LEVEL_INFO, "(FITS_OP) Input HDU contained no image data to encrypt.");
        }

        // --- 6. Create BINTABLE Extension and Write Encrypted Data ---
        if (data_unit_total_bytes > 0) {
            GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(FITS_OP) Creating BINTABLE extension for encrypted data...");
            int tfields = 1; // Single column
            char extname[] = "ENCRYPTED_DATA"; // Extension name (optional but useful)

            // Column definitions
            char *ttype[] = {(char *) "RAW_BYTES"}; // Column name
            char tform_str[20]; // Column format, e.g.: "27174556B"
            snprintf(tform_str, sizeof(tform_str), "%ldB", data_unit_total_bytes);
            char *tform[] = {tform_str};
            char *tunit[] = {(char *) ""}; // Units (none)

            if (fits_create_tbl(fptr_out, BINARY_TBL, 0, tfields, ttype, tform, tunit, extname, &status)) {
                fits_get_errstatus(status, err_text);
                GFC_LOG(GFC_LOG_LEVEL_ERROR, "FITS: Error creating BINTABLE: %s", err_text);
                throw std::runtime_error(std::string("FITS: Error creating BINTABLE: ") + err_text);
            }
            GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(FITS_OP) BINTABLE created with column format: %s", tform_str);

            // Write encrypted data to the first (and only) row, first column
            long firstrow = 1;
            long firstelem = 1;
            if (fits_write_col_byt(fptr_out, 1, firstrow, firstelem, data_unit_total_bytes, data_buffer_host.data(),
                                   &status)) {
                fits_get_errstatus(status, err_text);
                GFC_LOG(GFC_LOG_LEVEL_ERROR, "FITS: Error writing encrypted data to BINTABLE: %s", err_text);
                throw std::runtime_error(std::string("FITS: Error writing data to BINTABLE: ") + err_text);
            }
            GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(FITS_OP) Encrypted data (%ld bytes) written to BINTABLE.",
                    data_unit_total_bytes);
        } else {
            // If there is no data, do not create the BINTABLE extension. Primary HDU with NAXIS=0 is enough.
            GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(FITS_OP) No image data to write to BINTABLE.");
        }
    } catch (const std::exception &e) {
        // ---- MANUAL RESOURCE CLEANUP ----

        GFC_LOG(GFC_LOG_LEVEL_ERROR, "(FITS_OP) Exception in encryptFits: %s", e.what());

        // Close input file if open
        if (fptr_in) {
            int s = 0;
            fits_close_file(fptr_in, &s);
            fptr_in = nullptr;
        }
        // Close and delete output file if open
        if (fptr_out) {
            int s = 0;
            fits_close_file(fptr_out, &s);
            fptr_out = nullptr;
            // Try to delete physically (use outputFile, not the pointer!)
            remove(outputFile.c_str());
        } else {
            // If the pointer doesn't exist, delete manually if the file was created
            remove(outputFile.c_str());
        }

        // ---- Finish by returning failure ----
        return false;
    }

    int final_status_in = 0, final_status_out = 0;
    if (fptr_in) {
        if (fits_close_file(fptr_in, &final_status_in))
            GFC_LOG(GFC_LOG_LEVEL_ERROR, "CFITSIO error closing input: %d", final_status_in);
    }
    if (fptr_out) {
        if (fits_close_file(fptr_out, &final_status_out))
            GFC_LOG(GFC_LOG_LEVEL_ERROR, "CFITSIO error closing output: %d", final_status_out);
    }

    if (final_status_in || final_status_out) { return false; }

    GFC_LOG(GFC_LOG_LEVEL_INFO, "(FITS_OP) Encryption operation (v2-bintable) completed for: %s", outputFile.c_str());
    return true;
}

// ==========================================================
// === NEW FUNCTION FOR GCM ENCRYPTION ======================
// ==========================================================
bool encrypt_fits_file_gcm(
    const std::string &inputFile,
    const std::string &outputFile,
    uint32_t *h_aes_key_exp_header,
    uint32_t *h_aes_key_exp_data)
{
    GFC_LOG(GFC_LOG_LEVEL_INFO, "🔒 (FITS_OP_GCM) Encrypting (AES-GCM) from: %s to %s", inputFile.c_str(), outputFile.c_str());

    fitsfile *fptr_in = nullptr, *fptr_out = nullptr;
    int status = 0;
    char err_text[FLEN_ERRMSG];

    // [GCM] Use 12-byte nonces (96 bits), which is the GCM standard.
    std::vector<uint8_t> nonce_H(UTIL_NONCE_SIZE_BYTES);
    std::vector<uint8_t> nonce_D(UTIL_NONCE_SIZE_BYTES);
    // [TODO] Generate secure random nonces here.
    // Using /dev/urandom as in the original function:
    std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
    if (urandom) {
        urandom.read(reinterpret_cast<char *>(nonce_H.data()), nonce_H.size());
        urandom.read(reinterpret_cast<char *>(nonce_D.data()), nonce_D.size());
        urandom.close();
    } else {
        throw std::runtime_error("Could not open /dev/urandom to generate GCM nonces");
    }

    printNonce_util(nonce_H, "(FITS_OP_GCM) Nonce Header (Encrypt GCM)");
    printNonce_util(nonce_D, "(FITS_OP_GCM) Nonce Data   (Encrypt GCM)");


    try {
        // --- 1. Open input file and find the HDU with data ---
        if (fits_open_file(&fptr_in, inputFile.c_str(), READONLY, &status)) {
            fits_get_errstatus(status, err_text);
            GFC_LOG(GFC_LOG_LEVEL_ERROR, "FITS: Error opening input '%s': %s", inputFile.c_str(), err_text);
            throw std::runtime_error(std::string("FITS: Error opening input: ") + err_text);
        }

        int num_hdus = 0;
        fits_get_num_hdus(fptr_in, &num_hdus, &status);
        int image_hdu_num = -1;
        for (int i = 1; i <= num_hdus; ++i) {
            int hdutype, naxis_check;
            fits_movabs_hdu(fptr_in, i, &hdutype, &status);
            if (hdutype == IMAGE_HDU) {
                fits_get_img_dim(fptr_in, &naxis_check, &status);
                if (naxis_check > 0) {
                    image_hdu_num = i;
                    GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(FITS_OP_GCM) Found image HDU with data at HDU #%d.",
                            image_hdu_num);
                    break;
                }
            }
        }
        if (image_hdu_num == -1) {
            GFC_LOG(GFC_LOG_LEVEL_DEBUG,
                    "(FITS_OP_GCM) No image HDU with NAXIS>0 found. Using primary HDU (HDU #1) and assuming there is no image data.")
            ;
            image_hdu_num = 1;
        }
        fits_movabs_hdu(fptr_in, image_hdu_num, NULL, &status);
        if (status) {
            fits_get_errstatus(status, err_text);
            GFC_LOG(GFC_LOG_LEVEL_ERROR, "FITS: Error moving to image HDU #%d: %s", image_hdu_num, err_text);
            throw std::runtime_error("FITS: Error movabs_hdu on input while reading header.");
        }

        int essential_bitpix, essential_naxis;
        long essential_naxes[9];
        std::fill_n(essential_naxes, 9, 1L);
        if (fits_get_img_param(fptr_in, 9, &essential_bitpix, &essential_naxis, essential_naxes, &status)) {
            fits_get_errstatus(status, err_text);
            GFC_LOG(GFC_LOG_LEVEL_ERROR, "FITS: Error get_img_param for '%s' (HDU #%d): %s", inputFile.c_str(),
                    image_hdu_num, err_text);
            throw std::runtime_error(std::string("FITS: Error get_img_param on input: ") + err_text);
        }
        GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(FITS_OP_GCM) Params read from HDU #%d: BITPIX=%d, NAXIS=%d", image_hdu_num,
                essential_bitpix, essential_naxis);

        // --- 2. Read and Prepare Original Header for ENCHDR ---
        GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(FITS_OP_GCM) Reading full header (from HDU #%d) for ENCHDR...", image_hdu_num);
        std::vector<uint8_t> header_original_bytes_to_encrypt;
        char *header_str_logical = nullptr;
        int nkeys_dummy;

        if (fits_convert_hdr2str(fptr_in, 0, NULL, 0, &header_str_logical, &nkeys_dummy, &status)) {
            fits_get_errstatus(status, err_text);
            GFC_LOG(GFC_LOG_LEVEL_ERROR, "FITS: Error fits_convert_hdr2str(0) in '%s': %s", inputFile.c_str(),
                    err_text);
            if (header_str_logical)
                fits_free_memory(header_str_logical, &status);
            throw std::runtime_error(std::string("FITS: Error converting header(0) to string: ") + err_text);
        }
        if (!header_str_logical) { throw std::runtime_error("FITS: Header (getpad=0) could not be read."); }

        header_original_bytes_to_encrypt.assign(header_str_logical, header_str_logical + strlen(header_str_logical));
        fits_free_memory(header_str_logical, &status);
        header_str_logical = nullptr;

        size_t current_hdr_size = header_original_bytes_to_encrypt.size();
        size_t padded_hdr_size = ((current_hdr_size + FITS_BLOCK_SIZE - 1) / FITS_BLOCK_SIZE) * FITS_BLOCK_SIZE;
        if (padded_hdr_size > current_hdr_size) {
            header_original_bytes_to_encrypt.resize(padded_hdr_size, ' ');
        }
        GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(FITS_OP_GCM) Header for ENCHDR prepared: %zu bytes.",
                header_original_bytes_to_encrypt.size());

        // --- 3. Encrypt Header with GCM ---
        GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(FITS_OP_GCM) Encrypting header with GCM...");
        std::vector<uint8_t> header_aad; // Empty AAD for the header
        GcmEncryptionResult header_encrypt_result = gcmEncrypt(
            header_original_bytes_to_encrypt,
            header_aad,
            h_aes_key_exp_header,
            nonce_H
        );
        if (!header_encrypt_result.success) {
            throw std::runtime_error("GPU: Failed to encrypt header with GCM");
        }
        std::string hex_encrypted_header = bytesToHexString_util(header_encrypt_result.ciphertext);
        std::string header_authtag_hex = bytesToHexString_util(header_encrypt_result.auth_tag);
        GFC_LOG(GFC_LOG_LEVEL_INFO, "(FITS_OP_GCM) GPU header for ENCHDR encrypted (GCM).");


        // --- 4. Create Output File and Primary HDU (for encryption metadata) ---
        if (fits_create_file(&fptr_out, ("!" + outputFile).c_str(), &status)) {
            fits_get_errstatus(status, err_text);
            GFC_LOG(GFC_LOG_LEVEL_ERROR, "FITS: Error creating output '%s': %s", outputFile.c_str(), err_text);
            throw std::runtime_error(std::string("FITS: Error creating output: ") + err_text);
        }

        // Create primary HDU with NAXIS=0 (metadata only)
        if (fits_create_img(fptr_out, BYTE_IMG, 0, nullptr, &status)) {
            fits_get_errstatus(status, err_text);
            GFC_LOG(GFC_LOG_LEVEL_ERROR, "FITS: Error create_img (NAXIS=0) in '%s': %s", outputFile.c_str(), err_text);
            throw std::runtime_error(std::string("FITS: Error create_img (NAXIS=0) in output: ") + err_text);
        }
        GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(FITS_OP_GCM) Primary HDU (NAXIS=0) created in output.");

        // --- 5. Write GCM metadata to the primary HDU ---
        std::string nonce_h_fits_str = nonceToFitsString_util(nonce_H);
        std::string nonce_d_fits_str = nonceToFitsString_util(nonce_D);

        GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(FITS_OP_GCM) NONCE_H string (len %zu): %.30s...", nonce_h_fits_str.length(),
                nonce_h_fits_str.c_str());
        GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(FITS_OP_GCM) NONCE_D string (len %zu): %.30s...", nonce_d_fits_str.length(),
                nonce_d_fits_str.c_str());

        char comment_nonce_h[] = "Nonce for encrypted header (hex, GCM)";
        status = 0;
        if (fits_write_key_longstr(fptr_out, "NONCE_H", const_cast<char *>(nonce_h_fits_str.c_str()), comment_nonce_h,
                                   &status)) {
            fits_get_errstatus(status, err_text);
            GFC_LOG(GFC_LOG_LEVEL_ERROR, "FITS: Error writing NONCE_H (longstr): %s", err_text);
            throw std::runtime_error(std::string("FITS: Error writing NONCE_H (longstr): ") + err_text);
        }

        char comment_nonce_d[] = "Nonce for data unit (hex, GCM)";
        status = 0;
        if (fits_write_key_longstr(fptr_out, "NONCE_D", const_cast<char *>(nonce_d_fits_str.c_str()), comment_nonce_d,
                                   &status)) {
            fits_get_errstatus(status, err_text);
            GFC_LOG(GFC_LOG_LEVEL_ERROR, "FITS: Error writing NONCE_D (longstr): %s", err_text);
            throw std::runtime_error(std::string("FITS: Error writing NONCE_D (longstr): ") + err_text);
        }

        status = 0;
        if (fits_write_key_longstr(fptr_out, "ENCHDR", const_cast<char *>(hex_encrypted_header.c_str()),
                                   "Original FITS header, encrypted (hex, GCM)", &status)) {
            fits_get_errstatus(status, err_text);
            GFC_LOG(GFC_LOG_LEVEL_ERROR, "FITS: Error writing ENCHDR (longstr): %s", err_text);
            throw std::runtime_error(std::string("FITS: Error writing ENCHDR (longstr): ") + err_text);
        }

        status = 0;
        if (fits_write_key_longstr(fptr_out, "AUTHTAG_H", const_cast<char *>(header_authtag_hex.c_str()),
                                   "Auth Tag for ENCHDR (GCM)", &status)) {
            fits_get_errstatus(status, err_text);
            GFC_LOG(GFC_LOG_LEVEL_ERROR, "FITS: Error writing AUTHTAG_H (longstr): %s", err_text);
            throw std::runtime_error(std::string("FITS: Error writing AUTHTAG_H (longstr): ") + err_text);
        }
        GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(FITS_OP_GCM) NONCE_H, NONCE_D, ENCHDR, AUTHTAG_H written using longstr.");

        // Save original BITPIX/NAXIS/NAXES in the primary HDU for decryption reference
        status = 0;
        if (fits_update_key(fptr_out, TINT, "ORIG_BPX", &essential_bitpix, "Original BITPIX of data", &status) ||
            fits_update_key(fptr_out, TINT, "ORIG_NAX", &essential_naxis, "Original NAXIS of data", &status)) {
            fits_get_errstatus(status, err_text);
            GFC_LOG(GFC_LOG_LEVEL_ERROR, "FITS: Error writing ORIG_BPX/ORIG_NAX: %s", err_text);
            throw std::runtime_error(std::string("FITS: Error writing ORIG_* parameters: ") + err_text);
        }
        for (int i = 0; i < essential_naxis; ++i) {
            char keyname[FLEN_KEYWORD];
            snprintf(keyname, sizeof(keyname), "ORIG_NA%d", i + 1);
            if (fits_update_key(fptr_out, TLONG, keyname, &essential_naxes[i], "Original NAXISn of data", &status)) {
                fits_get_errstatus(status, err_text);
                GFC_LOG(GFC_LOG_LEVEL_ERROR, "FITS: Error writing %s: %s", keyname, err_text);
                throw std::runtime_error(std::string("FITS: Error writing ORIG_NAn parameter: ") + err_text);
            }
        }
        GFC_LOG(GFC_LOG_LEVEL_DEBUG,
                "(FITS_OP_GCM) Encryption metadata and original params (BPX=%d, NAX=%d) written to primary HDU.",
                essential_bitpix, essential_naxis);

        // --- 6. Read and Encrypt Original Image Data ---
        long total_pixels = 1;
        if (essential_naxis == 0) total_pixels = 0;
        else
            for (int i = 0; i < essential_naxis; i++) {
                if (essential_naxes[i] <= 0) {
                    total_pixels = 0;
                    break;
                }
                total_pixels *= essential_naxes[i];
            }

        long bytes_per_pixel_native = (essential_bitpix != 0) ? std::abs(essential_bitpix) / 8 : 0;
        long data_unit_total_bytes = total_pixels * bytes_per_pixel_native;
        std::vector<uint8_t> data_buffer_host;
        GcmEncryptionResult data_encrypt_result; // Declare here for scope

        if (data_unit_total_bytes > 0) {
            GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(FITS_OP_GCM) Processing %ld bytes of image data...", data_unit_total_bytes);
            data_buffer_host.resize(data_unit_total_bytes);
            long firstpixel_orig[9];
            std::fill_n(firstpixel_orig, 9, 1L);
            int original_cfitsio_datatype = get_cfitsio_datatype_from_bitpix_util(essential_bitpix);

            // Ensure we are in the correct HDU before reading pixels
            fits_movabs_hdu(fptr_in, image_hdu_num, NULL, &status);
            if (status) { throw std::runtime_error("FITS: Error movabs_hdu on input while reading image data."); }

            if (fits_read_pix(fptr_in, original_cfitsio_datatype, firstpixel_orig, total_pixels, NULL,
                              data_buffer_host.data(), NULL, &status)) {
                fits_get_errstatus(status, err_text);
                GFC_LOG(GFC_LOG_LEVEL_ERROR, "FITS: Error read_pix for '%s': %s", inputFile.c_str(), err_text);
                throw std::runtime_error(std::string("FITS: Error reading image data (input): ") + err_text);
            }
            GFC_LOG(GFC_LOG_LEVEL_DEBUG,
                    "(FITS_OP_GCM) Image data read from input (Little-Endian in RAM). Sending directly to GPU for encryption.");

            // --- 5a. Build AAD for the data. MUST BE CONSISTENT!
            std::vector<uint8_t> data_aad;
            // Example AAD: nonce + important keywords.
            data_aad.insert(data_aad.end(), nonce_D.begin(), nonce_D.end());
            // [TODO] Add other metadata you want to protect against tampering.
            // For example, original BITPIX and NAXIS, converted to string or bytes.
            std::string orig_bpx_str = std::to_string(essential_bitpix);
            data_aad.insert(data_aad.end(), orig_bpx_str.begin(), orig_bpx_str.end());
            std::string orig_nax_str = std::to_string(essential_naxis);
            data_aad.insert(data_aad.end(), orig_nax_str.begin(), orig_nax_str.end());
            for (int i = 0; i < essential_naxis; ++i) {
                std::string orig_naxn_str = std::to_string(essential_naxes[i]);
                data_aad.insert(data_aad.end(), orig_naxn_str.begin(), orig_naxn_str.end());
            }

            // 5b. Call the GCM encryption function
            data_encrypt_result = gcmEncrypt(
                data_buffer_host,
                data_aad,
                h_aes_key_exp_data,
                nonce_D
            );
            if (!data_encrypt_result.success) {
                throw std::runtime_error("GPU: Failed to encrypt image data with GCM");
            }
            GFC_LOG(GFC_LOG_LEVEL_INFO, "(FITS_OP_GCM) GPU image data encrypted (GCM).");

            // 5c. Write the data tag in the primary HDU
            std::string data_authtag_hex = bytesToHexString_util(data_encrypt_result.auth_tag);
            status = 0; // Reset status
            if (fits_update_key_longstr(fptr_out, "AUTHTAG_D", const_cast<char *>(data_authtag_hex.c_str()),
                                        "Auth Tag for ENCRYPTED_DATA (GCM)", &status)) {
                fits_get_errstatus(status, err_text);
                GFC_LOG(GFC_LOG_LEVEL_ERROR, "FITS: Error writing AUTHTAG_D (longstr): %s", err_text);
                throw std::runtime_error(std::string("FITS: Error writing AUTHTAG_D (longstr): ") + err_text);
            }
            GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(FITS_OP_GCM) AUTHTAG_D written using longstr.");

            // 5d. Create BINTABLE extension and write encrypted data
            GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(FITS_OP_GCM) Creating BINTABLE extension for encrypted data...");
            int tfields = 1;
            char extname[] = "ENCRYPTED_DATA";

            char tform_str[20];
            snprintf(tform_str, sizeof(tform_str), "%ldB", data_encrypt_result.ciphertext.size()); // Use ciphertext size
            char *ttype[] = {(char *) "RAW_BYTES"};
            char *tform[] = {tform_str};
            char *tunit[] = {(char *) ""};

            if (fits_create_tbl(fptr_out, BINARY_TBL, 0, tfields, ttype, tform, tunit, extname, &status)) {
                fits_get_errstatus(status, err_text);
                GFC_LOG(GFC_LOG_LEVEL_ERROR, "FITS: Error creating BINTABLE: %s", err_text);
                throw std::runtime_error(std::string("FITS: Error creating BINTABLE: ") + err_text);
            }
            GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(FITS_OP_GCM) BINTABLE created with column format: %s", tform_str);

            long firstrow = 1;
            long firstelem = 1;
            if (fits_write_col_byt(fptr_out, 1, firstrow, firstelem, data_encrypt_result.ciphertext.size(),
                                   data_encrypt_result.ciphertext.data(), &status)) {
                fits_get_errstatus(status, err_text);
                GFC_LOG(GFC_LOG_LEVEL_ERROR, "FITS: Error writing encrypted data to BINTABLE: %s", err_text);
                throw std::runtime_error(std::string("FITS: Error writing data to BINTABLE: ") + err_text);
            }
            GFC_LOG(GFC_LOG_LEVEL_DEBUG, "(FITS_OP_GCM) Encrypted data (%zu bytes) written to BINTABLE.",
                    data_encrypt_result.ciphertext.size());
        } else {
            GFC_LOG(GFC_LOG_LEVEL_INFO, "(FITS_OP_GCM) Input HDU contained no image data to encrypt.");
        }

    } catch (const std::exception &e) {
        GFC_LOG(GFC_LOG_LEVEL_ERROR, "(FITS_OP_GCM) Exception in encrypt_fits_file_gcm: %s", e.what());

        if (fptr_in) {
            int s = 0;
            fits_close_file(fptr_in, &s);
            fptr_in = nullptr;
        }
        if (fptr_out) {
            int s = 0;
            fits_close_file(fptr_out, &s);
            fptr_out = nullptr;
            remove(outputFile.c_str());
        } else {
            remove(outputFile.c_str());
        }
        return false;
    }

    int final_status_in = 0, final_status_out = 0;
    if (fptr_in) {
        if (fits_close_file(fptr_in, &final_status_in))
            GFC_LOG(GFC_LOG_LEVEL_ERROR, "CFITSIO error closing input: %d", final_status_in);
    }
    if (fptr_out) {
        if (fits_close_file(fptr_out, &final_status_out))
            GFC_LOG(GFC_LOG_LEVEL_ERROR, "CFITSIO error closing output: %d", final_status_out);
    }

    if (final_status_in || final_status_out) { return false; }

    GFC_LOG(GFC_LOG_LEVEL_INFO, "(FITS_OP_GCM) GCM encryption completed for: %s", outputFile.c_str());
    return true;
}
