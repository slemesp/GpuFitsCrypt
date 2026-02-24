// File: fits_crypto_operations.h
#ifndef FITS_CRYPTO_OPERATIONS_H
#define FITS_CRYPTO_OPERATIONS_H

#include <string>
#include <cstdint> // For uint32_t

#include "libgpufitscrypt.h"

/**
 * @brief Encrypts a FITS file (header and data) according to "v2" logic.
 * Writes the result to outputFile.
 *
 * @param inputFile Path to the original FITS file.
 * @param outputFile Path where the encrypted FITS will be saved.
 * @param h_aes_key_exp_header Pointer to the expanded AES key for the header.
 * @param h_aes_key_exp_data Pointer to the expanded AES key for the data.
 * @return true if the operation was successful, false otherwise.
 *         Detailed errors will be logged using GFC_LOG.
 */
bool encrypt_fits_file(
    const std::string& inputFile,
    const std::string& outputFile,
    uint32_t* h_aes_key_exp_header,
    uint32_t* h_aes_key_exp_data
);

// --- NEW FUNCTIONS FOR GCM ---

/**
 * @brief (GCM VERSION) Performs encryption of a FITS file using AES-GCM.
 *        Encrypts the header and data separately, and stores the authentication tags.
 *
 * @param inputFile Path to the original FITS file.
 * @param outputFile Path where the encrypted file will be saved.
 * @param h_aes_key_exp_header Expanded AES key for the header.
 * @param h_aes_key_exp_data Expanded AES key for the image data.
 * @return true if the operation was successful, false otherwise.
 */
bool encrypt_fits_file_gcm(
    const std::string &inputFile,
    const std::string &outputFile,
    uint32_t *h_aes_key_exp_header,
    uint32_t *h_aes_key_exp_data
);

#endif // FITS_CRYPTO_OPERATIONS_H
