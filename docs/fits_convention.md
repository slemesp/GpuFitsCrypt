# FITS Convention: GpuFitsCrypt Encrypted Container

**Convention Name:** GpuFitsCrypt Encrypted Container and Granular Access Control  
**Authors:** Samuel Lemes-Perera, Miguel R. Alarcón, Pino Caballero-Gil, Miquel Serra-Ricart  
**Affiliations:** Universidad de La Laguna (ULL), Light Bridges  
**Date:** September 2026  
**Status:** User Convention / Registered Candidate  
**Reference Paper:** *Astronomy and Computing*, 2026, [DOI: 10.1016/j.ascom.2026.101153](https://doi.org/10.1016/j.ascom.2026.101153)  
**arXiv Preprint:** [arXiv:2602.23067](https://arxiv.org/abs/2602.23067)  
**ASCL Record:** [ascl:2603.021](https://ascl.net/2603.021) | **NASA ADS Bibcode:** [2026ascl.soft03021L](https://ui.adsabs.harvard.edu/abs/2026ascl.soft03021L/abstract)

---

## 1. Overview & Purpose

The FITS standard (Flexible Image Transport System) defines a universal data format for astronomical imaging and tables. While modern open science promotes Findable, Accessible, Interoperable, and Reusable (FAIR) data practices, astronomical facilities frequently impose proprietary observation periods during which scientific payloads must remain strictly confidential while maintaining data integrity.

This convention specifies a syntactically conforming FITS container for storing encrypted astronomical images and tables using authenticated symmetric cryptography (AES-GCM and AES-CTR) accelerated on GPUs:
* **Syntactic Conformance**: Encrypted files remain standard FITS containers parseable by any conforming FITS reader (`cfitsio`, Astropy, DS9) without crashes or syntax errors.
* **Granular Access Control**: Decouples metadata encryption (Header) from pixel payload encryption (Data), allowing data providers to grant metadata-only access (for catalog indexing) without revealing proprietary pixel data.

---

## 2. Container Architecture

The convention organizes the encrypted file using a standard two-HDU structure:

```
+-------------------------------------------------------------+
| Primary HDU: Metadata & Encryption Envelope                 |
|   - NAXIS = 0 (No raw pixel data exposed)                   |
|   - Encapsulation keywords: NONCE_H, NONCE_D, ENCHDR        |
|   - Integrity tags: AUTHTAG_H, AUTHTAG_D                    |
|   - Reconstruction geometry: ORIG_BPX, ORIG_NAX, ORIG_NA1.. |
|   - Standard FITS integrity: CHECKSUM, DATASUM              |
+-------------------------------------------------------------+
| Extension 1: Binary Table HDU (EXTNAME = 'ENCRYPTED_DATA')  |
|   - XTENSION = 'BINTABLE'                                   |
|   - Single column: TTYPE1 = 'RAW_BYTES', TFORM1 = '<size>B' |
|   - Payload: Ciphertext bytes                               |
|   - Standard FITS integrity: CHECKSUM, DATASUM              |
+-------------------------------------------------------------+
```

### 2.1 Primary HDU (Header & Encryption Envelope)

* `SIMPLE = T`: Conforms to standard FITS syntax.
* `BITPIX = 8` and `NAXIS = 0`: In fully encrypted state, no unencrypted pixel array is exposed in the primary HDU.
* **Granular Access (Header Key Only)**: The original header is decrypted, while pixel data in Extension 1 remains physically suppressed/encrypted.
* **Granular Access (Data Key Only)**: A sanitized fallback header is provided in the primary HDU, while the pixel data is decrypted into the requested memory buffer.

### 2.2 Extension HDU: `ENCRYPTED_DATA`

* `XTENSION = 'BINTABLE'`: Conforms to standard FITS binary table extension rules.
* `EXTNAME = 'ENCRYPTED_DATA'`: Unique extension name identifying the encrypted payload.
* `TTYPE1 = 'RAW_BYTES'`, `TFORM1 = '<size>B'`: Encapsulates the exact ciphertext byte stream in a single column.

---

## 3. Keyword Dictionary

The following keywords are introduced by this convention:

### `NONCE_H`
* **Data Type:** String (hex-encoded, uses `CONTINUE` convention for long strings)
* **Description:** Cryptographic initialization vector / nonce (96-bit for GCM, 128-bit for CTR) used to encrypt the primary FITS header (`ENCHDR`).
* **Example:** `NONCE_H = 'a171ff0e30cc7f2a088b845b'`

### `NONCE_D`
* **Data Type:** String (hex-encoded, uses `CONTINUE` convention for long strings)
* **Description:** Cryptographic initialization vector / nonce (96-bit for GCM, 128-bit for CTR) used to encrypt the science data unit.
* **Example:** `NONCE_D = '10dd170716a7da17b53dc50f'`

### `ENCHDR`
* **Data Type:** String (hex-encoded, uses `CONTINUE` convention for long strings)
* **Description:** Ciphertext of the original, unencrypted primary FITS header (including scientific telemetry and observation metadata).
* **Example:** `ENCHDR = '130d1f606c768ff993d3e83ef20dce...'`

### `AUTHTAG_H`
* **Data Type:** String (hex-encoded 128-bit tag, 32 characters)
* **Description:** Galois/Counter Mode (GCM) authentication tag verifying the cryptographic integrity of `ENCHDR`.
* **Example:** `AUTHTAG_H = '53484d504c4420203d20212020202121'`

### `AUTHTAG_D`
* **Data Type:** String (hex-encoded 128-bit tag, 32 characters)
* **Description:** Galois/Counter Mode (GCM) authentication tag verifying the cryptographic integrity of the science data unit in `ENCRYPTED_DATA`.
* **Example:** `AUTHTAG_D = '0e591282eb3ebdfa98e14e6494a95dc0'`

### `ORIG_BPX`
* **Data Type:** Integer
* **Description:** Original `BITPIX` of the unencrypted astronomical image (e.g., 16, 32, -32, -64). Allows the decryption pipeline to reconstruct the correct numeric data type.
* **Example:** `ORIG_BPX = -32`

### `ORIG_NAX`
* **Data Type:** Integer
* **Description:** Original `NAXIS` dimensionality of the unencrypted data array (e.g., 2 for 2D images, 3 for data cubes).
* **Example:** `ORIG_NAX = 2`

### `ORIG_NA1`, `ORIG_NA2`, ... (`ORIG_NAn`)
* **Data Type:** Long Integer
* **Description:** Original dimensions of axis $n$ (`NAXISn`) of the unencrypted data array.
* **Example:** `ORIG_NA1 = 512`, `ORIG_NA2 = 512`

---

## 4. Conformance & Verification

* **Syntactic Conformance**: Verified with `cfitsio`'s `fitsverify` utility (version 4.2+). Conforms to FITS Standard 4.0.
* **Reference Encrypted File**: A sample encrypted file (`scientific_validation/encrypted.fits`, 1.05 MB) is available in the repository.
* **Open Source Reference Implementation**: [https://github.com/slemesp/GpuFitsCrypt](https://github.com/slemesp/GpuFitsCrypt)
