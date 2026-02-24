# GpuFitsCrypt API Documentation

`GpuFitsCrypt` is a high-performance C++/CUDA library for encrypting and decrypting FITS files using AES-128 in both **GCM** (Galois/Counter) and **CTR** (Counter) modes. It supports granular access control, allowing separate keys for metadata (Header) and pixel data (Data).

---

## 🛡️ Security Recommendation: GCM vs CTR

| Feature | **AES-GCM (Recommended)** | **AES-CTR (Legacy)** |
| :--- | :--- | :--- |
| **Confidentiality** | Yes | Yes |
| **Integrity Check** | **Yes (GHASH)** | **No** |
| **Tamper Detection** | Detects any modification | None (Silent corruption) |
| **Performance** | High (GPU Accelerated) | Ultra-High |
| **Use Case** | Production & Scientific Data | Performance testing only |

---

## Table of Contents

1.  [Compilation & Configuration](#compilation--configuration)
2.  [Data Structures](#data-structures)
3.  [Context Management](#context-management)
4.  [Encryption API](#encryption-api)
5.  [Decryption API](#decryption-api)
6.  [Granular Access & Error Codes](#granular-access--error-codes)
7.  [Utilities](#utilities)
8.  [Python Wrapper](#python-wrapper)

---

## Compilation & Configuration

The library is built using a `Makefile` that supports customization of CUDA kernel parameters for performance tuning on different GPU architectures.

### Basic Compilation
To compile the library with default settings (Thread Block Size = 64, Read Block Size = 4):

```bash
make
```

This produces `libgpufitscrypt.so` (symlink) and `libgpufitscrypt_64_4.so`.

### Custom Tuning (TSBS & RBS)
You can tune the performance by adjusting two key parameters:
*   **TSBS (Thread Block Size)**: Number of threads per CUDA block (e.g., 32, 64, 128, 256).
*   **RBS (Read Block Size)**: Number of 128-bit blocks processed per thread (e.g., 1, 2, 4, 8).

To compile a specific configuration, use the target format `TSBS_RBS`:

```bash
make 128_4    # Compiles for 128 threads, 4 blocks per thread
make 256_2    # Compiles for 256 threads, 2 blocks per thread
```

This will generate specific shared objects like `libgpufitscrypt_128_4.so`.

### Cleaning
To remove all compiled objects and libraries:

```bash
make clean
```

---

## Data Structures

### `FitsOperationResult`
The main structure returned by all cryptographic operations.

```c
typedef struct {
    unsigned char *data_buffer;      // Pointer to decrypted data (or NULL for encryption)
    size_t buffer_size;              // Size of the buffer in bytes
    int error_code;                  // 0 = Success, <0 = Error
    int warning_code;                // 0 = OK, 1 = Header Fallback, 2 = Data Zeroed
    char error_message[256];         // Human-readable status message

    // Performance Metrics (seconds)
    double time_total_c_function_s;
    double time_open_fits_file_s;
    double time_read_primary_hdu_meta_s;
    double time_data_section_read_s;
    double time_data_decryption_gpu_s;
    double time_data_decryption_gpu_kernel_s;
    double time_header_processing_s;
    double time_final_assembly_s;
} FitsOperationResult;
```

### Opaque Contexts
Handles for managing GPU resources (streams, pinned memory) across multiple operations.
*   `EncryptorContext`
*   `DecryptorContext`

---

## Context Management

Using contexts is recommended for high-throughput applications to avoid the overhead of allocating GPU resources for every file.

### Encryption Context

```c
// Create a context for encryption
EncryptorContext *gfc_encrypt_context_create(
    size_t max_input_data_buffer_size, 
    size_t max_header_work_buffer_size
);

// Destroy the context and free resources
void gfc_encrypt_context_destroy(EncryptorContext *ctx);
```

### Decryption Context

```c
// Create a context for decryption
DecryptorContext *gfc_context_create(
    size_t max_output_buffer_size, 
    size_t max_read_buffer_size
);

// Destroy the context
void gfc_context_destroy(DecryptorContext *ctx);

// Enable/Disable precise kernel timing (cudaEvent)
void gfc_context_set_use_kernel_timing(DecryptorContext *ctx, bool enabled);
```

---

## Encryption API

### 1. GCM Mode (Recommended)
AES-128-GCM provides both confidentiality and integrity (AEAD).

#### Context-based Encryption
```c
FitsOperationResult gfc_encrypt_file(
    EncryptorContext *ctx,
    const char *input_fits_path,
    const char *output_encrypted_path,
    const char *key_hex_header,
    const char *key_hex_data
);
```

#### Raw Memory Encryption
Encrypts data directly from memory buffers to a FITS file on disk. Ideal for acquisition pipelines.
```c
FitsOperationResult gfc_encrypt_frame(
    EncryptorContext *ctx,
    const char *output_path,
    const char *header_str, size_t header_len,
    const void *data_ptr, size_t data_len,
    int bitpix, int naxis, const long *naxes,
    const char *key_h, const char *key_d
);
```

#### One-shot Encryption (Without Context)
```c
FitsOperationResult gfc_encrypt_file_without_context(
    const char *input_fits_path,
    const char *output_encrypted_path,
    const char *key_hex_header,
    const char *key_hex_data
);
```

### 2. CTR Mode (Legacy / Not Recommended)
AES-128-CTR provides confidentiality but **no integrity check**.

#### Context-based Encryption (CTR)
```c
FitsOperationResult gfc_encrypt_file_ctr(
    EncryptorContext *ctx,
    const char *input_fits_path,
    const char *output_encrypted_path,
    const char *key_hex_header,
    const char *key_hex_data
);
```

#### One-shot Encryption (CTR)
```c
FitsOperationResult gfc_encrypt_file_ctr_without_context(
    const char *input_fits_path,
    const char *output_encrypted_path,
    const char *key_hex_header,
    const char *key_hex_data
);
```

---

## Decryption API

### 1. GCM Mode (Recommended)
AES-128-GCM verifies integrity tags before returning data.

#### Context-based Decryption
```c
FitsOperationResult gfc_decrypt_frame(
    DecryptorContext *ctx,
    const char *encrypted_fits_path,
    const char *key_hex_header,
    const char *key_hex_data
);
```

### 2. CTR Mode (Legacy / Not Recommended)
*Warning: CTR cannot detect incorrect keys or tampered data.*

#### Context-based Decryption (CTR)
```c
FitsOperationResult gfc_decrypt_frame_ctr(
    DecryptorContext *ctx,
    const char *encrypted_fits_path,
    const char *key_hex_header,
    const char *key_hex_data
);
```

#### One-shot Decryption (CTR)
```c
FitsOperationResult gfc_decrypt_frame_ctr_without_context(
    const char *encrypted_fits_path,
    const char *key_hex_header,
    const char *key_hex_data
);
```

---

## Granular Access & Error Codes

The library implements a **Granular Access** model. This allows partial decryption if only one of the keys is correct.

### Return Codes (`error_code`)

| Code | Meaning | Description |
| :--- | :--- | :--- |
| **0** | **Success** | At least one component (Header or Data) was successfully decrypted. Check `warning_code`. |
| **-998** | **No Action** | **No keys** were provided. Output is the raw encrypted file content. |
| **-999** | **Failure** | **Both** Header and Data decryption failed (or keys missing for both). Output is invalid. |
| **< 0** | **System Error** | Other errors (e.g., -1002: File not found, -302: Context NULL). |

### Warning Codes (`warning_code`)

When `error_code` is 0, `warning_code` indicates the status of the partial decryption:

| Code | Meaning | Scenario | Resulting Output |
| :--- | :--- | :--- | :--- |
| **0** | **Full Success** | Header Key OK + Data Key OK | **Valid Header + Valid Data**. |
| **1** | **Header Fallback** | Header Key Wrong/Missing + Data Key OK | **Fallback Header + Valid Data**. Header contains minimal structural keywords only. |
| **2** | **Data Failed** | Header Key OK + Data Key Wrong/Missing | **Valid Header + Zeroed Data**. Data array is filled with zeros. |
| **3** | **Total Failure** | Header Key Wrong/Missing + Data Key Wrong/Missing | (Usually returns Error -999). |

### Behavior Matrix (GCM Mode)

| Header Key | Data Key | Result Code | Warning Code | Output Content |
| :--- | :--- | :--- | :--- | :--- |
| **Correct** | **Correct** | 0 | 0 | Full Original FITS |
| **Wrong** | **Correct** | 0 | 1 | Fallback Header + Original Data |
| **Missing** | **Correct** | 0 | 1 | Fallback Header + Original Data |
| **Correct** | **Wrong** | 0 | 2 | Original Header + Zeroed Data |
| **Wrong** | **Wrong** | -999 | 3 | (Operation Aborted) |
| **Missing** | **Wrong** | -999 | 3 | (Operation Aborted) |
| **Correct** | **Missing** | 0 | 2 | Original Header + Zeroed Data |
| **Wrong** | **Missing** | -999 | 3 | (Operation Aborted) |
| **Missing** | **Missing** | -998 | 0 | Raw Encrypted File |

### Behavior Matrix (CTR Mode)

*Note: CTR cannot detect "Wrong Key". It decrypts to garbage.*

| Header Key | Data Key | Result Code | Warning Code | Output Content |
| :--- | :--- | :--- | :--- | :--- |
| **Correct** | **Correct** | 0 | 0 | Full Original FITS |
| **Wrong** | **Correct** | 0 | 1 | Fallback Header + Original Data |
| **Missing** | **Correct** | 0 | 1 | Fallback Header + Original Data |
| **Correct** | **Wrong** | 0 | 0 | Original Header + **Garbage Data** (Indistinguishable from valid data by library) |
| **Wrong** | **Wrong** | 0 | 1 | Fallback Header + **Garbage Data** |
| **Missing** | **Wrong** | 0 | 1 | Fallback Header + **Garbage Data** |
| **Correct** | **Missing** | 0 | 2 | Original Header + Zeroed Data |
| **Wrong** | **Missing** | -999 | 3 | (Operation Aborted) |
| **Missing** | **Missing** | -998 | 0 | Raw Encrypted File |

---

## Python Wrapper

A Python wrapper is provided in `python/gpufitscrypt.py` to simplify interaction with the C library.

### Loading the Library

```python
from python.gpufitscrypt import load_library

# Automatically compiles and loads the library
lib = load_library(tsbs=64, rbs=4)
```

### Usage Example

```python
# Create Context
ctx = lib.gfc_context_create(output_size, read_size)

# Decrypt
res = lib.gfc_decrypt_frame(ctx, path, key_h, key_d)

if res.error_code == 0:
    if res.warning_code == 0:
        print("Full Access Granted")
    elif res.warning_code == 1:
        print("Data Access Only (Header Restricted)")
    elif res.warning_code == 2:
        print("Metadata Access Only (Data Restricted)")
elif res.error_code == -998:
    print("No Keys Provided (Raw File)")
else:
    print("Access Denied (Wrong Keys)")
```
