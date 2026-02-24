#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GpuFitsCrypt: Comprehensive Usage Example
-----------------------------------------
This script demonstrates the core capabilities of the GpuFitsCrypt library:
1. Context Management: Efficient resource allocation for batch processing.
2. File Encryption: Standard disk-to-disk encryption.
3. Raw Encryption: High-performance memory-to-disk encryption (e.g., for camera pipelines).
4. Granular Decryption: Handling partial access scenarios (Header-only, Data-only).

Usage:
    python3 examples/basic_usage.py
"""

import os
import sys
import ctypes
import numpy as np
from astropy.io import fits

# --- Setup Import Path ---
# Add the project root to sys.path to import the python wrapper
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(project_root)

try:
    from python.gpufitscrypt import load_library, FitsOperationResult
except ImportError:
    print("Error: Could not import 'python.gpufitscrypt'. Ensure you are running this script from the 'examples' directory or project root.")
    sys.exit(1)

# --- Constants ---
OUTPUT_DIR = "example_output"
FILE_FROM_DISK = os.path.join(OUTPUT_DIR, "encrypted_from_disk.fits")
FILE_FROM_RAW = os.path.join(OUTPUT_DIR, "encrypted_from_raw.fits")
DECRYPTED_FILE = os.path.join(OUTPUT_DIR, "decrypted_output.fits")

# --- Helpers ---
def generate_hex_key():
    return os.urandom(16).hex()

def create_synthetic_fits(filename, width=2048, height=2048):
    """Creates a dummy FITS file on disk for testing."""
    print(f"  -> Generating synthetic FITS: {filename} ({width}x{height})")
    data = np.random.normal(1000, 50, (height, width)).astype(np.float32)
    hdu = fits.PrimaryHDU(data)
    hdu.header['TELESCOP'] = 'GpuFitsCrypt Simulator'
    hdu.writeto(filename, overwrite=True)
    return data

def handle_decryption_result(res: FitsOperationResult, label: str):
    """
     robustly handles the decryption result, interpreting error and warning codes
    according to the Granular Access model.
    """
    print(f"\n  [{label}] Result Analysis:")
    
    if res.error_code == 0:
        # Success (Full or Partial)
        if res.warning_code == 0:
            print("    ✅ SUCCESS: Full Access Granted (Header + Data).")
            print(f"       Buffer Size: {res.buffer_size} bytes")
        elif res.warning_code == 1:
            print("    ⚠️ PARTIAL SUCCESS: Data Access Only.")
            print("       (Header Key was wrong/missing. Using Fallback Header).")
        elif res.warning_code == 2:
            print("    ⚠️ PARTIAL SUCCESS: Metadata Access Only.")
            print("       (Data Key was wrong/missing. Data is zeroed out).")
        else:
            print(f"    ❓ Unknown Warning Code: {res.warning_code}")
            
    elif res.error_code == -998:
        print("    ℹ️ NO ACTION: No keys provided.")
        print("       (Returning raw encrypted file content).")
        
    elif res.error_code == -999:
        print("    ⛔ FAILURE: Access Denied.")
        print("       (Both Header and Data keys are incorrect or missing).")
        
    else:
        print(f"    ❌ SYSTEM ERROR: Code {res.error_code}")
        print(f"       Message: {res.error_message.decode()}")

# --- Main Workflow ---
def main():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    # 1. Load Library
    print("--- [1] Loading Library ---")
    # Automatically compiles if .so is missing
    lib = load_library(tsbs=64, rbs=4, base_path=project_root)
    print("    Library loaded successfully.")

    # 2. Generate Keys
    key_h = generate_hex_key()
    key_d = generate_hex_key()
    key_wrong = generate_hex_key()
    print(f"    Key Header (Correct): {key_h}")
    print(f"    Key Data   (Correct): {key_d}")

    # 3. Context Management
    print("\n--- [2] Context Management ---")
    # Define max expected size (e.g., 4K x 4K float32 image + header)
    # 4096 * 4096 * 4 bytes = 64 MB. Let's allocate 70 MB to be safe.
    max_data_size = 70 * 1024 * 1024 
    max_header_size = 2880 * 10 # 10 blocks for header
    
    print(f"    Creating reusable encryption context (Max Data: {max_data_size/1024/1024:.1f} MB)...")
    ctx_enc = lib.gfc_encrypt_context_create(max_data_size, max_header_size)
    
    print(f"    Creating reusable decryption context...")
    # Output size is roughly input size. Read size is input file size.
    ctx_dec = lib.gfc_context_create(max_data_size, max_data_size)

    if not ctx_enc or not ctx_dec:
        print("    ❌ Failed to create contexts.")
        return

    try:
        # 4. Scenario A: Standard File-to-File Encryption
        print("\n--- [3] Scenario A: Standard File Encryption ---")
        input_fits = os.path.join(OUTPUT_DIR, "input_original.fits")
        create_synthetic_fits(input_fits)
        
        print(f"    Encrypting '{input_fits}' -> '{FILE_FROM_DISK}'...")
        res = lib.gfc_encrypt_file(
            ctx_enc,
            input_fits.encode('utf-8'),
            FILE_FROM_DISK.encode('utf-8'),
            key_h.encode('utf-8'),
            key_d.encode('utf-8')
        )
        if res.error_code != 0:
            print(f"    ❌ Encryption Failed: {res.error_message.decode()}")
            return
        print("    ✅ Encryption Complete.")

        # 5. Scenario B: Raw Memory-to-Disk Encryption (Acquisition Pipeline)
        print("\n--- [4] Scenario B: Raw Memory Encryption ---")
        # Simulate data in memory (e.g., from a camera driver)
        width, height = 1024, 1024
        raw_data = np.random.normal(500, 10, (height, width)).astype(np.float32)
        
        # Create header string manually
        header_str = (
            f"{'SIMPLE':<8}= {'T':>20} / conforms to FITS standard".ljust(80) +
            f"{'BITPIX':<8}= {-32:>20} / array data type".ljust(80) +
            f"{'NAXIS':<8}= {2:>20} / number of array dimensions".ljust(80) +
            f"{'NAXIS1':<8}= {width:>20}".ljust(80) +
            f"{'NAXIS2':<8}= {height:>20}".ljust(80) +
            "END".ljust(80)
        )
        header_bytes = header_str.encode('ascii')
        
        # Prepare pointers
        data_ptr = raw_data.ctypes.data_as(ctypes.c_void_p)
        data_len = raw_data.nbytes
        naxes_array = (ctypes.c_long * 2)(width, height)
        
        print(f"    Encrypting Raw Buffer ({width}x{height}) -> '{FILE_FROM_RAW}'...")
        res = lib.gfc_encrypt_frame(
            ctx_enc,
            FILE_FROM_RAW.encode('utf-8'),
            header_bytes, len(header_bytes),
            data_ptr, data_len,
            -32, 2, naxes_array,
            key_h.encode('utf-8'),
            key_d.encode('utf-8')
        )
        if res.error_code != 0:
            print(f"    ❌ Raw Encryption Failed: {res.error_message.decode()}")
            return
        print("    ✅ Raw Encryption Complete.")

        # 6. Decryption & Granular Access Tests
        print("\n--- [5] Decryption & Granular Access Tests ---")
        target_file = FILE_FROM_DISK # Use the standard file for testing
        
        # Case 1: Full Access
        res = lib.gfc_decrypt_frame(
            ctx_dec, target_file.encode('utf-8'), key_h.encode('utf-8'), key_d.encode('utf-8')
        )
        handle_decryption_result(res, "Correct Keys")
        
        # Case 2: Data Only (Wrong Header Key)
        res = lib.gfc_decrypt_frame(
            ctx_dec, target_file.encode('utf-8'), key_wrong.encode('utf-8'), key_d.encode('utf-8')
        )
        handle_decryption_result(res, "Wrong Header Key")

        # Case 3: Metadata Only (Wrong Data Key)
        res = lib.gfc_decrypt_frame(
            ctx_dec, target_file.encode('utf-8'), key_h.encode('utf-8'), key_wrong.encode('utf-8')
        )
        handle_decryption_result(res, "Wrong Data Key")

        # Case 4: Access Denied (Both Wrong)
        res = lib.gfc_decrypt_frame(
            ctx_dec, target_file.encode('utf-8'), key_wrong.encode('utf-8'), key_wrong.encode('utf-8')
        )
        handle_decryption_result(res, "Both Wrong Keys")

    finally:
        # 7. Cleanup
        print("\n--- [6] Cleanup ---")
        if ctx_enc: lib.gfc_encrypt_context_destroy(ctx_enc)
        if ctx_dec: lib.gfc_context_destroy(ctx_dec)
        print("    Contexts destroyed.")

if __name__ == "__main__":
    main()
