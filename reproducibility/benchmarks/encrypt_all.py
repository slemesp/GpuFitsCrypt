#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import glob
import time

current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)
from utils import get_library, PROJECT_ROOT, setup_logger

logger = setup_logger("EncryptAll")

INPUT_DIR = os.getenv("BENCH_INPUT_FITS_DIR", os.path.join(PROJECT_ROOT, "fits_input_files"))
OUTPUT_DIR = os.getenv("BENCH_ENCRYPTED_DIR", os.path.join(PROJECT_ROOT, "encrypted_files"))
KEY_H_FILE = os.getenv("BENCH_KEY_H_FILE", os.path.join(PROJECT_ROOT, "key_H.txt"))
KEY_D_FILE = os.getenv("BENCH_KEY_D_FILE", os.path.join(PROJECT_ROOT, "key_D.txt"))
BENCH_MODE = os.getenv("BENCH_MODE", "both").lower()

# Filter logic: comma-separated keywords (e.g. "small,medium")
VERIFY_FILES_ENV = os.getenv("BENCH_VERIFY_FILES", "")
VERIFY_KEYWORDS = [f.strip() for f in VERIFY_FILES_ENV.split(",") if f.strip()]

def should_process(filename):
    if not VERIFY_KEYWORDS: return True
    return any(kw in filename for kw in VERIFY_KEYWORDS)

def main():
    logger.info(f"--- Starting Batch Encryption Phase (Mode: {BENCH_MODE}) ---")
    if VERIFY_KEYWORDS:
        logger.info(f"Filter Active: Processing only files matching {VERIFY_KEYWORDS}")

    try:
        with open(KEY_H_FILE, "r") as f: key_h = f.read().strip()
        with open(KEY_D_FILE, "r") as f: key_d = f.read().strip()
    except FileNotFoundError as e:
        logger.error(f"Key file not found: {e}")
        sys.exit(1)

    lib = get_library(64, 4)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    fits_files = sorted(glob.glob(os.path.join(INPUT_DIR, "*.fits")))
    
    modes = []
    if BENCH_MODE in ["gcm", "both"]: modes.append("gcm")
    if BENCH_MODE in ["ctr", "both"]: modes.append("ctr")

    processed_count = 0
    
    for fpath in fits_files:
        filename = os.path.basename(fpath)
        
        if not should_process(filename):
            continue
            
        original_size = os.path.getsize(fpath)
        
        for mode in modes:
            out_path = os.path.join(OUTPUT_DIR, f"enc_{mode}_{filename}")
            logger.info(f"Encrypting ({mode.upper()}): {filename}")
            
            ctx = lib.gfc_encrypt_context_create(int(original_size * 1.2), 512*1024)
            
            if mode == "gcm":
                res = lib.gfc_encrypt_file(ctx, fpath.encode(), out_path.encode(), key_h.encode(), key_d.encode())
            else:
                res = lib.gfc_encrypt_file_ctr(ctx, fpath.encode(), out_path.encode(), key_h.encode(), key_d.encode())
            
            lib.gfc_encrypt_context_destroy(ctx)
            
            if res.error_code != 0:
                logger.error(f"  -> FAILED: {res.error_message.decode()}")
            else:
                processed_count += 1

    if processed_count == 0 and fits_files:
        logger.warning("No files were encrypted. Check your filter settings.")

if __name__ == "__main__":
    main()
