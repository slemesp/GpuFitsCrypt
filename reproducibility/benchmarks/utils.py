#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ctypes
import os
import platform
import subprocess
import time
import logging
import sys
import numpy as np

# --- Paths ---
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))

# --- Logging Setup ---
def setup_logger(name="GpuFitsCrypt"):
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger

# --- C Types ---
class FitsOperationResult(ctypes.Structure):
    _fields_ = [
        ("data_buffer", ctypes.POINTER(ctypes.c_ubyte)),
        ("buffer_size", ctypes.c_size_t),
        ("error_code", ctypes.c_int),
        ("warning_code", ctypes.c_int),
        ("error_message", ctypes.c_char * 256),
        ("time_total_c_function_s", ctypes.c_double),
        ("time_open_fits_file_s", ctypes.c_double),
        ("time_read_primary_hdu_meta_s", ctypes.c_double),
        ("time_data_section_read_s", ctypes.c_double),
        ("time_data_decryption_gpu_s", ctypes.c_double),
        ("time_data_decryption_gpu_kernel_s", ctypes.c_double),
        ("time_header_processing_s", ctypes.c_double),
        ("time_final_assembly_s", ctypes.c_double),
    ]

class EncryptorContext(ctypes.Structure): pass
class DecryptorContext(ctypes.Structure): pass

def configure_lib(lib):
    lib.gfc_context_create.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
    lib.gfc_context_create.restype = ctypes.POINTER(DecryptorContext)
    lib.gfc_context_destroy.argtypes = [ctypes.POINTER(DecryptorContext)]
    lib.gfc_context_destroy.restype = None
    lib.gfc_encrypt_context_create.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
    lib.gfc_encrypt_context_create.restype = ctypes.POINTER(EncryptorContext)
    lib.gfc_encrypt_context_destroy.argtypes = [ctypes.POINTER(EncryptorContext)]
    lib.gfc_encrypt_context_destroy.restype = None
    lib.gfc_decrypt_frame.argtypes = [ctypes.POINTER(DecryptorContext), ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.gfc_decrypt_frame.restype = FitsOperationResult
    lib.gfc_decrypt_frame_ctr.argtypes = [ctypes.POINTER(DecryptorContext), ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.gfc_decrypt_frame_ctr.restype = FitsOperationResult
    lib.gfc_encrypt_file.argtypes = [ctypes.POINTER(EncryptorContext), ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.gfc_encrypt_file.restype = FitsOperationResult
    lib.gfc_encrypt_file_ctr.argtypes = [ctypes.POINTER(EncryptorContext), ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.gfc_encrypt_file_ctr.restype = FitsOperationResult
    lib.gfc_encrypt_frame.argtypes = [ctypes.POINTER(EncryptorContext), ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_long), ctypes.c_char_p, ctypes.c_char_p]
    lib.gfc_encrypt_frame.restype = FitsOperationResult
    lib.gfc_set_log_level.argtypes = [ctypes.c_int]
    lib.gfc_get_log_level.restype = ctypes.c_int
    lib.gfc_context_set_use_kernel_timing.argtypes = [ctypes.POINTER(DecryptorContext), ctypes.c_bool]
    lib.gfc_context_set_use_kernel_timing.restype = None
    return lib

def get_library(tsbs=64, rbs=4, base_path=None):
    logger = logging.getLogger("GpuFitsCrypt")
    if base_path is None: base_path = PROJECT_ROOT
    
    if tsbs is not None and rbs is not None:
        lib_filename = f"libgpufitscrypt_{tsbs}_{rbs}.so"
        make_target = f"{tsbs}_{rbs}"
    else:
        lib_filename = "libgpufitscrypt.so"
        make_target = None

    lib_full_path = os.path.join(base_path, lib_filename)
    
    if not os.path.exists(lib_full_path) and make_target:
        logger.info(f"Library {lib_filename} not found. Compiling...")
        try:
            subprocess.run(["make", "clean"], cwd=base_path, check=True, capture_output=True)
            subprocess.run(["make", make_target], cwd=base_path, check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"Compilation failed: {e.stderr.decode()}")
            raise
            
    if not os.path.exists(lib_full_path):
        raise OSError(f"Library {lib_filename} not found in {base_path}")
        
    return configure_lib(ctypes.CDLL(lib_full_path))
