# python/gpufitscrypt.py
import ctypes
import os
import subprocess
import sys

# --- Constants ---
GFC_LOG_LEVEL_NONE = 0
GFC_LOG_LEVEL_ERROR = 1
GFC_LOG_LEVEL_INFO = 2
GFC_LOG_LEVEL_DEBUG = 3

# --- C Structure Definitions ---

class FitsOperationResult(ctypes.Structure):
    """
    Structure returned by cryptographic operations containing the result buffer and status codes.
    """
    _fields_ = [
        ("data_buffer", ctypes.POINTER(ctypes.c_ubyte)),  # Pointer to decrypted data (or NULL)
        ("buffer_size", ctypes.c_size_t),                 # Size of the buffer in bytes
        ("error_code", ctypes.c_int),                     # 0 = Success, <0 = Error
        ("warning_code", ctypes.c_int),                   # 0 = OK, 1 = Header Fallback, 2 = Data Zeroed
        ("error_message", ctypes.c_char * 256),           # Human-readable status message

        # Performance Metrics (seconds)
        ("time_total_c_function_s", ctypes.c_double),
        ("time_open_fits_file_s", ctypes.c_double),
        ("time_read_primary_hdu_meta_s", ctypes.c_double),
        ("time_header_processing_s", ctypes.c_double),
        ("time_data_section_read_s", ctypes.c_double),
        ("time_data_decryption_gpu_s", ctypes.c_double),
        ("time_data_decryption_gpu_kernel_s", ctypes.c_double),
        ("time_final_assembly_s", ctypes.c_double),
    ]

class EncryptorContext(ctypes.Structure):
    """Opaque handle for the encryption context."""
    pass

class DecryptorContext(ctypes.Structure):
    """Opaque handle for the decryption context."""
    pass

# --- Library Loading & Configuration ---

def _configure_lib_functions(lib):
    """Configures ctypes argument and return types for the library functions."""
    
    # Context Management - Encryption
    if hasattr(lib, "gfc_encrypt_context_create"):
        lib.gfc_encrypt_context_create.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
        lib.gfc_encrypt_context_create.restype = ctypes.POINTER(EncryptorContext)

    if hasattr(lib, "gfc_encrypt_context_destroy"):
        lib.gfc_encrypt_context_destroy.argtypes = [ctypes.POINTER(EncryptorContext)]
        lib.gfc_encrypt_context_destroy.restype = None

    # Context Management - Decryption
    if hasattr(lib, "gfc_context_create"):
        lib.gfc_context_create.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
        lib.gfc_context_create.restype = ctypes.POINTER(DecryptorContext)

    if hasattr(lib, "gfc_context_destroy"):
        lib.gfc_context_destroy.argtypes = [ctypes.POINTER(DecryptorContext)]
        lib.gfc_context_destroy.restype = None

    # Encryption API (GCM)
    if hasattr(lib, "gfc_encrypt_file"):
        lib.gfc_encrypt_file.argtypes = [
            ctypes.POINTER(EncryptorContext), ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p
        ]
        lib.gfc_encrypt_file.restype = FitsOperationResult

    # Raw Encryption API (Memory-to-Disk)
    if hasattr(lib, "gfc_encrypt_frame"):
        lib.gfc_encrypt_frame.argtypes = [
            ctypes.POINTER(EncryptorContext), # ctx
            ctypes.c_char_p, # output_path
            ctypes.c_char_p, # header_str
            ctypes.c_size_t, # header_len
            ctypes.c_void_p, # data_ptr
            ctypes.c_size_t, # data_len
            ctypes.c_int,    # bitpix
            ctypes.c_int,    # naxis
            ctypes.POINTER(ctypes.c_long), # naxes
            ctypes.c_char_p, # key_h
            ctypes.c_char_p  # key_d
        ]
        lib.gfc_encrypt_frame.restype = FitsOperationResult

    # Decryption API (GCM)
    if hasattr(lib, "gfc_decrypt_frame"):
        lib.gfc_decrypt_frame.argtypes = [
            ctypes.POINTER(DecryptorContext), ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p
        ]
        lib.gfc_decrypt_frame.restype = FitsOperationResult

    # Utilities
    if hasattr(lib, "free_fits_operation_result"):
        lib.free_fits_operation_result.argtypes = [ctypes.POINTER(FitsOperationResult)]
        lib.free_fits_operation_result.restype = None

    if hasattr(lib, "gfc_set_log_level"):
        lib.gfc_set_log_level.argtypes = [ctypes.c_int]
        lib.gfc_set_log_level.restype = None

    return lib

def load_library(tsbs=64, rbs=4, base_path=None):
    """
    Loads the shared library, compiling it if necessary.
    
    Args:
        tsbs (int): Thread Block Size (default: 64).
        rbs (int): Read Block Size (default: 4).
        base_path (str): Path to the project root containing the Makefile. 
                         If None, attempts to find it relative to this file.
    
    Returns:
        ctypes.CDLL: The loaded and configured library instance.
    """
    if base_path is None:
        # Assume this file is in python/ and Makefile is in root
        base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

    lib_name = f"libgpufitscrypt_{tsbs}_{rbs}.so"
    lib_path = os.path.join(base_path, lib_name)

    if not os.path.exists(lib_path):
        print(f"[INFO] Library {lib_name} not found. Attempting to compile...")
        makefile_path = os.path.join(base_path, "Makefile")
        
        if not os.path.exists(makefile_path):
            raise FileNotFoundError(f"Makefile not found at {makefile_path}")

        try:
            # Clean first to ensure fresh build
            subprocess.run(["make", "clean"], cwd=base_path, check=True, capture_output=True)
            
            # Compile with specified parameters
            cmd = ["make", f"{tsbs}_{rbs}"]
            subprocess.run(cmd, cwd=base_path, check=True, capture_output=True)
            print(f"[INFO] Compilation successful: {lib_name}")
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Compilation failed:\n{e.stderr.decode()}")
            raise RuntimeError("Library compilation failed.")

    try:
        lib = ctypes.CDLL(lib_path)
        return _configure_lib_functions(lib)
    except OSError as e:
        raise RuntimeError(f"Failed to load library {lib_path}: {e}")
