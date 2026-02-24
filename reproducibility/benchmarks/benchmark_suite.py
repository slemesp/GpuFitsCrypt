#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import ctypes
import datetime
import gc
import glob
import os
import platform
import sys
import time
import warnings
import numpy as np
from astropy.io import fits
from astropy.utils.exceptions import AstropyWarning

try:
    import pynvml
    PYNVML_AVAILABLE = True
except ImportError:
    PYNVML_AVAILABLE = False

current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)
from utils import get_library, FitsOperationResult, PROJECT_ROOT, setup_logger
from compile_configs import COMPILE_CONFIGS_FULL, COMPILE_CONFIGS_REDUCED, COMPILE_CONFIGS_TEST

logger = setup_logger("BenchmarkSuite")

# --- Configuration ---
ORIGINAL_FITS_DIR = os.getenv("BENCH_INPUT_FITS_DIR", os.path.join(PROJECT_ROOT, "fits_input_files"))
ENCRYPTED_INPUT_DIR = os.getenv("BENCH_ENCRYPTED_DIR", os.path.join(PROJECT_ROOT, "encrypted_files"))
KEY_H_FILE = os.getenv("BENCH_KEY_H_FILE", os.path.join(PROJECT_ROOT, "key_H.txt"))
KEY_D_FILE = os.getenv("BENCH_KEY_D_FILE", os.path.join(PROJECT_ROOT, "key_D.txt"))
KEY_BAD_FILE = os.getenv("BENCH_KEY_BAD_FILE", os.path.join(PROJECT_ROOT, "key_BAD.txt"))
OUTPUT_CSV_FILE = os.getenv("BENCH_OUTPUT_CSV", os.path.join(PROJECT_ROOT, "benchmark_results.csv"))

NUM_WARMUP_RUNS = int(os.getenv("BENCH_WARMUP_RUNS", "5"))
NUM_TIMED_RUNS = int(os.getenv("BENCH_TIMED_RUNS", "200"))
BENCH_MODE_ENV = os.getenv("BENCH_MODE", "both").lower()
MODES = ["ctr", "gcm"] if BENCH_MODE_ENV == "both" else [BENCH_MODE_ENV]

BENCH_CONFIG_MODE = os.getenv("BENCH_CONFIG_MODE", "full").lower()
if BENCH_CONFIG_MODE == "reduced": COMPILE_CONFIGS = COMPILE_CONFIGS_REDUCED
elif BENCH_CONFIG_MODE == "test": COMPILE_CONFIGS = COMPILE_CONFIGS_TEST
else: COMPILE_CONFIGS = COMPILE_CONFIGS_FULL

BENCH_C_LOG_LEVEL = int(os.getenv("BENCH_C_LOG_LEVEL", "0"))
MAX_CONSECUTIVE_FAILURES = int(os.getenv("BENCH_MAX_FAILURES", str(max(1, int(NUM_TIMED_RUNS * 0.2)))))

# Filter logic
VERIFY_FILES_ENV = os.getenv("BENCH_VERIFY_FILES", "")
VERIFY_KEYWORDS = [f.strip() for f in VERIFY_FILES_ENV.split(",") if f.strip()]

LIB_ERR_OK = 0
LIB_WARN_NONE = 0
NO_KEY_STR = "NO_KEY"

def should_process(filename):
    if not VERIFY_KEYWORDS: return True
    return any(kw in filename for kw in VERIFY_KEYWORDS)

def get_system_info():
    info = {"timestamp": datetime.datetime.now().isoformat(), "hostname": platform.node(), "platform": platform.platform(), "python_version": platform.python_version()}
    if PYNVML_AVAILABLE:
        try:
            pynvml.nvmlInit()
            handle = pynvml.nvmlDeviceGetHandleByIndex(0)
            info["gpu_name"] = pynvml.nvmlDeviceGetName(handle).decode() if isinstance(pynvml.nvmlDeviceGetName(handle), bytes) else pynvml.nvmlDeviceGetName(handle)
            info["gpu_driver"] = pynvml.nvmlSystemGetDriverVersion()
            pynvml.nvmlShutdown()
        except Exception: info["gpu_name"], info["gpu_driver"] = "N/A", "N/A"
    else: info["gpu_name"], info["gpu_driver"] = "pynvml not available", "N/A"
    return info

SYSTEM_INFO_STATIC = get_system_info()

def _open_fits_file(fits_file_obj, memmap=None):
    hdul = None
    try:
        hdul = fits.open(fits_file_obj, mode='readonly', memmap=memmap)
        if len(hdul) > 0 and hasattr(hdul[0], 'data') and hdul[0].data is not None:
            _ = hdul[0].data.shape
    except Exception: pass
    finally:
        if hdul: hdul.close()

def _open_decryption_result(result_struct):
    err_c = result_struct.error_code
    out_buf_size = int(result_struct.buffer_size)
    if err_c == LIB_ERR_OK and result_struct.data_buffer and out_buf_size > 0:
        hdul = None
        try:
            numpy_array = np.ctypeslib.as_array(result_struct.data_buffer, shape=(out_buf_size,))
            fits_bytes = numpy_array.tobytes()
            hdul = fits.HDUList.fromstring(fits_bytes)
            if len(hdul) > 0 and hasattr(hdul[0], 'data') and hdul[0].data is not None:
                _ = hdul[0].data.shape
            else: err_c = -997
        except Exception: err_c = -998
        finally:
            if hdul: hdul.close()
    return err_c

def time_astropy_normal_open(fits_filepath, num_runs):
    if not os.path.exists(fits_filepath): return None
    times_taken = []
    for _ in range(num_runs):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', AstropyWarning)
                start_time = time.monotonic()
                _open_fits_file(fits_filepath, memmap=False)
                end_time = time.monotonic()
                times_taken.append(end_time - start_time)
        except Exception: return None
    return float(np.median(times_taken)) if times_taken else None

def main():
    logger.info(f"--- GpuFitsCrypt Benchmark (Mode: {BENCH_MODE_ENV}, Config: {BENCH_CONFIG_MODE}) ---")
    if VERIFY_KEYWORDS:
        logger.info(f"Filter Active: Processing only files matching {VERIFY_KEYWORDS}")
    
    try:
        with open(KEY_H_FILE, "r") as f: key_h_correct = f.read().strip()
        with open(KEY_D_FILE, "r") as f: key_d_correct = f.read().strip()
    except FileNotFoundError: logger.error("Key files not found."); sys.exit(1)

    if not os.path.isdir(ENCRYPTED_INPUT_DIR):
        logger.error(f"Directory {ENCRYPTED_INPUT_DIR} not found."); sys.exit(1)

    encrypted_files_to_test = []
    for mode in MODES:
        pattern = os.path.join(ENCRYPTED_INPUT_DIR, f"enc_{mode}_*.fits")
        files = sorted(glob.glob(pattern))
        for fpath in files:
            base_name = os.path.basename(fpath).replace("enc_", "").replace(f"{mode}_", "")
            if should_process(base_name):
                encrypted_files_to_test.append((mode, fpath))

    if not encrypted_files_to_test:
        logger.warning(f"No encrypted files found matching filter in {ENCRYPTED_INPUT_DIR}")
        sys.exit(1)

    logger.info(f"Testing {len(encrypted_files_to_test)} files across modes {MODES}.")

    benchmark_test_cases_defs = [
        ("CASE1", "Both Keys Correct", key_h_correct, key_d_correct, LIB_ERR_OK, LIB_WARN_NONE),
    ]

    lib_base_path = os.getenv("BENCH_LIB_BASE_PATH", PROJECT_ROOT)
    os.makedirs(os.path.dirname(OUTPUT_CSV_FILE), exist_ok=True)

    with open(OUTPUT_CSV_FILE, 'a', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        if os.path.getsize(OUTPUT_CSV_FILE) == 0:
            header = ["Timestamp", "Hostname", "Platform", "PythonVersion", "GPU_Name", "GPU_Driver",
                      "OriginalFile", "OriginalFileSize_bytes", "TimeAstropyNormalOpen_s",
                      "EncryptedFileSize_bytes", "TestCaseID_Config", "TestCaseDesc",
                      "KeyH_Used", "KeyD_Used", "ThreadSizeBS", "RepeatBS", "RunNum",
                      "TotalOpenTime_s", "LibErrorCode", "LibWarningCode", "OutputBufferSize_bytes",
                      "CTime_Total_s", "CTime_OpenFITS_s", "CTime_ReadMeta_s", "CTime_HeaderProc_s",
                      "CTime_DataRead_s", "CTime_DataDecryptGPU_s", "CTime_DataDecryptGPU_KernelOnly_s", "CTime_Assembly_s"]
            csv_writer.writerow(header)

        for config in COMPILE_CONFIGS:
            tsbs, rbs, config_desc = config["TSBS"], config["RBS"], config["DESC"]
            logger.info(f"Testing Config: {config_desc}")
            try: lib = get_library(tsbs=tsbs, rbs=rbs, base_path=lib_base_path)
            except Exception as e: logger.error(f"Failed to load library: {e}"); continue
            
            lib.gfc_set_log_level(BENCH_C_LOG_LEVEL)

            for mode, enc_path in encrypted_files_to_test:
                base_name = os.path.basename(enc_path).replace("enc_", "").replace(f"{mode}_", "")
                orig_path = os.path.join(ORIGINAL_FITS_DIR, base_name)
                if not os.path.exists(orig_path): continue

                orig_size, enc_size = os.path.getsize(orig_path), os.path.getsize(enc_path)
                logger.info(f"Processing: {base_name} (mode={mode})")
                
                astropy_s = time_astropy_normal_open(orig_path, 5)
                astropy_str = f"{astropy_s:.6f}" if astropy_s else "N/A"

                ctx = lib.gfc_context_create(int(orig_size * 1.2), enc_size)
                lib.gfc_context_set_use_kernel_timing(ctx, True)

                for case_id, desc, kh, kd, expected_err, expected_warn in benchmark_test_cases_defs:
                    all_times = {"total_py": [], "c_total": [], "c_datadec": [], "c_datadec_kernel": []}

                    warmup_ok = True
                    for run_num in range(1, NUM_WARMUP_RUNS + 1):
                        if mode == "gcm": res = lib.gfc_decrypt_frame(ctx, enc_path.encode(), kh.encode(), kd.encode())
                        else: res = lib.gfc_decrypt_frame_ctr(ctx, enc_path.encode(), kh.encode(), kd.encode())
                        if _open_decryption_result(res) != expected_err:
                            logger.warning(f"Warmup {run_num} FAILED. Skipping case."); warmup_ok = False; break

                    if not warmup_ok: continue

                    consecutive_failures = 0
                    for run_num in range(1, NUM_TIMED_RUNS + 1):
                        t_start = time.monotonic()
                        if mode == "gcm": res = lib.gfc_decrypt_frame(ctx, enc_path.encode(), kh.encode(), kd.encode())
                        else: res = lib.gfc_decrypt_frame_ctr(ctx, enc_path.encode(), kh.encode(), kd.encode())
                        err_c = _open_decryption_result(res)
                        t_end = time.monotonic()
                        
                        total_py_s = t_end - t_start
                        
                        key_h_status = "ActualKey" if kh == key_h_correct else ("NO_KEY" if kh == NO_KEY_STR else "WrongKey")
                        key_d_status = "ActualKey" if kd == key_d_correct else ("NO_KEY" if kd == NO_KEY_STR else "WrongKey")

                        csv_row = [
                            SYSTEM_INFO_STATIC["timestamp"], SYSTEM_INFO_STATIC["hostname"],
                            SYSTEM_INFO_STATIC["platform"], SYSTEM_INFO_STATIC["python_version"],
                            SYSTEM_INFO_STATIC["gpu_name"], SYSTEM_INFO_STATIC["gpu_driver"],
                            base_name, orig_size, astropy_str, enc_size,
                            f"{case_id}_{mode}_{config_desc}", desc, 
                            key_h_status, key_d_status,
                            tsbs, rbs, run_num,
                            f"{total_py_s:.6f}", err_c, res.warning_code, res.buffer_size,
                            f"{res.time_total_c_function_s:.6f}",
                            f"{res.time_open_fits_file_s:.6f}",
                            f"{res.time_read_primary_hdu_meta_s:.6f}",
                            f"{res.time_header_processing_s:.6f}",
                            f"{res.time_data_section_read_s:.6f}",
                            f"{res.time_data_decryption_gpu_s:.6f}",
                            f"{res.time_data_decryption_gpu_kernel_s:.6f}",
                            f"{res.time_final_assembly_s:.6f}"
                        ]
                        csv_writer.writerow(csv_row)
                        
                        if err_c == expected_err:
                            consecutive_failures = 0
                            all_times["total_py"].append(total_py_s)
                            all_times["c_total"].append(res.time_total_c_function_s)
                            all_times["c_datadec"].append(res.time_data_decryption_gpu_s)
                            all_times["c_datadec_kernel"].append(res.time_data_decryption_gpu_kernel_s)
                        else:
                            consecutive_failures += 1
                            if consecutive_failures >= MAX_CONSECUTIVE_FAILURES: break

                    if all_times["total_py"]:
                        def get_med(l): return f"{float(np.median(l)):.6f}"
                        logger.info(f"Summary (Medians): TotalPy={get_med(all_times['total_py'])}s, CLib={get_med(all_times['c_total'])}s, GPU={get_med(all_times['c_datadec'])}s, Kernel={get_med(all_times['c_datadec_kernel'])}s")

                lib.gfc_context_destroy(ctx)
                gc.collect()
                csvfile.flush()

    logger.info(f"Benchmark completed. Results in {OUTPUT_CSV_FILE}")

if __name__ == "__main__": main()
