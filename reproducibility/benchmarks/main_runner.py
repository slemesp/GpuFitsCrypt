#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess
import sys
import secrets

# Try to load .env file
try:
    from dotenv import load_dotenv
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(current_dir, '..', '..'))
    docker_env_path = os.path.join(project_root, 'reproducibility', 'docker', '.env')
    
    if os.path.exists(docker_env_path):
        load_dotenv(docker_env_path)
    else:
        load_dotenv()
except ImportError:
    pass

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from utils import PROJECT_ROOT
from fits_utils import generate_fits_batch

def resolve_path(path_str):
    """Resolves paths starting with ./ relative to PROJECT_ROOT"""
    if path_str.startswith("./"):
        return os.path.join(PROJECT_ROOT, path_str[2:])
    return path_str

# Configuration with path resolution
INPUT_FITS_DIR = resolve_path(os.getenv("BENCH_INPUT_FITS_DIR", "./fits_input_files"))
KEY_H_FILE = resolve_path(os.getenv("BENCH_KEY_H_FILE", "./key_H.txt"))
KEY_D_FILE = resolve_path(os.getenv("BENCH_KEY_D_FILE", "./key_D.txt"))
KEY_BAD_FILE = resolve_path(os.getenv("BENCH_KEY_BAD_FILE", "./key_BAD.txt"))
ENCRYPTED_DIR = resolve_path(os.getenv("BENCH_ENCRYPTED_DIR", "./encrypted_files"))
OUTPUT_CSV = resolve_path(os.getenv("BENCH_OUTPUT_CSV", "./benchmark_results.csv"))

def ensure_keys_exist():
    for key_file in [KEY_H_FILE, KEY_D_FILE, KEY_BAD_FILE]:
        if not os.path.exists(key_file):
            print(f"--- Generating missing key file: {os.path.basename(key_file)} ---")
            os.makedirs(os.path.dirname(key_file), exist_ok=True)
            with open(key_file, "w") as f:
                f.write(secrets.token_hex(16))

def clean_and_build_library():
    print(f"--- Building Library (Quiet Mode) ---")
    try:
        subprocess.run(["make", "clean"], cwd=PROJECT_ROOT, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["make"], cwd=PROJECT_ROOT, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"    -> Build Success")
        return True
    except subprocess.CalledProcessError as e:
        print(f"    -> Build Failed: {e}")
        return False

def run_phase(script_name, description):
    print(f"\n{'=' * 20} {description} {'=' * 20}")
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"{script_name}.py")
    try:
        env = os.environ.copy()
        # Pass RESOLVED absolute paths to sub-processes
        env["BENCH_KEY_H_FILE"] = KEY_H_FILE
        env["BENCH_KEY_D_FILE"] = KEY_D_FILE
        env["BENCH_KEY_BAD_FILE"] = KEY_BAD_FILE
        env["BENCH_INPUT_FITS_DIR"] = INPUT_FITS_DIR
        env["BENCH_ENCRYPTED_DIR"] = ENCRYPTED_DIR
        env["BENCH_OUTPUT_CSV"] = OUTPUT_CSV
        env["BENCH_LIB_BASE_PATH"] = PROJECT_ROOT
        
        subprocess.run([sys.executable, script_path], check=True, env=env)
        print(f"\n{'=' * 20} {description} - SUCCESS {'=' * 20}\n")
        return True
    except subprocess.CalledProcessError:
        return False

def main():
    print("--- Initializing Reproducibility Environment ---")
    
    if not clean_and_build_library():
        sys.exit(1)

    ensure_keys_exist()
    generate_fits_batch(num_images=1, output_path=INPUT_FITS_DIR, size_category='mixed')

    if not run_phase("encrypt_all", "PHASE 1: FILE ENCRYPTION"): sys.exit(1)
    if not run_phase("benchmark_suite", "PHASE 2: DECRYPTION BENCHMARK"): sys.exit(1)

if __name__ == "__main__":
    main()
