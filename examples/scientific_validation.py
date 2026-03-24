#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GpuFitsCrypt: Scientific Validation Example
--------------------------------------------
Generates a triptych figure demonstrating three properties of AES-GCM encryption:

1. Semantic Confidentiality — Encrypted data is indistinguishable from noise
   (source extraction finds zero objects).
2. Bit-Exact Integrity — Decrypted data matches the original with zero residuals.
3. Science Readiness — Photometric parameters (FWHM, flux, centroids) extracted
   from the decrypted image are identical to those from the original.

Source detection uses GPUPhot when available (https://github.com/Light-Bridges/GPUPhot),
falling back to SEP (pip install sep) or scipy for basic peak detection.

Usage:
    python3 examples/scientific_validation.py
    python3 examples/scientific_validation.py --input_fits /path/to/real_image.fits

Output:
    scientific_validation/scientific_validation_triptych.png
    scientific_validation/scientific_validation_triptych.pdf
"""

import argparse
import ctypes
import os
import sys
import numpy as np
import matplotlib.pyplot as plt
from astropy.io import fits
from astropy.visualization import ZScaleInterval, ImageNormalize, LinearStretch
from matplotlib.patches import Circle

# --- Setup Import Path ---
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(project_root)

try:
    from python.gpufitscrypt import load_library, FitsOperationResult
except ImportError:
    print("Error: Could not import 'python.gpufitscrypt'.")
    print("Ensure you are running from the project root: python3 examples/scientific_validation.py")
    sys.exit(1)

# --- Optional: GPUPhot for full photometric validation ---
# GPUPhot is a high-performance photometry package. When available, it provides
# full PSF-fitting photometry (FWHM, flux, centroids). Install from:
#   https://github.com/Light-Bridges/GPUPhot
HAS_GPUPHOT = False
try:
    from gpuphot.image_processor import create_processor
    from gpuphot_worker.header_descriptions import HEADER_DESCRIPTIONS
    HAS_GPUPHOT = True
except ImportError:
    pass

# --- Optional: SEP for intermediate source extraction ---
HAS_SEP = False
try:
    import sep
    HAS_SEP = True
except ImportError:
    from scipy.ndimage import maximum_filter

# --- Constants ---
OUTPUT_DIR = "scientific_validation"


# ========================================================================
# Source Detection (three tiers: GPUPhot > SEP > scipy)
# ========================================================================

def detect_sources_gpuphot(data, header):
    """Full photometric extraction with GPUPhot. Returns (coords, fwhm, flux)."""
    if not HAS_GPUPHOT:
        return detect_sources_fallback(data)

    try:
        camera_name = header.get('CAMERA', header.get('INSTRUME', 'Unknown'))
        image_processor = create_processor(camera_name)

        if data.dtype != np.float32:
            data = data.astype(np.float32)

        phot_df, hwcs = image_processor.process_image(
            data, header, header_descriptions=HEADER_DESCRIPTIONS, do_pad=True
        )

        fwhm = float(hwcs.get('FWHM', 0.0)) if hwcs else 0.0
        flux_mean = 0.0
        coords = []

        if phot_df is not None and not phot_df.empty:
            coords = list(zip(phot_df['xcentroid'], phot_df['ycentroid']))
            if 'flux' in phot_df.columns:
                flux_mean = phot_df['flux'].mean()

        return coords, fwhm, flux_mean

    except Exception as e:
        if "Insufficient" in str(e) or "no sources" in str(e).lower():
            # Expected failure on encrypted noise
            return [], 0.0, 0.0
        print(f"[WARNING] GPUPhot failed ({e}), falling back to simple detection.")
        return detect_sources_fallback(data)


def detect_sources_fallback(data):
    """Source detection without GPUPhot. Uses SEP if available, else scipy."""
    data = np.nan_to_num(data).astype(np.float32)
    data = np.ascontiguousarray(data)

    if HAS_SEP:
        try:
            bkg = sep.Background(data)
            data_sub = data - bkg
            objects = sep.extract(data_sub, 3.0, err=bkg.globalrms)
            fwhm = 0.0
            if len(objects) > 0:
                fwhm = np.mean(np.sqrt(objects['a']**2 + objects['b']**2)) * 2.355
            coords = [(obj['x'], obj['y']) for obj in objects]
            flux_mean = float(np.mean(objects['flux'])) if len(objects) > 0 else 0.0
            return coords, fwhm, flux_mean
        except Exception as e:
            print(f"[WARNING] SEP failed ({e}), falling back to scipy.")

    # Last resort: scipy peak detection
    mean, std = np.mean(data), np.std(data)
    thresh = mean + 3.0 * std
    data_max = maximum_filter(data, size=10)
    maxima = (data == data_max) & (data > thresh)
    y, x = np.where(maxima)
    return list(zip(x, y)), 0.0, 0.0


# ========================================================================
# FITS Helpers
# ========================================================================

def generate_hex_key():
    return os.urandom(16).hex()


def create_synthetic_fits(filename, size=512, n_stars=50):
    """Creates a synthetic FITS file with Gaussian point sources."""
    print(f"  Generating synthetic FITS: {filename} ({size}x{size}, {n_stars} stars)")
    data = np.random.normal(100, 5, (size, size)).astype(np.float32)

    rng = np.random.default_rng(42)
    yy, xx = np.mgrid[:size, :size]
    for _ in range(n_stars):
        cy, cx = rng.integers(20, size - 20, 2)
        flux = rng.uniform(200, 2000)
        sigma = rng.uniform(1.5, 3.0)
        data += flux * np.exp(-((xx - cx)**2 + (yy - cy)**2) / (2 * sigma**2))

    hdu = fits.PrimaryHDU(data)
    hdu.header['INSTRUME'] = 'Simulated'
    hdu.header['CAMERA'] = 'Simulated'
    hdu.writeto(filename, overwrite=True)
    return filename


# ========================================================================
# Main Workflow
# ========================================================================

def main():
    parser = argparse.ArgumentParser(description="Scientific Validation of GpuFitsCrypt AES-GCM Encryption")
    parser.add_argument("--input_fits", type=str, default=None,
                        help="Path to a real FITS file. If omitted, a synthetic image is generated.")
    args = parser.parse_args()

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # --- Detection backend ---
    if HAS_GPUPHOT:
        print("[INFO] Using GPUPhot for source detection.")
    elif HAS_SEP:
        print("[INFO] GPUPhot not available. Using SEP for source detection.")
    else:
        print("[INFO] GPUPhot and SEP not available. Using scipy peak detection (limited).")

    # --- Prepare Input ---
    if args.input_fits and os.path.exists(args.input_fits):
        input_path = args.input_fits
        print(f"[1/5] Using input FITS: {input_path}")
    else:
        if args.input_fits:
            print(f"[WARNING] File not found: {args.input_fits}. Generating synthetic data.")
        input_path = os.path.join(OUTPUT_DIR, "synthetic_input.fits")
        create_synthetic_fits(input_path)
        print(f"[1/5] Synthetic FITS created: {input_path}")

    encrypted_path = os.path.join(OUTPUT_DIR, "encrypted.fits")
    decrypted_path = os.path.join(OUTPUT_DIR, "decrypted.fits")

    # --- Load Library ---
    print("[2/5] Loading GpuFitsCrypt library...")
    lib = load_library(tsbs=64, rbs=4, base_path=project_root)

    key_h = generate_hex_key()
    key_d = generate_hex_key()

    # --- Encrypt ---
    print("[3/5] Encrypting...")
    file_size = os.path.getsize(input_path)
    max_header_size = 2880 * 10
    ctx_enc = lib.gfc_encrypt_context_create(file_size, max_header_size)
    if not ctx_enc:
        print("ERROR: Failed to create encryption context.")
        return

    try:
        res = lib.gfc_encrypt_file(
            ctx_enc,
            input_path.encode('utf-8'),
            encrypted_path.encode('utf-8'),
            key_h.encode('utf-8'),
            key_d.encode('utf-8')
        )
        if res.error_code != 0:
            print(f"ERROR: Encryption failed (code {res.error_code}): {res.error_message.decode()}")
            return
        print(f"  Encrypted: {encrypted_path}")
    finally:
        lib.gfc_encrypt_context_destroy(ctx_enc)

    # --- Decrypt ---
    print("[4/5] Decrypting...")
    enc_size = os.path.getsize(encrypted_path)
    ctx_dec = lib.gfc_context_create(enc_size, enc_size)
    if not ctx_dec:
        print("ERROR: Failed to create decryption context.")
        return

    try:
        res = lib.gfc_decrypt_frame(
            ctx_dec,
            encrypted_path.encode('utf-8'),
            key_h.encode('utf-8'),
            key_d.encode('utf-8')
        )
        if res.error_code != 0:
            print(f"ERROR: Decryption failed (code {res.error_code}): {res.error_message.decode()}")
            return

        # Write decrypted buffer to FITS
        buf = ctypes.string_at(res.data_buffer, res.buffer_size)
        with open(decrypted_path, 'wb') as f:
            f.write(buf)
        print(f"  Decrypted: {decrypted_path}")
    finally:
        lib.gfc_context_destroy(ctx_dec)

    # --- Scientific Validation ---
    print("[5/5] Running scientific validation...")

    # Load original
    with fits.open(input_path) as hdul:
        idx = 0 if hdul[0].data is not None else 1
        original_data = hdul[idx].data
        original_header = hdul[idx].header

    # Load encrypted as raw bytes for display
    with open(encrypted_path, 'rb') as f:
        enc_bytes = f.read()
    total_pixels = original_data.shape[0] * original_data.shape[1]
    enc_array = np.frombuffer(enc_bytes[:min(len(enc_bytes), total_pixels)], dtype=np.uint8)
    if enc_array.size < total_pixels:
        enc_array = np.pad(enc_array, (0, total_pixels - enc_array.size), 'constant')
    enc_display = enc_array.reshape(original_data.shape)

    # Load decrypted
    with fits.open(decrypted_path) as hdul:
        idx = 0 if hdul[0].data is not None else 1
        decrypted_data = hdul[idx].data
        decrypted_header = hdul[idx].header

    # Detect sources
    print("  Detecting sources on original...")
    src_orig, fwhm_orig, flux_orig = detect_sources_gpuphot(original_data, original_header)
    print(f"    Original:  {len(src_orig)} sources | FWHM={fwhm_orig:.2f} px")

    print("  Detecting sources on encrypted noise...")
    src_enc, fwhm_enc, _ = detect_sources_gpuphot(enc_display, original_header)
    print(f"    Encrypted: {len(src_enc)} sources (expected: 0)")

    print("  Detecting sources on decrypted...")
    src_dec, fwhm_dec, flux_dec = detect_sources_gpuphot(decrypted_data, decrypted_header)
    print(f"    Decrypted: {len(src_dec)} sources | FWHM={fwhm_dec:.2f} px")

    # Integrity check
    residual = np.sum(np.abs(original_data - decrypted_data))
    if residual == 0:
        integrity_msg = "Bit-exact restoration"
        print(f"  INTEGRITY CHECK: PASSED (zero residuals)")
    else:
        integrity_msg = f"Residual sum = {residual}"
        print(f"  INTEGRITY CHECK: FAILED ({integrity_msg})")

    # --- Generate Triptych Figure ---
    print("  Generating triptych figure...")
    fig, axes = plt.subplots(1, 3, figsize=(18, 6))

    norm = ImageNormalize(original_data, interval=ZScaleInterval(), stretch=LinearStretch())
    norm_dec = ImageNormalize(decrypted_data, interval=ZScaleInterval(), stretch=LinearStretch())

    # Panel (a): Original
    axes[0].imshow(original_data, cmap='gray', origin='lower', norm=norm)
    axes[0].set_title(f"(a) Original Input\nFWHM: {fwhm_orig:.2f} px | Sources: {len(src_orig)}", fontsize=14)
    axes[0].axis('off')
    for x, y in src_orig:
        axes[0].add_patch(Circle((x, y), radius=10, edgecolor='lime', facecolor='none', lw=1.5))

    # Panel (b): Encrypted
    axes[1].imshow(enc_display, cmap='gray', origin='lower')
    axes[1].set_title(f"(b) AES-GCM Encrypted\nStructure destroyed | Sources: {len(src_enc)}", fontsize=14)
    axes[1].axis('off')
    for x, y in src_enc:
        axes[1].add_patch(Circle((x, y), radius=10, edgecolor='red', facecolor='none', lw=1.0))

    # Panel (c): Decrypted
    axes[2].imshow(decrypted_data, cmap='gray', origin='lower', norm=norm_dec)
    axes[2].set_title(f"(c) Decrypted Output\nFWHM: {fwhm_dec:.2f} px | {integrity_msg}", fontsize=14)
    axes[2].axis('off')
    for x, y in src_dec:
        axes[2].add_patch(Circle((x, y), radius=10, edgecolor='lime', facecolor='none', lw=1.5))

    plt.tight_layout()

    fig_png = os.path.join(OUTPUT_DIR, "scientific_validation_triptych.png")
    fig_pdf = os.path.join(OUTPUT_DIR, "scientific_validation_triptych.pdf")
    plt.savefig(fig_png, dpi=300, bbox_inches='tight')
    plt.savefig(fig_pdf, dpi=300, bbox_inches='tight')
    plt.close('all')

    print(f"\n  Output saved to:")
    print(f"    {fig_png}")
    print(f"    {fig_pdf}")
    print("\nDone.")


if __name__ == "__main__":
    main()
