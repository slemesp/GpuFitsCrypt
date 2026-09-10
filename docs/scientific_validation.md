# Scientific Validation

The library has been rigorously validated using **[GPUPhot](https://github.com/Light-Bridges/GPUPhot)**, a high-performance astronomical photometry package, as well as **[SEP](https://github.com/kbarbary/sep)** and `scipy`.

Validation tests confirm three fundamental properties:

1. **Semantic Confidentiality**: Encrypted payloads are statistically indistinguishable from high-entropy noise (zero sources detected by extraction algorithms).
2. **Bit-Exact Integrity**: Decrypted images match the original input with zero residuals (bitwise exact).
3. **Science Readiness**: Photometric parameters (FWHM, instrumental flux, and centroids) extracted from decrypted data are identical to those from the original data within machine precision.

## Running the Validation Script

The validation script supports three detection backends (GPUPhot > SEP > scipy) and works out of the box with synthetic data or real astronomical FITS images:

```bash
# Using synthetic test image
python3 examples/scientific_validation.py

# Using a real FITS image
python3 examples/scientific_validation.py --input_fits /path/to/real_image.fits
```

Outputs are saved in `scientific_validation/` as:
* `scientific_validation_triptych.png`
* `scientific_validation_triptych.pdf`
