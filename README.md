# GpuFitsCrypt: High-Performance FITS Encryption Library

GpuFitsCrypt is a specialized C++/CUDA library designed for the secure, high-throughput encryption and decryption of astronomical FITS files. It implements the AES-128 standard in both GCM (Galois/Counter Mode) and CTR (Counter Mode) using a highly optimized bit-sliced approach on NVIDIA GPUs.

The library introduces a Granular Access Control model, which allows for independent cryptographic keys for metadata (Header) and pixel data (Data). This enables flexible data sharing policies—such as metadata-only access during proprietary periods—without compromising the confidentiality or integrity of the scientific payload.

> **Note on Core Engine:** The underlying bit-sliced AES-CTR implementation is based on the [AES-BS-GPU](https://github.com/benlwk/AES-BS-GPU) project by W.-K. Lee et al. This library extends that work with FITS-specific encapsulation, GCM authentication, and high-level Python bindings.

---

## Key Technical Features

*   **High-Throughput Performance**: Fully parallelized AES-GCM implementation on GPU, achieving multi-gigabit throughput capable of saturating modern storage interfaces and acquisition pipelines.
*   **Granular Access Control**: Decouples header and data decryption paths.
    *   **Header Key Only**: Allows metadata inspection while the pixel data remains physically suppressed (zero-filled).
    *   **Data Key Only**: Allows scientific analysis with a sanitized fallback header when telemetry is restricted.
*   **Authenticated Encryption (AEAD)**: The GCM mode provides intrinsic data integrity verification, ensuring that any unauthorized modification to the FITS container is detected during decryption.
*   **Standard Compatibility**: Encrypted files remain valid FITS containers, allowing standard archival tools to parse the structural metadata without exposing the encrypted content.
*   **Flexible Integration**: Supports both file-to-file operations and direct memory-to-disk encryption for integration with camera drivers and real-time acquisition software.
*   **Scientific Python Bindings**: Comprehensive Python wrapper for seamless integration into existing workflows using `astropy` and `numpy`.

---

## Installation and Usage

### Prerequisites
*   NVIDIA GPU (Compute Capability 5.0 or higher)
*   CUDA Toolkit 11.0+
*   `cfitsio` library
*   Python 3.8+ (for wrappers and examples)

### Compilation
The library uses a `Makefile` for automated builds. The compilation process can be tuned for specific GPU architectures by adjusting thread block sizes.

```bash
# Build with default parameters (TSBS=64, RBS=4)
make
```

### Basic Example
A canonical example demonstrating the encryption of synthetic data and subsequent granular decryption is provided in the `examples` directory.

```bash
python3 examples/basic_usage.py
```

---

## Documentation

For detailed technical information, please refer to the following resources:

*   **[API Reference (README_API.md)](README_API.md)**: Detailed documentation of C structures, API functions, and error handling.
*   **[Granular Access Model](README_API.md#granular-access--error-codes)**: Technical explanation of partial decryption behavior and warning codes.
*   **[References (REFERENCES.md)](REFERENCES.md)**: Academic background and algorithmic foundations.

---

## Scientific Validation

The library has been rigorously validated using **GPUPhot**, a high-performance photometry package. Validation tests confirm:
1.  **Semantic Confidentiality**: Encrypted payloads are statistically indistinguishable from high-entropy noise (zero sources detected by extraction algorithms).
2.  **Bit-Exact Integrity**: Decrypted images match the original input with zero residuals.
3.  **Science Readiness**: Photometric parameters (FWHM, instrumental flux, and centroids) extracted from decrypted data are identical to those from the original data within machine precision.

Detailed validation workflows can be found in `examples/scientific_validation.py`.

---

## Citation

If you utilize GpuFitsCrypt in your research or infrastructure, please cite the following work:

```bibtex
@article{lemes_gpufitscrypt_2025,
  title={GpuFitsCrypt: High-Throughput Granular Encryption for Astronomical Archives},
  author={Lemes-Perera, Samuel and Alarcon, Miguel R. and Caballero-Gil, Pino and Serra-Ricart, Miquel},
  journal={Submitted to Astronomy & Computing},
  year={2025},
  note={GitHub Repository: https://github.com/slemes/GpuFitsCrypt}
}
```

### Acknowledgments
This library builds upon foundational research in GPU cryptography:

*   **W.-K. Lee et al.**, "Speed Record of AES-CTR and AES-ECB Bit-Sliced Implementation on GPUs," *IEEE Embedded Systems Letters*, 2024. DOI: [10.1109/LES.2024.3409725](https://doi.org/10.1109/LES.2024.3409725)
*   **J. Lee et al.**, "Parallel implementation of GCM on GPUs," *ICT Express*, 2025. DOI: [10.1016/j.icte.2025.01.006](https://doi.org/10.1016/j.icte.2025.01.006)

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
