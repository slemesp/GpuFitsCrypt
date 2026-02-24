# References & Acknowledgements

The high-performance cryptographic implementations in `GpuFitsCrypt` are based on state-of-the-art research in parallel computing and GPU acceleration. We gratefully acknowledge the following works:

## Core AES-CTR Implementation
The bit-sliced AES-CTR implementation is derived from the optimization strategies described in:

> **W.-K. Lee, S. C. Seo, H. Seo, D. C. Kim and S. O. Hwang**, "Speed Record of AES-CTR and AES-ECB Bit-Sliced Implementation on GPUs," in *IEEE Embedded Systems Letters*, vol. 16, no. 4, pp. 481-484, Dec. 2024.  
> **DOI:** [10.1109/LES.2024.3409725](https://doi.org/10.1109/LES.2024.3409725)

**Codebase Origin:**
This project builds upon the foundational CUDA implementation provided by the authors of the above paper:
*   **Repository:** [benlwk/AES-BS-GPU](https://github.com/benlwk/AES-BS-GPU)
*   **Modifications:** We have significantly extended this core to support the FITS file format, implemented the GCM authenticated encryption mode (with parallel GHASH), added Python bindings, and developed the granular access control system.

## Parallel AES-GCM & GHASH
The fully parallelized GCM mode and the logarithmic-time GHASH reduction strategy are based on:

> **JaeSeok Lee, DongCheon Kim, Seog Chung Seo**, "Parallel implementation of GCM on GPUs," in *ICT Express*, Volume 11, Issue 2, pp. 310-316, 2025.  
> **ISSN:** 2405-9595  
> **DOI:** [10.1016/j.icte.2025.01.006](https://doi.org/10.1016/j.icte.2025.01.006)

---
*This library adapts these algorithms specifically for the FITS file format and astronomical data pipelines.*
