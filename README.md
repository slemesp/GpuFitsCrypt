# GpuFitsCrypt

**A High-Throughput AES-GCM Implementation on GPUs for Secure, Policy-Based Access to Massive Astronomical Catalogs**

---

## Overview

Large astronomical surveys produce image catalogs at petabyte scale.  During
pre-publication embargo periods, data providers need fine-grained, high-speed
access control that does not create a bottleneck for downstream pipelines.

GpuFitsCrypt addresses this with two complementary components:

1. **GPU-accelerated AES-GCM** – authenticated encryption whose inherently
   sequential bottleneck (the GHASH polynomial hash) is eliminated through a
   *parallel tree-reduction* strategy.
2. **Policy engine** – a flexible, rule-based access-control framework that
   lets data providers express per-user, per-role, and per-resource
   permissions with optional temporal conditions (e.g. embargo dates).

---

## Key Innovation – Parallel GHASH via Tree Reduction

Standard GCM authentication is inherently sequential:

```
Y_i = (Y_{i-1} XOR X_i) · H,    Y_0 = 0
```

Expanding the recurrence over *m* blocks gives an equivalent dot product:

```
GHASH_H(X_1, …, X_m) = X_1·H^m  ⊕  X_2·H^(m-1)  ⊕  …  ⊕  X_m·H^1
```

This form decomposes into three data-parallel phases that map directly onto
CUDA kernel launches:

| Phase | Operation | Complexity |
|-------|-----------|------------|
| 1 | Precompute H^1 … H^m | O(log m) squarings |
| 2 | Compute X_i · H^(m−i+1) for each block (one thread per block) | O(1) per thread |
| 3 | XOR tree reduction of partial products | O(log m) synchronisation steps |

The CUDA kernels are in
[`src/gpufitscrypt/kernels/`](src/gpufitscrypt/kernels/).
The CPU reference implementation (used when no GPU is available) is in
[`src/gpufitscrypt/ghash.py`](src/gpufitscrypt/ghash.py).

---

## Repository Structure

```
GpuFitsCrypt/
├── src/
│   └── gpufitscrypt/
│       ├── __init__.py          # Public API re-exports
│       ├── gf128.py             # GF(2^128) arithmetic (NIST SP 800-38D)
│       ├── ghash.py             # GHASH: sequential + parallel tree reduction
│       ├── aes_gcm.py           # AES-GCM encrypt / decrypt (CPU reference)
│       ├── policy_engine.py     # Fine-grained access-control policy engine
│       ├── fits_handler.py      # FITS file encryption / decryption handler
│       └── kernels/
│           ├── ghash_kernel.cu  # CUDA parallel GHASH (Phases 1-3)
│           └── aes_gcm_kernel.cu# CUDA fused AES-CTR + GHASH kernel
├── tests/
│   ├── test_gf128.py            # GF(2^128) field axioms + known values
│   ├── test_ghash.py            # Sequential == parallel equivalence + ref tags
│   ├── test_aes_gcm.py          # Round-trip, reference compat, auth tests
│   ├── test_policy_engine.py    # Policy evaluation, conditions, rule management
│   └── test_fits_handler.py     # FITS encrypt/decrypt, policy enforcement
├── CMakeLists.txt               # CUDA kernel build (requires nvcc >= 11)
├── requirements.txt
└── setup.py
```

---

## Quick Start

### Python (CPU reference – no GPU required)

```bash
pip install -e .
```

```python
import os
from gpufitscrypt import gcm_encrypt, gcm_decrypt

key = os.urandom(32)      # AES-256
iv  = os.urandom(12)      # 96-bit IV (GCM standard)
plaintext = b"Crab Nebula flux catalogue 2025"
aad       = b"survey:DR1"

ciphertext, tag = gcm_encrypt(key, iv, plaintext, aad)
recovered = gcm_decrypt(key, iv, ciphertext, tag, aad)
assert recovered == plaintext
```

### FITS file encryption

```python
from gpufitscrypt import FitsEncryptionHandler, PolicyEngine, PolicyRule, Action, Effect

# Build an access policy
engine = PolicyEngine()
engine.add_rule(PolicyRule(
    rule_id="allow-researchers",
    effect=Effect.ALLOW,
    actions=[Action.ENCRYPT, Action.DECRYPT],
    principals=["role:researcher"],
    resources=["fits:*"],
))

handler = FitsEncryptionHandler(policy_engine=engine)

# Encrypt
handler.encrypt_fits_to_file(
    "survey_tile_042.fits", "survey_tile_042.enc.fits",
    key=key, iv=iv, principal="role:researcher",
)

# Decrypt (policy-checked)
with handler.decrypt_fits("survey_tile_042.enc.fits", key,
                           principal="role:researcher") as hdul:
    print(hdul[0].header["OBJECT"])
```

### CUDA kernel build (requires NVIDIA GPU + nvcc >= 11)

```bash
cmake -S . -B build -DCMAKE_CUDA_ARCHITECTURES="80;86;90"
cmake --build build -j
```

---

## Testing

```bash
pip install pytest
pytest tests/ -v
```

All 104 tests pass on a CPU-only machine.

---

## Policy Engine

Rules are composed of:

| Field | Description |
|-------|-------------|
| `rule_id` | Unique identifier for auditing |
| `effect` | `ALLOW` or `DENY` (DENY always takes precedence) |
| `actions` | `READ`, `WRITE`, `ENCRYPT`, `DECRYPT`, `ADMIN` |
| `principals` | `"user:<name>"`, `"role:<name>"`, or `"*"` |
| `resources` | Glob patterns, e.g. `"fits:survey/*.fits"` |
| `conditions` | Key/value constraints; supports `{"before": "<iso-date>"}` for embargoes |

---

## Encrypted FITS File Format

The encrypted file is a valid FITS file whose primary HDU contains a raw
byte array with the layout:

```
[IV – 12 bytes] [TAG – 16 bytes] [CIPHERTEXT – variable]
```

A `GPUCRYPT = T` keyword in the header marks the file as encrypted.
Standard FITS tooling can read the provenance keywords (OBJECT, TELESCOP,
DATE-OBS, …) from the encrypted file without the decryption key.

---

## References

- NIST SP 800-38D – *Recommendation for Block Cipher Modes of Operation:
  Galois/Counter Mode (GCM) and GMAC*
- NIST FIPS 197 – *Advanced Encryption Standard (AES)*
- D. A. McGrew & J. Viega, "The Galois/Counter Mode of Operation (GCM)",
  *IEEE Transactions on Information Forensics and Security*, 2004.
