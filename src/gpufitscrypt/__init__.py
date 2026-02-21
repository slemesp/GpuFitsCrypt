"""GpuFitsCrypt – GPU-accelerated AES-GCM for astronomical FITS catalogs.

Public API re-exports for convenience:

    from gpufitscrypt import gcm_encrypt, gcm_decrypt
    from gpufitscrypt import PolicyEngine, PolicyRule, AccessRequest, Action, Effect
    from gpufitscrypt import FitsEncryptionHandler
"""

from .aes_gcm import gcm_decrypt, gcm_encrypt
from .fits_handler import FitsEncryptionHandler
from .gf128 import GF128_ONE, gf128_mul, gf128_pow
from .ghash import ghash_parallel, ghash_sequential
from .policy_engine import (
    AccessRequest,
    Action,
    Effect,
    PolicyEngine,
    PolicyRule,
)

__all__ = [
    # AES-GCM
    "gcm_encrypt",
    "gcm_decrypt",
    # GF(2^128)
    "gf128_mul",
    "gf128_pow",
    "GF128_ONE",
    # GHASH
    "ghash_sequential",
    "ghash_parallel",
    # Policy engine
    "PolicyEngine",
    "PolicyRule",
    "AccessRequest",
    "Action",
    "Effect",
    # FITS handler
    "FitsEncryptionHandler",
]
