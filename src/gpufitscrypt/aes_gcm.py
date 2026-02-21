"""AES-GCM authenticated encryption with parallel GHASH.

Implements AES-GCM (NIST SP 800-38D) using:
  - AES block cipher via the ``cryptography`` library (hardware-accelerated).
  - CTR-mode encryption: each 16-byte block is encrypted independently,
    making the entire plaintext trivially parallelisable on a GPU.
  - GHASH authentication via the parallel tree-reduction algorithm
    implemented in :mod:`gpufitscrypt.ghash`.

The GPU path (kernels/aes_gcm_kernel.cu) fuses the CTR and GHASH kernels
into a single pass over the data, minimising global-memory bandwidth.

Only 12-byte (96-bit) IVs are supported; this is the recommended form
defined in NIST SP 800-38D Section 8.2.1 and avoids a second GHASH pass.
"""

import hmac

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .ghash import ghash_parallel

_BACKEND = default_backend()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _aes_ecb_block(key: bytes, block: bytes) -> bytes:
    """Compute AES_K(block) – a single block encryption used as a PRF.

    Implemented via CTR mode with *block* as the initial counter and
    all-zero plaintext, so that:
        output = AES_K(block) XOR 0^128 = AES_K(block)
    This avoids using ECB mode while producing the identical result needed
    by the GCM key schedule (H = AES_K(0^128)) and CTR keystream.
    """
    cipher = Cipher(algorithms.AES(key), modes.CTR(block), backend=_BACKEND)
    enc = cipher.encryptor()
    return enc.update(b"\x00" * 16)


def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _int_to_bytes(n: int, length: int = 16) -> bytes:
    return n.to_bytes(length, "big")


def _pad16(data: bytes) -> bytes:
    """Zero-pad *data* to the next multiple of 16 bytes."""
    rem = len(data) % 16
    return data if rem == 0 else data + b"\x00" * (16 - rem)


def _inc32(counter: bytes) -> bytes:
    """Increment the least-significant 32 bits of a 128-bit counter block."""
    n = _bytes_to_int(counter)
    lower32 = ((n & 0xFFFFFFFF) + 1) & 0xFFFFFFFF
    return _int_to_bytes((n & ~0xFFFFFFFF) | lower32)


def _build_ghash_blocks(aad: bytes, ciphertext: bytes) -> list:
    """Assemble the GHASH input sequence per NIST SP 800-38D Section 7.1.

    Returns a list of 128-bit integers:
        pad(AAD) || pad(C) || [len(AAD)*8 as u64] || [len(C)*8 as u64]
    """
    blocks = []
    if aad:
        padded = _pad16(aad)
        for i in range(0, len(padded), 16):
            blocks.append(_bytes_to_int(padded[i: i + 16]))
    if ciphertext:
        padded = _pad16(ciphertext)
        for i in range(0, len(padded), 16):
            blocks.append(_bytes_to_int(padded[i: i + 16]))
    len_block = (len(aad) * 8).to_bytes(8, "big") + (len(ciphertext) * 8).to_bytes(8, "big")
    blocks.append(_bytes_to_int(len_block))
    return blocks


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def gcm_encrypt(
    key: bytes, iv: bytes, plaintext: bytes, aad: bytes = b""
) -> tuple:
    """Encrypt *plaintext* with AES-GCM and return ``(ciphertext, tag)``.

    The authentication tag covers both *aad* (in the clear) and *ciphertext*,
    providing integrity verification for the full record.

    The CTR encryption phase is data-parallel: each 16-byte block is
    independently encrypted as ``C_i = P_i XOR AES_K(J0 + i)``.  The
    parallel GHASH phase is described in :mod:`gpufitscrypt.ghash`.

    Args:
        key:       AES key – 16, 24, or 32 bytes.
        iv:        Initialisation vector – must be exactly 12 bytes.
        plaintext: Plaintext bytes (may be empty).
        aad:       Additional authenticated data (not encrypted).

    Returns:
        A ``(ciphertext, tag)`` tuple where *tag* is 16 bytes.

    Raises:
        ValueError: If *key* or *iv* lengths are invalid.
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("Key must be 16, 24, or 32 bytes")
    if len(iv) != 12:
        raise ValueError("IV must be exactly 12 bytes")

    # Hash subkey H = AES_K(0^128)
    h = _bytes_to_int(_aes_ecb_block(key, b"\x00" * 16))

    # Initial counter block J0 = IV || 0x00000001
    j0 = iv + b"\x00\x00\x00\x01"

    # CTR encryption – each block is independent (trivially parallel on GPU)
    ciphertext_blocks = []
    counter = _inc32(j0)
    num_blocks = (len(plaintext) + 15) // 16 if plaintext else 0
    for _ in range(num_blocks):
        ks = _aes_ecb_block(key, counter)
        ciphertext_blocks.append(ks)
        counter = _inc32(counter)

    if plaintext:
        padded_pt = _pad16(plaintext)
        ciphertext = bytes(
            a ^ b
            for chunk, ks in zip(
                (padded_pt[i: i + 16] for i in range(0, len(padded_pt), 16)),
                ciphertext_blocks,
            )
            for a, b in zip(chunk, ks)
        )[: len(plaintext)]
    else:
        ciphertext = b""

    # Parallel GHASH over AAD || ciphertext || lengths
    ghash_blocks = _build_ghash_blocks(aad, ciphertext)
    s = ghash_parallel(h, ghash_blocks)
    ej0 = _bytes_to_int(_aes_ecb_block(key, j0))
    tag = _int_to_bytes(s ^ ej0)

    return ciphertext, tag


def gcm_decrypt(
    key: bytes, iv: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b""
) -> bytes:
    """Decrypt and authenticate an AES-GCM ciphertext.

    Authenticates *ciphertext* and *aad* before decrypting.  The tag is
    compared using a constant-time digest to prevent timing side-channels.

    Args:
        key:        AES key – 16, 24, or 32 bytes.
        iv:         Initialisation vector – must be exactly 12 bytes.
        ciphertext: Encrypted bytes.
        tag:        16-byte authentication tag.
        aad:        Additional authenticated data (must match encryption).

    Returns:
        Decrypted plaintext bytes.

    Raises:
        ValueError: If *tag* verification fails or inputs are invalid.
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("Key must be 16, 24, or 32 bytes")
    if len(iv) != 12:
        raise ValueError("IV must be exactly 12 bytes")
    if len(tag) != 16:
        raise ValueError("Tag must be 16 bytes")

    h = _bytes_to_int(_aes_ecb_block(key, b"\x00" * 16))
    j0 = iv + b"\x00\x00\x00\x01"

    # Compute and verify the authentication tag
    ghash_blocks = _build_ghash_blocks(aad, ciphertext)
    s = ghash_parallel(h, ghash_blocks)
    ej0 = _bytes_to_int(_aes_ecb_block(key, j0))
    expected_tag = _int_to_bytes(s ^ ej0)

    if not hmac.compare_digest(expected_tag, tag):
        raise ValueError("AES-GCM authentication tag verification failed")

    # CTR decryption (symmetric with encryption)
    if not ciphertext:
        return b""

    plaintext_blocks = []
    counter = _inc32(j0)
    padded_ct = _pad16(ciphertext)
    for i in range(0, len(padded_ct), 16):
        ks = _aes_ecb_block(key, counter)
        plaintext_blocks.append(bytes(a ^ b for a, b in zip(padded_ct[i: i + 16], ks)))
        counter = _inc32(counter)

    return b"".join(plaintext_blocks)[: len(ciphertext)]
