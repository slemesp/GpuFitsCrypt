"""Tests for GHASH implementations (ghash.py).

Validates that:
  1. ghash_sequential and ghash_parallel produce identical results.
  2. Both implementations are consistent with the AES-GCM tag produced by
     the ``cryptography`` reference library.
"""

import os
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from gpufitscrypt.gf128 import gf128_mul
from gpufitscrypt.ghash import ghash_parallel, ghash_sequential


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _aes_block(key: bytes, block: bytes) -> bytes:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    # CTR with `block` as counter, all-zero plaintext: output = AES_K(block).
    c = Cipher(algorithms.AES(key), modes.CTR(block), backend=default_backend())
    enc = c.encryptor()
    return enc.update(b"\x00" * 16)


def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _pad16(data: bytes) -> bytes:
    rem = len(data) % 16
    return data if rem == 0 else data + b"\x00" * (16 - rem)


def _build_ghash_blocks(aad: bytes, ciphertext: bytes) -> list:
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
# Sequential == Parallel for arbitrary inputs
# ---------------------------------------------------------------------------

class TestGhashEquivalence:
    """ghash_parallel must equal ghash_sequential for all inputs."""

    H = 0x66E94BD4EF8A2C3B884CFA59CA342B2E  # AES_K(0) for zero key

    def test_single_block(self):
        blocks = [0xDEADBEEFCAFEBABE0102030405060708]
        assert ghash_parallel(self.H, blocks) == ghash_sequential(self.H, blocks)

    def test_two_blocks(self):
        blocks = [0x11223344556677881122334455667788,
                  0x99AABBCCDDEEFF0099AABBCCDDEEFF00]
        assert ghash_parallel(self.H, blocks) == ghash_sequential(self.H, blocks)

    def test_many_blocks(self):
        blocks = [i * 0x0101010101010101010101010101 + 1 for i in range(64)]
        assert ghash_parallel(self.H, blocks) == ghash_sequential(self.H, blocks)

    def test_empty_block_list(self):
        assert ghash_parallel(self.H, []) == 0
        assert ghash_sequential(self.H, []) == 0

    def test_zero_valued_blocks(self):
        blocks = [0] * 8
        assert ghash_parallel(self.H, blocks) == ghash_sequential(self.H, blocks)

    def test_power_of_two_minus_one_blocks(self):
        # 15 blocks – not a power of 2, exercises the odd-length path
        blocks = [0xABCDEF01234567890ABCDEF012345678 ^ (i << 4) for i in range(15)]
        assert ghash_parallel(self.H, blocks) == ghash_sequential(self.H, blocks)

    @pytest.mark.parametrize("n", [1, 2, 3, 4, 7, 8, 9, 16, 17, 32, 33, 100])
    def test_various_lengths(self, n):
        h = 0x66E94BD4EF8A2C3B884CFA59CA342B2E
        blocks = [(h * (i + 1)) % (1 << 128) for i in range(n)]
        assert ghash_parallel(h, blocks) == ghash_sequential(h, blocks)


# ---------------------------------------------------------------------------
# Correctness against the ``cryptography`` reference AES-GCM
# ---------------------------------------------------------------------------

class TestGhashCorrectness:
    """Verify GHASH output is consistent with a known-correct AES-GCM tag."""

    def _compute_our_tag(self, key, iv, plaintext, aad):
        """Compute AES-GCM tag using our GHASH implementations."""
        from gpufitscrypt.aes_gcm import gcm_encrypt
        _, tag = gcm_encrypt(key, iv, plaintext, aad)
        return tag

    def _compute_ref_tag(self, key, iv, plaintext, aad):
        """Compute AES-GCM tag using the ``cryptography`` library."""
        ct_with_tag = AESGCM(key).encrypt(iv, plaintext, aad if aad else None)
        return ct_with_tag[-16:]  # last 16 bytes are the tag

    @pytest.mark.parametrize("key_len", [16, 32])
    def test_tag_matches_reference_empty(self, key_len):
        key = bytes(range(key_len))
        iv = os.urandom(12)
        tag_ours = self._compute_our_tag(key, iv, b"", b"")
        tag_ref = self._compute_ref_tag(key, iv, b"", b"")
        assert tag_ours == tag_ref

    @pytest.mark.parametrize("key_len", [16, 32])
    def test_tag_matches_reference_with_data(self, key_len):
        key = bytes(range(key_len))
        iv = os.urandom(12)
        pt = b"Hello, astronomical world!" * 4
        aad = b"survey:DR1:2025"
        tag_ours = self._compute_our_tag(key, iv, pt, aad)
        tag_ref = self._compute_ref_tag(key, iv, pt, aad)
        assert tag_ours == tag_ref

    def test_tag_matches_reference_large_plaintext(self):
        key = os.urandom(16)
        iv = os.urandom(12)
        pt = os.urandom(4096)
        aad = b"catalog:tile42"
        tag_ours = self._compute_our_tag(key, iv, pt, aad)
        tag_ref = self._compute_ref_tag(key, iv, pt, aad)
        assert tag_ours == tag_ref
