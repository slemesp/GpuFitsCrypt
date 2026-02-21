"""Tests for AES-GCM encryption/decryption (aes_gcm.py).

Validates correctness against the ``cryptography`` reference library and
checks that authenticated-encryption properties hold.
"""

import os
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from gpufitscrypt.aes_gcm import gcm_decrypt, gcm_encrypt


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ref_encrypt(key, iv, pt, aad=b""):
    """Encrypt with the ``cryptography`` library; returns (ct, tag)."""
    blob = AESGCM(key).encrypt(iv, pt, aad if aad else None)
    return blob[:-16], blob[-16:]


def ref_decrypt(key, iv, ct, tag, aad=b""):
    """Decrypt with the ``cryptography`` library."""
    return AESGCM(key).decrypt(iv, ct + tag, aad if aad else None)


# ---------------------------------------------------------------------------
# Basic encrypt / decrypt round-trip
# ---------------------------------------------------------------------------

class TestAesGcmRoundTrip:
    def test_empty_plaintext(self):
        key, iv = os.urandom(16), os.urandom(12)
        ct, tag = gcm_encrypt(key, iv, b"")
        pt = gcm_decrypt(key, iv, ct, tag)
        assert pt == b""

    def test_short_plaintext(self):
        key, iv = os.urandom(16), os.urandom(12)
        plain = b"Hello, FITS!"
        ct, tag = gcm_encrypt(key, iv, plain)
        assert gcm_decrypt(key, iv, ct, tag) == plain

    def test_exact_block_size(self):
        key, iv = os.urandom(16), os.urandom(12)
        plain = b"A" * 16
        ct, tag = gcm_encrypt(key, iv, plain)
        assert gcm_decrypt(key, iv, ct, tag) == plain

    def test_multi_block(self):
        key, iv = os.urandom(16), os.urandom(12)
        plain = os.urandom(256)
        ct, tag = gcm_encrypt(key, iv, plain)
        assert gcm_decrypt(key, iv, ct, tag) == plain

    def test_large_plaintext(self):
        key, iv = os.urandom(32), os.urandom(12)
        plain = os.urandom(65536)
        ct, tag = gcm_encrypt(key, iv, plain)
        assert gcm_decrypt(key, iv, ct, tag) == plain

    @pytest.mark.parametrize("key_len", [16, 24, 32])
    def test_key_lengths(self, key_len):
        key, iv = os.urandom(key_len), os.urandom(12)
        plain = b"test payload for key length " + bytes([key_len])
        ct, tag = gcm_encrypt(key, iv, plain)
        assert gcm_decrypt(key, iv, ct, tag) == plain

    def test_with_aad(self):
        key, iv = os.urandom(16), os.urandom(12)
        plain = b"secret astronomical data"
        aad = b"fits:survey2025.fits"
        ct, tag = gcm_encrypt(key, iv, plain, aad)
        assert gcm_decrypt(key, iv, ct, tag, aad) == plain

    def test_aad_does_not_appear_in_ciphertext(self):
        key, iv = os.urandom(16), os.urandom(12)
        aad = b"metadata-header"
        plain = b"image data " * 10
        ct, tag = gcm_encrypt(key, iv, plain, aad)
        assert aad not in ct


# ---------------------------------------------------------------------------
# Compatibility with the ``cryptography`` reference library
# ---------------------------------------------------------------------------

class TestAesGcmReferenceCompatibility:
    """Our ciphertext and tag must match the reference library."""

    @pytest.mark.parametrize("key_len,pt_len", [
        (16, 0), (16, 1), (16, 15), (16, 16), (16, 31), (16, 64),
        (24, 64), (32, 64), (32, 4096),
    ])
    def test_ciphertext_matches_reference(self, key_len, pt_len):
        key = bytes(range(key_len))
        iv = bytes(range(12))
        pt = bytes(range(pt_len % 256)) * (pt_len // 256 + 1)
        pt = pt[:pt_len]
        aad = b"aad-data"

        ct_ours, tag_ours = gcm_encrypt(key, iv, pt, aad)
        ct_ref, tag_ref = ref_encrypt(key, iv, pt, aad)

        assert ct_ours == ct_ref, "Ciphertext mismatch"
        assert tag_ours == tag_ref, "Tag mismatch"

    def test_decrypt_reference_ciphertext(self):
        """We can decrypt a ciphertext produced by the reference library."""
        key, iv = os.urandom(16), os.urandom(12)
        pt = os.urandom(128)
        aad = b"header-bytes"
        ct_ref, tag_ref = ref_encrypt(key, iv, pt, aad)
        assert gcm_decrypt(key, iv, ct_ref, tag_ref, aad) == pt

    def test_reference_decrypts_our_ciphertext(self):
        """The reference library can decrypt what we encrypt."""
        key, iv = os.urandom(16), os.urandom(12)
        pt = os.urandom(128)
        aad = b"header-bytes"
        ct_ours, tag_ours = gcm_encrypt(key, iv, pt, aad)
        assert ref_decrypt(key, iv, ct_ours, tag_ours, aad) == pt


# ---------------------------------------------------------------------------
# Authentication tag verification
# ---------------------------------------------------------------------------

class TestAesGcmAuthentication:
    """Modified ciphertexts and AAD must be rejected."""

    def test_wrong_key_rejected(self):
        key, iv = os.urandom(16), os.urandom(12)
        ct, tag = gcm_encrypt(key, iv, b"data")
        with pytest.raises(ValueError, match="tag"):
            gcm_decrypt(os.urandom(16), iv, ct, tag)

    def test_wrong_iv_rejected(self):
        key, iv = os.urandom(16), os.urandom(12)
        ct, tag = gcm_encrypt(key, iv, b"data")
        with pytest.raises(ValueError, match="tag"):
            gcm_decrypt(key, os.urandom(12), ct, tag)

    def test_tampered_ciphertext_rejected(self):
        key, iv = os.urandom(16), os.urandom(12)
        ct, tag = gcm_encrypt(key, iv, b"important data")
        tampered = bytes([ct[0] ^ 0xFF]) + ct[1:]
        with pytest.raises(ValueError, match="tag"):
            gcm_decrypt(key, iv, tampered, tag)

    def test_tampered_tag_rejected(self):
        key, iv = os.urandom(16), os.urandom(12)
        ct, tag = gcm_encrypt(key, iv, b"important data")
        tampered_tag = bytes([tag[0] ^ 0x01]) + tag[1:]
        with pytest.raises(ValueError, match="tag"):
            gcm_decrypt(key, iv, ct, tampered_tag)

    def test_wrong_aad_rejected(self):
        key, iv = os.urandom(16), os.urandom(12)
        ct, tag = gcm_encrypt(key, iv, b"data", b"correct-aad")
        with pytest.raises(ValueError, match="tag"):
            gcm_decrypt(key, iv, ct, tag, b"wrong-aad")

    def test_missing_aad_rejected(self):
        key, iv = os.urandom(16), os.urandom(12)
        ct, tag = gcm_encrypt(key, iv, b"data", b"required-aad")
        with pytest.raises(ValueError, match="tag"):
            gcm_decrypt(key, iv, ct, tag)  # no aad


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

class TestAesGcmInputValidation:
    def test_invalid_key_length(self):
        with pytest.raises(ValueError, match="Key"):
            gcm_encrypt(b"short", os.urandom(12), b"")

    def test_invalid_iv_length(self):
        with pytest.raises(ValueError, match="IV"):
            gcm_encrypt(os.urandom(16), b"short-iv", b"")

    def test_invalid_tag_length(self):
        with pytest.raises(ValueError, match="Tag"):
            gcm_decrypt(os.urandom(16), os.urandom(12), b"ct", b"short")
