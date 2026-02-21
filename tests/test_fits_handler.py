"""Tests for FITS file encryption/decryption handler (fits_handler.py)."""

import io
import os
import tempfile

import numpy as np
import pytest
from astropy.io import fits

from gpufitscrypt.fits_handler import FitsEncryptionHandler
from gpufitscrypt.policy_engine import (
    AccessRequest,
    Action,
    Effect,
    PolicyEngine,
    PolicyRule,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def aes_key():
    return os.urandom(16)


@pytest.fixture
def aes_iv():
    return os.urandom(12)


@pytest.fixture
def sample_fits_path(tmp_path):
    """Create a minimal FITS file with a small image array."""
    data = np.arange(100, dtype=np.float32).reshape(10, 10)
    hdu = fits.PrimaryHDU(data)
    hdu.header["OBJECT"] = "TestGalaxy"
    hdu.header["DATE-OBS"] = "2025-01-01"
    path = str(tmp_path / "sample.fits")
    hdu.writeto(path)
    return path


@pytest.fixture
def multi_hdu_fits_path(tmp_path):
    """Create a multi-extension FITS file."""
    primary = fits.PrimaryHDU(np.zeros((4, 4), dtype=np.float32))
    image = fits.ImageHDU(np.ones((4, 4), dtype=np.float32), name="SCI")
    hdul = fits.HDUList([primary, image])
    path = str(tmp_path / "multi.fits")
    hdul.writeto(path)
    return path


@pytest.fixture
def handler():
    return FitsEncryptionHandler()


# ---------------------------------------------------------------------------
# Encrypt → payload bytes
# ---------------------------------------------------------------------------

class TestEncryptPayload:
    def test_returns_bytes(self, handler, sample_fits_path, aes_key, aes_iv):
        payload = handler.encrypt_fits(sample_fits_path, aes_key, aes_iv)
        assert isinstance(payload, bytes)

    def test_payload_minimum_length(self, handler, sample_fits_path, aes_key, aes_iv):
        payload = handler.encrypt_fits(sample_fits_path, aes_key, aes_iv)
        # At minimum: 12 (IV) + 16 (tag) + 1 byte ciphertext
        assert len(payload) > 28

    def test_payload_starts_with_iv(self, handler, sample_fits_path, aes_key, aes_iv):
        payload = handler.encrypt_fits(sample_fits_path, aes_key, aes_iv)
        assert payload[:12] == aes_iv

    def test_different_ivs_produce_different_ciphertexts(self, handler, sample_fits_path, aes_key):
        iv1, iv2 = os.urandom(12), os.urandom(12)
        p1 = handler.encrypt_fits(sample_fits_path, aes_key, iv1)
        p2 = handler.encrypt_fits(sample_fits_path, aes_key, iv2)
        assert p1[28:] != p2[28:]  # ciphertexts differ


# ---------------------------------------------------------------------------
# Round-trip: encrypt_fits → decrypt_payload
# ---------------------------------------------------------------------------

class TestRoundTripPayload:
    def _read_fits_bytes(self, path):
        buf = io.BytesIO()
        with fits.open(path) as hdul:
            hdul.writeto(buf)
        return buf.getvalue()

    def test_decrypt_recovers_original(self, handler, sample_fits_path, aes_key, aes_iv):
        payload = handler.encrypt_fits(sample_fits_path, aes_key, aes_iv)
        decrypted = handler.decrypt_payload(payload, aes_key, aad=b"")
        assert decrypted == self._read_fits_bytes(sample_fits_path)

    def test_wrong_key_rejected(self, handler, sample_fits_path, aes_key, aes_iv):
        payload = handler.encrypt_fits(sample_fits_path, aes_key, aes_iv)
        with pytest.raises(ValueError):
            handler.decrypt_payload(payload, os.urandom(16), aad=b"")

    def test_tampered_payload_rejected(self, handler, sample_fits_path, aes_key, aes_iv):
        payload = handler.encrypt_fits(sample_fits_path, aes_key, aes_iv)
        tampered = bytearray(payload)
        tampered[-1] ^= 0xFF  # flip last byte of ciphertext
        with pytest.raises(ValueError):
            handler.decrypt_payload(bytes(tampered), aes_key, aad=b"")

    def test_wrong_aad_rejected(self, handler, sample_fits_path, aes_key, aes_iv):
        """Demonstrates that explicit AAD is enforced by the lower-level API."""
        aad = b"survey:DR1"
        with fits.open(sample_fits_path) as hdul:
            buf = io.BytesIO()
            hdul.writeto(buf)
            plaintext = buf.getvalue()
        from gpufitscrypt.aes_gcm import gcm_encrypt as _gcm_encrypt
        ciphertext, tag = _gcm_encrypt(aes_key, aes_iv, plaintext, aad)
        payload = aes_iv + tag + ciphertext
        with pytest.raises(ValueError):
            handler.decrypt_payload(payload, aes_key, aad=b"wrong-aad")


# ---------------------------------------------------------------------------
# Full file round-trip: encrypt_fits_to_file → decrypt_fits
# ---------------------------------------------------------------------------

class TestFullFileRoundTrip:
    def test_encrypted_file_created(self, handler, sample_fits_path, aes_key, aes_iv, tmp_path):
        out = str(tmp_path / "enc.fits")
        handler.encrypt_fits_to_file(sample_fits_path, out, aes_key, aes_iv)
        assert os.path.isfile(out)

    def test_encrypted_file_has_gpucrypt_keyword(
        self, handler, sample_fits_path, aes_key, aes_iv, tmp_path
    ):
        out = str(tmp_path / "enc.fits")
        handler.encrypt_fits_to_file(sample_fits_path, out, aes_key, aes_iv)
        with fits.open(out) as hdul:
            assert hdul[0].header.get("GPUCRYPT") is True

    def test_decrypt_recovers_header(
        self, handler, sample_fits_path, aes_key, aes_iv, tmp_path
    ):
        out = str(tmp_path / "enc.fits")
        handler.encrypt_fits_to_file(sample_fits_path, out, aes_key, aes_iv)
        with handler.decrypt_fits(out, aes_key) as hdul:
            assert hdul[0].header.get("OBJECT") == "TestGalaxy"
            assert hdul[0].header.get("DATE-OBS") == "2025-01-01"

    def test_decrypt_recovers_data(
        self, handler, sample_fits_path, aes_key, aes_iv, tmp_path
    ):
        out = str(tmp_path / "enc.fits")
        handler.encrypt_fits_to_file(sample_fits_path, out, aes_key, aes_iv)
        with handler.decrypt_fits(out, aes_key) as hdul:
            with fits.open(sample_fits_path) as orig:
                np.testing.assert_array_equal(hdul[0].data, orig[0].data)

    def test_non_encrypted_file_raises(self, handler, sample_fits_path, aes_key):
        with pytest.raises(ValueError, match="GpuFitsCrypt-encrypted"):
            handler.decrypt_fits(sample_fits_path, aes_key)


# ---------------------------------------------------------------------------
# Policy enforcement
# ---------------------------------------------------------------------------

class TestPolicyEnforcement:
    def _make_handler_with_policy(self, *rules):
        engine = PolicyEngine()
        for r in rules:
            engine.add_rule(r)
        return FitsEncryptionHandler(policy_engine=engine)

    def _allow_rule(self, action, principal):
        return PolicyRule(
            rule_id=f"allow-{principal}",
            effect=Effect.ALLOW,
            actions=[action],
            principals=[principal],
            resources=["fits:*"],
        )

    def test_allowed_principal_can_encrypt(
        self, sample_fits_path, aes_key, aes_iv
    ):
        handler = self._make_handler_with_policy(
            self._allow_rule(Action.ENCRYPT, "user:alice")
        )
        payload = handler.encrypt_fits(sample_fits_path, aes_key, aes_iv, principal="user:alice")
        assert isinstance(payload, bytes)

    def test_denied_principal_cannot_encrypt(
        self, sample_fits_path, aes_key, aes_iv
    ):
        handler = self._make_handler_with_policy()  # no rules
        with pytest.raises(PermissionError):
            handler.encrypt_fits(sample_fits_path, aes_key, aes_iv, principal="user:eve")

    def test_allowed_principal_can_decrypt(
        self, handler, sample_fits_path, aes_key, aes_iv, tmp_path
    ):
        out = str(tmp_path / "enc.fits")
        handler.encrypt_fits_to_file(sample_fits_path, out, aes_key, aes_iv)

        eng = PolicyEngine()
        eng.add_rule(self._allow_rule(Action.DECRYPT, "user:alice"))
        secured = FitsEncryptionHandler(policy_engine=eng)
        with secured.decrypt_fits(out, aes_key, principal="user:alice") as hdul:
            assert hdul[0].header.get("OBJECT") == "TestGalaxy"

    def test_denied_principal_cannot_decrypt(
        self, handler, sample_fits_path, aes_key, aes_iv, tmp_path
    ):
        out = str(tmp_path / "enc.fits")
        handler.encrypt_fits_to_file(sample_fits_path, out, aes_key, aes_iv)

        secured = FitsEncryptionHandler(policy_engine=PolicyEngine())  # no rules
        with pytest.raises(PermissionError):
            secured.decrypt_fits(out, aes_key, principal="user:eve")

    def test_no_policy_engine_permits_all(
        self, handler, sample_fits_path, aes_key, aes_iv, tmp_path
    ):
        """Without a policy engine, all operations are permitted."""
        out = str(tmp_path / "enc.fits")
        handler.encrypt_fits_to_file(sample_fits_path, out, aes_key, aes_iv)
        with handler.decrypt_fits(out, aes_key) as hdul:
            assert hdul is not None
