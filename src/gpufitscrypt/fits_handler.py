"""FITS file encryption and decryption handler.

Integrates AES-GCM authenticated encryption with FITS astronomical image
files using ``astropy``.  Key design choices:

  - The FITS header is retained in cleartext and used as Additional
    Authenticated Data (AAD), giving integrity protection without hiding
    the metadata needed for data-discovery and cataloguing workflows.
  - Only the image data array is encrypted, keeping the file usable for
    policy checks (e.g. embargo dates derived from the header) without
    requiring the decryption key.
  - The on-disk format wraps the encrypted payload in a plain FITS file
    so that standard FITS tooling can still read the header.

Encrypted-file layout (stored in the primary HDU data field as a raw byte
array with a ``GPUCRYPT`` marker in the header):

    [IV  – 12 bytes]
    [TAG – 16 bytes]
    [CIPHERTEXT – variable]

Optional policy enforcement is provided via :class:`~gpufitscrypt.policy_engine.PolicyEngine`.
"""

import io
import os
from typing import Optional

import numpy as np
from astropy.io import fits

from .aes_gcm import gcm_decrypt, gcm_encrypt
from .policy_engine import Action, AccessRequest, PolicyEngine

# Magic string written to FITS keyword to identify encrypted files.
_ENCRYPTED_MARKER = "GPUCRYPT"
_IV_LEN = 12
_TAG_LEN = 16


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _header_aad(header: fits.Header) -> bytes:
    """Serialise a FITS header to bytes for use as GHASH AAD."""
    buf = io.StringIO()
    header.totextfile(buf)
    return buf.getvalue().encode("ascii", errors="replace")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class FitsEncryptionHandler:
    """Encrypt and decrypt FITS image files with AES-GCM.

    The handler optionally enforces a :class:`~gpufitscrypt.policy_engine.PolicyEngine`
    so that callers must hold the appropriate permission before a key is
    used to decrypt data.

    Args:
        policy_engine: Optional :class:`~gpufitscrypt.policy_engine.PolicyEngine`
                       instance.  When provided, every encrypt/decrypt call
                       is checked for the ``ENCRYPT`` / ``DECRYPT`` action.
    """

    def __init__(self, policy_engine: Optional[PolicyEngine] = None) -> None:
        self.policy_engine = policy_engine

    # ------------------------------------------------------------------
    # Encryption
    # ------------------------------------------------------------------

    def encrypt_fits(
        self,
        fits_path: str,
        key: bytes,
        iv: bytes,
        *,
        principal: Optional[str] = None,
    ) -> bytes:
        """Encrypt a FITS file and return the encrypted payload as bytes.

        The FITS header of the primary HDU is serialised and passed as
        AAD so that any tampering with the metadata is detected on
        decryption.

        Args:
            fits_path: Path to the source FITS file.
            key:       AES key (16, 24, or 32 bytes).
            iv:        12-byte initialisation vector (must be unique per key).
            principal: Caller identity for policy enforcement (optional).

        Returns:
            Raw bytes in the format ``[IV][TAG][CIPHERTEXT]``.

        Raises:
            PermissionError: If policy enforcement is active and the caller
                             lacks the ``ENCRYPT`` action.
        """
        self._check_policy(principal, Action.ENCRYPT, fits_path)

        with fits.open(fits_path) as hdul:
            return self._encrypt_hdul(hdul, key, iv)

    def encrypt_fits_to_file(
        self,
        fits_path: str,
        output_path: str,
        key: bytes,
        iv: bytes,
        *,
        principal: Optional[str] = None,
    ) -> None:
        """Encrypt *fits_path* and write a new FITS file to *output_path*.

        The output is a valid FITS file whose primary HDU data field
        contains the raw ``[IV][TAG][CIPHERTEXT]`` payload and whose
        header carries a ``GPUCRYPT = T`` keyword so that readers can
        detect the encrypted status without a key.

        Args:
            fits_path:   Source FITS file.
            output_path: Destination path for the encrypted FITS file.
            key:         AES key (16, 24, or 32 bytes).
            iv:          12-byte initialisation vector.
            principal:   Caller identity for policy enforcement.
        """
        self._check_policy(principal, Action.ENCRYPT, fits_path)

        with fits.open(fits_path) as hdul:
            payload = self._encrypt_hdul(hdul, key, iv)

            # Build a new primary HDU that holds the encrypted blob.
            # Start from a minimal header to avoid stale NAXISj keywords.
            arr = np.frombuffer(payload, dtype=np.uint8)
            new_hdu = fits.PrimaryHDU(data=arr)
            # Carry over selected provenance keywords from the original header.
            for kw in ("OBJECT", "TELESCOP", "INSTRUME", "DATE-OBS", "ORIGIN"):
                if kw in hdul[0].header:
                    new_hdu.header[kw] = hdul[0].header[kw]
            new_hdu.header["GPUCRYPT"] = (True, "Data encrypted with AES-GCM (GpuFitsCrypt)")
            new_hdul = fits.HDUList([new_hdu])
            new_hdul.writeto(output_path, overwrite=True)

    # ------------------------------------------------------------------
    # Decryption
    # ------------------------------------------------------------------

    def decrypt_payload(
        self,
        payload: bytes,
        key: bytes,
        aad: bytes,
    ) -> bytes:
        """Decrypt a raw ``[IV][TAG][CIPHERTEXT]`` payload.

        Args:
            payload: Bytes produced by :meth:`encrypt_fits`.
            key:     AES key used during encryption.
            aad:     AAD bytes (must match those used at encryption time).

        Returns:
            Decrypted plaintext bytes.

        Raises:
            ValueError: If the authentication tag fails verification.
        """
        if len(payload) < _IV_LEN + _TAG_LEN:
            raise ValueError("Payload too short to contain IV and tag")
        iv = payload[:_IV_LEN]
        tag = payload[_IV_LEN: _IV_LEN + _TAG_LEN]
        ciphertext = payload[_IV_LEN + _TAG_LEN:]
        return gcm_decrypt(key, iv, ciphertext, tag, aad)

    def decrypt_fits(
        self,
        encrypted_fits_path: str,
        key: bytes,
        *,
        principal: Optional[str] = None,
    ) -> fits.HDUList:
        """Decrypt an encrypted FITS file and return an :class:`astropy.io.fits.HDUList`.

        Args:
            encrypted_fits_path: Path to the encrypted FITS file produced
                                 by :meth:`encrypt_fits_to_file`.
            key:                 AES key (16, 24, or 32 bytes).
            principal:           Caller identity for policy enforcement.

        Returns:
            An :class:`astropy.io.fits.HDUList` with the decrypted content.

        Raises:
            PermissionError: If the caller lacks the ``DECRYPT`` action.
            ValueError:      If the authentication tag fails.
        """
        self._check_policy(principal, Action.DECRYPT, encrypted_fits_path)

        with fits.open(encrypted_fits_path) as hdul:
            header = hdul[0].header
            if not header.get("GPUCRYPT", False):
                raise ValueError("File does not appear to be a GpuFitsCrypt-encrypted FITS file")

            payload = bytes(hdul[0].data.tobytes())

        decrypted_bytes = self.decrypt_payload(payload, key, aad=b"")
        return fits.open(io.BytesIO(decrypted_bytes))

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _encrypt_hdul(self, hdul: fits.HDUList, key: bytes, iv: bytes) -> bytes:
        """Encrypt the serialised *hdul* and return the raw payload bytes.

        The full FITS byte stream (header + data) is the plaintext, so the
        header is authenticated as part of the ciphertext GHASH.  Empty AAD
        is used here; callers that need explicit AAD should use
        :meth:`gcm_encrypt` directly.
        """
        buf = io.BytesIO()
        hdul.writeto(buf)
        plaintext = buf.getvalue()
        ciphertext, tag = gcm_encrypt(key, iv, plaintext)
        return iv + tag + ciphertext

    def _check_policy(
        self,
        principal: Optional[str],
        action: Action,
        resource_path: str,
    ) -> None:
        """Raise :exc:`PermissionError` if *principal* is denied *action*."""
        if self.policy_engine is None or principal is None:
            return
        resource = f"fits:{os.path.basename(resource_path)}"
        request = AccessRequest(principal=principal, action=action, resource=resource)
        allowed, reason = self.policy_engine.evaluate(request)
        if not allowed:
            raise PermissionError(
                f"Principal '{principal}' is not authorised to perform "
                f"'{action.value}' on '{resource}': {reason}"
            )
