"""
app/middlewares/encrypt.py — AES-256-GCM encryption for sensitive fields.

Why AES-GCM?
GCM (Galois/Counter Mode) provides AUTHENTICATED encryption.
If anyone tampers with stored ciphertext (even 1 bit), decryption raises
an exception. AES-CBC/CFB have no such protection — you'd silently get
corrupted data. In a finance system storing account numbers, tamper
detection is non-negotiable.
"""
import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from loguru import logger


class Encryptor:
    """
    AES-256-GCM encryptor for sensitive PII (account numbers, etc).

    Usage:
        encryptor = Encryptor(key_bytes)
        ciphertext = encryptor.encrypt("1234567890")
        plaintext  = encryptor.decrypt(ciphertext)
    """

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError(
                f"AES key must be exactly 32 bytes for AES-256, got {len(key)}"
            )
        self._aesgcm = AESGCM(key)

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypts plaintext and returns base64-encoded ciphertext.

        Output format: base64(nonce [12 bytes] + ciphertext + auth_tag [16 bytes])

        A fresh random nonce is generated per encryption call.
        Same plaintext → different ciphertext every time (due to random nonce).
        This is correct — deterministic encryption leaks information.
        """
        if not plaintext:
            raise ValueError("Cannot encrypt empty string")

        # 12-byte nonce is the GCM standard. Never reuse a nonce with the same key.
        nonce = os.urandom(12)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext.encode(), None)

        # Prepend nonce so we can extract it during decryption
        combined = nonce + ciphertext
        return base64.b64encode(combined).decode()

    def decrypt(self, encoded: str) -> str:
        """
        Decrypts base64-encoded ciphertext.
        Raises InvalidTag if the ciphertext has been tampered with.
        """
        if not encoded:
            raise ValueError("Cannot decrypt empty string")

        try:
            data = base64.b64decode(encoded.encode())
            nonce = data[:12]
            ciphertext = data[12:]
            plaintext = self._aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode()
        except Exception as e:
            # Never log the key or plaintext in error messages
            logger.error("Decryption failed — possible data tampering")
            raise ValueError("Decryption failed: data may be tampered or key mismatch") from e


def mask_account_number(account: str) -> str:
    """
    Returns a display-safe masked account number.
    "1234567890" → "******7890"
    """
    if len(account) <= 4:
        return "****"
    return "*" * (len(account) - 4) + account[-4:]
