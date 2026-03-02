"""
tests/test_encrypt.py — Unit tests for AES-256-GCM encryption.
"""
import base64

import pytest

from app.middlewares.encrypt import Encryptor, mask_account_number


VALID_KEY = b"exactly-32-bytes-for-aes-256-key"  # exactly 32 bytes


# ── Encryptor tests ───────────────────────────────────────────────────────────

def test_encrypt_returns_base64_string():
    enc = Encryptor(VALID_KEY)
    result = enc.encrypt("1234567890")
    # Should be valid base64
    assert base64.b64decode(result)


def test_encrypt_decrypt_roundtrip():
    enc = Encryptor(VALID_KEY)
    original = "9876543210"
    ciphertext = enc.encrypt(original)
    assert enc.decrypt(ciphertext) == original


def test_same_plaintext_different_ciphertext():
    """Same plaintext should produce different ciphertext each call (random nonce)."""
    enc = Encryptor(VALID_KEY)
    c1 = enc.encrypt("1234567890")
    c2 = enc.encrypt("1234567890")
    assert c1 != c2  # Different nonces → different ciphertext


def test_tampered_ciphertext_raises_error():
    """Modified ciphertext should fail decryption (GCM auth tag mismatch)."""
    enc = Encryptor(VALID_KEY)
    ciphertext = enc.encrypt("1234567890")
    # Flip a byte in the middle of the ciphertext
    data = bytearray(base64.b64decode(ciphertext))
    data[15] ^= 0xFF  # Flip all bits in byte 15
    tampered = base64.b64encode(bytes(data)).decode()

    with pytest.raises(ValueError, match="Decryption failed"):
        enc.decrypt(tampered)


def test_wrong_key_raises_error():
    """Decryption with wrong key should fail."""
    enc1 = Encryptor(VALID_KEY)
    enc2 = Encryptor(b"different-32-byte-key-for-test!!")

    ciphertext = enc1.encrypt("secret-account")

    with pytest.raises(ValueError):
        enc2.decrypt(ciphertext)


def test_invalid_key_length_raises():
    with pytest.raises(ValueError, match="32 bytes"):
        Encryptor(b"too-short")


def test_encrypt_empty_string_raises():
    enc = Encryptor(VALID_KEY)
    with pytest.raises(ValueError, match="empty"):
        enc.encrypt("")


# ── Mask account number tests ─────────────────────────────────────────────────

def test_mask_normal_account():
    assert mask_account_number("1234567890") == "******7890"


def test_mask_short_account():
    assert mask_account_number("1234") == "****"


def test_mask_very_short_account():
    assert mask_account_number("12") == "****"
