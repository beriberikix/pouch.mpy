# SPDX-License-Identifier: Apache-2.0
"""Test vectors for the pouch_crypto native module.

These tests verify the native module's cryptographic functions against
standard test vectors from RFC 5869 (HKDF), NIST SP 800-38D (AES-GCM),
and RFC 7539 (ChaCha20-Poly1305).

When the native module is not built (development/CI), these tests run
against the mock from conftest.py and verify only the API contract.
When the real native module is available, the test vectors validate
correctness of the crypto implementations.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# conftest.py installs the mock if pouch_crypto is not available
import pouch_crypto

from pouch.const import SAEAD_ALG_AES_GCM, SAEAD_ALG_CHACHA20_POLY1305

# Detect whether we're running the real native module or the test mock.
# The conftest.py mock is a types.ModuleType created dynamically.
_USING_MOCK = not hasattr(pouch_crypto, "_is_native")


# ---- RFC 5869 HKDF-SHA256 Test Vectors ----
# These verify the interface; the mock returns deterministic but incorrect
# values, so we only assert lengths when using the mock.

# RFC 5869 Test Case 1
_HKDF_TC1_IKM = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
_HKDF_TC1_SALT = bytes.fromhex("000102030405060708090a0b0c")
_HKDF_TC1_INFO = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
_HKDF_TC1_L = 42
_HKDF_TC1_OKM = bytes.fromhex(
    "3cb25f25faacd57a90434f64d0362f2a"
    "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    "34007208d5b887185865"
)


def test_hkdf_sha256_output_length():
    result = pouch_crypto.hkdf_sha256(
        _HKDF_TC1_IKM, _HKDF_TC1_SALT, _HKDF_TC1_INFO, _HKDF_TC1_L
    )
    assert isinstance(result, bytes)
    assert len(result) == _HKDF_TC1_L


def test_hkdf_sha256_rfc5869_tc1():
    """RFC 5869 Test Case 1 — only passes with real native module."""
    if _USING_MOCK:
        return  # skip: mock produces deterministic but incorrect values
    result = pouch_crypto.hkdf_sha256(
        _HKDF_TC1_IKM, _HKDF_TC1_SALT, _HKDF_TC1_INFO, _HKDF_TC1_L
    )
    assert result == _HKDF_TC1_OKM


def test_hkdf_sha256_empty_salt():
    """HKDF with empty salt should not raise."""
    result = pouch_crypto.hkdf_sha256(b"\x01" * 32, b"", b"info", 16)
    assert len(result) == 16


def test_hkdf_sha256_various_lengths():
    for l in [16, 32, 48, 64]:
        result = pouch_crypto.hkdf_sha256(b"\x0b" * 22, b"", b"", l)
        assert len(result) == l


# ---- NIST SP 800-38D AES-GCM Test Vectors ----
# NIST AES-GCM test case: 128-bit key, 96-bit IV, with AAD

_GCM_KEY = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
_GCM_NONCE = bytes.fromhex("cafebabefacedbaddecaf888")
_GCM_AAD = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
_GCM_PT = bytes.fromhex(
    "d9313225f88406e5a55909c5aff5269a"
    "86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525"
    "b16aedf5aa0de657ba637b39"
)
_GCM_CT = bytes.fromhex(
    "42831ec2217774244b7221b784d0d49c"
    "e3aa212f2c02a4e035c17e2329aca12e"
    "21d514b25466931c7d8f6a5aac84aa05"
    "1ba30b396a0aac973d58e091"
)
_GCM_TAG = bytes.fromhex("5bc94fbc3221a5db94fae95ae7121a47")


def test_aead_encrypt_aes_gcm_output_length():
    ct = pouch_crypto.aead_encrypt(
        SAEAD_ALG_AES_GCM, _GCM_KEY, _GCM_NONCE, _GCM_AAD, _GCM_PT
    )
    assert len(ct) == len(_GCM_PT) + 16  # ciphertext + tag


def test_aead_encrypt_aes_gcm_nist():
    """NIST SP 800-38D test vector — only passes with real native module."""
    if _USING_MOCK:
        return  # skip: mock does not implement real AES-GCM
    ct = pouch_crypto.aead_encrypt(
        SAEAD_ALG_AES_GCM, _GCM_KEY, _GCM_NONCE, _GCM_AAD, _GCM_PT
    )
    assert ct[:len(_GCM_CT)] == _GCM_CT
    assert ct[len(_GCM_CT):] == _GCM_TAG


def test_aead_decrypt_aes_gcm_roundtrip():
    ct = pouch_crypto.aead_encrypt(
        SAEAD_ALG_AES_GCM, _GCM_KEY, _GCM_NONCE, _GCM_AAD, _GCM_PT
    )
    pt = pouch_crypto.aead_decrypt(
        SAEAD_ALG_AES_GCM, _GCM_KEY, _GCM_NONCE, _GCM_AAD, ct
    )
    assert pt == _GCM_PT


def test_aead_decrypt_aes_gcm_tampered():
    ct = pouch_crypto.aead_encrypt(
        SAEAD_ALG_AES_GCM, _GCM_KEY, _GCM_NONCE, _GCM_AAD, _GCM_PT
    )
    tampered = bytearray(ct)
    tampered[-1] ^= 0xFF
    try:
        pouch_crypto.aead_decrypt(
            SAEAD_ALG_AES_GCM, _GCM_KEY, _GCM_NONCE, _GCM_AAD, bytes(tampered)
        )
        assert False, "Should have raised ValueError"
    except ValueError:
        pass


# ---- RFC 7539 ChaCha20-Poly1305 Test Vectors ----

_CC_KEY = bytes.fromhex(
    "808182838485868788898a8b8c8d8e8f"
    "909192939495969798999a9b9c9d9e9f"
)
_CC_NONCE = bytes.fromhex("070000004041424344454647")
_CC_AAD = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
_CC_PT = (
    b"Ladies and Gentlemen of the class of '99: "
    b"If I could offer you only one tip for the future, sunscreen would be it."
)
_CC_CT = bytes.fromhex(
    "d31a8d34648e60db7b86afbc53ef7ec2"
    "a4aded51296e08fea9e2b5a736ee62d6"
    "3dbea45e8ca9671282fafb69da92728b"
    "1a71de0a9e060b2905d6a5b67ecd3b36"
    "92ddbd7f2d778b8c9803aee328091b58"
    "fab324e4fad675945585808b4831d7bc"
    "3ff4def08e4b7a9de576d26586cec64b"
    "6116"
)
_CC_TAG = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")


def test_aead_encrypt_chacha_output_length():
    ct = pouch_crypto.aead_encrypt(
        SAEAD_ALG_CHACHA20_POLY1305, _CC_KEY, _CC_NONCE, _CC_AAD, _CC_PT
    )
    assert len(ct) == len(_CC_PT) + 16


def test_aead_encrypt_chacha_rfc7539():
    """RFC 7539 Section 2.8.2 test vector — only passes with real native module."""
    if _USING_MOCK:
        return  # skip: mock does not implement real ChaCha20-Poly1305
    ct = pouch_crypto.aead_encrypt(
        SAEAD_ALG_CHACHA20_POLY1305, _CC_KEY, _CC_NONCE, _CC_AAD, _CC_PT
    )
    assert ct[:len(_CC_CT)] == _CC_CT
    assert ct[len(_CC_CT):] == _CC_TAG


def test_aead_decrypt_chacha_roundtrip():
    ct = pouch_crypto.aead_encrypt(
        SAEAD_ALG_CHACHA20_POLY1305, _CC_KEY, _CC_NONCE, _CC_AAD, _CC_PT
    )
    pt = pouch_crypto.aead_decrypt(
        SAEAD_ALG_CHACHA20_POLY1305, _CC_KEY, _CC_NONCE, _CC_AAD, ct
    )
    assert pt == _CC_PT


def test_aead_decrypt_chacha_tampered():
    ct = pouch_crypto.aead_encrypt(
        SAEAD_ALG_CHACHA20_POLY1305, _CC_KEY, _CC_NONCE, _CC_AAD, _CC_PT
    )
    tampered = bytearray(ct)
    tampered[0] ^= 0xFF
    try:
        pouch_crypto.aead_decrypt(
            SAEAD_ALG_CHACHA20_POLY1305, _CC_KEY, _CC_NONCE, _CC_AAD,
            bytes(tampered)
        )
        assert False, "Should have raised ValueError"
    except ValueError:
        pass


# ---- ECDH P-256 ----

def test_ecdh_p256_output_length():
    priv = bytes(32)
    pub = b"\x04" + bytes(64)
    secret = pouch_crypto.ecdh_p256(priv, pub)
    assert isinstance(secret, bytes)
    assert len(secret) == 32


def test_ecdh_p256_deterministic():
    priv = bytes(range(32))
    pub = b"\x04" + bytes(range(64))
    s1 = pouch_crypto.ecdh_p256(priv, pub)
    s2 = pouch_crypto.ecdh_p256(priv, pub)
    assert s1 == s2


# ---- random_bytes ----

def test_random_bytes_length():
    for n in [1, 16, 32, 64, 128]:
        r = pouch_crypto.random_bytes(n)
        assert isinstance(r, bytes)
        assert len(r) == n


def test_random_bytes_returns_bytes():
    r = pouch_crypto.random_bytes(16)
    assert isinstance(r, bytes)


# ---- AEAD edge cases ----

def test_aead_encrypt_empty_plaintext():
    key = bytes(16)
    nonce = bytes(12)
    ct = pouch_crypto.aead_encrypt(SAEAD_ALG_AES_GCM, key, nonce, b"", b"")
    assert len(ct) == 16  # tag only, no ciphertext


def test_aead_encrypt_empty_aad():
    key = bytes(16)
    nonce = bytes(12)
    ct = pouch_crypto.aead_encrypt(SAEAD_ALG_AES_GCM, key, nonce, b"", b"hello")
    assert len(ct) == 5 + 16  # 5B ciphertext + 16B tag


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print("PASS", t.__name__)
            passed += 1
        except Exception as exc:
            print("FAIL", t.__name__, "–", exc)
            failed += 1
    print("\n{} passed, {} failed".format(passed, failed))
    if failed:
        sys.exit(1)
