# SPDX-License-Identifier: Apache-2.0
"""Shared test fixtures — mock the pouch_crypto native module."""

import sys
import types
import hashlib

# Create a mock pouch_crypto module with functional implementations
# so that pouch.crypto can be imported in tests without the native .mpy.
_mock = types.ModuleType("pouch_crypto")


def _mock_ecdh_p256(private_key, peer_pubkey):
    """Deterministic fake ECDH shared secret."""
    return hashlib.sha256(private_key + peer_pubkey).digest()


def _mock_hkdf_sha256(ikm, salt, info, out_len):
    """Deterministic fake HKDF."""
    h = hashlib.sha256(ikm + salt + info)
    d = h.digest()
    result = d * ((out_len // len(d)) + 1)
    return result[:out_len]


def _mock_aead_encrypt(alg, key, nonce, aad, plaintext):
    """Fake AEAD: XOR with key[0], append 16-byte HMAC-like tag."""
    k = key[0] if key else 0
    ct = bytes(b ^ k for b in plaintext)
    tag = hashlib.sha256(nonce + aad + ct).digest()[:16]
    return ct + tag


def _mock_aead_decrypt(alg, key, nonce, aad, ct_with_tag):
    """Fake AEAD: verify tag, then reverse XOR."""
    ct = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]
    expected_tag = hashlib.sha256(nonce + aad + ct).digest()[:16]
    if tag != expected_tag:
        raise ValueError("authentication failed")
    k = key[0] if key else 0
    return bytes(b ^ k for b in ct)


def _mock_random_bytes(n):
    """Deterministic 'random' bytes for testing."""
    return bytes(range(n)) if n <= 256 else bytes(n)


_mock.ecdh_p256 = _mock_ecdh_p256
_mock.hkdf_sha256 = _mock_hkdf_sha256
_mock.aead_encrypt = _mock_aead_encrypt
_mock.aead_decrypt = _mock_aead_decrypt
_mock.random_bytes = _mock_random_bytes

# Install before any test module can trigger pouch.crypto import
sys.modules["pouch_crypto"] = _mock
