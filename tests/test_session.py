# SPDX-License-Identifier: Apache-2.0
"""Unit tests for pouch.crypto.session (with mocked native module)."""

import sys
import os
import struct

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# The pouch_crypto mock is installed by conftest.py

from pouch.crypto.session import (
    generate_session_id,
    build_key_info,
    derive_session_key,
    build_nonce,
    Session,
)
from pouch.const import (
    SAEAD_ALG_AES_GCM,
    SAEAD_ALG_CHACHA20_POLY1305,
    POUCH_ROLE_DEVICE,
    POUCH_ROLE_SERVER,
    SESSION_ID_LEN,
    NONCE_LEN,
    AUTH_TAG_LEN,
)


# ---- generate_session_id ----

def test_generate_session_id_length():
    sid = generate_session_id()
    assert len(sid) == SESSION_ID_LEN


def test_generate_session_id_returns_bytes():
    sid = generate_session_id()
    assert isinstance(sid, bytes)


# ---- build_nonce ----

def test_nonce_length():
    nonce = build_nonce(1, 0, POUCH_ROLE_DEVICE)
    assert len(nonce) == NONCE_LEN


def test_nonce_structure():
    nonce = build_nonce(0x0102, 0x0304, POUCH_ROLE_DEVICE)
    assert nonce[:2] == b"\x01\x02"  # pouch_id big-endian
    assert nonce[2:4] == b"\x03\x04"  # block_index big-endian
    assert nonce[4] == POUCH_ROLE_DEVICE  # sender role
    assert nonce[5:] == b"\x00" * 7  # padding


def test_nonce_different_roles():
    n_dev = build_nonce(0, 0, POUCH_ROLE_DEVICE)
    n_srv = build_nonce(0, 0, POUCH_ROLE_SERVER)
    assert n_dev != n_srv
    assert n_dev[4] == POUCH_ROLE_DEVICE
    assert n_srv[4] == POUCH_ROLE_SERVER


# ---- build_key_info ----

def test_key_info_format():
    sid = b"\x00" * 16
    info = build_key_info(POUCH_ROLE_DEVICE, sid, SAEAD_ALG_AES_GCM, True, 9)
    assert info.startswith(b"E0:D:")
    assert b":CAGR:" in info
    assert info.endswith(b":09")


def test_key_info_chacha():
    sid = b"\x01" * 16
    info = build_key_info(POUCH_ROLE_SERVER, sid, SAEAD_ALG_CHACHA20_POLY1305,
                          True, 10)
    assert info.startswith(b"E0:S:")
    assert b":CCCR:" in info
    assert info.endswith(b":0a")


def test_key_info_sequential_id():
    sid = b"\x00" * 16
    info = build_key_info(POUCH_ROLE_DEVICE, sid, SAEAD_ALG_AES_GCM, False, 9)
    assert b":CAGS:" in info


# ---- derive_session_key ----

def test_derive_key_aes_gcm_length():
    priv = bytes(32)
    pub = b"\x04" + bytes(64)
    sid = bytes(16)
    key = derive_session_key(priv, pub, sid, POUCH_ROLE_DEVICE,
                             SAEAD_ALG_AES_GCM)
    assert len(key) == 16  # AES-128-GCM


def test_derive_key_chacha_length():
    priv = bytes(32)
    pub = b"\x04" + bytes(64)
    sid = bytes(16)
    key = derive_session_key(priv, pub, sid, POUCH_ROLE_DEVICE,
                             SAEAD_ALG_CHACHA20_POLY1305)
    assert len(key) == 32  # ChaCha20-Poly1305


# ---- Session encrypt/decrypt ----

def test_session_encrypt_adds_tag():
    key = bytes(16)
    session = Session(key, SAEAD_ALG_AES_GCM, POUCH_ROLE_DEVICE)
    pt = b"hello world"
    ct = session.encrypt_block(0, pt)
    assert len(ct) == len(pt) + AUTH_TAG_LEN


def test_session_encrypt_decrypt_roundtrip():
    key = bytes(16)
    pt = b"test payload data"

    # Encrypt as device
    enc_session = Session(key, SAEAD_ALG_AES_GCM, POUCH_ROLE_DEVICE)
    ct = enc_session.encrypt_block(0, pt)

    # Decrypt as server
    dec_session = Session(key, SAEAD_ALG_AES_GCM, POUCH_ROLE_SERVER)
    result = dec_session.decrypt_block(0, POUCH_ROLE_DEVICE, ct)
    assert result == pt


def test_session_ad_chaining():
    """Multiple blocks should chain auth tags as additional data."""
    key = bytes(16)
    blocks = [b"block0", b"block1", b"block2"]

    enc_session = Session(key, SAEAD_ALG_AES_GCM, POUCH_ROLE_DEVICE)
    ciphertexts = []
    for pt in blocks:
        ciphertexts.append(enc_session.encrypt_block(0, pt))

    dec_session = Session(key, SAEAD_ALG_AES_GCM, POUCH_ROLE_SERVER)
    for i, ct in enumerate(ciphertexts):
        result = dec_session.decrypt_block(0, POUCH_ROLE_DEVICE, ct)
        assert result == blocks[i]


def test_session_decrypt_auth_failure():
    key = bytes(16)
    pt = b"sensitive data"
    enc_session = Session(key, SAEAD_ALG_AES_GCM, POUCH_ROLE_DEVICE)
    ct = enc_session.encrypt_block(0, pt)

    # Tamper with the ciphertext
    tampered = bytearray(ct)
    tampered[0] ^= 0xFF
    tampered = bytes(tampered)

    dec_session = Session(key, SAEAD_ALG_AES_GCM, POUCH_ROLE_SERVER)
    try:
        dec_session.decrypt_block(0, POUCH_ROLE_DEVICE, tampered)
        assert False, "Should have raised ValueError"
    except ValueError:
        pass


def test_session_reset_block_state():
    key = bytes(16)
    session = Session(key, SAEAD_ALG_AES_GCM, POUCH_ROLE_DEVICE)
    session.encrypt_block(0, b"data")
    assert session._block_index == 1
    assert session._prev_tag != b""

    session.reset_block_state()
    assert session._block_index == 0
    assert session._prev_tag == b""


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
