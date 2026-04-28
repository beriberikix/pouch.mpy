# SPDX-License-Identifier: Apache-2.0
"""Unit tests for pouch.header."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pouch.header import encode_header, encode_header_saead, decode_header
from pouch.const import (
    POUCH_VERSION,
    ENCRYPTION_NONE,
    ENCRYPTION_SAEAD,
    SAEAD_ALG_AES_GCM,
    SAEAD_ALG_CHACHA20_POLY1305,
    POUCH_ROLE_DEVICE,
    POUCH_ROLE_SERVER,
)
from pouch import cbor


def test_encode_returns_bytes():
    result = encode_header("device-123")
    assert isinstance(result, bytes)
    assert len(result) > 0


def test_encode_cbor_structure():
    """Encoded header should be a CBOR array: [version, [enc_type, device_id]]."""
    raw = encode_header("dev01")
    header, _ = cbor.decode(raw)
    assert isinstance(header, list)
    assert len(header) == 2
    assert header[0] == POUCH_VERSION
    enc_info = header[1]
    assert isinstance(enc_info, list)
    assert enc_info[0] == ENCRYPTION_NONE
    assert enc_info[1] == "dev01"


def test_decode_roundtrip():
    device_id = "my-device-42"
    raw = encode_header(device_id)
    decoded_id, enc_type, consumed = decode_header(raw)
    assert decoded_id == device_id
    assert enc_type == ENCRYPTION_NONE
    assert consumed == len(raw)


def test_decode_at_offset():
    """decode_header should respect a non-zero byte offset."""
    device_id = "dev"
    raw = b"\x00\x00\x00" + encode_header(device_id)
    decoded_id, _, consumed = decode_header(raw, offset=3)
    assert decoded_id == device_id
    # consumed reflects only the header bytes, not the leading garbage
    assert consumed == len(raw) - 3


def test_decode_wrong_version():
    # Manually encode a header with version=99
    raw = cbor.encode([99, [ENCRYPTION_NONE, "dev"]])
    try:
        decode_header(raw)
        assert False, "Should have raised"
    except ValueError as exc:
        assert "version" in str(exc).lower()


def test_decode_unsupported_encryption():
    raw = cbor.encode([POUCH_VERSION, [99, "fake-session-info"]])
    try:
        decode_header(raw)
        assert False, "Should have raised"
    except ValueError as exc:
        assert "encryption" in str(exc).lower()


def test_decode_malformed_not_array():
    raw = cbor.encode(42)
    try:
        decode_header(raw)
        assert False, "Should have raised"
    except ValueError:
        pass


def test_different_device_ids():
    for did in ["a", "abc123", "dev-" + "x" * 28]:
        raw = encode_header(did)
        decoded_id, _, _ = decode_header(raw)
        assert decoded_id == did


# ---- SAEAD header tests ----

def test_saead_encode_returns_bytes():
    session_id = b"\x01" * 16
    cert_ref = b"\xaa" * 6
    result = encode_header_saead(session_id, POUCH_ROLE_DEVICE,
                                 SAEAD_ALG_AES_GCM, 9, cert_ref, 0)
    assert isinstance(result, bytes)
    assert len(result) > 0


def test_saead_encode_cbor_structure():
    session_id = b"\x42" * 16
    cert_ref = b"\xff" * 6
    raw = encode_header_saead(session_id, POUCH_ROLE_DEVICE,
                              SAEAD_ALG_CHACHA20_POLY1305, 9, cert_ref, 5)
    header, _ = cbor.decode(raw)
    assert isinstance(header, list)
    assert header[0] == POUCH_VERSION
    enc_info = header[1]
    assert enc_info[0] == ENCRYPTION_SAEAD
    session_info = enc_info[1]
    pouch_id = enc_info[2]
    assert pouch_id == 5
    assert isinstance(session_info, list)
    assert len(session_info) == 5
    assert session_info[0] == [session_id]
    assert session_info[1] == POUCH_ROLE_DEVICE
    assert session_info[2] == SAEAD_ALG_CHACHA20_POLY1305
    assert session_info[3] == 9
    assert session_info[4] == cert_ref


def test_saead_decode_roundtrip():
    session_id = b"\x01\x02\x03\x04\x05\x06\x07\x08" * 2
    cert_ref = b"\xab\xcd\xef\x01\x02\x03"
    raw = encode_header_saead(session_id, POUCH_ROLE_SERVER,
                              SAEAD_ALG_AES_GCM, 10, cert_ref, 42)
    info, enc_type, consumed = decode_header(raw)
    assert enc_type == ENCRYPTION_SAEAD
    assert consumed == len(raw)
    assert info["session_id"] == session_id
    assert info["initiator"] == POUCH_ROLE_SERVER
    assert info["algorithm"] == SAEAD_ALG_AES_GCM
    assert info["max_block_size_log"] == 10
    assert info["cert_ref"] == cert_ref
    assert info["pouch_id"] == 42


def test_saead_decode_at_offset():
    session_id = b"\x00" * 16
    cert_ref = b"\x00" * 6
    raw = b"\xde\xad" + encode_header_saead(
        session_id, POUCH_ROLE_DEVICE, SAEAD_ALG_AES_GCM, 9, cert_ref, 0)
    info, enc_type, consumed = decode_header(raw, offset=2)
    assert enc_type == ENCRYPTION_SAEAD
    assert consumed == len(raw) - 2
    assert info["session_id"] == session_id


def test_saead_malformed_session_info():
    # encryption_type 1 but only 2 elements (missing pouch_id)
    raw = cbor.encode([POUCH_VERSION, [ENCRYPTION_SAEAD, [[b"\x00" * 16], 0, 0, 9, b"\x00" * 6]]])
    try:
        decode_header(raw)
        assert False, "Should have raised"
    except ValueError as exc:
        assert "session_info" in str(exc).lower() or "pouch_id" in str(exc).lower()


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
