# SPDX-License-Identifier: Apache-2.0
"""Unit tests for pouch.block."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pouch.block import (
    Block,
    encode_entry,
    decode_entries,
    encode_stream_first,
    decode_stream_first,
)
from pouch.const import BLOCK_ID_ENTRY, CONTENT_TYPE_JSON, CONTENT_TYPE_CBOR, CONTENT_TYPE_OCTET_STREAM


# ---------------------------------------------------------------------------
# Block encode / decode
# ---------------------------------------------------------------------------

def test_block_encode_empty_entry():
    """An empty entry block should have a 3-byte header (size=1, id=0|FIRST|LAST)."""
    b = Block()
    raw = b.encode()
    # size field = 1 (id byte only), id byte = 0x00 | 0x40 | 0x80 = 0xC0
    assert len(raw) == 3
    assert raw[0] == 0x00
    assert raw[1] == 0x01
    assert raw[2] == 0xC0


def test_block_encode_with_payload():
    payload = b"\x01\x02\x03"
    b = Block()
    b.write(payload)
    raw = b.encode()
    # size = 1 (id) + 3 (payload) = 4
    assert raw[0] == 0x00
    assert raw[1] == 0x04
    assert raw[2] == 0xC0  # FIRST | LAST, stream_id=0
    assert raw[3:] == payload


def test_block_decode_entry():
    payload = b"\xAB\xCD"
    b = Block()
    b.write(payload)
    raw = b.encode()

    decoded, consumed = Block.decode(raw)
    assert consumed == len(raw)
    assert not decoded.is_stream
    assert decoded.is_first
    assert decoded.is_last
    assert decoded.payload == payload


def test_block_decode_stream_first():
    b = Block(stream_id=1, is_first=True, is_last=False)
    b.write(b"\xFF")
    raw = b.encode()

    decoded, consumed = Block.decode(raw)
    assert consumed == len(raw)
    assert decoded.is_stream
    assert decoded.stream_id == 1
    assert decoded.is_first
    assert not decoded.is_last
    assert decoded.payload == b"\xFF"


def test_block_decode_stream_last():
    b = Block(stream_id=2, is_first=False, is_last=True)
    b.write(b"\x00\x01")
    raw = b.encode()

    decoded, consumed = Block.decode(raw)
    assert decoded.stream_id == 2
    assert not decoded.is_first
    assert decoded.is_last


def test_block_decode_incomplete_header():
    """Too-short data should return (None, 0)."""
    block, consumed = Block.decode(b"\x00")
    assert block is None
    assert consumed == 0


def test_block_decode_incomplete_payload():
    """Data truncated mid-payload should return (None, 0)."""
    # Claim size=10 but only provide 5 bytes
    raw = b"\x00\x0A\xC0" + b"\x00" * 3  # 6 bytes total, need 12
    block, consumed = Block.decode(raw)
    assert block is None
    assert consumed == 0


def test_block_decode_offset():
    """decode() should honour a non-zero offset."""
    b = Block()
    b.write(b"\xBE\xEF")
    raw = b"\x00\x00" + b.encode()  # 2 bytes of garbage before the block
    decoded, consumed = Block.decode(raw, offset=2)
    assert consumed == 5  # 3 header + 2 payload
    assert decoded.payload == b"\xBE\xEF"


def test_multiple_blocks_sequential():
    """Multiple blocks can be decoded sequentially from a buffer."""
    b1 = Block()
    b1.write(b"\x01")
    b2 = Block()
    b2.write(b"\x02\x03")
    raw = b1.encode() + b2.encode()

    d1, c1 = Block.decode(raw, 0)
    d2, c2 = Block.decode(raw, c1)
    assert d1.payload == b"\x01"
    assert d2.payload == b"\x02\x03"
    assert c1 + c2 == len(raw)


# ---------------------------------------------------------------------------
# Entry encode / decode
# ---------------------------------------------------------------------------

def test_encode_entry_bytes_path():
    raw = encode_entry(b"path", CONTENT_TYPE_JSON, b"data")
    # data_len=4, content_type=50, path_len=4
    assert raw[:5] == bytes([0x00, 0x04, 0x00, 0x32, 0x04])
    assert raw[5:9] == b"path"
    assert raw[9:] == b"data"


def test_encode_entry_str_path():
    raw = encode_entry("p", CONTENT_TYPE_OCTET_STREAM, b"\x00")
    # data_len=1, content_type=42=0x2A, path_len=1
    import struct
    data_len, ct, path_len = struct.unpack_from(">HHB", raw, 0)
    assert data_len == 1
    assert ct == CONTENT_TYPE_OCTET_STREAM
    assert path_len == 1
    assert raw[5:6] == b"p"
    assert raw[6:] == b"\x00"


def test_encode_entry_str_data():
    raw = encode_entry("key", CONTENT_TYPE_JSON, '{"x":1}')
    import struct
    data_len, _, _ = struct.unpack_from(">HHB", raw, 0)
    assert data_len == 7  # len('{"x":1}')


def test_decode_entries_single():
    payload = encode_entry(".s/temp", CONTENT_TYPE_JSON, b'{"t":20}')
    entries = list(decode_entries(payload))
    assert len(entries) == 1
    path, ct, data = entries[0]
    assert path == ".s/temp"
    assert ct == CONTENT_TYPE_JSON
    assert data == b'{"t":20}'


def test_decode_entries_multiple():
    payload = (
        encode_entry("a", CONTENT_TYPE_JSON, b"1")
        + encode_entry("b", CONTENT_TYPE_CBOR, b"2")
    )
    entries = list(decode_entries(payload))
    assert len(entries) == 2
    assert entries[0][0] == "a"
    assert entries[1][0] == "b"


def test_decode_entries_empty_data():
    payload = encode_entry("x", CONTENT_TYPE_OCTET_STREAM, b"")
    entries = list(decode_entries(payload))
    assert len(entries) == 1
    assert entries[0][2] == b""


# ---------------------------------------------------------------------------
# Stream first-block encode / decode
# ---------------------------------------------------------------------------

def test_stream_first_roundtrip():
    raw = encode_stream_first(".s/log", CONTENT_TYPE_JSON, b"hello")
    path, ct, data = decode_stream_first(raw)
    assert path == ".s/log"
    assert ct == CONTENT_TYPE_JSON
    assert data == b"hello"


def test_stream_first_empty_data():
    raw = encode_stream_first("path", CONTENT_TYPE_OCTET_STREAM)
    path, ct, data = decode_stream_first(raw)
    assert path == "path"
    assert data == b""


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print("PASS", t.__name__)
            passed += 1
        except Exception as exc:
            import traceback
            print("FAIL", t.__name__, "–", exc)
            traceback.print_exc()
            failed += 1
    print("\n{} passed, {} failed".format(passed, failed))
    if failed:
        sys.exit(1)
