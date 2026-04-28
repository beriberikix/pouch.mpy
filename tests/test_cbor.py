# SPDX-License-Identifier: Apache-2.0
"""Unit tests for pouch.cbor."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pouch.cbor import encode, decode


def test_uint_small():
    assert encode(0) == b"\x00"
    assert encode(1) == b"\x01"
    assert encode(23) == b"\x17"


def test_uint_one_byte():
    assert encode(24) == b"\x18\x18"
    assert encode(255) == b"\x18\xff"


def test_uint_two_bytes():
    assert encode(256) == b"\x19\x01\x00"
    assert encode(65535) == b"\x19\xff\xff"


def test_uint_four_bytes():
    assert encode(65536) == b"\x1a\x00\x01\x00\x00"


def test_nint():
    assert encode(-1) == b"\x20"
    assert encode(-24) == b"\x37"
    assert encode(-25) == b"\x38\x18"


def test_bstr_empty():
    assert encode(b"") == b"\x40"


def test_bstr():
    assert encode(b"\x01\x02\x03") == b"\x43\x01\x02\x03"


def test_tstr_empty():
    assert encode("") == b"\x60"


def test_tstr():
    encoded = encode("abc")
    assert encoded == b"\x63abc"


def test_array_empty():
    assert encode([]) == b"\x80"


def test_array():
    assert encode([1, 2, 3]) == b"\x83\x01\x02\x03"


def test_nested_array():
    encoded = encode([1, [2, 3]])
    assert encoded == b"\x82\x01\x82\x02\x03"


def test_map():
    # Map with one entry
    encoded = encode({"a": 1})
    assert encoded == b"\xa1\x61\x61\x01"


def test_bool_false():
    assert encode(False) == b"\xf4"


def test_bool_true():
    assert encode(True) == b"\xf5"


def test_decode_uint():
    assert decode(b"\x00") == (0, 1)
    assert decode(b"\x17") == (23, 1)
    assert decode(b"\x18\x18") == (24, 2)
    assert decode(b"\x19\x01\x00") == (256, 3)


def test_decode_nint():
    assert decode(b"\x20") == (-1, 1)
    assert decode(b"\x38\x18") == (-25, 2)


def test_decode_bstr():
    assert decode(b"\x43\x01\x02\x03") == (b"\x01\x02\x03", 4)


def test_decode_tstr():
    assert decode(b"\x63abc") == ("abc", 4)


def test_decode_array():
    assert decode(b"\x83\x01\x02\x03") == ([1, 2, 3], 4)


def test_decode_nested():
    assert decode(b"\x82\x01\x82\x02\x03") == ([1, [2, 3]], 5)


def test_decode_map():
    obj, n = decode(b"\xa1\x61\x61\x01")
    assert obj == {"a": 1}
    assert n == 4


def test_roundtrip_header_like():
    """Roundtrip test for a structure similar to the Pouch header."""
    original = [1, [0, "my-device-01"]]
    encoded = encode(original)
    decoded, _ = decode(encoded)
    assert decoded == original


def test_roundtrip_info_like():
    """Roundtrip test for the Pouch GATT info map."""
    original = {"flags": 0, "server_cert_snr": b""}
    encoded = encode(original)
    decoded, _ = decode(encoded)
    assert decoded == original


def test_bytearray_input():
    """bytearray input should be treated the same as bytes."""
    assert encode(bytearray(b"\xde\xad")) == b"\x42\xde\xad"


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
