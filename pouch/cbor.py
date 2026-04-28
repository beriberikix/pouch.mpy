# SPDX-License-Identifier: Apache-2.0
"""Minimal CBOR encoder/decoder for MicroPython.

Only the subset of CBOR required by the Pouch protocol is implemented:
  Major types 0-5 (uint, nint, bstr, tstr, array, map) plus IEEE 754
  floating-point (major type 7, additional info 25/26/27).

Indefinite-length items are not supported.
"""

import struct


# ---------------------------------------------------------------------------
# Float16 helpers (IEEE 754 half-precision)
# ---------------------------------------------------------------------------

def _decode_float16(bits):
    """Decode a 16-bit IEEE 754 half-precision integer bit-pattern to float."""
    sign = (bits >> 15) & 1
    exp = (bits >> 10) & 0x1F
    frac = bits & 0x3FF
    if exp == 0:
        val = frac / 1024.0 * (2.0 ** -14)
    elif exp == 31:
        val = float("inf") if frac == 0 else float("nan")
    else:
        val = (1.0 + frac / 1024.0) * (2.0 ** (exp - 15))
    return -val if sign else val


# ---------------------------------------------------------------------------
# Encoder
# ---------------------------------------------------------------------------

def _encode_head(major, value):
    """Encode a CBOR type/value head byte(s)."""
    tag = major << 5
    if value <= 23:
        return bytes([tag | value])
    if value <= 0xFF:
        return bytes([tag | 24, value])
    if value <= 0xFFFF:
        return bytes([tag | 25]) + struct.pack(">H", value)
    if value <= 0xFFFFFFFF:
        return bytes([tag | 26]) + struct.pack(">I", value)
    return bytes([tag | 27]) + struct.pack(">Q", value)


def encode(obj):
    """Encode *obj* to CBOR bytes.

    Supports: bool, int (positive and negative), float, bytes/bytearray, str,
    list, dict.
    """
    if isinstance(obj, bool):
        # booleans must be checked before int (bool is a subclass of int)
        return bytes([0xF5]) if obj else bytes([0xF4])
    if obj is None:
        return bytes([0xF6])
    if isinstance(obj, float):
        # Encode as IEEE 754 double (64-bit); additional info 27 = 0xFB
        return bytes([0xFB]) + struct.pack(">d", obj)
    if isinstance(obj, int):
        if obj >= 0:
            return _encode_head(0, obj)
        return _encode_head(1, -1 - obj)
    if isinstance(obj, (bytes, bytearray)):
        return _encode_head(2, len(obj)) + bytes(obj)
    if isinstance(obj, str):
        enc = obj.encode("utf-8")
        return _encode_head(3, len(enc)) + enc
    if isinstance(obj, list):
        result = _encode_head(4, len(obj))
        for item in obj:
            result += encode(item)
        return result
    if isinstance(obj, dict):
        result = _encode_head(5, len(obj))
        for k, v in obj.items():
            result += encode(k) + encode(v)
        return result
    raise TypeError("cbor.encode: unsupported type {!r}".format(type(obj)))


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------

def _decode_head(data, offset):
    """Decode the CBOR type-head at *offset*.

    Returns ``(major, value, new_offset)``.

    For major type 7 with additional info 25/26/27, *value* is already the
    decoded Python ``float`` (not raw integer bits).
    """
    b = data[offset]
    major = b >> 5
    info = b & 0x1F
    offset += 1

    if info <= 23:
        return major, info, offset
    if info == 24:
        return major, data[offset], offset + 1
    if info == 25:
        if major == 7:
            (raw,) = struct.unpack_from(">H", data, offset)
            return major, _decode_float16(raw), offset + 2
        (v,) = struct.unpack_from(">H", data, offset)
        return major, v, offset + 2
    if info == 26:
        if major == 7:
            (v,) = struct.unpack_from(">f", data, offset)
            return major, v, offset + 4
        (v,) = struct.unpack_from(">I", data, offset)
        return major, v, offset + 4
    if info == 27:
        if major == 7:
            (v,) = struct.unpack_from(">d", data, offset)
            return major, v, offset + 8
        (v,) = struct.unpack_from(">Q", data, offset)
        return major, v, offset + 8
    raise ValueError("cbor.decode: unsupported additional info {}".format(info))


def decode(data, offset=0):
    """Decode CBOR bytes starting at *offset*.

    Returns ``(object, new_offset)``.
    """
    major, value, offset = _decode_head(data, offset)

    if major == 0:  # unsigned int
        return value, offset
    if major == 1:  # negative int
        return -1 - value, offset
    if major == 2:  # byte string
        end = offset + value
        return bytes(data[offset:end]), end
    if major == 3:  # text string
        end = offset + value
        return data[offset:end].decode("utf-8"), end
    if major == 4:  # array
        result = []
        for _ in range(value):
            item, offset = decode(data, offset)
            result.append(item)
        return result, offset
    if major == 5:  # map
        result = {}
        for _ in range(value):
            k, offset = decode(data, offset)
            v, offset = decode(data, offset)
            result[k] = v
        return result, offset
    if major == 7:  # simple values / floats
        if isinstance(value, float):
            return value, offset
        if value == 20:
            return False, offset
        if value == 21:
            return True, offset
        if value == 22:
            return None, offset
    raise ValueError("cbor.decode: unsupported major type {}".format(major))
