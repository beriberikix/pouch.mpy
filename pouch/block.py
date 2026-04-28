# SPDX-License-Identifier: Apache-2.0
"""Pouch block framing and entry/stream payload encoding.

Block wire format (big-endian multibyte fields):

    | offset | size | description                              |
    |--------|------|------------------------------------------|
    |      0 |    2 | block size (bytes after size field)      |
    |      2 |    1 | id byte: stream_id[4:0] | LAST[7] | FIRST[6] |
    |      3 |  var | payload (entry or stream data)           |

Entry payload format (non-stream blocks, stream_id == 0):

    | offset  | size    | description                           |
    |---------|---------|---------------------------------------|
    |       0 |       2 | data length                           |
    |       2 |       2 | content type                          |
    |       4 |       1 | path length                           |
    |       5 | path_len| path (UTF-8, no NUL terminator)       |
    | 5+p_len | data_len| payload data                          |

Stream first-block payload format:

    | offset  | size    | description                           |
    |---------|---------|---------------------------------------|
    |       0 |       2 | content type                          |
    |       2 |       1 | path length                           |
    |       3 | path_len| path (UTF-8, no NUL terminator)       |
    | 3+p_len |     var | data                                  |

Subsequent stream blocks carry raw data only.
"""

import struct
from .const import (
    BLOCK_HEADER_SIZE,
    BLOCK_ID_ENTRY,
    BLOCK_ID_MASK,
    BLOCK_FLAG_FIRST,
    BLOCK_FLAG_LAST,
)


# ---------------------------------------------------------------------------
# Block
# ---------------------------------------------------------------------------

class Block:
    """A single Pouch block."""

    def __init__(self, stream_id=BLOCK_ID_ENTRY, is_first=True, is_last=True):
        self.stream_id = stream_id
        self.is_first = is_first
        self.is_last = is_last
        self._payload = bytearray()

    @property
    def is_stream(self):
        """True when this block carries stream data (stream_id != 0)."""
        return self.stream_id != BLOCK_ID_ENTRY

    @property
    def payload(self):
        return bytes(self._payload)

    def write(self, data):
        """Append *data* to the block payload."""
        self._payload.extend(data)

    def encode(self):
        """Serialise the block to bytes ready for transmission."""
        id_byte = self.stream_id & BLOCK_ID_MASK
        if self.is_first:
            id_byte |= BLOCK_FLAG_FIRST
        if self.is_last:
            id_byte |= BLOCK_FLAG_LAST
        # size field covers id byte + payload
        size = 1 + len(self._payload)
        return struct.pack(">H", size) + bytes([id_byte]) + bytes(self._payload)

    @classmethod
    def decode(cls, data, offset=0):
        """Parse a block from *data* starting at *offset*.

        Returns ``(block, bytes_consumed)`` or ``(None, 0)`` if *data* is too
        short to contain a complete block.
        """
        if len(data) - offset < BLOCK_HEADER_SIZE:
            return None, 0
        (size,) = struct.unpack_from(">H", data, offset)
        total = 2 + size  # size field (2 B) + rest of block
        if len(data) - offset < total:
            return None, 0

        id_byte = data[offset + 2]
        stream_id = id_byte & BLOCK_ID_MASK
        is_first = bool(id_byte & BLOCK_FLAG_FIRST)
        is_last = bool(id_byte & BLOCK_FLAG_LAST)

        block = cls(stream_id=stream_id, is_first=is_first, is_last=is_last)
        block._payload = bytearray(data[offset + 3: offset + total])
        return block, total


# ---------------------------------------------------------------------------
# Entry helpers
# ---------------------------------------------------------------------------

def encode_entry(path, content_type, data):
    """Encode a single Pouch entry payload (for inclusion in an entry block).

    Args:
        path:         Destination path as *str* or *bytes*.
        content_type: Integer content-type (see :data:`~pouch.const.CONTENT_TYPE_*`).
        data:         Payload as *bytes*, *bytearray*, or *str*.

    Returns:
        Bytes ready to write into a :class:`Block`.
    """
    if isinstance(path, str):
        path = path.encode("utf-8")
    if isinstance(data, str):
        data = data.encode("utf-8")
    return (
        struct.pack(">HHB", len(data), content_type, len(path))
        + bytes(path)
        + bytes(data)
    )


def decode_entries(payload):
    """Iterate over entries packed into a block payload.

    Yields ``(path: str, content_type: int, data: bytes)`` tuples.
    """
    offset = 0
    while offset + 5 <= len(payload):
        data_len, content_type, path_len = struct.unpack_from(">HHB", payload, offset)
        offset += 5
        path = payload[offset: offset + path_len].decode("utf-8")
        offset += path_len
        data = bytes(payload[offset: offset + data_len])
        offset += data_len
        yield path, content_type, data


def encode_stream_first(path, content_type, data=b""):
    """Encode the first-block payload for a stream.

    Args:
        path:         Destination path as *str* or *bytes*.
        content_type: Integer content-type.
        data:         Initial data bytes to include in this block (may be empty).

    Returns:
        Bytes ready to write into a :class:`Block`.
    """
    if isinstance(path, str):
        path = path.encode("utf-8")
    if isinstance(data, str):
        data = data.encode("utf-8")
    return struct.pack(">HB", content_type, len(path)) + bytes(path) + bytes(data)


def decode_stream_first(payload):
    """Decode the first-block payload for a stream.

    Returns ``(path: str, content_type: int, data: bytes)``.
    """
    if len(payload) < 3:
        raise ValueError("stream first-block payload too short")
    (content_type, path_len) = struct.unpack_from(">HB", payload, 0)
    offset = 3
    path = payload[offset: offset + path_len].decode("utf-8")
    offset += path_len
    data = bytes(payload[offset:])
    return path, content_type, data
