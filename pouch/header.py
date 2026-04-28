# SPDX-License-Identifier: Apache-2.0
"""Pouch header encoding/decoding.

The Pouch header is a CBOR array:

    pouch_header = [version: uint, encryption_info]

For plaintext (encryption_type == 0):

    encryption_info = [0, device_id: tstr]

For SAEAD (encryption_type == 1):

    encryption_info = [1, session_info, pouch_id: uint]
    session_info = [[session_id: bstr], initiator: uint, algorithm: uint,
                     max_block_size_log: uint, cert_ref: bstr]
"""

from . import cbor
from .const import POUCH_VERSION, ENCRYPTION_NONE, ENCRYPTION_SAEAD


def encode_header(device_id):
    """Encode a plaintext Pouch header.

    Args:
        device_id: Device identifier string (max 32 characters).

    Returns:
        Bytes containing the CBOR-encoded Pouch header.
    """
    return cbor.encode([POUCH_VERSION, [ENCRYPTION_NONE, device_id]])


def encode_header_saead(session_id, initiator, algorithm, max_block_size_log,
                        cert_ref, pouch_id):
    """Encode an SAEAD Pouch header.

    Args:
        session_id:          16-byte random session identifier.
        initiator:           Role of session initiator (POUCH_ROLE_DEVICE or
                             POUCH_ROLE_SERVER).
        algorithm:           AEAD algorithm (SAEAD_ALG_AES_GCM or
                             SAEAD_ALG_CHACHA20_POLY1305).
        max_block_size_log:  Log2 of the maximum block payload size.
        cert_ref:            6-byte certificate reference (truncated hash).
        pouch_id:            Monotonically increasing pouch identifier (uint).

    Returns:
        Bytes containing the CBOR-encoded Pouch header.
    """
    session_info = [
        [bytes(session_id)],
        initiator,
        algorithm,
        max_block_size_log,
        bytes(cert_ref),
    ]
    return cbor.encode([POUCH_VERSION, [ENCRYPTION_SAEAD, session_info, pouch_id]])


def decode_header(data, offset=0):
    """Decode a Pouch header from *data*.

    Args:
        data:   Raw bytes containing the header.
        offset: Starting byte offset within *data*.

    Returns:
        For plaintext (encryption_type == 0):
            Tuple ``(device_id: str, encryption_type: int, bytes_consumed: int)``.

        For SAEAD (encryption_type == 1):
            Tuple ``(session_info: dict, encryption_type: int, bytes_consumed: int)``
            where *session_info* has keys ``session_id``, ``initiator``,
            ``algorithm``, ``max_block_size_log``, ``cert_ref``, ``pouch_id``.

    Raises:
        ValueError: If the header is malformed or uses an unsupported
                    encryption type.
    """
    try:
        header, new_offset = cbor.decode(data, offset)
    except Exception as exc:
        raise ValueError("Failed to decode Pouch header: {}".format(exc))

    if not isinstance(header, list) or len(header) < 2:
        raise ValueError("Pouch header must be a CBOR array with at least 2 elements")

    version = header[0]
    if version != POUCH_VERSION:
        raise ValueError("Unsupported Pouch version: {}".format(version))

    enc_info = header[1]
    if not isinstance(enc_info, list) or len(enc_info) < 2:
        raise ValueError("Pouch encryption_info must be a CBOR array")

    encryption_type = enc_info[0]

    if encryption_type == ENCRYPTION_NONE:
        device_id = enc_info[1]
        return device_id, encryption_type, new_offset - offset

    if encryption_type == ENCRYPTION_SAEAD:
        if len(enc_info) < 3:
            raise ValueError("SAEAD encryption_info requires session_info and pouch_id")
        raw_session_info = enc_info[1]
        pouch_id = enc_info[2]
        if not isinstance(raw_session_info, list) or len(raw_session_info) < 5:
            raise ValueError("SAEAD session_info must have 5 elements")
        id_arr = raw_session_info[0]
        if not isinstance(id_arr, list) or len(id_arr) < 1:
            raise ValueError("session_info id must be a single-element array")
        session_info = {
            "session_id": bytes(id_arr[0]),
            "initiator": raw_session_info[1],
            "algorithm": raw_session_info[2],
            "max_block_size_log": raw_session_info[3],
            "cert_ref": bytes(raw_session_info[4]),
            "pouch_id": pouch_id,
        }
        return session_info, encryption_type, new_offset - offset

    raise ValueError("Unsupported encryption type: {}".format(encryption_type))
