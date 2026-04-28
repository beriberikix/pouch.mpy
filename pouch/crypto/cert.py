# SPDX-License-Identifier: Apache-2.0
"""Minimal DER/ASN.1 parser for X.509 certificates.

Extracts just enough information for Pouch SAEAD:
  - EC P-256 public key (65 bytes, uncompressed) for ECDH
  - cert_ref: SHA-256(cert_DER)[:6]  (truncated hash for header)
  - Serial number (for info characteristic)

Does NOT perform certificate chain validation; the gateway handles trust.
"""

import hashlib
from ..const import CERT_REF_LEN


# ASN.1 tag constants
_TAG_SEQUENCE = 0x30
_TAG_INTEGER = 0x02
_TAG_BIT_STRING = 0x03
_TAG_OID = 0x06

# OID for EC public key algorithm (1.2.840.10045.2.1)
_OID_EC_PUBKEY = b"\x2a\x86\x48\xce\x3d\x02\x01"
# OID for P-256 / secp256r1 / prime256v1 (1.2.840.10045.3.1.7)
_OID_P256 = b"\x2a\x86\x48\xce\x3d\x03\x01\x07"


def _read_tag_length(data, offset):
    """Read ASN.1 tag and length at *offset*.

    Returns ``(tag, content_offset, content_length)``.
    """
    if offset >= len(data):
        raise ValueError("ASN.1: unexpected end of data")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise ValueError("ASN.1: missing length")
    length = data[offset]
    offset += 1
    if length & 0x80:
        num_bytes = length & 0x7F
        if num_bytes == 0 or num_bytes > 4:
            raise ValueError("ASN.1: unsupported length encoding")
        length = 0
        for _ in range(num_bytes):
            if offset >= len(data):
                raise ValueError("ASN.1: truncated length")
            length = (length << 8) | data[offset]
            offset += 1
    return tag, offset, length


def _find_sequence(data, offset):
    """Expect a SEQUENCE at *offset*, return ``(content_offset, length)``."""
    tag, content_off, length = _read_tag_length(data, offset)
    if tag != _TAG_SEQUENCE:
        raise ValueError("Expected SEQUENCE, got 0x{:02x}".format(tag))
    return content_off, length


def _skip_element(data, offset):
    """Skip one ASN.1 TLV element, return new offset."""
    _tag, content_off, length = _read_tag_length(data, offset)
    return content_off + length


def cert_ref(cert_der):
    """Compute the 6-byte certificate reference.

    Args:
        cert_der: Raw DER-encoded X.509 certificate bytes.

    Returns:
        6-byte ``bytes`` object (truncated SHA-256 of the certificate).
    """
    h = hashlib.sha256(cert_der)
    return h.digest()[:CERT_REF_LEN]


def cert_serial(cert_der):
    """Extract the serial number from a DER X.509 certificate.

    Returns the serial number as ``bytes`` (big-endian, possibly with
    leading zero for positive representation).
    """
    # Certificate ::= SEQUENCE { tbsCertificate, ... }
    tbs_off, _tbs_len = _find_sequence(cert_der, 0)
    # tbsCertificate ::= SEQUENCE { version, serialNumber, ... }
    inner_off, _inner_len = _find_sequence(cert_der, tbs_off)
    off = inner_off

    # version is optional, context-tagged [0] EXPLICIT
    if off < len(cert_der) and cert_der[off] == 0xA0:
        off = _skip_element(cert_der, off)

    # serialNumber ::= INTEGER
    tag, content_off, length = _read_tag_length(cert_der, off)
    if tag != _TAG_INTEGER:
        raise ValueError("Expected INTEGER for serial number")
    return bytes(cert_der[content_off:content_off + length])


def extract_ec_pubkey(cert_der):
    """Extract the EC P-256 public key from a DER X.509 certificate.

    Returns:
        65-byte ``bytes`` (uncompressed point: ``04 || x || y``).

    Raises:
        ValueError: If the certificate does not contain an EC P-256 key.
    """
    # We search for the SubjectPublicKeyInfo SEQUENCE containing the
    # EC P-256 OID, then extract the BIT STRING that follows.
    #
    # SubjectPublicKeyInfo ::= SEQUENCE {
    #   algorithm  AlgorithmIdentifier,   -- SEQUENCE { OID ecPublicKey, OID p256 }
    #   subjectPublicKey  BIT STRING      -- 0x00 || 0x04 || x(32) || y(32)
    # }

    ec_oid_pos = _find_bytes(cert_der, _OID_EC_PUBKEY)
    if ec_oid_pos < 0:
        raise ValueError("Certificate does not contain EC public key OID")

    p256_pos = _find_bytes(cert_der, _OID_P256)
    if p256_pos < 0:
        raise ValueError("Certificate does not use P-256 curve")

    # Walk back from the EC OID to find the enclosing SubjectPublicKeyInfo
    # SEQUENCE. A simpler approach: scan forward from the P-256 OID to find
    # the BIT STRING.
    # After the algorithm SEQUENCE, the next element is the BIT STRING.
    off = p256_pos + len(_OID_P256)

    # Skip to the end of the AlgorithmIdentifier SEQUENCE, then read
    # the BIT STRING. Since we might be mid-SEQUENCE, scan for BIT STRING tag.
    while off < len(cert_der):
        tag, content_off, length = _read_tag_length(cert_der, off)
        if tag == _TAG_BIT_STRING:
            # BIT STRING: first byte is number of unused bits (should be 0)
            if length < 66 or cert_der[content_off] != 0x00:
                raise ValueError("Unexpected BIT STRING format for EC key")
            pubkey = bytes(cert_der[content_off + 1:content_off + 1 + 65])
            if pubkey[0] != 0x04:
                raise ValueError("Expected uncompressed EC point (0x04 prefix)")
            return pubkey
        off = content_off + length

    raise ValueError("EC public key BIT STRING not found")


def _find_bytes(data, needle):
    """Find *needle* in *data*, return offset or -1."""
    nlen = len(needle)
    for i in range(len(data) - nlen + 1):
        if data[i:i + nlen] == needle:
            return i
    return -1
