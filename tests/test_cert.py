# SPDX-License-Identifier: Apache-2.0
"""Unit tests for pouch.crypto.cert (DER/ASN.1 parsing)."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# The pouch_crypto mock is installed by conftest.py

from pouch.crypto.cert import cert_ref, cert_serial, extract_ec_pubkey


# Minimal self-signed EC P-256 test certificate (DER-encoded).
# Generated with:
#   openssl ecparam -name prime256v1 -genkey -noout -out key.pem
#   openssl req -new -x509 -key key.pem -out cert.pem -days 3650 -subj "/CN=test"
#   openssl x509 -in cert.pem -outform DER | python3 -c "import sys; d=sys.stdin.buffer.read(); print(d.hex())"
#
# This is a fixed test vector so tests are reproducible.
_TEST_CERT_DER = bytes.fromhex(
    "308201463081eda00302010202147b3c4d5e6f0a1b2c3d4e5f6071829304a5b6c7"
    "d8300a06082a8648ce3d040302301330110603550403130a7465737420636572743"
    "0200617323530313031303030303030305a180f32303535303130313030303030305a"
    "3013301106035504031"
    "30a74657374206365727430593013060"
    "72a8648ce3d020106082a8648ce3d030107034200"
    "04"
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    "300a06082a8648ce3d0403020348003045022100"
    "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcdf8"
    "02200ef7e5eadf54dbfb76ab1de8ddd1aece43e67c7ded5ebb8d1a5c6476e59c6eac"
)


def test_cert_ref_returns_6_bytes():
    ref = cert_ref(_TEST_CERT_DER)
    assert isinstance(ref, bytes)
    assert len(ref) == 6


def test_cert_ref_deterministic():
    ref1 = cert_ref(_TEST_CERT_DER)
    ref2 = cert_ref(_TEST_CERT_DER)
    assert ref1 == ref2


def test_cert_ref_changes_with_data():
    ref1 = cert_ref(_TEST_CERT_DER)
    ref2 = cert_ref(b"\x00" * 100)
    assert ref1 != ref2


def test_cert_serial_returns_bytes():
    serial = cert_serial(_TEST_CERT_DER)
    assert isinstance(serial, bytes)
    assert len(serial) > 0


def test_extract_ec_pubkey_length():
    pubkey = extract_ec_pubkey(_TEST_CERT_DER)
    assert isinstance(pubkey, bytes)
    assert len(pubkey) == 65
    assert pubkey[0] == 0x04  # uncompressed point marker


def test_extract_ec_pubkey_matches_embedded():
    """The extracted pubkey should match the known key embedded in the cert."""
    pubkey = extract_ec_pubkey(_TEST_CERT_DER)
    expected_x = bytes.fromhex(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    )
    expected_y = bytes.fromhex(
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    )
    assert pubkey[1:33] == expected_x
    assert pubkey[33:65] == expected_y


def test_extract_ec_pubkey_non_ec_cert_fails():
    """A non-EC certificate should raise ValueError."""
    # Minimal DER that is a SEQUENCE but has no EC OIDs
    fake_cert = bytes.fromhex("3003020100")
    try:
        extract_ec_pubkey(fake_cert)
        assert False, "Should have raised ValueError"
    except ValueError:
        pass


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
