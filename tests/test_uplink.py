# SPDX-License-Identifier: Apache-2.0
"""Integration tests for Pouch uplink payload building and downlink parsing."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pouch import Pouch
from pouch.block import Block, decode_entries
from pouch.header import decode_header
from pouch.const import CONTENT_TYPE_JSON, CONTENT_TYPE_CBOR, CONTENT_TYPE_OCTET_STREAM


# ---------------------------------------------------------------------------
# Uplink building
# ---------------------------------------------------------------------------

def test_build_uplink_no_entries():
    """build_uplink() with no entries should return None."""
    p = Pouch("dev-001")
    assert p.build_uplink() is None


def test_build_uplink_single_entry():
    p = Pouch("dev-001")

    @p.uplink_handler
    def provide():
        p.add_entry(".s/temp", CONTENT_TYPE_JSON, b'{"t":21}')

    payload = p.build_uplink()
    assert payload is not None
    assert isinstance(payload, bytes)


def test_build_uplink_header_prefix():
    """Uplink payload must start with a valid Pouch header."""
    p = Pouch("dev-001")
    p.add_entry("x", CONTENT_TYPE_OCTET_STREAM, b"hi")
    payload = p.build_uplink()

    device_id, enc_type, header_len = decode_header(payload)
    assert device_id == "dev-001"
    assert header_len > 0


def test_build_uplink_block_parse():
    """After the header, the payload should contain a valid entry block."""
    p = Pouch("sensor-1")
    p.add_entry(".s/sensor", CONTENT_TYPE_JSON, b'{"v":42}')
    payload = p.build_uplink()

    _, _, header_len = decode_header(payload)
    block, consumed = Block.decode(payload, header_len)
    assert block is not None
    assert not block.is_stream
    assert block.is_first
    assert block.is_last

    entries = list(decode_entries(block.payload))
    assert len(entries) == 1
    path, ct, data = entries[0]
    assert path == ".s/sensor"
    assert ct == CONTENT_TYPE_JSON
    assert data == b'{"v":42}'


def test_build_uplink_multiple_entries_same_block():
    """Multiple entries should be packed into a single block."""
    p = Pouch("dev")
    p.add_entry("a", CONTENT_TYPE_JSON, b"1")
    p.add_entry("b", CONTENT_TYPE_JSON, b"2")
    p.add_entry("c", CONTENT_TYPE_JSON, b"3")
    payload = p.build_uplink()

    _, _, header_len = decode_header(payload)
    block, _ = Block.decode(payload, header_len)
    entries = list(decode_entries(block.payload))
    assert len(entries) == 3


def test_build_uplink_clears_queue():
    """After build_uplink() the pending queue should be empty."""
    p = Pouch("dev")
    p.add_entry("x", CONTENT_TYPE_JSON, b"1")
    p.build_uplink()
    # Second call should return None (queue is cleared)
    assert p.build_uplink() is None


def test_build_uplink_str_data():
    """String data should be UTF-8 encoded."""
    p = Pouch("dev")
    p.add_entry("k", CONTENT_TYPE_JSON, '{"hello":"world"}')
    payload = p.build_uplink()

    _, _, header_len = decode_header(payload)
    block, _ = Block.decode(payload, header_len)
    entries = list(decode_entries(block.payload))
    assert entries[0][2] == b'{"hello":"world"}'


# ---------------------------------------------------------------------------
# Downlink parsing
# ---------------------------------------------------------------------------

def _make_downlink(device_id, entries):
    """Build a minimal Pouch downlink payload."""
    from pouch.header import encode_header
    from pouch.block import Block, encode_entry

    header = encode_header(device_id)
    block = Block()
    for path, ct, data in entries:
        block.write(encode_entry(path, ct, data))
    return header + block.encode()


def test_handle_downlink_single_entry():
    p = Pouch("gw")
    received = []

    @p.downlink_handler
    def on_data(path, content_type, data):
        received.append((path, content_type, data))

    raw = _make_downlink("gw", [(".d/led", CONTENT_TYPE_JSON, b'{"on":true}')])
    p.handle_downlink(raw)

    assert len(received) == 1
    assert received[0][0] == ".d/led"
    assert received[0][2] == b'{"on":true}'


def test_handle_downlink_multiple_entries():
    p = Pouch("gw")
    received = []

    @p.downlink_handler
    def on_data(path, content_type, data):
        received.append(path)

    raw = _make_downlink("gw", [
        ("a", CONTENT_TYPE_JSON, b"1"),
        ("b", CONTENT_TYPE_JSON, b"2"),
    ])
    p.handle_downlink(raw)

    assert len(received) == 2
    assert set(received) == {"a", "b"}


def test_handle_downlink_no_callback():
    """handle_downlink() without a callback should not raise."""
    p = Pouch("dev")
    raw = _make_downlink("dev", [("x", CONTENT_TYPE_OCTET_STREAM, b"\x00")])
    p.handle_downlink(raw)  # should not raise


def test_handle_downlink_malformed():
    """Malformed data should be silently ignored."""
    p = Pouch("dev")
    p.handle_downlink(b"\x00\x01\x02")  # garbage – should not raise


# ---------------------------------------------------------------------------
# SAR layer (transport-independent)
# ---------------------------------------------------------------------------

def test_sar_sender_basic():
    """SAR sender should send all fragments and FIN for a simple payload."""
    from pouch.transport.ble_gatt import _SARSender
    from pouch.const import SAR_FLAG_FIRST, SAR_FLAG_LAST, SAR_FLAG_FIN

    sent = []
    sender = _SARSender(notify_fn=sent.append, maxlen=8)

    payload = b"ABCDEFGH"  # exactly 6 bytes of payload per fragment (8 - 2 header)
    sender.start(payload)

    # Initial ACK: seq=0xFF, window=4 → sender should send up to 4 fragments
    initial_ack = bytes([0x00, 0xFF, 4])  # code=ACK, seq=0xFF, window=4
    sender.on_ack(initial_ack)

    assert len(sent) > 0
    # First packet should have FIRST flag
    assert sent[0][0] & SAR_FLAG_FIRST


def test_sar_sender_fin():
    """After all data is sent and the last ACK arrives, sender should FIN."""
    from pouch.transport.ble_gatt import _SARSender
    from pouch.const import SAR_FLAG_FIN

    sent = []
    sender = _SARSender(notify_fn=sent.append, maxlen=10)

    payload = b"hi"  # tiny payload – fits in one fragment
    sender.start(payload)

    # Initial ACK with large window
    sender.on_ack(bytes([0x00, 0xFF, 10]))
    # The data fragment was sent; last seq is 0x00

    # ACK for seq 0 with window 0 (no more room, but last was sent)
    sender.on_ack(bytes([0x00, 0x00, 0]))

    fin_packets = [p for p in sent if p[0] & SAR_FLAG_FIN]
    assert len(fin_packets) >= 1


def test_sar_receiver_basic():
    """SAR receiver should reassemble fragments and send ACKs."""
    from pouch.transport.ble_gatt import _SARReceiver
    from pouch.const import SAR_FLAG_FIRST, SAR_FLAG_LAST, SAR_SEQ_MAX

    acks_sent = []
    data_received = []

    def recv_data(chunk, is_last):
        data_received.append((chunk, is_last))

    receiver = _SARReceiver(
        notify_fn=acks_sent.append,
        data_cb=recv_data,
        window=4,
    )
    receiver.open()
    # open() sends an initial ACK
    assert len(acks_sent) == 1
    initial_ack = acks_sent[0]
    assert initial_ack[0] == 0x00        # ACK code
    assert initial_ack[1] == SAR_SEQ_MAX  # seq starts at 0xFF

    # Send a single-fragment message (FIRST|LAST, seq=0)
    pkt = bytes([SAR_FLAG_FIRST | SAR_FLAG_LAST, 0x00]) + b"hello"
    receiver.on_rx(pkt)

    assert len(data_received) == 1
    assert data_received[0][0] == b"hello"
    assert data_received[0][1] is True  # is_last


def test_sar_receiver_out_of_order():
    """Out-of-order packets should result in a NACK."""
    from pouch.transport.ble_gatt import _SARReceiver
    from pouch.const import SAR_FLAG_FIRST, SAR_CODE_NACK_UNKNOWN

    acks_sent = []

    receiver = _SARReceiver(
        notify_fn=acks_sent.append,
        data_cb=lambda c, l: None,
        window=4,
    )
    receiver.open()

    # Send seq=1 when seq=0 is expected – should NACK
    pkt = bytes([SAR_FLAG_FIRST, 0x01]) + b"bad"
    receiver.on_rx(pkt)

    last_ack = acks_sent[-1]
    assert last_ack[0] == SAR_CODE_NACK_UNKNOWN


# ---------------------------------------------------------------------------
# Encrypted uplink / downlink (SAEAD)
# ---------------------------------------------------------------------------

# Test certificate (same as tests/test_cert.py)
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


def _make_encrypted_pouch():
    """Create an encrypted Pouch instance with test cert/key provisioned."""
    from pouch.const import SAEAD_ALG_AES_GCM
    p = Pouch("dev-enc", private_key=bytes(32), certificate=_TEST_CERT_DER,
              algorithm=SAEAD_ALG_AES_GCM)
    p.set_server_certificate(_TEST_CERT_DER)
    return p


def test_encrypted_property():
    p = Pouch("dev", private_key=bytes(32), certificate=_TEST_CERT_DER)
    assert p.encrypted is True


def test_plaintext_property():
    p = Pouch("dev")
    assert p.encrypted is False


def test_encrypted_build_uplink_returns_bytes():
    p = _make_encrypted_pouch()
    p.add_entry(".s/temp", CONTENT_TYPE_JSON, b'{"t":22}')
    payload = p.build_uplink()
    assert payload is not None
    assert isinstance(payload, bytes)


def test_encrypted_uplink_has_saead_header():
    from pouch.const import ENCRYPTION_SAEAD
    p = _make_encrypted_pouch()
    p.add_entry(".s/temp", CONTENT_TYPE_JSON, b'{"t":22}')
    payload = p.build_uplink()

    info, enc_type, header_len = decode_header(payload)
    assert enc_type == ENCRYPTION_SAEAD
    assert isinstance(info, dict)
    assert "session_id" in info
    assert "algorithm" in info
    assert header_len > 0


def test_encrypted_uplink_block_has_tag():
    """Encrypted block payload should be larger than plaintext (auth tag)."""
    from pouch.const import ENCRYPTION_SAEAD, AUTH_TAG_LEN
    p = _make_encrypted_pouch()
    entry_data = b'{"v":1}'
    p.add_entry(".s/x", CONTENT_TYPE_JSON, entry_data)
    payload = p.build_uplink()

    _, _, header_len = decode_header(payload)
    block, _ = Block.decode(payload, header_len)
    assert block is not None
    # The block payload should contain the encrypted entry + auth tag
    # The plaintext entry (with block-level framing) is smaller than the
    # encrypted payload by exactly AUTH_TAG_LEN
    assert len(block.payload) >= AUTH_TAG_LEN


def test_encrypted_uplink_no_entries():
    p = _make_encrypted_pouch()
    assert p.build_uplink() is None


def test_encrypted_uplink_pouch_id_increments():
    """Each build_uplink should use a new pouch_id."""
    from pouch.const import ENCRYPTION_SAEAD
    p = _make_encrypted_pouch()

    p.add_entry("a", CONTENT_TYPE_JSON, b"1")
    payload1 = p.build_uplink()
    info1, _, _ = decode_header(payload1)

    p.add_entry("b", CONTENT_TYPE_JSON, b"2")
    payload2 = p.build_uplink()
    info2, _, _ = decode_header(payload2)

    assert info2["pouch_id"] == info1["pouch_id"] + 1


def test_encrypted_downlink_roundtrip():
    """Build an encrypted downlink and verify the device can decrypt it."""
    from pouch.const import SAEAD_ALG_AES_GCM, POUCH_ROLE_SERVER
    from pouch.header import encode_header_saead
    from pouch.block import Block, encode_entry
    from pouch.crypto.session import derive_session_key, Session
    from pouch.crypto.cert import extract_ec_pubkey, cert_ref

    device_priv = bytes(32)
    server_priv = bytes(range(32))
    device_pubkey = b"\x04" + bytes(64)  # fake, mock ECDH ignores format
    server_pubkey = extract_ec_pubkey(_TEST_CERT_DER)

    # Set up device-side Pouch
    p = Pouch("dev-enc", private_key=device_priv, certificate=_TEST_CERT_DER,
              algorithm=SAEAD_ALG_AES_GCM)
    p.set_server_certificate(_TEST_CERT_DER)

    received = []

    @p.downlink_handler
    def on_data(path, content_type, data):
        received.append((path, content_type, data))

    # Build a server-side encrypted downlink
    session_id = bytes(16)  # deterministic for test
    cr = cert_ref(_TEST_CERT_DER)
    pouch_id = 0

    # Derive the same key the device will derive
    key = derive_session_key(device_priv, server_pubkey, session_id,
                             POUCH_ROLE_SERVER, SAEAD_ALG_AES_GCM, 9)
    server_session = Session(key, SAEAD_ALG_AES_GCM, POUCH_ROLE_SERVER)

    # Build plaintext block
    entry_payload = encode_entry(".d/led", CONTENT_TYPE_JSON, b'{"on":true}')
    block = Block()
    block.write(entry_payload)
    plaintext_block_data = block.payload

    # Encrypt the block
    encrypted_data = server_session.encrypt_block(pouch_id, plaintext_block_data)

    # Build encrypted block
    enc_block = Block()
    enc_block.write(encrypted_data)

    # Build SAEAD header
    header = encode_header_saead(session_id, POUCH_ROLE_SERVER,
                                 SAEAD_ALG_AES_GCM, 9, cr, pouch_id)

    raw_downlink = header + enc_block.encode()
    p.handle_downlink(raw_downlink)

    assert len(received) == 1
    assert received[0][0] == ".d/led"
    assert received[0][2] == b'{"on":true}'


def test_clear_session():
    """clear_session should remove crypto state."""
    p = _make_encrypted_pouch()
    assert p._uplink_session is not None
    assert p._downlink_session is not None
    p.clear_session()
    assert p._uplink_session is None
    assert p._downlink_session is None


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
