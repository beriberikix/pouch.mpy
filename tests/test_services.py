# SPDX-License-Identifier: Apache-2.0
"""Tests for Golioth services (pouch.services.*)."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pouch import Pouch
from pouch import cbor
from pouch.block import Block, encode_entry, encode_stream_first
from pouch.header import encode_header, decode_header
from pouch.const import (
    CONTENT_TYPE_JSON,
    CONTENT_TYPE_CBOR,
    BLOCK_ID_ENTRY,
    BLOCK_FLAG_FIRST,
    BLOCK_FLAG_LAST,
)
from pouch.services.logging import LogService, LOG_LEVEL_ERR, LOG_LEVEL_WRN, LOG_LEVEL_INF, LOG_LEVEL_DBG
from pouch.services.settings import SettingsService
from pouch.services.stream import StreamService
from pouch.services.state import StateService
from pouch.services.ota import OTAService, OTA_STATE_IDLE, OTA_STATE_DOWNLOADING, _hex_to_bytes


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_downlink(entries):
    """Build a Pouch downlink payload with the given (path, ct, data) entries."""
    header = encode_header("gw")
    block = Block()
    for path, ct, data in entries:
        block.write(encode_entry(path, ct, data))
    return header + block.encode()


def _build_uplink(pouch):
    """Build uplink and parse the resulting entries."""
    payload = pouch.build_uplink()
    if payload is None:
        return []
    _, _, hl = decode_header(payload)
    block, _ = Block.decode(payload, hl)
    from pouch.block import decode_entries
    return list(decode_entries(block.payload))


# ===========================================================================
# CBOR float support (needed by settings)
# ===========================================================================

def test_cbor_encode_decode_float():
    """float values should round-trip through CBOR encode/decode."""
    import math
    original = 3.14
    encoded = cbor.encode(original)
    decoded, _ = cbor.decode(encoded)
    assert isinstance(decoded, float)
    assert abs(decoded - original) < 1e-10


def test_cbor_decode_float32():
    """float32 CBOR bytes (0xFA prefix) should decode correctly."""
    import struct
    # Encode a float32 manually: 0xFA + big-endian float32 bytes
    raw = bytes([0xFA]) + struct.pack(">f", 1.5)
    val, n = cbor.decode(raw)
    assert isinstance(val, float)
    assert abs(val - 1.5) < 1e-6
    assert n == 5


def test_cbor_decode_float16_one():
    """float16 CBOR bytes for 1.0 should decode to Python float 1.0."""
    # CBOR float16 for 1.0 = 0xF9 0x3C 0x00
    raw = bytes([0xF9, 0x3C, 0x00])
    val, n = cbor.decode(raw)
    assert isinstance(val, float)
    assert abs(val - 1.0) < 1e-4
    assert n == 3


def test_cbor_map_with_float_value():
    """Maps containing float values should decode correctly."""
    payload = cbor.encode({"threshold": 22.5})
    decoded, _ = cbor.decode(payload)
    assert isinstance(decoded["threshold"], float)
    assert abs(decoded["threshold"] - 22.5) < 1e-9


# ===========================================================================
# LogService
# ===========================================================================

def test_log_info_queues_entry():
    """log.info() should queue an entry on the .log path."""
    p = Pouch("dev")
    log = LogService(p)
    log.info("app", "hello")

    entries = _build_uplink(p)
    assert len(entries) == 1
    path, ct, data = entries[0]
    assert path == ".log"
    assert ct == CONTENT_TYPE_CBOR
    msg, _ = cbor.decode(data)
    assert msg["level"] == LOG_LEVEL_INF
    assert msg["module"] == "app"
    assert msg["msg"] == "hello"


def test_log_levels():
    """All log level helpers should set the correct level in the CBOR."""
    p = Pouch("dev")
    log = LogService(p)

    log.error("m", "e")
    log.warning("m", "w")
    log.debug("m", "d")

    entries = _build_uplink(p)
    assert len(entries) == 3
    levels = [cbor.decode(e[2])[0]["level"] for e in entries]
    assert LOG_LEVEL_ERR in levels
    assert LOG_LEVEL_WRN in levels
    assert LOG_LEVEL_DBG in levels


def test_log_multiple_messages():
    """Multiple log calls should each produce their own entry."""
    p = Pouch("dev")
    log = LogService(p)
    for i in range(5):
        log.info("mod", "msg {}".format(i))

    entries = _build_uplink(p)
    assert len(entries) == 5


# ===========================================================================
# SettingsService – uplink
# ===========================================================================

def test_settings_uplink_null_version_initially():
    """Settings status uplink should report null version before any downlink."""
    p = Pouch("dev")
    _svc = SettingsService(p)

    entries = _build_uplink(p)
    status_entries = [e for e in entries if e[0] == ".c/status"]
    assert len(status_entries) == 1
    msg, _ = cbor.decode(status_entries[0][2])
    assert msg["version"] is None


def test_settings_uplink_version_after_downlink():
    """After receiving a settings downlink, the uplink version should match."""
    p = Pouch("dev")
    svc = SettingsService(p)

    payload = cbor.encode({"settings": {"K": 1}, "version": 42})
    raw = _make_downlink([("/.c", CONTENT_TYPE_CBOR, payload)])
    p.handle_downlink(raw)

    entries = _build_uplink(p)
    status = [e for e in entries if e[0] == ".c/status"][0]
    msg, _ = cbor.decode(status[2])
    assert msg["version"] == 42


# ===========================================================================
# SettingsService – downlink dispatch
# ===========================================================================

def test_settings_handler_int():
    """Integer settings values should be dispatched to the correct handler."""
    p = Pouch("dev")
    svc = SettingsService(p)
    received = {}

    @svc.handler("LOOP_DELAY_S")
    def on_delay(val):
        received["LOOP_DELAY_S"] = val

    payload = cbor.encode({"settings": {"LOOP_DELAY_S": 30}, "version": 1})
    raw = _make_downlink([("/.c", CONTENT_TYPE_CBOR, payload)])
    p.handle_downlink(raw)

    assert received.get("LOOP_DELAY_S") == 30


def test_settings_handler_bool():
    """Boolean settings values should be dispatched correctly."""
    p = Pouch("dev")
    svc = SettingsService(p)
    received = {}

    @svc.handler("ENABLED")
    def on_enabled(val):
        received["ENABLED"] = val

    payload = cbor.encode({"settings": {"ENABLED": True}, "version": 2})
    raw = _make_downlink([("/.c", CONTENT_TYPE_CBOR, payload)])
    p.handle_downlink(raw)

    assert received.get("ENABLED") is True


def test_settings_handler_string():
    """String settings values should be dispatched correctly."""
    p = Pouch("dev")
    svc = SettingsService(p)
    received = {}

    svc.register("DEVICE_NAME", lambda v: received.__setitem__("DEVICE_NAME", v))

    payload = cbor.encode({"settings": {"DEVICE_NAME": "prod-01"}, "version": 3})
    raw = _make_downlink([("/.c", CONTENT_TYPE_CBOR, payload)])
    p.handle_downlink(raw)

    assert received.get("DEVICE_NAME") == "prod-01"


def test_settings_unregistered_key_ignored():
    """Unregistered setting keys should be silently ignored."""
    p = Pouch("dev")
    _svc = SettingsService(p)

    payload = cbor.encode({"settings": {"UNKNOWN_KEY": 99}, "version": 4})
    raw = _make_downlink([("/.c", CONTENT_TYPE_CBOR, payload)])
    p.handle_downlink(raw)  # should not raise


def test_settings_downlink_does_not_reach_app_handler():
    """Settings downlinks should NOT be forwarded to the application handler."""
    p = Pouch("dev")
    _svc = SettingsService(p)
    app_received = []

    @p.downlink_handler
    def on_data(path, ct, data):
        app_received.append(path)

    payload = cbor.encode({"settings": {}, "version": 5})
    raw = _make_downlink([("/.c", CONTENT_TYPE_CBOR, payload)])
    p.handle_downlink(raw)

    assert "/.c" not in app_received


# ===========================================================================
# StreamService
# ===========================================================================

def test_stream_send_queues_entry():
    """StreamService.send() should queue an entry with .s/ prefix."""
    p = Pouch("dev")
    svc = StreamService(p)
    svc.send("temperature", b'{"value": 22}')

    entries = _build_uplink(p)
    assert len(entries) == 1
    assert entries[0][0] == ".s/temperature"
    assert entries[0][1] == CONTENT_TYPE_JSON


def test_stream_send_custom_content_type():
    """StreamService.send() should respect a custom content type."""
    p = Pouch("dev")
    svc = StreamService(p)
    svc.send("accel", cbor.encode({"x": 0.1}), content_type=CONTENT_TYPE_CBOR)

    entries = _build_uplink(p)
    assert entries[0][1] == CONTENT_TYPE_CBOR


def test_stream_multiple_paths():
    """Multiple sends to different subpaths should produce distinct entries."""
    p = Pouch("dev")
    svc = StreamService(p)
    svc.send("temp", b"1")
    svc.send("humid", b"2")
    svc.send("pressure", b"3")

    entries = _build_uplink(p)
    paths = {e[0] for e in entries}
    assert paths == {".s/temp", ".s/humid", ".s/pressure"}


# ===========================================================================
# StateService – uplink
# ===========================================================================

def test_state_set_queues_entry():
    """StateService.set() should queue an entry with .d/ prefix."""
    p = Pouch("dev")
    svc = StateService(p)
    svc.set("led", b'{"on": false}')

    entries = _build_uplink(p)
    assert len(entries) == 1
    assert entries[0][0] == ".d/led"


# ===========================================================================
# StateService – downlink
# ===========================================================================

def test_state_observe_receives_desired():
    """Desired state downlinks should be dispatched to the observe callback."""
    p = Pouch("dev")
    svc = StateService(p)
    received = []

    @svc.observe
    def on_desired(subpath, ct, data):
        received.append((subpath, data))

    raw = _make_downlink([("/.d/led", CONTENT_TYPE_JSON, b'{"on": true}')])
    p.handle_downlink(raw)

    assert len(received) == 1
    assert received[0][0] == "led"
    assert received[0][1] == b'{"on": true}'


def test_state_observe_strips_prefix():
    """The /.d/ prefix should be stripped from the subpath in the callback."""
    p = Pouch("dev")
    svc = StateService(p)
    paths_seen = []

    @svc.observe
    def on_desired(subpath, ct, data):
        paths_seen.append(subpath)

    raw = _make_downlink([
        ("/.d/config/mode", CONTENT_TYPE_JSON, b'"auto"'),
        ("/.d/thresholds/high", CONTENT_TYPE_JSON, b"100"),
    ])
    p.handle_downlink(raw)

    assert "config/mode" in paths_seen
    assert "thresholds/high" in paths_seen


def test_state_downlink_does_not_reach_app_handler():
    """State downlinks should NOT be forwarded to the application handler."""
    p = Pouch("dev")
    _svc = StateService(p)
    app_paths = []

    @p.downlink_handler
    def on_data(path, ct, data):
        app_paths.append(path)

    raw = _make_downlink([("/.d/led", CONTENT_TYPE_JSON, b"1")])
    p.handle_downlink(raw)

    assert not any(x.startswith("/.d/") for x in app_paths)


# ===========================================================================
# OTAService – helpers
# ===========================================================================

def test_hex_to_bytes_basic():
    """_hex_to_bytes should decode a hex string to bytes."""
    assert _hex_to_bytes("deadbeef") == bytes([0xDE, 0xAD, 0xBE, 0xEF])
    assert _hex_to_bytes("00ff") == bytes([0x00, 0xFF])


def test_hex_to_bytes_uppercase():
    """_hex_to_bytes should accept uppercase hex."""
    assert _hex_to_bytes("DEADBEEF") == bytes([0xDE, 0xAD, 0xBE, 0xEF])


# ===========================================================================
# OTAService – manifest downlink
# ===========================================================================

def _build_manifest_payload(sequence=1, components=None):
    """Build a CBOR OTA manifest matching the Golioth wire format."""
    if components is None:
        components = [
            {1: "main", 2: "1.2.0", 3: "a" * 64, 4: 65536},
        ]
    # Integer keys as per the Golioth OTA spec
    manifest = {1: sequence, 3: components}
    return cbor.encode(manifest)


def test_ota_manifest_fires_callback():
    """A valid OTA manifest should invoke the on_manifest callback."""
    p = Pouch("dev")
    ota = OTAService(p)
    received = []

    @ota.on_manifest
    def got_manifest(comps):
        received.extend(comps)

    payload = _build_manifest_payload(components=[{1: "main", 2: "1.2.0", 3: "ab" * 32, 4: 1024}])
    raw = _make_downlink([("/.u/desired", CONTENT_TYPE_CBOR, payload)])
    p.handle_downlink(raw)

    assert len(received) == 1
    assert received[0]["package"] == "main"
    assert received[0]["version"] == "1.2.0"
    assert received[0]["size"] == 1024
    assert len(received[0]["hash"]) == 32


def test_ota_manifest_multiple_components():
    """Manifests with multiple components should fire callback for each."""
    p = Pouch("dev")
    ota = OTAService(p)
    received = []

    @ota.on_manifest
    def got_manifest(comps):
        received.extend(comps)

    components = [
        {1: "main", 2: "2.0.0", 3: "cd" * 32, 4: 131072},
        {1: "bootloader", 2: "1.0.0", 3: "ef" * 32, 4: 16384},
    ]
    payload = cbor.encode({1: 5, 3: components})
    raw = _make_downlink([("/.u/desired", CONTENT_TYPE_CBOR, payload)])
    p.handle_downlink(raw)

    packages = [c["package"] for c in received]
    assert "main" in packages
    assert "bootloader" in packages


def test_ota_manifest_updates_registered_component_target():
    """A manifest for a registered component should update its target version."""
    p = Pouch("dev")
    ota = OTAService(p)
    ota.register_component("main", current_version="1.0.0")

    payload = cbor.encode({1: 1, 3: [{1: "main", 2: "2.0.0", 3: "00" * 32, 4: 512}]})
    raw = _make_downlink([("/.u/desired", CONTENT_TYPE_CBOR, payload)])
    p.handle_downlink(raw)

    assert ota._components["main"]["target"] == "2.0.0"


# ===========================================================================
# OTAService – uplink status
# ===========================================================================

def test_ota_uplink_idle_no_entries_by_default():
    """With no registered components, no OTA entries should appear in uplink."""
    p = Pouch("dev")
    _ota = OTAService(p)
    entries = _build_uplink(p)
    ota_entries = [e for e in entries if e[0].startswith(".u/c/")]
    assert len(ota_entries) == 0


def test_ota_uplink_registered_component():
    """A registered component should produce a status entry on uplink."""
    p = Pouch("dev")
    ota = OTAService(p)
    ota.register_component("main", current_version="1.0.0")

    entries = _build_uplink(p)
    ota_entries = [e for e in entries if e[0].startswith(".u/c/")]
    assert len(ota_entries) == 1
    assert ota_entries[0][0] == ".u/c/main"

    status, _ = cbor.decode(ota_entries[0][2])
    assert status["s"] == OTA_STATE_IDLE
    assert status["pkg"] == "main"
    assert status["v"] == "1.0.0"
    assert "t" not in status  # no target version when IDLE


def test_ota_uplink_downloading_includes_target():
    """A DOWNLOADING component should include the target version in its status."""
    p = Pouch("dev")
    ota = OTAService(p)
    ota.register_component("main", current_version="1.0.0")
    ota._components["main"]["target"] = "2.0.0"
    ota.mark_downloading("main")

    entries = _build_uplink(p)
    ota_entries = [e for e in entries if e[0] == ".u/c/main"]
    status, _ = cbor.decode(ota_entries[0][2])
    assert status["s"] == OTA_STATE_DOWNLOADING
    assert status["t"] == "2.0.0"


def test_ota_state_transitions():
    """State transition helpers should update the component state."""
    p = Pouch("dev")
    ota = OTAService(p)
    ota.register_component("main", "1.0.0")

    ota.mark_downloading("main")
    assert ota._components["main"]["state"] == OTA_STATE_DOWNLOADING

    ota.mark_idle("main", new_version="2.0.0")
    assert ota._components["main"]["state"] == OTA_STATE_IDLE
    assert ota._components["main"]["version"] == "2.0.0"


# ===========================================================================
# OTAService – component stream downlink
# ===========================================================================

def _make_stream_downlink(path, content_type, data):
    """Build a Pouch payload with a single-fragment stream block."""
    header = encode_header("gw")
    # Stream id = 1, first=True, last=True for a single-fragment stream
    block = Block(stream_id=1, is_first=True, is_last=True)
    block.write(encode_stream_first(path, content_type, data))
    return header + block.encode()


def test_ota_component_stream_fires_data_callback():
    """A firmware component stream should invoke the on_component_data callback."""
    p = Pouch("dev")
    ota = OTAService(p)
    received = []

    @ota.on_component_data
    def got_data(pkg, ver, offset, data, is_last):
        received.append((pkg, ver, offset, data, is_last))

    raw = _make_stream_downlink(
        "/.u/c/main@2.0.0", CONTENT_TYPE_CBOR, b"\xde\xad\xbe\xef"
    )
    p.handle_downlink(raw)

    assert len(received) == 1
    pkg, ver, offset, data, is_last = received[0]
    assert pkg == "main"
    assert ver == "2.0.0"
    assert offset == 0
    assert data == b"\xde\xad\xbe\xef"
    assert is_last is True


def test_ota_component_stream_tracks_offset():
    """Subsequent stream blocks should report increasing offsets."""
    p = Pouch("dev")
    ota = OTAService(p)
    received = []

    @ota.on_component_data
    def got_data(pkg, ver, offset, data, is_last):
        received.append((offset, data, is_last))

    # First block (stream_id=2, first=True, last=False)
    header = encode_header("gw")
    b1 = Block(stream_id=2, is_first=True, is_last=False)
    b1.write(encode_stream_first("/.u/c/main@1.1.0", CONTENT_TYPE_CBOR, b"AAAA"))
    # Second block (stream_id=2, first=False, last=True)
    b2 = Block(stream_id=2, is_first=False, is_last=True)
    b2.write(b"BBBB")
    raw = header + b1.encode() + b2.encode()
    p.handle_downlink(raw)

    assert len(received) == 2
    assert received[0] == (0, b"AAAA", False)
    assert received[1] == (4, b"BBBB", True)


# ===========================================================================
# Service co-existence: multiple services on the same Pouch instance
# ===========================================================================

def test_multiple_services_on_same_pouch():
    """Multiple services should co-exist without interfering."""
    p = Pouch("dev")
    log = LogService(p)
    svc = SettingsService(p)
    stream = StreamService(p)
    state = StateService(p)
    ota = OTAService(p)
    ota.register_component("main", "1.0.0")

    log.info("app", "boot")
    stream.send("temp", b'{"t":25}')
    state.set("status", b'"ok"')

    entries = _build_uplink(p)
    paths = {e[0] for e in entries}
    # Should contain: .log, .c/status, .s/temp, .d/status, .u/c/main
    assert ".log" in paths
    assert ".c/status" in paths
    assert ".s/temp" in paths
    assert ".d/status" in paths
    assert ".u/c/main" in paths


def test_services_downlinks_do_not_cross_contaminate():
    """Each service should only receive its own downlink paths."""
    p = Pouch("dev")
    settings = SettingsService(p)
    state = StateService(p)

    settings_received = []
    state_received = []

    @settings.handler("K")
    def on_k(v):
        settings_received.append(v)

    @state.observe
    def on_desired(subpath, ct, data):
        state_received.append(subpath)

    raw = _make_downlink([
        ("/.c", CONTENT_TYPE_CBOR, cbor.encode({"settings": {"K": 7}, "version": 1})),
        ("/.d/led", CONTENT_TYPE_JSON, b"1"),
    ])
    p.handle_downlink(raw)

    assert settings_received == [7]
    assert state_received == ["led"]


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
