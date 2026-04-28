# SPDX-License-Identifier: Apache-2.0
"""Golioth services example for MicroPython and OpenMV.

Demonstrates all five Golioth application services on top of the Pouch BLE
GATT transport:

* **Logging**  – send structured log messages to Golioth
* **Settings** – receive and acknowledge cloud-pushed settings
* **Stream**   – publish time-series sensor data to LightDB Stream
* **State**    – publish device state and react to desired-state pushes
* **OTA**      – receive OTA manifest, download firmware, and track state

Hardware requirements
---------------------
* Any MicroPython board with BLE support.

Usage
-----
1. Copy the ``pouch/`` directory to your board's filesystem.
2. Edit the configuration constants below.
3. Run: ``mpremote run examples/golioth_services_example.py``
"""

import time

from pouch import Pouch
from pouch.transport.ble_gatt import BLEGATTTransport
from pouch.services.logging import LogService
from pouch.services.settings import SettingsService
from pouch.services.stream import StreamService
from pouch.services.state import StateService
from pouch.services.ota import OTAService, OTA_STATE_DOWNLOADING

# ---------------------------------------------------------------------------
# Configuration – edit these values
# ---------------------------------------------------------------------------

DEVICE_ID = "example-device-01"
ADVERTISING_NAME = "PouchDevice"

# Simulated current firmware version for OTA tracking
CURRENT_FW_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Application state
# ---------------------------------------------------------------------------

_led_on = False
_loop_delay_s = 5
_counter = 0

# ---------------------------------------------------------------------------
# Pouch + services setup
# ---------------------------------------------------------------------------

pouch = Pouch(device_id=DEVICE_ID)
log = LogService(pouch)
settings = SettingsService(pouch)
stream = StreamService(pouch)
state = StateService(pouch)
ota = OTAService(pouch)

# Register the "main" firmware component so OTA status is included in uplinks
ota.register_component("main", current_version=CURRENT_FW_VERSION)


# ---------------------------------------------------------------------------
# Settings handlers – called when the cloud pushes a new value
# ---------------------------------------------------------------------------

@settings.handler("LOOP_DELAY_S")
def on_loop_delay(value):
    global _loop_delay_s
    _loop_delay_s = int(value)
    log.info("settings", "LOOP_DELAY_S = {}".format(_loop_delay_s))
    print("[settings] LOOP_DELAY_S =", _loop_delay_s)


@settings.handler("LED_ON")
def on_led_on(value):
    global _led_on
    _led_on = bool(value)
    log.info("settings", "LED_ON = {}".format(_led_on))
    print("[settings] LED_ON =", _led_on)


# ---------------------------------------------------------------------------
# LightDB State – react to desired state from the cloud
# ---------------------------------------------------------------------------

@state.observe
def on_desired(subpath, content_type, data):
    print("[state] desired change: {} = {!r}".format(subpath, data))
    log.debug("state", "desired: {}".format(subpath))


# ---------------------------------------------------------------------------
# OTA handlers – called when a firmware manifest or data chunk arrives
# ---------------------------------------------------------------------------

@ota.on_manifest
def on_ota_manifest(components):
    print("[ota] manifest received:")
    for c in components:
        print("  package={} version={} size={}".format(
            c["package"], c["version"], c["size"]
        ))
        # Request download for the "main" component
        if c["package"] == "main" and c["version"] != CURRENT_FW_VERSION:
            print("[ota] requesting download for main@{}".format(c["version"]))
            ota.mark_downloading("main")


@ota.on_component_data
def on_firmware_chunk(package, version, offset, data, is_last):
    print("[ota] {} chunk: offset={} len={} last={}".format(
        package, offset, len(data), is_last
    ))
    # Write to flash: write_flash(offset, data)
    if is_last:
        print("[ota] download complete for {}@{}".format(package, version))
        ota.mark_idle("main", new_version=version)


# ---------------------------------------------------------------------------
# Uplink handler – called before each uplink session
# ---------------------------------------------------------------------------

@pouch.uplink_handler
def collect_data():
    """Queue sensor data for the next uplink."""
    global _counter
    _counter += 1

    # LightDB Stream: time-series sensor reading
    payload = '{{"counter": {}, "uptime_ms": {}}}'.format(
        _counter, time.ticks_ms()
    )
    stream.send("sensor", payload)

    # LightDB State: publish current device state
    state.set("status", '{{"led": {}, "counter": {}}}'.format(
        "true" if _led_on else "false", _counter
    ))

    print("[uplink] queued sensor + state entries (counter={})".format(_counter))


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------

transport = BLEGATTTransport(
    device_id=DEVICE_ID,
    uplink_handler=pouch.build_uplink,
    downlink_handler=pouch.handle_downlink,
    advertising_name=ADVERTISING_NAME,
)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("Starting Golioth services example…")
    print("  Device ID:  ", DEVICE_ID)
    print("  FW version: ", CURRENT_FW_VERSION)

    log.info("app", "Device started, FW={}".format(CURRENT_FW_VERSION))

    transport.start(request_sync=True)
    print("Advertising – waiting for gateway…")

    while True:
        time.sleep_ms(_loop_delay_s * 1000)


if __name__ == "__main__":
    main()
