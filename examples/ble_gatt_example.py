# SPDX-License-Identifier: Apache-2.0
"""BLE GATT Pouch example for MicroPython and OpenMV.

This example shows how to use the ``pouch.mpy`` library to send sensor data
to a Golioth cloud gateway over BLE GATT.

Hardware requirements
---------------------
* Any MicroPython board with BLE support (e.g. ESP32, Raspberry Pi Pico W,
  OpenMV Cam H7 Plus, OpenMV Cam RT1062, nRF52840-DK, etc.)

Usage
-----
1. Copy the ``pouch/`` directory to your board's filesystem (e.g. via Thonny
   or ``mpremote``).
2. Edit the ``DEVICE_ID`` constant below.
3. Run this file: ``mpremote run examples/ble_gatt_example.py``

The board will advertise as a Pouch BLE peripheral.  Use the Golioth mobile
app or a Pouch-compatible gateway to connect and sync data.
"""

import time

from pouch import Pouch
from pouch.const import CONTENT_TYPE_JSON
from pouch.transport.ble_gatt import BLEGATTTransport

# ---------------------------------------------------------------------------
# Configuration – edit these values
# ---------------------------------------------------------------------------

#: Unique identifier for this device (max 32 ASCII characters).
DEVICE_ID = "example-device-01"

#: BLE advertising name (visible during discovery).
ADVERTISING_NAME = "PouchDevice"


# ---------------------------------------------------------------------------
# Application state
# ---------------------------------------------------------------------------

# Counter that is sent as part of every uplink session
_counter = 0


# ---------------------------------------------------------------------------
# Pouch setup
# ---------------------------------------------------------------------------

pouch = Pouch(device_id=DEVICE_ID)


@pouch.uplink_handler
def collect_data():
    """Called before each uplink session to queue entries."""
    global _counter
    _counter += 1
    payload = '{{"counter": {}, "uptime_ms": {}}}'.format(_counter, time.ticks_ms())
    pouch.add_entry(".s/sensor", CONTENT_TYPE_JSON, payload)
    print("[uplink] queued entry:", payload)


@pouch.downlink_handler
def on_data(path, content_type, data):
    """Called for each entry received from the gateway."""
    print("[downlink] path={!r} content_type={} data={!r}".format(path, content_type, data))


# ---------------------------------------------------------------------------
# Transport setup
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
    print("Starting Pouch BLE GATT peripheral…")
    print("  Device ID:  ", DEVICE_ID)
    print("  Adv. name:  ", ADVERTISING_NAME)

    # Start BLE, register GATT service, and begin advertising
    transport.start(request_sync=True)

    print("Advertising – waiting for a gateway to connect…")

    # Keep the main loop alive; BLE events are handled via IRQ callbacks.
    while True:
        time.sleep_ms(100)


if __name__ == "__main__":
    main()
