# SPDX-License-Identifier: Apache-2.0
"""Encrypted BLE GATT Pouch example for MicroPython and OpenMV.

This example shows how to use the ``pouch.mpy`` library with SAEAD encryption
to send sensor data to a Golioth cloud gateway over BLE GATT.

Prerequisites
-------------
1. Build and install the ``pouch_crypto`` native module for your target
   architecture (see ``native/pouch_crypto/README.md``).
2. Pre-provision the device with an EC P-256 private key and X.509 certificate
   in DER format (e.g. via ``mpremote cp``).

Hardware requirements
---------------------
* Any MicroPython board with BLE support (e.g. ESP32, Raspberry Pi Pico W,
  OpenMV Cam H7 Plus, OpenMV Cam RT1062, nRF52840-DK, etc.)

Usage
-----
1. Copy the ``pouch/`` directory and ``pouch_crypto.mpy`` to the board.
2. Copy the device key/cert DER files to the board's filesystem.
3. Edit the configuration constants below.
4. Run: ``mpremote run examples/encrypted_ble_gatt_example.py``

The board will advertise as a Pouch BLE peripheral with SAEAD encryption.
When a gateway connects and pushes its server certificate, encryption is
established automatically.
"""

import time

from pouch import Pouch
from pouch.const import CONTENT_TYPE_JSON, SAEAD_ALG_AES_GCM
from pouch.transport.ble_gatt import BLEGATTTransport

# ---------------------------------------------------------------------------
# Configuration – edit these values
# ---------------------------------------------------------------------------

#: Unique identifier for this device (max 32 ASCII characters).
DEVICE_ID = "encrypted-device-01"

#: BLE advertising name (visible during discovery).
ADVERTISING_NAME = "PouchEncDevice"

#: Path to the device EC private key (32 bytes, raw P-256 scalar, DER/raw).
DEVICE_KEY_PATH = "/device_key.der"

#: Path to the device X.509 certificate (DER format).
DEVICE_CERT_PATH = "/device_cert.der"

#: AEAD algorithm to use (AES-GCM or ChaCha20-Poly1305).
ALGORITHM = SAEAD_ALG_AES_GCM


# ---------------------------------------------------------------------------
# Load device credentials from filesystem
# ---------------------------------------------------------------------------

def load_file(path):
    """Read a binary file from the device filesystem."""
    with open(path, "rb") as f:
        return f.read()


print("Loading device credentials…")
try:
    device_key = load_file(DEVICE_KEY_PATH)
    device_cert = load_file(DEVICE_CERT_PATH)
    print("  Key:  {} bytes".format(len(device_key)))
    print("  Cert: {} bytes".format(len(device_cert)))
except OSError as e:
    print("ERROR: Could not load credentials:", e)
    print("  Ensure {} and {} exist on the device.".format(
        DEVICE_KEY_PATH, DEVICE_CERT_PATH))
    raise SystemExit(1)


# ---------------------------------------------------------------------------
# Application state
# ---------------------------------------------------------------------------

_counter = 0


# ---------------------------------------------------------------------------
# Pouch setup (encrypted mode)
# ---------------------------------------------------------------------------

pouch = Pouch(
    device_id=DEVICE_ID,
    private_key=device_key,
    certificate=device_cert,
    algorithm=ALGORITHM,
)


@pouch.uplink_handler
def collect_data():
    """Called before each uplink session to queue entries."""
    global _counter
    _counter += 1
    payload = '{{"counter": {}, "uptime_ms": {}}}'.format(
        _counter, time.ticks_ms())
    pouch.add_entry(".s/sensor", CONTENT_TYPE_JSON, payload)
    print("[uplink] queued encrypted entry:", payload)


@pouch.downlink_handler
def on_data(path, content_type, data):
    """Called for each decrypted entry received from the gateway."""
    print("[downlink] path={!r} content_type={} data={!r}".format(
        path, content_type, data))


# ---------------------------------------------------------------------------
# Server certificate handler
# ---------------------------------------------------------------------------

def on_server_cert(cert_der):
    """Called when the gateway pushes its server certificate over BLE."""
    print("[crypto] Received server certificate ({} bytes)".format(len(cert_der)))
    pouch.set_server_certificate(cert_der)
    print("[crypto] SAEAD session established")


# ---------------------------------------------------------------------------
# Transport setup
# ---------------------------------------------------------------------------

transport = BLEGATTTransport(
    device_id=DEVICE_ID,
    uplink_handler=pouch.build_uplink,
    downlink_handler=pouch.handle_downlink,
    advertising_name=ADVERTISING_NAME,
    server_cert_handler=on_server_cert,
    device_cert_der=device_cert,
)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("Starting encrypted Pouch BLE GATT peripheral…")
    print("  Device ID:  ", DEVICE_ID)
    print("  Adv. name:  ", ADVERTISING_NAME)
    print("  Algorithm:  ", "AES-GCM" if ALGORITHM == 0 else "ChaCha20-Poly1305")

    transport.start(request_sync=True)

    print("Advertising – waiting for a gateway to connect…")
    print("  The gateway will push its server certificate to establish encryption.")

    while True:
        time.sleep_ms(100)


if __name__ == "__main__":
    main()
