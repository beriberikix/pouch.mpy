# pouch.mpy

A Python-native implementation of the [Pouch protocol](https://github.com/golioth/pouch) for
MicroPython and OpenMV.  Pouch is a non-IP protocol for communication between IoT devices and
cloud services, typically through one or more BLE gateways.

> **Caution** – This library is under active development and breaking changes may be introduced
> at any time.

---

## Features

- Pure-Python implementation – no native C extensions required.
- Works on any MicroPython board with BLE support (ESP32, Raspberry Pi Pico W, nRF52840, etc.)
  and on OpenMV cameras (H7 Plus, RT1062, …).
- Pluggable transport layer – start with BLE GATT, add more later.
- Minimal CBOR encoder/decoder built-in (no external dependencies). The
  `cbor2` module in `micropython-lib` was evaluated but not adopted: its
  `decode_float16` path raises `NotImplementedError`, and its stream-based
  `loads` API does not expose the byte-offset information that the Pouch
  header parser requires to locate the block payload immediately following
  the CBOR header.
- Tested with standard Python 3 for easy CI integration.

---

## Supported Transports

| Transport  | Status      | Notes                                    |
|------------|-------------|------------------------------------------|
| `ble_gatt` | ✅ Available | BLE peripheral (GATT server) role        |

---

## Architecture

```
┌───────────────────────────────────────────────┐
│                  Application                   │
│  pouch.add_entry(path, content_type, data)    │
│  @pouch.downlink_handler                       │
└────────────────────┬──────────────────────────┘
                     │
┌────────────────────▼──────────────────────────┐
│              Pouch Core  (pouch/)              │
│  header.py  – CBOR header encode/decode        │
│  block.py   – block/entry/stream framing       │
│  cbor.py    – minimal CBOR codec               │
└────────────────────┬──────────────────────────┘
                     │
┌────────────────────▼──────────────────────────┐
│           Transport Layer  (pouch/transport/)  │
│  ble_gatt.py – BLE peripheral + SAR            │
│    • three GATT characteristics                │
│      (uplink / downlink / info)                │
│    • windowed SAR fragmentation                │
└────────────────────┬──────────────────────────┘
                     │ bluetooth (MicroPython)
                     ▼
              BLE Gateway / Cloud
```

### Protocol layers

1. **BLE GATT** – BLE peripheral role; the device advertises and accepts connections from a
   Pouch gateway (central).
2. **SAR** – Segmentation & Reassembly; fragments large payloads across small BLE MTUs using a
   window-based flow-control protocol.
3. **Pouch blocks** – Fixed 3-byte block header (`size_BE16 | id_byte`) followed by payload.
4. **Pouch header** – CBOR-encoded preamble `[version, [encryption_type, device_id]]` prepended
   to every uplink payload.
5. **Entries** – Key/value records packed inside blocks:
   `data_len_BE16 | content_type_BE16 | path_len | path | data`.

---

## BLE GATT UUIDs

| Characteristic | UUID                                   | Direction          |
|----------------|----------------------------------------|--------------------|
| Service        | `89a316ae-89b7-4ef6-b1d3-5c9a6e27d272` | –                  |
| Uplink         | `89a316ae-89b7-4ef6-b1d3-5c9a6e27d273` | device → gateway   |
| Downlink       | `89a316ae-89b7-4ef6-b1d3-5c9a6e27d274` | gateway → device   |
| Info           | `89a316ae-89b7-4ef6-b1d3-5c9a6e27d275` | device → gateway   |

Advertisement service data uses 16-bit UUID **`0xFC49`**.

---

## Quick start

### Installation

**Via mip (MicroPython 1.19.1+, recommended)**

On a board with network access:

```python
import mip
mip.install("github:beriberikix/pouch.mpy")
```

Or from the host with `mpremote`:

```bash
mpremote mip install github:beriberikix/pouch.mpy
```

**Manual installation**

Copy the `pouch/` directory to your board's flash, e.g.:

```bash
mpremote cp -r pouch/ :
```

### Usage

```python
import time
from pouch import Pouch
from pouch.const import CONTENT_TYPE_JSON
from pouch.transport.ble_gatt import BLEGATTTransport

DEVICE_ID = "my-device-01"

pouch = Pouch(device_id=DEVICE_ID)

@pouch.uplink_handler
def collect():
    pouch.add_entry(".s/sensor", CONTENT_TYPE_JSON, '{"temp":22}')

@pouch.downlink_handler
def on_data(path, content_type, data):
    print("Received:", path, data)

transport = BLEGATTTransport(
    device_id=DEVICE_ID,
    uplink_handler=pouch.build_uplink,
    downlink_handler=pouch.handle_downlink,
    advertising_name="MyDevice",
)
transport.start(request_sync=True)

while True:
    time.sleep_ms(100)
```

See `examples/ble_gatt_example.py` for a complete example.

---

## API reference

### `pouch.Pouch`

| Method / property        | Description                                                   |
|--------------------------|---------------------------------------------------------------|
| `Pouch(device_id)`       | Create a Pouch client with the given device identifier.       |
| `device_id`              | Read the device identifier.                                   |
| `@uplink_handler`        | Decorator – register a function called before each uplink.    |
| `@downlink_handler`      | Decorator – register a function called for each received entry.|
| `add_entry(path, ct, d)` | Queue an entry for the next uplink build.                     |
| `build_uplink()`         | Build and return a complete Pouch uplink payload.             |
| `handle_downlink(raw)`   | Parse a raw downlink payload and dispatch to the handler.     |

### `pouch.transport.ble_gatt.BLEGATTTransport`

| Method / argument         | Description                                                  |
|---------------------------|--------------------------------------------------------------|
| `BLEGATTTransport(...)`   | Create the transport; see constructor docstring.             |
| `start(request_sync=True)`| Activate BLE, register service, and begin advertising.       |
| `advertise(request_sync)` | (Re-)start BLE advertising.                                  |
| `stop_advertising()`      | Stop BLE advertising.                                        |

### Content types (`pouch.const`)

| Constant                        | Value | Description            |
|---------------------------------|-------|------------------------|
| `CONTENT_TYPE_OCTET_STREAM`     | 42    | Raw bytes              |
| `CONTENT_TYPE_JSON`             | 50    | JSON-encoded data      |
| `CONTENT_TYPE_CBOR`             | 60    | CBOR-encoded data      |

---

## Running tests

The tests use only the Python standard library and can be run on a desktop Python 3.x
installation:

```bash
python3 tests/test_cbor.py
python3 tests/test_block.py
python3 tests/test_header.py
python3 tests/test_uplink.py
```

---

## License

Apache-2.0 – see [LICENSE](LICENSE).
