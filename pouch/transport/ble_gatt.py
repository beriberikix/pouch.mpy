# SPDX-License-Identifier: Apache-2.0
"""BLE GATT transport for Pouch.

Implements the Pouch BLE GATT transport protocol as a BLE *peripheral*
(GATT server) that connects to a Pouch gateway (central/GATT client).

Protocol overview
-----------------
Three GATT characteristics share a common SAR (Segmentation & Reassembly)
sub-protocol over BLE notifications/writes:

* **Uplink**   – device sends Pouch data to the gateway
* **Downlink** – gateway sends Pouch data to the device
* **Info**     – device sends device-info CBOR to the gateway

All three characteristics carry the WRITE + NOTIFY properties:
  - WRITE  is used by the *receiver* side to send ACK/NACK packets.
  - NOTIFY is used by the *sender* side to send data fragments.

SAR packet formats
------------------
TX (sender→receiver) data packet::

    [flags (1 B)] [seq (1 B)] [payload ...]

TX FIN packet::

    [FIN(0x04) (1 B)] [code (1 B)]

RX (receiver→sender) ACK packet::

    [code (1 B)] [seq (1 B)] [window (1 B)]

Advertisement
-------------
The device advertises with service data attached to the 16-bit Pouch UUID
(0xFC49)::

    [UUID_16 LE (2 B)] [version (1 B)] [flags (1 B)]

The *sync-request* flag (bit 0 of *flags*) is set when the device wants to
connect to a gateway.

Compatibility
-------------
Designed for MicroPython ``bluetooth`` module (≥ v1.15) and OpenMV.
"""

import struct
try:
    import bluetooth
except ImportError:
    bluetooth = None  # allow import in test environments without hardware

from . import Transport
from ..const import (
    POUCH_VERSION,
    POUCH_GATT_VERSION,
    GATT_SERVICE_UUID,
    GATT_UPLINK_UUID,
    GATT_DOWNLINK_UUID,
    GATT_INFO_UUID,
    GATT_SERVER_CERT_UUID,
    GATT_DEVICE_CERT_UUID,
    GATT_ADV_UUID_16,
    GATT_ADV_FLAG_SYNC_REQUEST,
    GATT_ADV_VERSION_POUCH_SHIFT,
    GATT_ADV_VERSION_SELF_SHIFT,
    FLAG_WRITE,
    FLAG_NOTIFY,
    SAR_TX_PKT_HEADER_LEN,
    SAR_RX_PKT_LEN,
    SAR_SEQ_MAX,
    SAR_SEQ_MASK,
    SAR_WINDOW_MAX,
    SAR_WINDOW_DEFAULT,
    SAR_FLAG_FIRST,
    SAR_FLAG_LAST,
    SAR_FLAG_FIN,
    SAR_CODE_ACK,
    SAR_CODE_NACK_UNKNOWN,
    SAR_CODE_NACK_IDLE,
)
from .. import cbor

# BLE IRQ event constants (same as micropython-lib bluetooth module)
_IRQ_CENTRAL_CONNECT = 1
_IRQ_CENTRAL_DISCONNECT = 2
_IRQ_GATTS_WRITE = 3


# ---------------------------------------------------------------------------
# SAR Sender
# ---------------------------------------------------------------------------

class _SARSender:
    """Sends a complete payload via windowed SAR fragmentation.

    Usage::

        sender = _SARSender(notify_fn, maxlen=20)
        sender.start(payload_bytes)          # queue payload
        sender.on_ack(ack_bytes)             # call from IRQ on each ACK write
    """

    _STATE_IDLE = 0
    _STATE_READY = 1
    _STATE_ACTIVE = 2
    _STATE_FIN = 3

    def __init__(self, notify_fn, maxlen=20):
        self._notify = notify_fn
        self._maxlen = maxlen
        self._state = self._STATE_IDLE
        self._data = None
        self._offset = 0
        self._seq = 0
        self._window = 0
        self._on_done = None

    def start(self, data, on_done=None):
        """Begin sending *data*.  *on_done(success: bool)* is called on completion."""
        self._data = data
        self._offset = 0
        self._seq = 0
        self._window = 0
        self._state = self._STATE_READY
        self._on_done = on_done
        # Sending begins when the first ACK arrives from the receiver.

    def on_ack(self, buf):
        """Process an ACK/NACK packet written by the remote receiver."""
        if len(buf) != SAR_RX_PKT_LEN:
            return

        code = buf[0]
        ack_seq = buf[1]
        window = buf[2]

        if code != SAR_CODE_ACK:
            self._state = self._STATE_IDLE
            if self._on_done:
                self._on_done(False)
            return

        if window > SAR_WINDOW_MAX:
            self._state = self._STATE_IDLE
            if self._on_done:
                self._on_done(False)
            return

        self._window = (ack_seq + window + 1) & SAR_SEQ_MASK

        if self._state in (self._STATE_ACTIVE, self._STATE_READY):
            self._push_fragments()
        elif self._state == self._STATE_FIN:
            # All data acknowledged – send FIN if last ack covers all sent
            if ((ack_seq + 1) & SAR_SEQ_MASK) == self._seq:
                self._send_fin()

    def _push_fragments(self):
        """Send fragments up to the current window."""
        while self._seq != self._window and self._data is not None:
            payload_max = self._maxlen - SAR_TX_PKT_HEADER_LEN
            start = self._offset
            end = min(start + payload_max, len(self._data))
            chunk = self._data[start:end]
            is_last = (end >= len(self._data))

            flags = 0
            if self._state == self._STATE_READY:
                flags |= SAR_FLAG_FIRST
            if is_last:
                flags |= SAR_FLAG_LAST

            pkt = bytes([flags, self._seq]) + bytes(chunk)
            try:
                self._notify(pkt)
            except Exception:
                return

            self._offset = end
            self._seq = (self._seq + 1) & SAR_SEQ_MASK
            self._state = self._STATE_ACTIVE

            if is_last:
                self._state = self._STATE_FIN
                return

    def _send_fin(self):
        """Send a FIN control packet."""
        idle = (self._state == self._STATE_IDLE)
        code = SAR_CODE_NACK_IDLE if idle else SAR_CODE_ACK
        pkt = bytes([SAR_FLAG_FIN, code])
        try:
            self._notify(pkt)
        except Exception:
            pass
        self._state = self._STATE_IDLE
        if self._on_done:
            self._on_done(True)


# ---------------------------------------------------------------------------
# SAR Receiver
# ---------------------------------------------------------------------------

class _SARReceiver:
    """Receives a payload via windowed SAR reassembly.

    Usage::

        def got_data(chunk, is_last):
            ...

        receiver = _SARReceiver(notify_fn, got_data, window=4, maxlen=20)
        receiver.open()                # call when CCC enabled (session start)
        receiver.on_rx(raw_bytes)      # call from IRQ on each write
    """

    _STATE_IDLE = 0
    _STATE_ACTIVE = 1
    _STATE_FAILED = 2

    def __init__(self, notify_fn, data_cb, window=SAR_WINDOW_DEFAULT, maxlen=20):
        self._notify = notify_fn
        self._data_cb = data_cb
        self._window = window
        self._maxlen = maxlen
        self._state = self._STATE_IDLE
        self._seq = SAR_SEQ_MAX

    def open(self):
        """Start a receive session and send the initial ACK."""
        self._seq = SAR_SEQ_MAX
        self._state = self._STATE_ACTIVE
        self._send_ack()

    def on_rx(self, buf):
        """Process a raw TX packet written by the remote sender."""
        if len(buf) < SAR_TX_PKT_HEADER_LEN:
            return

        flag_mask = SAR_FLAG_FIRST | SAR_FLAG_LAST | SAR_FLAG_FIN
        flags = buf[0] & flag_mask

        if flags & SAR_FLAG_FIN:
            self._state = self._STATE_IDLE
            return

        if self._state != self._STATE_ACTIVE:
            self._state = self._STATE_FAILED
            self._send_ack()
            return

        seq = buf[1]
        data = buf[2:]
        expected = (self._seq + 1) & SAR_SEQ_MASK

        if seq != expected:
            self._state = self._STATE_FAILED
            self._send_ack()
            return

        is_last = bool(flags & SAR_FLAG_LAST)
        try:
            self._data_cb(bytes(data), is_last)
        except Exception:
            self._state = self._STATE_FAILED
            self._send_ack()
            return

        self._seq = seq
        self._send_ack()

    def _send_ack(self):
        """Send an ACK or NACK to the remote sender."""
        code = SAR_CODE_ACK if self._state == self._STATE_ACTIVE else SAR_CODE_NACK_UNKNOWN
        pkt = bytes([code, self._seq, self._window])
        try:
            self._notify(pkt)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# BLE GATT Transport
# ---------------------------------------------------------------------------

class BLEGATTTransport(Transport):
    """Pouch BLE GATT peripheral transport.

    The device advertises as a BLE peripheral with the Pouch GATT service.
    When a gateway connects and enables notifications on the uplink
    characteristic, the transport calls *uplink_handler* to collect the bytes
    to send.  Received downlink data is forwarded to *downlink_handler*.

    Args:
        device_id:         Unique device identifier string (max 32 chars).
        uplink_handler:    Callable ``() -> bytes | None``.  Called when the
                           gateway requests an uplink.  Return the raw Pouch
                           bytes (header + blocks) to transmit, or *None* when
                           there is nothing to send.
        downlink_handler:  Callable ``(data: bytes) -> None``.  Called with
                           the complete reassembled downlink Pouch payload.
        window:            SAR receive window size (default 4).
        advertising_name:  Local device name included in BLE advertisements.
    """

    def __init__(
        self,
        device_id,
        uplink_handler,
        downlink_handler,
        window=SAR_WINDOW_DEFAULT,
        advertising_name="pouch",
        server_cert_handler=None,
        device_cert_der=None,
    ):
        super().__init__()
        self._device_id = device_id
        self._uplink_handler = uplink_handler
        self._downlink_handler = downlink_handler
        self._window = window
        self._advertising_name = advertising_name
        self._server_cert_handler = server_cert_handler
        self._device_cert_der = device_cert_der

        self._ble = None
        self._conn_handle = None
        self._request_sync = False

        # GATT characteristic value handles (set after registration)
        self._h_uplink = None
        self._h_downlink = None
        self._h_info = None
        self._h_server_cert = None
        self._h_device_cert = None

        # SAR state for each endpoint
        self._uplink_sender = None
        self._downlink_receiver = None
        self._info_sender = None

        # Reassembly buffer for downlink
        self._downlink_buf = bytearray()

        # Reassembly buffer for info (unused on sender side but kept for symmetry)
        self._info_buf = bytearray()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self, request_sync=True):
        """Initialise BLE hardware, register the GATT service, and advertise.

        Args:
            request_sync: When *True* the advertisement sets the sync-request
                          flag, signalling to gateways that this device wants
                          to sync.
        """
        if bluetooth is None:
            raise RuntimeError("bluetooth module not available")

        self._request_sync = request_sync
        self._ble = bluetooth.BLE()
        self._ble.active(True)
        self._ble.irq(self._irq)
        self._register_services()
        self.advertise(request_sync)

    def advertise(self, request_sync=True):
        """Start or update BLE advertisements.

        Args:
            request_sync: Advertise the sync-request flag when *True*.
        """
        if self._ble is None:
            return
        self._request_sync = request_sync
        adv_data = self._build_adv_data(request_sync)
        # 100 ms advertising interval (in units of 625 µs → 160)
        self._ble.gap_advertise(160000, adv_data=adv_data)

    def stop_advertising(self):
        """Stop BLE advertisements."""
        if self._ble:
            self._ble.gap_advertise(None)

    def send(self, data):
        """Satisfy a :class:`~pouch.transport.Transport` send request.

        For the BLE GATT transport this queues *data* as the uplink payload.
        The data will be sent when the gateway opens the uplink characteristic.
        """
        # Not used directly; uplink data comes from uplink_handler callback.
        pass

    # ------------------------------------------------------------------
    # BLE advertisement helpers
    # ------------------------------------------------------------------

    def _build_adv_data(self, request_sync):
        """Build the raw BLE advertisement payload."""
        # Flags AD type: LE General Discoverable + BR/EDR Not Supported
        flags = bytes([0x02, 0x01, 0x06])

        # Service data (16-bit UUID) per Bluetooth Core Spec Supplement
        version_byte = (
            (POUCH_VERSION << GATT_ADV_VERSION_POUCH_SHIFT)
            | (POUCH_GATT_VERSION << GATT_ADV_VERSION_SELF_SHIFT)
        )
        sync_flags = GATT_ADV_FLAG_SYNC_REQUEST if request_sync else 0x00
        svc_uuid_le = struct.pack("<H", GATT_ADV_UUID_16)
        svc_data = svc_uuid_le + bytes([version_byte, sync_flags])
        # AD type 0x16 = Service Data – 16-bit UUID
        svc_ad = bytes([len(svc_data) + 1, 0x16]) + svc_data

        # Complete Local Name
        name_bytes = self._advertising_name.encode("utf-8")
        name_ad = bytes([len(name_bytes) + 1, 0x09]) + name_bytes

        return flags + svc_ad + name_ad

    # ------------------------------------------------------------------
    # GATT service registration
    # ------------------------------------------------------------------

    def _register_services(self):
        """Register the Pouch GATT service."""
        _UUID = bluetooth.UUID
        _F = FLAG_WRITE | FLAG_NOTIFY

        chars = [
            (_UUID(GATT_UPLINK_UUID), _F),
            (_UUID(GATT_DOWNLINK_UUID), _F),
            (_UUID(GATT_INFO_UUID), _F),
        ]
        # Add cert exchange characteristics when encryption is configured
        if self._server_cert_handler is not None or self._device_cert_der is not None:
            chars.append((_UUID(GATT_SERVER_CERT_UUID), FLAG_WRITE))
            chars.append((_UUID(GATT_DEVICE_CERT_UUID), FLAG_NOTIFY))

        service = (_UUID(GATT_SERVICE_UUID), chars)
        (handles,) = self._ble.gatts_register_services([service])

        self._h_uplink = handles[0]
        self._h_downlink = handles[1]
        self._h_info = handles[2]
        if len(handles) > 3:
            self._h_server_cert = handles[3]
            self._h_device_cert = handles[4]

        # Build SAR objects bound to their notify functions
        self._uplink_sender = _SARSender(
            lambda pkt: self._ble.gatts_notify(self._conn_handle, self._h_uplink, pkt),
            maxlen=20,
        )
        self._downlink_receiver = _SARReceiver(
            lambda pkt: self._ble.gatts_notify(self._conn_handle, self._h_downlink, pkt),
            self._on_downlink_chunk,
            window=self._window,
        )
        self._info_sender = _SARSender(
            lambda pkt: self._ble.gatts_notify(self._conn_handle, self._h_info, pkt),
            maxlen=20,
        )

    # ------------------------------------------------------------------
    # BLE IRQ handler
    # ------------------------------------------------------------------

    def _irq(self, event, data):
        if event == _IRQ_CENTRAL_CONNECT:
            conn_handle, _addr_type, _addr = data
            self._conn_handle = conn_handle
            self.stop_advertising()
            self._on_connected()

        elif event == _IRQ_CENTRAL_DISCONNECT:
            self._conn_handle = None
            self._on_disconnected()
            # Resume advertising after disconnect
            self.advertise(self._request_sync)

        elif event == _IRQ_GATTS_WRITE:
            conn_handle, attr_handle = data
            val = self._ble.gatts_read(attr_handle)
            self._on_write(attr_handle, bytes(val))

    def _on_connected(self):
        """Called when a central connects."""
        self._downlink_buf = bytearray()
        # Open the downlink receiver so it sends the initial ACK
        if self._downlink_receiver:
            self._downlink_receiver.open()

    def _on_disconnected(self):
        """Called when the central disconnects."""
        self._downlink_buf = bytearray()

    def _on_write(self, handle, data):
        """Route a GATT write to the appropriate SAR handler."""
        if handle == self._h_uplink:
            # Gateway wrote an ACK to the uplink characteristic
            if self._uplink_sender:
                if self._uplink_sender._state == _SARSender._STATE_IDLE:
                    # Initial ACK: collect uplink data and start sending
                    payload = self._uplink_handler() if self._uplink_handler else None
                    if payload:
                        self._uplink_sender.start(
                            payload, on_done=self._on_uplink_done
                        )
                self._uplink_sender.on_ack(data)

        elif handle == self._h_downlink:
            # Gateway sent a downlink data fragment
            if self._downlink_receiver:
                self._downlink_receiver.on_rx(data)

        elif handle == self._h_info:
            # Gateway wrote an ACK to the info characteristic
            if self._info_sender:
                if self._info_sender._state == _SARSender._STATE_IDLE:
                    info_payload = self._build_info_payload()
                    self._info_sender.start(info_payload)
                self._info_sender.on_ack(data)

        elif handle == self._h_server_cert:
            # Gateway pushed server certificate (complete DER in one write
            # or reassembled by BLE stack)
            if self._server_cert_handler:
                self._server_cert_handler(data)

    # ------------------------------------------------------------------
    # Endpoint data handlers
    # ------------------------------------------------------------------

    def _on_downlink_chunk(self, chunk, is_last):
        """Called by the downlink SAR receiver for each reassembled chunk."""
        self._downlink_buf.extend(chunk)
        if is_last and self._downlink_handler:
            try:
                self._downlink_handler(bytes(self._downlink_buf))
            finally:
                self._downlink_buf = bytearray()

    def _on_uplink_done(self, success):
        """Called when the uplink SAR transfer completes."""
        pass  # hook for subclasses / future use

    def _build_info_payload(self):
        """Build the CBOR-encoded device info payload.

        Structure (CBOR map)::

            {
                "flags":           uint,   ; provisioning flags (currently 0)
                "server_cert_snr": bstr,   ; server cert serial (empty = none)
            }
        """
        flags = 0x01 if self._device_cert_der else 0
        info = {"flags": flags, "server_cert_snr": b""}
        return cbor.encode(info)
