# SPDX-License-Identifier: Apache-2.0
"""pouch.mpy – MicroPython implementation of the Pouch protocol.

Pouch is a non-IP protocol for communication between IoT devices and cloud
services, typically through one or more gateways.  This library implements
the *device* side of the protocol.

Quick-start (BLE GATT transport)::

    from pouch import Pouch
    from pouch.transport.ble_gatt import BLEGATTTransport
    from pouch.const import CONTENT_TYPE_JSON

    pouch = Pouch(device_id="my-device-01")

    @pouch.uplink_handler
    def send_sensor_data():
        pouch.add_entry(".s/sensor", CONTENT_TYPE_JSON, b'{"temp":22}')

    @pouch.downlink_handler
    def on_data(path, content_type, data):
        print("Received:", path, data)

    transport = BLEGATTTransport(
        device_id=pouch.device_id,
        uplink_handler=pouch.build_uplink,
        downlink_handler=pouch.handle_downlink,
    )
    transport.start(request_sync=True)
"""

from .header import encode_header, encode_header_saead, decode_header
from .block import Block, encode_entry, decode_entries, decode_stream_first
from .const import (
    BLOCK_ID_ENTRY,
    CONTENT_TYPE_JSON,
    CONTENT_TYPE_CBOR,
    CONTENT_TYPE_OCTET_STREAM,
    ENCRYPTION_NONE,
    ENCRYPTION_SAEAD,
    AUTH_TAG_LEN,
)


class Pouch:
    """Main Pouch device-side client.

    Args:
        device_id:    Unique device identifier (max 32 ASCII characters).
        private_key:  32-byte EC private key (bytes) for SAEAD mode, or *None*
                      for plaintext mode.
        certificate:  DER-encoded X.509 device certificate (bytes) for SAEAD
                      mode, or *None* for plaintext mode.
        algorithm:    AEAD algorithm (default: AES-GCM).  Only used when
                      *private_key* and *certificate* are provided.
    """

    def __init__(self, device_id, private_key=None, certificate=None,
                 algorithm=None):
        self._device_id = device_id
        self._pending_entries = []   # list of (path, content_type, data)
        self._uplink_cb = None       # registered by @uplink_handler
        self._downlink_cb = None     # registered by @downlink_handler

        # Service hooks (used by pouch.services.* modules)
        self._service_uplink_cbs = []
        self._service_entry_handlers = []
        self._service_stream_handlers = []
        self._active_streams = {}

        # SAEAD encryption state
        self._private_key = private_key
        self._certificate = certificate
        self._algorithm = algorithm
        self._uplink_session = None    # UplinkSession instance
        self._downlink_session = None  # DownlinkSession instance

        if private_key is not None and certificate is not None:
            if algorithm is None:
                from .const import SAEAD_ALG_AES_GCM
                self._algorithm = SAEAD_ALG_AES_GCM

    @property
    def device_id(self):
        """The device identifier."""
        return self._device_id

    @property
    def encrypted(self):
        """True when SAEAD encryption is configured."""
        return self._private_key is not None

    def set_server_certificate(self, cert_der):
        """Set the server certificate received over BLE.

        This triggers SAEAD session establishment (ECDH + key derivation).
        Must be called before :meth:`build_uplink` in encrypted mode.

        Args:
            cert_der: DER-encoded X.509 server certificate bytes.
        """
        if not self.encrypted:
            return
        from .crypto.cert import extract_ec_pubkey
        from .crypto.uplink import UplinkSession
        from .crypto.downlink import DownlinkSession

        server_pubkey = extract_ec_pubkey(cert_der)
        self._uplink_session = UplinkSession(
            self._private_key, self._certificate, server_pubkey,
            self._algorithm,
        )
        self._downlink_session = DownlinkSession(
            self._private_key, server_pubkey,
        )

    def clear_session(self):
        """Clear the current SAEAD session (e.g. on BLE disconnect)."""
        self._uplink_session = None
        self._downlink_session = None

    # ------------------------------------------------------------------
    # Service registration (called by pouch.services.* constructors)
    # ------------------------------------------------------------------

    def _register_service_uplink(self, callback):
        """Register an internal service uplink data provider.

        *callback* is called with no arguments during :meth:`build_uplink` and
        should call :meth:`add_entry` to queue its entries.
        """
        self._service_uplink_cbs.append(callback)

    def _register_service_entry_handler(self, path, callback, prefix=False):
        """Register a service handler for entry-block downlinks.

        Args:
            path:     Downlink path to match (e.g. ``"/.c"``).
            callback: ``(path: str, content_type: int, data: bytes) -> None``.
            prefix:   When *True*, match any path that *starts* with *path*.
        """
        self._service_entry_handlers.append((path, prefix, callback))

    def _register_service_stream_handler(self, path, callback, prefix=False):
        """Register a service handler for stream-block downlinks.

        Args:
            path:     Downlink path prefix to match (e.g. ``"/.u/c/"``).
            callback: ``(path: str, content_type: int, data: bytes,
                         is_last: bool) -> None``.
            prefix:   When *True*, match any path that *starts* with *path*.
        """
        self._service_stream_handlers.append((path, prefix, callback))

    # ------------------------------------------------------------------
    # Decorator-style handler registration (application API)
    # ------------------------------------------------------------------

    def uplink_handler(self, func):
        """Decorator that registers *func* as the uplink data provider.

        The decorated function is called with no arguments before each uplink
        session.  It should call :meth:`add_entry` (or
        :meth:`add_stream_entry`) to queue entries, then return.

        Example::

            @pouch.uplink_handler
            def send_data():
                pouch.add_entry(".s/sensor", CONTENT_TYPE_JSON, b'{"v":1}')
        """
        self._uplink_cb = func
        return func

    def downlink_handler(self, func):
        """Decorator that registers *func* as the downlink data consumer.

        The decorated function is called with ``(path: str, content_type: int,
        data: bytes)`` for each entry received from the gateway.

        Example::

            @pouch.downlink_handler
            def on_data(path, content_type, data):
                print(path, data)
        """
        self._downlink_cb = func
        return func

    # ------------------------------------------------------------------
    # Uplink entry queuing
    # ------------------------------------------------------------------

    def add_entry(self, path, content_type, data):
        """Queue a single entry for the next uplink session.

        Args:
            path:         Destination path string (e.g. ``".s/sensor"``).
            content_type: One of :data:`~pouch.const.CONTENT_TYPE_JSON`,
                          :data:`~pouch.const.CONTENT_TYPE_CBOR`, or
                          :data:`~pouch.const.CONTENT_TYPE_OCTET_STREAM`.
            data:         Payload as ``bytes``, ``bytearray``, or ``str``.
        """
        if isinstance(data, str):
            data = data.encode("utf-8")
        self._pending_entries.append((path, content_type, bytes(data)))

    # ------------------------------------------------------------------
    # Uplink build
    # ------------------------------------------------------------------

    def build_uplink(self):
        """Build a complete Pouch uplink payload.

        Calls the registered *uplink_handler* (if any), then serialises all
        queued entries into a header + block payload.  If SAEAD encryption is
        active, each block payload is encrypted.

        Returns:
            Bytes containing the complete Pouch uplink payload, or *None* if
            there are no entries to send.
        """
        # Let the application queue entries
        if self._uplink_cb:
            self._uplink_cb()

        # Let each registered service queue its own entries
        for svc_cb in self._service_uplink_cbs:
            svc_cb()

        if not self._pending_entries:
            return None

        # Pack all entries into a single entry block
        block = Block(stream_id=BLOCK_ID_ENTRY, is_first=True, is_last=True)
        for path, content_type, data in self._pending_entries:
            block.write(encode_entry(path, content_type, data))

        # Clear queue after building
        self._pending_entries = []

        if self._uplink_session is not None:
            # SAEAD mode: encrypted header + encrypted block
            header = self._uplink_session.start_pouch()
            raw_payload = block.payload
            encrypted_payload = self._uplink_session.encrypt_block(raw_payload)
            # Rebuild block with encrypted payload
            enc_block = Block(stream_id=BLOCK_ID_ENTRY, is_first=True,
                              is_last=True)
            enc_block.write(encrypted_payload)
            return header + enc_block.encode()
        else:
            # Plaintext mode
            header = encode_header(self._device_id)
            return header + block.encode()

    # ------------------------------------------------------------------
    # Downlink parsing
    # ------------------------------------------------------------------

    def handle_downlink(self, raw):
        """Parse a raw Pouch downlink payload and dispatch entries.

        Handles both plaintext and SAEAD-encrypted payloads.

        Args:
            raw: Complete Pouch payload bytes received from the gateway.
        """
        try:
            info, enc_type, header_len = decode_header(raw)
        except ValueError:
            return

        offset = header_len

        if enc_type == ENCRYPTION_SAEAD:
            if self._downlink_session is None:
                return  # no session established, drop
            session = self._downlink_session.begin_pouch(info)
            pouch_id = info["pouch_id"]
            sender_role = info["initiator"]
            # For server-initiated downlinks, sender is server
            from .const import POUCH_ROLE_SERVER
            while offset < len(raw):
                block, consumed = Block.decode(raw, offset)
                if block is None or consumed == 0:
                    break
                offset += consumed
                try:
                    plaintext = session.decrypt_block(
                        pouch_id, POUCH_ROLE_SERVER,
                        block.payload,
                    )
                except ValueError:
                    return  # auth failure, drop entire pouch
                # Replace block payload with decrypted data
                block._payload = bytearray(plaintext)
                if not block.is_stream:
                    for path, content_type, data in decode_entries(block.payload):
                        self._dispatch_entry(path, content_type, data)
                else:
                    self._dispatch_stream(block)
        else:
            # Plaintext mode
            while offset < len(raw):
                block, consumed = Block.decode(raw, offset)
                if block is None or consumed == 0:
                    break
                offset += consumed
                if not block.is_stream:
                    for path, content_type, data in decode_entries(block.payload):
                        self._dispatch_entry(path, content_type, data)
                else:
                    self._dispatch_stream(block)

    def _dispatch_entry(self, path, content_type, data):
        """Route an entry-block item to a service handler or the app callback."""
        for svc_path, prefix, cb in self._service_entry_handlers:
            if prefix:
                if path.startswith(svc_path):
                    cb(path, content_type, data)
                    return
            else:
                if path == svc_path:
                    cb(path, content_type, data)
                    return
        # No service claimed it – forward to application handler
        if self._downlink_cb:
            self._downlink_cb(path, content_type, data)

    def _dispatch_stream(self, block):
        """Route a stream block to a service handler or the app callback."""
        stream_id = block.stream_id

        if block.is_first:
            try:
                path, content_type, data = decode_stream_first(block.payload)
            except ValueError:
                return
            is_last = block.is_last

            # Find a service stream handler
            handler = None
            for svc_path, prefix, cb in self._service_stream_handlers:
                if prefix:
                    if path.startswith(svc_path):
                        handler = cb
                        break
                else:
                    if path == svc_path:
                        handler = cb
                        break

            self._active_streams[stream_id] = (path, content_type, handler)

            if handler:
                handler(path, content_type, data, is_last)
            elif self._downlink_cb and data:
                self._downlink_cb(path, content_type, data)

            if is_last:
                self._active_streams.pop(stream_id, None)

        else:
            if stream_id not in self._active_streams:
                return
            path, content_type, handler = self._active_streams[stream_id]
            is_last = block.is_last

            if handler:
                handler(path, content_type, block.payload, is_last)
            elif self._downlink_cb and block.payload:
                self._downlink_cb("", 0, block.payload)

            if is_last:
                self._active_streams.pop(stream_id, None)
