# SPDX-License-Identifier: Apache-2.0
"""Golioth OTA (Over-the-Air firmware update) service.

Receives OTA manifests and firmware component data from the Golioth cloud and
reports component state on every uplink.

Wire format
-----------
**Manifest downlink** (path ``/.u/desired``, content type CBOR, entry block):

    CBOR map with integer keys::

        {
            1: <sequence_number: uint>,   // MANIFEST_KEY_SEQUENCE_NUMBER
            3: [                           // MANIFEST_KEY_COMPONENTS
                {
                    1: <package: tstr>,    // COMPONENT_KEY_PACKAGE
                    2: <version: tstr>,    // COMPONENT_KEY_VERSION
                    3: <hash_hex: tstr>,   // COMPONENT_KEY_HASH (64-char hex)
                    4: <size: uint>,       // COMPONENT_KEY_SIZE
                },
                ...
            ]
        }

**Component data downlink** (path ``/.u/c/<package>@<version>``, stream block):

    Raw binary firmware bytes delivered as a stream.  The first stream block
    carries the path; subsequent blocks carry continuation data.

**Status uplink** (path ``.u/c/<package>``, content type CBOR, per component):

    CBOR map::

        {
            "s":   <state: uint 0–3>,
            "r":   0,
            "pkg": <package: tstr>,
            "v":   <current_version: tstr>,
            "t":   <target_version: tstr>,  // omitted when state == IDLE
        }

    States: ``0`` = IDLE, ``1`` = DOWNLOADING, ``2`` = DOWNLOADED,
    ``3`` = UPDATING.

OTA state machine
-----------------
When the cloud pushes a manifest the :attr:`~OTAService.on_manifest` callback
fires.  Call :meth:`~OTAService.mark_downloading` to transition a component to
the DOWNLOADING state and start receiving its binary stream.  After all bytes
have arrived :attr:`~OTAService.on_component_data` fires with ``is_last=True``.
Call :meth:`~OTAService.mark_downloaded` or :meth:`~OTAService.mark_updating`
as appropriate.  Call :meth:`~OTAService.mark_idle` once the update is
complete.

Example::

    from pouch import Pouch
    from pouch.services.ota import OTAService, OTA_STATE_DOWNLOADING

    pouch = Pouch(device_id="dev-01")
    ota = OTAService(pouch)

    @ota.on_manifest
    def manifest_received(components):
        for c in components:
            print("OTA component:", c["package"], c["version"], c["size"])
            ota.mark_downloading(c["package"])

    @ota.on_component_data
    def firmware_chunk(package, version, offset, data, is_last):
        write_flash(offset, data)
        if is_last:
            ota.mark_downloaded(package)
"""

from .. import cbor
from ..const import CONTENT_TYPE_CBOR

# Manifest integer keys
_MANIFEST_KEY_SEQUENCE = 1
_MANIFEST_KEY_COMPONENTS = 3

# Component map integer keys
_COMPONENT_KEY_PACKAGE = 1
_COMPONENT_KEY_VERSION = 2
_COMPONENT_KEY_HASH = 3
_COMPONENT_KEY_SIZE = 4

# Golioth paths
_MANIFEST_DOWNLINK_PATH = "/.u/desired"
_COMPONENT_DOWNLINK_PREFIX = "/.u/c/"
_COMPONENT_UPLINK_PREFIX = ".u/c/"

# OTA states
OTA_STATE_IDLE = 0
OTA_STATE_DOWNLOADING = 1
OTA_STATE_DOWNLOADED = 2
OTA_STATE_UPDATING = 3


class OTAService:
    """Golioth OTA firmware update service.

    Registers itself with *pouch* to receive OTA manifests and firmware
    component streams, and to include per-component status on every uplink.

    Args:
        pouch: The :class:`~pouch.Pouch` instance to attach to.
    """

    def __init__(self, pouch):
        self._pouch = pouch
        self._manifest_cb = None      # on_manifest(components: list[dict])
        self._data_cb = None          # on_component_data(pkg, ver, offset, data, is_last)

        # Registered components: package -> {"version": str, "state": int,
        #                                    "target": str, "size": int}
        self._components = {}

        # Active component download: tracks (package, version, offset) by stream
        self._active_download = None  # (package, version, offset)

        pouch._register_service_uplink(self._on_uplink)
        pouch._register_service_entry_handler(
            _MANIFEST_DOWNLINK_PATH, self._on_manifest_downlink
        )
        pouch._register_service_stream_handler(
            _COMPONENT_DOWNLINK_PREFIX, self._on_component_stream, prefix=True
        )

    # ------------------------------------------------------------------
    # Public API – callback registration
    # ------------------------------------------------------------------

    def on_manifest(self, func):
        """Decorator that registers *func* as the manifest-received callback.

        The callback receives a list of component dicts, each with keys
        ``"package"``, ``"version"``, ``"hash"`` (bytes), and ``"size"``::

            @ota.on_manifest
            def got_manifest(components):
                for c in components:
                    print(c["package"], c["version"])
        """
        self._manifest_cb = func
        return func

    def on_component_data(self, func):
        """Decorator that registers *func* as the firmware-data callback.

        The callback receives ``(package: str, version: str, offset: int,
        data: bytes, is_last: bool)``::

            @ota.on_component_data
            def got_data(pkg, ver, offset, data, is_last):
                flash.write(offset, data)
        """
        self._data_cb = func
        return func

    # ------------------------------------------------------------------
    # Public API – state management
    # ------------------------------------------------------------------

    def register_component(self, package, current_version=""):
        """Register a firmware component tracked by this device.

        Must be called before OTA uplinks will include status for this
        component.

        Args:
            package:         Package name (e.g. ``"main"``).
            current_version: Currently installed version string.
        """
        if package not in self._components:
            self._components[package] = {
                "version": current_version,
                "state": OTA_STATE_IDLE,
                "target": "",
                "size": 0,
            }

    def mark_downloading(self, package):
        """Transition *package* to the DOWNLOADING state."""
        self._set_state(package, OTA_STATE_DOWNLOADING)

    def mark_downloaded(self, package):
        """Transition *package* to the DOWNLOADED state."""
        self._set_state(package, OTA_STATE_DOWNLOADED)

    def mark_updating(self, package):
        """Transition *package* to the UPDATING state."""
        self._set_state(package, OTA_STATE_UPDATING)

    def mark_idle(self, package, new_version=None):
        """Transition *package* back to IDLE.

        Args:
            package:     Package name.
            new_version: If provided, update the recorded current version.
        """
        self._set_state(package, OTA_STATE_IDLE)
        if new_version is not None and package in self._components:
            self._components[package]["version"] = new_version

    def _set_state(self, package, state):
        if package not in self._components:
            self._components[package] = {
                "version": "",
                "state": state,
                "target": "",
                "size": 0,
            }
        else:
            self._components[package]["state"] = state

    # ------------------------------------------------------------------
    # Internal service callbacks
    # ------------------------------------------------------------------

    def _on_uplink(self):
        """Add per-component OTA status entries to the pending uplink queue."""
        for package, info in self._components.items():
            state = info["state"]
            payload = {
                "s": state,
                "r": 0,
                "pkg": package,
                "v": info["version"],
            }
            if state != OTA_STATE_IDLE:
                payload["t"] = info["target"]
            self._pouch.add_entry(
                _COMPONENT_UPLINK_PREFIX + package,
                CONTENT_TYPE_CBOR,
                cbor.encode(payload),
            )

    def _on_manifest_downlink(self, path, content_type, data):
        """Parse an OTA manifest downlink entry."""
        try:
            manifest, _ = cbor.decode(data)
        except Exception:
            return

        if not isinstance(manifest, dict):
            return

        components_raw = manifest.get(_MANIFEST_KEY_COMPONENTS)
        if not isinstance(components_raw, list):
            return

        components = []
        for item in components_raw:
            if not isinstance(item, dict):
                continue
            package = item.get(_COMPONENT_KEY_PACKAGE, "")
            version = item.get(_COMPONENT_KEY_VERSION, "")
            hash_hex = item.get(_COMPONENT_KEY_HASH, "")
            size = item.get(_COMPONENT_KEY_SIZE, 0)

            # Decode hex hash string to bytes
            try:
                hash_bytes = _hex_to_bytes(hash_hex)
            except Exception:
                hash_bytes = b""

            # Record target version for any already-registered component
            if package in self._components:
                self._components[package]["target"] = version
                self._components[package]["size"] = size

            components.append({
                "package": package,
                "version": version,
                "hash": hash_bytes,
                "size": size,
            })

        if self._manifest_cb is not None and components:
            try:
                self._manifest_cb(components)
            except Exception:
                pass

    def _on_component_stream(self, path, content_type, data, is_last):
        """Handle a firmware component stream block."""
        # path example: "/.u/c/main@1.2.0"
        # Extract package and version from path
        remainder = path[len(_COMPONENT_DOWNLINK_PREFIX):]
        at_pos = remainder.find("@")
        if at_pos >= 0:
            package = remainder[:at_pos]
            version = remainder[at_pos + 1:]
        else:
            package = remainder
            version = ""

        if self._active_download is None:
            # First block – start a new download
            offset = 0
        else:
            # Continuation block
            pkg, ver, offset = self._active_download
            # Guard: if path changed unexpectedly, reset
            if pkg != package:
                self._active_download = None
                offset = 0

        if self._data_cb is not None and data:
            try:
                self._data_cb(package, version, offset, data, is_last)
            except Exception:
                pass

        new_offset = offset + len(data)
        if is_last:
            self._active_download = None
        else:
            self._active_download = (package, version, new_offset)


# ---------------------------------------------------------------------------
# Hex decode helper (no binascii dependency for MicroPython compatibility)
# ---------------------------------------------------------------------------

def _hex_to_bytes(hex_str):
    """Decode a hex string to bytes without using binascii."""
    if len(hex_str) % 2 != 0:
        raise ValueError("odd-length hex string")
    result = bytearray(len(hex_str) // 2)
    for i in range(len(result)):
        high = _nibble(hex_str[i * 2])
        low = _nibble(hex_str[i * 2 + 1])
        result[i] = (high << 4) | low
    return bytes(result)


def _nibble(c):
    """Convert a single hex character to its integer value."""
    o = ord(c)
    if 48 <= o <= 57:   # '0'-'9'
        return o - 48
    if 65 <= o <= 70:   # 'A'-'F'
        return o - 55
    if 97 <= o <= 102:  # 'a'-'f'
        return o - 87
    raise ValueError("invalid hex character: {!r}".format(c))
