# SPDX-License-Identifier: Apache-2.0
"""Golioth Settings service.

Receives Golioth Settings from the cloud and acknowledges them with a version
status on every uplink.

Wire format
-----------
**Downlink** (path ``/.c``, content type CBOR, entry block):

    CBOR map::

        {
            "settings": {
                "KEY_NAME": <bool | int | float | str>,
                ...
            },
            "version": <int>
        }

    If settings is ``null`` (no settings configured) the ``"settings"`` key is
    absent or its value is CBOR ``null``.

**Uplink** (path ``.c/status``, content type CBOR):

    CBOR map reporting the last acknowledged version::

        {"version": <int | null>}

    ``null`` is encoded as CBOR ``null`` when no settings have been received
    yet.

Example::

    from pouch import Pouch
    from pouch.services.settings import SettingsService

    pouch = Pouch(device_id="dev-01")
    settings = SettingsService(pouch)

    @settings.handler("LOOP_DELAY_S")
    def on_loop_delay(value):
        print("Loop delay:", value)

    @settings.handler("ENABLED")
    def on_enabled(value):
        print("Enabled:", value)
"""

from .. import cbor
from ..const import CONTENT_TYPE_CBOR

_DOWNLINK_PATH = "/.c"
_UPLINK_PATH = ".c/status"


class SettingsService:
    """Golioth Settings service.

    Registers itself with *pouch* to receive settings downlinks and to
    automatically include a version-acknowledgement entry on every uplink.

    Args:
        pouch: The :class:`~pouch.Pouch` instance to attach to.
    """

    def __init__(self, pouch):
        self._pouch = pouch
        self._handlers = {}   # key -> callback(value)
        self._version = None  # last received settings version

        pouch._register_service_uplink(self._on_uplink)
        pouch._register_service_entry_handler(_DOWNLINK_PATH, self._on_downlink)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def handler(self, key):
        """Decorator that registers *func* as the callback for *key*.

        The callback receives the new value whenever the cloud pushes a
        settings update.  The value type matches the CBOR type sent by the
        cloud: ``bool``, ``int``, ``float``, or ``str``.

        Example::

            @settings.handler("LOOP_DELAY_S")
            def on_loop_delay(value):
                loop_delay = int(value)
        """
        def decorator(func):
            self._handlers[key] = func
            return func
        return decorator

    def register(self, key, callback):
        """Programmatically register a callback for *key* (non-decorator form).

        Args:
            key:      Setting key string (e.g. ``"LOOP_DELAY_S"``).
            callback: Callable ``(value) -> None``.
        """
        self._handlers[key] = callback

    # ------------------------------------------------------------------
    # Internal service callbacks
    # ------------------------------------------------------------------

    def _on_uplink(self):
        """Add the settings-status entry to the pending uplink queue."""
        # {"version": <version | null>}
        payload = cbor.encode({"version": self._version})
        self._pouch.add_entry(_UPLINK_PATH, CONTENT_TYPE_CBOR, payload)

    def _on_downlink(self, path, content_type, data):
        """Handle a settings downlink from the cloud."""
        try:
            msg, _ = cbor.decode(data)
        except Exception:
            return

        if not isinstance(msg, dict):
            return

        version = msg.get("version")
        if version is not None:
            self._version = version

        settings_map = msg.get("settings")
        if not isinstance(settings_map, dict):
            return

        for key, value in settings_map.items():
            cb = self._handlers.get(key)
            if cb is not None:
                try:
                    cb(value)
                except Exception:
                    pass
