# SPDX-License-Identifier: Apache-2.0
"""Golioth LightDB Stream service.

Convenience wrapper for sending time-series data to Golioth LightDB Stream.
Data is sent as Pouch entries on paths under ``.s/``.

Example::

    from pouch import Pouch
    from pouch.services.stream import StreamService

    pouch = Pouch(device_id="dev-01")
    stream = StreamService(pouch)

    # Queue a JSON reading on .s/temperature
    stream.send("temperature", b'{"value": 22.5, "unit": "C"}')

    # Queue a CBOR reading
    from pouch.const import CONTENT_TYPE_CBOR
    from pouch import cbor
    stream.send("accel", cbor.encode({"x": 0.1, "y": -0.2, "z": 9.8}),
                content_type=CONTENT_TYPE_CBOR)
"""

from ..const import CONTENT_TYPE_JSON

_PATH_PREFIX = ".s/"


class StreamService:
    """Golioth LightDB Stream service.

    Provides a thin wrapper around :meth:`~pouch.Pouch.add_entry` that
    automatically prepends the ``.s/`` path prefix required for LightDB Stream
    entries.

    Args:
        pouch: The :class:`~pouch.Pouch` instance to attach to.
    """

    def __init__(self, pouch):
        self._pouch = pouch

    def send(self, subpath, data, content_type=CONTENT_TYPE_JSON):
        """Queue a LightDB Stream entry for the next uplink session.

        Args:
            subpath:      Stream sub-path (e.g. ``"temperature"``).  The full
                          Pouch path will be ``".s/<subpath>"``.
            data:         Payload as ``bytes``, ``bytearray``, or ``str``.
            content_type: CoAP content-format integer (default: JSON).
        """
        self._pouch.add_entry(_PATH_PREFIX + subpath, content_type, data)
