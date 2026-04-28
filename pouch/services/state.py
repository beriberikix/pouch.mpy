# SPDX-License-Identifier: Apache-2.0
"""Golioth LightDB State service.

Supports reading and writing persistent key/value state via Golioth LightDB
State.

Wire format
-----------
**Uplink** – set state (path ``.d/<subpath>``, any content type):

    Any bytes.  Typically a JSON or CBOR-encoded value.

**Downlink** – desired state from cloud (path ``/.d/<subpath>``, entry block):

    Any bytes received at a path starting with ``/.d/`` are forwarded to the
    registered :meth:`~StateService.observe` callback.

Example::

    from pouch import Pouch
    from pouch.services.state import StateService

    pouch = Pouch(device_id="dev-01")
    state = StateService(pouch)

    # Send current LED state to cloud
    state.set("led", b'{"on": false}')

    # React when cloud pushes a desired state
    @state.observe
    def on_desired(subpath, content_type, data):
        print("Cloud wants", subpath, "=", data)
"""

from ..const import CONTENT_TYPE_JSON

_UPLINK_PREFIX = ".d/"
_DOWNLINK_PREFIX = "/.d/"


class StateService:
    """Golioth LightDB State service.

    Registers itself with *pouch* to receive desired-state downlinks and
    provides a :meth:`set` method for publishing current state.

    Args:
        pouch: The :class:`~pouch.Pouch` instance to attach to.
    """

    def __init__(self, pouch):
        self._pouch = pouch
        self._observe_cb = None

        pouch._register_service_entry_handler(
            _DOWNLINK_PREFIX, self._on_downlink, prefix=True
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set(self, subpath, data, content_type=CONTENT_TYPE_JSON):
        """Queue a state update entry for the next uplink session.

        Args:
            subpath:      State key path (e.g. ``"led"`` → full path
                          ``".d/led"``).
            data:         Payload as ``bytes``, ``bytearray``, or ``str``.
            content_type: CoAP content-format integer (default: JSON).
        """
        self._pouch.add_entry(_UPLINK_PREFIX + subpath, content_type, data)

    def observe(self, func):
        """Decorator that registers *func* as the desired-state callback.

        The callback receives ``(subpath: str, content_type: int, data: bytes)``
        for each desired-state entry pushed by the cloud.  *subpath* has the
        ``/.d/`` prefix stripped.

        Example::

            @state.observe
            def on_desired(subpath, content_type, data):
                print("Desired:", subpath, data)
        """
        self._observe_cb = func
        return func

    # ------------------------------------------------------------------
    # Internal service callback
    # ------------------------------------------------------------------

    def _on_downlink(self, path, content_type, data):
        """Handle a desired-state downlink from the cloud."""
        if self._observe_cb is None:
            return
        # Strip the /.d/ prefix to give the application a clean subpath
        subpath = path[len(_DOWNLINK_PREFIX):]
        try:
            self._observe_cb(subpath, content_type, data)
        except Exception:
            pass
