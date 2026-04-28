# SPDX-License-Identifier: Apache-2.0
"""Transport base class for Pouch.

A transport is responsible for delivering raw Pouch bytes between the device
and the cloud gateway.  Concrete implementations (e.g. BLE GATT) extend this
class and override :meth:`send`.
"""


class Transport:
    """Abstract base class for Pouch transports.

    Subclasses must implement :meth:`send`.  They should call
    :meth:`_on_rx` whenever bytes are received from the gateway.
    """

    def __init__(self):
        self._rx_callback = None

    def set_rx_callback(self, callback):
        """Register a callback invoked with ``(data: bytes)`` when data arrives.

        Args:
            callback: Callable ``(data: bytes) -> None``.
        """
        self._rx_callback = callback

    def send(self, data):
        """Send *data* bytes to the gateway.

        Args:
            data: Bytes to transmit.

        Raises:
            NotImplementedError: Always – subclasses must override.
        """
        raise NotImplementedError

    def _on_rx(self, data):
        """Dispatch received *data* to the registered callback."""
        if self._rx_callback:
            self._rx_callback(data)
