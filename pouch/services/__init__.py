# SPDX-License-Identifier: Apache-2.0
"""Golioth application services for Pouch.

Each service wraps a Pouch instance and registers itself as an uplink data
provider and/or downlink path handler.  Import the service you need and pass
your :class:`~pouch.Pouch` instance to its constructor::

    from pouch import Pouch
    from pouch.services.settings import SettingsService
    from pouch.services.logging import LogService
    from pouch.services.stream import StreamService
    from pouch.services.state import StateService
    from pouch.services.ota import OTAService

Available services
------------------
* :class:`~pouch.services.logging.LogService` – send log messages to Golioth
* :class:`~pouch.services.settings.SettingsService` – receive & acknowledge
  Golioth Settings
* :class:`~pouch.services.stream.StreamService` – convenience wrapper for
  LightDB Stream (time-series data uploads)
* :class:`~pouch.services.state.StateService` – LightDB State read/write
* :class:`~pouch.services.ota.OTAService` – receive OTA manifests and firmware
  component data
"""
