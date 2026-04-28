# SPDX-License-Identifier: Apache-2.0
"""Golioth Logging service.

Queues structured log messages as Pouch uplink entries on the ``.log`` path.
Each call to :meth:`~LogService.log` (or the level helpers) adds one CBOR-
encoded log record to the pending uplink queue; the record is transmitted on
the next uplink session.

Wire format
-----------
Each record is a CBOR map sent as a Pouch entry on path ``.log``::

    {
        "level":  <uint: 0=ERR 1=WRN 2=INF 3=DBG>,
        "module": <tstr>,
        "msg":    <tstr>,
    }

Example::

    from pouch import Pouch
    from pouch.services.logging import LogService, LOG_LEVEL_INF

    pouch = Pouch(device_id="dev-01")
    log = LogService(pouch)

    log.info("app", "Device started")
    log.warning("sensor", "Temperature above threshold")
    log.error("net", "Connection lost")
"""

from .. import cbor
from ..const import CONTENT_TYPE_CBOR

# Log levels (matching Golioth / Zephyr log severity)
LOG_LEVEL_ERR = 0
LOG_LEVEL_WRN = 1
LOG_LEVEL_INF = 2
LOG_LEVEL_DBG = 3

_LOG_PATH = ".log"


class LogService:
    """Golioth Logging service.

    Attach to a :class:`~pouch.Pouch` instance and call :meth:`log` (or the
    level-specific helpers) to enqueue log messages for the next uplink.

    Args:
        pouch: The :class:`~pouch.Pouch` instance to attach to.
    """

    def __init__(self, pouch):
        self._pouch = pouch
        # No uplink/downlink registration needed – log() queues entries
        # directly via pouch.add_entry() at call time (not deferred).

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log(self, module, msg, level=LOG_LEVEL_INF):
        """Queue a log message for the next uplink session.

        Args:
            module: Module/component name string (e.g. ``"app"``).
            msg:    Log message string.
            level:  One of :data:`LOG_LEVEL_ERR`, :data:`LOG_LEVEL_WRN`,
                    :data:`LOG_LEVEL_INF`, :data:`LOG_LEVEL_DBG`.
        """
        payload = cbor.encode({"level": level, "module": module, "msg": msg})
        self._pouch.add_entry(_LOG_PATH, CONTENT_TYPE_CBOR, payload)

    def error(self, module, msg):
        """Queue an error-level log message."""
        self.log(module, msg, LOG_LEVEL_ERR)

    def warning(self, module, msg):
        """Queue a warning-level log message."""
        self.log(module, msg, LOG_LEVEL_WRN)

    def info(self, module, msg):
        """Queue an info-level log message."""
        self.log(module, msg, LOG_LEVEL_INF)

    def debug(self, module, msg):
        """Queue a debug-level log message."""
        self.log(module, msg, LOG_LEVEL_DBG)
