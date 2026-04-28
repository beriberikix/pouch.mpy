# SPDX-License-Identifier: Apache-2.0
"""SAEAD downlink session manager.

Manages decryption of received downlink pouches: session key derivation
(or reuse), header parsing, and per-block decryption with AD chaining.
"""

from ..const import (
    ENCRYPTION_SAEAD,
    POUCH_ROLE_SERVER,
    AUTH_TAG_LEN,
    MAX_BLOCK_PAYLOAD_SIZE_LOG,
)
from .session import derive_session_key, Session


class DownlinkSession:
    """Manages the decryption side of downlink pouches.

    Created once per BLE connection.  Caches the session key when the
    session ID matches a previous pouch, avoiding repeated ECDH.

    Args:
        private_key:    32-byte device EC private key.
        server_pubkey:  65-byte server EC public key (uncompressed).
    """

    def __init__(self, private_key, server_pubkey):
        self._private_key = private_key
        self._server_pubkey = server_pubkey
        self._cached_session_id = None
        self._cached_key = None
        self._cached_algorithm = None

    def begin_pouch(self, session_info):
        """Prepare to decrypt a downlink pouch.

        Args:
            session_info: Dict from :func:`~pouch.header.decode_header` with
                          keys ``session_id``, ``initiator``, ``algorithm``,
                          ``max_block_size_log``, ``cert_ref``, ``pouch_id``.

        Returns:
            A :class:`~pouch.crypto.session.Session` ready to decrypt blocks.
        """
        sid = session_info["session_id"]
        alg = session_info["algorithm"]
        block_log = session_info["max_block_size_log"]
        initiator = session_info["initiator"]

        # Reuse cached key if session ID matches
        if sid == self._cached_session_id and alg == self._cached_algorithm:
            key = self._cached_key
        else:
            key = derive_session_key(
                self._private_key, self._server_pubkey, sid,
                initiator, alg, block_log,
            )
            self._cached_session_id = sid
            self._cached_key = key
            self._cached_algorithm = alg

        session = Session(key, alg, POUCH_ROLE_SERVER)
        return session
