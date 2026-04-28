# SPDX-License-Identifier: Apache-2.0
"""SAEAD uplink session manager.

Manages encrypted uplink pouch construction: session establishment, header
encoding, and per-block encryption with AD chaining.
"""

from ..const import (
    POUCH_ROLE_DEVICE,
    AUTH_TAG_LEN,
    MAX_BLOCK_PAYLOAD_SIZE_LOG,
)
from ..header import encode_header_saead
from .cert import cert_ref as compute_cert_ref
from .session import (
    generate_session_id,
    derive_session_key,
    Session,
)


class UplinkSession:
    """Manages the encryption side of uplink pouches.

    Created once per BLE connection when the server certificate is received.
    Each call to :meth:`start_pouch` begins a new pouch with fresh block state.

    Args:
        private_key:         32-byte device EC private key.
        device_cert_der:     Device certificate (DER) for cert_ref.
        server_pubkey:       65-byte server EC public key (uncompressed).
        algorithm:           AEAD algorithm identifier.
        max_block_size_log:  Log2 of max block payload size.
    """

    def __init__(self, private_key, device_cert_der, server_pubkey, algorithm,
                 max_block_size_log=MAX_BLOCK_PAYLOAD_SIZE_LOG):
        self._private_key = private_key
        self._cert_ref = compute_cert_ref(device_cert_der)
        self._server_pubkey = server_pubkey
        self._algorithm = algorithm
        self._max_block_size_log = max_block_size_log

        # Generate session
        self._session_id = generate_session_id()
        key = derive_session_key(
            private_key, server_pubkey, self._session_id,
            POUCH_ROLE_DEVICE, algorithm, max_block_size_log,
        )
        self._session = Session(key, algorithm, POUCH_ROLE_DEVICE)
        self._pouch_id = 0

    @property
    def session_id(self):
        return self._session_id

    @property
    def pouch_id(self):
        return self._pouch_id

    def start_pouch(self):
        """Begin a new pouch, returning the encoded SAEAD header.

        Increments the pouch ID and resets the block encryption state.

        Returns:
            Bytes containing the CBOR-encoded SAEAD header.
        """
        self._session.reset_block_state()
        header = encode_header_saead(
            self._session_id, POUCH_ROLE_DEVICE, self._algorithm,
            self._max_block_size_log, self._cert_ref, self._pouch_id,
        )
        self._pouch_id += 1
        return header

    def encrypt_block(self, plaintext):
        """Encrypt a block payload for the current pouch.

        Args:
            plaintext: Raw block payload bytes.

        Returns:
            Encrypted payload (ciphertext + 16-byte auth tag).
        """
        # Use pouch_id - 1 because start_pouch already incremented
        return self._session.encrypt_block(self._pouch_id - 1, plaintext)
