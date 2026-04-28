# SPDX-License-Identifier: Apache-2.0
"""SAEAD session management for Pouch.

Handles session key derivation, nonce generation, and per-block AEAD
encryption/decryption with chained authentication tags.

Upstream reference: golioth/pouch ``src/saead/session.c``
"""

import struct

try:
    from ubinascii import b2a_base64
except ImportError:
    from binascii import b2a_base64

from ..const import (
    SAEAD_ALG_AES_GCM,
    SAEAD_ALG_CHACHA20_POLY1305,
    POUCH_ROLE_DEVICE,
    POUCH_ROLE_SERVER,
    AUTH_TAG_LEN,
    NONCE_LEN,
    SESSION_ID_LEN,
    MAX_BLOCK_PAYLOAD_SIZE_LOG,
)
from . import ecdh_p256, hkdf_sha256, aead_encrypt, aead_decrypt, random_bytes


def generate_session_id():
    """Generate a random 16-byte session ID."""
    return random_bytes(SESSION_ID_LEN)


def _b64_no_newline(data):
    """Base64 encode without trailing newline/padding whitespace."""
    encoded = b2a_base64(data)
    # Strip trailing newline and padding (MicroPython's b2a_base64 adds \\n)
    if isinstance(encoded, bytes):
        encoded = encoded.rstrip(b"\n\r ")
    return encoded


def build_key_info(role, session_id, algorithm, id_type_random,
                   max_block_size_log):
    """Build the HKDF info string for session key derivation.

    Format: ``"E0:{D|S}:{base64(session_id)}:C{CC|AG}{R|S}:{hex_block_log}"``

    Args:
        role:                ``POUCH_ROLE_DEVICE`` or ``POUCH_ROLE_SERVER``.
        session_id:          16-byte session ID.
        algorithm:           ``SAEAD_ALG_AES_GCM`` or ``SAEAD_ALG_CHACHA20_POLY1305``.
        id_type_random:      True if session ID is random, False if sequential.
        max_block_size_log:  Log2 of maximum block payload size.

    Returns:
        Info string as ``bytes``.
    """
    role_char = b"D" if role == POUCH_ROLE_DEVICE else b"S"
    alg_str = b"CC" if algorithm == SAEAD_ALG_CHACHA20_POLY1305 else b"AG"
    id_type_char = b"R" if id_type_random else b"S"
    b64_id = _b64_no_newline(session_id)
    block_log_hex = "{:02x}".format(max_block_size_log).encode()

    return (b"E0:" + role_char + b":" + b64_id + b":C" +
            alg_str + id_type_char + b":" + block_log_hex)


def derive_session_key(private_key, peer_pubkey, session_id, role, algorithm,
                       max_block_size_log=MAX_BLOCK_PAYLOAD_SIZE_LOG):
    """Derive the SAEAD session key via ECDH + HKDF.

    Args:
        private_key:   32-byte device EC private key.
        peer_pubkey:   65-byte peer (server) EC public key (uncompressed).
        session_id:    16-byte session ID.
        role:          Initiator role (POUCH_ROLE_DEVICE or POUCH_ROLE_SERVER).
        algorithm:     AEAD algorithm identifier.
        max_block_size_log: Log2 of max block payload size (default 9).

    Returns:
        Derived key as ``bytes`` (32 bytes for ChaCha20, 16 bytes for AES-GCM).
    """
    shared_secret = ecdh_p256(private_key, peer_pubkey)
    info = build_key_info(role, session_id, algorithm, True, max_block_size_log)
    key_len = 32 if algorithm == SAEAD_ALG_CHACHA20_POLY1305 else 16
    return hkdf_sha256(shared_secret, b"", info, key_len)


def build_nonce(pouch_id, block_index, sender_role):
    """Build a 12-byte AEAD nonce.

    Format: ``pouch_id(2B BE) | block_index(2B BE) | sender_role(1B) | zeros(7B)``

    Args:
        pouch_id:     Pouch session counter (uint16).
        block_index:  Block index within this pouch (uint16).
        sender_role:  ``POUCH_ROLE_DEVICE`` or ``POUCH_ROLE_SERVER``.

    Returns:
        12-byte ``bytes`` nonce.
    """
    return struct.pack(">HHB", pouch_id, block_index, sender_role) + b"\x00" * 7


class Session:
    """An active SAEAD encryption session.

    Manages per-pouch state: block counter, AD chaining, and key material.
    """

    def __init__(self, key, algorithm, role):
        """
        Args:
            key:       Derived session key (from :func:`derive_session_key`).
            algorithm: AEAD algorithm identifier.
            role:      This endpoint's role (POUCH_ROLE_DEVICE or POUCH_ROLE_SERVER).
        """
        self.key = key
        self.algorithm = algorithm
        self.role = role
        self._block_index = 0
        self._prev_tag = b""  # AD for next block (empty for first block)

    def encrypt_block(self, pouch_id, plaintext):
        """Encrypt a single block's payload.

        Args:
            pouch_id:   Current pouch ID.
            plaintext:  Block payload bytes to encrypt.

        Returns:
            Ciphertext with appended 16-byte auth tag.
        """
        nonce = build_nonce(pouch_id, self._block_index, self.role)
        ct = aead_encrypt(self.algorithm, self.key, nonce,
                          self._prev_tag, plaintext)
        # Last AUTH_TAG_LEN bytes of ct are the tag
        self._prev_tag = ct[-AUTH_TAG_LEN:]
        self._block_index += 1
        return ct

    def decrypt_block(self, pouch_id, sender_role, ciphertext_with_tag):
        """Decrypt a single block's payload.

        Args:
            pouch_id:             Current pouch ID.
            sender_role:          Role of the sender (opposite of this session's role).
            ciphertext_with_tag:  Ciphertext + 16-byte auth tag.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            ValueError: If authentication fails.
        """
        nonce = build_nonce(pouch_id, self._block_index, sender_role)
        plaintext = aead_decrypt(self.algorithm, self.key, nonce,
                                 self._prev_tag, ciphertext_with_tag)
        # Update AD chain with the received tag
        self._prev_tag = ciphertext_with_tag[-AUTH_TAG_LEN:]
        self._block_index += 1
        return plaintext

    def reset_block_state(self):
        """Reset block counter and AD chain for a new pouch."""
        self._block_index = 0
        self._prev_tag = b""
