# SPDX-License-Identifier: Apache-2.0
"""Pouch SAEAD encryption support.

Requires the ``pouch_crypto`` native .mpy module to be installed on the
target device.  Build it from ``native/pouch_crypto/`` for your target
architecture::

    cd native/pouch_crypto
    make ARCH=armv7emsp   # OpenMV / Cortex-M4F
    make ARCH=xtensawin   # ESP32
    make ARCH=x64         # host testing

Then copy the resulting ``pouch_crypto.mpy`` to the device's filesystem
(alongside the ``pouch/`` package directory).
"""

try:
    import pouch_crypto  # native .mpy module
except ImportError:
    raise ImportError(
        "pouch_crypto native module not found. "
        "Build it from native/pouch_crypto/ for your target architecture "
        "and copy the .mpy file to the device filesystem."
    )

# Re-export native crypto primitives
ecdh_p256 = pouch_crypto.ecdh_p256
hkdf_sha256 = pouch_crypto.hkdf_sha256
aead_encrypt = pouch_crypto.aead_encrypt
aead_decrypt = pouch_crypto.aead_decrypt
random_bytes = pouch_crypto.random_bytes
