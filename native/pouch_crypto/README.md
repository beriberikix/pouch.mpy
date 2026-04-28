# pouch_crypto — Native MicroPython Module

Native `.mpy` module providing cryptographic primitives for Pouch SAEAD encryption.

## Prerequisites

1. **MicroPython source tree** — needed for `py/dynruntime.h` and the natmod build system.

2. **micro-ecc** — vendor into `lib/micro-ecc/`:
   ```bash
   git clone https://github.com/kmackay/micro-ecc.git lib/micro-ecc
   ```

3. **mbedTLS** — vendor into `lib/mbedtls/`:
   ```bash
   git clone --depth 1 --branch v3.6.0 https://github.com/Mbed-TLS/mbedtls.git lib/mbedtls
   ```

## Building

Set `MPY_DIR` to your MicroPython source directory, then build for your target architecture:

```bash
# OpenMV / Cortex-M4F with hardware FPU
make MPY_DIR=/path/to/micropython ARCH=armv7emsp

# ESP32
make MPY_DIR=/path/to/micropython ARCH=xtensawin

# Host testing (Linux x86_64)
make MPY_DIR=/path/to/micropython ARCH=x64
```

Output: `pouch_crypto.mpy`

## Installation

Copy `pouch_crypto.mpy` to the device's filesystem root (alongside the `pouch/` package directory).

## API

```python
import pouch_crypto

# ECDH P-256 key agreement
shared_secret = pouch_crypto.ecdh_p256(private_key_32b, peer_pubkey_65b)

# HKDF-SHA256 key derivation
key = pouch_crypto.hkdf_sha256(ikm, salt, info, output_length)

# AEAD encryption (returns ciphertext + 16-byte auth tag)
ct = pouch_crypto.aead_encrypt(algorithm, key, nonce_12b, aad, plaintext)

# AEAD decryption (raises ValueError on auth failure)
pt = pouch_crypto.aead_decrypt(algorithm, key, nonce_12b, aad, ciphertext_with_tag)

# Cryptographically secure random bytes
rand = pouch_crypto.random_bytes(n)
```

Algorithm constants: `0` = AES-128-GCM, `1` = ChaCha20-Poly1305.
