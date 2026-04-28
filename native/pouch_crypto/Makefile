# SPDX-License-Identifier: Apache-2.0
#
# Makefile for the pouch_crypto MicroPython native module (.mpy).
#
# Prerequisites:
#   - MicroPython source tree: set MPY_DIR to the path
#   - micro-ecc vendored in lib/micro-ecc/
#   - mbedTLS subset vendored in lib/mbedtls/
#
# Usage:
#   make ARCH=armv7emsp   # OpenMV / Cortex-M4F with FPU
#   make ARCH=xtensawin   # ESP32
#   make ARCH=x64         # host testing (Linux/macOS)
#
# Output: pouch_crypto.mpy

# Path to MicroPython source (override on command line or environment)
MPY_DIR ?= $(HOME)/micropython

# Module name
MOD = pouch_crypto

# Source files
SRC = pouch_crypto.c
SRC += shims.c

# Vendored library sources
SRC += lib/micro-ecc/uECC.c

# mbedTLS subset (only what we need for HKDF + AES-GCM + ChaCha20-Poly1305)
MBEDTLS_DIR = lib/mbedtls/library
SRC += $(MBEDTLS_DIR)/aes.c
SRC += $(MBEDTLS_DIR)/gcm.c
SRC += $(MBEDTLS_DIR)/chacha20.c
SRC += $(MBEDTLS_DIR)/chachapoly.c
SRC += $(MBEDTLS_DIR)/poly1305.c
SRC += $(MBEDTLS_DIR)/md.c
SRC += $(MBEDTLS_DIR)/sha256.c
SRC += $(MBEDTLS_DIR)/hkdf.c
SRC += $(MBEDTLS_DIR)/platform_util.c
SRC += $(MBEDTLS_DIR)/block_cipher.c
SRC += $(MBEDTLS_DIR)/constant_time.c

# Include paths
CFLAGS += -Ilib/micro-ecc
CFLAGS += -Ilib/mbedtls/include
CFLAGS += -Ilib/mbedtls/library

# mbedTLS configuration: minimal build with only what we need
CFLAGS += -DMBEDTLS_CONFIG_FILE='"mbedtls_config_pouch.h"'

# micro-ecc configuration
CFLAGS += -DuECC_OPTIMIZATION_LEVEL=3
CFLAGS += -DuECC_SUPPORTS_secp256r1=1
CFLAGS += -DuECC_SUPPORTS_secp256k1=0
CFLAGS += -DuECC_SUPPORTS_secp224r1=0
CFLAGS += -DuECC_SUPPORTS_secp192r1=0
CFLAGS += -DuECC_SUPPORTS_secp160r1=0
CFLAGS += -DuECC_SQUARE_FUNC=1

# Include the MicroPython natmod build system
include $(MPY_DIR)/py/dynruntime.mk
