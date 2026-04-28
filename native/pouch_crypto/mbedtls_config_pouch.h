/* SPDX-License-Identifier: Apache-2.0
 *
 * Minimal mbedTLS configuration for pouch_crypto native module.
 * Only enables the algorithms required for Pouch SAEAD:
 *   - AES-128-GCM
 *   - ChaCha20-Poly1305
 *   - HKDF-SHA256
 */

#ifndef MBEDTLS_CONFIG_POUCH_H
#define MBEDTLS_CONFIG_POUCH_H

/* System support */
#define MBEDTLS_HAVE_ASM

/* mbed TLS modules */
#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C
#define MBEDTLS_CHACHA20_C
#define MBEDTLS_CHACHAPOLY_C
#define MBEDTLS_POLY1305_C
#define MBEDTLS_BLOCK_CIPHER_C
#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_HKDF_C
#define MBEDTLS_PLATFORM_C

/* Disable everything else */
#define MBEDTLS_NO_PLATFORM_ENTROPY

/* Small code size optimizations */
#define MBEDTLS_AES_FEWER_TABLES
#define MBEDTLS_SHA256_SMALLER

/* Use compile-time AES tables in .rodata instead of runtime-computed
   tables in static BSS.  mpy_ld.py rejects static BSS variables. */
#define MBEDTLS_AES_ROM_TABLES

#endif /* MBEDTLS_CONFIG_POUCH_H */
