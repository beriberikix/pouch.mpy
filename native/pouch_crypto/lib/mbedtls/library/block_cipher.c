/**
 * \file block_cipher.c
 *
 * \brief Lightweight abstraction layer for block ciphers with 128 bit blocks,
 * for use by the GCM and CCM modules.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#include "block_cipher_internal.h"

#if defined(MBEDTLS_BLOCK_CIPHER_C)

void mbedtls_block_cipher_free(mbedtls_block_cipher_context_t *ctx)
{
    switch (ctx->id) {
#if defined(MBEDTLS_AES_C)
        case MBEDTLS_BLOCK_CIPHER_ID_AES:
            mbedtls_aes_free(&ctx->ctx.aes);
            break;
#endif
        default:
            break;
    }
    ctx->id = MBEDTLS_BLOCK_CIPHER_ID_NONE;
}

int mbedtls_block_cipher_setup(mbedtls_block_cipher_context_t *ctx,
                               mbedtls_cipher_id_t cipher_id)
{
    ctx->id = (cipher_id == MBEDTLS_CIPHER_ID_AES) ? MBEDTLS_BLOCK_CIPHER_ID_AES :
              MBEDTLS_BLOCK_CIPHER_ID_NONE;

    switch (ctx->id) {
#if defined(MBEDTLS_AES_C)
        case MBEDTLS_BLOCK_CIPHER_ID_AES:
            mbedtls_aes_init(&ctx->ctx.aes);
            return 0;
#endif
        default:
            ctx->id = MBEDTLS_BLOCK_CIPHER_ID_NONE;
            return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }
}

int mbedtls_block_cipher_setkey(mbedtls_block_cipher_context_t *ctx,
                                const unsigned char *key,
                                unsigned key_bitlen)
{
    switch (ctx->id) {
#if defined(MBEDTLS_AES_C)
        case MBEDTLS_BLOCK_CIPHER_ID_AES:
            return mbedtls_aes_setkey_enc(&ctx->ctx.aes, key, key_bitlen);
#endif
        default:
            return MBEDTLS_ERR_CIPHER_INVALID_CONTEXT;
    }
}

int mbedtls_block_cipher_encrypt(mbedtls_block_cipher_context_t *ctx,
                                 const unsigned char input[16],
                                 unsigned char output[16])
{
    switch (ctx->id) {
#if defined(MBEDTLS_AES_C)
        case MBEDTLS_BLOCK_CIPHER_ID_AES:
            return mbedtls_aes_crypt_ecb(&ctx->ctx.aes, MBEDTLS_AES_ENCRYPT,
                                         input, output);
#endif
        default:
            return MBEDTLS_ERR_CIPHER_INVALID_CONTEXT;
    }
}

#endif /* MBEDTLS_BLOCK_CIPHER_C */
