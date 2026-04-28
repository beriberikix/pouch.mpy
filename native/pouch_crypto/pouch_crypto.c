// SPDX-License-Identifier: Apache-2.0
//
// pouch_crypto — MicroPython native module for Pouch SAEAD encryption.
//
// Provides five functions used by the pouch.crypto Python package:
//   - ecdh_p256(private_key, peer_pubkey) -> shared_secret
//   - hkdf_sha256(ikm, salt, info, out_len) -> derived_key
//   - aead_encrypt(alg, key, nonce, aad, plaintext) -> ciphertext_with_tag
//   - aead_decrypt(alg, key, nonce, aad, ciphertext_with_tag) -> plaintext
//   - random_bytes(n) -> bytes
//
// Build:
//   make ARCH=armv7emsp   # OpenMV / Cortex-M4F
//   make ARCH=xtensawin   # ESP32
//   make ARCH=x64         # host testing
//
// Requires:
//   - MicroPython source tree (for py/dynruntime.h)
//   - micro-ecc library (vendored in lib/micro-ecc/)
//   - mbedTLS subset (vendored in lib/mbedtls/)

#include "py/dynruntime.h"

// Vendored library headers
#include "uECC.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/gcm.h"
#include "mbedtls/chachapoly.h"

// Algorithm constants (must match pouch/const.py)
#define SAEAD_ALG_AES_GCM           0
#define SAEAD_ALG_CHACHA20_POLY1305 1
#define AUTH_TAG_LEN                16

// ---------------------------------------------------------------------------
// Helper: extract mp_obj bytes buffer
// ---------------------------------------------------------------------------
static void get_buffer(mp_obj_t obj, const uint8_t **buf, size_t *len) {
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(obj, &bufinfo, MP_BUFFER_READ);
    *buf = bufinfo.buf;
    *len = bufinfo.len;
}

// ---------------------------------------------------------------------------
// ecdh_p256(private_key: bytes, peer_pubkey: bytes) -> bytes
// ---------------------------------------------------------------------------
static mp_obj_t mod_ecdh_p256(mp_obj_t priv_obj, mp_obj_t pub_obj) {
    const uint8_t *priv, *pub;
    size_t priv_len, pub_len;
    get_buffer(priv_obj, &priv, &priv_len);
    get_buffer(pub_obj, &pub, &pub_len);

    if (priv_len != 32) {
        mp_raise_ValueError(MP_ERROR_TEXT("private key must be 32 bytes"));
    }
    if (pub_len != 65 || pub[0] != 0x04) {
        mp_raise_ValueError(MP_ERROR_TEXT("public key must be 65 bytes (uncompressed)"));
    }

    uint8_t secret[32];
    // micro-ecc expects the public key without the 0x04 prefix (64 bytes)
    int ok = uECC_shared_secret(pub + 1, priv, secret, uECC_secp256r1());
    if (!ok) {
        mp_raise_ValueError(MP_ERROR_TEXT("ECDH computation failed"));
    }

    return mp_obj_new_bytes(secret, 32);
}
MP_DEFINE_CONST_FUN_OBJ_2(mod_ecdh_p256_obj, mod_ecdh_p256);

// ---------------------------------------------------------------------------
// hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, out_len: int) -> bytes
// ---------------------------------------------------------------------------
static mp_obj_t mod_hkdf_sha256(size_t n_args, const mp_obj_t *args) {
    const uint8_t *ikm, *salt, *info;
    size_t ikm_len, salt_len, info_len;
    get_buffer(args[0], &ikm, &ikm_len);
    get_buffer(args[1], &salt, &salt_len);
    get_buffer(args[2], &info, &info_len);
    mp_int_t out_len = mp_obj_get_int(args[3]);

    if (out_len <= 0 || out_len > 255 * 32) {
        mp_raise_ValueError(MP_ERROR_TEXT("invalid output length"));
    }

    uint8_t *okm = m_new(uint8_t, out_len);
    const void *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int ret = mbedtls_hkdf(md_info, salt, salt_len, ikm, ikm_len,
                           info, info_len, okm, out_len);
    if (ret != 0) {
        m_del(uint8_t, okm, out_len);
        mp_raise_ValueError(MP_ERROR_TEXT("HKDF failed"));
    }

    mp_obj_t result = mp_obj_new_bytes(okm, out_len);
    m_del(uint8_t, okm, out_len);
    return result;
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_hkdf_sha256_obj, 4, 4,
                                    mod_hkdf_sha256);

// ---------------------------------------------------------------------------
// aead_encrypt(alg: int, key: bytes, nonce: bytes, aad: bytes,
//              plaintext: bytes) -> bytes
// ---------------------------------------------------------------------------
static mp_obj_t mod_aead_encrypt(size_t n_args, const mp_obj_t *args) {
    mp_int_t alg = mp_obj_get_int(args[0]);
    const uint8_t *key, *nonce, *aad, *pt;
    size_t key_len, nonce_len, aad_len, pt_len;
    get_buffer(args[1], &key, &key_len);
    get_buffer(args[2], &nonce, &nonce_len);
    get_buffer(args[3], &aad, &aad_len);
    get_buffer(args[4], &pt, &pt_len);

    if (nonce_len != 12) {
        mp_raise_ValueError(MP_ERROR_TEXT("nonce must be 12 bytes"));
    }

    size_t out_len = pt_len + AUTH_TAG_LEN;
    uint8_t *out = m_new(uint8_t, out_len);

    int ret = -1;

    if (alg == SAEAD_ALG_AES_GCM) {
        if (key_len != 16) {
            m_del(uint8_t, out, out_len);
            mp_raise_ValueError(MP_ERROR_TEXT("AES-GCM key must be 16 bytes"));
        }
        mbedtls_gcm_context gcm_ctx;
        mbedtls_gcm_init(&gcm_ctx);
        ret = mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, key, 128);
        if (ret == 0) {
            ret = mbedtls_gcm_crypt_and_tag(&gcm_ctx, MBEDTLS_GCM_ENCRYPT, pt_len,
                                            nonce, nonce_len, aad, aad_len,
                                            pt, out, AUTH_TAG_LEN,
                                            out + pt_len);
        }
        mbedtls_gcm_free(&gcm_ctx);
    } else if (alg == SAEAD_ALG_CHACHA20_POLY1305) {
        if (key_len != 32) {
            m_del(uint8_t, out, out_len);
            mp_raise_ValueError(
                MP_ERROR_TEXT("ChaCha20-Poly1305 key must be 32 bytes"));
        }
        mbedtls_chachapoly_context cc_ctx;
        mbedtls_chachapoly_init(&cc_ctx);
        ret = mbedtls_chachapoly_setkey(&cc_ctx, key);
        if (ret == 0) {
            ret = mbedtls_chachapoly_encrypt_and_tag(&cc_ctx, pt_len, nonce,
                                                      aad, aad_len, pt, out,
                                                      out + pt_len);
        }
        mbedtls_chachapoly_free(&cc_ctx);
    } else {
        m_del(uint8_t, out, out_len);
        mp_raise_ValueError(MP_ERROR_TEXT("unsupported algorithm"));
    }

    if (ret != 0) {
        m_del(uint8_t, out, out_len);
        mp_raise_ValueError(MP_ERROR_TEXT("encryption failed"));
    }

    mp_obj_t result = mp_obj_new_bytes(out, out_len);
    m_del(uint8_t, out, out_len);
    return result;
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_aead_encrypt_obj, 5, 5,
                                    mod_aead_encrypt);

// ---------------------------------------------------------------------------
// aead_decrypt(alg: int, key: bytes, nonce: bytes, aad: bytes,
//              ciphertext_with_tag: bytes) -> bytes
// ---------------------------------------------------------------------------
static mp_obj_t mod_aead_decrypt(size_t n_args, const mp_obj_t *args) {
    mp_int_t alg = mp_obj_get_int(args[0]);
    const uint8_t *key, *nonce, *aad, *ct;
    size_t key_len, nonce_len, aad_len, ct_len;
    get_buffer(args[1], &key, &key_len);
    get_buffer(args[2], &nonce, &nonce_len);
    get_buffer(args[3], &aad, &aad_len);
    get_buffer(args[4], &ct, &ct_len);

    if (nonce_len != 12) {
        mp_raise_ValueError(MP_ERROR_TEXT("nonce must be 12 bytes"));
    }
    if (ct_len < AUTH_TAG_LEN) {
        mp_raise_ValueError(MP_ERROR_TEXT("ciphertext too short"));
    }

    size_t pt_len = ct_len - AUTH_TAG_LEN;
    uint8_t *pt = m_new(uint8_t, pt_len);
    const uint8_t *tag = ct + pt_len;

    int ret = -1;

    if (alg == SAEAD_ALG_AES_GCM) {
        if (key_len != 16) {
            m_del(uint8_t, pt, pt_len);
            mp_raise_ValueError(MP_ERROR_TEXT("AES-GCM key must be 16 bytes"));
        }
        mbedtls_gcm_context gcm_ctx;
        mbedtls_gcm_init(&gcm_ctx);
        ret = mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, key, 128);
        if (ret == 0) {
            ret = mbedtls_gcm_auth_decrypt(&gcm_ctx, pt_len, nonce, nonce_len,
                                           aad, aad_len, tag, AUTH_TAG_LEN,
                                           ct, pt);
        }
        mbedtls_gcm_free(&gcm_ctx);
    } else if (alg == SAEAD_ALG_CHACHA20_POLY1305) {
        if (key_len != 32) {
            m_del(uint8_t, pt, pt_len);
            mp_raise_ValueError(
                MP_ERROR_TEXT("ChaCha20-Poly1305 key must be 32 bytes"));
        }
        mbedtls_chachapoly_context cc_ctx;
        mbedtls_chachapoly_init(&cc_ctx);
        ret = mbedtls_chachapoly_setkey(&cc_ctx, key);
        if (ret == 0) {
            ret = mbedtls_chachapoly_auth_decrypt(&cc_ctx, pt_len, nonce,
                                                   aad, aad_len, tag, ct, pt);
        }
        mbedtls_chachapoly_free(&cc_ctx);
    } else {
        m_del(uint8_t, pt, pt_len);
        mp_raise_ValueError(MP_ERROR_TEXT("unsupported algorithm"));
    }

    if (ret != 0) {
        m_del(uint8_t, pt, pt_len);
        mp_raise_ValueError(MP_ERROR_TEXT("authentication failed"));
    }

    mp_obj_t result = mp_obj_new_bytes(pt, pt_len);
    m_del(uint8_t, pt, pt_len);
    return result;
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_aead_decrypt_obj, 5, 5,
                                    mod_aead_decrypt);

// ---------------------------------------------------------------------------
// random_bytes(n: int) -> bytes
// ---------------------------------------------------------------------------
static mp_obj_t mod_random_bytes(mp_obj_t n_obj) {
    mp_int_t n = mp_obj_get_int(n_obj);
    if (n <= 0 || n > 256) {
        mp_raise_ValueError(MP_ERROR_TEXT("n must be 1-256"));
    }

    uint8_t *buf = m_new(uint8_t, n);

    // In natmod, POSIX syscalls (open/read/close) and hardware RNG APIs
    // are not available.  The Python layer should use os.urandom() and pass
    // random bytes in via the session API.  This function exists so the
    // native module's interface is complete.
    m_del(uint8_t, buf, n);
    mp_raise_NotImplementedError(
        MP_ERROR_TEXT("random_bytes: use os.urandom() from Python"));

    mp_obj_t result = mp_obj_new_bytes(buf, n);
    m_del(uint8_t, buf, n);
    return result;
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_random_bytes_obj, mod_random_bytes);

// ---------------------------------------------------------------------------
// Module entry point (natmod / dynruntime)
// ---------------------------------------------------------------------------
mp_obj_t mpy_init(mp_obj_fun_bc_t *self, size_t n_args, size_t n_kw, mp_obj_t *args) {
    MP_DYNRUNTIME_INIT_ENTRY

    mp_store_global(MP_QSTR_ecdh_p256,    MP_OBJ_FROM_PTR(&mod_ecdh_p256_obj));
    mp_store_global(MP_QSTR_hkdf_sha256,  MP_OBJ_FROM_PTR(&mod_hkdf_sha256_obj));
    mp_store_global(MP_QSTR_aead_encrypt, MP_OBJ_FROM_PTR(&mod_aead_encrypt_obj));
    mp_store_global(MP_QSTR_aead_decrypt, MP_OBJ_FROM_PTR(&mod_aead_decrypt_obj));
    mp_store_global(MP_QSTR_random_bytes, MP_OBJ_FROM_PTR(&mod_random_bytes_obj));

    MP_DYNRUNTIME_INIT_EXIT
}
