/*
 * This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "crypto_aes.h"
#include "mbedtls/aes.h"
#include <string.h>

/**
 * @brief Generic AES encryption function
 */
crypto_result_t aes_encrypt(const uint8_t *key, const uint8_t *iv, 
                          uint16_t key_size, aes_mode_t mode,
                          uint8_t *data, uint16_t len) {
    mbedtls_aes_context aes;
    uint8_t tmp_iv[IV_SIZE];
    size_t iv_offset = 0;
    int ret;

    if (!key || !data || len == 0 || 
        (key_size != 128 && key_size != 192 && key_size != 256)) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }

    mbedtls_aes_init(&aes);
    memset(tmp_iv, 0, IV_SIZE);
    
    if (iv) {
        memcpy(tmp_iv, iv, IV_SIZE);
    }

    ret = mbedtls_aes_setkey_enc(&aes, key, key_size);
    if (ret != 0) {
        mbedtls_aes_free(&aes);
        return CRYPTO_ERROR_EXECUTION;
    }

    if (mode == AES_MODE_CBC) {
        ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, len, tmp_iv, data, data);
    }
    else if (mode == AES_MODE_CFB) {
        ret = mbedtls_aes_crypt_cfb128(&aes, MBEDTLS_AES_ENCRYPT, len, &iv_offset, tmp_iv, data, data);
    }
    else {
        mbedtls_aes_free(&aes);
        return CRYPTO_ERROR_INVALID_PARAM;
    }

    mbedtls_aes_free(&aes);
    return (ret == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR_EXECUTION;
}

/**
 * @brief Generic AES decryption function
 */
crypto_result_t aes_decrypt(const uint8_t *key, const uint8_t *iv,
                          uint16_t key_size, aes_mode_t mode,
                          uint8_t *data, uint16_t len) {
    mbedtls_aes_context aes;
    uint8_t tmp_iv[IV_SIZE];
    size_t iv_offset = 0;
    int ret;

    if (!key || !data || len == 0 ||
        (key_size != 128 && key_size != 192 && key_size != 256)) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }

    mbedtls_aes_init(&aes);
    memset(tmp_iv, 0, IV_SIZE);
    
    if (iv) {
        memcpy(tmp_iv, iv, IV_SIZE);
    }

    if (mode == AES_MODE_CBC) {
        ret = mbedtls_aes_setkey_dec(&aes, key, key_size);
    }
    else if (mode == AES_MODE_CFB) {
        /* CFB mode always uses encryption key setup */
        ret = mbedtls_aes_setkey_enc(&aes, key, key_size);
    }
    else {
        mbedtls_aes_free(&aes);
        return CRYPTO_ERROR_INVALID_PARAM;
    }

    if (ret != 0) {
        mbedtls_aes_free(&aes);
        return CRYPTO_ERROR_EXECUTION;
    }

    if (mode == AES_MODE_CBC) {
        ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, len, tmp_iv, data, data);
    }
    else { /* AES_MODE_CFB */
        ret = mbedtls_aes_crypt_cfb128(&aes, MBEDTLS_AES_DECRYPT, len, &iv_offset, tmp_iv, data, data);
    }

    mbedtls_aes_free(&aes);
    return (ret == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR_EXECUTION;
}

// /**
//  * @brief Convenience function for AES-256-CFB encryption
//  */
// crypto_result_t aes_encrypt_cfb_256(const uint8_t *key, const uint8_t *iv,
//                                    uint8_t *data, uint16_t len) {
//     return aes_encrypt(key, iv, 256, AES_MODE_CFB, data, len);
// }

// /**
//  * @brief Convenience function for AES-256-CFB decryption
//  */
// crypto_result_t aes_decrypt_cfb_256(const uint8_t *key, const uint8_t *iv,
//                                    uint8_t *data, uint16_t len) {
//     return aes_decrypt(key, iv, 256, AES_MODE_CFB, data, len);
// }
