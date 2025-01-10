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

#include "crypto_utils.h"
#include "crypto_curves.h"
#include "crypto_aes.h"
#include "crypto_hash.h"
#include "crypto_common.h"

/* Wrapper functions to maintain API compatibility while using new implementation */

mbedtls_ecp_group_id get_curve_from_prime(const uint8_t *prime, size_t prime_len) {
    return ec_get_curve_from_prime(prime, prime_len);
}

int aes_encrypt_cfb_256(const uint8_t *key, const uint8_t *iv, uint8_t *data, uint16_t len) {
    crypto_result_t result = aes_encrypt(key, iv, 256, AES_MODE_CFB, data, len);
    return (result == CRYPTO_SUCCESS) ? 0 : -1;
}

int aes_decrypt_cfb_256(const uint8_t *key, const uint8_t *iv, uint8_t *data, uint16_t len) {
    crypto_result_t result = aes_decrypt(key, iv, 256, AES_MODE_CFB, data, len);
    return (result == CRYPTO_SUCCESS) ? 0 : -1;
}

int double_hash_pin(const uint8_t *pin, uint16_t len, uint8_t output[32]) {
    crypto_result_t result = ch_double_hash_pin(pin, len, output);
    return (result == CRYPTO_SUCCESS) ? 0 : -1;
}

int hash_multi(const uint8_t *input, uint16_t len, uint8_t output[32]) {
    crypto_result_t result = ch_hash_multi(input, len, output);
    return (result == CRYPTO_SUCCESS) ? 0 : -1;
}

int hash256(const uint8_t *input, size_t len, uint8_t output[32]) {
    crypto_result_t result = ch_hash256(input, len, output);
    return (result == CRYPTO_SUCCESS) ? 0 : -1;
}
