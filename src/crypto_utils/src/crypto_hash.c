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

#include "crypto_hash.h"
#include "mbedtls/sha256.h"
#include <string.h>

#if defined(ENABLE_EMULATION)
#elif defined(ESP_PLATFORM)
    #include "esp_compat.h"
#else
    #include <pico/unique_id.h>
#endif

/**
 * @brief Double hash a PIN with XOR operation in between
 */
crypto_result_t ch_double_hash_pin(const uint8_t *pin, uint16_t len, uint8_t output[HASH_SIZE]) {
    uint8_t first_hash[HASH_SIZE];
    crypto_result_t result;
    
    if (!pin || !output || len == 0) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }

    result = ch_hash_multi(pin, len, first_hash);
    if (result != CRYPTO_SUCCESS) {
        return result;
    }

    /* XOR first hash with PIN */
    for (int i = 0; i < HASH_SIZE; i++) {
        first_hash[i] ^= pin[i % len];
    }

    /* Second hash */
    return ch_hash_multi(first_hash, HASH_SIZE, output);
}

/**
 * @brief Multiple iteration hash function with device-specific seed
 */
crypto_result_t ch_hash_multi(const uint8_t *input, uint16_t len, uint8_t output[HASH_SIZE]) {
    mbedtls_sha256_context ctx;
    uint16_t iters = 256;

    if (!input || !output || len == 0) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }

    mbedtls_sha256_init(&ctx);
    if(mbedtls_sha256_starts(&ctx, 0) != 0) {
        mbedtls_sha256_free(&ctx);
        return CRYPTO_ERROR_EXECUTION;
    }

#ifndef ENABLE_EMULATION
    /* Add device-specific seed */
    if(mbedtls_sha256_update(&ctx, pico_serial.id, sizeof(pico_serial.id)) != 0) {
        mbedtls_sha256_free(&ctx);
        return CRYPTO_ERROR_EXECUTION;
    }
#endif

    /* Multiple iterations of input */
    while (iters > len) {
        if(mbedtls_sha256_update(&ctx, input, len) != 0) {
            mbedtls_sha256_free(&ctx);
            return CRYPTO_ERROR_EXECUTION;
        }
        iters -= len;
    }

    if (iters > 0) {
        if(mbedtls_sha256_update(&ctx, input, iters) != 0) {
            mbedtls_sha256_free(&ctx);
            return CRYPTO_ERROR_EXECUTION;
        }
    }

    if(mbedtls_sha256_finish(&ctx, output) != 0) {
        mbedtls_sha256_free(&ctx);
        return CRYPTO_ERROR_EXECUTION;
    }

    mbedtls_sha256_free(&ctx);
    return CRYPTO_SUCCESS;
}

/**
 * @brief Simple SHA-256 hash function
 */
crypto_result_t ch_hash256(const uint8_t *input, size_t len, uint8_t output[HASH_SIZE]) {
    mbedtls_sha256_context ctx;
    
    if (!input || !output || len == 0) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }

    mbedtls_sha256_init(&ctx);
    
    if(mbedtls_sha256_starts(&ctx, 0) != 0 ||
       mbedtls_sha256_update(&ctx, input, len) != 0 ||
       mbedtls_sha256_finish(&ctx, output) != 0) {
        mbedtls_sha256_free(&ctx);
        return CRYPTO_ERROR_EXECUTION;
    }

    mbedtls_sha256_free(&ctx);
    return CRYPTO_SUCCESS;
}

/**
 * @brief Generic hash function using mbedtls MD interface
 */
crypto_result_t generic_hash(mbedtls_md_type_t md, const uint8_t *input, size_t len, uint8_t *output) {
    if (!input || !output || len == 0) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }

    if (mbedtls_md(mbedtls_md_info_from_type(md), input, len, output) != 0) {
        return CRYPTO_ERROR_EXECUTION;
    }

    return CRYPTO_SUCCESS;
}
