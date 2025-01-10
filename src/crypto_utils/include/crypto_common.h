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

#ifndef CRYPTO_COMMON_H
#define CRYPTO_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * @brief Common result codes for crypto operations
 */
typedef enum {
    CRYPTO_SUCCESS = 0,                /**< Operation completed successfully */
    CRYPTO_ERROR_INVALID_PARAM = -1,   /**< Invalid parameter provided */
    CRYPTO_ERROR_EXECUTION = -2,       /**< Error during operation execution */
    CRYPTO_ERROR_BUFFER_TOO_SMALL = -3,/**< Output buffer too small */
    CRYPTO_ERROR_UNSUPPORTED = -4      /**< Operation or parameter not supported */
} crypto_result_t;

/**
 * @brief Common size definitions
 */
#define HASH_SIZE 32    /**< Size of SHA-256 hash output */
#define IV_SIZE 16      /**< Size of initialization vector for AES */
#define MAX_KEY_SIZE 64 /**< Maximum supported key size */

/**
 * @brief Macro for checking if operation succeeded
 */
#define CRYPTO_IS_SUCCESS(result) ((result) == CRYPTO_SUCCESS)

/**
 * @brief Macro for secure clearing of sensitive data
 */
#define CRYPTO_SECURE_CLEAR(ptr, size) \
    do { \
        volatile uint8_t *vptr = (volatile uint8_t *)(ptr); \
        size_t _size = (size); \
        while (_size--) *vptr++ = 0; \
    } while(0)

#endif /* CRYPTO_COMMON_H */
