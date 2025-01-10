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

#ifndef _CRYPTO_CURVES_H_
#define _CRYPTO_CURVES_H_

#include "crypto_common.h"
#include "mbedtls/ecp.h"

/**
 * @brief Structure containing curve parameters
 */
typedef struct {
    const uint8_t *prime;  /**< Curve prime value */
    size_t len;           /**< Length of prime value in bytes */
} curve_params_t;

/* Private curve definition structure */
typedef struct {
    const curve_params_t *params;
    mbedtls_ecp_group_id id;
} curve_def_t;

/* NIST standard curves */
extern const curve_params_t secp192r1_params;  /**< NIST P-192 curve */
extern const curve_params_t secp256r1_params;  /**< NIST P-256 curve */
extern const curve_params_t secp384r1_params;  /**< NIST P-384 curve */
extern const curve_params_t secp521r1_params;  /**< NIST P-521 curve */

/* Brainpool standard curves */
extern const curve_params_t bp256r1_params;    /**< Brainpool P-256r1 curve */
extern const curve_params_t bp384r1_params;    /**< Brainpool P-384r1 curve */
extern const curve_params_t bp512r1_params;    /**< Brainpool P-512r1 curve */

/* Koblitz curves */
extern const curve_params_t secp192k1_params;  /**< SECG K-192 curve */
extern const curve_params_t secp256k1_params;  /**< SECG K-256 curve */

/* Montgomery curves */
extern const curve_params_t curve25519_params; /**< Curve25519 */
extern const curve_params_t curve448_params;   /**< Curve448 */

/* Curve sizes in bytes */
#define CURVE_192_SIZE 24
#define CURVE_256_SIZE 32
#define CURVE_384_SIZE 48
#define CURVE_521_SIZE 66
#define CURVE_448_SIZE 56

/**
 * @brief Get mbedtls curve ID from prime value
 *
 * @param prime Pointer to prime value buffer
 * @param prime_len Length of prime value in bytes
 * @return mbedtls_ecp_group_id Curve ID or MBEDTLS_ECP_DP_NONE if not found
 */
mbedtls_ecp_group_id ec_get_curve_from_prime(const uint8_t *prime, size_t prime_len);

/**
 * @brief Get curve parameters from mbedtls curve ID
 * 
 * @param curve_id mbedtls curve ID
 * @return const curve_params_t* Pointer to curve parameters or NULL if not found
 */
const curve_params_t* ec_get_curve_params(mbedtls_ecp_group_id curve_id);

/**
 * @brief Check if curve is supported
 * 
 * @param curve_id mbedtls curve ID to check
 * @return bool true if supported, false otherwise
 */
bool ec_is_curve_supported(mbedtls_ecp_group_id curve_id);

#endif /* _CRYPTO_CURVES_H_ */
