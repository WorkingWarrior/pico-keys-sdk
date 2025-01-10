#ifndef CRYPTO_HASH_H
#define CRYPTO_HASH_H

#include "crypto_common.h"
#include "mbedtls/md.h"

/**
 * @brief Double hash a PIN with XOR operation in between
 *
 * @param pin Input PIN buffer
 * @param len Length of PIN buffer
 * @param output Output buffer (must be HASH_SIZE bytes)
 * @return crypto_result_t Operation result
 */
crypto_result_t ch_double_hash_pin(const uint8_t *pin, uint16_t len, uint8_t output[HASH_SIZE]);

/**
 * @brief Multiple iteration hash function with device-specific seed
 *
 * @param input Input data buffer
 * @param len Length of input data
 * @param output Output buffer (must be HASH_SIZE bytes)
 * @return crypto_result_t Operation result
 */
crypto_result_t ch_hash_multi(const uint8_t *input, uint16_t len, uint8_t output[HASH_SIZE]);

/**
 * @brief Simple SHA-256 hash function
 *
 * @param input Input data buffer
 * @param len Length of input data
 * @param output Output buffer (must be HASH_SIZE bytes)
 * @return crypto_result_t Operation result
 */
crypto_result_t ch_hash256(const uint8_t *input, size_t len, uint8_t output[HASH_SIZE]);

/**
 * @brief Generic hash function using mbedtls MD interface
 *
 * @param md Hash algorithm type
 * @param input Input data buffer
 * @param len Length of input data
 * @param output Output buffer (size depends on hash algorithm)
 * @return crypto_result_t Operation result
 */
crypto_result_t generic_hash(mbedtls_md_type_t md, const uint8_t *input, size_t len, uint8_t *output);

#endif /* CRYPTO_HASH_H */