#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include "crypto_common.h"
#include "crypto_hash.h"
#include "crypto_aes.h"
#include "crypto_curves.h"

/* Key type definitions */
#define KEY_TYPE_RSA_1K 0x0001
#define KEY_TYPE_RSA_2K 0x0002
#define KEY_TYPE_RSA_3K 0x0004
#define KEY_TYPE_RSA_4K 0x0008
#define KEY_TYPE_EC     0x0010
#define KEY_TYPE_AES_128 0x0100
#define KEY_TYPE_AES_192 0x0200
#define KEY_TYPE_AES_256 0x0400
#define KEY_TYPE_AES_512 0x0800

#define KEY_TYPE_RSA_MASK 0x000F
#define KEY_TYPE_AES_MASK 0x0F00

/**
 * @brief Get curve ID from prime value
 * 
 * @param prime Prime number buffer
 * @param prime_len Length of prime buffer
 * @return mbedtls_ecp_group_id Curve ID or MBEDTLS_ECP_DP_NONE if not found
 */
mbedtls_ecp_group_id get_curve_from_prime(const uint8_t *prime, size_t prime_len);

/**
 * @brief AES-256-CFB encryption
 * 
 * @param key 256-bit key
 * @param iv Initialization vector (16 bytes)
 * @param data Input/output buffer
 * @param len Length of data
 * @return int 0 on success, -1 on error
 */
int aes_encrypt_cfb_256(const uint8_t *key, const uint8_t *iv, uint8_t *data, uint16_t len);

/**
 * @brief AES-256-CFB decryption
 * 
 * @param key 256-bit key
 * @param iv Initialization vector (16 bytes)
 * @param data Input/output buffer
 * @param len Length of data
 * @return int 0 on success, -1 on error
 */
int aes_decrypt_cfb_256(const uint8_t *key, const uint8_t *iv, uint8_t *data, uint16_t len);

/**
 * @brief Double hash PIN with XOR operation
 * 
 * @param pin Input PIN buffer
 * @param len Length of PIN
 * @param output Output buffer (32 bytes)
 * @return int 0 on success, -1 on error
 */
int double_hash_pin(const uint8_t *pin, uint16_t len, uint8_t output[32]);

/**
 * @brief Multiple iteration hash with device-specific seed
 * 
 * @param input Input buffer
 * @param len Length of input
 * @param output Output buffer (32 bytes)
 * @return int 0 on success, -1 on error
 */
int hash_multi(const uint8_t *input, uint16_t len, uint8_t output[32]);

/**
 * @brief Single SHA-256 hash
 * 
 * @param input Input buffer
 * @param len Length of input
 * @param output Output buffer (32 bytes)
 * @return int 0 on success, -1 on error
 */
int hash256(const uint8_t *input, size_t len, uint8_t output[32]);

#endif /* _CRYPTO_UTILS_H_ */
