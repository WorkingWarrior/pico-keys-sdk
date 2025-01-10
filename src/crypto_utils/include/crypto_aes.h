#ifndef CRYPTO_AES_H
#define CRYPTO_AES_H

#include "crypto_common.h"

/**
 * @brief AES operation modes
 */
typedef enum {
    AES_MODE_CBC = 1,   /**< Cipher Block Chaining mode */
    AES_MODE_CFB = 2    /**< Cipher Feedback mode */
} aes_mode_t;

#define PICO_KEYS_AES_MODE_CBC 1

/**
 * @brief Generic AES encryption function
 *
 * @param key Encryption key
 * @param iv Initialization vector (16 bytes) or NULL
 * @param key_size Key size in bits (128, 192, or 256)
 * @param mode AES operation mode
 * @param data Input/output buffer
 * @param len Length of data (must be multiple of 16 for CBC)
 * @return crypto_result_t Operation result
 */
crypto_result_t aes_encrypt(const uint8_t *key, const uint8_t *iv, 
                          uint16_t key_size, aes_mode_t mode,
                          uint8_t *data, uint16_t len);

/**
 * @brief Generic AES decryption function
 *
 * @param key Decryption key
 * @param iv Initialization vector (16 bytes) or NULL
 * @param key_size Key size in bits (128, 192, or 256)
 * @param mode AES operation mode
 * @param data Input/output buffer
 * @param len Length of data (must be multiple of 16 for CBC)
 * @return crypto_result_t Operation result
 */
crypto_result_t aes_decrypt(const uint8_t *key, const uint8_t *iv,
                          uint16_t key_size, aes_mode_t mode,
                          uint8_t *data, uint16_t len);

// /**
//  * @brief Convenience function for AES-256-CFB encryption
//  */
// crypto_result_t aes_encrypt_cfb_256(const uint8_t *key, const uint8_t *iv,
//                                    uint8_t *data, uint16_t len);

// /**
//  * @brief Convenience function for AES-256-CFB decryption
//  */
// crypto_result_t aes_decrypt_cfb_256(const uint8_t *key, const uint8_t *iv,
//                                    uint8_t *data, uint16_t len);

#endif /* CRYPTO_AES_H */