#ifndef HWRNG_H
#define HWRNG_H
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

#include <stdlib.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdbool.h>

#if defined(ENABLE_EMULATION)
    #include <time.h>
    #include <openssl/rand.h>
#elif defined(ESP_PLATFORM)
    #include "esp_timer.h"
    #include "esp_random.h"
    #include "driver/temp_sensor.h"
    #include "esp_adc/adc_oneshot.h"
    #include "esp_adc/adc_cali.h"
    #include "esp_adc/adc_cali_scheme.h"
#else
    #include "pico/stdlib.h"
    #include "hardware/timer.h"
    #include "pico/rand.h"
    #include "hardware/adc.h"
    #include "hardware/regs/addressmap.h"
    #include "hardware/regs/adc.h"
#endif

#include "mbedtls/platform_util.h"
#include "mbedtls/sha3.h"
#include "mbedtls/chacha20.h"
#include "ringbuffer/ringbuffer.h"

// Constants and macros
#define CHACHA_KEY_SIZE 32
#define CHACHA_NONCE_SIZE 12
#define ENTROPY_POOL_SIZE 64
#define RESEED_INTERVAL 1000000

// Error handling macros
#define CHECK_NULL(ptr) if(!ptr) return RNG_ERROR_INVALID_PARAM
#define CHECK_SIZE(size) if(size == 0) return RNG_ERROR_INVALID_PARAM
#define HANDLE_CRYPTO_ERROR(ret) if(ret != 0) return RNG_ERROR_CRYPTO_FAILED

// Type definitions
typedef enum {
    SUCCESS = 0,
    ERROR = -1
} error_status_t;

typedef enum {
    RNG_OK = 0,
    RNG_ERROR_INIT_FAILED,
    RNG_ERROR_NO_ENTROPY,
    RNG_ERROR_NEED_RESEED,
    RNG_ERROR_INVALID_PARAM,
    RNG_ERROR_CRYPTO_FAILED
} rng_status_t;

typedef struct {
    mbedtls_chacha20_context chacha;
    mbedtls_sha3_context sha3;
    uint8_t key[CHACHA_KEY_SIZE];
    uint8_t nonce[CHACHA_NONCE_SIZE];
    atomic_uint_least64_t reseed_counter;
    uint8_t entropy_pool[ENTROPY_POOL_SIZE];
} rng_state_t;

typedef struct {
    bool sensor_initialized;
    #if defined(ESP_PLATFORM)
        temp_sensor_handle_t temp_handle;
        adc_oneshot_unit_handle_t adc_handle;
        adc_cali_handle_t adc_cali_handle;
    #endif
} temp_sensor_config_t;

// Public API declarations
/**
 * @brief Initializes the random number generator
 * @param buf Buffer for storing random numbers
 * @param size Size of the buffer in 32-bit words
 * @return Status code
 */
rng_status_t hwrng_init(uint32_t *buf, uint8_t size);

/**
 * @brief Gets a random 32-bit number
 * @return Random number or 0 on error
 */
uint32_t hwrng_get_random(void);

/**
 * @brief Clears all internal states and buffers
 */
void hwrng_flush(void);

/**
 * @brief Waits until the random buffer is full
 */
void hwrng_wait_buffer_full(void);

/**
 * @brief Gets raw entropy from the generator
 * @param buffer Buffer to store entropy
 * @param len Length of buffer
 * @return Status code
 */
rng_status_t hwrng_get_entropy(uint8_t *buffer, size_t len);

/**
 * @brief Starts the hardware random number generator
 */
void hwrng_start(void);

/**
 * @brief Periodic task for maintaining the random number generator buffer
 *
 * This function checks if the random number buffer is full. If not, it generates
 * new random numbers to fill the buffer. It should be called periodically to ensure
 * random numbers are always available when needed.
 * 
 * @note This function is non-blocking and returns immediately even if the buffer
 *       is not completely filled.
 */
void hwrng_task(void);

#endif /* HWRNG_H */
