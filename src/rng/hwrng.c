#include "hwrng.h"
#include <string.h>
#include <stdatomic.h>

#if defined(ESP_PLATFORM)
static bool init_esp_temp_sensor(void);
#else
static bool init_rp2350_temp_sensor(void);
#endif

static error_status_t init_temp_sensor(void);
static void deinit_temp_sensor(void);
static error_status_t read_temp_raw(float *temperature, uint32_t *raw_reading);
static rng_status_t collect_temp_entropy(uint8_t *buffer, size_t size);
static rng_status_t collect_hardware_entropy(uint8_t *temp, size_t size);
static rng_status_t mix_entropy_sources(const uint8_t *temp_entropy,
                                        const uint8_t *hw_entropy,
                                        size_t entropy_size);
static rng_status_t collect_entropy(void);
static rng_status_t generate_new_key(void);
static rng_status_t init_chacha20(void);
static rng_status_t reseed(void);
static inline bool needs_reseed(void);

#if defined(ENABLE_EMULATION)
static uint64_t board_millis(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}
#elif defined(ESP_PLATFORM)
static uint64_t board_millis(void)
{
    return esp_timer_get_time() / 1000;
}
#else
static uint64_t board_millis(void)
{
    return to_ms_since_boot(get_absolute_time());
}
#endif

static rng_state_t rng_state = {0};
static ring_buffer_t rng_buffer;

static temp_sensor_config_t temp_config = {0};

#if defined(ESP_PLATFORM)
static bool init_esp_temp_sensor(void)
{
    temp_sensor_config_t temp_sensor = {
        .range_min = -20,
        .range_max = 110,
        .clk_div = 6,
    };

    if (temp_sensor_install(&temp_sensor, &temp_config.temp_handle) != ESP_OK)
    {
        return false;
    }

    if (temp_sensor_enable(temp_config.temp_handle) != ESP_OK)
    {
        temp_sensor_uninstall(temp_config.temp_handle);
        return false;
    }

    adc_oneshot_unit_init_cfg_t adc_config = {
        .unit_id = ADC_UNIT_1,
        .ulp_mode = ADC_ULP_MODE_DISABLE,
    };

    if (adc_oneshot_new_unit(&adc_config, &temp_config.adc_handle) != ESP_OK)
    {
        temp_sensor_disable(temp_config.temp_handle);
        temp_sensor_uninstall(temp_config.temp_handle);
        return false;
    }

    adc_cali_handle_t handle = NULL;
    adc_cali_curve_fitting_config_t cali_config = {
        .unit_id = ADC_UNIT_1,
        .atten = ADC_ATTEN_DB_11,
        .bit_width = ADC_BITWIDTH_DEFAULT,
    };

    if (adc_cali_create_scheme_curve_fitting(&cali_config, &handle) != ESP_OK)
    {
        adc_oneshot_del_unit(temp_config.adc_handle);
        temp_sensor_disable(temp_config.temp_handle);
        temp_sensor_uninstall(temp_config.temp_handle);
        return false;
    }

    temp_config.adc_cali_handle = handle;
    return true;
}
#endif

#if defined(PICO_RP2350)
static bool init_rp2350_temp_sensor(void)
{
    adc_init();
    adc_set_temp_sensor_enabled(true);
    adc_select_input(4);

    return true;
}
#endif

static error_status_t init_temp_sensor(void)
{
    if (temp_config.sensor_initialized)
    {
        return SUCCESS;
    }

#if defined(ESP_PLATFORM)
    if (!init_esp_temp_sensor())
    {
        return ERROR;
    }
#else
    if (!init_rp2350_temp_sensor())
    {
        return ERROR;
    }
#endif

    temp_config.sensor_initialized = true;
    return SUCCESS;
}

static void deinit_temp_sensor(void)
{
    if (!temp_config.sensor_initialized)
    {
        return;
    }

#if defined(ESP_PLATFORM)
    temp_sensor_disable(temp_config.temp_handle);
    temp_sensor_uninstall(temp_config.temp_handle);
    adc_oneshot_del_unit(temp_config.adc_handle);
    if (temp_config.adc_cali_handle)
    {
        adc_cali_delete_scheme_curve_fitting(temp_config.adc_cali_handle);
    }
#endif
#if defined(PICO_RP2350)
    adc_set_temp_sensor_enabled(false);
#endif

    temp_config.sensor_initialized = false;
}

static rng_status_t collect_hardware_entropy(uint8_t *temp, size_t size)
{
    CHECK_NULL(temp);
    CHECK_SIZE(size);

#if defined(ENABLE_EMULATION)
    return (RAND_bytes(temp, size) == 1) ? RNG_OK : RNG_ERROR_NO_ENTROPY;
#elif defined(ESP_PLATFORM)
    esp_fill_random(temp, size);
    return RNG_OK;
#else
    for (size_t i = 0; i < size; i += 8)
    {
        uint64_t rand = get_rand_64();
        size_t copy_size = MIN(8, size - i);
        memcpy(temp + i, &rand, copy_size);
    }
    return RNG_OK;
#endif
}

static rng_status_t mix_entropy_sources(const uint8_t *temp_entropy,
                                        const uint8_t *hw_entropy,
                                        size_t entropy_size)
{
    mbedtls_sha3_init(&rng_state.sha3);

    int ret = mbedtls_sha3_starts(&rng_state.sha3, MBEDTLS_SHA3_512);
    HANDLE_CRYPTO_ERROR(ret);

    const uint64_t timestamp = board_millis();
    ret = mbedtls_sha3_update(&rng_state.sha3, (uint8_t *)&timestamp, sizeof(timestamp));
    HANDLE_CRYPTO_ERROR(ret);

    ret = mbedtls_sha3_update(&rng_state.sha3, temp_entropy, entropy_size);
    HANDLE_CRYPTO_ERROR(ret);

    ret = mbedtls_sha3_update(&rng_state.sha3, hw_entropy, entropy_size);
    HANDLE_CRYPTO_ERROR(ret);

    ret = mbedtls_sha3_finish(&rng_state.sha3, rng_state.entropy_pool, ENTROPY_POOL_SIZE);
    HANDLE_CRYPTO_ERROR(ret);

    mbedtls_sha3_free(&rng_state.sha3);
    return RNG_OK;
}

/**
 * @brief Reads the raw temperature value from the hardware sensor.
 *
 * This function reads the raw temperature value from the hardware sensor and
 * returns it in the provided pointers. The temperature value is returned as a
 * floating-point number, and the raw reading is returned as a 32-bit unsigned
 * integer.
 *
 * @param[out] temperature Pointer to a float where the temperature value will be stored.
 * @param[out] raw_reading Pointer to a uint32_t where the raw reading will be stored.
 * @return error_status_t Returns an error status code indicating the success or failure of the operation.
 */
static error_status_t read_temp_raw(float *temperature, uint32_t *raw_reading)
{
    if (!temp_config.sensor_initialized || !temperature || !raw_reading)
    {
        return ERROR;
    }

#if defined(ESP_PLATFORM)
    if (temp_sensor_read_celsius(temp_config.temp_handle, temperature) != ESP_OK)
    {
        return ERROR;
    }

    int adc_raw;
    if (adc_oneshot_read(temp_config.adc_handle, ADC_CHANNEL_4, &adc_raw) != ESP_OK)
    {
        return ERROR;
    }
    *raw_reading = (uint32_t)adc_raw;
#else // RP2350
    adc_select_input(4);
    uint16_t raw = adc_read();
    *raw_reading = raw;

    const float conversion_factor = 3.3f / (1 << 12);
    float voltage = raw * conversion_factor;
    *temperature = 27.0f - (voltage - 0.706f) / 0.001721f;
#endif

    return SUCCESS;
}

static rng_status_t collect_temp_entropy(uint8_t *buffer, size_t size)
{
    CHECK_NULL(buffer);
    CHECK_SIZE(size);

    if (init_temp_sensor() != SUCCESS)
    {
        return RNG_ERROR_INIT_FAILED;
    }

    const int SAMPLES_PER_BYTE = 8;
    float temp_readings[SAMPLES_PER_BYTE];
    uint32_t raw_readings[SAMPLES_PER_BYTE];

    for (size_t byte_idx = 0; byte_idx < size; byte_idx++)
    {
        uint8_t entropy_byte = 0;
        bool valid_sample = false;

        for (int i = 0; i < SAMPLES_PER_BYTE; i++)
        {
            if (read_temp_raw(&temp_readings[i], &raw_readings[i]) != SUCCESS)
            {
                continue;
            }
            valid_sample = true;

#if defined(ESP_PLATFORM)
            vTaskDelay(pdMS_TO_TICKS(10));
#else
            busy_wait_us(50);
#endif
        }

        if (!valid_sample)
        {
            return RNG_ERROR_NO_ENTROPY;
        }

        for (int i = 0; i < SAMPLES_PER_BYTE; i++)
        {
            uint8_t temp_bit = (uint8_t)(temp_readings[i] * 100) & 0x01;
            uint8_t raw_bit = (uint8_t)(raw_readings[i]) & 0x01;
            uint8_t combined_bit = temp_bit ^ raw_bit;
            entropy_byte |= (combined_bit << i);
        }

        buffer[byte_idx] = entropy_byte;
    }

    return RNG_OK;
}

static rng_status_t collect_entropy(void)
{
    uint8_t hw_entropy[ENTROPY_POOL_SIZE];
    uint8_t temp_entropy[ENTROPY_POOL_SIZE / 2];

    rng_status_t status = collect_temp_entropy(temp_entropy, sizeof(temp_entropy));
    if (status != RNG_OK) {
        return status;
    }

    status = collect_hardware_entropy(hw_entropy, sizeof(hw_entropy));
    if (status != RNG_OK) {
        return status;
    }

    return mix_entropy_sources(temp_entropy, hw_entropy, ENTROPY_POOL_SIZE);
}

static rng_status_t generate_new_key(void)
{
    mbedtls_sha3_init(&rng_state.sha3);

    int ret = mbedtls_sha3_starts(&rng_state.sha3, MBEDTLS_SHA3_256);
    HANDLE_CRYPTO_ERROR(ret);

    ret = mbedtls_sha3_update(&rng_state.sha3, rng_state.entropy_pool, ENTROPY_POOL_SIZE);
    HANDLE_CRYPTO_ERROR(ret);

    ret = mbedtls_sha3_finish(&rng_state.sha3, rng_state.key, CHACHA_KEY_SIZE);
    HANDLE_CRYPTO_ERROR(ret);

    mbedtls_sha3_free(&rng_state.sha3);
    return RNG_OK;
}

static rng_status_t init_chacha20(void)
{
    mbedtls_chacha20_free(&rng_state.chacha);
    mbedtls_chacha20_init(&rng_state.chacha);

    int ret = mbedtls_chacha20_setkey(&rng_state.chacha, rng_state.key);
    HANDLE_CRYPTO_ERROR(ret);

    return RNG_OK;
}

static rng_status_t reseed(void)
{
    rng_status_t status = collect_entropy();
    if (status != RNG_OK) {
        return status;
    }

    status = generate_new_key();
    if (status != RNG_OK) {
        return status;
    }

    memcpy(rng_state.nonce, rng_state.entropy_pool + CHACHA_KEY_SIZE, CHACHA_NONCE_SIZE);

    status = init_chacha20();
    if (status != RNG_OK) {
        return status;
    }

    atomic_store(&rng_state.reseed_counter, 0);
    return RNG_OK;
}

static inline bool needs_reseed(void)
{
    return atomic_load(&rng_state.reseed_counter) >= RESEED_INTERVAL;
}

rng_status_t hwrng_init(uint32_t *buf, uint8_t size)
{
    CHECK_NULL(buf);
    CHECK_SIZE(size);

    ring_buffer_init(&rng_buffer, buf, size);

    mbedtls_chacha20_init(&rng_state.chacha);
    reseed();

    hwrng_start();

    return RNG_OK;
}

uint32_t hwrng_get_random(void)
{
    uint32_t value = 0;
    static uint32_t counter = 0;

    if (needs_reseed())
    {
        if (reseed() != RNG_OK)
        {
            return 0;
        }
    }

    while (ring_buffer_is_empty(&rng_buffer))
    {
        uint8_t output[8] = {0};

        if (mbedtls_chacha20_crypt(
                rng_state.key,
                rng_state.nonce,
                counter++,
                sizeof(output),
                NULL,
                output) != 0)
        {
            return 0;
        }

        const uint32_t *words = (const uint32_t *)output;
        if (!ring_buffer_put(&rng_buffer, words[0]))
        {
            break;
        }
        if (!ring_buffer_is_full(&rng_buffer) && !ring_buffer_put(&rng_buffer, words[1]))
        {
            break;
        }

        atomic_fetch_add(&rng_state.reseed_counter, 1);
    }

    return ring_buffer_get(&rng_buffer, &value) ? value : 0;
}

void hwrng_flush(void)
{
    ring_buffer_clear(&rng_buffer);

    mbedtls_platform_zeroize(rng_state.key, sizeof(rng_state.key));
    mbedtls_platform_zeroize(rng_state.nonce, sizeof(rng_state.nonce));
    mbedtls_platform_zeroize(&rng_state.chacha, sizeof(rng_state.chacha));
    mbedtls_platform_zeroize(&rng_state.sha3, sizeof(rng_state.sha3));
    mbedtls_platform_zeroize(rng_state.entropy_pool, sizeof(rng_state.entropy_pool));
    atomic_store(&rng_state.reseed_counter, 0);
    deinit_temp_sensor();
}

void hwrng_wait_buffer_full(void)
{
    while (!ring_buffer_is_full(&rng_buffer))
    {
        uint32_t dummy;
        if (!ring_buffer_get(&rng_buffer, &dummy))
        {
            hwrng_get_random();
        }
    }
}

void hwrng_task(void)
{
    if (!ring_buffer_is_full(&rng_buffer))
    {
        hwrng_get_random();
    }
}

rng_status_t hwrng_get_entropy(uint8_t *buffer, size_t len)
{
    CHECK_NULL(buffer);
    CHECK_SIZE(len);

    rng_status_t status;
    for (size_t i = 0; i < len; i += ENTROPY_POOL_SIZE)
    {
        size_t chunk_size = MIN(ENTROPY_POOL_SIZE, len - i);
        status = collect_entropy();
        if (status != RNG_OK)
        {
            return status;
        }
        memcpy(buffer + i, rng_state.entropy_pool, chunk_size);
    }
    return RNG_OK;
}

void hwrng_start(void)
{
#if defined(ENABLE_EMULATION)
    srand(time(NULL));
#elif defined(ESP_PLATFORM)
    bootloader_random_enable();
#else
#endif
}
