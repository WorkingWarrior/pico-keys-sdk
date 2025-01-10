/* otp.c */
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

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "file.h"
#include "pico_keys.h"
#include "otp.h"
#include "random.h"
#include "mbedtls/ecdsa.h"

#ifdef PICO_RP2350
    #include "pico/bootrom.h"
    #include "hardware/structs/otp.h"
    #include "hardware/regs/otp_data.h"
#endif

/* Global variables */
const uint8_t *otp_key_1 = NULL;
const uint8_t *otp_key_2 = NULL;

#ifdef ESP_PLATFORM
    uint8_t _otp_key_1[32] = {0};
    uint8_t _otp_key_2[32] = {0};
#endif

/* Platform-specific type definitions and macros */
#ifdef PICO_RP2350
    typedef int otp_ret_t;
    #define OTP_WRITE(ROW, DATA, LEN)     otp_write_data(ROW, DATA, LEN)
    #define OTP_READ(ROW, PTR)            do { PTR = otp_buffer(ROW); } while(0)
    #define OTP_EMPTY(ROW, LEN)           is_empty_otp_buffer(ROW, LEN)
#elif defined(ESP_PLATFORM)
    typedef esp_err_t otp_ret_t;
    #define OTP_WRITE(ROW, DATA, LEN)     esp_efuse_write_key(ROW, ESP_EFUSE_KEY_PURPOSE_USER, DATA, LEN)
    #define OTP_READ(ROW, PTR)            do { \
                                            esp_err_t ret = read_key_from_efuse(ROW, _##PTR, sizeof(_##PTR)); \
                                            if (ret != ESP_OK) { printf("Error reading OTP key 1 [%d]\n", ret); } \
                                            PTR = _##PTR; \
                                         } while(0)
    #define OTP_EMPTY(ROW, LEN)           esp_efuse_key_block_unused(ROW)
#endif

#ifndef SECURE_BOOT_BOOTKEY_INDEX
    #define SECURE_BOOT_BOOTKEY_INDEX 0
#endif

/* RP2040-specific functions */
#ifdef PICO_RP2350

/**
 * @brief Checks if the buffer contains only zeros
 * 
 * This function iterates through the provided buffer and checks if all the bytes are zero.
 * 
 * @param buffer Pointer to the buffer to check
 * @param buffer_len Buffer length in bytes
 * @return true if buffer contains only zeros
 * @return false if buffer contains any non-zero values
 */
static inline bool is_empty_buffer(const uint8_t *buffer, size_t buffer_len) {
    if (buffer == NULL || buffer_len == 0) {
        return false;
    }
    const uint32_t *buf32 = (const uint32_t *)buffer;
    const size_t words = buffer_len >> 2;
    const size_t rem = buffer_len & 0x03;
    for (size_t i = 0; i < words; i++) {
        if (buf32[i] != 0) {
            return false;
        }
    }
    const uint8_t *rem_ptr = (const uint8_t *)&buf32[words];
    for (size_t i = 0; i < rem; i++) {
        if (rem_ptr[i] != 0) {
            return false;
        }
    }
    return true;
}

static int otp_write_data_mode(uint16_t row, uint8_t *data, size_t len, bool is_ecc) {
    otp_cmd_t cmd = {
        .flags = row | (is_ecc ? OTP_CMD_ECC_BITS : 0) | OTP_CMD_WRITE_BITS
    };
    uint32_t ret = rom_func_otp_access(data, len, cmd);
    if (ret) {
        printf("OTP Write failed with error: %ld\n", ret);
    }
    return ret;
}

int otp_write_data(uint16_t row, uint8_t *data, size_t len) {
    return otp_write_data_mode(row, data, len, true);
}

int otp_write_data_raw(uint16_t row, uint8_t *data, size_t len) {
    return otp_write_data_mode(row, data, len, false);
}

uint8_t* otp_buffer(uint16_t row) {
    volatile uint32_t *p = ((uint32_t *)(OTP_DATA_BASE + (row * 2)));
    return (uint8_t *)p;
}

uint8_t* otp_buffer_raw(uint16_t row) {
    volatile uint32_t *p = ((uint32_t *)(OTP_DATA_RAW_BASE + (row * 4)));
    return (uint8_t *)p;
}

bool is_empty_otp_buffer(uint16_t row, size_t len) {
    return is_empty_buffer(otp_buffer(row), len);
}

static bool is_otp_locked_page(uint8_t page) {
    volatile uint32_t *p = ((uint32_t *)(OTP_DATA_BASE + ((OTP_DATA_PAGE0_LOCK0_ROW + page * 2) * 2)));
    return ((p[0] & 0xFFFF0000) == 0x3C3C0000 && (p[1] & 0xFF) == 0x3C);
}

static void otp_lock_page(uint8_t page) {
    if (!is_otp_locked_page(page)) {
        uint32_t value = 0x3c3c3c;
        otp_write_data_raw(OTP_DATA_PAGE0_LOCK0_ROW + page * 2 + 1, (uint8_t *)&value, sizeof(value));
    }
    otp_hw->sw_lock[page] = 0b1100;
}

#endif

/* ESP32-specific functions */
#ifdef ESP_PLATFORM

esp_err_t read_key_from_efuse(esp_efuse_block_t block, uint8_t *key, size_t key_len) {
    const esp_efuse_desc_t **key_desc = esp_efuse_get_key(block);
    if (!key_desc) {
        return ESP_FAIL;
    }
    return esp_efuse_read_field_blob(key_desc, key, key_len * 8);
}

#endif

/* Common implementation */
int otp_enable_secure_boot(uint8_t bootkey, bool secure_lock) {
    if (bootkey >= OTP_MAX_BOOT_KEYS) {
        return OTP_ERROR_INVALID_PARAM;
    }

#ifdef PICO_RP2350
    static const uint8_t BOOTKEY[OTP_SECURE_BOOT_KEY_SIZE] = {
        0xE1, 0xD1, 0x6B, 0xA7, 0x64, 0xAB, 0xD7, 0x12,
        0xD4, 0xEF, 0x6E, 0x3E, 0xDD, 0x74, 0x4E, 0xD5,
        0x63, 0x8C, 0x26, 0x0B, 0x77, 0x1C, 0xF9, 0x81,
        0x51, 0x11, 0x0B, 0xAF, 0xAC, 0x9B, 0xC8, 0x71
    };

    int ret = OTP_SUCCESS;
    const uint16_t bootkey_row = OTP_DATA_BOOTKEY0_0_ROW + (OTP_SECURE_BOOT_KEY_SIZE/2) * bootkey;

    if (is_empty_otp_buffer(bootkey_row, OTP_SECURE_BOOT_KEY_SIZE)) {
        ret = otp_write_data(bootkey_row, (uint8_t*)BOOTKEY, OTP_SECURE_BOOT_KEY_SIZE);
        if (ret != OTP_SUCCESS) {
            return ret;
        }
    }

    uint8_t *boot_flags1 = otp_buffer_raw(OTP_DATA_BOOT_FLAGS1_ROW);
    uint8_t flagsb1[4] = {
        boot_flags1[0] | (1 << (bootkey + OTP_DATA_BOOT_FLAGS1_KEY_VALID_LSB)),
        boot_flags1[1],
        boot_flags1[2],
        0x00
    };

    if (secure_lock) {
        flagsb1[1] |= ((OTP_DATA_BOOT_FLAGS1_KEY_INVALID_BITS >> 
                       OTP_DATA_BOOT_FLAGS1_KEY_INVALID_LSB) & 
                      (~(1 << bootkey)));
    }

    const uint16_t boot_flag_rows[] = {
        OTP_DATA_BOOT_FLAGS1_ROW,
        OTP_DATA_BOOT_FLAGS1_R1_ROW,
        OTP_DATA_BOOT_FLAGS1_R2_ROW
    };

    for (size_t i = 0; i < sizeof(boot_flag_rows)/sizeof(boot_flag_rows[0]); i++) {
        if ((ret = otp_write_data_raw(boot_flag_rows[i], flagsb1, sizeof(flagsb1))) != OTP_SUCCESS) {
            return ret;
        }
    }

    uint8_t *crit1 = otp_buffer_raw(OTP_DATA_CRIT1_ROW);
    uint8_t flagsc1[4] = {
        crit1[0] | (1 << OTP_DATA_CRIT1_SECURE_BOOT_ENABLE_LSB),
        crit1[1],
        crit1[2],
        0x00
    };

    if (secure_lock) {
        flagsc1[0] |= (1 << OTP_DATA_CRIT1_DEBUG_DISABLE_LSB);
        flagsc1[0] |= (1 << OTP_DATA_CRIT1_GLITCH_DETECTOR_ENABLE_LSB);
        flagsc1[0] |= (3 << OTP_DATA_CRIT1_GLITCH_DETECTOR_SENS_LSB);
    }

    const uint16_t crit_rows[] = {
        OTP_DATA_CRIT1_ROW,
        OTP_DATA_CRIT1_R1_ROW,
        OTP_DATA_CRIT1_R2_ROW,
        OTP_DATA_CRIT1_R3_ROW,
        OTP_DATA_CRIT1_R4_ROW,
        OTP_DATA_CRIT1_R5_ROW,
        OTP_DATA_CRIT1_R6_ROW,
        OTP_DATA_CRIT1_R7_ROW
    };

    for (size_t i = 0; i < sizeof(crit_rows)/sizeof(crit_rows[0]); i++) {
        if ((ret = otp_write_data_raw(crit_rows[i], flagsc1, sizeof(flagsc1))) != OTP_SUCCESS) {
            return ret;
        }
    }

    if (secure_lock) {
        uint8_t *page1 = otp_buffer_raw(OTP_DATA_PAGE1_LOCK1_ROW);
        uint8_t page1v = page1[0] | (OTP_DATA_PAGE1_LOCK1_LOCK_BL_VALUE_READ_ONLY << 
                                    OTP_DATA_PAGE1_LOCK1_LOCK_BL_LSB);
        uint8_t flagsp1[4] = { page1v, page1v, page1v, 0x00 };
        if ((ret = otp_write_data_raw(OTP_DATA_PAGE1_LOCK1_ROW, flagsp1, sizeof(flagsp1))) != OTP_SUCCESS) {
            return ret;
        }

        uint8_t *page2 = otp_buffer_raw(OTP_DATA_PAGE2_LOCK1_ROW);
        uint8_t page2v = page2[0] | (OTP_DATA_PAGE2_LOCK1_LOCK_BL_VALUE_READ_ONLY << 
                                    OTP_DATA_PAGE2_LOCK1_LOCK_BL_LSB);
        uint8_t flagsp2[4] = { page2v, page2v, page2v, 0x00 };
        if ((ret = otp_write_data_raw(OTP_DATA_PAGE2_LOCK1_ROW, flagsp2, sizeof(flagsp2))) != OTP_SUCCESS) {
            return ret;
        }
    }

#elif defined(ESP_PLATFORM)
#endif

    return OTP_SUCCESS;
}

#if defined(PICO_RP2350) || defined(ESP_PLATFORM)

static void generate_random_key(uint8_t *key, size_t key_size) {
    random_gen(NULL, key, key_size);
}

static void generate_secp256k1_key(uint8_t *key, size_t key_size) {
    mbedtls_ecdsa_context ecdsa;
    size_t olen = 0;
    
    while (olen != 32) {
        mbedtls_ecdsa_init(&ecdsa);
        mbedtls_ecp_group_id ec_id = MBEDTLS_ECP_DP_SECP256K1;
        mbedtls_ecdsa_genkey(&ecdsa, ec_id, random_gen, NULL);
        mbedtls_ecp_write_key_ext(&ecdsa, &olen, key, key_size);
        mbedtls_ecdsa_free(&ecdsa);
    }
}

static void lock_otp_entry(uint16_t otp_index) {
#if defined(PICO_RP2350)
    otp_lock_page(otp_index >> 6);
#elif defined(ESP_PLATFORM)
    otp_ret_t ret;
    ret = esp_efuse_set_key_dis_write(otp_index);
    if (ret != ESP_OK) {
        printf("Error setting OTP key %d to read only [%d]\n", otp_index, ret);
    }
    ret = esp_efuse_set_keypurpose_dis_write(otp_index);
    if (ret != ESP_OK) {
        printf("Error setting OTP key %d purpose to read only [%d]\n", otp_index, ret);
    }
#endif
}

static bool initialize_otp_key(uint16_t key_index, void (*key_generator)(uint8_t*, size_t)) {
    if (key_index >= OTP_MAX_KEYS) {
        return false;
    }
    
    if (OTP_EMPTY(key_index, OTP_KEY_SIZE)) {
        uint8_t key[OTP_KEY_SIZE] = {0};
        key_generator(key, OTP_KEY_SIZE);
        
        otp_ret_t ret = OTP_WRITE(key_index, key, OTP_KEY_SIZE);
        if (ret != OTP_SUCCESS) {
            printf("Error writing OTP key %d [%d]\n", key_index, ret);
            return false;
        }
        return true;
    }
    return false;
}

void init_otp_files(void) {
    uint16_t write_otp[OTP_MAX_KEYS] = {0xFFFF, 0xFFFF};

    // Initialize MKEK
    if (initialize_otp_key(OTP_KEY_INDEX_MKEK, generate_random_key)) {
        write_otp[OTP_KEY_INDEX_MKEK] = OTP_KEY_1;
    }
    OTP_READ(OTP_KEY_1, otp_key_1);

    // Initialize DEVK
    if (initialize_otp_key(OTP_KEY_INDEX_DEVK, generate_secp256k1_key)) {
        write_otp[OTP_KEY_INDEX_DEVK] = OTP_KEY_2;
    }
    OTP_READ(OTP_KEY_2, otp_key_2);

    // Lock written OTP entries
    for (int i = 0; i < OTP_MAX_KEYS; i++) {
        if (write_otp[i] != 0xFFFF) {
            lock_otp_entry(write_otp[i]);
        }
    }
}

#endif
