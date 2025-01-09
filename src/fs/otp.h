/* otp.h */
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

#ifndef _OTP_H_
#define _OTP_H_

#ifdef PICO_RP2350
    /* RP2040 specific definitions */
    #define OTP_MKEK_ROW     0x0EF0
    #define OTP_DEVK_ROW     0x0ED0
    #define OTP_KEY_1        OTP_MKEK_ROW
    #define OTP_KEY_2        OTP_DEVK_ROW

    extern uint8_t* otp_buffer(uint16_t row);
    extern uint8_t* otp_buffer_raw(uint16_t row);
    extern bool is_empty_otp_buffer(uint16_t row, uint16_t len);
    extern int otp_write_data(uint16_t row, uint8_t *data, uint16_t len);
    extern int otp_write_data_raw(uint16_t row, uint8_t *data, uint16_t len);

#elif defined(ESP_PLATFORM)
    /* ESP32 specific definitions */
    #include "esp_efuse.h"
    #define OTP_KEY_1        EFUSE_BLK_KEY3
    #define OTP_KEY_2        EFUSE_BLK_KEY4

#endif

/* Common interface */
extern int otp_enable_secure_boot(uint8_t bootkey, bool secure_lock);
extern void init_otp_files(void);

extern const uint8_t *otp_key_1;
extern const uint8_t *otp_key_2;

#endif /* _OTP_H_ */
