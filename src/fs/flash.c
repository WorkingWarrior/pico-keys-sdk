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

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#if defined(ENABLE_EMULATION) || defined(ESP_PLATFORM)
    #define XIP_BASE                0
    #define FLASH_SECTOR_SIZE       4096
    #ifdef ESP_PLATFORM
        uint32_t PICO_FLASH_SIZE_BYTES = (1 * 1024 * 1024);
    #else
        #define PICO_FLASH_SIZE_BYTES   (8 * 1024 * 1024)
    #endif
#else
    #include "pico/stdlib.h"
    #include "hardware/flash.h"
#endif

#include "pico_keys.h"
#include "file.h"
#include "flash_file_system.h"

/* Private types and definitions */
typedef enum {
    INTERNAL_OK = 0,
    INTERNAL_ERROR_NULL_POINTER,
    INTERNAL_ERROR_INVALID_SIZE,
    INTERNAL_ERROR_OUT_OF_MEMORY,
    INTERNAL_ERROR_INVALID_ADDRESS,
} internal_error_t;

/* Flash memory layout constants */
#define FLASH_DATA_HEADER_SIZE (sizeof(uintptr_t) + sizeof(uint32_t))
#define FLASH_PERMANENT_REGION (4 * FLASH_SECTOR_SIZE)

/* Global variables - keeping original names and visibility */
uintptr_t end_flash, end_rom_pool, start_rom_pool, end_data_pool, start_data_pool;
uintptr_t last_base;
uint32_t num_files = 0;

/* External function declarations - keeping original */
extern int flash_program_block(uintptr_t addr, const uint8_t *data, size_t len);
extern int flash_program_halfword(uintptr_t addr, uint16_t data);
extern int flash_program_uintptr(uintptr_t, uintptr_t);
extern uintptr_t flash_read_uintptr(uintptr_t addr);
extern uint16_t flash_read_uint16(uintptr_t addr);
extern uint8_t *flash_read(uintptr_t addr);
extern void low_flash_available();

/* Private helper functions */
static inline int convert_internal_error(internal_error_t err) {
    switch (err) {
        case INTERNAL_OK: 
            return PICOKEY_OK;
        case INTERNAL_ERROR_NULL_POINTER: 
            return PICOKEY_ERR_NULL_PARAM;
        case INTERNAL_ERROR_OUT_OF_MEMORY: 
            return PICOKEY_ERR_NO_MEMORY;
        case INTERNAL_ERROR_INVALID_SIZE:
        case INTERNAL_ERROR_INVALID_ADDRESS:
        default:
            return PICOKEY_ERR_MEMORY_FATAL;
    }
}

static inline bool validate_file(const file_t *file) {
    return (file != NULL);
}

static inline bool validate_address(uintptr_t addr) {
    return (addr >= start_data_pool && addr <= end_flash);
}

static inline bool validate_size(uint16_t size) {
    return (size <= FLASH_SECTOR_SIZE);
}

/* Original public functions with internal implementations */
void flash_set_bounds(uintptr_t start, uintptr_t end) {
    end_flash = end;
    end_rom_pool = end_flash - FLASH_DATA_HEADER_SIZE - 4;
    start_rom_pool = end_rom_pool - FLASH_PERMANENT_REGION;
    end_data_pool = start_rom_pool - FLASH_DATA_HEADER_SIZE;
    start_data_pool = start;
    last_base = end_data_pool;
}

/* Internal allocation function */
static internal_error_t allocate_free_addr_internal(uint16_t size, bool persistent, uintptr_t *out_addr) {
    if (!validate_size(size) || !out_addr) {
        return INTERNAL_ERROR_INVALID_SIZE;
    }

    size_t real_size = size + sizeof(uint16_t) + sizeof(uintptr_t) + 
                       sizeof(uint16_t) + sizeof(uintptr_t);
    uintptr_t next_base = 0x0;
    uintptr_t endp = persistent ? end_rom_pool : end_data_pool;
    uintptr_t startp = persistent ? start_rom_pool : start_data_pool;

    for (uintptr_t base = endp; base >= startp; base = next_base) {
        uintptr_t addr_alg = base & -FLASH_SECTOR_SIZE;
        uintptr_t potential_addr = base - real_size;
        next_base = flash_read_uintptr(base);

        if (next_base == 0x0) {
            if (addr_alg <= potential_addr) {
                flash_program_uintptr(potential_addr, 0x0);
                flash_program_uintptr(potential_addr + sizeof(uintptr_t), base);
                flash_program_uintptr(base, potential_addr);
                *out_addr = potential_addr;
                return INTERNAL_OK;
            }
            else if (addr_alg - FLASH_SECTOR_SIZE >= startp) {
                potential_addr = addr_alg - real_size;
                flash_program_uintptr(potential_addr, 0x0);
                flash_program_uintptr(potential_addr + sizeof(uintptr_t), base);
                flash_program_uintptr(base, potential_addr);
                *out_addr = potential_addr;
                return INTERNAL_OK;
            }
            return INTERNAL_ERROR_OUT_OF_MEMORY;
        }
        else if (addr_alg <= potential_addr &&
                 base - (next_base + flash_read_uint16(next_base + sizeof(uintptr_t) + 
                 sizeof(uintptr_t) + sizeof(uint16_t)) + 2 * sizeof(uint16_t) + 
                 2 * sizeof(uintptr_t)) > base - potential_addr &&
                 (flash_read_uint16(next_base + 2 * sizeof(uintptr_t)) & 0x1000) != 0x1000) {
            
            flash_program_uintptr(potential_addr, next_base);
            flash_program_uintptr(next_base + sizeof(uintptr_t), potential_addr);
            flash_program_uintptr(potential_addr + sizeof(uintptr_t), base);
            flash_program_uintptr(base, potential_addr);
            *out_addr = potential_addr;
            return INTERNAL_OK;
        }
    }
    return INTERNAL_ERROR_OUT_OF_MEMORY;
}

/* Original public functions implementation */
int flash_clear_file(file_t *file) {
    if (!validate_file(file) || !file->data) {
        return PICOKEY_OK;
    }

    uintptr_t base_addr = (uintptr_t)(file->data - sizeof(uintptr_t) - 
                                     sizeof(uint16_t) - sizeof(uintptr_t));
    uintptr_t prev_addr = flash_read_uintptr(base_addr + sizeof(uintptr_t));
    uintptr_t next_addr = flash_read_uintptr(base_addr);

    flash_program_uintptr(prev_addr, next_addr);
    flash_program_halfword((uintptr_t)file->data, 0);
    
    if (next_addr > 0) {
        flash_program_uintptr(next_addr + sizeof(uintptr_t), prev_addr);
    }
    
    flash_program_uintptr(base_addr, 0);
    flash_program_uintptr(base_addr + sizeof(uintptr_t), 0);
    file->data = NULL;
    num_files--;
    
    return PICOKEY_OK;
}

int flash_write_data_to_file(file_t *file, const uint8_t *data, uint16_t len) {
    return flash_write_data_to_file_offset(file, data, len, 0);
}

int flash_write_data_to_file_offset(file_t *file, const uint8_t *data, 
                                  uint16_t len, uint16_t offset) {
    if (!validate_file(file)) {
        return PICOKEY_ERR_NULL_PARAM;
    }

    if (offset + len > FLASH_SECTOR_SIZE) {
        return PICOKEY_ERR_NO_MEMORY;
    }

    uint16_t size_file_flash = file->data ? flash_read_uint16((uintptr_t)file->data) : 0;
    uint8_t *old_data = NULL;

    if (file->data) {
        if (offset + len <= size_file_flash) {
            flash_program_halfword((uintptr_t)file->data, offset + len);
            if (data) {
                flash_program_block((uintptr_t)file->data + sizeof(uint16_t) + offset, 
                                  data, len);
            }
            return PICOKEY_OK;
        }

        flash_clear_file(file);
        if (offset > 0) {
            old_data = (uint8_t *)calloc(1, offset + len);
            if (!old_data) {
                return PICOKEY_ERR_NO_MEMORY;
            }
            memcpy(old_data, flash_read((uintptr_t)(file->data + sizeof(uint16_t))), offset);
            memcpy(old_data + offset, data, len);
            len = offset + len;
            data = old_data;
        }
    }

    uintptr_t new_addr;
    internal_error_t err = allocate_free_addr_internal(len, (file->type & FILE_PERSISTENT), &new_addr);
    
    if (err != INTERNAL_OK) {
        if (old_data) {
            free(old_data);
        }
        return convert_internal_error(err);
    }

    if (new_addr < last_base) {
        last_base = new_addr;
    }

    file->data = (uint8_t *)new_addr + sizeof(uintptr_t) + sizeof(uint16_t) + 
                 sizeof(uintptr_t);
    flash_program_halfword(new_addr + sizeof(uintptr_t) + sizeof(uintptr_t), file->fid);
    flash_program_halfword((uintptr_t)file->data, len);
    
    if (data) {
        flash_program_block((uintptr_t)file->data + sizeof(uint16_t), data, len);
    }

    if (old_data) {
        free(old_data);
    }

    num_files++;
    return PICOKEY_OK;
}

/* Status functions - keeping original interface */
uint32_t flash_free_space(void) {
    return last_base - start_data_pool;
}

uint32_t flash_used_space(void) {
    return end_data_pool - last_base;
}

uint32_t flash_total_space(void) {
    return end_data_pool - start_data_pool;
}

uint32_t flash_num_files(void) {
    return num_files;
}

uint32_t flash_size(void) {
    return PICO_FLASH_SIZE_BYTES;
}
