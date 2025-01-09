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

#ifndef FLASH_FILE_SYSTEM_H
#define FLASH_FILE_SYSTEM_H

#include <stdint.h>
#include "file.h"

/**
 * Sets the bounds for the flash memory regions
 */
void flash_set_bounds(uintptr_t start, uintptr_t end);

/**
 * Writes data to a file
 */
int flash_write_data_to_file(file_t *file, const uint8_t *data, uint16_t len);

/**
 * Writes data to a file at specified offset
 */
int flash_write_data_to_file_offset(file_t *file, const uint8_t *data, uint16_t len, uint16_t offset);

/**
 * Clears a file from flash
 */
int flash_clear_file(file_t *file);

/**
 * Returns available free space in flash
 */
uint32_t flash_free_space(void);

/**
 * Returns used space in flash
 */
uint32_t flash_used_space(void);

/**
 * Returns total space in flash
 */
uint32_t flash_total_space(void);

/**
 * Returns number of files in flash
 */
uint32_t flash_num_files(void);

/**
 * Returns flash size
 */
uint32_t flash_size(void);

#endif /* FLASH_FILE_SYSTEM_H */
