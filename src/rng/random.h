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


#ifndef _RANDOM_H_
#define _RANDOM_H_

#include <stdlib.h>
#include <stdint.h>

#define MAX_RANDOM_BUFFER   (1024)
#define RANDOM_BYTES_LENGTH (32)
#define RANDOM_WORDS_COUNT  (RANDOM_BYTES_LENGTH / sizeof(uint32_t))

void random_init(void);

/* 32-byte random bytes */
const uint8_t *random_bytes_get(size_t);
void random_bytes_free(const uint8_t *p);

/* iterator returning a byta at a time */
extern int random_gen(void *arg, unsigned char *output, size_t output_len);

#endif
