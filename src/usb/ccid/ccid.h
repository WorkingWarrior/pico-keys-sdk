/* ccid.h */
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

#ifndef _CCID_H_
#define _CCID_H_

#include <stdint.h>

/* Buffer sizes */
#define MAX_CMD_APDU_DATA_SIZE     (24 + 4 + 512 * 4)
#define MAX_RES_APDU_DATA_SIZE     (5 + 9 + 512 * 4)
#define CCID_MSG_HEADER_SIZE       10
#define USB_LL_BUF_SIZE           64

#if MAX_RES_APDU_DATA_SIZE > MAX_CMD_APDU_DATA_SIZE
    #define USB_BUF_SIZE          (MAX_RES_APDU_DATA_SIZE + 20 + 9)
#else
    #define USB_BUF_SIZE          (MAX_CMD_APDU_DATA_SIZE + 20 + 9)
#endif

/* CCID Commands */
#define CCID_SET_PARAMS                       0x61 /* non-ICCD command */
#define CCID_POWER_ON                         0x62
#define CCID_POWER_OFF                        0x63
#define CCID_SLOT_STATUS                      0x65 /* non-ICCD command */
#define CCID_SECURE                           0x69 /* non-ICCD command */
#define CCID_GET_PARAMS                       0x6C /* non-ICCD command */
#define CCID_RESET_PARAMS                     0x6D /* non-ICCD command */
#define CCID_XFR_BLOCK                        0x6F
#define CCID_DATA_BLOCK_RET                   0x80
#define CCID_SLOT_STATUS_RET                  0x81 /* non-ICCD result */
#define CCID_PARAMS_RET                       0x82 /* non-ICCD result */
#define CCID_SETDATARATEANDCLOCKFREQUENCY     0x73
#define CCID_SETDATARATEANDCLOCKFREQUENCY_RET 0x84

/* Message offsets */
#define CCID_MSG_SEQ_OFFSET        6
#define CCID_MSG_STATUS_OFFSET     7
#define CCID_MSG_ERROR_OFFSET      8
#define CCID_MSG_CHAIN_OFFSET      9
#define CCID_MSG_DATA_OFFSET       10  /* == CCID_MSG_HEADER_SIZE */
#define CCID_MAX_MSG_DATA_SIZE     USB_BUF_SIZE

/* Status codes */
#define CCID_STATUS_RUN           0x00
#define CCID_STATUS_PRESENT       0x01
#define CCID_STATUS_NOTPRESENT    0x02
#define CCID_CMD_STATUS_OK        0x00
#define CCID_CMD_STATUS_ERROR     0x40
#define CCID_CMD_STATUS_TIMEEXT   0x80

/* Error codes */
#define CCID_ERROR_XFR_OVERRUN    0xFC

/* Offset definitions */
#define CCID_OFFSET_CMD_NOT_SUPPORTED  0
#define CCID_OFFSET_DATA_LEN           1
#define CCID_OFFSET_PARAM              8

/* Thread states */
#define CCID_THREAD_TERMINATED    0xffff
#define CCID_ACK_TIMEOUT         0x6600

/* Data structures */
PACK(
typedef struct {
    uint8_t  bMessageType;
    uint32_t dwLength;
    uint8_t  bSlot;
    uint8_t  bSeq;
    uint8_t  abRFU0;
    uint16_t abRFU1;
    uint8_t  apdu;  /* Actually it is an array */
}) ccid_header_t;

/* CCID states */
enum ccid_state {
    CCID_STATE_NOCARD,          /* No card available */
    CCID_STATE_START,           /* Initial */
    CCID_STATE_WAIT,            /* Waiting APDU */
    CCID_STATE_EXECUTE,         /* Executing command */
    CCID_STATE_ACK_REQUIRED_0,  /* Ack required (executing) */
    CCID_STATE_ACK_REQUIRED_1,  /* Waiting user's ACK (execution finished) */
    CCID_STATE_EXITED,          /* CCID Thread Terminated */
    CCID_STATE_EXEC_REQUESTED,  /* Exec requested */
};

/* External declarations */
extern const uint8_t *ccid_atr;
extern const uint8_t historical_bytes[];

/* Function declarations */
int driver_process_usb_packet_ccid(uint8_t itf, uint16_t rx_read);

#endif /* _CCID_H_ */
