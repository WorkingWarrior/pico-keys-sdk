/* ccid.c */
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

#include "random.h"
#include "pico_keys.h"
#include "ccid.h"
#include "usb_descriptors.h"
#include "apdu.h"
#include "usb.h"

#ifdef PICO_PLATFORM
    #include "bsp/board.h"
#endif

#ifndef ENABLE_EMULATION
    #include "tusb.h"
    #include "device/usbd_pvt.h"
#else
    #include "emulation.h"
#endif

/* Global variables */
uint8_t ccid_status = 1;

#ifndef ENABLE_EMULATION
    static uint8_t itf_num;
#endif

static usb_buffer_t ccid_rx[ITF_SC_TOTAL] = {0};
static usb_buffer_t ccid_tx[ITF_SC_TOTAL] = {0};

ccid_header_t *ccid_response[ITF_SC_TOTAL];
ccid_header_t *ccid_resp_fast[ITF_SC_TOTAL];
ccid_header_t *ccid_header[ITF_SC_TOTAL];

/* Static CCID parameters for GET_PARAMS command */
static const uint8_t ccid_params[] = {
    0x11, /* bmFindexDindex */
    0x10, /* bmTCCKST1 */
    0xFE, /* bGuardTimeT1 */
    0x55, /* bmWaitingIntegersT1 */
    0x03, /* bClockStop */
    0xFE, /* bIFSC */
    0x00  /* bNadValue */
};

/* Helper functions */
static uint8_t sc_itf_to_usb_itf(uint8_t itf) {
    if (itf == ITF_SC_CCID) {
        return ITF_CCID;
    }
    else if (itf == ITF_SC_WCID) {
        return ITF_WCID;
    }
    return itf;
}

/* CCID Interface functions */
void ccid_write_offset(uint8_t itf, uint16_t size, uint16_t offset) {
    ccid_tx[itf].w_ptr += size + offset;
    ccid_tx[itf].r_ptr += offset;
}

void ccid_write(uint8_t itf, uint16_t size) {
    ccid_write_offset(itf, size, 0);
}

int driver_init_ccid(uint8_t itf) {
    ccid_header[itf] = (ccid_header_t *)(ccid_rx[itf].buffer + ccid_rx[itf].r_ptr);
    ccid_resp_fast[itf] = (ccid_header_t *)(ccid_tx[itf].buffer + sizeof(ccid_tx[itf].buffer) - 64);
    ccid_response[itf] = (ccid_header_t *)(ccid_tx[itf].buffer + ccid_tx[itf].w_ptr);
    
    usb_set_timeout_counter(sc_itf_to_usb_itf(itf), 1500);
    
    return PICOKEY_OK;
}

/* USB Vendor callbacks */
void tud_vendor_rx_cb(uint8_t itf, const uint8_t *buffer, uint16_t bufsize) {
    uint32_t len = tud_vendor_n_available(itf);
    
    do {
        uint16_t tlen = (len > 0xFFFF) ? 0xFFFF : (uint16_t)len;
        tlen = (uint16_t)tud_vendor_n_read(itf, ccid_rx[itf].buffer + ccid_rx[itf].w_ptr, tlen);
        ccid_rx[itf].w_ptr += tlen;
        driver_process_usb_packet_ccid(itf, tlen);
        len -= tlen;
    } while (len > 0);
}

void tud_vendor_tx_cb(uint8_t itf, uint32_t sent_bytes) {
    (void)sent_bytes;
    tud_vendor_n_write_flush(itf);
}

/* Driver interface functions */
int driver_write_ccid(uint8_t itf, const uint8_t *tx_buffer, uint16_t buffer_size) {
    if (*tx_buffer != 0x81) {
        DEBUG_PAYLOAD(tx_buffer, buffer_size);
    }
    
    int r = tud_vendor_n_write(itf, tx_buffer, buffer_size);
    if (r > 0) {
        tud_vendor_n_flush(itf);
        
        ccid_tx[itf].r_ptr += (uint16_t)buffer_size;
        if (ccid_tx[itf].r_ptr >= ccid_tx[itf].w_ptr) {
            ccid_tx[itf].r_ptr = ccid_tx[itf].w_ptr = 0;
        }
    }

#ifdef ENABLE_EMULATION
    tud_vendor_tx_cb(itf, r);
#endif

    return r;
}

int ccid_write_fast(uint8_t itf, const uint8_t *buffer, uint16_t buffer_size) {
    return driver_write_ccid(itf, buffer, buffer_size);
}

/* CCID packet processing */
int driver_process_usb_packet_ccid(uint8_t itf, uint16_t rx_read) {
    (void)rx_read;
    
    if (ccid_rx[itf].w_ptr - ccid_rx[itf].r_ptr >= 10) {
        driver_init_ccid(itf);
        
        if (ccid_header[itf]->dwLength <= (uint32_t)(ccid_rx[itf].w_ptr - ccid_rx[itf].r_ptr - 10)) {
            ccid_rx[itf].r_ptr += (uint16_t)(ccid_header[itf]->dwLength + 10);
            if (ccid_rx[itf].r_ptr >= ccid_rx[itf].w_ptr) {
                ccid_rx[itf].r_ptr = ccid_rx[itf].w_ptr = 0;
            }

            size_t apdu_sent = 0;
            if (ccid_header[itf]->bMessageType != CCID_SLOT_STATUS) {
                DEBUG_PAYLOAD((uint8_t *)ccid_header[itf], ccid_header[itf]->dwLength + 10);
            }

            /* Handle different CCID message types */
            switch (ccid_header[itf]->bMessageType) {
                case CCID_SLOT_STATUS:
                    ccid_resp_fast[itf]->bMessageType = CCID_SLOT_STATUS_RET;
                    ccid_resp_fast[itf]->dwLength = 0;
                    ccid_resp_fast[itf]->bSlot = 0;
                    ccid_resp_fast[itf]->bSeq = ccid_header[itf]->bSeq;
                    ccid_resp_fast[itf]->abRFU0 = ccid_status;
                    ccid_resp_fast[itf]->abRFU1 = 0;
                    ccid_write_fast(itf, (const uint8_t *)ccid_resp_fast[itf], 10);
                    break;

                case CCID_POWER_ON: {
                    size_t size_atr = (ccid_atr ? ccid_atr[0] : 0);
                    ccid_resp_fast[itf]->bMessageType = CCID_DATA_BLOCK_RET;
                    ccid_resp_fast[itf]->dwLength = (uint32_t)size_atr;
                    ccid_resp_fast[itf]->bSlot = 0;
                    ccid_resp_fast[itf]->bSeq = ccid_header[itf]->bSeq;
                    ccid_resp_fast[itf]->abRFU0 = 0;
                    ccid_resp_fast[itf]->abRFU1 = 0;
                    
                    memcpy(&ccid_resp_fast[itf]->apdu, ccid_atr + 1, size_atr);
                    if (ccid_status == 1) {
                        //card_start(apdu_thread);
                    }
                    ccid_status = 0;
                    ccid_write_fast(itf, (const uint8_t *)ccid_resp_fast[itf], (uint16_t)(size_atr + 10));
                    led_set_mode(MODE_MOUNTED);
                    break;
                }

                case CCID_POWER_OFF:
                    if (ccid_status == 0) {
                        //card_exit(0);
                    }
                    ccid_status = 1;
                    ccid_resp_fast[itf]->bMessageType = CCID_SLOT_STATUS_RET;
                    ccid_resp_fast[itf]->dwLength = 0;
                    ccid_resp_fast[itf]->bSlot = 0;
                    ccid_resp_fast[itf]->bSeq = ccid_header[itf]->bSeq;
                    ccid_resp_fast[itf]->abRFU0 = ccid_status;
                    ccid_resp_fast[itf]->abRFU1 = 0;
                    ccid_write_fast(itf, (const uint8_t *)ccid_resp_fast[itf], 10);
                    led_set_mode(MODE_SUSPENDED);
                    break;

                case CCID_SET_PARAMS:
                case CCID_GET_PARAMS:
                case CCID_RESET_PARAMS:
                    ccid_resp_fast[itf]->bMessageType = CCID_PARAMS_RET;
                    ccid_resp_fast[itf]->dwLength = sizeof(ccid_params);
                    ccid_resp_fast[itf]->bSlot = 0;
                    ccid_resp_fast[itf]->bSeq = ccid_header[itf]->bSeq;
                    ccid_resp_fast[itf]->abRFU0 = ccid_status;
                    ccid_resp_fast[itf]->abRFU1 = 0x0100;
                    memcpy(&ccid_resp_fast[itf]->apdu, ccid_params, sizeof(ccid_params));
                    ccid_write_fast(itf, (const uint8_t *)ccid_resp_fast[itf], sizeof(ccid_params) + 10);
                    break;

                case CCID_SETDATARATEANDCLOCKFREQUENCY:
                    ccid_resp_fast[itf]->bMessageType = CCID_SETDATARATEANDCLOCKFREQUENCY_RET;
                    ccid_resp_fast[itf]->dwLength = 8;
                    ccid_resp_fast[itf]->bSlot = 0;
                    ccid_resp_fast[itf]->bSeq = ccid_header[itf]->bSeq;
                    ccid_resp_fast[itf]->abRFU0 = ccid_status;
                    ccid_resp_fast[itf]->abRFU1 = 0;
                    memset(&ccid_resp_fast[itf]->apdu, 0, 8);
                    ccid_write_fast(itf, (const uint8_t *)ccid_resp_fast[itf], 18);
                    break;

                case CCID_XFR_BLOCK:
                    apdu.rdata = &ccid_response[itf]->apdu;
                    apdu_sent = apdu_process(itf, &ccid_header[itf]->apdu, (uint16_t)ccid_header[itf]->dwLength);
                    #ifndef ENABLE_EMULATION
                    if (apdu_sent > 0) {
                        card_start(sc_itf_to_usb_itf(itf), apdu_thread);
                        usb_send_event(EV_CMD_AVAILABLE);
                    }
                    #endif
                    break;
            }
            return (uint16_t)apdu_sent;
        }
    }
    return 0;
}

/* Driver execution handlers */
void driver_exec_timeout_ccid(uint8_t itf) {
    ccid_resp_fast[itf]->bMessageType = CCID_DATA_BLOCK_RET;
    ccid_resp_fast[itf]->dwLength = 0;
    ccid_resp_fast[itf]->bSlot = 0;
    ccid_resp_fast[itf]->bSeq = ccid_header[itf]->bSeq;
    ccid_resp_fast[itf]->abRFU0 = CCID_CMD_STATUS_TIMEEXT;
    ccid_resp_fast[itf]->abRFU1 = 0;
    ccid_write_fast(itf, (const uint8_t *)ccid_resp_fast[itf], 10);
}

void driver_exec_finished_ccid(uint8_t itf, uint16_t size_next) {
    driver_exec_finished_cont_ccid(itf, size_next, 0);
}

void driver_exec_finished_cont_ccid(uint8_t itf, uint16_t size_next, uint16_t offset) {
    ccid_response[itf] = (ccid_header_t *)(ccid_tx[itf].buffer + ccid_tx[itf].w_ptr + offset);
    ccid_response[itf]->bMessageType = CCID_DATA_BLOCK_RET;
    ccid_response[itf]->dwLength = size_next;
    ccid_response[itf]->bSlot = 0;
    ccid_response[itf]->bSeq = ccid_header[itf]->bSeq;
    ccid_response[itf]->abRFU0 = ccid_status;
    ccid_response[itf]->abRFU1 = 0;
    ccid_write_offset(itf, size_next + 10, offset);
}

/* Main CCID task */
void ccid_task(void) {
    for (int itf = 0; itf < ITF_SC_TOTAL; itf++) {
        int status = card_status(sc_itf_to_usb_itf(itf));
        if (status == PICOKEY_OK) {
            driver_exec_finished_ccid(itf, finished_data_size);
        }
        else if (status == PICOKEY_ERR_BLOCKED) {
            driver_exec_timeout_ccid(itf);
        }
        
        if (ccid_tx[itf].w_ptr > ccid_tx[itf].r_ptr) {
            driver_write_ccid(itf, 
                            ccid_tx[itf].buffer + ccid_tx[itf].r_ptr,
                            ccid_tx[itf].w_ptr - ccid_tx[itf].r_ptr);
        }
    }
}

#ifndef ENABLE_EMULATION

#define USB_CONFIG_ATT_ONE      TU_BIT(7)
#define MAX_USB_POWER           1

/* USB CCID Driver Implementation */
static void ccid_init_cb(void) {
    vendord_init();
}

static void ccid_reset_cb(uint8_t rhport) {
    itf_num = 0;
    vendord_reset(rhport);
}

static uint16_t ccid_open(uint8_t rhport, tusb_desc_interface_t const *itf_desc, uint16_t max_len) {
    /* Verify CCID interface descriptor */
    TU_VERIFY(itf_desc->bInterfaceClass == TUSB_CLASS_SMART_CARD && 
              itf_desc->bInterfaceSubClass == 0 && 
              itf_desc->bInterfaceProtocol == 0, 0);

    /* Calculate driver length */
    uint16_t const drv_len = sizeof(tusb_desc_interface_t) + 
                            sizeof(struct ccid_class_descriptor) + 
                            TUSB_SMARTCARD_CCID_EPS * sizeof(tusb_desc_endpoint_t);
    
    /* Prepare vendor interface descriptor */
    uint8_t *itf_vendor = (uint8_t *)malloc(sizeof(uint8_t) * max_len);
    memcpy(itf_vendor, itf_desc, sizeof(uint8_t) * max_len);
    ((tusb_desc_interface_t *)itf_vendor)->bInterfaceClass = TUSB_CLASS_VENDOR_SPECIFIC;

#if TUSB_SMARTCARD_CCID_EPS == 3
    /* Special handling for 3 endpoints */
    ((tusb_desc_interface_t *)itf_vendor)->bNumEndpoints -= 1;
    vendord_open(rhport, (tusb_desc_interface_t *)itf_vendor, max_len - sizeof(tusb_desc_endpoint_t));

    /* Open additional endpoint */
    tusb_desc_endpoint_t const *desc_ep = (tusb_desc_endpoint_t const *)
        ((uint8_t *)itf_desc + drv_len - sizeof(tusb_desc_endpoint_t));
    TU_ASSERT(usbd_edpt_open(rhport, desc_ep), 0);

    /* Send initial message */
    uint8_t msg[] = { 0x50, 0x03 };
    usbd_edpt_xfer(rhport, desc_ep->bEndpointAddress, msg, sizeof(msg));
#else
    vendord_open(rhport, (tusb_desc_interface_t *)itf_vendor, max_len);
#endif

    free(itf_vendor);
    TU_VERIFY(max_len >= drv_len, 0);
    itf_num = itf_desc->bInterfaceNumber;
    
    return drv_len;
}

static bool ccid_control_xfer_cb(uint8_t __unused rhport,
                                uint8_t stage,
                                tusb_control_request_t const *request) {
    /* Handle only SETUP stage */
    if (stage != CONTROL_STAGE_SETUP) {
        return true;
    }

    /* Process only requests for our interface */
    if (request->wIndex == itf_num) {
        TU_LOG2("-------- CCID CTRL XFER\n");
        TU_LOG2("-------- bmRequestType %x, bRequest %x, wValue %x, wLength %x\n",
                request->bmRequestType,
                request->bRequest,
                request->wValue,
                request->wLength);

        /* Add any custom control request handling here */
        return true;
    }
    return false;
}

static bool ccid_xfer_cb(uint8_t rhport,
                        uint8_t ep_addr,
                        xfer_result_t result,
                        uint32_t xferred_bytes) {
    return vendord_xfer_cb(rhport, ep_addr, result, xferred_bytes);
}

/* CCID USB driver structure */
static const usbd_class_driver_t ccid_driver = {
#if CFG_TUSB_DEBUG >= 2
    .name = "CCID",
#endif
    .init             = ccid_init_cb,
    .reset            = ccid_reset_cb,
    .open             = ccid_open,
    .control_xfer_cb  = ccid_control_xfer_cb,
    .xfer_cb          = ccid_xfer_cb,
    .sof              = NULL
};

/* Register CCID driver with TinyUSB */
usbd_class_driver_t const *usbd_app_driver_get_cb(uint8_t *driver_count) {
    *driver_count = 1;
    return &ccid_driver;
}

#endif /* ENABLE_EMULATION */
