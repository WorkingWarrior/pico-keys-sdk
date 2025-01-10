#
# This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
# Copyright (c) 2022 Pol Henarejos.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

include(pico-keys-sdk/cmake/version.cmake)
include(pico-keys-sdk/cmake/boards.cmake)

if(PICO_BOARD)
  dict(GET led_driver ${PICO_BOARD} LED_DRIVER)
endif()

option(VIDPID "Set specific VID/PID from a known platform {NitroHSM, NitroFIDO2, NitroStart, NitroPro, Nitro3, Yubikey5, YubikeyNeo, YubiHSM, Gnuk, GnuPG}" "None")

message(STATUS "VIDPID:\t\t\t '${VIDPID}'")

if(VIDPID STREQUAL "NitroHSM")
    set(USB_VID 0x20A0)
    set(USB_PID 0x4230)
elseif(VIDPID STREQUAL "NitroFIDO2")
    set(USB_VID 0x20A0)
    set(USB_PID 0x42B1)
elseif(VIDPID STREQUAL "NitroStart")
    set(USB_VID 0x20A0)
    set(USB_PID 0x4211)
elseif(VIDPID STREQUAL "NitroPro")
    set(USB_VID 0x20A0)
    set(USB_PID 0x4108)

elseif(VIDPID STREQUAL "Nitro3")
    set(USB_VID 0x20A0)
    set(USB_PID 0x42B2)
elseif(VIDPID STREQUAL "Yubikey5")
    set(USB_VID 0x1050)
    set(USB_PID 0x0407)
elseif(VIDPID STREQUAL "YubikeyNeo")
    set(USB_VID 0x1050)
    set(USB_PID 0x0116)
elseif(VIDPID STREQUAL "YubiHSM")
    set(USB_VID 0x1050)
    set(USB_PID 0x0030)
elseif(VIDPID STREQUAL "Gnuk")
    set(USB_VID 0x234B)
    set(USB_PID 0x0000)
elseif(VIDPID STREQUAL "GnuPG")
    set(USB_VID 0x1209)
    set(USB_PID 0x2440)
endif()

if(ESP_PLATFORM)
    if(DEFINED CONFIG_TINYUSB_DESC_CUSTOM_VID)
        set(USB_VID CONFIG_TINYUSB_DESC_CUSTOM_VID)
    endif()
    if(DEFINED CONFIG_TINYUSB_DESC_CUSTOM_PID)
        set(USB_PID CONFIG_TINYUSB_DESC_CUSTOM_PID)
    endif()
endif()

if(NOT DEFINED USB_VID)
    set(USB_VID 0xFEFF)
endif()
add_definitions(-DUSB_VID=${USB_VID})

if(NOT DEFINED USB_PID)
    set(USB_PID 0xFCFD)
endif()
add_definitions(-DUSB_PID=${USB_PID})

if(NOT DEFINED DEBUG_APDU)
    set(DEBUG_APDU 0)
endif()
if(NOT DEFINED ENABLE_EMULATION)
    set(ENABLE_EMULATION 0)
endif()

option(ENABLE_DELAYED_BOOT "Enable/disable delayed boot" OFF)
if(ENABLE_DELAYED_BOOT)
    add_definitions(-DPICO_XOSC_STARTUP_DELAY_MULTIPLIER=64)
    message(STATUS "Delayed boot:\t\t enabled")
else()
    message(STATUS "Delayed boot:\t\t disabled")
endif(ENABLE_DELAYED_BOOT)
if(USB_ITF_HID)
    add_definitions(-DUSB_ITF_HID=1)
    message(STATUS "USB HID Interface:\t\t enabled")
endif(USB_ITF_HID)
if(USB_ITF_CCID)
    add_definitions(-DUSB_ITF_CCID=1)
    message(STATUS "USB CCID Interface:\t\t enabled")
    if(USB_ITF_WCID)
        add_definitions(-DUSB_ITF_WCID=1)
        message(STATUS "USB WebCCID Interface:\t enabled")
    endif(USB_ITF_WCID)
endif(USB_ITF_CCID)
add_definitions(-DDEBUG_APDU=${DEBUG_APDU})
if(NOT ESP_PLATFORM)
    add_definitions(-DMBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_LIST_DIR}/config/mbedtls_config.h")
else()
    add_definitions(-DCFG_TUSB_CONFIG_FILE="${CMAKE_CURRENT_LIST_DIR}/src/usb/tusb_config.h")
endif()

message(STATUS "USB VID/PID:\t\t\t ${USB_VID}:${USB_PID}")

set(MBEDTLS_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/aes.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/asn1parse.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/asn1write.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/bignum.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/bignum_core.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/ccm.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/cmac.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/cipher.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/cipher_wrap.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/constant_time.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/ecdsa.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/ecdh.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/ecp.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/ecp_curves.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/gcm.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/hkdf.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/md.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/md5.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/oid.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/pkcs5.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/platform_util.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/rsa.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/rsa_alt_helpers.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/sha1.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/sha3.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/sha256.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/sha512.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/chachapoly.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/chacha20.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/poly1305.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/ripemd160.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/des.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/x509write_crt.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/x509_create.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/x509write_csr.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/pk.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/pk_wrap.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/pkwrite.c
)

set(CRYPTO_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/src/crypto_utils/src/crypto_aes.c
    ${CMAKE_CURRENT_LIST_DIR}/src/crypto_utils/src/crypto_hash.c
    ${CMAKE_CURRENT_LIST_DIR}/src/crypto_utils/src/crypto_curves.c
    ${CMAKE_CURRENT_LIST_DIR}/src/crypto_utils/src/crypto_utils.c
)

set(SOURCES ${SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/src/main.c
    ${CMAKE_CURRENT_LIST_DIR}/src/usb/usb.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fs/file.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fs/flash.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fs/flash_memory_manager.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fs/otp.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fs/phy.c
    ${CMAKE_CURRENT_LIST_DIR}/src/ringbuffer/ringbuffer.c
    ${CMAKE_CURRENT_LIST_DIR}/src/rng/random.c
    ${CMAKE_CURRENT_LIST_DIR}/src/rng/hwrng.c
    ${CMAKE_CURRENT_LIST_DIR}/src/eac.c
    ${CRYPTO_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/src/asn1.c
    ${CMAKE_CURRENT_LIST_DIR}/src/apdu.c
    ${CMAKE_CURRENT_LIST_DIR}/src/rescue.c
    ${CMAKE_CURRENT_LIST_DIR}/src/led/led.c
)

if(ESP_PLATFORM)
  set(LED_DRIVER led_neopixel)
endif()
if (LED_DRIVER)
    message(STATUS "LED driver:\t\t\t ${LED_DRIVER}")
    set(SOURCES ${SOURCES} ${CMAKE_CURRENT_LIST_DIR}/src/led/${LED_DRIVER}.c)
endif()

## mbedTLS reports an stringop overflow for cmac.c
if(NOT ENABLE_EMULATION AND NOT APPLE)
    set_source_files_properties(
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/cmac.c
        PROPERTIES
        COMPILE_FLAGS "-Wno-error=stringop-overflow= -Wno-stringop-overflow"
    )
endif()
set(INCLUDES ${INCLUDES}
    ${CMAKE_CURRENT_LIST_DIR}/src/crypto_utils/include
    ${CMAKE_CURRENT_LIST_DIR}/src
    ${CMAKE_CURRENT_LIST_DIR}/src/usb
    ${CMAKE_CURRENT_LIST_DIR}/src/fs
    ${CMAKE_CURRENT_LIST_DIR}/src/ringbuffer
    ${CMAKE_CURRENT_LIST_DIR}/src/rng
    ${CMAKE_CURRENT_LIST_DIR}/src/led
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/include
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library
)

if(USB_ITF_HID)
    set(MBEDTLS_SOURCES ${MBEDTLS_SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/x509write_crt.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/x509_create.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/x509write_csr.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/pk.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/pk_wrap.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/pkwrite.c
    )
    set(CBOR_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/tinycbor/src/cborencoder.c
        ${CMAKE_CURRENT_LIST_DIR}/tinycbor/src/cborparser.c
        ${CMAKE_CURRENT_LIST_DIR}/tinycbor/src/cborparser_dup_string.c
    )

    set(INCLUDES ${INCLUDES}
        ${CMAKE_CURRENT_LIST_DIR}/tinycbor/src
    )
endif()

set(LIBRARIES
    pico_stdlib
    pico_multicore
    pico_rand
    pico_aon_timer
    hardware_flash
    pico_unique_id
    tinyusb_device
    tinyusb_board
    hardware_pio
)

if(PICO_BOARD STREQUAL "pico_w")
    set(LIBRARIES ${LIBRARIES} pico_cyw43_arch_none)
endif()

function(add_impl_library target)
    add_library(${target} INTERFACE)
    string(TOUPPER ${target} TARGET_UPPER)
    target_compile_definitions(${target} INTERFACE LIB_${TARGET_UPPER}=1)
endfunction()
if(${USB_ITF_HID})
    set(SOURCES ${SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/hid/hid.c
    )
    set(INCLUDES ${INCLUDES}
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/hid
    )
endif()
if(ENABLE_EMULATION)
    if(APPLE)
        add_definitions("-Wno-deprecated-declarations")
    elseif(MSVC)
        set(SOURCES ${SOURCES}
            ${CMAKE_CURRENT_LIST_DIR}/src/fs/mman.c
        )
    endif()
    add_definitions(-DENABLE_EMULATION)
    set(SOURCES ${SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/emulation/emulation.c
    )
    set(MBEDTLS_SOURCES ${MBEDTLS_SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/aesni.c
    )
    set(INCLUDES ${INCLUDES}
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/emulation
    )
else()
    if(USB_ITF_CCID)
        set(SOURCES ${SOURCES}
            ${CMAKE_CURRENT_LIST_DIR}/src/usb/ccid/ccid.c
        )
        set(INCLUDES ${INCLUDES}
            ${CMAKE_CURRENT_LIST_DIR}/src/usb/ccid
        )
    endif()
    set(SOURCES ${SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/usb_descriptors.c
    )
endif()
set(EXTERNAL_SOURCES ${CBOR_SOURCES})
if(NOT ESP_PLATFORM)
    set(EXTERNAL_SOURCES ${EXTERNAL_SOURCES} ${MBEDTLS_SOURCES})
endif()
if(MSVC)
    set(
        CMAKE_C_FLAGS
        "${CMAKE_C_FLAGS} -wd4820 -wd4255 -wd5045 -wd4706 -wd4061 -wd5105"
    )

    add_compile_definitions(_CRT_SECURE_NO_WARNINGS
        __STDC_WANT_SECURE_LIB__=0
        _WIN32_WINNT_WIN10_TH2=0
        _WIN32_WINNT_WIN10_RS1=0
        _WIN32_WINNT_WIN10_RS2=0
        _WIN32_WINNT_WIN10_RS3=0
        _WIN32_WINNT_WIN10_RS4=0
        _WIN32_WINNT_WIN10_RS5=0
        _STRALIGN_USE_SECURE_CRT=0
        NTDDI_WIN10_CU=0)
    set_source_files_properties(
        ${EXTERNAL_SOURCES}
        PROPERTIES
        COMPILE_FLAGS " -W3 -wd4242 -wd4065"
    )
endif()
if(PICO_RP2350)
    pico_set_uf2_family(${CMAKE_PROJECT_NAME} "rp2350-arm-s")
    pico_embed_pt_in_binary(${CMAKE_PROJECT_NAME} "${CMAKE_CURRENT_LIST_DIR}/config/rp2350/pt.json")
    pico_set_binary_type(${CMAKE_PROJECT_NAME} copy_to_ram)
    if (SECURE_BOOT_PKEY)
        message(STATUS "Secure Boot Key ${SECURE_BOOT_PKEY}")
        pico_sign_binary(${CMAKE_PROJECT_NAME} ${SECURE_BOOT_PKEY})
        pico_hash_binary(${CMAKE_PROJECT_NAME})
    endif()
    target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE pico_bootrom)

    set(INCLUDES ${INCLUDES}
        ${CMAKE_CURRENT_LIST_DIR}/config/rp2350/alt
    )
    set(SOURCES ${SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/config/rp2350/alt/sha256_alt.c
    )
    set(LIBRARIES ${LIBRARIES} pico_sha256)
endif()
set(INTERNAL_SOURCES ${SOURCES})
set(SOURCES ${SOURCES} ${EXTERNAL_SOURCES})
if(NOT TARGET pico_keys_sdk)
    if(ENABLE_EMULATION OR ESP_PLATFORM)
        add_impl_library(pico_keys_sdk)
    else()
        pico_add_library(pico_keys_sdk)

        target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE ${LIBRARIES})
    endif()
    target_sources(pico_keys_sdk INTERFACE ${SOURCES})
    target_include_directories(pico_keys_sdk INTERFACE ${INCLUDES})
    target_link_libraries(pico_keys_sdk INTERFACE ${LIBRARIES})
endif()
