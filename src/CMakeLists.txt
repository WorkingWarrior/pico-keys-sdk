idf_component_register(
    SRCS ${INTERNAL_SOURCES}
    INCLUDE_DIRS 
        . 
        src/crypto_utils/include 
        src 
        src/fs 
        src/rng 
        src/usb 
        src/led 
        ../mbedtls/include 
        ../tinycbor/src
    REQUIRES 
        bootloader_support 
        esp_partition 
        esp_tinyusb 
        efuse
)
