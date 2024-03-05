#ifndef DA_H
#define DA_H

#include <libusb-1.0/libusb.h>
#include <stdint.h>

#define EMMC_BLOCK_SIZE 512

typedef enum {
    CMD_STATUS = 0x0000,
    CMD_VERSION = 0x0001,

    // EMMC
    CMD_EMMC_INIT = 0x0002,
    CMD_EMMC_SWITCH = 0x0003,
    CMD_EMMC_GET_SEC_COUNT = 0x0004,
    CMD_EMMC_READ_SINGLE_BLOCK = 0x0005,
    CMD_EMMC_WRITE_BLOCK = 0x0006,

    CMD_EXIT = 0xFFFF,
} da_cmd_t;

typedef enum {
    STATUS_OK = 0x00,
    STATUS_ERROR = 0x01,
} da_status_t;

int da_receive(libusb_device_handle *handle, uint16_t *cmd, uint16_t *data_length, void **data);
int da_receive_status(libusb_device_handle *handle, da_status_t *status);
int da_check_status(libusb_device_handle *handle);
int da_send(libusb_device_handle *handle, uint16_t cmd, uint16_t data_length, const void *data);

int da_emmc_init(libusb_device_handle *handle);
int da_emmc_switch(libusb_device_handle *handle, uint8_t index, uint8_t value);
int da_get_sec_count(libusb_device_handle *handle, uint32_t *sec_count);
int da_read_single_block(libusb_device_handle *handle, uint32_t lba, void *data);
int da_write_block(libusb_device_handle *handle, uint32_t lba, const void *data);

#endif //DA_H
