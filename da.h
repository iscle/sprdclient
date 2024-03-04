#ifndef DA_H
#define DA_H

#include <libusb-1.0/libusb.h>
#include <stdint.h>

typedef enum {
    CMD_STATUS = 0x00,
    CMD_VERSION = 0x01,

    // EMMC
    CMD_EMMC_INIT = 0x02,
    CMD_EMMC_READ_SINGLE_BLOCK = 0x03,

    CMD_EXIT = 0xFF,
} da_cmd_t;

typedef enum {
    STATUS_OK = 0x00,
    STATUS_ERROR = 0x01,
} da_status_t;

int da_receive(libusb_device_handle *handle, uint16_t *cmd, uint16_t *data_length, void **data);
int da_receive_status(libusb_device_handle *handle, da_status_t *status);
int da_check_status(libusb_device_handle *handle);
int da_send(libusb_device_handle *handle, uint16_t cmd, uint16_t data_length, const void *data);

#endif //DA_H
