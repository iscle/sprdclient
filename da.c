#include "da.h"
#include <stdio.h>
#include <string.h>

#define EP_IN 0x85 // (0x80 | 0x05)
#define EP_OUT 0x06
#define TIMEOUT_MS 0

#define DA_MAX_LENGTH 2048
static uint8_t da_buf[DA_MAX_LENGTH];

static uint16_t crc16(const void *data, size_t length) {
    const uint8_t *d = data;
    uint16_t crc = 0;
    for (size_t i = 0; i < length; i++) {
        crc ^= d[i] << 8;
        for (uint8_t j = 0; j < 8; j++) {
            if (crc & 0x8000) {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc = crc << 1;
            }
        }
    }
    return crc;
}

int da_receive(libusb_device_handle *handle, da_cmd_t *cmd, uint16_t *data_length, void **data) {
    int transferred;
    int ret = libusb_bulk_transfer(
            handle,
            EP_IN,
            da_buf,
            sizeof(da_buf),
            &transferred,
            TIMEOUT_MS
    );
    if (ret) {
        printf("libusb_bulk_transfer failed: %s\n", libusb_error_name(ret));
        return ret;
    }

    printf("Received %d bytes\n", transferred);

    if (transferred < 3) {
        printf("transferred < 3\n");
        return -1;
    }

    *cmd = da_buf[0];
    *data_length = (da_buf[1] << 8) | da_buf[2];

    if (*data_length > (DA_MAX_LENGTH - 3 - 2)) {
        printf("length too long\n");
        return -1;
    }

    if (transferred != (3 + *data_length + 2)) {
        printf("transferred != (3 + *data_length + 2)\n");
        return -1;
    }

    *data = da_buf + 3;

    uint16_t crc = da_buf[3 + *data_length] << 8 | da_buf[3 + *data_length + 1];
    if (crc != crc16(da_buf, 3 + *data_length)) {
        printf("crc != crc16(da_buf, 3 + length)\n");
        return -1;
    }

    return 0;
}

int da_send_check(libusb_device_handle *handle, da_cmd_t cmd, uint16_t data_length, const void *data) {
    if (data_length > (DA_MAX_LENGTH - 3 - 2)) {
        printf("data_length too long\n");
        return -1;
    }

    da_buf[0] = cmd;
    da_buf[1] = (data_length >> 8) & 0xFF;
    da_buf[2] = data_length & 0xFF;
    memcpy(da_buf + 3, data, data_length);
    uint16_t crc = crc16(da_buf, 3 + data_length);
    da_buf[3 + data_length] = (crc >> 8) & 0xFF;
    da_buf[3 + data_length + 1] = crc & 0xFF;

    int transferred;
    int ret = libusb_bulk_transfer(
            handle,
            EP_OUT,
            da_buf,
            3 + data_length + 2,
            &transferred,
            TIMEOUT_MS
    );
    if (ret) {
        printf("libusb_bulk_transfer failed: %s\n", libusb_error_name(ret));
        return ret;
    }

    printf("Sent %d bytes\n", transferred);

    if (transferred != (3 + data_length + 2)) {
        printf("transferred != (3 + data_length + 2)\n");
        return -1;
    }

    da_cmd_t rcv_cmd;
    uint8_t *status;
    uint16_t status_length;
    ret = da_receive(handle, &rcv_cmd, &status_length, &status);
    if (ret || *status != STATUS_OK) {
        printf("da_receive failed\n");
        return ret;
    }

    return 0;
}