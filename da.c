#include "da.h"
#include <stdio.h>
#include <string.h>
#include "endianness.h"

#define EP_IN 0x85 // (0x80 | 0x05)
#define EP_OUT 0x06
#define TIMEOUT_MS 0

#define DA_MAX_LENGTH 4096
#define DA_MAX_DATA_LENGTH (DA_MAX_LENGTH - 4 - 2)
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

int da_receive(libusb_device_handle *handle, uint16_t *cmd, uint16_t *data_length, void **data) {
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

    *cmd = READ_BE16(da_buf + 0);
    *data_length = READ_BE16(da_buf + 2);

    if (*data_length > DA_MAX_DATA_LENGTH) {
        printf("length too long\n");
        return -1;
    }

    if (transferred != (4 + *data_length + 2)) {
        printf("transferred != (4 + *data_length + 2)\n");
        return -1;
    }

    *data = da_buf + 4;

    uint16_t crc = READ_BE16(da_buf + 4 + *data_length);
    if (crc != crc16(da_buf, 4 + *data_length)) {
        printf("crc != crc16(da_buf, 4 + length)\n");
        return -1;
    }

    return 0;
}

int da_receive_status(libusb_device_handle *handle, da_status_t *status) {
    uint16_t cmd;
    uint16_t data_length;
    void *data;
    int ret = da_receive(handle, &cmd, &data_length, &data);
    if (ret) {
        return ret;
    }

    if (cmd != CMD_STATUS) {
        printf("cmd != CMD_STATUS\n");
        return -1;
    }

    if (data_length != 2) {
        printf("data_length != 2\n");
        return -1;
    }

    *status = READ_BE16(data);
    return 0;
}

int da_check_status(libusb_device_handle *handle) {
    da_status_t status;
    int ret = da_receive_status(handle, &status);
    if (ret) {
        return ret;
    }

    if (status != STATUS_OK) {
        printf("status != STATUS_OK\n");
        return -1;
    }

    return 0;
}

int da_send(libusb_device_handle *handle, uint16_t cmd, uint16_t data_length, const void *data) {
    if (data_length > DA_MAX_DATA_LENGTH) {
        printf("data_length too long\n");
        return -1;
    }

    WRITE_BE16(da_buf + 0, cmd);
    WRITE_BE16(da_buf + 2, data_length);
    memcpy(da_buf + 4, data, data_length);
    uint16_t crc = crc16(da_buf, 4 + data_length);
    WRITE_BE16(da_buf + 4 + data_length, crc);

    int transferred;
    int ret = libusb_bulk_transfer(
            handle,
            EP_OUT,
            da_buf,
            4 + data_length + 2,
            &transferred,
            TIMEOUT_MS
    );
    if (ret) {
        printf("libusb_bulk_transfer failed: %s\n", libusb_error_name(ret));
        return ret;
    }

    printf("Sent %d bytes\n", transferred);

    if (transferred != (4 + data_length + 2)) {
        printf("transferred != (4 + data_length + 2)\n");
        return -1;
    }

    return 0;
}