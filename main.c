#include <stdio.h>
#include <libusb-1.0/libusb.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include "gpt.h"

#define VENDOR_ID 0x1782
#define PRODUCT_ID 0x4d00
#define TIMEOUT_MS 15000

#define FRAME_MAX_SIZE 4096

#define HDLC_FLAG 0x7e

typedef struct {
    libusb_device_handle *handle;
    int ep_in;
    int ep_out;
    uint16_t (*crc)(const uint8_t *buf, size_t len);
    uint8_t buffer[FRAME_MAX_SIZE];
    int buffer_length;
} sprd_context_t;

#define CRC_16_L_SEED       0x80
#define CRC_16_L_POLYNOMIAL 0x8000
#define CRC_16_POLYNOMIAL   0x1021
static uint16_t sprd_brom_crc(const uint8_t *buf, size_t len) {
    uint16_t crc = 0;

    while (len-- != 0) {
        for (uint8_t i = CRC_16_L_SEED; i != 0 ; i >>= 1) {
            if ((crc & CRC_16_L_POLYNOMIAL) != 0) {
                crc <<= 1;
                crc ^= CRC_16_POLYNOMIAL;
            } else {
                crc <<= 1;
            }

            if ((*buf & i) != 0) {
                crc ^= CRC_16_POLYNOMIAL;
            }
        }

        buf++;
    }

    return crc;
}

static uint16_t sprd_fdl_crc(const uint8_t *buf, size_t len) {
    uint32_t crc = 0;
    size_t i;

    for (i = 0; len - i > 1; i += 2) {
        crc += buf[i] << 8 | buf[i + 1];
    }

    if (i != len) {
        crc += buf[i];
    }

    crc = (crc >> 16) + (crc & 0x0FFFF);
    crc += (crc >> 16);

    return ~crc;
}

static int find_endpoints(sprd_context_t *context) {
    int ret;
    struct libusb_device_descriptor desc = {};
    struct libusb_config_descriptor *config = NULL;

    ret = libusb_get_device_descriptor(libusb_get_device(context->handle), &desc);
    if (ret) {
        printf("libusb_get_device_descriptor failed: %s\n", libusb_error_name(ret));
        goto exit;
    }

    if (desc.bNumConfigurations != 1) {
        printf("Unexpected number of configurations: %d\n", desc.bNumConfigurations);
        ret = LIBUSB_ERROR_NO_DEVICE;
        goto exit;
    }

    ret = libusb_get_config_descriptor(libusb_get_device(context->handle), 0, &config);
    if (ret) {
        printf("libusb_get_config_descriptor failed: %s\n", libusb_error_name(ret));
        goto exit;
    }

    if (config->bNumInterfaces != 1) {
        printf("Unexpected number of interfaces: %d\n", config->bNumInterfaces);
        ret = LIBUSB_ERROR_NO_DEVICE;
        goto exit;
    }

    if (config->interface->num_altsetting != 1) {
        printf("Unexpected number of alternate settings: %d\n", config->interface->num_altsetting);
        ret = LIBUSB_ERROR_NO_DEVICE;
        goto exit;
    }

    if (config->interface->altsetting->bNumEndpoints != 2) {
        printf("Unexpected number of endpoints: %d\n", config->interface->altsetting->bNumEndpoints);
        ret = LIBUSB_ERROR_NO_DEVICE;
        goto exit;
    }

    bool found_in = false;
    bool found_out = false;

    for (uint8_t i = 0; i < config->interface->altsetting->bNumEndpoints; i++) {
        const struct libusb_endpoint_descriptor *endpoint = &config->interface->altsetting->endpoint[i];
        if ((endpoint->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_IN) {
            if (found_in) {
                printf("Multiple IN endpoints found\n");
                ret = LIBUSB_ERROR_NO_DEVICE;
                goto exit;
            }
            context->ep_in = endpoint->bEndpointAddress;
            found_in = true;
        } else if ((endpoint->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_OUT) {
            if (found_out) {
                printf("Multiple OUT endpoints found\n");
                ret = LIBUSB_ERROR_NO_DEVICE;
                goto exit;
            }
            context->ep_out = endpoint->bEndpointAddress;
            found_out = true;
        }
    }

    if (!found_in || !found_out) {
        printf("Endpoints not found\n");
        ret = LIBUSB_ERROR_NO_DEVICE;
        goto exit;
    }

exit:
    if (config) {
        libusb_free_config_descriptor(config);
        config = NULL;
    }

    return ret;
}

int trigger_serial(sprd_context_t *context) {
    // Trigger USB endpoint configuration
    printf("Triggering USB serial port mode...\n"); // (calibration_detect)
    return libusb_control_transfer(
            context->handle,
            0x21, // bmRequestType: Host to device, class, interface
            0x22, // bRequest: gser_setup
            1, // wValue: Bit 0 set, gser_port_open_complete
            0, // wIndex: Don't care
            NULL, // data: Don't care
            0, // wLength: Don't care
            TIMEOUT_MS
    );
}

struct msg_header {
    unsigned int seq_num;  // Message sequence number, used for flow control
    unsigned short len;    // The total size of the packet "sizeof(MSG_HEAD_T)
    unsigned char type;     // Main command type
    unsigned char subtype;  // Sub command type
} __attribute__((packed));

int stage1(sprd_context_t *context) {
    uint8_t buffer[FRAME_MAX_SIZE];
    int transferred;

    // avoid: 0x17, 0x15, calibration=2,0,146
    struct msg_header header = {
        .seq_num = htole32(0),
        .len = htole16(sizeof(header)),
        .type = 0xfe,
        .subtype = 0x02
    };

    buffer[0] = HDLC_FLAG;
    memcpy(buffer + 1, &header, sizeof(header));
    buffer[1 + sizeof(header)] = HDLC_FLAG;

    for (int i = 1; i < 1 + sizeof(header) + 1 - 1; i++) {
        if (buffer[i] == 0x7d || buffer[i] == 0x7e) {
            printf("Byte at index %d needs escaping: 0x%02x\n", i, buffer[i]);
        }
    }

    int ret = libusb_bulk_transfer(
            context->handle,
            context->ep_out,
            buffer,
            1 + sizeof(header) + 1,
            NULL,
            TIMEOUT_MS
    );
    if (ret) {
        printf("libusb_bulk_transfer failed: %s\n", libusb_error_name(ret));
        return ret;
    }

    printf("Sent stage1, waiting for response...\n");

    // Get response
    ret = libusb_bulk_transfer(
            context->handle,
            context->ep_in,
            buffer,
            sizeof(buffer),
            &transferred,
            TIMEOUT_MS
    );
    if (ret) {
        printf("libusb_bulk_transfer failed: %s\n", libusb_error_name(ret));
        return ret;
    }

    printf("Received %d bytes\n", transferred);
    for (int i = 0; i < transferred; i++) {
        printf("%02x ", buffer[i]);
    }
    printf("\n");

    return ret;
}

int stage2(sprd_context_t *context) {
    uint8_t buffer[FRAME_MAX_SIZE];
    int transferred;

    char command[] = "AT+PROP=0,[ro.board.platform]";

    struct msg_header header = {
        .seq_num = htole32(0),
        .len = htole16(sizeof(header) + strlen(command)),
        .type = 0x68,
        .subtype = 0x00
    };

    buffer[0] = HDLC_FLAG;
    memcpy(buffer + 1, &header, sizeof(header));
    memcpy(buffer + 1 + sizeof(header), command, strlen(command));
    buffer[1 + sizeof(header) + strlen(command)] = HDLC_FLAG;

    for (int i = 1; i < 1 + sizeof(header) + strlen(command) + 1 - 1; i++) {
        if (buffer[i] == 0x7d || buffer[i] == 0x7e) {
            printf("Byte at index %d needs escaping: 0x%02x\n", i, buffer[i]);
        }
    }

    int ret = libusb_bulk_transfer(
            context->handle,
            context->ep_out,
            buffer,
            1 + sizeof(header) + strlen(command) + 1,
            NULL,
            TIMEOUT_MS
    );
    if (ret) {
        printf("libusb_bulk_transfer failed: %s\n", libusb_error_name(ret));
        return ret;
    }

    printf("Sent stage2, waiting for response...\n");

    while (1) {
        // Get response
        ret = libusb_bulk_transfer(
                context->handle,
                context->ep_in,
                buffer,
                sizeof(buffer),
                &transferred,
                TIMEOUT_MS
        );
        if (ret) {
            printf("libusb_bulk_transfer failed: %s\n", libusb_error_name(ret));
            return ret;
        }

        printf("Received %d bytes\n", transferred);
        for (int i = 0; i < transferred; i++) {
            printf("%02x ", buffer[i]);
        }
        printf("\n");
    }

    return ret;
}

int main() {
    int ret;
    sprd_context_t context = {0};
    bool is_open = false;
    bool interface_claimed = false;

    printf("sprdclient v1.0 by iscle\n");

    ret = libusb_init(NULL);
    if (ret) {
        printf("libusb_init failed: %s\n", libusb_error_name(ret));
        goto exit;
    }

    printf("Waiting for connection...");
    fflush(stdout);

    do {
        context.handle = libusb_open_device_with_vid_pid(NULL, VENDOR_ID, PRODUCT_ID);
        if (context.handle) {
            printf("\n");
            break;
        }
        printf(".");
        fflush(stdout);
        usleep(500000); // 500 ms
    } while (1);

    is_open = true;
    printf("Connected\n");

    ret = find_endpoints(&context);
    if (ret) {
        ret = LIBUSB_ERROR_NO_DEVICE;
        goto exit;
    }

    printf("Endpoints found, claiming interface...\n");

    ret = libusb_claim_interface(context.handle, 0);
    if (ret) {
        printf("libusb_claim_interface failed: %s\n", libusb_error_name(ret));
        goto exit;
    }

    printf("Interface claimed\n");
    interface_claimed = true;

//    trigger_serial(&context);
//    stage1(&context);
    trigger_serial(&context);
    stage2(&context);

exit:
    if (interface_claimed) {
        libusb_release_interface(context.handle, 0);
        interface_claimed = false;
    }
    if (is_open) {
        libusb_close(context.handle);
        context.handle = NULL;
        libusb_exit(NULL);
        is_open = false;
    }

    return ret;
}
