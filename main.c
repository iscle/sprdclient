#include <stdio.h>
#include <libusb-1.0/libusb.h>
#include <unistd.h>
#include <stdbool.h>

#define VENDOR_ID 0x1782
#define PRODUCT_ID 0x4d00

typedef struct {
    libusb_device_handle *handle;
    struct libusb_endpoint_descriptor *ep_in;
    struct libusb_endpoint_descriptor *ep_out;
} SprdContext;

static int sprd_do_work(SprdContext *sprd_context) {
    // TODO: Do stuff now that we have the endpoints
    return 0;
}

int main() {
    int ret;
    SprdContext sprd_context = {0};
    struct libusb_device_descriptor desc = {};
    struct libusb_config_descriptor *config = NULL;
    bool is_open = false;
    bool has_config_descriptor = false;
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
        sprd_context.handle = libusb_open_device_with_vid_pid(NULL, VENDOR_ID, PRODUCT_ID);
        if (sprd_context.handle) {
            printf("\n");
            break;
        }
        printf(".");
        fflush(stdout);
        sleep(1);
    } while (1);

    printf("Connected\n");
    is_open = true;

    ret = libusb_get_device_descriptor(libusb_get_device(sprd_context.handle), &desc);
    if (ret) {
        printf("libusb_get_device_descriptor failed: %s\n", libusb_error_name(ret));
        goto exit;
    }

    if (desc.bNumConfigurations != 1) {
        printf("Unexpected number of configurations: %d\n", desc.bNumConfigurations);
        ret = LIBUSB_ERROR_NO_DEVICE;
        goto exit;
    }

    ret = libusb_get_config_descriptor(libusb_get_device(sprd_context.handle), 0, &config);
    if (ret) {
        printf("libusb_get_config_descriptor failed: %s\n", libusb_error_name(ret));
        goto exit;
    }

    has_config_descriptor = true;

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

    for (uint8_t i = 0; i < config->interface->altsetting->bNumEndpoints; i++) {
        const struct libusb_endpoint_descriptor *endpoint = &config->interface->altsetting->endpoint[i];
        if (endpoint->bEndpointAddress == 0x85) {
            sprd_context.ep_in = (struct libusb_endpoint_descriptor *)endpoint;
        } else if (endpoint->bEndpointAddress == 0x06) {
            sprd_context.ep_out = (struct libusb_endpoint_descriptor *)endpoint;
        }
    }

    if (sprd_context.ep_in == NULL || sprd_context.ep_out == NULL) {
        printf("Endpoints not found\n");
        ret = LIBUSB_ERROR_NO_DEVICE;
        goto exit;
    }

    printf("Endpoints found, claiming interface...\n");

    ret = libusb_claim_interface(sprd_context.handle, 0);
    if (ret) {
        printf("libusb_claim_interface failed: %s\n", libusb_error_name(ret));
        goto exit;
    }

    printf("Interface claimed\n");
    interface_claimed = true;

    ret = sprd_do_work(&sprd_context);

exit:
    if (interface_claimed) {
        libusb_release_interface(sprd_context.handle, 0);
        interface_claimed = false;
    }
    if (has_config_descriptor) {
        libusb_free_config_descriptor(config);
        config = NULL;
        has_config_descriptor = false;
    }
    if (is_open) {
        libusb_close(sprd_context.handle);
        sprd_context.handle = NULL;
        libusb_exit(NULL);
        is_open = false;
    }

    return ret;
}
