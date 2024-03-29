#include <stdio.h>
#include <libusb-1.0/libusb.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <malloc.h>
#include "sprd.h"
#include "da.h"
#include "endianness.h"
#include "gpt.h"

#define VENDOR_ID 0x1782
#define PRODUCT_ID 0x4d00
#define EP_IN 0x85 // (0x80 | 0x05)
#define EP_OUT 0x06
#define TIMEOUT_MS 1000

#define FRAME_HEADER_SIZE 4
#define FRAME_MAX_DATA_SIZE 4096
#define FRAME_CRC_SIZE 2
#define FRAME_MAX_SIZE (1 + FRAME_HEADER_SIZE + FRAME_MAX_DATA_SIZE + FRAME_CRC_SIZE + 1)

#define BSL_CMD_CONNECT 0x00
#define BSL_CMD_START_DATA 0x01
#define BSL_CMD_MIDST_DATA 0x02
#define BSL_CMD_END_DATA 0x03
#define BSL_CMD_EXEC_DATA 0x04

#define BSL_REP_ACK 0x80
#define BSL_REP_VER 0x81

#define HDLC_FLAG 0x7e
#define HDLC_ESCAPE 0x7d
#define HDLC_ESCAPE_MASK 0x20
#define HDLC_FRAME_MIN_SIZE 8

/*
 * HDLC frame format:
 *
 * HDLC_FLAG (1 byte)
 * Type (2 bytes)
 * Length (2 bytes)
 * Data (Length bytes)
 * CRC (2 bytes)
 * HDLC_FLAG (1 byte)
 *
 */

enum packet_state {
    PACKET_STATE_START,
    PACKET_STATE_UNESCAPED,
    PACKET_STATE_ESCAPED,
    PACKET_STATE_END,
};

typedef struct {
    libusb_device_handle *handle;
    uint16_t (*crc)(const uint8_t *buf, size_t len);
    uint8_t buffer[FRAME_MAX_SIZE];
    int buffer_length;
} SprdContext;

static inline uint16_t sprd_get_frame_type(SprdContext *sprd_context) {
    return (sprd_context->buffer[0] << 8) | sprd_context->buffer[1];
}

static inline uint16_t sprd_get_frame_data_size(SprdContext *sprd_context) {
    return (sprd_context->buffer[2] << 8) | sprd_context->buffer[3];
}

static inline uint8_t *sprd_get_frame_data(SprdContext *sprd_context) {
    return sprd_context->buffer + 4;
}

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

static int sprd_send(SprdContext *sprd_context) {
    uint8_t buffer[FRAME_MAX_SIZE];
    int buffer_length = 0;

    buffer[buffer_length++] = HDLC_FLAG;
    for (int i = 0; i < sprd_context->buffer_length; i++) {
        if (buffer_length >= FRAME_MAX_SIZE) {
            printf("Payload too long\n");
            return -1;
        }

        if (sprd_context->buffer[i] == HDLC_FLAG || sprd_context->buffer[i] == HDLC_ESCAPE) {
            buffer[buffer_length++] = HDLC_ESCAPE;
            buffer[buffer_length++] = sprd_context->buffer[i] ^ HDLC_ESCAPE_MASK;
        } else {
            buffer[buffer_length++] = sprd_context->buffer[i];
        }
    }
    buffer[buffer_length++] = HDLC_FLAG;

    int transferred_total = 0;
    do {
        int transferred;
        int ret = libusb_bulk_transfer(
                sprd_context->handle,
                EP_OUT,
                buffer + transferred_total,
                buffer_length - transferred_total,
                &transferred,
                TIMEOUT_MS
        );
        if (ret) {
            printf("libusb_bulk_transfer failed: %s\n", libusb_error_name(ret));
            return ret;
        }

        transferred_total += transferred;
    } while (transferred_total < buffer_length);

    return 0;
}

static int sprd_receive(SprdContext *sprd_context) {
    uint8_t buffer[FRAME_MAX_SIZE];

    int received = 0;
    enum packet_state packet_state = PACKET_STATE_START;
    do {
        int transferred;
        int ret = libusb_bulk_transfer(
                sprd_context->handle,
                EP_IN,
                buffer,
                FRAME_MAX_SIZE - received,
                &transferred,
                TIMEOUT_MS
        );
        if (ret) {
            printf("libusb_bulk_transfer failed: %s\n", libusb_error_name(ret));
            return ret;
        }

        printf("Received %d bytes\n", transferred);
        // print bytes as hex
        for (int i = 0; i < transferred; i++) {
            printf("%02x ", buffer[i]);
        }
        printf("\n");

        for (int i = 0; i < transferred; i++) {
            if (received == FRAME_MAX_SIZE) {
                printf("Buffer too small\n");
                return -1;
            }

            if (packet_state == PACKET_STATE_START) {
                if (buffer[i] == HDLC_FLAG) {
                    packet_state = PACKET_STATE_UNESCAPED;
                }
            } else if (packet_state == PACKET_STATE_ESCAPED) {
                sprd_context->buffer[received++] = buffer[i] ^ HDLC_ESCAPE_MASK;
            } else {
                if (buffer[i] == HDLC_FLAG) {
                    packet_state = PACKET_STATE_END;
                    break;
                } else if (buffer[i] == HDLC_ESCAPE) {
                    packet_state = PACKET_STATE_ESCAPED;
                } else {
                    sprd_context->buffer[received++] = buffer[i];
                }
            }
        }
    } while (packet_state != PACKET_STATE_END);

    sprd_context->buffer_length = received;

    uint16_t crc = sprd_context->crc(sprd_context->buffer, received - FRAME_CRC_SIZE);
    uint16_t received_crc = (sprd_context->buffer[received - 2] << 8) | sprd_context->buffer[received - 1];
    if (crc != received_crc) {
        printf("CRC mismatch (0x%04x != 0x%04x)\n", crc, received_crc);
        return -1;
    }

    return 0;
}

static int sprd_send_frame(SprdContext *sprd_context, uint16_t type, uint16_t data_size, uint8_t *data) {
    if (data_size > FRAME_MAX_DATA_SIZE) {
        printf("Data too long\n");
        return -1;
    }

    sprd_context->buffer[0] = (type >> 8) & 0xff;
    sprd_context->buffer[1] = type & 0xff;
    sprd_context->buffer[2] = (data_size >> 8) & 0xff;
    sprd_context->buffer[3] = data_size & 0xff;
    memcpy(sprd_context->buffer + 4, data, data_size);
    uint16_t crc = sprd_context->crc(sprd_context->buffer, FRAME_HEADER_SIZE + data_size);
    sprd_context->buffer[4 + data_size] = (crc >> 8) & 0xff;
    sprd_context->buffer[5 + data_size] = crc & 0xff;
    sprd_context->buffer_length = FRAME_HEADER_SIZE + data_size + FRAME_CRC_SIZE;

    return sprd_send(sprd_context);
}

static int sprd_send_and_check_frame(SprdContext *sprd_context, uint16_t type, uint16_t data_size, uint8_t *data) {
    int ret;

    ret = sprd_send_frame(sprd_context, type, data_size, data);
    if (ret) {
        return ret;
    }

    ret = sprd_receive(sprd_context);
    if (ret) {
        return ret;
    }

    if (sprd_get_frame_type(sprd_context) != BSL_REP_ACK) {
        printf("Unexpected frame type: 0x%04x\n", sprd_get_frame_type(sprd_context));
        return -1;
    }

    return 0;
}

static int sprd_send_usb_hello(SprdContext *sprd_context) {
    int ret;

    // Trigger USB endpoint configuration
    ret = libusb_control_transfer(
            sprd_context->handle,
            0x21, // bmRequestType: Host to device, class, interface
            0, // bRequest: Don't care
            1, // wValue: Bit 0 set
            0, // wIndex: Don't care
            NULL, // data: Don't care
            0, // wLength: Don't care
            TIMEOUT_MS
    );
    if (ret) {
        printf("libusb_control_transfer failed: %s\n", libusb_error_name(ret));
        return ret;
    }

    // Send HDLC_FLAG as a hello
    uint8_t data = HDLC_FLAG;
    ret = libusb_bulk_transfer(
            sprd_context->handle,
            EP_OUT,
            &data,
            1,
            NULL,
            TIMEOUT_MS
    );
    if (ret) {
        printf("libusb_bulk_transfer failed: %s\n", libusb_error_name(ret));
        return ret;
    }

    // Get response
    ret = sprd_receive(sprd_context);
    if (ret) {
        // TODO: Do something about it?
    }

    // BSL_REP_VER
    if (sprd_get_frame_type(sprd_context) != BSL_REP_VER) {
        printf("Unexpected frame type: 0x%04x\n", sprd_get_frame_type(sprd_context));
        return -1;
    }

    return 0;
}

static int sprd_check_connection(SprdContext *sprd_context) {
    return sprd_send_and_check_frame(sprd_context, BSL_CMD_CONNECT, 0, NULL);
}

/*
 * Execute a payload using the BootROM, jumps at (load_address + 0x200)
 */
static int sprd_execute_payload(SprdContext *sprd_context, uint32_t load_address, uint8_t *payload, uint32_t payload_size) {
    int ret;
    uint8_t buffer[8];

    printf("Sending BSL_CMD_START_DATA...\n");

    // Send BSL_CMD_START_DATA
    buffer[0] = (load_address >> 24) & 0xff;
    buffer[1] = (load_address >> 16) & 0xff;
    buffer[2] = (load_address >> 8) & 0xff;
    buffer[3] = load_address & 0xff;
    buffer[4] = (payload_size >> 24) & 0xff;
    buffer[5] = (payload_size >> 16) & 0xff;
    buffer[6] = (payload_size >> 8) & 0xff;
    buffer[7] = payload_size & 0xff;
    ret = sprd_send_and_check_frame(sprd_context, BSL_CMD_START_DATA, 8, buffer);
    if (ret) {
        printf("sprd_send_and_check_frame failed: %d\n", ret);
        return ret;
    }

    printf("Sending BSL_CMD_MIDST_DATA...\n");

    // Send BSL_CMD_MIDST_DATA
    uint32_t offset = 0;
    while (offset < payload_size) {
        uint32_t chunk_size = payload_size - offset;
        // Worst case, all bytes have to be escaped
        if (chunk_size > 528) {
            chunk_size = 528;
        }
        printf("Sending %d bytes...\n", chunk_size);
        ret = sprd_send_and_check_frame(sprd_context, BSL_CMD_MIDST_DATA, chunk_size, payload + offset);
        if (ret) {
            printf("sprd_send_and_check_frame failed: %d\n", ret);
            return ret;
        }
        offset += chunk_size;
    }

    printf("Sending BSL_CMD_END_DATA...\n");

    // Send BSL_CMD_END_DATA
    ret = sprd_send_and_check_frame(sprd_context, BSL_CMD_END_DATA, 0, NULL);
    if (ret) {
        printf("sprd_send_and_check_frame failed: %d\n", ret);
        return ret;
    }

    printf("Sending BSL_CMD_EXEC_DATA...\n");
    ret = sprd_send_and_check_frame(sprd_context, BSL_CMD_EXEC_DATA, 0, NULL);
    if (ret) {
        printf("sprd_send_and_check_frame failed: %d\n", ret);
        return ret;
    }

    return 0;
}

static int mmap_file(const char *filename, uint8_t **fileptr, ssize_t *filesize) {
    int fd;

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        printf("open failed: %s\n", filename);
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        printf("fstat failed: %s\n", filename);
        close(fd);
        return -1;
    }

    *fileptr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (*fileptr == MAP_FAILED) {
        printf("mmap failed: %s\n", filename);
        close(fd);
        return -1;
    }

    *filesize = st.st_size;
    return 0;
}

static int munmap_file(uint8_t *fileptr, ssize_t filesize) {
    if (munmap(fileptr, filesize) < 0) {
        printf("munmap failed: %p, %ld\n", fileptr, filesize);
        return -1;
    }
    return 0;
}

static bool is_guid_zero(const uint8_t *guid) {
    for (int i = 0; i < 16; i++) {
        if (guid[i] != 0) {
            return false;
        }
    }
    return true;
}

static void print_utf16(const uint16_t *buf) {
    while (*buf) {
        printf("%c", *buf);
        buf++;
    }
}

static uint64_t get_time() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000 + (uint64_t) ts.tv_nsec / 1000000;
}

static void read_partition_to_file(libusb_device_handle *handle, gpt_entry_t *entry) {
    // file name from entry ".img"
    char filename[40];
    int filename_length = 0;
    for (int i = 0; i < 36; i++) {
        if (entry->partition_name[i] == 0) {
            break;
        }
        filename[filename_length++] = (char) entry->partition_name[i];
    }
    filename[filename_length++] = '.';
    filename[filename_length++] = 'i';
    filename[filename_length++] = 'm';
    filename[filename_length++] = 'g';
    filename[filename_length] = 0;

    printf("Writing partition to %s...\n", filename);

    int ret;
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        printf("open failed: %s\n", filename);
        return;
    }

    uint8_t buffer[EMMC_BLOCK_SIZE];
    uint32_t total_blocks = entry->ending_lba - entry->starting_lba + 1;
    for (uint32_t i = 0; i < total_blocks; i++) {
        uint64_t start_time = get_time();
        ret = da_read_single_block(handle, entry->starting_lba + i, buffer);
        if (ret) {
            printf("da_read_single_block failed: %d\n", ret);
            close(fd);
            return;
        }

        ssize_t written = write(fd, buffer, EMMC_BLOCK_SIZE);
        if (written != EMMC_BLOCK_SIZE) {
            printf("write failed: %ld\n", written);
            close(fd);
            return;
        }
        uint64_t end_time = get_time();

        // calculate also mb/s
        printf("Read block %u/%u (%u%%) in %lu ms (%.2f MB/s)\n", i + 1, total_blocks, (i + 1) * 100 / total_blocks, end_time - start_time, ((double) EMMC_BLOCK_SIZE / (double) (end_time - start_time)) * 1000 / (1024 * 1024));
    }

    close(fd);
    printf("Done\n");
}

static int sprd_do_work(SprdContext *sprd_context) {
    int ret;

    sprd_context->crc = sprd_brom_crc;

    printf("Sending USB hello...\n");
    ret = sprd_send_usb_hello(sprd_context);
    if (ret) {
        printf("sprd_send_usb_init failed: %s\n", libusb_error_name(ret));
        return ret;
    }

    printf("Received BSL_REP_VER: %.*s\n", sprd_get_frame_data_size(sprd_context), sprd_get_frame_data(sprd_context));

    ret = sprd_check_connection(sprd_context);
    if (ret) {
        printf("sprd_check_connection failed: %d\n", ret);
        return ret;
    }

    printf("Connected to BootROM!\n");

    // TODO: Everything's set up, now we can start real work!

    printf("Starting fdl1 execution...\n");

    char *filename = "/home/iscle/Documents/sprd_test/app_with_gap.bin";
    uint8_t *payload;
    ssize_t payload_size;
    ret = mmap_file(filename, &payload, &payload_size);
    if (ret) {
        printf("mmap_file failed: %d\n", ret);
        return ret;
    }

    ret = sprd_execute_payload(sprd_context, 0x00005500, payload, payload_size);
    if (ret) {
        printf("sprd_execute_payload failed: %d\n", ret);
        return ret;
    }

    ret = munmap_file(payload, payload_size);
    if (ret) {
        printf("munmap_file failed: %d\n", ret);
        return ret;
    }

    uint16_t cmd;
    uint16_t data_length;
    void *data;
    if (da_receive(sprd_context->handle, &cmd, &data_length, &data)) {
        printf("da_receive failed\n");
        return -1;
    }

    if (cmd != CMD_VERSION) {
        printf("Unexpected command: 0x%02x\n", cmd);
        return -1;
    }

    printf("Received version: %.*s\n", data_length, (char *) data);

    ret = da_emmc_init(sprd_context->handle);
    if (ret) {
        printf("da_emmc_init failed: %d\n", ret);
        return -1;
    }

    uint32_t sec_count;
    ret = da_get_sec_count(sprd_context->handle, &sec_count);
    if (ret) {
        printf("da_get_sec_count failed: %d\n", ret);
        return -1;
    }

    printf("emmc sector count: %u\n", sec_count);

    uint8_t blk_buf[EMMC_BLOCK_SIZE];
    ret = da_read_single_block(sprd_context->handle, 1, blk_buf);
    if (ret) {
        printf("da_read_single_block failed: %d\n", ret);
        return -1;
    }

    gpt_header_t gpt_header;
    memcpy(&gpt_header, blk_buf, sizeof(gpt_header_t));
    if (gpt_header.signature != GPT_HEADER_SIGNATURE) {
        printf("Invalid GPT header signature: 0x%08lx\n", gpt_header.signature);
        return -1;
    }

    printf("GPT header:\n");
    printf("  Header size: %u\n", gpt_header.header_size);
    printf("  MyLBA: %lu\n", gpt_header.my_lba);
    printf("  AlternateLBA: %lu\n", gpt_header.alternate_lba);
    printf("  FirstUsableLBA: %lu\n", gpt_header.first_usable_lba);
    printf("  LastUsableLBA: %lu\n", gpt_header.last_usable_lba);
    printf("  PartitionEntryLBA: %lu\n", gpt_header.partition_entry_lba);
    printf("  NumberOfPartitionEntries: %u\n", gpt_header.number_of_partition_entries);
    printf("  SizeOfPartitionEntry: %u\n", gpt_header.size_of_partition_entry);

    uint32_t partition_entries_per_block = EMMC_BLOCK_SIZE / gpt_header.size_of_partition_entry;
    uint32_t partition_entries_blocks = gpt_header.number_of_partition_entries / partition_entries_per_block;
    for (uint32_t i = 0; i < partition_entries_blocks; i++) {
        uint32_t lba = gpt_header.partition_entry_lba + i;
        ret = da_read_single_block(sprd_context->handle, lba, blk_buf);
        if (ret) {
            printf("da_read_single_block failed: %d\n", ret);
            return -1;
        }

        gpt_entry_t gpt_entry;
        for (uint32_t j = 0; j < partition_entries_per_block; j++) {
            memcpy(&gpt_entry, blk_buf + j * gpt_header.size_of_partition_entry, sizeof(gpt_entry_t));
            if (is_guid_zero(gpt_entry.partition_type_guid)) {
                continue;
            }

            printf("Partition entry %u:\n", i + j);
            printf("  StartingLBA: %lu\n", gpt_entry.starting_lba);
            printf("  EndingLBA: %lu\n", gpt_entry.ending_lba);
            printf("  PartitionName: ");
            print_utf16(gpt_entry.partition_name);
            printf("\n");

            read_partition_to_file(sprd_context->handle, &gpt_entry);
        }
    }

    return 0;
}

static int check_endpoints(SprdContext *sprd_context) {
    int ret;
    struct libusb_device_descriptor desc = {};
    struct libusb_config_descriptor *config = NULL;
    bool has_config_descriptor = false;

    ret = libusb_get_device_descriptor(libusb_get_device(sprd_context->handle), &desc);
    if (ret) {
        printf("libusb_get_device_descriptor failed: %s\n", libusb_error_name(ret));
        goto exit;
    }

    if (desc.bNumConfigurations != 1) {
        printf("Unexpected number of configurations: %d\n", desc.bNumConfigurations);
        ret = LIBUSB_ERROR_NO_DEVICE;
        goto exit;
    }

    ret = libusb_get_config_descriptor(libusb_get_device(sprd_context->handle), 0, &config);
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

    bool found_in = false;
    bool found_out = false;

    for (uint8_t i = 0; i < config->interface->altsetting->bNumEndpoints; i++) {
        const struct libusb_endpoint_descriptor *endpoint = &config->interface->altsetting->endpoint[i];
        if (endpoint->bEndpointAddress == 0x85) {
            found_in = true;
        } else if (endpoint->bEndpointAddress == 0x06) {
            found_out = true;
        }
    }

    if (!found_in || !found_out) {
        printf("Endpoints not found\n");
        ret = LIBUSB_ERROR_NO_DEVICE;
        goto exit;
    }

exit:
    if (has_config_descriptor) {
        libusb_free_config_descriptor(config);
        config = NULL;
        has_config_descriptor = false;
    }

    return ret;
}

int main() {
    int ret;
    SprdContext sprd_context = {0};
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

    ret = check_endpoints(&sprd_context);
    if (ret) {
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
    if (is_open) {
        libusb_close(sprd_context.handle);
        sprd_context.handle = NULL;
        libusb_exit(NULL);
        is_open = false;
    }

    return ret;
}
