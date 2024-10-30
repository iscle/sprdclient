#ifndef ENDIANNESS_H
#define ENDIANNESS_H

#define WRITE_BE16(ptr, val) do { \
    ((uint8_t *)(ptr))[0] = (uint8_t)((val) >> 8); \
    ((uint8_t *)(ptr))[1] = (uint8_t)(val); \
} while (0)

#define WRITE_BE32(ptr, val) do { \
    ((uint8_t *)(ptr))[0] = (uint8_t)((val) >> 24); \
    ((uint8_t *)(ptr))[1] = (uint8_t)((val) >> 16); \
    ((uint8_t *)(ptr))[2] = (uint8_t)((val) >> 8); \
    ((uint8_t *)(ptr))[3] = (uint8_t)(val); \
} while (0)

#define WRITE_BE64(ptr, val) do { \
    ((uint8_t *)(ptr))[0] = (uint8_t)((val) >> 56); \
    ((uint8_t *)(ptr))[1] = (uint8_t)((val) >> 48); \
    ((uint8_t *)(ptr))[2] = (uint8_t)((val) >> 40); \
    ((uint8_t *)(ptr))[3] = (uint8_t)((val) >> 32); \
    ((uint8_t *)(ptr))[4] = (uint8_t)((val) >> 24); \
    ((uint8_t *)(ptr))[5] = (uint8_t)((val) >> 16); \
    ((uint8_t *)(ptr))[6] = (uint8_t)((val) >> 8); \
    ((uint8_t *)(ptr))[7] = (uint8_t)(val); \
} while (0)

#define READ_BE16(ptr) \
    (((uint16_t)((const uint8_t *)(ptr))[0] << 8) | \
     ((uint16_t)((const uint8_t *)(ptr))[1]))

#define READ_BE32(ptr) \
    (((uint32_t)((const uint8_t *)(ptr))[0] << 24) | \
     ((uint32_t)((const uint8_t *)(ptr))[1] << 16) | \
     ((uint32_t)((const uint8_t *)(ptr))[2] << 8) | \
     ((uint32_t)((const uint8_t *)(ptr))[3]))

#define READ_BE64(ptr) \
    (((uint64_t)((const uint8_t *)(ptr))[0] << 56) | \
     ((uint64_t)((const uint8_t *)(ptr))[1] << 48) | \
     ((uint64_t)((const uint8_t *)(ptr))[2] << 40) | \
     ((uint64_t)((const uint8_t *)(ptr))[3] << 32) | \
     ((uint64_t)((const uint8_t *)(ptr))[4] << 24) | \
     ((uint64_t)((const uint8_t *)(ptr))[5] << 16) | \
     ((uint64_t)((const uint8_t *)(ptr))[6] << 8) | \
     ((uint64_t)((const uint8_t *)(ptr))[7]))

#endif //ENDIANNESS_H
