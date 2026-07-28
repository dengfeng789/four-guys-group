#ifndef SM3_H
#define SM3_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SM3_DIGEST_SIZE 32
#define SM3_BLOCK_SIZE 64

typedef enum {
    SM3_BACKEND_AUTO = 0,
    SM3_BACKEND_REFERENCE,
    SM3_BACKEND_AVX2_OFFLINE,
    SM3_BACKEND_AVX2_ONLINE,
    SM3_BACKEND_ARM64_OFFLINE,
    SM3_BACKEND_ARM64_ONLINE,
    SM3_BACKEND_COUNT
} sm3_backend;

typedef struct {
    uint32_t state[8];
    uint64_t total_len;
    uint8_t buffer[SM3_BLOCK_SIZE];
    size_t buffer_len;
    sm3_backend backend;
} sm3_ctx;

void sm3_init(sm3_ctx *ctx);
int sm3_init_backend(sm3_ctx *ctx, sm3_backend backend);
void sm3_update(sm3_ctx *ctx, const void *data, size_t len);
void sm3_final(sm3_ctx *ctx, uint8_t digest[SM3_DIGEST_SIZE]);

void sm3_digest(const void *data, size_t len,
                uint8_t digest[SM3_DIGEST_SIZE]);
int sm3_digest_backend(sm3_backend backend, const void *data, size_t len,
                       uint8_t digest[SM3_DIGEST_SIZE]);

int sm3_backend_available(sm3_backend backend);
const char *sm3_backend_name(sm3_backend backend);

#ifdef __cplusplus
}
#endif

#endif
