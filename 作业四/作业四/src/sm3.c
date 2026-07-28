#include "sm3_internal.h"

#include <string.h>

static const uint32_t sm3_initial_state[8] = {
    UINT32_C(0x7380166f), UINT32_C(0x4914b2b9),
    UINT32_C(0x172442d7), UINT32_C(0xda8a0600),
    UINT32_C(0xa96f30bc), UINT32_C(0x163138aa),
    UINT32_C(0xe38dee4d), UINT32_C(0xb0fb0e4e)
};

static sm3_backend sm3_best_backend(void)
{
#if defined(SM3_HAVE_X86_BACKENDS)
    __builtin_cpu_init();
    if (__builtin_cpu_supports("avx2"))
        return SM3_BACKEND_AVX2_OFFLINE;
#elif defined(SM3_HAVE_ARM64_BACKENDS)
    return SM3_BACKEND_ARM64_OFFLINE;
#endif
    return SM3_BACKEND_REFERENCE;
}

static sm3_compress_fn sm3_get_compress(sm3_backend backend)
{
    switch (backend) {
    case SM3_BACKEND_REFERENCE: return sm3_compress_ref;
#if defined(SM3_HAVE_X86_BACKENDS)
    case SM3_BACKEND_AVX2_OFFLINE: return sm3_compress_avx2_offline;
    case SM3_BACKEND_AVX2_ONLINE: return sm3_compress_avx2_online;
#endif
#if defined(SM3_HAVE_ARM64_BACKENDS)
    case SM3_BACKEND_ARM64_OFFLINE: return sm3_compress_arm64_offline;
    case SM3_BACKEND_ARM64_ONLINE: return sm3_compress_arm64_online;
#endif
    default: return NULL;
    }
}

int sm3_backend_available(sm3_backend backend)
{
    if (backend == SM3_BACKEND_AUTO || backend == SM3_BACKEND_REFERENCE)
        return 1;
#if defined(SM3_HAVE_X86_BACKENDS)
    __builtin_cpu_init();
    if (backend == SM3_BACKEND_AVX2_OFFLINE ||
        backend == SM3_BACKEND_AVX2_ONLINE)
        return __builtin_cpu_supports("avx2");
#endif
#if defined(SM3_HAVE_ARM64_BACKENDS)
    if (backend == SM3_BACKEND_ARM64_OFFLINE ||
        backend == SM3_BACKEND_ARM64_ONLINE)
        return 1;
#endif
    return 0;
}

const char *sm3_backend_name(sm3_backend backend)
{
    static const char *const names[SM3_BACKEND_COUNT] = {
        "auto", "reference", "avx2-offline", "avx2-online",
        "arm64-offline", "arm64-online"
    };
    return backend >= 0 && backend < SM3_BACKEND_COUNT
               ? names[backend] : "unknown";
}

int sm3_init_backend(sm3_ctx *ctx, sm3_backend backend)
{
    if (ctx == NULL)
        return 0;
    if (backend == SM3_BACKEND_AUTO)
        backend = sm3_best_backend();
    if (!sm3_backend_available(backend) || sm3_get_compress(backend) == NULL)
        return 0;
    memcpy(ctx->state, sm3_initial_state, sizeof(ctx->state));
    ctx->total_len = 0;
    ctx->buffer_len = 0;
    ctx->backend = backend;
    return 1;
}

void sm3_init(sm3_ctx *ctx)
{
    (void)sm3_init_backend(ctx, SM3_BACKEND_AUTO);
}

void sm3_update(sm3_ctx *ctx, const void *data, size_t len)
{
    const uint8_t *input = (const uint8_t *)data;
    sm3_compress_fn compress = sm3_get_compress(ctx->backend);

    if (len == 0)
        return;
    ctx->total_len += (uint64_t)len;
    if (ctx->buffer_len != 0) {
        size_t needed = SM3_BLOCK_SIZE - ctx->buffer_len;
        size_t take = len < needed ? len : needed;
        memcpy(ctx->buffer + ctx->buffer_len, input, take);
        ctx->buffer_len += take; input += take; len -= take;
        if (ctx->buffer_len == SM3_BLOCK_SIZE) {
            compress(ctx->state, ctx->buffer, 1);
            ctx->buffer_len = 0;
        }
    }
    if (len >= SM3_BLOCK_SIZE) {
        size_t blocks = len / SM3_BLOCK_SIZE;
        compress(ctx->state, input, blocks);
        input += blocks * SM3_BLOCK_SIZE;
        len -= blocks * SM3_BLOCK_SIZE;
    }
    if (len != 0) {
        memcpy(ctx->buffer, input, len);
        ctx->buffer_len = len;
    }
}

void sm3_final(sm3_ctx *ctx, uint8_t digest[SM3_DIGEST_SIZE])
{
    uint8_t tail[2 * SM3_BLOCK_SIZE] = {0};
    uint64_t bit_len = ctx->total_len << 3;
    size_t tail_len = ctx->buffer_len;
    size_t padded_len, i;
    sm3_compress_fn compress = sm3_get_compress(ctx->backend);

    memcpy(tail, ctx->buffer, tail_len);
    tail[tail_len++] = 0x80;
    padded_len = tail_len <= 56 ? 64 : 128;
    for (i = 0; i < 8; ++i)
        tail[padded_len - 1 - i] = (uint8_t)(bit_len >> (8U * i));
    compress(ctx->state, tail, padded_len / SM3_BLOCK_SIZE);
    for (i = 0; i < 8; ++i)
        sm3_store_be32(digest + 4 * i, ctx->state[i]);
    memset(tail, 0, sizeof(tail));
    memset(ctx, 0, sizeof(*ctx));
}

void sm3_digest(const void *data, size_t len, uint8_t digest[SM3_DIGEST_SIZE])
{
    sm3_ctx ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, data, len);
    sm3_final(&ctx, digest);
}

int sm3_digest_backend(sm3_backend backend, const void *data, size_t len,
                       uint8_t digest[SM3_DIGEST_SIZE])
{
    sm3_ctx ctx;
    if (!sm3_init_backend(&ctx, backend))
        return 0;
    sm3_update(&ctx, data, len);
    sm3_final(&ctx, digest);
    return 1;
}
