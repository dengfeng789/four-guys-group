#ifndef SM3_INTERNAL_H
#define SM3_INTERNAL_H

#include "sm3.h"

#include <stddef.h>
#include <stdint.h>

typedef void (*sm3_compress_fn)(uint32_t state[8], const uint8_t *blocks,
                                size_t num_blocks);

static inline uint32_t sm3_load_be32(const uint8_t src[4])
{
    return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) |
           ((uint32_t)src[2] << 8) | (uint32_t)src[3];
}

static inline void sm3_store_be32(uint8_t dst[4], uint32_t value)
{
    dst[0] = (uint8_t)(value >> 24);
    dst[1] = (uint8_t)(value >> 16);
    dst[2] = (uint8_t)(value >> 8);
    dst[3] = (uint8_t)value;
}

static inline uint32_t sm3_rotl32(uint32_t value, unsigned int count)
{
    count &= 31U;
    return count == 0 ? value : (value << count) | (value >> (32U - count));
}

static inline uint32_t sm3_p0(uint32_t x)
{
    return x ^ sm3_rotl32(x, 9) ^ sm3_rotl32(x, 17);
}

static inline uint32_t sm3_p1(uint32_t x)
{
    return x ^ sm3_rotl32(x, 15) ^ sm3_rotl32(x, 23);
}

static inline uint32_t sm3_ff(uint32_t x, uint32_t y, uint32_t z,
                              unsigned int round)
{
    return round < 16 ? x ^ y ^ z : (x & y) | (x & z) | (y & z);
}

static inline uint32_t sm3_gg(uint32_t x, uint32_t y, uint32_t z,
                              unsigned int round)
{
    return round < 16 ? x ^ y ^ z : (x & y) | (~x & z);
}

typedef struct {
    uint32_t a, b, c, d, e, f, g, h;
} sm3_working_state;

static inline void sm3_working_init(sm3_working_state *w,
                                    const uint32_t state[8])
{
    w->a = state[0]; w->b = state[1]; w->c = state[2]; w->d = state[3];
    w->e = state[4]; w->f = state[5]; w->g = state[6]; w->h = state[7];
}

/*
 * Four rounds are written with rotated arguments. After four rounds every
 * logical variable is back in its original C variable, eliminating the
 * A<-TT1, B<-A, ... register-copy chain from every single round.
 */
static inline void sm3_round4(sm3_working_state *working,
                              const uint32_t words[8],
                              unsigned int round)
{
    uint32_t a = working->a, b = working->b;
    uint32_t c = working->c, d = working->d;
    uint32_t e = working->e, f = working->f;
    uint32_t g = working->g, h = working->h;
    uint32_t ss1, ss2, tt1, tt2;

#define SM3_STEP(A, B, C, D, E, F, G, H, O) do {                         \
        unsigned int sm3_j = round + (O);                                \
        uint32_t sm3_a12 = sm3_rotl32((A), 12);                           \
        uint32_t sm3_t = sm3_j < 16 ? UINT32_C(0x79cc4519)                \
                                    : UINT32_C(0x7a879d8a);                \
        ss1 = sm3_rotl32(sm3_a12 + (E) + sm3_rotl32(sm3_t, sm3_j), 7);    \
        ss2 = ss1 ^ sm3_a12;                                              \
        tt1 = sm3_ff((A), (B), (C), sm3_j) + (D) + ss2 +                 \
              (words[(O)] ^ words[(O) + 4]);                              \
        tt2 = sm3_gg((E), (F), (G), sm3_j) + (H) + ss1 + words[(O)];     \
        (D) = tt1; (H) = sm3_p0(tt2);                                     \
        (B) = sm3_rotl32((B), 9); (F) = sm3_rotl32((F), 19);             \
    } while (0)

    SM3_STEP(a, b, c, d, e, f, g, h, 0);
    SM3_STEP(d, a, b, c, h, e, f, g, 1);
    SM3_STEP(c, d, a, b, g, h, e, f, 2);
    SM3_STEP(b, c, d, a, f, g, h, e, 3);
#undef SM3_STEP

    working->a = a; working->b = b; working->c = c; working->d = d;
    working->e = e; working->f = f; working->g = g; working->h = h;
}

static inline void sm3_working_finish(uint32_t state[8],
                                      const sm3_working_state *w)
{
    state[0] ^= w->a; state[1] ^= w->b; state[2] ^= w->c; state[3] ^= w->d;
    state[4] ^= w->e; state[5] ^= w->f; state[6] ^= w->g; state[7] ^= w->h;
}

static inline void sm3_slide_window(uint32_t words[20])
{
    unsigned int i;
    for (i = 0; i < 16; ++i)
        words[i] = words[i + 4];
}

static inline void sm3_compress_expanded(uint32_t state[8],
                                         const uint32_t words[68])
{
    sm3_working_state working;
    unsigned int j;
    sm3_working_init(&working, state);
    for (j = 0; j < 64; j += 4)
        sm3_round4(&working, words + j, j);
    sm3_working_finish(state, &working);
}

void sm3_compress_ref(uint32_t state[8], const uint8_t *blocks,
                      size_t num_blocks);

#if defined(SM3_HAVE_X86_BACKENDS)
void sm3_compress_avx2_offline(uint32_t state[8], const uint8_t *blocks,
                               size_t num_blocks);
void sm3_compress_avx2_online(uint32_t state[8], const uint8_t *blocks,
                              size_t num_blocks);
#endif

#if defined(SM3_HAVE_ARM64_BACKENDS)
void sm3_compress_arm64_offline(uint32_t state[8], const uint8_t *blocks,
                                size_t num_blocks);
void sm3_compress_arm64_online(uint32_t state[8], const uint8_t *blocks,
                               size_t num_blocks);
#endif

#endif
