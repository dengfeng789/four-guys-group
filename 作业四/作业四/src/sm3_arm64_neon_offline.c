#include "sm3_internal.h"

#include <arm_neon.h>

#define VROTL32(X, N) \
    vorrq_u32(vshlq_n_u32((X), (N)), vshrq_n_u32((X), 32 - (N)))

static uint32x4_t p1x4(uint32x4_t x)
{
    return veorq_u32(x, veorq_u32(VROTL32(x, 15), VROTL32(x, 23)));
}

static void load_words(uint32_t words[68], const uint8_t block[64])
{
    unsigned int j;
    for (j = 0; j < 16; j += 4) {
        uint8x16_t input = vld1q_u8(block + 4U * j);
        vst1q_u32(words + j,
                  vreinterpretq_u32_u8(vrev32q_u8(input)));
    }
}

static void expand4(uint32_t words[68], unsigned int j)
{
    uint32x4_t a = vld1q_u32(words + j - 16);
    uint32x4_t b = vld1q_u32(words + j - 9);
    uint32x4_t c = vld1q_u32(words + j - 3);
    uint32x4_t d = vld1q_u32(words + j - 13);
    uint32x4_t e = vld1q_u32(words + j - 6);
    uint32x4_t x, result;

    c = vsetq_lane_u32(0, c, 3);
    x = veorq_u32(a, veorq_u32(b, VROTL32(c, 15)));
    result = veorq_u32(p1x4(x), veorq_u32(VROTL32(d, 7), e));
    vst1q_u32(words + j, result);
    words[j + 3] = sm3_p1(words[j - 13] ^ words[j - 6] ^
                          sm3_rotl32(words[j], 15)) ^
                   sm3_rotl32(words[j - 10], 7) ^ words[j - 3];
}

void sm3_compress_arm64_offline(uint32_t state[8], const uint8_t *blocks,
                                size_t num_blocks)
{
    while (num_blocks-- != 0) {
        uint32_t words[68];
        unsigned int j;
        load_words(words, blocks);
        for (j = 16; j < 68; j += 4)
            expand4(words, j);
        sm3_compress_expanded(state, words);
        blocks += SM3_BLOCK_SIZE;
    }
}

#undef VROTL32

