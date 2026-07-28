#include "sm3_internal.h"

#include <arm_neon.h>

#define VROTL32(X, N) \
    vorrq_u32(vshlq_n_u32((X), (N)), vshrq_n_u32((X), 32 - (N)))

static uint32x4_t p1x4(uint32x4_t x)
{
    return veorq_u32(x, veorq_u32(VROTL32(x, 15), VROTL32(x, 23)));
}

static void load_words(uint32_t words[20], const uint8_t block[64])
{
    unsigned int j;
    for (j = 0; j < 16; j += 4) {
        uint8x16_t input = vld1q_u8(block + 4U * j);
        vst1q_u32(words + j,
                  vreinterpretq_u32_u8(vrev32q_u8(input)));
    }
}

static void expand_next4(uint32_t words[20])
{
    uint32x4_t a = vld1q_u32(words + 0);
    uint32x4_t b = vld1q_u32(words + 7);
    uint32x4_t c = vld1q_u32(words + 13);
    uint32x4_t d = vld1q_u32(words + 3);
    uint32x4_t e = vld1q_u32(words + 10);
    uint32x4_t x, result;

    c = vsetq_lane_u32(0, c, 3);
    x = veorq_u32(a, veorq_u32(b, VROTL32(c, 15)));
    result = veorq_u32(p1x4(x), veorq_u32(VROTL32(d, 7), e));
    vst1q_u32(words + 16, result);
    words[19] = sm3_p1(words[3] ^ words[10] ^
                       sm3_rotl32(words[16], 15)) ^
                sm3_rotl32(words[6], 7) ^ words[13];
}

void sm3_compress_arm64_online(uint32_t state[8], const uint8_t *blocks,
                               size_t num_blocks)
{
    while (num_blocks-- != 0) {
        uint32_t words[20] = {0};
        sm3_working_state working;
        unsigned int j;
        load_words(words, blocks);
        sm3_working_init(&working, state);
        sm3_round4(&working, words, 0);
        sm3_round4(&working, words + 4, 4);
        sm3_round4(&working, words + 8, 8);
        for (j = 16; j < 68; j += 4) {
            expand_next4(words);
            sm3_round4(&working, words + 12, j - 4);
            if (j != 64)
                sm3_slide_window(words);
        }
        sm3_working_finish(state, &working);
        blocks += SM3_BLOCK_SIZE;
    }
}

#undef VROTL32

