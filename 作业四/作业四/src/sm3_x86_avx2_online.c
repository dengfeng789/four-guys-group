#include "sm3_internal.h"

#include <immintrin.h>

#define VROTL32(X, N) \
    _mm_or_si128(_mm_slli_epi32((X), (N)), _mm_srli_epi32((X), 32 - (N)))

static __m128i p1x4(__m128i x)
{
    return _mm_xor_si128(x,
           _mm_xor_si128(VROTL32(x, 15), VROTL32(x, 23)));
}

static void load_words(uint32_t words[20], const uint8_t block[64])
{
    const __m256i swap = _mm256_setr_epi8(
        3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12,
        3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12);
    __m256i lo = _mm256_loadu_si256((const __m256i *)(const void *)block);
    __m256i hi = _mm256_loadu_si256(
        (const __m256i *)(const void *)(block + 32));
    _mm256_storeu_si256((__m256i *)(void *)words,
                        _mm256_shuffle_epi8(lo, swap));
    _mm256_storeu_si256((__m256i *)(void *)(words + 8),
                        _mm256_shuffle_epi8(hi, swap));
}

static void expand_next4(uint32_t words[20])
{
    __m128i a = _mm_loadu_si128((const __m128i *)(const void *)(words + 0));
    __m128i b = _mm_loadu_si128((const __m128i *)(const void *)(words + 7));
    __m128i c = _mm_loadu_si128((const __m128i *)(const void *)(words + 13));
    __m128i d = _mm_loadu_si128((const __m128i *)(const void *)(words + 3));
    __m128i e = _mm_loadu_si128((const __m128i *)(const void *)(words + 10));
    __m128i x, result;

    c = _mm_blend_epi32(c, _mm_setzero_si128(), 0x8);
    x = _mm_xor_si128(a, _mm_xor_si128(b, VROTL32(c, 15)));
    result = _mm_xor_si128(p1x4(x),
             _mm_xor_si128(VROTL32(d, 7), e));
    _mm_storeu_si128((__m128i *)(void *)(words + 16), result);
    words[19] = sm3_p1(words[3] ^ words[10] ^
                       sm3_rotl32(words[16], 15)) ^
                sm3_rotl32(words[6], 7) ^ words[13];
}

void sm3_compress_avx2_online(uint32_t state[8], const uint8_t *blocks,
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

