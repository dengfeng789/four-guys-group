#include "sm3_internal.h"

#include <immintrin.h>

#define VROTL32(X, N) \
    _mm_or_si128(_mm_slli_epi32((X), (N)), _mm_srli_epi32((X), 32 - (N)))

static __m128i p1x4(__m128i x)
{
    return _mm_xor_si128(x,
           _mm_xor_si128(VROTL32(x, 15), VROTL32(x, 23)));
}

/* AVX2 handles eight input words per instruction. */
static void load_words(uint32_t words[68], const uint8_t block[64])
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

/*
 * Compute W[j..j+2] together. W[j+3] depends on the newly generated W[j],
 * so its lane is repaired with one scalar expression.
 */
static void expand4(uint32_t words[68], unsigned int j)
{
    __m128i a = _mm_loadu_si128(
        (const __m128i *)(const void *)(words + j - 16));
    __m128i b = _mm_loadu_si128(
        (const __m128i *)(const void *)(words + j - 9));
    __m128i c = _mm_loadu_si128(
        (const __m128i *)(const void *)(words + j - 3));
    __m128i d = _mm_loadu_si128(
        (const __m128i *)(const void *)(words + j - 13));
    __m128i e = _mm_loadu_si128(
        (const __m128i *)(const void *)(words + j - 6));
    __m128i x, result;

    c = _mm_blend_epi32(c, _mm_setzero_si128(), 0x8);
    x = _mm_xor_si128(a, _mm_xor_si128(b, VROTL32(c, 15)));
    result = _mm_xor_si128(p1x4(x),
             _mm_xor_si128(VROTL32(d, 7), e));
    _mm_storeu_si128((__m128i *)(void *)(words + j), result);
    words[j + 3] = sm3_p1(words[j - 13] ^ words[j - 6] ^
                          sm3_rotl32(words[j], 15)) ^
                   sm3_rotl32(words[j - 10], 7) ^ words[j - 3];
}

void sm3_compress_avx2_offline(uint32_t state[8], const uint8_t *blocks,
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

