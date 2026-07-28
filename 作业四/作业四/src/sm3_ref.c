#include "sm3_internal.h"

/* Straightforward scalar implementation used as the correctness oracle. */
void sm3_compress_ref(uint32_t state[8], const uint8_t *blocks,
                      size_t num_blocks)
{
    while (num_blocks-- != 0) {
        uint32_t words[68];
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
        unsigned int j;

        for (j = 0; j < 16; ++j)
            words[j] = sm3_load_be32(blocks + 4U * j);
        for (j = 16; j < 68; ++j)
            words[j] = sm3_p1(words[j - 16] ^ words[j - 9] ^
                              sm3_rotl32(words[j - 3], 15)) ^
                       sm3_rotl32(words[j - 13], 7) ^ words[j - 6];

        for (j = 0; j < 64; ++j) {
            uint32_t t = j < 16 ? UINT32_C(0x79cc4519)
                                : UINT32_C(0x7a879d8a);
            uint32_t a12 = sm3_rotl32(a, 12);
            uint32_t ss1 = sm3_rotl32(a12 + e + sm3_rotl32(t, j), 7);
            uint32_t ss2 = ss1 ^ a12;
            uint32_t tt1 = sm3_ff(a, b, c, j) + d + ss2 +
                           (words[j] ^ words[j + 4]);
            uint32_t tt2 = sm3_gg(e, f, g, j) + h + ss1 + words[j];

            d = c; c = sm3_rotl32(b, 9); b = a; a = tt1;
            h = g; g = sm3_rotl32(f, 19); f = e; e = sm3_p0(tt2);
        }
        state[0] ^= a; state[1] ^= b; state[2] ^= c; state[3] ^= d;
        state[4] ^= e; state[5] ^= f; state[6] ^= g; state[7] ^= h;
        blocks += SM3_BLOCK_SIZE;
    }
}

