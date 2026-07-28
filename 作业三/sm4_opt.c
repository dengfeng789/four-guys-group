#include <stdint.h>
#include <string.h>
#include <immintrin.h>

// 1. BMI2 / RORX Optimizations (PPT指出: 新指令普遍支持3目操作 RORX, andn)
#if defined(_MSC_VER)
#include <stdlib.h>
#define ROTL32(x, n) _rotl(x, n)
#else
static inline uint32_t ROTL32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}
#endif

// BMI2 ANDN implementation for 3-operand logic
#define ANDN32(x, y) _andn_u32(x, y)

#define P0(x) ((x) ^ ROTL32((x), 9) ^ ROTL32((x), 17))
#define P1(x) ((x) ^ ROTL32((x), 15) ^ ROTL32((x), 23))

#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define GG0(x, y, z) ((x) ^ (y) ^ (z))
// GG1 Optimization using ANDN (PPT优化: A^B^C / GG(x,y,z) 可利用 andn 简化)
#define GG1(x, y, z) (((x) & (y)) | ANDN32((x), (z)))

// 2. 消除字置换 (Eliminate Word Permutations)
// PPT指出: "不再置换，保持在原寄存器，4轮后回到原始位置... 消除了3个置换操作"
#define RND_STEP(A, B, C, D, E, F, G, H, W, Wp, T, funcF, funcG) \
    do { \
        uint32_t SS1 = ROTL32((ROTL32(A, 12) + E + T), 7); \
        uint32_t SS2 = SS1 ^ ROTL32(A, 12); \
        uint32_t TT1 = funcF(A, B, C) + D + SS2 + Wp; \
        uint32_t TT2 = funcG(E, F, G) + H + SS1 + W; \
        D = TT1; \
        H = P0(TT2); \
        B = ROTL32(B, 9); \
        F = ROTL32(F, 19); \
    } while(0)

#define RND_4(A, B, C, D, E, F, G, H, W, Wp, T0, T1, T2, T3, F_MACRO, G_MACRO) \
    RND_STEP(A, B, C, D, E, F, G, H, W[0], Wp[0], T0, F_MACRO, G_MACRO); \
    RND_STEP(D, A, B, C, H, E, F, G, W[1], Wp[1], T1, F_MACRO, G_MACRO); \
    RND_STEP(C, D, A, B, G, H, E, F, W[2], Wp[2], T2, F_MACRO, G_MACRO); \
    RND_STEP(B, C, D, A, F, G, H, E, W[3], Wp[3], T3, F_MACRO, G_MACRO);

// Constant T table (Tj <<< j precalculated for optimization)
static const uint32_t T_TABLE[64] = {
    0x79cc4519, 0xf3988a32, 0xe7311465, 0xce6228cb, 0x9cc45197, 0x3988a32f, 0x7311465e, 0xe6228cbc,
    0xcc451979, 0x988a32f3, 0x311465e7, 0x6228cbce, 0xc451979c, 0x88a32f39, 0x11465e73, 0x228cbce6,
    0x9d8a7a87, 0x3b14f50f, 0x7629ea1e, 0xec53d43c, 0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce,
    0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec, 0xa7a879d8, 0x4f50f3b1, 0x9ea1e762, 0x3d43cec5,
    0x7a879d8a, 0xf50f3b14, 0xea1e7629, 0xd43cec53, 0xa879d8a7, 0x50f3b14f, 0xa1e7629e, 0x43cec53d,
    0x879d8a7a, 0x0f3b14f5, 0x1e7629ea, 0x3cec53d4, 0x79d8a7a8, 0xf3b14f50, 0xe7629ea1, 0xcec53d43,
    0x9d8a7a87, 0x3b14f50f, 0x7629ea1e, 0xec53d43c, 0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce,
    0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec, 0xa7a879d8, 0x4f50f3b1, 0x9ea1e762, 0x3d43cec5
};

void sm3_compress_block_x86_hybrid(uint32_t state[8], const uint8_t data[64]) {
    // 3. 栈中转存放中间变量 (Stack intermediary array)
    // PPT指出: "混合寄存器数据间传递开销大，通过栈来中转数据，减少SIMD和通用寄存器数据依赖"
    __attribute__((aligned(32))) uint32_t W[68];
    __attribute__((aligned(32))) uint32_t Wp[64];

    // 4. SIMD 消息扩展 (AVX2/SSSE3)
    // PPT指出: "SIMD-shuffle指令，按字节洗牌，用于大小端转换 vpshufb"
    __m128i mask = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);

    // 加载数据至 SIMD 寄存器 (xmm0 ~ xmm3)
    __m128i xmm0 = _mm_loadu_si128((__m128i*)(data + 0));
    __m128i xmm1 = _mm_loadu_si128((__m128i*)(data + 16));
    __m128i xmm2 = _mm_loadu_si128((__m128i*)(data + 32));
    __m128i xmm3 = _mm_loadu_si128((__m128i*)(data + 48));

    // 大小端转换
    xmm0 = _mm_shuffle_epi8(xmm0, mask);
    xmm1 = _mm_shuffle_epi8(xmm1, mask);
    xmm2 = _mm_shuffle_epi8(xmm2, mask);
    xmm3 = _mm_shuffle_epi8(xmm3, mask);

    // 将基础消息写入栈内存
    _mm_store_si128((__m128i*) & W[0], xmm0);
    _mm_store_si128((__m128i*) & W[4], xmm1);
    _mm_store_si128((__m128i*) & W[8], xmm2);
    _mm_store_si128((__m128i*) & W[12], xmm3);

    /*
     * 消息扩展阶段：
     * PPT详述了利用 vpalignr 和 vpshufd 指令可以并行生成 W16~W67。
     * 概念性指令序列(对应PPT中的X86-64架构实现-消息扩展2):
     * xmm4 = _mm_alignr_epi8(xmm1, xmm0, 12);  // PALIGNR
     * xmm6 = _mm_alignr_epi8(xmm2, xmm1, 12);  // PALIGNR
     * __m128i xmm7 = _mm_shuffle_epi32(xmm2, _MM_SHUFFLE(3, 3, 2, 1)); // SHUFFLE
     * 此处为了保证编译泛用性，利用C循环结构表示，现代编译器会在AVX2目标下自动展开为相应指令序列，同时将结果存入栈区。
     */
    for (int j = 16; j < 68; j++) {
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL32(W[j - 3], 15)) ^ ROTL32(W[j - 13], 7) ^ W[j - 6];
    }

    // W'j 也可以通过 SIMD 的 vpxor 指令在栈上计算完成
    for (int j = 0; j < 64; j++) {
        Wp[j] = W[j] ^ W[j + 4];
    }

    // 5. 迭代压缩部分 - 转移至通用寄存器
    // PPT指出: "尽可能减少内存写...将Wj, 和w’j从栈中读取，并执行寄存器加法"
    uint32_t A = state[0], B = state[1], C = state[2], D = state[3];
    uint32_t E = state[4], F = state[5], G = state[6], H = state[7];

    // 全展开64轮 (PPT指出: "如寄存器数量紧张，核心函数尝试全展开")
    for (int j = 0; j < 16; j += 4) {
        RND_4(A, B, C, D, E, F, G, H, (&W[j]), (&Wp[j]),
            T_TABLE[j], T_TABLE[j + 1], T_TABLE[j + 2], T_TABLE[j + 3], FF0, GG0);
    }
    for (int j = 16; j < 64; j += 4) {
        RND_4(A, B, C, D, E, F, G, H, (&W[j]), (&Wp[j]),
            T_TABLE[j], T_TABLE[j + 1], T_TABLE[j + 2], T_TABLE[j + 3], FF1, GG1);
    }

    state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
    state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
}

// 供外部测试的空 main 函数
int main() {
    uint32_t state[8] = {
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    };
    uint8_t data[64] = { 0 };
    // 执行一轮压缩
    sm3_compress_block_x86_hybrid(state, data);
    return 0;
}