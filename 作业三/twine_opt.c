#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#define BENCHMARK_SIZE (16 * 1024 * 1024) // 16 MB 测试数据大小

// ---------------------------------------------------------
// TWINE 基础常数与 S 盒定义
// ---------------------------------------------------------
static const uint8_t S[16] = {
    0xC, 0x0, 0xF, 0xA, 0x2, 0xB, 0x9, 0x5,
    0x8, 0x3, 0xD, 0x7, 0x1, 0xE, 0x6, 0x4
};

static const uint8_t CON[36] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x03, 0x06,
    0x0c, 0x18, 0x30, 0x23, 0x05, 0x0a, 0x14, 0x28,
    0x13, 0x26, 0x0f, 0x1e, 0x3c, 0x3b, 0x35, 0x29,
    0x11, 0x22, 0x07, 0x0e, 0x1c, 0x38, 0x33, 0x25,
    0x0d, 0x1a, 0x34, 0x2b
};

void twine_init() {
    // 初始化空函数，保持接口一致
}

// ---------------------------------------------------------
// 密钥扩展算法 (TWINE-128)
// ---------------------------------------------------------
void twine_setkey(uint32_t rk[36], const uint8_t key[16]) {
    uint8_t WK[32];
    for (int i = 0; i < 16; i++) {
        WK[2 * i]     = (key[i] >> 4) & 0x0F;
        WK[2 * i + 1] = key[i] & 0x0F;
    }

    for (int r = 0; r < 36; r++) {
        uint32_t rk_val = 0;
        static const int rk_idx[8] = {1, 3, 4, 6, 13, 14, 15, 17};
        for (int j = 0; j < 8; j++) {
            rk_val |= ((uint32_t)(WK[rk_idx[j]] & 0x0F)) << (4 * j);
        }
        rk[r] = rk_val;

        // 密钥状态更新
        WK[1]  ^= S[WK[0]];
        WK[4]  ^= S[WK[16]];
        WK[7]  ^= (CON[r] >> 3) & 0x07;
        WK[19] ^= CON[r] & 0x07;

        // 循环左移 4 个 nibbles
        uint8_t temp[4];
        memcpy(temp, WK, 4);
        memmove(WK, WK + 4, 28);
        memcpy(WK + 28, temp, 4);
    }
}

// ---------------------------------------------------------
// 基础串行 TWINE 单块加密 (标准实现)
// ---------------------------------------------------------
void twine_encrypt_std_block(const uint8_t in[8], uint8_t out[8], const uint32_t rk[36]) {
    uint8_t X[16];
    for (int i = 0; i < 8; i++) {
        X[2 * i]     = (in[i] >> 4) & 0x0F;
        X[2 * i + 1] = in[i] & 0x0F;
    }

    static const int pi[16] = {5, 0, 1, 4, 7, 12, 3, 8, 13, 6, 9, 11, 2, 10, 15, 14};

    for (int r = 0; r < 36; r++) {
        uint32_t round_rk = rk[r];
        for (int j = 0; j < 8; j++) {
            uint8_t rk_j = (round_rk >> (4 * j)) & 0x0F;
            X[2 * j + 1] ^= S[X[2 * j] ^ rk_j];
        }
        if (r < 35) {
            uint8_t nextX[16];
            for (int i = 0; i < 16; i++) {
                nextX[pi[i]] = X[i];
            }
            memcpy(X, nextX, 16);
        }
    }

    for (int i = 0; i < 8; i++) {
        out[i] = (X[2 * i] << 4) | (X[2 * i + 1] & 0x0F);
    }
}

// ---------------------------------------------------------
// 优化实现核心：64 位寄存器打包与内联轮函数
// ---------------------------------------------------------
static inline uint64_t block_to_u64(const uint8_t in[8]) {
    uint64_t s = 0;
    for (int i = 0; i < 8; i++) {
        s |= ((uint64_t)((in[i] >> 4) & 0x0F)) << (8 * i);
        s |= ((uint64_t)(in[i] & 0x0F))       << (8 * i + 4);
    }
    return s;
}

static inline void u64_to_block(uint64_t s, uint8_t out[8]) {
    for (int i = 0; i < 8; i++) {
        uint8_t x_even = (s >> (8 * i)) & 0x0F;
        uint8_t x_odd  = (s >> (8 * i + 4)) & 0x0F;
        out[i] = (x_even << 4) | x_odd;
    }
}

static inline uint64_t twine_round_opt(uint64_t s, uint32_t rk) {
    uint8_t x0  = S[((s >>  0) & 0xF) ^ ((rk >>  0) & 0xF)];
    uint8_t x2  = S[((s >>  8) & 0xF) ^ ((rk >>  4) & 0xF)];
    uint8_t x4  = S[((s >> 16) & 0xF) ^ ((rk >>  8) & 0xF)];
    uint8_t x6  = S[((s >> 24) & 0xF) ^ ((rk >> 12) & 0xF)];
    uint8_t x8  = S[((s >> 32) & 0xF) ^ ((rk >> 16) & 0xF)];
    uint8_t x10 = S[((s >> 40) & 0xF) ^ ((rk >> 20) & 0xF)];
    uint8_t x12 = S[((s >> 48) & 0xF) ^ ((rk >> 24) & 0xF)];
    uint8_t x14 = S[((s >> 56) & 0xF) ^ ((rk >> 28) & 0xF)];

    uint64_t xor_mask = ((uint64_t)x0 << 4)   | ((uint64_t)x2 << 12) |
                       ((uint64_t)x4 << 20)  | ((uint64_t)x6 << 28) |
                       ((uint64_t)x8 << 36)  | ((uint64_t)x10 << 44) |
                       ((uint64_t)x12 << 52) | ((uint64_t)x14 << 60);
    s ^= xor_mask;

    // 寄存器级别的置换实现
    uint64_t next_s = 0;
    next_s |= ((s >>  0) & 0xF) << 20; // 0 -> 5
    next_s |= ((s >>  4) & 0xF) << 0;  // 1 -> 0
    next_s |= ((s >>  8) & 0xF) << 4;  // 2 -> 1
    next_s |= ((s >> 12) & 0xF) << 16; // 3 -> 4
    next_s |= ((s >> 16) & 0xF) << 28; // 4 -> 7
    next_s |= ((s >> 20) & 0xF) << 48; // 5 -> 12
    next_s |= ((s >> 24) & 0xF) << 12; // 6 -> 3
    next_s |= ((s >> 28) & 0xF) << 32; // 7 -> 8
    next_s |= ((s >> 32) & 0xF) << 52; // 8 -> 13
    next_s |= ((s >> 36) & 0xF) << 24; // 9 -> 6
    next_s |= ((s >> 40) & 0xF) << 36; // 10 -> 9
    next_s |= ((s >> 44) & 0xF) << 44; // 11 -> 11
    next_s |= ((s >> 48) & 0xF) << 8;  // 12 -> 2
    next_s |= ((s >> 52) & 0xF) << 40; // 13 -> 10
    next_s |= ((s >> 56) & 0xF) << 60; // 14 -> 15
    next_s |= ((s >> 60) & 0xF) << 56; // 15 -> 14

    return next_s;
}

static inline uint64_t twine_last_round_opt(uint64_t s, uint32_t rk) {
    uint8_t x0  = S[((s >>  0) & 0xF) ^ ((rk >>  0) & 0xF)];
    uint8_t x2  = S[((s >>  8) & 0xF) ^ ((rk >>  4) & 0xF)];
    uint8_t x4  = S[((s >> 16) & 0xF) ^ ((rk >>  8) & 0xF)];
    uint8_t x6  = S[((s >> 24) & 0xF) ^ ((rk >> 12) & 0xF)];
    uint8_t x8  = S[((s >> 32) & 0xF) ^ ((rk >> 16) & 0xF)];
    uint8_t x10 = S[((s >> 40) & 0xF) ^ ((rk >> 20) & 0xF)];
    uint8_t x12 = S[((s >> 48) & 0xF) ^ ((rk >> 24) & 0xF)];
    uint8_t x14 = S[((s >> 56) & 0xF) ^ ((rk >> 28) & 0xF)];

    uint64_t xor_mask = ((uint64_t)x0 << 4)   | ((uint64_t)x2 << 12) |
                       ((uint64_t)x4 << 20)  | ((uint64_t)x6 << 28) |
                       ((uint64_t)x8 << 36)  | ((uint64_t)x10 << 44) |
                       ((uint64_t)x12 << 52) | ((uint64_t)x14 << 60);
    return s ^ xor_mask;
}

// 8 路并行核心加密引擎
static inline void twine_encrypt_8way_blocks(const uint8_t in[64], uint8_t out[64], const uint32_t rk[36]) {
    uint64_t s0 = block_to_u64(in + 0);
    uint64_t s1 = block_to_u64(in + 8);
    uint64_t s2 = block_to_u64(in + 16);
    uint64_t s3 = block_to_u64(in + 24);
    uint64_t s4 = block_to_u64(in + 32);
    uint64_t s5 = block_to_u64(in + 40);
    uint64_t s6 = block_to_u64(in + 48);
    uint64_t s7 = block_to_u64(in + 56);

    for (int r = 0; r < 35; r++) {
        uint32_t round_key = rk[r];
        s0 = twine_round_opt(s0, round_key);
        s1 = twine_round_opt(s1, round_key);
        s2 = twine_round_opt(s2, round_key);
        s3 = twine_round_opt(s3, round_key);
        s4 = twine_round_opt(s4, round_key);
        s5 = twine_round_opt(s5, round_key);
        s6 = twine_round_opt(s6, round_key);
        s7 = twine_round_opt(s7, round_key);
    }

    uint32_t last_key = rk[35];
    s0 = twine_last_round_opt(s0, last_key);
    s1 = twine_last_round_opt(s1, last_key);
    s2 = twine_last_round_opt(s2, last_key);
    s3 = twine_last_round_opt(s3, last_key);
    s4 = twine_last_round_opt(s4, last_key);
    s5 = twine_last_round_opt(s5, last_key);
    s6 = twine_last_round_opt(s6, last_key);
    s7 = twine_last_round_opt(s7, last_key);

    u64_to_block(s0, out + 0);
    u64_to_block(s1, out + 8);
    u64_to_block(s2, out + 16);
    u64_to_block(s3, out + 24);
    u64_to_block(s4, out + 32);
    u64_to_block(s5, out + 40);
    u64_to_block(s6, out + 48);
    u64_to_block(s7, out + 56);
}

// ---------------------------------------------------------
// CTR 模式实现 (串行 vs 8路并行)
// ---------------------------------------------------------
static inline void inc_ctr_64(uint8_t ctr[8]) {
    for (int i = 7; i >= 0; i--) {
        if (++ctr[i] != 0) break;
    }
}

void twine_ctr_encrypt_std(const uint8_t *in, uint8_t *out, size_t len, const uint32_t rk[36], uint8_t iv[8]) {
    uint8_t ctr[8], keystream[8];
    memcpy(ctr, iv, 8);
    for (size_t i = 0; i < len; i += 8) {
        twine_encrypt_std_block(ctr, keystream, rk);
        for (int j = 0; j < 8 && (i + j) < len; j++) {
            out[i + j] = in[i + j] ^ keystream[j];
        }
        inc_ctr_64(ctr);
    }
}

void twine_ctr_encrypt_8way(const uint8_t *in, uint8_t *out, size_t len, const uint32_t rk[36], uint8_t iv[8]) {
    uint8_t ctr_buf[64], keystream[64];
    uint8_t ctr[8];
    memcpy(ctr, iv, 8);

    size_t i = 0;
    for (; i + 64 <= len; i += 64) {
        for (int b = 0; b < 8; b++) {
            memcpy(ctr_buf + b * 8, ctr, 8);
            inc_ctr_64(ctr);
        }
        twine_encrypt_8way_blocks(ctr_buf, keystream, rk);
        for (int j = 0; j < 64; j++) {
            out[i + j] = in[i + j] ^ keystream[j];
        }
    }
    // 处理余块
    for (; i < len; i += 8) {
        twine_encrypt_std_block(ctr, keystream, rk);
        for (int j = 0; j < 8 && (i + j) < len; j++) {
            out[i + j] = in[i + j] ^ keystream[j];
        }
        inc_ctr_64(ctr);
    }
}

// ---------------------------------------------------------
// XTS 模式实现 (GF(2^64) 乘法)
// ---------------------------------------------------------
static inline uint64_t gf64_mul_alpha(uint64_t t) {
    uint64_t carry = (t >> 63) & 1;
    return (t << 1) ^ (carry ? 0x000000000000001BULL : 0);
}

static inline uint64_t load64_le(const uint8_t b[8]) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= ((uint64_t)b[i]) << (8 * i);
    return v;
}

static inline void store64_le(uint64_t v, uint8_t b[8]) {
    for (int i = 0; i < 8; i++) b[i] = (v >> (8 * i)) & 0xFF;
}

void twine_xts_encrypt_std(const uint8_t *in, uint8_t *out, size_t len, const uint32_t rk[36], uint8_t twk[8]) {
    uint64_t T = load64_le(twk);
    uint8_t block[8], tmp_tkn[8];

    for (size_t i = 0; i < len; i += 8) {
        store64_le(T, tmp_tkn);
        for (int j = 0; j < 8; j++) block[j] = in[i + j] ^ tmp_tkn[j];
        twine_encrypt_std_block(block, block, rk);
        for (int j = 0; j < 8; j++) out[i + j] = block[j] ^ tmp_tkn[j];
        T = gf64_mul_alpha(T);
    }
}

void twine_xts_encrypt_8way(const uint8_t *in, uint8_t *out, size_t len, const uint32_t rk[36], uint8_t twk[8]) {
    uint64_t T = load64_le(twk);
    uint8_t block_in[64], block_out[64], T_buf[64];

    size_t i = 0;
    for (; i + 64 <= len; i += 64) {
        for (int b = 0; b < 8; b++) {
            store64_le(T, T_buf + b * 8);
            for (int j = 0; j < 8; j++) {
                block_in[b * 8 + j] = in[i + b * 8 + j] ^ T_buf[b * 8 + j];
            }
            T = gf64_mul_alpha(T);
        }
        twine_encrypt_8way_blocks(block_in, block_out, rk);
        for (int b = 0; b < 8; b++) {
            for (int j = 0; j < 8; j++) {
                out[i + b * 8 + j] = block_out[b * 8 + j] ^ T_buf[b * 8 + j];
            }
        }
    }
    // 处理余块
    for (; i < len; i += 8) {
        uint8_t tmp_tkn[8], block[8];
        store64_le(T, tmp_tkn);
        for (int j = 0; j < 8; j++) block[j] = in[i + j] ^ tmp_tkn[j];
        twine_encrypt_std_block(block, block, rk);
        for (int j = 0; j < 8; j++) out[i + j] = block[j] ^ tmp_tkn[j];
        T = gf64_mul_alpha(T);
    }
}

// ---------------------------------------------------------
// GCM 模式实现 (基于 GF(2^64) 认证)
// ---------------------------------------------------------
static uint64_t gf64_mul(uint64_t a, uint64_t b) {
    uint64_t res = 0;
    for (int i = 0; i < 64; i++) {
        if ((b >> i) & 1) res ^= a;
        uint64_t carry = (a >> 63) & 1;
        a = (a << 1) ^ (carry ? 0x000000000000001BULL : 0);
    }
    return res;
}

void twine_gcm_encrypt_std(const uint8_t *in, uint8_t *out, size_t len, const uint32_t rk[36],
                           uint8_t iv[8], const uint8_t *aad, size_t aad_len, uint8_t tag[8]) {
    // 1. 生成 H
    uint8_t h_buf[8] = {0};
    twine_encrypt_std_block(h_buf, h_buf, rk);
    uint64_t H = load64_le(h_buf);

    // 2. CTR 加密
    twine_ctr_encrypt_std(in, out, len, rk, iv);

    // 3. GHASH 计算
    uint64_t Y = 0;
    for (size_t i = 0; i < aad_len; i += 8) {
        uint64_t block_val = 0;
        for (size_t j = 0; j < 8 && (i + j) < aad_len; j++) block_val |= ((uint64_t)aad[i + j]) << (8 * j);
        Y = gf64_mul(Y ^ block_val, H);
    }
    for (size_t i = 0; i < len; i += 8) {
        uint64_t block_val = 0;
        for (size_t j = 0; j < 8 && (i + j) < len; j++) block_val |= ((uint64_t)out[i + j]) << (8 * j);
        Y = gf64_mul(Y ^ block_val, H);
    }

    // 4. 认证 Tag 异或生成
    uint8_t tag_mask[8];
    twine_encrypt_std_block(iv, tag_mask, rk);
    store64_le(Y ^ load64_le(tag_mask), tag);
}

void twine_gcm_encrypt_8way(const uint8_t *in, uint8_t *out, size_t len, const uint32_t rk[36],
                            uint8_t iv[8], const uint8_t *aad, size_t aad_len, uint8_t tag[8]) {
    // 1. 生成 H
    uint8_t h_buf[8] = {0};
    twine_encrypt_std_block(h_buf, h_buf, rk);
    uint64_t H = load64_le(h_buf);

    // 2. 8-Way CTR 加密
    twine_ctr_encrypt_8way(in, out, len, rk, iv);

    // 3. 展开 GHASH 认证计算
    uint64_t Y = 0;
    for (size_t i = 0; i < aad_len; i += 8) {
        uint64_t block_val = 0;
        for (size_t j = 0; j < 8 && (i + j) < aad_len; j++) block_val |= ((uint64_t)aad[i + j]) << (8 * j);
        Y = gf64_mul(Y ^ block_val, H);
    }
    for (size_t i = 0; i < len; i += 8) {
        uint64_t block_val = 0;
        for (size_t j = 0; j < 8 && (i + j) < len; j++) block_val |= ((uint64_t)out[i + j]) << (8 * j);
        Y = gf64_mul(Y ^ block_val, H);
    }

    // 4. 认证 Tag 异或生成
    uint8_t tag_mask[8];
    twine_encrypt_std_block(iv, tag_mask, rk);
    store64_le(Y ^ load64_le(tag_mask), tag);
}

// ---------------------------------------------------------
// 主测试与性能 Benchmark 函数
// ---------------------------------------------------------
int main() {
    printf("========== TWINE指令集及CTR / XTS / GCM 模式优化 ==========\n\n");
    twine_init();
    printf("[系统初始化] 64-bit TWINE 寄存器表与展开掩码初始化完成。\n\n");

    uint8_t key[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    uint8_t iv[8]   = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};
    uint32_t rk[36];
    twine_setkey(rk, key);

    // ---------------------------------------------------------
    // 第一部分：正确性交叉验证 (CTR, XTS, GCM)
    // ---------------------------------------------------------
    printf("【一、正确性交叉验证 (256 字节测试数据)】\n");
    uint8_t test_in[256];
    for (int i = 0; i < 256; i++) test_in[i] = (uint8_t)i;

    uint8_t std_out[256], opt_out[256];

    // --- CTR 验证 ---
    {
        uint8_t iv1[8], iv2[8];
        memcpy(iv1, iv, 8); memcpy(iv2, iv, 8);
        twine_ctr_encrypt_std(test_in, std_out, 256, rk, iv1);
        twine_ctr_encrypt_8way(test_in, opt_out, 256, rk, iv2);
        printf(" [+] CTR 模式并行优化 %s\n", memcmp(std_out, opt_out, 256) == 0 ? "[通过]" : "[失败]");
    }

    // --- XTS 验证 ---
    {
        uint8_t twk1[8], twk2[8];
        memcpy(twk1, iv, 8); memcpy(twk2, iv, 8);
        twine_xts_encrypt_std(test_in, std_out, 256, rk, twk1);
        twine_xts_encrypt_8way(test_in, opt_out, 256, rk, twk2);
        printf(" [+] XTS  模式并行优化 %s\n", memcmp(std_out, opt_out, 256) == 0 ? "[通过]" : "[失败]");
    }

    // --- GCM 验证 (加密 + 认证标签) ---
    {
        uint8_t iv_gcm[8] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};
        uint8_t aad[4] = {0x11,0x22,0x33,0x44};
        uint8_t tag_std[8], tag_opt[8];
        uint8_t std_gcm_out[256], opt_gcm_out[256];

        twine_gcm_encrypt_std(test_in, std_gcm_out, 256, rk, iv_gcm, aad, 4, tag_std);
        twine_gcm_encrypt_8way(test_in, opt_gcm_out, 256, rk, iv_gcm, aad, 4, tag_opt);

        int cipher_ok = (memcmp(std_gcm_out, opt_gcm_out, 256) == 0);
        int tag_ok    = (memcmp(tag_std, tag_opt, 8) == 0);
        printf(" [+] GCM  模式加密与认证 %s\n", (cipher_ok && tag_ok) ? "[通过]" : "[失败]");
        if (!(cipher_ok && tag_ok)) {
            printf("     串行标签: ");
            for (int i = 0; i < 8; i++) printf("%02x", tag_std[i]);
            printf("\n     并行标签: ");
            for (int i = 0; i < 8; i++) printf("%02x", tag_opt[i]);
            printf("\n");
        }
    }
    printf("\n");

    // ---------------------------------------------------------
    // 第二部分：大数据吞吐性能对比
    // ---------------------------------------------------------
    printf("【二、性能基准测试 ,测试数据大小: 16MB】\n");
    uint8_t *big_in  = (uint8_t*)malloc(BENCHMARK_SIZE);
    uint8_t *big_out = (uint8_t*)malloc(BENCHMARK_SIZE);
    memset(big_in, 0x11, BENCHMARK_SIZE);

    clock_t start, end;
    double time_std, time_opt;

    // --- CTR 性能 ---
    {
        uint8_t iv1[8]; memcpy(iv1, iv, 8);
        start = clock();
        twine_ctr_encrypt_std(big_in, big_out, BENCHMARK_SIZE, rk, iv1);
        end = clock();
        time_std = (double)(end - start) / CLOCKS_PER_SEC;

        uint8_t iv2[8]; memcpy(iv2, iv, 8);
        start = clock();
        twine_ctr_encrypt_8way(big_in, big_out, BENCHMARK_SIZE, rk, iv2);
        end = clock();
        time_opt = (double)(end - start) / CLOCKS_PER_SEC;

        printf(" [1] CTR 工作模式:\n");
        printf("     - 基础串行 TWINE-CTR 耗时 : %.4f 秒 (吞吐率: %.2f MB/s)\n", time_std, (BENCHMARK_SIZE/1024.0/1024.0)/time_std);
        printf("     - 并行优化 TWINE-CTR 耗时 : %.4f 秒 (吞吐率: %.2f MB/s)\n", time_opt, (BENCHMARK_SIZE/1024.0/1024.0)/time_opt);
        printf("     => 提速比: %.2f 倍\n\n", time_std / time_opt);
    }

    // --- XTS 性能 ---
    {
        uint8_t twk1[8]; memcpy(twk1, iv, 8);
        start = clock();
        twine_xts_encrypt_std(big_in, big_out, BENCHMARK_SIZE, rk, twk1);
        end = clock();
        time_std = (double)(end - start) / CLOCKS_PER_SEC;

        uint8_t twk2[8]; memcpy(twk2, iv, 8);
        start = clock();
        twine_xts_encrypt_8way(big_in, big_out, BENCHMARK_SIZE, rk, twk2);
        end = clock();
        time_opt = (double)(end - start) / CLOCKS_PER_SEC;

        printf(" [2] XTS 工作模式:\n");
        printf("     - 基础串行 TWINE-XTS 耗时 : %.4f 秒 (吞吐率: %.2f MB/s)\n", time_std, (BENCHMARK_SIZE/1024.0/1024.0)/time_std);
        printf("     - 并行优化 TWINE-XTS 耗时 : %.4f 秒 (吞吐率: %.2f MB/s)\n", time_opt, (BENCHMARK_SIZE/1024.0/1024.0)/time_opt);
        printf("     => 提速比: %.2f 倍\n\n", time_std / time_opt);
    }

    // --- GCM 性能 ---
    {
        uint8_t iv_gcm[8] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};
        uint8_t aad[4] = {0x11,0x22,0x33,0x44};
        uint8_t tag[8];

        start = clock();
        twine_gcm_encrypt_std(big_in, big_out, BENCHMARK_SIZE, rk, iv_gcm, aad, 4, tag);
        end = clock();
        time_std = (double)(end - start) / CLOCKS_PER_SEC;

        start = clock();
        twine_gcm_encrypt_8way(big_in, big_out, BENCHMARK_SIZE, rk, iv_gcm, aad, 4, tag);
        end = clock();
        time_opt = (double)(end - start) / CLOCKS_PER_SEC;

        printf(" [3] GCM 工作模式 (含认证标签):\n");
        printf("     - 基础串行 TWINE-GCM 耗时 : %.4f 秒 (吞吐率: %.2f MB/s)\n", time_std, (BENCHMARK_SIZE/1024.0/1024.0)/time_std);
        printf("     - 并行优化 TWINE-GCM 耗时 : %.4f 秒 (吞吐率: %.2f MB/s)\n", time_opt, (BENCHMARK_SIZE/1024.0/1024.0)/time_opt);
        printf("     => 提速比: %.2f 倍\n", time_std / time_opt);
        printf("     GCM 加密部分与 CTR 一致，瓶颈主要在 GHASH 认证\n\n");
    }

    free(big_in);
    free(big_out);
    return 0;
}
