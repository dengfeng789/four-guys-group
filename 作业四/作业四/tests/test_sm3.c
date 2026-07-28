#include "sm3.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *name;
    const uint8_t *message;
    size_t length;
    const char *digest_hex;
} test_vector;

static int hex_to_bytes(const char *hex, uint8_t out[SM3_DIGEST_SIZE])
{
    size_t i;
    if (strlen(hex) != SM3_DIGEST_SIZE * 2)
        return 0;
    for (i = 0; i < SM3_DIGEST_SIZE; ++i) {
        unsigned int value;
        if (sscanf(hex + i * 2, "%2x", &value) != 1)
            return 0;
        out[i] = (uint8_t)value;
    }
    return 1;
}

static void print_hex(const uint8_t digest[SM3_DIGEST_SIZE])
{
    size_t i;
    for (i = 0; i < SM3_DIGEST_SIZE; ++i)
        fprintf(stderr, "%02x", digest[i]);
}

static int check_vector(sm3_backend backend, const test_vector *vector)
{
    uint8_t expected[SM3_DIGEST_SIZE], actual[SM3_DIGEST_SIZE];
    if (!hex_to_bytes(vector->digest_hex, expected) ||
        !sm3_digest_backend(backend, vector->message, vector->length, actual))
        return 0;
    if (memcmp(actual, expected, sizeof(actual)) != 0) {
        fprintf(stderr, "\n%s: vector \"%s\" failed\nexpected: ",
                sm3_backend_name(backend), vector->name);
        print_hex(expected);
        fputs("\nactual:   ", stderr);
        print_hex(actual);
        fputc('\n', stderr);
        return 0;
    }
    return 1;
}

static int check_incremental(sm3_backend backend,
                             const uint8_t *message, size_t length)
{
    uint8_t expected[SM3_DIGEST_SIZE], actual[SM3_DIGEST_SIZE];
    sm3_ctx ctx;
    size_t offset = 0, chunk = 1;

    sm3_digest_backend(SM3_BACKEND_REFERENCE, message, length, expected);
    if (!sm3_init_backend(&ctx, backend))
        return 0;
    sm3_update(&ctx, NULL, 0);
    while (offset < length) {
        size_t take = chunk < length - offset ? chunk : length - offset;
        sm3_update(&ctx, message + offset, take);
        offset += take;
        chunk = chunk * 5 % 97 + 1;
    }
    sm3_final(&ctx, actual);
    if (memcmp(actual, expected, sizeof(actual)) != 0) {
        fprintf(stderr, "\n%s: incremental input failed at length %zu\n",
                sm3_backend_name(backend), length);
        return 0;
    }
    return 1;
}

static uint32_t random_state = UINT32_C(0x6d2b79f5);

static uint32_t next_random(void)
{
    uint32_t x = random_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    random_state = x;
    return x;
}

static int check_differential(sm3_backend backend)
{
    uint8_t storage[4097];
    uint8_t *message = storage + 1; /* deliberately unaligned */
    uint8_t expected[SM3_DIGEST_SIZE], actual[SM3_DIGEST_SIZE];
    size_t iteration;

    for (iteration = 0; iteration < 10000; ++iteration) {
        size_t length = iteration < 260 ? iteration
                          : next_random() % (sizeof(storage) - 1);
        size_t i;
        for (i = 0; i < length; ++i)
            message[i] = (uint8_t)next_random();
        sm3_digest_backend(SM3_BACKEND_REFERENCE,
                           message, length, expected);
        sm3_digest_backend(backend, message, length, actual);
        if (memcmp(actual, expected, sizeof(actual)) != 0) {
            fprintf(stderr,
                    "\n%s: differential test failed at iteration %zu, "
                    "length %zu\n",
                    sm3_backend_name(backend), iteration, length);
            return 0;
        }
    }
    return 1;
}

static int check_million_a(sm3_backend backend)
{
    static const char expected_hex[] =
        "c8aaf89429554029e231941a2acc0ad6"
        "1ff2a5acd8fadd25847a3a732b3b02c3";
    uint8_t expected[SM3_DIGEST_SIZE], actual[SM3_DIGEST_SIZE];
    uint8_t chunk[1000];
    sm3_ctx ctx;
    size_t i;

    memset(chunk, 'a', sizeof(chunk));
    if (!hex_to_bytes(expected_hex, expected) ||
        !sm3_init_backend(&ctx, backend))
        return 0;
    for (i = 0; i < 1000; ++i)
        sm3_update(&ctx, chunk, sizeof(chunk));
    sm3_final(&ctx, actual);
    if (memcmp(actual, expected, sizeof(actual)) != 0) {
        fprintf(stderr, "\n%s: one-million-'a' vector failed\n",
                sm3_backend_name(backend));
        return 0;
    }
    return 1;
}

static int parse_backend(const char *name, sm3_backend *backend)
{
    sm3_backend candidate;
    for (candidate = SM3_BACKEND_REFERENCE;
         candidate < SM3_BACKEND_COUNT; ++candidate) {
        if (strcmp(name, sm3_backend_name(candidate)) == 0) {
            *backend = candidate;
            return 1;
        }
    }
    return 0;
}

static int test_backend(sm3_backend backend)
{
    static const uint8_t empty[] = "";
    static const uint8_t abc[] = "abc";
    static const uint8_t abcd_64[] =
        "abcdabcdabcdabcdabcdabcdabcdabcd"
        "abcdabcdabcdabcdabcdabcdabcdabcd";
    static const test_vector vectors[] = {
        {"empty", empty, 0,
         "1ab21d8355cfa17f8e61194831e81a8f"
         "22bec8c728fefb747ed035eb5082aa2b"},
        {"abc", abc, 3,
         "66c7f0f462eeedd9d1f2d46bdc10e4e"
         "24167c4875cf2f7a2297da02b8f4ba8e0"},
        {"abcd x 16", abcd_64, 64,
         "debe9ff92275b8a138604889c18e5a4d"
         "6fdb70e5387e5765293dcba39c0c5732"}
    };
    uint8_t boundary_message[260];
    size_t i;

    printf("testing %-15s ... ", sm3_backend_name(backend));
    fflush(stdout);
    for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); ++i)
        if (!check_vector(backend, &vectors[i]))
            return 0;
    for (i = 0; i < sizeof(boundary_message); ++i)
        boundary_message[i] = (uint8_t)i;
    for (i = 0; i < sizeof(boundary_message); ++i)
        if (!check_incremental(backend, boundary_message, i))
            return 0;
    if (!check_million_a(backend) || !check_differential(backend))
        return 0;
    puts("ok");
    return 1;
}

int main(int argc, char **argv)
{
    sm3_backend backend;
    int ok = 1;

    if (argc == 3 && strcmp(argv[1], "--backend") == 0) {
        if (!parse_backend(argv[2], &backend)) {
            fprintf(stderr, "unknown backend: %s\n", argv[2]);
            return EXIT_FAILURE;
        }
        if (!sm3_backend_available(backend)) {
            fprintf(stderr, "backend unavailable on this CPU: %s\n", argv[2]);
            return 77;
        }
        return test_backend(backend) ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    if (argc != 1) {
        fprintf(stderr, "usage: %s [--backend NAME]\n", argv[0]);
        return EXIT_FAILURE;
    }
    for (backend = SM3_BACKEND_REFERENCE;
         backend < SM3_BACKEND_COUNT; ++backend)
        if (sm3_backend_available(backend))
            ok &= test_backend(backend);
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}

