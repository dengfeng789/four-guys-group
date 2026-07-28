#define _POSIX_C_SOURCE 200809L

#include "sm3.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(__x86_64__) || defined(_M_X64)
#include <x86intrin.h>
#endif

static uint64_t monotonic_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) +
           (uint64_t)ts.tv_nsec;
}

static uint64_t read_cycles(void)
{
#if defined(__x86_64__) || defined(_M_X64)
    unsigned int auxiliary;
    _mm_lfence();
    return __rdtscp(&auxiliary);
#else
    return 0;
#endif
}

static void run_case(sm3_backend backend, const uint8_t *message,
                     size_t length)
{
    const size_t target_bytes = 128U * 1024U * 1024U;
    size_t iterations = target_bytes / length;
    uint8_t digest[SM3_DIGEST_SIZE];
    volatile uint8_t checksum = 0;
    uint64_t start_ns, end_ns, start_cycles, end_cycles;
    double total_bytes, seconds;
    size_t i;

    if (iterations < 16)
        iterations = 16;
    for (i = 0; i < 32; ++i)
        sm3_digest_backend(backend, message, length, digest);

    start_cycles = read_cycles();
    start_ns = monotonic_ns();
    for (i = 0; i < iterations; ++i) {
        sm3_digest_backend(backend, message, length, digest);
        checksum = (uint8_t)(checksum * 33U) ^
                   digest[i & (SM3_DIGEST_SIZE - 1)];
    }
    end_ns = monotonic_ns();
    end_cycles = read_cycles();

    total_bytes = (double)length * (double)iterations;
    seconds = (double)(end_ns - start_ns) / 1.0e9;
    printf("%-15s %8zu B  %10.2f MiB/s  %7.3f ns/B",
           sm3_backend_name(backend), length,
           total_bytes / (1024.0 * 1024.0) / seconds,
           (double)(end_ns - start_ns) / total_bytes);
    if (end_cycles > start_cycles)
        printf("  %8.3f TSC-ticks/B",
               (double)(end_cycles - start_cycles) / total_bytes);
    printf("  [%02x]\n", checksum);
}

static int parse_backend(const char *name, sm3_backend *backend)
{
    sm3_backend candidate;
    for (candidate = SM3_BACKEND_REFERENCE;
         candidate < SM3_BACKEND_COUNT; ++candidate)
        if (strcmp(name, sm3_backend_name(candidate)) == 0) {
            *backend = candidate;
            return 1;
        }
    return 0;
}

int main(int argc, char **argv)
{
    static const size_t lengths[] = {64, 1024, 8192, 1024 * 1024};
    uint8_t *message = (uint8_t *)malloc(lengths[3]);
    sm3_backend first = SM3_BACKEND_REFERENCE;
    sm3_backend last = (sm3_backend)(SM3_BACKEND_COUNT - 1);
    sm3_backend backend;
    size_t i;

    if (argc == 3 && strcmp(argv[1], "--backend") == 0) {
        if (!parse_backend(argv[2], &first)) {
            fprintf(stderr, "unknown backend: %s\n", argv[2]);
            free(message);
            return EXIT_FAILURE;
        }
        last = first;
    } else if (argc != 1) {
        fprintf(stderr, "usage: %s [--backend NAME]\n", argv[0]);
        free(message);
        return EXIT_FAILURE;
    }
    if (message == NULL) {
        fputs("allocation failed\n", stderr);
        return EXIT_FAILURE;
    }
    for (i = 0; i < lengths[3]; ++i)
        message[i] = (uint8_t)(i * 131U + 17U);

    puts("backend             message       throughput       latency"
         "             cycles");
    for (backend = first; backend <= last; ++backend) {
        if (!sm3_backend_available(backend))
            continue;
        for (i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i)
            run_case(backend, message, lengths[i]);
    }
    free(message);
    return EXIT_SUCCESS;
}
