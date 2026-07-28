cmake_minimum_required(VERSION 3.16)
project(sm3_simd_gpr C)

option(SM3_BUILD_TESTS "Build correctness tests" ON)
option(SM3_BUILD_BENCH "Build performance benchmark" ON)
option(SM3_ENABLE_SANITIZERS "Enable AddressSanitizer and UBSan" OFF)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_library(sm3 STATIC
    src/sm3.c
    src/sm3_ref.c
)
target_include_directories(sm3 PUBLIC include PRIVATE src)
target_compile_options(sm3 PRIVATE -Wall -Wextra -Wpedantic)

string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" SM3_PROCESSOR)

if(SM3_PROCESSOR MATCHES "x86_64|amd64")
    target_sources(sm3 PRIVATE
        src/sm3_x86_avx2_offline.c
        src/sm3_x86_avx2_online.c
    )
    set_source_files_properties(
        src/sm3_x86_avx2_offline.c
        src/sm3_x86_avx2_online.c
        PROPERTIES COMPILE_OPTIONS "-mavx2"
    )
    target_compile_definitions(sm3 PRIVATE SM3_HAVE_X86_BACKENDS=1)
elseif(SM3_PROCESSOR MATCHES "aarch64|arm64")
    target_sources(sm3 PRIVATE
        src/sm3_arm64_neon_offline.c
        src/sm3_arm64_neon_online.c
    )
    target_compile_definitions(sm3 PRIVATE SM3_HAVE_ARM64_BACKENDS=1)
endif()

if(SM3_ENABLE_SANITIZERS AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(sm3 PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(sm3 PRIVATE -fsanitize=address,undefined)
endif()

if(SM3_BUILD_TESTS)
    enable_testing()
    add_executable(test_sm3 tests/test_sm3.c)
    target_link_libraries(test_sm3 PRIVATE sm3)
    target_compile_options(test_sm3 PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME sm3_correctness COMMAND test_sm3)
    if(SM3_ENABLE_SANITIZERS AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(test_sm3 PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(test_sm3 PRIVATE -fsanitize=address,undefined)
        # LeakSanitizer is not usable in some container/ptrace environments.
        set_tests_properties(sm3_correctness PROPERTIES
            ENVIRONMENT "ASAN_OPTIONS=detect_leaks=0")
    endif()
endif()

if(SM3_BUILD_BENCH)
    add_executable(bench_sm3 bench/bench_sm3.c)
    target_link_libraries(bench_sm3 PRIVATE sm3)
    target_compile_options(bench_sm3 PRIVATE -Wall -Wextra -Wpedantic)
endif()
