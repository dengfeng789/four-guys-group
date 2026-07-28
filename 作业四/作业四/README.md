# SM3 软件实现与 SIMD/GPR 混合优化

本工程提供同一套流式 SM3 API，并按文件拆分为：

- 普通标量实现：`src/sm3_ref.c`
- x86 AVX2 离线扩展：`src/sm3_x86_avx2_offline.c`
- x86 AVX2 在线扩展：`src/sm3_x86_avx2_online.c`
- ARM64 NEON 离线扩展：`src/sm3_arm64_neon_offline.c`
- ARM64 NEON 在线扩展：`src/sm3_arm64_neon_online.c`
- 正确性测试：`tests/test_sm3.c`
- 效率测试：`bench/bench_sm3.c`

“离线扩展”先生成完整 `W[68]`，再压缩；“在线扩展”只保存 20 个字，
让 SIMD 消息扩展与使用通用寄存器保存 `A..H` 的四轮展开压缩交错执行。
两者计算的是完全相同的 SM3。由于单消息的 `W[j]` 存在递推依赖，
SIMD 每组并行生成前三个字，依赖本组新结果的第四个字由标量表达式补齐。

## x86_64 直接编译和运行

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
./build/test_sm3
./build/bench_sm3
```

也可只验证或测试某一后端：

```bash
./build/test_sm3 --backend avx2-offline
./build/test_sm3 --backend avx2-online
./build/bench_sm3 --backend reference
```

程序会在运行时检测 AVX2，当前 CPU 不支持时会自动使用普通标量实现。
为了减少调度噪声，可用 `taskset -c 0 ./build/bench_sm3` 固定到一个 CPU
核心。

## ARM64 编译

在 ARM64 Linux 主机上直接使用上面的构建命令，CMake 会自动选择 NEON
文件（AArch64 基线包含 Advanced SIMD）。在安装了交叉编译器的 x86 主机：

```bash
cmake -S . -B build-arm64 -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/aarch64-linux-gnu.cmake \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build-arm64
```

交叉编译生成的测试程序需要复制到真实 ARM64 机器执行。模拟器可以验证
正确性，但模拟器时间不能作为 ARM64 硬件性能结论。

## 测试范围

正确性测试包含国标常用向量（空串、`abc`、64 字节 `abcd`）、一百万个
`a`、0–259 字节填充边界、非对齐输入、分块更新，以及 10000 组相对普通
实现的随机差分测试。效率测试统一处理约 128 MiB 数据，输出 MiB/s、ns/B，
x86 上另输出 TSC ticks/B。
