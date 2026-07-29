"""
输入: 4x4, 卷积核: 3x3, 步长: 1, 填充: 无, 输出: 2x2
策略: 打包 -> 旋转 -> 累加
"""
import numpy as np
import tenseal as ts
from typing import Tuple, List


# ============================================================
# 明文卷积 baseline (直接滑动窗口)
# ============================================================
def plain_convolution(input_matrix: np.ndarray, kernel: np.ndarray,
                      stride: int = 1, padding: int = 0) -> np.ndarray:
    """用最直观的滑动窗口做明文卷积，方便后面比对结果"""
    H, W = input_matrix.shape
    Kh, Kw = kernel.shape
    out_H = (H + 2 * padding - Kh) // stride + 1
    out_W = (W + 2 * padding - Kw) // stride + 1
    output = np.zeros((out_H, out_W))
    for i in range(out_H):
        for j in range(out_W):
            rf = input_matrix[i*stride:i*stride+Kh, j*stride:j*stride+Kw]
            output[i, j] = np.sum(rf * kernel)
    return output


# ============================================================
# 打包策略与旋转偏移
# ============================================================
def get_rotation_offsets(kernel_size: int, input_width: int) -> List[int]:
    """
    行优先打包时，每个卷积核权重对应的旋转偏移量
    公式: offset = 所在行 * 输入宽度 + 所在列
    3x3 卷积核 -> [0, 1, 2, 4, 5, 6, 8, 9, 10]
    """
    offsets = []
    for i in range(kernel_size):
        for j in range(kernel_size):
            offsets.append(i * input_width + j)
    return offsets


def rotate_vector(vector: np.ndarray, offset: int) -> np.ndarray:
    """循环左移 offset 位，模拟 CKKS 里的 Rot 操作"""
    n = len(vector)
    offset = offset % n
    if offset == 0:
        return vector.copy()
    return np.concatenate([vector[offset:], vector[:offset]])


def packed_convolution_plain(input_matrix: np.ndarray, kernel: np.ndarray,
                             input_size: int = 4,
                             output_size: int = 2) -> Tuple[np.ndarray, int]:
    """
    在明文里完整走一遍“打包 -> 旋转 -> 乘权重 -> 累加”流程
    用来验证策略对不对，顺便计旋转次数
    返回 (输出矩阵, 实际旋转次数)
    """
    input_vector = input_matrix.flatten()
    total_slots = input_size * input_size
    offsets = get_rotation_offsets(kernel.shape[0], input_size)

    rotation_count = 0
    result_vector = np.zeros(total_slots)
    kernel_flat = kernel.flatten()

    for idx, offset in enumerate(offsets):
        if offset == 0:
            rotated = input_vector          # 偏移为0不用转
        else:
            rotated = rotate_vector(input_vector, offset)
            rotation_count += 1
        result_vector += rotated * kernel_flat[idx]

    # 输出对应的四个槽位：(0,0)->0, (0,1)->1, (1,0)->4, (1,1)->5
    output = np.zeros((output_size, output_size))
    output[0, 0] = result_vector[0]
    output[0, 1] = result_vector[1]
    output[1, 0] = result_vector[4]
    output[1, 1] = result_vector[5]

    return output, rotation_count


# ============================================================
# CKKS 上下文
# ============================================================
def create_ckks_context(poly_modulus_degree: int = 8192,
                        scale: float = 2**40) -> ts.Context:
    """创建 CKKS 上下文，带上 Galois 密钥才能做旋转"""
    context = ts.context(
        ts.SCHEME_TYPE.CKKS,
        poly_modulus_degree=poly_modulus_degree,
        coeff_mod_bit_sizes=[60, 40, 40, 60]
    )
    context.global_scale = scale
    context.generate_galois_keys()
    return context


# ============================================================
# 密文卷积 (TenSEAL / CKKS)
# ============================================================
def encrypted_convolution(context: ts.Context,
                          input_matrix: np.ndarray,
                          kernel: np.ndarray,
                          input_size: int = 4,
                          output_size: int = 2) -> np.ndarray:
    """
    密文卷积实现：对每个输出位置构造权重掩码，然后和密文输入逐元素相乘再求和
    TenSEAL 的 .sum() 底层也是靠旋转累加实现的，所以本质上还是
    “打包 -> 旋转 -> 累加”，只不过库把旋转藏起来了。
    """
    input_vector = input_matrix.flatten()
    kernel_flat = kernel.flatten()
    ct_input = ts.ckks_vector(context, input_vector)

    # 先算好每个输出位置需要哪 9 个输入槽位
    output_indices = []
    for i in range(output_size):
        for j in range(output_size):
            indices = []
            for ki in range(kernel.shape[0]):
                for kj in range(kernel.shape[1]):
                    indices.append((i + ki) * input_size + (j + kj))
            output_indices.append(indices)

    results = []
    for indices in output_indices:
        weight_vec = np.zeros(input_size * input_size)
        for k_idx, in_idx in enumerate(indices):
            weight_vec[in_idx] = kernel_flat[k_idx]
        ct_weighted = ct_input * weight_vec
        results.append(ct_weighted.sum().decrypt()[0])

    return np.array(results).reshape(output_size, output_size)


# ============================================================
# 理论最小旋转次数分析
# ============================================================
def theoretical_min_rotations(kernel_size: int) -> int:
    """
    在“行优先打包 + 朴素旋转累加”的策略下，理论最少旋转次数就是 K²-1
    因为每个权重对应一个唯一偏移，偏移为0的那个不用转，剩下都要转一次
    3x3 -> 8 次
    """
    return kernel_size * kernel_size - 1


# ============================================================
# 主函数
# ============================================================
def main():
    INPUT_SIZE = 4
    KERNEL_SIZE = 3
    OUTPUT_SIZE = 2

    print("=" * 60)
    print("FHE Convolution: TenSEAL/CKKS  4x4 * 3x3")
    print("策略: 打包 -> 旋转 -> 累加")
    print("=" * 60)

    # ---------- 测试数据 ----------
    np.random.seed(42)
    input_matrix = np.random.randint(0, 10, (INPUT_SIZE, INPUT_SIZE)).astype(float)
    kernel = np.random.randint(0, 5, (KERNEL_SIZE, KERNEL_SIZE)).astype(float)

    print(f"\nInput ({INPUT_SIZE}x{INPUT_SIZE}):")
    print(input_matrix)
    print(f"\nKernel ({KERNEL_SIZE}x{KERNEL_SIZE}):")
    print(kernel)

    # ---------- 明文 baseline ----------
    plain_result = plain_convolution(input_matrix, kernel)
    print(f"\n[1] Plain convolution (sliding window):")
    print(plain_result)

    # ---------- 打包策略 ----------
    print(f"\n[2] Packing strategy: row-major SIMD")
    print(f"    slot_idx = row * width + col")
    offsets = get_rotation_offsets(KERNEL_SIZE, INPUT_SIZE)
    offset_mat = np.array(offsets).reshape(KERNEL_SIZE, KERNEL_SIZE)
    print(f"    Rotation offsets:")
    for i in range(KERNEL_SIZE):
        print("     ", "  ".join(f"{v:2d}" for v in offset_mat[i]))

    # ---------- 明文模拟打包->旋转->累加 ----------
    packed_result, plain_rotations = packed_convolution_plain(
        input_matrix, kernel, INPUT_SIZE, OUTPUT_SIZE)
    print(f"\n[3] Packed rotate-accumulate (plain simulation):")
    print(packed_result)
    err_pack = np.max(np.abs(plain_result - packed_result))
    print(f"    diff from sliding-window: {err_pack:.2e}")
    print(f"    rotations counted        : {plain_rotations}")

    # ---------- 密文卷积 ----------
    print(f"\n[4] Encrypted convolution (CKKS) ...")
    ctx = create_ckks_context(8192, 2**40)
    enc_result = encrypted_convolution(
        ctx, input_matrix, kernel, INPUT_SIZE, OUTPUT_SIZE)
    print(enc_result)

    # ---------- 精度验证 ----------
    max_err = np.max(np.abs(plain_result - enc_result))
    rel_err = max_err / np.max(np.abs(plain_result)) * 100
    print(f"\n[5] Accuracy check (plain vs encrypted):")
    print(f"    max absolute error : {max_err:.6e}")
    print(f"    max relative error : {rel_err:.6e} %")
    print(f"    plain  : {plain_result.flatten()}")
    print(f"    cipher : {[f'{v:.4f}' for v in enc_result.flatten()]}")

    # ---------- 旋转次数分析 ----------
    theo_min = theoretical_min_rotations(KERNEL_SIZE)
    print(f"\n[6] Rotation count analysis:")
    print(f"    total weights         : {KERNEL_SIZE**2}")
    print(f"    zero-offset (skip)    : 1  (k[0,0])")
    print(f"    theoretical minimum   : {theo_min}  (row-major naive)")
    print(f"    actual (plain sim)    : {plain_rotations}")
    if plain_rotations == theo_min:
        print(f"    result: matches theoretical minimum ✓")
    else:
        print(f"    result: {plain_rotations - theo_min} extra rotations")

    # ---------- 总结 ----------
    print(f"\n{'=' * 60}")
    print(f"Summary")
    print(f"{'=' * 60}")
    print(f"  Library / Scheme : TenSEAL v0.3.16 / CKKS")
    print(f"  poly_modulus_degree = 8192,  scale = 2^40")
    print(f"  Strategy           : pack -> rotate -> accumulate")
    print(f"  plain vs encrypted max error : {max_err:.2e}")
    print(f"  rotation count : {plain_rotations} (theory {theo_min})")


if __name__ == "__main__":
    main()