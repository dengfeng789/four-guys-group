import sys
from binascii import unhexlify

def read_varint(data, offset):
    first = data[offset]
    if first < 0xFD:
        return first, 1
    elif first == 0xFD:
        return int.from_bytes(data[offset+1:offset+3], 'little'), 3
    elif first == 0xFE:
        return int.from_bytes(data[offset+1:offset+5], 'little'), 5
    elif first == 0xFF:
        return int.from_bytes(data[offset+1:offset+9], 'little'), 9
    else:
        raise ValueError("Invalid VarInt")

def byte_to_bin(b):
    """将单个字节转为8位二进制字符串"""
    return bin(b)[2:].zfill(8)

def print_bytes_hex_and_bin(data, start, length, label):
    """打印指定范围的每个字节的十六进制和二进制"""
    print(f"  {label} (长度 {length} 字节):")
    for i in range(length):
        b = data[start+i]
        print(f"    [{i:2d}] 0x{b:02x}  {byte_to_bin(b)}")
    print()

def parse_transaction(raw_hex):
    data = bytes.fromhex(raw_hex)
    offset = 0
    print("交易原始数据解析")
    print(f"总字节数: {len(data)}\n")

    # 1. 版本号
    version = int.from_bytes(data[offset:offset+4], 'little')
    print(f"1. 版本号 (Version): {version} (0x{version:08x})")
    print_bytes_hex_and_bin(data, offset, 4, "版本号字节")
    offset += 4

    # 2. 输入计数 
    in_count, v_size = read_varint(data, offset)
    print(f"2. 输入计数 (Input Count): {in_count}")
    print_bytes_hex_and_bin(data, offset, v_size, "输入计数 VarInt 字节")
    offset += v_size

    # 3. 解析每个输入
    for i in range(in_count):
        print(f"\n--- 输入 #{i+1} ---")
        # 前序交易哈希 
        prev_hash_bytes = data[offset:offset+32]
        prev_hash_hex = prev_hash_bytes[::-1].hex()  
        print(f"  前序交易哈希 (Previous Tx Hash): {prev_hash_hex}")
        print_bytes_hex_and_bin(data, offset, 32, f"输入#{i+1} 前序哈希字节")
        offset += 32

        # 输出索引 
        prev_index = int.from_bytes(data[offset:offset+4], 'little')
        print(f"  前序输出索引 (Previous Index): {prev_index}")
        print_bytes_hex_and_bin(data, offset, 4, f"输入#{i+1} 索引字节")
        offset += 4

        # 解锁脚本长度 
        script_len, s_len = read_varint(data, offset)
        print(f"  解锁脚本长度 (ScriptSig Length): {script_len}")
        print_bytes_hex_and_bin(data, offset, s_len, f"输入#{i+1} 脚本长度VarInt")
        offset += s_len

        # 解锁脚本 
        script_sig = data[offset:offset+script_len]
        print(f"  解锁脚本 (ScriptSig): {script_sig.hex()}")
        if script_len > 0:
            print_bytes_hex_and_bin(data, offset, script_len, f"输入#{i+1} 解锁脚本字节")
        else:
            print("  (空脚本)")
        offset += script_len

        # 序列号
        seq = int.from_bytes(data[offset:offset+4], 'little')
        print(f"  序列号 (Sequence): {seq}")
        print_bytes_hex_and_bin(data, offset, 4, f"输入#{i+1} 序列号字节")
        offset += 4

    # 4. 输出计数 
    out_count, v_size = read_varint(data, offset)
    print(f"\n3. 输出计数 (Output Count): {out_count}")
    print_bytes_hex_and_bin(data, offset, v_size, "输出计数 VarInt 字节")
    offset += v_size

    # 5. 解析每个输出
    for i in range(out_count):
        print(f"\n--- 输出 #{i+1} ---")
        # 金额
        value_sat = int.from_bytes(data[offset:offset+8], 'little')
        print(f"  金额 (Value): {value_sat} 聪 ({value_sat/1e8:.8f} BTC)")
        print_bytes_hex_and_bin(data, offset, 8, f"输出#{i+1} 金额字节")
        offset += 8

        # 锁定脚本长度 
        script_len, s_len = read_varint(data, offset)
        print(f"  锁定脚本长度 (ScriptPubKey Length): {script_len}")
        print_bytes_hex_and_bin(data, offset, s_len, f"输出#{i+1} 脚本长度VarInt")
        offset += s_len
        # 锁定脚本 
        script_pubkey = data[offset:offset+script_len]
        print(f"  锁定脚本 (ScriptPubKey): {script_pubkey.hex()}")
        if script_len > 0:
            print_bytes_hex_and_bin(data, offset, script_len, f"输出#{i+1} 锁定脚本字节")
        else:
            print("  (空脚本)")
        offset += script_len

    # 6. 锁定时间 
    locktime = int.from_bytes(data[offset:offset+4], 'little')
    print(f"\n4. 锁定时间 (LockTime): {locktime}")
    print_bytes_hex_and_bin(data, offset, 4, "锁定时间字节")
    offset += 4

    if offset == len(data):
        print("\n解析完成，所有字节已读尽！")
    else:
        print(f"\n剩余 {len(data)-offset} 个字节未解析")

if __name__ == "__main__":
    # 从文件 raw_tx.hex 读取交易十六进制
    with open('raw_tx.hex', 'r') as f:
        hex_str = f.read().strip()
    parse_transaction(hex_str)
