import hashlib
import time
import sys

def double_sha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

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

def parse_block(block_hex):
    data = bytes.fromhex(block_hex)
    print(f"区块总字节数: {len(data)}\n")
    
    offset = 0
    # ---- 区块头 ----
    header = {}
    header['version'] = int.from_bytes(data[offset:offset+4], 'little')
    offset += 4
    header['prev_hash'] = data[offset:offset+32][::-1].hex()
    offset += 32
    header['merkle_root'] = data[offset:offset+32][::-1].hex()
    offset += 32
    header['timestamp'] = int.from_bytes(data[offset:offset+4], 'little')
    offset += 4
    header['bits'] = int.from_bytes(data[offset:offset+4], 'little')
    offset += 4
    header['nonce'] = int.from_bytes(data[offset:offset+4], 'little')
    offset += 4
    
    print("=== 区块头 (80字节) ===")
    for k, v in header.items():
        if k == 'timestamp':
            print(f"  {k}: {v} ({time.ctime(v)})")
        else:
            print(f"  {k}: {v}")
    
    # 计算区块哈希
    block_hash = double_sha256(data[:80])[::-1].hex()
    print(f"\n计算的区块哈希: {block_hash}")
    
    # PoW 验证
    exponent = (header['bits'] >> 24) & 0xFF
    coefficient = header['bits'] & 0xFFFFFF
    target = coefficient * (256 ** (exponent - 3))
    hash_int = int.from_bytes(double_sha256(data[:80]), 'little')
    print(f"目标难度值 (Target): {target}")
    print(f"哈希整数: {hash_int}")
    if hash_int <= target:
        print("PoW 验证通过！")
    else:
        print("PoW 验证失败")
    
    # ---- 交易列表 ----
    tx_count, v_size = read_varint(data, offset)
    print(f"\n交易数量: {tx_count}")
    offset += v_size
    
    print("\n=== 交易列表 ===")
    for i in range(tx_count):
        print(f"交易 #{i+1}: 偏移量 {offset}")
        offset += 1 
    

if __name__ == "__main__":
    with open('block_hex.txt', 'r') as f:
        hex_str = f.read().strip()
    parse_block(hex_str)

