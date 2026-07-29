OP_CODES = {
    0x00: 'OP_0',
    0x76: 'OP_DUP',
    0xa9: 'OP_HASH160',
    0x88: 'OP_EQUALVERIFY',
    0xac: 'OP_CHECKSIG',
    0x6a: 'OP_RETURN',
}

def parse_script(script_hex):
    data = bytes.fromhex(script_hex)
    i = 0
    result = []
    while i < len(data):
        op = data[i]
        if op in OP_CODES:
            result.append(OP_CODES[op])
            i += 1
        elif 0x01 <= op <= 0x4b:
            length = op
            data_push = data[i+1:i+1+length].hex()
            result.append(f"PUSH {length} bytes: {data_push}")
            i += 1 + length
        else:
            result.append(f"UNKNOWN(0x{op:02x})")
            i += 1
    return result

if __name__ == '__main__':
    script = input("请输入脚本十六进制: ")
    ops = parse_script(script)
    for op in ops:
        print(op)
