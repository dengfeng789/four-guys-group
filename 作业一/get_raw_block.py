import requests

# 获取最新区块哈希
tip_url = 'https://blockstream.info/testnet/api/blocks/tip/hash'
block_hash = requests.get(tip_url).text.strip()
print("最新区块哈希:", block_hash)

# 获取该区块的原始十六进制数据
raw_url = f'https://blockstream.info/testnet/api/block/{block_hash}/raw'
block_hex = requests.get(raw_url).text.strip()

# 保存到文件
with open('raw_block.hex', 'w') as f:
    f.write(block_hex)

print(f"区块原始数据已保存到 raw_block.hex")
print(f"区块大小: {len(block_hex)//2} 字节")
