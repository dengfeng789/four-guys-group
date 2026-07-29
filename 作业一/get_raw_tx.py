import requests

txid = '02d79bfb36b4a10db70bb181bf823afdcae7b6bd7049a3c79397b069d3ace6d0'
url = f'https://blockstream.info/testnet/api/tx/{txid}/hex'
response = requests.get(url)
raw_hex = response.text.strip()
print("原始交易十六进制:")
print(raw_hex)
with open('raw_tx.hex', 'w') as f:
    f.write(raw_hex)
print("已保存到 raw_tx.hex")
