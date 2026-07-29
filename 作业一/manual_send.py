from bit import PrivateKeyTestnet
import requests

wif = 'cUtjujEzZ7n4AAPGqpfNK93ozHhP3X4mdfeTX5XWbBLmpPcYpZCs'        
key = PrivateKeyTestnet(wif)
to_address = 'mvP7ogEXJGs7paKQu5pfRcegWampataPgx'   


tx_hex = key.create_transaction([(to_address, 5000, 'satoshi')], fee=200)
print("交易十六进制:", tx_hex)

# 广播到 blockstream.info
url = 'https://blockstream.info/testnet/api/tx'
response = requests.post(url, data=tx_hex, headers={'Content-Type': 'text/plain>

if response.status_code == 200:
    txid = response.text.strip()
    print("广播成功！交易ID:", txid)
else:
    print("广播失败，状态码:", response.status_code)
    print("错误信息:", response.text)
