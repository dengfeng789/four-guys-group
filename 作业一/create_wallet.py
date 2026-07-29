from bit import PrivateKeyTestnet

key = PrivateKeyTestnet()
print("测试网地址:", key.address)
print("私钥 WIF:", key.to_wif())
