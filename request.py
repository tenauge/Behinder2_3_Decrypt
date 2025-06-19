#!/usr/bin/python
# -*- coding:utf-8 -*-
# author:nothing

import base64
from Crypto.Cipher import AES  
import binascii
import json  

def aes_decode(data, key):
    try:
        aes = AES.new(str.encode(key), AES.MODE_ECB)  # 初始化加密器
        decrypted_text = aes.decrypt(data)  # 解密
        decrypted_text = decrypted_text[:-(decrypted_text[-1])]  
    except Exception as e:
        print("解密失败：", e)
        return b''
    return decrypted_text

def main():
    key = '469bba0a564235df'  # AES 密钥
    input_data = input("请输入请求体内容：\n").strip()
    try:
        data = base64.b64decode(input_data)
    except Exception as e:
        print("Base64 解码失败：", e)
        return

    decrypted = aes_decode(data, key)
    if decrypted:
        print("解密成功，写入 request.class 文件")
        with open('request.class', 'wb') as f:
            f.write(decrypted)
    else:
        print("未成功解密，未写入文件")

if __name__ == "__main__":
    main()
