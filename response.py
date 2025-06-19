#!/usr/bin/python
# -*- coding:utf-8 -*-
# author: nothing

import base64
import binascii
import json
import re
import sys
from Crypto.Cipher import AES
from colorama import init, Fore, Style

# 初始化 colorama（支持 Windows 控制台）
init(autoreset=True)

def aes_decode(data, key):
    try:
        aes = AES.new(str.encode(key), AES.MODE_ECB)
        decrypted_text = aes.decrypt(data)
        decrypted_text = decrypted_text[:-(decrypted_text[-1])]  # 去除 PKCS#7 padding
        return decrypted_text
    except Exception as e:
        print(Fore.LIGHTRED_EX + "\nAES 解密失败（请检查连接密钥与复制内容）:", e)
        return None

def try_base64_decode(data):
    try:
        decoded = base64.b64decode(data)
        decoded_str = decoded.decode('utf-8')
        if any(ord(c) < 32 and c not in '\r\n\t' for c in decoded_str):
            return data
        return decoded_str
    except Exception:
        return data

def parse_chunked(data):
    i = 0
    decoded = b''
    while i < len(data):
        crlf = data.find(b'\r\n', i)
        if crlf == -1:
            break
        try:
            chunk_size = int(data[i:crlf].decode(), 16)
        except ValueError:
            break
        if chunk_size == 0:
            break
        start = crlf + 2
        end = start + chunk_size
        decoded += data[start:end]
        i = end + 2  # skip trailing \r\n
    return decoded

def extract_http_body(raw_data):
    split_pos = raw_data.find(b'\r\n\r\n')
    if split_pos == -1:
        return raw_data
    headers = raw_data[:split_pos].decode(errors='ignore')
    body = raw_data[split_pos + 4:]

    # 判断是否为 chunked 编码
    if re.search(r'Transfer-Encoding:\s*chunked', headers, re.IGNORECASE):
        return parse_chunked(body)

    # 如果有 Content-Length，尝试只读取指定长度
    match = re.search(r'Content-Length:\s*(\d+)', headers, re.IGNORECASE)
    if match:
        length = int(match.group(1))
        return body[:length]

    return body

def main():
    key = '469bba0a564235df'  # AES 密钥
    
    print(Fore.LIGHTGREEN_EX + "请输入十六进制的加密数据（支持 Wireshark 或 Burp 样式）：")
    hex_input = ''
    while True:
        line = input()  # 捕获单行输入
        if line.strip() == '':  # 如果输入为空行，结束循环
            break
        hex_input += line + '\n'  # 拼接输入内容（保留换行符）

    is_burp = ' ' in hex_input or '\n' not in hex_input
    try:
        if is_burp:
            hex_input = hex_input.replace(" ", "").replace("\n", "").lower()
        else:
            hex_input = hex_input.replace('\n', '')
            hex_input = ''.join(line[6:].split('#')[0].strip() for line in hex_input.splitlines() if len(line) > 6)
            hex_input = hex_input.replace(" ", "").lower()

        raw_data = binascii.a2b_hex(hex_input)
        body = extract_http_body(raw_data)
    except Exception as e:
        print(Fore.LIGHTRED_EX + "\n十六进制解析失败（请检查复制内容）:", e)
        return

    decrypted = aes_decode(body, key)
    if not decrypted:
        return

    print(Fore.LIGHTGREEN_EX + "\nAES 解密后的原始数据:")
    print(decrypted)

    try:
        parsed = json.loads(decrypted)
        print(Fore.LIGHTGREEN_EX + "\n将 AES 解密后的数据尝试 base64 解码的字段结果：")
        for k, v in parsed.items():
            if isinstance(v, str):
                decoded_value = try_base64_decode(v)
                print(Fore.LIGHTBLUE_EX + f"{k}:" + Style.RESET_ALL + f" {decoded_value}\n")
            else:
                print(Fore.LIGHTBLUE_EX + f"{k}:" + Style.RESET_ALL + f" {v}")
    except Exception as e:
        print(Fore.LIGHTRED_EX + "\nJSON 解析失败:", e)

if __name__ == "__main__":
    main()
