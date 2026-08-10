#!/usr/bin/env python3
"""Demo: how Gree pack encryption works — self-contained, no real capture needed.

Run with: python3 gree_crypto_demo.py
Requires: pycryptodome
"""
import base64, json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"

print("=" * 60)
print("STEP 1: 构造一条格力设备回包 (scan响应)")
print("=" * 60)
inner_plain = {"t": "dev", "cid": "", "bc": "<device-broadcast-id>", "brand": "",
               "catalog": "", "mac": "<device-mac>", "mid": "11002",
               "model": "", "name": "<device-mac>", "lock": 0,
               "series": "", "vender": "", "ver": ""}
print("内层明文JSON (要藏起来的内容):")
print(json.dumps(inner_plain, indent=2, ensure_ascii=False))
print()

print("=" * 60)
print("STEP 2: PKCS7 padding -> AES-128-ECB 加密 -> Base64")
print("=" * 60)
cipher = AES.new(GENERIC_KEY, AES.MODE_ECB)
padded = pad(json.dumps(inner_plain).encode(), AES.block_size)
print(f"padding后: {len(padded)} 字节 = {len(padded)//16} 个AES分组")
encrypted = cipher.encrypt(padded)
pack_b64 = base64.b64encode(encrypted).decode()
print(f"Base64密文 (就是pack字段): {pack_b64[:60]}...")
print()

print("=" * 60)
print("STEP 3: 外层明文JSON (格力实际在网络上发的样子)")
print("=" * 60)
outer = {"t": "pack", "i": 1, "uid": 0, "cid": "", "tcid": "", "pack": pack_b64}
print(json.dumps(outer, indent=2))
print()
print("注意：外层 t/i/uid/cid/tcid 全是明文，只有 pack 是密文。")
print("       scan 响应时 cid/tcid 为空；bind/status/cmd 请求里 tcid 填设备 mac。")
print()

print("=" * 60)
print("STEP 4: 接收方解密 —— Base64解码 -> AES解密 -> 去padding")
print("=" * 60)
cipher_bytes = base64.b64decode(pack_b64)
plain_padded = AES.new(GENERIC_KEY, AES.MODE_ECB).decrypt(cipher_bytes)
print(f"解密后(含padding, 注意末尾的padding字节): {plain_padded[-16:]!r}")
plain = unpad(plain_padded, AES.block_size)
print(f"去padding后明文: {plain.decode()}")
print()

print("=" * 60)
print("反向: 发控制指令 = 同样的流程反过来")
print("=" * 60)
inner = {"opt": ["Pow"], "p": [0], "t": "cmd"}  # 关机指令
print(f"1. 明文JSON: {json.dumps(inner)}")
padded = pad(json.dumps(inner).encode(), AES.block_size)
print(f"2. PKCS7补到16倍数: {padded!r}")
enc_cipher = AES.new(GENERIC_KEY, AES.MODE_ECB)
encrypted = enc_cipher.encrypt(padded)
print(f"3. AES-ECB加密: {len(encrypted)}字节")
b64 = base64.b64encode(encrypted).decode()
print(f"4. Base64: {b64[:40]}...")
outer = {"cid": "app", "i": 0, "t": "pack", "uid": 0, "tcid": "<device-mac>", "pack": b64}
print(f"5. 包进外层明文JSON发回UDP 7000: {json.dumps(outer)[:80]}...")
print()
print("注意：真实控制指令用【bind 拿到的设备专属key】加密，不是通用key！")
print("       通用key只能用于 scan 和 bind；bind 成功后换设备key（见 gree_ac.py）。")
