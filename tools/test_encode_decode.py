#!/usr/bin/env python3
"""测试 Encode=1 编解码往返"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lingma_full_auth import encode_to_string, decode_string, ALPHA, STD_B64, _custom_b64_encode, _custom_b64_decode

# 测试1: 基本编解码往返
test = "test123\nabc\nxyz"
encoded = encode_to_string(test.encode())
decoded = decode_string(encoded)
print(f"测试1: 基本往返")
print(f"  原文: {test!r}")
print(f"  编码: {encoded!r} ({len(encoded)} chars)")
print(f"  解码: {decoded!r}")
print(f"  匹配: {decoded.decode() == test}")
print()

# 测试2: 使用实际回调中的 auth 值
auth_val = ')n#SQEjMpfpHKruEzhDHa$n.l@VfjMN(l@TflRzIVRBkoEj@z^VR#kjMz%VR&QlR_Yjf'
print(f"测试2: 解码实际 auth 值")
print(f"  auth ({len(auth_val)} chars): {auth_val!r}")
try:
    decoded = decode_string(auth_val)
    print(f"  解码后 ({len(decoded)} bytes): {decoded.hex()[:60]}...")
    print(f"  文本: {decoded.decode('utf-8', errors='replace')}")
except Exception as e:
    print(f"  错误: {e}")

# 测试3: 验证 token 解码
token_val = "dn@LCnmHDQ,&n%j^&^VMakV^z.jM_^J%@()soEKwGSta,xLzpMjlJTg@paiaaRNZptpwQIVwCrmFF@SE"
print(f"\n测试3: 解码实际 token 值")
print(f"  token ({len(token_val)} chars)")
try:
    decoded = decode_string(token_val)
    print(f"  解码后 ({len(decoded)} bytes): {decoded.hex()[:60]}...")
    print(f"  文本: {decoded.decode('utf-8', errors='replace')}")
except Exception as e:
    print(f"  错误: {e}")

# 测试4: decode_string 分步调试
print(f"\n测试4: decode_string 分步调试 auth")
body = auth_val
dollar_start = body.find('$')
print(f"  dollar at index: {dollar_start}")
if dollar_start >= 0:
    pad = 0
    pos = dollar_start
    while pos < len(body) and body[pos] == '$':
        pad += 1
        pos += 1
    print(f"  pad count: {pad}")
    rev = body[:dollar_start] + body[dollar_start + pad:]
    E = len(rev)
    print(f"  rev length: {E}")
    BS = (E + 2) // 3  # math.ceil(E/3)
    lb = E - 2 * BS
    b2 = rev[:lb]
    b1 = rev[lb:lb + BS]
    b0 = rev[lb + BS:]
    print(f"  BS={BS}, lb={lb}")
    print(f"  b0({len(b0)}): {b0[:30]}...")
    print(f"  b1({len(b1)}): {b1[:30]}...")
    print(f"  b2({len(b2)}): {b2[:30]}...")
    restored = b0 + b1 + b2
    print(f"  restored({len(restored)}): {restored}")

    # 检查所有字符是否在字母表中
    bad_chars = [c for c in restored if c not in ALPHA]
    if bad_chars:
        print(f"  BAD: 不在字母表中的字符: {bad_chars!r}")
    else:
        print(f"  OK: 所有字符都在字母表中")
        # 手动 base64 解码
        converted = ''.join(STD_B64[ALPHA.index(c)] for c in restored)
        import base64
        pad2 = (4 - len(converted) % 4) % 4
        decoded_manual = base64.b64decode(converted + '=' * pad2)
        print(f"  手动解码: {decoded_manual.hex()}")
        print(f"  文本: {decoded_manual.decode('utf-8', errors='replace')}")
