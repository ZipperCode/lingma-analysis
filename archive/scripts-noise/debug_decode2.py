#!/usr/bin/env python3
"""调试 decode_string 的不同块分法"""
import sys, math, base64
sys.path.insert(0, "D:/Project/lingma/tools")
from lingma_full_auth import ALPHA, STD_B64, _custom_b64_decode

auth = ')n#SQEjMpfpHKruEzhDHa$n.l@VfjMN(l@TflRzIVRBkoEj@z^VR#kjMz%VR&QlR_Yjf'
token = 'dn@LCnmHDQ,&n%j^&^VMakV^z.jM_^J%@()soEKwGSta,xLzpMjlJTg@paiaaRNZptpwQIVwCrmFF@SE'

def try_decode(body, method_name, BS_func):
    """用不同的 BS 公式尝试解码"""
    dollar_start = body.find('$')
    if dollar_start < 0:
        rev = body
        pad_count = 0
    else:
        pad_count = 0
        pos = dollar_start
        while pos < len(body) and body[pos] == '$':
            pad_count += 1
            pos += 1
        rev = body[:dollar_start] + body[dollar_start + pad_count:]

    E = len(rev)
    BS = BS_func(E)
    lb = E - 2 * BS
    b2 = rev[:lb]
    b1 = rev[lb:lb + BS]
    b0 = rev[lb + BS:]
    try:
        decoded = _custom_b64_decode(b0 + b1 + b2)
    except Exception as e:
        decoded = f"ERROR: {e}".encode()

    if decoded and isinstance(decoded, bytes):
        try:
            text = decoded.decode('utf-8')
        except:
            text = decoded.decode('utf-8', errors='replace')
        print(f"  {method_name}: BS={BS}, lb={lb} → ({len(decoded)}B) {text[:80]}")
        return text
    return str(decoded)

print("=== Auth 解码尝试 ===")
try_decode(auth, "ceil(E/3)", lambda E: math.ceil(E / 3))
try_decode(auth, "floor(E/3)", lambda E: E // 3)
try_decode(auth, "E//4", lambda E: E // 4)
try_decode(auth, "ceil(E/4)", lambda E: math.ceil(E / 4))
try_decode(auth, "E//2", lambda E: E // 2)
try_decode(auth, "len//3_pad", lambda E: (len(auth) - 1) // 3)

# 尝试不使用块反转
print("\n=== 直接解码 (无块反转) ===")
dollar_start = auth.find('$')
pad = 0
pos = dollar_start
while pos < len(auth) and auth[pos] == '$':
    pad += 1
    pos += 1
no_dollar = auth[:dollar_start] + auth[dollar_start+pad:]
try:
    decoded = _custom_b64_decode(no_dollar)
    print(f"  直接解码 ({len(no_dollar)} chars): {decoded.hex()}")
    print(f"  文本: {decoded.decode('utf-8', 'replace')}")
except Exception as e:
    print(f"  错误: {e}")

# 标准 base64 解码
print("\n=== 标准 base64 解码 ===")
import base64
for test_name, test_val in [("auth", auth), ("token", token)]:
    # 移除 $ 填充
    clean = test_val.replace('$', '')
    try:
        decoded = base64.b64decode(clean + '=' * ((4 - len(clean) % 4) % 4))
        print(f"  {test_name} 标准b64: {decoded.hex()[:60]}...")
        print(f"    文本: {decoded.decode('utf-8', 'replace')[:60]}")
    except Exception as e:
        print(f"  {test_name} 标准b64错误: {e}")

    # 先转换自定义字母表→标准字母表，再标准b64
    try:
        converted = ''.join(STD_B64[ALPHA.index(c)] for c in test_val if c in ALPHA)
        decoded = base64.b64decode(converted + '=' * ((4 - len(converted) % 4) % 4))
        print(f"  {test_name} 直接转换b64: {decoded.hex()[:60]}...")
        print(f"    文本: {decoded.decode('utf-8', 'replace')[:60]}")
    except Exception as e:
        print(f"  {test_name} 转换b64错误: {e}")
