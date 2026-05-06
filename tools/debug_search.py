#!/usr/bin/env python3
"""搜索所有解码结果中的已知模式"""
import sys, math, base64
sys.path.insert(0, "D:/Project/lingma/tools")
from lingma_full_auth import _custom_b64_decode

auth = ')n#SQEjMpfpHKruEzhDHa$n.l@VfjMN(l@TflRzIVRBkoEj@z^VR#kjMz%VR&QlR_Yjf'
token = 'dn@LCnmHDQ,&n%j^&^VMakV^z.jM_^J%@()soEKwGSta,xLzpMjlJTg@paiaaRNZptpwQIVwCrmFF@SE'

# 要搜索的模式
patterns = {
    'uid': b'5930676910898027',
    'email': b'@blny.de',
    'uid_part': b'910898027',
    'pt': b'pt-',
    'rt': b'rt-',
    'expire': b'1783257395',
}

def decode_and_search(data, desc):
    """解码并搜索所有模式"""
    # 去掉 $
    body = data
    dollar = body.find('$')
    if dollar >= 0:
        rev = body[:dollar] + body[dollar+1:]
    else:
        rev = body

    n = len(rev)
    v24 = (n + n // 3) // 2
    v7 = n - v24

    # 尝试在 rev 上分割, b2 = rev[:v7], b01 = rev[v7:]
    b2 = rev[:v7]
    b01 = rev[v7:]

    results = []

    # 尝试 b0 和 b1 的不同分割点
    for split in range(0, len(b01)+1):
        b0 = b01[:split]
        b1 = b01[split:]

        for order_name, combined in [
            ("b0+b1+b2", b0 + b1 + b2),
            ("b1+b0+b2", b1 + b0 + b2),
            ("b0+b2+b1", b0 + b2 + b1),
            ("b1+b2+b0", b1 + b2 + b0),
            ("b2+b0+b1", b2 + b0 + b1),
            ("b2+b1+b0", b2 + b1 + b0),
        ]:
            try:
                decoded = _custom_b64_decode(combined)
                # 搜索模式
                for pname, pattern in patterns.items():
                    if pattern in decoded:
                        results.append((pname, order_name, split, decoded))
            except:
                pass

    return results

print("=== Auth 中搜索模式 ===")
auth_results = decode_and_search(auth, "auth")
seen = set()
for pname, order, split, decoded in auth_results:
    key = (pname, order, split)
    if key not in seen:
        seen.add(key)
        text = decoded.decode('utf-8', 'replace')
        idx = text.find('@blny.de')
        print(f"  [{order}] split={split}: found '{pname}' -> ...{text[max(0,idx-30):idx+30] if idx>=0 else text[:80]}...")

print("\n=== Token 中搜索模式 ===")
token_results = decode_and_search(token, "token")
seen = set()
for pname, order, split, decoded in token_results:
    key = (pname, order, split)
    if key not in seen:
        seen.add(key)
        text = decoded.decode('utf-8', 'replace')
        if 'pt-' in text:
            print(f"  [{order}] split={split}: pt- found: {text[:80]}")
        if 'rt-' in text:
            print(f"  [{order}] split={split}: rt- found: ...{text[-60:]}")
        if '1783257395' in text:
            print(f"  [{order}] split={split}: expire found: {text[-30:]}")
