#!/usr/bin/env python3
"""获取最佳解码的完整输出"""
import sys, base64
sys.path.insert(0, "D:/Project/lingma/tools")
from lingma_full_auth import _custom_b64_decode

auth = ')n#SQEjMpfpHKruEzhDHa$n.l@VfjMN(l@TflRzIVRBkoEj@z^VR#kjMz%VR&QlR_Yjf'
token = 'dn@LCnmHDQ,&n%j^&^VMakV^z.jM_^J%@()soEKwGSta,xLzpMjlJTg@paiaaRNZptpwQIVwCrmFF@SE'

def decode_best(data, desc):
    body = data
    dollar = body.find('$')
    if dollar >= 0:
        rev = body[:dollar] + body[dollar+1:]
    else:
        rev = body
    n = len(rev)
    v24 = (n + n // 3) // 2
    v7 = n - v24
    b2 = rev[:v7]
    b01 = rev[v7:]

    print(f"\n=== {desc} ===")
    print(f"rev({n}): {rev}")

    # b1+b2+b0 with split=2 (best for auth based on search)
    for split in range(0, min(5, len(b01)+1)):
        b0 = b01[:split]
        b1 = b01[split:]
        for oname, combo in [("b1+b2+b0", b1 + b2 + b0)]:
            try:
                decoded = _custom_b64_decode(combo)
                text = decoded.decode('utf-8', errors='replace')
                print(f"\n[{oname}] split={split}: ({len(decoded)}B)")
                print(f"  hex: {decoded.hex()}")
                print(f"  txt: {text}")
                # Find all ASCII sequences
                ascii_parts = []
                current = b''
                for byte in decoded:
                    if 32 <= byte < 127:
                        current += bytes([byte])
                    else:
                        if current:
                            ascii_parts.append(current.decode())
                            current = b''
                if current:
                    ascii_parts.append(current.decode())
                for p in ascii_parts:
                    print(f"  ASCII: {p!r}")
                # Show \n positions
                nl_pos = [i for i, b in enumerate(decoded) if b == 0x0a]
                print(f"  \\n at positions: {nl_pos}")
            except Exception as e:
                pass

decode_best(auth, "auth")
decode_best(token, "token")
