#!/usr/bin/env python3
import base64, sys, re
sys.path.insert(0, "D:/Project/lingma/tools")
from lingma_full_auth import decode_string, ALPHA, STD_B64

# 实际回调的 auth 和 token 值
auth = ')n#SQEjMpfpHKruEzhDHa$n.l@VfjMN(l@TflRzIVRBkoEj@z^VR#kjMz%VR&QlR_Yjf'
token = 'dn@LCnmHDQ,&n%j^&^VMakV^z.jM_^J%@()soEKwGSta,xLzpMjlJTg@paiaaRNZptpwQIVwCrmFF@SE'

print("=== auth 解码分析 ===")
decoded = decode_string(auth)
print(f"解码后 ({len(decoded)} bytes): {decoded.hex()}")
print(f"文本: {decoded.decode('utf-8', 'replace')}")

# 检查所有字节
for i in range(min(len(decoded), 50)):
    b = decoded[i]
    c = chr(b) if 32 <= b < 127 else '?'
    print(f"  [{i:3d}] {b:3d} 0x{b:02x} {c}")

print()
print("=== token 解码分析 ===")
tdecoded = decode_string(token)
print(f"解码后 ({len(tdecoded)} bytes): {tdecoded.hex()}")
print(f"文本: {tdecoded.decode('utf-8', 'replace')}")

for i in range(min(len(tdecoded), 60)):
    b = tdecoded[i]
    c = chr(b) if 32 <= b < 127 else '?'
    print(f"  [{i:3d}] {b:3d} 0x{b:02x} {c}")
