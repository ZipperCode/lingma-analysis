#!/usr/bin/env python3
"""根据 IDA decodeString 公式 v24=(len+len/3)//2 修正解码"""
import sys, math, base64
sys.path.insert(0, "D:/Project/lingma/tools")
from lingma_full_auth import ALPHA, STD_B64, _custom_b64_decode

auth = ')n#SQEjMpfpHKruEzhDHa$n.l@VfjMN(l@TflRzIVRBkoEj@z^VR#kjMz%VR&QlR_Yjf'
#token
token = 'dn@LCnmHDQ,&n%j^&^VMakV^z.jM_^J%@()soEKwGSta,xLzpMjlJTg@paiaaRNZptpwQIVwCrmFF@SE'

def ida_decode_string(encoded_str):
    """模仿 IDA decodeString 逻辑"""
    body = encoded_str
    # 找 padding symbol (padChar = 0x24 = '$' 或别的)
    # 在 IDA 中 padChar 在结构体里，这里尝试几种
    for pad_char in ['$']:
        dollar = body.find(pad_char)
        if dollar >= 0:
            break

    if dollar < 0:
        raw = body
    else:
        # 数有多少个 pad_char
        pad_count = 0
        pos = dollar
        while pos < len(body) and body[pos] == pad_char:
            pad_count += 1
            pos += 1
        raw = body[:dollar] + body[dollar + pad_count:]

    n = len(raw)
    # v24 = (n + n/3) // 2  ← IDA 公式
    v24 = (n + n // 3) // 2
    # v7 = n - v24
    v7 = n - v24

    print(f"  n={n}, v24={v24}, v7={v7}")

    # 在 IDA decodeString 中，memmove 操作将 raw 的块重新排列
    # v24 = b0+b1 的长度, v7 = b2 的长度
    # 输入: b2 + b0 + b1 (根据 encodeToString 的输出顺序)
    # 输出: b0 + b1 + b2 (还原为原始顺序)

    b2_len = v7
    b01_len = v24

    b2 = raw[:b2_len]   # 第一部分: b2 (原始第三块)
    b01 = raw[b2_len:]  # 第二部分: b0 + b1 (原始第一+第二块)

    # 然后从 b01 中分出 b0 和 b1
    # v8 = (n + n/3)//2 (跟 v24 相同)
    v8 = (n + n // 3) // 2

    # 从 IDA 的 memmove 看: 先复制 b01 的前 b1_len 个字节到 b2 之后
    # 再复制 b01 的剩余部分
    # 观察代码: v10 = v8, r7 = v10, 第二个 memmove 从 array[v7 & ...] 复制
    # 这个逻辑很复杂. 试试 b0 和 b1 各占 v24/2

    # 简单尝试: b01 分成 b1(后半) + b0(前半) 或 b0(前半) + b1(后半)
    b1_len = v8  # 试试 b0 和 b1 各占 v24//2
    b0_len = v24 - b1_len

    print(f"  b2={b2_len}, b01={b01_len}, b0_len={b0_len}, b1_len={b1_len}")

    for order_name, restored in [
        ("b0+b1+b2(原始)", b01 + b2),
        ("b1+b0+b2",     b01[:b1_len] + b2 + b01[b1_len:] if b1_len <= len(b01) else b01 + b2),
        ("b2+b0+b1",     b2 + b01),
        ("b2+b1+b0(默认逆)", b2 + b01[::-1]),
    ]:
        try:
            decoded = _custom_b64_decode(restored)
            text = decoded.decode('utf-8', errors='replace')
            print(f"  [{order_name}] ({len(restored)}c) {text[:80]}")
        except Exception as e:
            print(f"  [{order_name}] ERROR: {e}")

print("=== Auth 解码 ===")
ida_decode_string(auth)

print("\n=== Token 解码 ===")
ida_decode_string(token)
