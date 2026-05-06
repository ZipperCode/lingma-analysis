#!/usr/bin/env python3
"""测试不同的块反转方式"""
import sys, math, base64
sys.path.insert(0, "D:/Project/lingma/tools")
from lingma_full_auth import ALPHA, STD_B64, _custom_b64_decode, decode_string

auth = ')n#SQEjMpfpHKruEzhDHa$n.l@VfjMN(l@TflRzIVRBkoEj@z^VR#kjMz%VR&QlR_Yjf'

# 准备 rev (去掉 $)
body = auth
dollar_start = body.find('$')
pad = 0
pos = dollar_start
while pos < len(body) and body[pos] == '$':
    pad += 1
    pos += 1
rev = body[:dollar_start] + body[dollar_start + pad:]
E = len(rev)

print(f"rev ({E} chars): {rev}")

# 测试不同的块排列
def try_block_order(rev, E, BS, order_name, b0_slice, b1_slice, b2_slice):
    """尝试不同的块排列顺序"""
    b0 = rev[b0_slice[0]:b0_slice[1]]
    b1 = rev[b1_slice[0]:b1_slice[1]]
    b2 = rev[b2_slice[0]:b2_slice[1]]

    # 尝试三种组合
    for combo_name, restored in [
        ("b0+b1+b2(原始)", b0 + b1 + b2),
        ("b0+b2+b1",     b0 + b2 + b1),
        ("b1+b0+b2",     b1 + b0 + b2),
        ("b1+b2+b0",     b1 + b2 + b0),
        ("b2+b0+b1",     b2 + b0 + b1),
        ("b2+b1+b0",     b2 + b1 + b0),
    ]:
        try:
            decoded = _custom_b64_decode(restored)
            text = decoded.decode('utf-8', errors='replace')
        except Exception as ex:
            text = f"[ERROR: {ex}]"
        print(f"  {order_name}/{combo_name}: ({len(restored)}c) {text[:80]}")

# 测试1: BS=23 (ceil), 当前公式
BS = math.ceil(E / 3)
lb = E - 2 * BS  # length of b2 in original
print(f"\n=== BS={BS} (ceil), lb={lb} ===")
print(f"rev[:{lb}] = b2, rev[{lb}:{lb+BS}] = b1, rev[{lb+BS}:] = b0")
b0 = rev[lb+BS:]
b1 = rev[lb:lb+BS]
b2 = rev[:lb]
for name, restored in [
    ("b0+b1+b2(默认)", b0 + b1 + b2),
    ("b1+b0+b2",     b1 + b0 + b2),
    ("b2+b0+b1",     b2 + b0 + b1),
]:
    decoded = _custom_b64_decode(restored)
    text = decoded.decode('utf-8', errors='replace')
    print(f"  {name}: {text[:80]}")

# 测试2: BS=22 (floor)
BS2 = E // 3
lb2 = E - 2 * BS2
print(f"\n=== BS={BS2} (floor), lb={lb2} ===")
b0f = rev[lb2+BS2:]
b1f = rev[lb2:lb2+BS2]
b2f = rev[:lb2]
for name, restored in [
    ("b0+b1+b2(默认)", b0f + b1f + b2f),
    ("b1+b0+b2",     b1f + b0f + b2f),
    ("b2+b0+b1",     b2f + b0f + b1f),
]:
    decoded = _custom_b64_decode(restored)
    text = decoded.decode('utf-8', errors='replace')
    print(f"  {name}: {text[:80]}")

# 测试3: 尝试 IDA 公式 v22 = (v21 + v21/3) / 2
# 这对应的是原编码的总长度 v21, v22 是 b0+b1 长度
v21 = E  # 67
v22 = (v21 + v21 // 3) // 2  # (67 + 22) // 2 = 44
# v22 = b0 + b1, v21 - v22 = b2
b2_len = v21 - v22
print(f"\n=== IDA 公式: v22={v22}, b2_len={b2_len} ===")
print(f"  rev[:{b2_len}] = b2? rev[{b2_len}:] = b0+b1?")

# 如果 IDA 排列是 b2 + (b0 + b1)，即 last block + first+middle
# 或 b2 + (b1 + b0)
for split in [v22, b2_len]:
    b2_part = rev[:split]
    b01_part = rev[split:]
    print(f"\n  split={split}: b2={len(b2_part)}, b0+b1={len(b01_part)}")
    # Try splitting b01_part into two
    for inner_bs in [BS, BS2, split//2, len(b01_part)//2]:
        if inner_bs <= 0 or inner_bs >= len(b01_part):
            continue
        ib0 = b01_part[:inner_bs]
        ib1 = b01_part[inner_bs:]
        for combo in [
            (ib0 + ib1 + b2_part, "b0+b1+b2"),
            (ib1 + ib0 + b2_part, "b1+b0+b2"),
            (b2_part + ib0 + ib1, "b2+b0+b1"),
            (b2_part + ib1 + ib0, "b2+b1+b0(默认)"),
        ]:
            try:
                decoded = _custom_b64_decode(combo[0])
                text = decoded.decode('utf-8', errors='replace')
                if '5930' in text or text.strip():
                    print(f"    BS={inner_bs} {combo[1]}: {text[:100]}")
            except:
                pass
