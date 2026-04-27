#!/usr/bin/env python3
"""
session_key_oracle.py

字典攻击 + 交叉验证工具：枚举候选 key × 候选公式，
用已知的 (Date, Signature) oracle 对筛选出正确的 session_key。

用法：
    python tools/session_key_oracle.py
    python tools/session_key_oracle.py --verify --key "YOUR_KEY"
"""

import argparse
import hashlib
import sys

# 已知 oracle：(date_string, expected_md5_hex)
# 来源：docs/lingma-analysis-endpoint-auth.md + docs/topics/encryption-analysis.md
ORACLES = [
    ("Fri, 24 Apr 2026 07:54:36 GMT", "e8b434d0a2596ca2ff99c60c4756a1ff"),
    ("1777011796", "8d915d7d99452c143dc52ce040b9a355"),
    ("1777016140", "0f6648253e94ed37c37f33bd3851c25c"),
]

# 候选 key（来源：appsalt_v7_stdout.txt 反推 + .rodata 字符串）
CANDIDATE_KEYS = [
    "&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe",
    "war, war never changes",
    "9f1dff714a390b20aeb19175ecc496e6",
    # 常见变体：尝试拼接前缀+hex
    "&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe9f1dff714a390b20aeb19175ecc496e6",
    "war, war never changes9f1dff714a390b20aeb19175ecc496e6",
]


def build_formulas():
    """构造候选公式族。"""
    formulas = []

    def fmt(name, fn):
        formulas.append((name, fn))

    # 基础拼接（RFC1123 / Unix）
    fmt("md5(date+key)",    lambda d, k: hashlib.md5((d + k).encode()).hexdigest())
    fmt("md5(key+date)",    lambda d, k: hashlib.md5((k + d).encode()).hexdigest())
    fmt("md5(date+\\n+key)", lambda d, k: hashlib.md5((d + "\n" + k).encode()).hexdigest())
    fmt("md5(key+\\n+date)", lambda d, k: hashlib.md5((k + "\n" + d).encode()).hexdigest())

    # 带固定分隔符的变体
    fmt("md5(date+|+key)",  lambda d, k: hashlib.md5((d + "|" + k).encode()).hexdigest())
    fmt("md5(key+|+date)",  lambda d, k: hashlib.md5((k + "|" + d).encode()).hexdigest())
    fmt("md5(date+:+key)",  lambda d, k: hashlib.md5((d + ":" + k).encode()).hexdigest())
    fmt("md5(key+:+date)",  lambda d, k: hashlib.md5((k + ":" + d).encode()).hexdigest())

    # 大写变体（某些系统可能用大写 MD5）
    fmt("MD5(date+key)",    lambda d, k: hashlib.md5((d + k).encode()).hexdigest().upper())
    fmt("MD5(key+date)",    lambda d, k: hashlib.md5((k + d).encode()).hexdigest().upper())

    return formulas


def try_key(key, formulas, oracles, verbose=False):
    """
    用给定 key 测试所有公式，返回命中数最高的结果。
    要求：同一 key + 同一公式 必须同时满足**全部** oracle。
    """
    best = None
    for name, fn in formulas:
        hits = 0
        fails = []
        for date_str, expected in oracles:
            actual = fn(date_str, key)
            if actual == expected:
                hits += 1
            else:
                fails.append((date_str, expected, actual))
        if hits == len(oracles):
            return (key, name, hits, None)
        if best is None or hits > best[2]:
            best = (key, name, hits, fails)
    return best


def main():
    parser = argparse.ArgumentParser(description="Session key dictionary attack via oracle verification")
    parser.add_argument("--verify", action="store_true", help="verify a specific key")
    parser.add_argument("--key", type=str, default="", help="key to verify")
    parser.add_argument("--candidates-file", type=str, default="", help="newline-separated candidate keys file")
    parser.add_argument("-v", "--verbose", action="store_true", help="print every attempt")
    args = parser.parse_args()

    formulas = build_formulas()
    oracles = ORACLES

    candidates = list(CANDIDATE_KEYS)
    if args.candidates_file:
        with open(args.candidates_file, "r", encoding="utf-8") as f:
            candidates += [line.strip() for line in f if line.strip()]

    if args.verify and args.key:
        result = try_key(args.key, formulas, oracles, verbose=args.verbose)
        key, name, hits, fails = result
        if hits == len(oracles):
            print(f"[PASS] key='{key}' formula={name} — ALL {hits}/{len(oracles)} oracles hit!")
            sys.exit(0)
        else:
            print(f"[FAIL] key='{key}' best_formula={name} hits={hits}/{len(oracles)}")
            if fails:
                for date_str, expected, actual in fails[:3]:
                    print(f"       mismatch: date={date_str} expected={expected} actual={actual}")
            sys.exit(1)

    print(f"[*] Loaded {len(candidates)} candidate(s), {len(formulas)} formula(s), {len(oracles)} oracle(s)")
    print("=" * 60)

    winners = []
    for key in candidates:
        result = try_key(key, formulas, oracles, verbose=args.verbose)
        if result is None:
            continue
        key, name, hits, fails = result
        if args.verbose or hits >= len(oracles) - 1:
            status = "WIN" if hits == len(oracles) else f"{hits}/{len(oracles)}"
            print(f"[{status}] key='{key}' formula={name}")
        if hits == len(oracles):
            winners.append((key, name))

    print("=" * 60)
    if winners:
        print(f"[RESULT] {len(winners)} winner(s) found:")
        for key, name in winners:
            print(f"  key='{key}'  formula={name}")
    else:
        print("[RESULT] No winner found. Consider expanding candidates or formulas.")
        print("Tip: check capture/ directory for additional (Date, Signature) pairs.")


if __name__ == "__main__":
    main()
