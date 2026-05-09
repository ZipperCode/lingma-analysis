"""
Lingma 签名算法验证 - 测试可能的 session key
"""
import hashlib
import hmac

# From capture 1
ts1 = "1777011796"
sig1 = "8d915d7d99452c143dc52ce040b9a355"

# From capture 2
ts2 = "1777016140"
sig2 = "0f6648253e94ed37c37f33bd3851c25c"

# machine_token.type and machine_id
machine_type = "ef46db379151d8e999"
machine_id = "35346164-3866-492d-a339-30773a32652d"

print("=== Testing with machine_token.type and common keys ===")

common_keys = [
    b"",
    b"cosy",
    b"lingma",
    b"alibaba",
    b"aliyun",
    b"qwen",
    b"dashscope",
    b"cosy-secret",
    b"lingma-secret",
    b"app-salt",
    b"tongyi",
    b"tongyi-lingma",
    machine_type.encode(),
    machine_id.encode(),
]

for key in common_keys:
    for ts, expected in [(ts1, sig1), (ts2, sig2)]:
        ts_bytes = ts.encode()
        # Try MD5(key + ts)
        sig = hashlib.md5(key + ts_bytes).hexdigest()
        if sig == expected:
            print(f"MATCH: MD5(key + ts) with key={key!r}")
        # Try MD5(ts + key)
        sig = hashlib.md5(ts_bytes + key).hexdigest()
        if sig == expected:
            print(f"MATCH: MD5(ts + key) with key={key!r}")
        # Try HMAC-MD5(key, ts)
        sig = hmac.new(key, ts_bytes, hashlib.md5).hexdigest()
        if sig == expected:
            print(f"MATCH: HMAC-MD5({key!r}, {ts!r})")

print("\nDone. If no match found, the session key is not a simple constant.")
print("It's likely derived from login credentials or generated at runtime.")
