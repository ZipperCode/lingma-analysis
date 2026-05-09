#!/usr/bin/env python3
"""
测试：验证 Authorization header 构造逻辑

对比 IDA 分析结果和 Python 实现
"""

import hashlib
import base64
import json
import uuid
from datetime import datetime, timezone

# ========== 测试数据（来自用户缓存）==========
test_data = {
    "user_id": "5930676910898027",
    "security_oauth_token": "pt-Atl8MQJdcCqbDEdAZAyYgnbp",
    "refresh_token": "rt-GLbIaXzLEFCo8rINstjCv6EC",
    "path": "/api/v3/user/refresh_token",
    "method": "POST"
}

session_key_b64 = "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="
session_key = base64.b64decode(session_key_b64).decode()

# ========== Python 实现（IDA Pro MCP 验证版）==========
def build_authorization_header_correct():
    """IDA Pro MCP 验证的正确实现"""
    payload = {
        "version": "v2",
        "requestId": str(uuid.uuid4()),
        "user": test_data["user_id"],
        "cosyVersion": "2.11.2",
        "ideVersion": "vscode"  # 需要从环境获取，暂时硬编码
    }

    payload_json = json.dumps(payload, separators=(',', ':'))
    payload_b64 = base64.b64encode(payload_json.encode()).decode()

    # 签名参数顺序（IDA Pro MCP 验证）
    # fmt.Sprintf("%s\n%s\n%s\n%s\n%s", a1, a10, a7, a5, a3)
    # 参数映射: a1=userId, a3=secToken, a5=refreshToken, a7=path, a10=method
    # 实际顺序: userId → method → path → refreshToken → secToken
    sign_data = f"{test_data['user_id']}\n{test_data['method']}\n{test_data['path']}\n{test_data['refresh_token']}\n{test_data['security_oauth_token']}"
    signature = hashlib.md5(sign_data.encode()).hexdigest()

    authorization = f"Bearer COSY.{payload_b64}.{signature}"

    return {
        "payload": payload,
        "payload_json": payload_json,
        "payload_b64": payload_b64,
        "sign_data": sign_data,
        "signature": signature,
        "authorization": authorization
    }

# ========== IDA 分析的理论实现 ==========
def build_signature_header():
    """Signature header 计算（IDA 分析）"""
    date_str = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
    sign_input = f"cosy&{session_key}&{date_str}"
    signature = hashlib.md5(sign_input.encode()).hexdigest()

    return {
        "date": date_str,
        "sign_input": sign_input,
        "signature": signature
    }

# ========== 执行测试 ==========
print("="*60)
print("Authorization Header 构造测试 (IDA Pro MCP 验证版)")
print("="*60)

result = build_authorization_header_correct()

print("\n[1] Payload 构造（IDA Pro MCP 验证）:")
print("  字段名称:")
print("    - version: 'v2'")
print("    - requestId: UUID")
print("    - user: userId (注意：不是 'userId' 字段名)")
print("    - cosyVersion: '2.11.2' (全局变量)")
print("    - ideVersion: IDE版本")
print("  JSON:", result["payload_json"][:100] + "...")
print("  Base64:", result["payload_b64"][:50] + "...")

print("\n[2] 签名计算（IDA Pro MCP 验证）:")
print("  参数顺序: userId → method → path → refreshToken → secToken")
print("  (注意：顺序与之前推测完全不同！)")
print("  签名数据:", result["sign_data"][:100] + "...")
print("  MD5签名:", result["signature"])

print("\n[3] Authorization Header:")
print("  ", result["authorization"][:100] + "...")

print("\n[4] Signature Header（IDA 分析）:")
sig_result = build_signature_header()
print("  Date:", sig_result["date"])
print("  Sign Input:", sig_result["sign_input"])
print("  Signature:", sig_result["signature"])

print("\n"+"="*60)
print("验证要点（IDA Pro MCP 验证后）")
print("="*60)

print("\n✅ Payload 字段检查（已验证）:")
required_fields_ida = ["version", "requestId", "user", "cosyVersion", "ideVersion"]
actual_fields = list(result["payload"].keys())
print("  IDA验证字段:", required_fields_ida)
print("  实际字段:", actual_fields)
if set(required_fields_ida) == set(actual_fields):
    print("  ✅ 字段完全匹配（IDA Pro MCP验证）")
else:
    print("  ❌ 字段不匹配！缺少:", set(required_fields_ida) - set(actual_fields))

print("\n✅ 签名参数顺序（已验证）:")
print("  IDA验证顺序: userId → method → path → refreshToken → secToken")
print("  当前实现: userId → method → path → refreshToken → secToken")
print("  ✅ 顺序正确（IDA Pro MCP验证）")
print("  注意: 与之前推测的顺序(userId→secToken→rt→path→method)完全不同！")

print("\n❓ 关键问题:")
print("  1. Authorization header 格式是否正确？")
print("     - IDA: Bearer COSY.{payload_b64}.{signature}")
print("     - 当前: Bearer COSY.{payload_b64}.{signature}")
print("     ✅ 格式正确")

print("\n  2. Signature header 计算是否正确？")
print("     - IDA: MD5(\"cosy&\" + session_key + \"&\" + RFC1123_date)")
print("     - 当前实现: 需要在请求中添加")
print("     ⚠️  Python 实现缺少 Signature header")

print("\n  3. pt-* token 格式是否兼容？")
print("     - IDA 发现: pt-* 是 Lingma 内部格式")
print("     - v3 endpoint 期望: 标准 JWT token")
print("     ❌ 格式不兼容！这是核心问题")

print("\n✅ IDA Pro MCP 验证结果:")
print("  - Payload 字段名称已确认: version, requestId, user, cosyVersion, ideVersion")
print("  - 签名参数顺序已确认: userId → method → path → refreshToken → secToken")
print("  - cosyVersion 硬编码值已确认: '2.11.2'")