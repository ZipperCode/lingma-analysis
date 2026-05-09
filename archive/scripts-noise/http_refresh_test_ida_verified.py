#!/usr/bin/env python3
"""
HTTP Token Refresh 测试 - IDA Pro MCP 验证版

使用 IDA 验证的正确 payload 和签名参数顺序
"""

import hashlib
import base64
import json
import uuid
import requests
from datetime import datetime, timezone

# ========== 用户凭证（从缓存读取）==========
test_data = {
    "user_id": "5930676910898027",
    "security_oauth_token": "pt-Atl8MQJdcCqbDEdAZAyYgnbp",
    "refresh_token": "rt-GLbIaXzLEFCo8rINstjCv6EC"
}

session_key_b64 = "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="
session_key = base64.b64decode(session_key_b64).decode()

# ========== Authorization Header 构造（IDA验证）==========
def build_authorization_header():
    """IDA Pro MCP 验证的正确实现"""
    payload = {
        "version": "v2",
        "requestId": str(uuid.uuid4()),
        "user": test_data["user_id"],
        "cosyVersion": "2.11.2",  # IDA验证：硬编码全局变量
        "ideVersion": "vscode"     # 需要从环境获取，暂时硬编码
    }

    payload_json = json.dumps(payload, separators=(',', ':'))
    payload_b64 = base64.b64encode(payload_json.encode()).decode()

    # 签名参数顺序（IDA Pro MCP 验证）
    # fmt.Sprintf("%s\n%s\n%s\n%s\n%s", userId, method, path, refreshToken, secToken)
    sign_data = (
        f"{test_data['user_id']}\n"
        f"POST\n"
        f"/api/v3/user/refresh_token\n"
        f"{test_data['refresh_token']}\n"
        f"{test_data['security_oauth_token']}"
    )
    signature = hashlib.md5(sign_data.encode()).hexdigest()

    authorization = f"Bearer COSY.{payload_b64}.{signature}"

    return {
        "payload": payload,
        "authorization": authorization,
        "signature": signature
    }

# ========== Signature Header 构造 ==========
def build_signature_header():
    """IDA 分析的 Signature header"""
    date_str = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
    sign_input = f"cosy&{session_key}&{date_str}"
    signature = hashlib.md5(sign_input.encode()).hexdigest()

    return {
        "date": date_str,
        "signature": signature
    }

# ========== HTTP Refresh 测试 ==========
def test_http_refresh():
    """测试 HTTP token refresh"""
    print("="*60)
    print("HTTP Token Refresh 测试（IDA验证版）")
    print("="*60)

    # 构造 headers
    auth_result = build_authorization_header()
    sig_result = build_signature_header()

    headers = {
        "Authorization": auth_result["authorization"],
        "Cosy-Date": sig_result["date"],
        "Cosy-Signature": sig_result["signature"],
        "Content-Type": "application/json"
    }

    # 构造 body（推测）
    body = {
        "userId": test_data["user_id"],
        "securityOauthToken": test_data["security_oauth_token"],
        "refreshToken": test_data["refresh_token"]
    }

    print("\n[1] Request Details:")
    print("  URL: https://lingma.alibabacloud.com/api/v3/user/refresh_token")
    print("  Method: POST")
    print("\n[2] Authorization Header (IDA验证):")
    print("  Payload字段:", list(auth_result["payload"].keys()))
    print("  Header:", auth_result["authorization"][:100] + "...")

    print("\n[3] Signature Header:")
    print("  Cosy-Date:", sig_result["date"])
    print("  Cosy-Signature:", sig_result["signature"])

    print("\n[4] Request Body:")
    print("  ", json.dumps(body, indent=2))

    print("\n[5] 发送 HTTP 请求...")

    try:
        response = requests.post(
            "https://lingma.alibabacloud.com/api/v3/user/refresh_token",
            headers=headers,
            json=body,
            timeout=10
        )

        print("\n[6] Response:")
        print("  Status:", response.status_code)
        print("  Headers:", dict(response.headers))

        try:
            resp_json = response.json()
            print("  Body:", json.dumps(resp_json, indent=2))
        except:
            print("  Body (text):", response.text[:200])

        if response.status_code == 200:
            print("\n✅ Token refresh 成功！")
            return True
        else:
            print("\n❌ Token refresh 失败")
            return False

    except requests.exceptions.RequestException as e:
        print(f"\n❌ 请求失败: {e}")
        return False

# ========== 执行测试 ==========
if __name__ == "__main__":
    test_http_refresh()