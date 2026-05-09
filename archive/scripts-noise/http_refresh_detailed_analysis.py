#!/usr/bin/env python3
"""
HTTP Token Refresh 测试 - 详细分析版

分析 v3 endpoint 返回 HTML 的原因
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
        "cosyVersion": "2.11.2",
        "ideVersion": "vscode"
    }

    payload_json = json.dumps(payload, separators=(',', ':'))
    payload_b64 = base64.b64encode(payload_json.encode()).decode()

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
        "signature": signature,
        "sign_data": sign_data
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
    print("HTTP Token Refresh 测试 - 详细分析版")
    print("="*60)

    # 构造 headers
    auth_result = build_authorization_header()
    sig_result = build_signature_header()

    headers = {
        "Authorization": auth_result["authorization"],
        "Cosy-Date": sig_result["date"],
        "Cosy-Signature": sig_result["signature"],
        "Content-Type": "application/json",
        "User-Agent": "Lingma/2.11.2 (Windows; x64)",  # 添加 User-Agent
        "Accept": "application/json"                   # 明确接受 JSON
    }

    # 构造 body
    body = {
        "userId": test_data["user_id"],
        "securityOauthToken": test_data["security_oauth_token"],
        "refreshToken": test_data["refresh_token"]
    }

    print("\n[1] Request Details:")
    print("  URL: https://lingma.alibabacloud.com/api/v3/user/refresh_token")
    print("  Method: POST")

    print("\n[2] Headers:")
    print("  Authorization:", auth_result["authorization"][:80] + "...")
    print("  Cosy-Date:", sig_result["date"])
    print("  Cosy-Signature:", sig_result["signature"])
    print("  User-Agent:", headers["User-Agent"])
    print("  Accept:", headers["Accept"])

    print("\n[3] Request Body:")
    print(json.dumps(body, indent=2))

    print("\n[4] 发送 HTTP 请求...")

    try:
        response = requests.post(
            "https://lingma.alibabacloud.com/api/v3/user/refresh_token",
            headers=headers,
            json=body,
            timeout=10
        )

        print("\n[5] Response分析:")
        print("  Status Code:", response.status_code)
        print("  Content-Type:", response.headers.get('Content-Type', 'N/A'))
        print("  Content-Length:", response.headers.get('Content-Length', 'N/A'))

        # 检查响应类型
        content_type = response.headers.get('Content-Type', '')

        if 'application/json' in content_type:
            print("\n✅ 返回 JSON 响应")
            try:
                resp_json = response.json()
                print("  Response Body:", json.dumps(resp_json, indent=2))

                if response.status_code == 200 and 'token' in resp_json:
                    print("\n✅✅ Token refresh 真正成功！")
                    return True
                else:
                    print("\n⚠️ JSON 返回但状态异常")
                    return False
            except Exception as e:
                print(f"  JSON解析失败: {e}")
                print("  Raw text:", response.text[:200])
                return False

        elif 'text/html' in content_type:
            print("\n❌ 返回 HTML 页面（不是API响应）")
            print("  页面标题:", response.text[response.text.find('<title>')+7:response.text.find('</title>')][:100])
            print("  问题分析:")
            print("    - v3 endpoint 可能不接受此请求格式")
            print("    - 可能需要其他必要 headers")
            print("    - pt-* token 格式可能不被接受")

            # 检查HTML内容中的关键信息
            if 'Lingma' in response.text and 'Alibaba Cloud' in response.text:
                print("  ⚠️ 返回的是 Lingma 官网首页")
                print("     可能原因: endpoint 被重定向到首页")

            return False

        else:
            print("\n❓ 未知响应类型:", content_type)
            print("  Response text (前200字符):", response.text[:200])
            return False

    except requests.exceptions.RequestException as e:
        print(f"\n❌ 请求失败: {e}")
        return False

# ========== 执行测试 ==========
if __name__ == "__main__":
    test_http_refresh()