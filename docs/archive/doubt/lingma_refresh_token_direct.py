#!/usr/bin/env python3
"""
灵码 Token Refresh 直连测试脚本
基于 IDA Pro 分析结果实现独立 token refresh

日期：2026-04-30
分析来源：docs/topics/ida-oauth-refresh-analysis.md

目标端点：https://lingma.alibabacloud.com/algo/api/v3/user/refresh_token
认证机制：灵码旧签名 + Encode=1 编码

使用方法：
    python lingma_refresh_token_direct.py --credentials ~/.lingma/cache/user
"""

import argparse
import base64
import hashlib
import math
import json
import uuid
import requests
from datetime import datetime, timezone
from pathlib import Path
import sys

# Encode=1 自定义 base64 字母表（已验证）
ENCODE1_ALPHA = "_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!"
ENCODE1_STD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# Session Key（已确认）
SESSION_KEY_B64 = "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="  # base64 编码
SESSION_KEY = base64.b64decode(SESSION_KEY_B64).decode()  # "war, war never changes"

# 构建映射表
STD_TO_ALPHA = {std: alpha for std, alpha in zip(ENCODE1_STD_B64, ENCODE1_ALPHA)}

def lingma_encode_v1(data: bytes) -> str:
    """
    Encode=1 编码算法（自定义 base64 + 分块重排）

    参考：docs/topics/encode1-complete-analysis.md
    """
    # 1. 标准 base64 编码，去掉 padding
    std_b64 = base64.b64encode(data).decode().rstrip('=')

    # 2. 字符映射
    custom = ''.join(STD_TO_ALPHA.get(c, c) for c in std_b64)

    # 3. 分块重排
    e = len(custom)
    bs = math.ceil(e / 3.0)  # 块大小
    pad = (4 - e % 4) % 4    # padding 标记数

    b0 = custom[:bs]
    b1 = custom[bs:2*bs] if 2*bs <= e else custom[bs:]
    b2 = custom[2*bs:]

    # 4. 输出格式：b2 + $padding + b1 + b0
    return b2 + ('$' * pad) + b1 + b0

def compute_signature(session_key: str, date_str: str) -> str:
    """
    计算灵码旧签名

    公式：MD5("cosy&" + session_key + "&" + date)

    参考：docs/topics/standalone-oauth-analysis.md
    """
    sign_input = f"cosy&{session_key}&{date_str}"
    return hashlib.md5(sign_input.encode()).hexdigest()

def get_rfc1123_date() -> str:
    """
    生成 RFC1123 格式日期

    格式：Wed, 29 Apr 2026 05:02:30 GMT
    """
    now = datetime.now(timezone.utc)
    return now.strftime('%a, %d %b %Y %H:%M:%S GMT')

def build_authorization_header(
    user_id: str,
    security_oauth_token: str,
    refresh_token: str,
    request_path: str,
    request_method: str = "POST"
) -> str:
    """
    构建灵码 Authorization Header

    格式：Bearer COSY.{base64_payload}.{md5_signature}

    参考：docs/topics/ida-http-auth-headers-analysis.md

    Args:
        user_id: 用户 ID
        security_oauth_token: Security Oauth Token (pt-xxx)
        refresh_token: Refresh Token (rt-xxx)
        request_path: 请求路径
        request_method: HTTP 方法

    Returns:
        Authorization header 字符串
    """
    import uuid

    # 1. 构建 Payload (JSON)
    payload = {
        "version": "v2",
        "requestId": str(uuid.uuid4()),
        "userId": user_id,
        "securityOauthToken": security_oauth_token,
        "path": request_path,
        "method": request_method
    }

    # 2. JSON 序列化（紧凑格式，无空格）
    payload_json = json.dumps(payload, separators=(',', ':'))

    # 3. Base64 编码
    payload_b64 = base64.b64encode(payload_json.encode('utf-8')).decode('utf-8')

    # 4. 构建签名字符串（关键：参数顺序需要验证）
    # 根据反编译推测：userId, securityOauthToken, refreshToken, path, method
    sign_data = f"{user_id}\n{security_oauth_token}\n{refresh_token}\n{request_path}\n{request_method}"

    # 5. 计算 MD5 签名
    signature = hashlib.md5(sign_data.encode('utf-8')).hexdigest()

    # 6. 构造 Authorization header
    authorization = f"Bearer COSY.{payload_b64}.{signature}"

    return authorization

def build_headers_v2(
    machine_id: str,
    signature: str,
    date_str: str,
    user_id: str,
    org_id: str,
    security_oauth_token: str,
    refresh_token: str,
    request_path: str,
    version: str = "2.11.2"
) -> dict:
    """
    构建灵码 HTTP 请求头（完整版，包含 Authorization）

    参考：IDA Pro 分析结果（docs/topics/ida-http-auth-headers-analysis.md）
    """
    headers = {
        'User-Agent': 'Go-http-client/1.1',
        'Accept': 'application/json',
        'Accept-Encoding': 'identity',
        'Appcode': 'cosy',
        'Content-Type': 'application/json',
        'Cosy-Clientip': '127.0.0.1',
        'Cosy-Clienttype': '2',
        'Cosy-Machinecode': '',
        'Cosy-Machineid': machine_id,
        'Cosy-Machineos': 'x86_64_windows',
        'Cosy-Machinetoken': '',
        'Cosy-Machinetype': '',
        'Cosy-Version': version,
        'Cosy-Organization-Id': org_id,
        'Date': date_str,
        'Login-Version': 'v2',
        'Signature': signature,
        'Authorization': build_authorization_header(
            user_id=user_id,
            security_oauth_token=security_oauth_token,
            refresh_token=refresh_token,
            request_path=request_path,
            request_method="POST"
        )
    }
    return headers

def parse_lingma_user_cache(cache_file: Path) -> dict:
    """
    解析灵码用户缓存文件

    文件位置：~/.lingma/cache/user（AES-128-CBC 加密）

    注意：这里简化处理，假设文件已经解密或者读取 JSON
    实际实现需要 AES 解密（key = machine_id[:16]）
    """
    try:
        # 尝试直接读取 JSON
        with open(cache_file, 'r', encoding='utf-8') as f:
            content = f.read()

        # 检查是否是 base64 编码（加密情况）
        if content.startswith('{'):
            # 未加密，直接解析
            # 但可能有多个 JSON 对象，需要提取第一个
            import re
            json_pattern = r'\{[^{}]*\}'
            first_json_match = re.search(json_pattern, content)

            if first_json_match:
                return json.loads(first_json_match.group(0))
            else:
                print(f"❌ 未找到有效 JSON 对象")
                return None
        else:
            # 尝试 base64 解码 + AES 解密
            print(f"⚠️ 缓存文件可能是加密的，需要 AES 解密")
            print(f"   请使用 --machine-id, --user-id, --org-id 等参数手动提供")
            return None

    except Exception as e:
        print(f"❌ 解析缓存文件失败：{e}")
        return None

def refresh_token_direct(
    security_oauth_token: str,
    refresh_token: str,
    user_id: str,
    org_id: str,
    machine_id: str,
    endpoint: str = "https://lingma.alibabacloud.com/algo"
) -> dict:
    """
    直接调用灵码 refresh token 端点

    基于 IDA Pro 分析的 doRefreshToken 流程：
    1. 构建签名请求
    2. Encode=1 编码请求体
    3. HTTP POST 发送
    4. 解析响应

    参考：docs/topics/ida-oauth-refresh-analysis.md
    """

    print(f"\n🔍 开始 refresh token 直接调用测试...")
    print(f"   端点：{endpoint}")
    print(f"   用户ID：{user_id}")
    print(f"   组织ID：{org_id}")
    print(f"   Machine ID：{machine_id}")

    # 1. 构建请求体（基于 IDA 分析）
    request_body = {
        "userId": user_id,
        "orgId": org_id,
        "securityOauthToken": security_oauth_token,
        "refreshToken": refresh_token,
    }

    print(f"\n📦 请求体（原始 JSON）：")
    print(json.dumps(request_body, indent=2, ensure_ascii=False))

    # 2. Encode=1 编码请求体
    body_json = json.dumps(request_body, ensure_ascii=False)
    encoded_body = lingma_encode_v1(body_json.encode('utf-8'))

    print(f"\n🔐 Encode=1 编码后（长度={len(encoded_body)}）：")
    print(f"   前 100 字符：{encoded_body[:100]}...")

    # 3. 计算签名
    date_str = get_rfc1123_date()
    signature = compute_signature(SESSION_KEY, date_str)

    print(f"\n🔑 签名计算：")
    print(f"   Session Key：{SESSION_KEY}")
    print(f"   Date：{date_str}")
    print(f"   Signature：{signature}")

    # 4. 构建请求头（完整版，包含 Authorization）
    headers = build_headers_v2(
        machine_id=machine_id,
        signature=signature,
        date_str=date_str,
        user_id=user_id,
        org_id=org_id,
        security_oauth_token=security_oauth_token,
        refresh_token=refresh_token,
        request_path="/api/v3/user/refresh_token"  # 用于 Authorization header
    )

    print(f"\n📋 请求头：")
    for key, value in headers.items():
        if key.startswith('Cosy-') or key in ['Signature', 'Date', 'Appcode', 'Authorization']:
            if key == 'Authorization':
                print(f"   {key}: {value[:50]}...")  # 只打印前 50 字符
            else:
                print(f"   {key}: {value}")

    # 5. 构建完整 URL（添加 Encode=1 参数）
    url = f"{endpoint}/api/v3/user/refresh_token"
    params = {'Encode': '1'}  # Encode=1 参数

    print(f"\n🚀 发送 HTTP POST 请求...")
    print(f"   URL：{url}")
    print(f"   Params：{params}")

    try:
        response = requests.post(
            url,
            params=params,
            headers=headers,
            data=encoded_body,  # 编码后的 body
            timeout=30,
            verify=True,  # 验证 SSL
        )

        print(f"\n📥 响应状态码：{response.status_code}")
        print(f"   响应头：{dict(response.headers)}")

        # 尝试解析响应
        try:
            # 如果响应也是 Encode=1 编码，需要解码
            # 但根据之前测试，响应可能是明文 JSON 或编码
            resp_text = response.text
            print(f"\n📄 响应内容（原始）：")
            print(resp_text[:500])

            # 尝试 JSON 解析
            if resp_text.startswith('{'):
                resp_json = json.loads(resp_text)
                print(f"\n✅ JSON 解析成功：")
                print(json.dumps(resp_json, indent=2, ensure_ascii=False))
                return resp_json
            else:
                print(f"\n⚠️ 响应不是 JSON，可能是 Encode=1 编码")
                return {"raw_response": resp_text, "status_code": response.status_code}

        except json.JSONDecodeError as e:
            print(f"\n❌ JSON 解析失败：{e}")
            return {"raw_response": response.text, "status_code": response.status_code, "error": str(e)}

    except requests.exceptions.RequestException as e:
        print(f"\n❌ HTTP 请求失败：{e}")
        return {"error": str(e)}

def main():
    parser = argparse.ArgumentParser(description='灵码 Token Refresh 直连测试')
    parser.add_argument('--credentials', type=str,
                        default='~/.lingma/cache/user',
                        help='灵码缓存凭证文件路径')
    parser.add_argument('--endpoint', type=str,
                        default='https://lingma.alibabacloud.com/algo',
                        help='灵码 API 端点')
    parser.add_argument('--machine-id', type=str,
                        help='Machine ID（UUID 格式）')
    parser.add_argument('--user-id', type=str,
                        help='用户 ID')
    parser.add_argument('--org-id', type=str,
                        help='组织 ID')
    parser.add_argument('--security-token', type=str,
                        help='SecurityOauthToken')
    parser.add_argument('--refresh-token', type=str,
                        help='RefreshToken')

    args = parser.parse_args()

    # 如果提供了所有必需参数，直接使用（org_id 可以是空字符串）
    if args.security_token and args.refresh_token and args.user_id and args.machine_id:
        print("✅ 使用命令行参数进行 refresh")
        result = refresh_token_direct(
            security_oauth_token=args.security_token,
            refresh_token=args.refresh_token,
            user_id=args.user_id,
            org_id=args.org_id or '',  # 确保是字符串，即使是空
            machine_id=args.machine_id,
            endpoint=args.endpoint
        )
        print("\n🎉 Refresh 测试完成")
        return

    # 否则尝试从缓存文件读取
    cache_file = Path(args.credentials).expanduser()
    print(f"📂 尝试读取缓存文件：{cache_file}")

    if not cache_file.exists():
        print(f"❌ 缓存文件不存在：{cache_file}")
        print("\n请使用以下参数手动提供：")
        print("  --security-token <pt-xxx>")
        print("  --refresh-token <rt-xxx>")
        print("  --user-id <uid>")
        print("  --org-id <org_id>")
        print("  --machine-id <UUID>")
        sys.exit(1)

    # 解析缓存文件
    creds = parse_lingma_user_cache(cache_file)
    if not creds:
        sys.exit(1)

    # 提取字段（需要根据实际文件结构调整）
    print("\n⚠️ 注意：缓存文件是 AES 加密的，此脚本暂时不支持自动解密")
    print("   请手动解密或提供以下字段：")
    print("   - securityOauthToken")
    print("   - refreshToken")
    print("   - userId")
    print("   - orgId")
    print("   - machineId")

    print("\n💡 示例命令：")
    print("   python lingma_refresh_token_direct.py \\")
    print("     --security-token 'pt-...' \\")
    print("     --refresh-token 'rt-...' \\")
    print("     --user-id 'xxx' \\")
    print("     --org-id 'xxx' \\")
    print("     --machine-id 'UUID'")

if __name__ == '__main__':
    main()
