"""
灵码 Encode=1 编码实现（已验证 ✅）

验证日期：2026-04-29
验证方法：编码灵码二进制截获的心跳 JSON，输出与二进制发送的完全一致

Encode=1 是纯自定义 base64 编码，不使用 AES 加密。
用于 v1 API 端点（heartbeat、tracking 等）。

v3 API 端点（refresh_token、login 等）使用 Encode=2，尚未逆向。
"""

import base64
import math
import json
import time
import hashlib
import http.client
import ssl

# ======== 自定义字母表 ========
ENCODE1_ALPHA = "_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!"
ENCODE1_STD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# 构建映射表
_STD_TO_ALPHA = {}
_ALPHA_TO_STD = {}
for _i, _c in enumerate(ENCODE1_ALPHA):
    _STD_TO_ALPHA[ENCODE1_STD_B64[_i]] = _c
    _ALPHA_TO_STD[_c] = ENCODE1_STD_B64[_i]


def lingma_encode(data: bytes) -> str:
    """Encode=1 编码：JSON bytes -> 自定义 base64 字符串

    算法步骤：
    1. 标准 base64 编码，去掉 '=' padding
    2. 字符映射：标准 base64 字符 -> 自定义字母表
    3. 分块重排：b0+b1+b2 -> b2+$pad+b1+b0
    """
    std = base64.b64encode(data).decode().rstrip('=')
    custom = ''.join(_STD_TO_ALPHA.get(c, c) for c in std)

    e = len(custom)
    bs = math.ceil(e / 3.0)
    pad = (4 - e % 4) % 4

    b0 = custom[:bs]
    b1, b2 = '', ''
    if 2 * bs <= e:
        b1 = custom[bs:2*bs]
        b2 = custom[2*bs:]
    elif bs < e:
        b1 = custom[bs:]

    return b2 + ('$' * pad) + b1 + b0


def lingma_decode(encoded: str) -> bytes:
    """Encode=1 解码：自定义 base64 字符串 -> JSON bytes"""
    dollar_start = encoded.find('$')
    if dollar_start < 0:
        rev = encoded
    else:
        pad = 0
        pos = dollar_start
        while pos < len(encoded) and encoded[pos] == '$':
            pad += 1
            pos += 1
        rev = encoded[:dollar_start] + encoded[dollar_start + pad:]

    e = len(rev)
    bs = math.ceil(e / 3.0)
    lb = e - 2 * bs
    if lb < 0:
        lb = 0

    b2 = rev[:lb]
    b1_end = min(lb + bs, e)
    b1 = rev[lb:b1_end]
    b0 = rev[b1_end:]

    reordered = b0 + b1 + b2
    converted = ''.join(_ALPHA_TO_STD.get(c, c) for c in reordered)
    missing = (4 - len(converted) % 4) % 4
    converted += '=' * missing

    return base64.b64decode(converted)


# ======== 签名公式 ========
SESSION_KEY = "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="  # "war, war never changes"
SESSION_KEY_ALT = "&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe"


def make_signature(date_rfc1123: str, session_key: str = SESSION_KEY) -> str:
    """生成旧签名：MD5("cosy&" + key + "&" + date)"""
    preimage = f"cosy&{session_key}&{date_rfc1123}"
    return hashlib.md5(preimage.encode()).hexdigest()


def make_headers(machine_id: str, session_key: str = SESSION_KEY) -> dict:
    """生成灵码 v1 API 请求头"""
    date_rfc = time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())
    sig = make_signature(date_rfc, session_key)

    return {
        'content-type': 'application/json',
        'appcode': 'cosy',
        'user-agent': 'Go-http-client/2.0',
        'date': date_rfc,
        'signature': sig,
        'cosy-machineid': machine_id,
        'cosy-machinetype': '',
        'cosy-version': '2.11.2',
        'cosy-clientip': '198.18.0.1',
        'cosy-machinecode': '',
        'cosy-machinetoken': '',
        'cosy-machineos': 'aarch64_darwin',
        'cosy-clienttype': '2',
        'login-version': 'v2',
        'accept': 'application/json',
    }


def call_v1_api(method: str, path: str, body: dict = None,
                machine_id: str = "", host: str = "lingma-api.tongyi.aliyun.com") -> dict:
    """调用灵码 v1 API

    Args:
        method: HTTP 方法（GET/POST）
        path: API 路径（如 /algo/api/v1/heartbeat）
        body: 请求体（POST 时自动 Encode=1 编码）
        machine_id: 机器 ID
        host: 服务端地址

    Returns:
        解析后的 JSON 响应
    """
    ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection(host, context=ctx)

    headers = make_headers(machine_id)

    encoded_body = None
    if body and method == 'POST':
        encoded_body = lingma_encode(json.dumps(body).encode())
        path = f"{path}?Encode=1"

    conn.request(method, path, body=encoded_body, headers=headers)
    resp = conn.getresponse()
    resp_body = resp.read().decode()
    conn.close()

    return json.loads(resp_body)


if __name__ == '__main__':
    # 验证编码算法
    test_data = b'{"test": "hello world"}'
    encoded = lingma_encode(test_data)
    decoded = lingma_decode(encoded)
    assert decoded == test_data, "Round-trip test failed!"
    print(f"Round-trip test passed: {test_data} -> {encoded[:30]}... -> {decoded}")

    # 验证签名公式
    test_date = "Wed, 29 Apr 2026 04:57:23 GMT"
    expected_sig = "24990ee5060611de7743dcc5b74eafab"
    actual_sig = make_signature(test_date)
    assert actual_sig == expected_sig, f"Signature mismatch: {actual_sig} != {expected_sig}"
    print(f"Signature test passed: {actual_sig}")

    print("\nAll tests passed!")
