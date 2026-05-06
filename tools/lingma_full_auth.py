#!/usr/bin/env python3
"""
Lingma 完整认证模拟 v4.0 — 完全模拟 Lingma 二进制流程
基于 IDA Pro 逆向 v2.11.2 (2026-05-06)

完整流程:
  Phase 1: auth/login 获取 PKCE OAuth URL（或 standalone 生成）
  Phase 2: 浏览器认证 → 37510 回调
  Phase 3: 解析回调参数（V2 格式）
  Phase 4: 后端 API 调用（正确编码 body）
  Phase 5: 凭据保存

关键发现:
  - /api/v3/user/status 使用 EncodeVersion="1"，body 需要 Encode=1 编码！
  - doRefreshToken 使用 EncodeVersion=""，body 是原始 JSON
  - Signature 模式 (magic="none"): MD5(base64(body) + "&" + key + "&" + date)
  - Authorization 模式 (magic="http"): Bearer COSY.token

使用方法:
  python tools/lingma_full_auth.py --standalone   # 完全独立模式
  python tools/lingma_full_auth.py                # 通过 LSP 获取 URL
"""
import argparse
import base64
import hashlib
import http.server
import json
import math
import os
import re
import secrets
import ssl
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

# ============================================================
# 常量
# ============================================================
CALLBACK_PORT = 37510
LSP_PORT = 37010

# Cosy-Key (IDA @ addBigModelSignatureHeaders 0x14087e5e0)
COSY_KEY = "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="
ALT_COSY_KEY = "&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe"

# API 端点
BIG_MODEL_ENDPOINT = "https://lingma.alibabacloud.com/algo"

# OAuth Base URL — 国际站 (IDA: off_146011C20 动态配置)
# LSP 实际使用的是国际站: https://lingma.alibabacloud.com/lingma/login
# 国内站: https://devops.aliyun.com/lingma/login (500 错误)
OAUTH_BASE_URL = "https://lingma.alibabacloud.com/lingma/login"

# 自定义 base64 字母表 (IDA @ encodeToString 0x1404549e0)
ALPHA = '_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!'
STD_B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

# Nonce 映射 (模拟 IDA: qword_1460D9528)
_nonce_map = {}


# ============================================================
# Encode=1 编解码
# ============================================================
def _custom_b64_encode(data: bytes) -> str:
    std = base64.b64encode(data).decode().rstrip('=')
    return ''.join(ALPHA[STD_B64.index(c)] for c in std)


def _custom_b64_decode(encoded: str) -> bytes:
    converted = ''.join(STD_B64[ALPHA.index(c)] for c in encoded if c in ALPHA)
    pad = (4 - len(converted) % 4) % 4
    return base64.b64decode(converted + '=' * pad)


def encode_to_string(data: bytes) -> str:
    """encodeToString (IDA @ 0x1404549e0)"""
    encoded = _custom_b64_encode(data)
    E = len(encoded)
    BS = math.ceil(E / 3)
    pad = (4 - E % 4) % 4
    b0, b1, b2 = encoded[:BS], encoded[BS:2*BS], encoded[2*BS:]
    return b2 + '$' * pad + b1 + b0


def decode_string(body: str) -> bytes:
    """decodeString"""
    dollar_start = body.find('$')
    if dollar_start < 0:
        rev = body
        E = len(body)
    else:
        pad = 0
        pos = dollar_start
        while pos < len(body) and body[pos] == '$':
            pad += 1
            pos += 1
        rev = body[:dollar_start] + body[dollar_start + pad:]
        E = len(rev)
    BS = math.ceil(E / 3)
    lb = E - 2 * BS
    b2 = rev[:lb]
    b1 = rev[lb:lb + BS]
    b0 = rev[lb + BS:]
    return _custom_b64_decode(b0 + b1 + b2)


# ============================================================
# 签名算法 (IDA @ addBigModelSignatureHeaders 0x14087e5e0)
# ============================================================
def md5_sign(encoded_body: str, date_str: str, use_alt_key: bool = False) -> str:
    """MD5(base64(body) + "&" + key + "&" + date)"""
    key = ALT_COSY_KEY if use_alt_key else COSY_KEY
    raw = f"{encoded_body}&{key}&{date_str}"
    return hashlib.md5(raw.encode()).hexdigest()


def get_rfc1123_date() -> str:
    return datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')


# ============================================================
# 请求头构造
# ============================================================
def build_sign_headers(body: str, machine_id: str, client_type: str = "2",
                       cosy_version: str = "20", date_str: str = None) -> dict:
    """Signature 模式请求头 (IDA @ addBasicHeaders + addBigModelSignatureHeaders)"""
    if date_str is None:
        date_str = get_rfc1123_date()
    encoded = base64.b64encode(body.encode()).decode()
    return {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Accept-Encoding": "gzip",
        "User-Agent": f"Cosy/{cosy_version}",
        "X-Forwarded-For": "127.0.0.1",
        "Cosy-MachineId": machine_id,
        "Cosy-MachineToken": "",
        "Cosy-MachineType": "",
        "Cosy-MachineCode": "",
        "Cosy-MachineOS": "x86_64_windows",
        "Cosy-ClientType": client_type,
        "Cosy-Version": cosy_version,
        "Date": date_str,
        "Cosy-Date": date_str,
        "Cosy-User": encoded,
        "Signature": md5_sign(encoded, date_str),
    }


# ============================================================
# API 调用 —— 完整模拟 Lingma 的请求构造
# ============================================================
def api_call(method: str, path: str, body_json: dict,
             machine_id: str, encode_version: str = "") -> tuple:
    """
    通用 API 调用，完整模拟 buildRequest 流程

    encode_version:
      ""   → 原始 JSON body (用于 doRefreshToken)
      "1"  → Encode=1 编码 body (用于 /api/v3/user/status)
    """
    body_str = json.dumps(body_json, ensure_ascii=False, separators=(",", ":"))

    # Step 1: encodeRequestBody — 如果是 dict 则 JSON marshal
    # (body_str 已经是 JSON 字符串，转换为 bytes)
    body_bytes = body_str.encode('utf-8')

    # Step 2: shouldEncryptBody — 检查是否需要 encodeToString
    # 逻辑: EncodeVersion="1" + 方法=POST + 路径不在跳过列表 → 需要编码
    if encode_version == "1":
        # Encode=1 编码 body (IDA @ shouldAddEncodeParam)
        encoded_body = encode_to_string(body_bytes)
        final_body = encoded_body.encode('utf-8')
    else:
        final_body = body_bytes

    # Step 3: 构建签名头
    url = f"{BIG_MODEL_ENDPOINT}{path}"
    date_str = get_rfc1123_date()
    headers = build_sign_headers(body_str, machine_id, date_str=date_str)
    headers["Content-Length"] = str(len(final_body))

    # Step 4: 发送请求
    req = urllib.request.Request(
        url, data=final_body, headers=headers, method=method
    )
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        resp = urllib.request.urlopen(req, context=ctx, timeout=30)
        return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        err_body = e.read().decode(errors="replace")
        return e.code, {"error": str(e), "body": err_body[:500]}
    except Exception as e:
        return 0, {"error": str(e)}


# ============================================================
# PKCE 工具
# ============================================================
def generate_nonce() -> str:
    return uuid.uuid4().hex


def generate_pkce() -> tuple:
    verifier = secrets.token_urlsafe(32)[:43]
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
    return verifier, challenge


def build_oauth_url(nonce: str, port: int, challenge: str, machine_id: str) -> str:
    """
    构造 OAuth URL (IDA @ PrepareLoginRequest 0x141a198a0)

    state 参数格式: "{version}-{nonce}"
      - version = "2" (当前解析版本 V2)
      - nonce = UUID 去横线 (32 字符)
    """
    params = urllib.parse.urlencode({
        "nonce": nonce,
        "port": port,
        "state": f"2-{nonce}",  # V2 格式: 版本前缀 + nonce
        "challenge": challenge,
        "challenge_method": "S256",
        "machine_id": machine_id,
    })
    return f"{OAUTH_BASE_URL}?{params}"


# ============================================================
# V2 auth/token 编解码
# ============================================================
def build_auth_v2(uid: str, aid: str, name: str) -> str:
    """V2 Auth: UID\\nAID\\nName → encodeToString → URL-escape"""
    raw = f"{uid}\n{aid}\n{name}"
    return urllib.parse.quote(encode_to_string(raw.encode()), safe='')


def build_token_v2(token: str, refresh_token: str, expire_time: int) -> str:
    """V2 Token: Token\\nRefreshToken\\nExpireTime → encodeToString → URL-escape"""
    raw = f"{token}\n{refresh_token}\n{expire_time}"
    return urllib.parse.quote(encode_to_string(raw.encode()), safe='')


def custom_decrypt_parts(encoded: str, expected_parts: int = 3) -> list:
    """CustomDecryptParts: decodeString → split(\\n, expected_parts)"""
    decoded = decode_string(encoded)
    text = decoded.decode('utf-8')
    return text.split('\n', expected_parts - 1)


def parse_callback_v2(params: dict) -> dict:
    """
    解析 37510 回调参数 (IDA @ parseAuthInfoV2 0x141a21800)
    支持 V2 (auth/token) 和 V1 (aid/uid/name) 格式
    """
    result = {}

    if "auth" in params:
        parts = custom_decrypt_parts(params["auth"], 3)
        if len(parts) >= 3:
            result.update(uid=parts[0], aid=parts[1], name=parts[2])
    elif "aid" in params and "uid" in params:
        result.update(uid=params["uid"], aid=params["aid"], name=params.get("name", ""))

    if "token" in params:
        parts = custom_decrypt_parts(params["token"], 3)
        if len(parts) >= 3:
            try:
                expire = int(parts[2])
            except ValueError:
                expire = 0
            result.update(token=parts[0], refresh_token=parts[1], expire_time=expire)

    return result


# ============================================================
# LSP WebSocket
# ============================================================
def make_lsp_frame(method: str, params: dict = None, msg_id: int = 1) -> str:
    body = {"jsonrpc": "2.0", "method": method, "id": msg_id}
    if params:
        body["params"] = params
    content = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
    return f"Content-Length: {len(content.encode('utf-8'))}\r\n\r\n{content}"


def parse_lsp_frames(payload: bytes) -> list:
    msgs, offset = [], 0
    marker = b"\r\n\r\n"
    while offset < len(payload):
        header_end = payload.find(marker, offset)
        if header_end < 0:
            break
        header = payload[offset:header_end].decode("ascii", errors="replace")
        cl = None
        for line in header.split("\r\n"):
            if line.lower().startswith("content-length:"):
                cl = int(line.split(":", 1)[1].strip())
                break
        if cl is None:
            break
        body_start = header_end + len(marker)
        body_end = body_start + cl
        if body_end > len(payload):
            break
        msgs.append(json.loads(payload[body_start:body_end]))
        offset = body_end
    return msgs


def get_login_url_via_lsp() -> dict:
    import websocket as ws_lib
    ws = ws_lib.create_connection(f"ws://127.0.0.1:{LSP_PORT}", timeout=10)
    result = {}
    try:
        ws.send(make_lsp_frame("initialize", {
            "processId": None,
            "clientInfo": {"name": "lingma-auth-sim", "version": "4.0"},
            "rootUri": "file:///C:/sim", "capabilities": {},
            "workspaceFolders": [{"uri": "file:///C:/sim", "name": "sim"}],
        }, 1))
        ws.settimeout(3)
        try: ws.recv()
        except: pass

        ws.send(make_lsp_frame("auth/login", {}, 3))
        ws.settimeout(30)

        login_url, deadline = None, time.time() + 25
        while time.time() < deadline:
            try:
                raw = ws.recv()
            except ws_lib.WebSocketTimeoutException:
                continue
            except Exception:
                break
            raw_bytes = raw.encode() if isinstance(raw, str) else raw
            for m in parse_lsp_frames(raw_bytes):
                if "result" in m:
                    r = m["result"]
                    urls = re.findall(r'https?://[^\s"\']+', json.dumps(r))
                    if urls:
                        login_url = urls[0]
        ws.close()
        if login_url:
            qp = urllib.parse.parse_qs(urllib.parse.urlparse(login_url).query)
            result["login_url"] = login_url
            result["url_params"] = {k: v[0] for k, v in qp.items()}
    except Exception as e:
        print(f"  [!] LSP Error: {e}")
    finally:
        try: ws.close()
        except: pass
    return result


# ============================================================
# 37510 HTTP 回调处理器
# ============================================================
class CallbackHandler(http.server.BaseHTTPRequestHandler):
    captured = None
    result_event = threading.Event()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        flat = {k: v[0] for k, v in params.items()}

        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Connection", "close")
        self.end_headers()

        state = flat.get("state", "")
        auth_data = parse_callback_v2(flat)
        nonce_valid = state in _nonce_map

        print(f'\n{"="*60}')
        print(f'[*] 收到 OAuth 回调~ φ(≧ω≦*)♪')
        print(f'  Nonce valid: {nonce_valid}')
        print(f'  Format: {"V2 (auth+token)" if "auth" in flat else "V1 (aid/uid/name)" if "aid" in flat else "unknown"}')
        if auth_data.get("uid"):
            print(f'  UID: {auth_data["uid"][:20]}... Name: {auth_data.get("name", "")[:30]}...')
        if auth_data.get("token"):
            print(f'  Token: {auth_data["token"][:20]}...')

        CallbackHandler.captured = {
            "path": self.path,
            "query_params": flat,
            "auth_data": auth_data,
            "timestamp": time.time(),
            "nonce_valid": nonce_valid,
        }

        success = bool(auth_data.get("uid"))
        html = f"""<html><body style="font-family:sans-serif;text-align:center;margin-top:100px">
<h1>{'✅ 登录成功' if success else '❌ 登录失败'}</h1>
<p>{'你可以关闭此窗口' if success else '未获取到用户信息'}</p>
</body></html>"""
        self.wfile.write(html.encode('utf-8'))
        CallbackHandler.result_event.set()

    def log_message(self, format, *args):
        pass


# ============================================================
# 主流程
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="Lingma 完整认证模拟 v4.0")
    parser.add_argument("--standalone", action="store_true", help="完全独立模式")
    parser.add_argument("--port", type=int, default=CALLBACK_PORT)
    parser.add_argument("--machine-id", help="Machine ID (自动生成)")
    args = parser.parse_args()

    port, machine_id = args.port, args.machine_id or str(uuid.uuid4())

    print("=" * 60)
    print("Lingma 完整认证模拟 v4.0")
    print("基于 IDA Pro 逆向 v2.11.2")
    print(f"模式: {'完全独立' if args.standalone else '通过 LSP'}")
    print("=" * 60)

    # ── Phase 1: 获取 Login URL ──
    print(f"\n{'='*60}\nPhase 1: 获取 Login URL\n{'='*60}")

    if args.standalone:
        nonce = generate_nonce()
        verifier, challenge = generate_pkce()
        login_url = build_oauth_url(nonce, port, challenge, machine_id)
        _nonce_map[nonce] = {"ts": time.time(), "verifier": verifier}
        print(f"  Nonce: {nonce[:20]}...")
    else:
        info = get_login_url_via_lsp()
        if not info.get("login_url"):
            print("[!] 获取失败，尝试 standalone: python tools/lingma_full_auth.py --standalone")
            sys.exit(1)
        login_url = info["login_url"]
        state = info.get("url_params", {}).get("state", "")
        if state:
            _nonce_map[state] = {"ts": time.time()}

    print(f"  URL: {login_url[:120]}...")

    # ── Phase 2: 启动 37510 服务器 ──
    print(f"\n{'='*60}\nPhase 2: 启动回调服务器 :{port}\n{'='*60}")
    server = http.server.HTTPServer(("127.0.0.1", port), CallbackHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"  Listening on http://127.0.0.1:{port}/auth/callback")

    # ── Phase 3: 打开浏览器 ──
    print(f"\n{'='*60}\nPhase 3: 在浏览器中完成认证\n{'='*60}")
    webbrowser.open(login_url)

    if not CallbackHandler.result_event.wait(timeout=180):
        print("\n[!] 超时")
        server.shutdown()
        sys.exit(1)
    server.shutdown()

    auth_data = CallbackHandler.captured.get("auth_data", {})
    if not auth_data.get("uid"):
        print("[!] 未获取到用户信息")
        sys.exit(1)

    uid, name = auth_data["uid"], auth_data.get("name", "")
    oauth_token = auth_data.get("token", "")
    refresh_token = auth_data.get("refresh_token", "")

    print(f"\n[*] 用户: {uid[:20]}... ({name[:30]})")
    print(f"[*] OAuth Token: {oauth_token[:20]}...")
    print(f"[*] Refresh Token: {refresh_token[:20]}...")

    # ── Phase 4: 调用 /api/v3/user/status (Encode=1 编码!) ──
    print(f"\n{'='*60}")
    print(f"Phase 4: 调用 /api/v3/user/status [EncodeVersion=1]")
    print(f"{'='*60}")

    status_body = {
        "uid": uid,
        # AuthQueryParam 可能还需要其他字段
    }
    status_code, status_resp = api_call(
        "POST", "/api/v3/user/status", status_body,
        machine_id, encode_version="1"
    )
    print(f"  HTTP {status_code}")
    if status_code == 200:
        print(f"  响应: {json.dumps(status_resp, ensure_ascii=False)[:300]}")
    else:
        print(f"  错误: {status_resp.get('body', str(status_resp))[:200]}")

    # ── Phase 5: 凭据保存 ──
    print(f"\n{'='*60}\nPhase 5: 凭据保存\n{'='*60}")
    creds = {
        "machine_id": machine_id,
        "uid": uid, "name": name,
        "oauth_token": oauth_token,
        "refresh_token": refresh_token,
        "timestamp": int(time.time()),
    }
    config_dir = Path.home() / ".lingma"
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "portable_config.json"
    with open(config_path, "w") as f:
        json.dump(creds, f, indent=2, ensure_ascii=False)
    print(f"\n[*] 凭据已保存到: {config_path}")
    print(f"\n[*] 完成!")


if __name__ == "__main__":
    main()
