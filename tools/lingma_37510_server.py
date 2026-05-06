#!/usr/bin/env python3
"""
Lingma 37510 回调模拟服务器 v3.0 — 完整认证流程
基于 IDA Pro 逆向 v2.11.2 (2026-05-06)

完整实现:
  Phase 1: 生成 PKCE OAuth URL (或通过 LSP 获取)
  Phase 2: 启动 37510 HTTP 服务器等待回调
  Phase 3: 解析回调参数 (V2: auth/token 或 V1: aid/uid/name)
  Phase 4: 模拟后端 API 调用 (user/login + user/status)
  Phase 5: 凭据保存

Callback V2 格式 (当前二进制版本):
  /auth/callback?state=<nonce>&auth=<encoded>&token=<encoded>
    - auth: CustomDecryptParts(auth, 3) → [UID, AID, Name]
    - token: parseAuthToken(token) → [Token, RefreshToken, ExpireTime]

Callback V1 格式 (兼容):
  /auth/callback?state=<nonce>&aid=<id>&uid=<id>&name=<email>

使用方法:
  # 模式 1: 通过 LSP 获取 URL (需 Lingma 运行)
  python tools/lingma_37510_server.py

  # 模式 2: 完全独立 (自动生成 URL)
  python tools/lingma_37510_server.py --standalone

  # 模式 3: 指定参数
  python tools/lingma_37510_server.py --standalone --client-id your_client_id
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
# 配置
# ============================================================
CALLBACK_PORT = 37510
LSP_PORT = 37010

# Cosy-Key (IDA @ addBigModelSignatureHeaders 0x14087e5e0)
COSY_KEY = "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="
ALT_COSY_KEY = "&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe"

# API 端点
BIG_MODEL_ENDPOINT = "https://lingma.alibabacloud.com/algo"
# 备用: https://lingma-api.tongyi.aliyun.com/algo

# 自定义 base64 字母表 (IDA: encodeToString @ 0x1404549e0)
ALPHA = '_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!'
STD_B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

# OAuth 基础 URL (IDA @ 0x14252655e)
OAUTH_BASE_URL = "https://devops.aliyun.com/lingma/login"

# ============================================================
# 全局 nonce → context 映射 (模拟 IDA: qword_1460D9528)
# ============================================================
_nonce_map = {}


# ============================================================
# 自定义 base64 编码/解码 (Encode=1)
# ============================================================
def _custom_b64_encode(data: bytes) -> str:
    """自定义 base64: 替换字母表"""
    std = base64.b64encode(data).decode().rstrip('=')
    return ''.join(ALPHA[STD_B64.index(c)] for c in std)


def _custom_b64_decode(encoded: str) -> bytes:
    """自定义 base64 解码"""
    converted = ''.join(STD_B64[ALPHA.index(c)] for c in encoded if c in ALPHA)
    pad = (4 - len(converted) % 4) % 4
    return base64.b64decode(converted + '=' * pad)


def encode_to_string(data: bytes) -> str:
    """
    encodeToString (IDA @ 0x1404549e0)
    自定义base64 → 3块反转 → $填充到4的倍数
    """
    encoded = _custom_b64_encode(data)
    E = len(encoded)
    BS = math.ceil(E / 3)
    pad = (4 - E % 4) % 4
    b0, b1, b2 = encoded[:BS], encoded[BS:2*BS], encoded[2*BS:]
    return b2 + '$' * pad + b1 + b0


def decode_string(body: str) -> bytes:
    """decodeString: 去$ → 反转恢复 → 自定义base64解码"""
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


def custom_decrypt_parts(encoded: str, expected_parts: int = 3) -> list:
    """
    CustomDecryptParts (IDA @ 0x140455ca0)
    1. decodeString (自定义base64解码)
    2. split("\n", expected_parts)
    """
    decoded = decode_string(encoded)
    text = decoded.decode('utf-8')
    parts = text.split('\n', expected_parts - 1)
    return parts


# ============================================================
# 签名算法 (IDA @ addBigModelSignatureHeaders 0x14087e5e0)
# ============================================================
def md5_sign(encoded_body: str, date_str: str, use_alt_key: bool = False) -> str:
    key = ALT_COSY_KEY if use_alt_key else COSY_KEY
    raw = f"{encoded_body}&{key}&{date_str}"
    return hashlib.md5(raw.encode()).hexdigest()


# ============================================================
# 请求头构造 (IDA @ addBasicHeaders 0x14087ef20)
# ============================================================
def build_headers(body_str: str, machine_id: str, client_type: str = "2",
                  cosy_version: str = "20", date_str: str = None) -> dict:
    if date_str is None:
        date_str = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
    encoded = base64.b64encode(body_str.encode()).decode()
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
# Auth/TokenString 编码/解码
# ============================================================
def build_auth_string(uid: str, aid: str, name: str) -> str:
    """
    构造 Auth 参数 (IDA @ ToLoginAuthCallbackParam)
    JSON{UID, AID, Name} → encodeToString → URL-escape
    """
    auth_info = {"UID": uid, "AID": aid, "Name": name}
    auth_json = json.dumps(auth_info, ensure_ascii=False, separators=(",", ":"))
    encoded = encode_to_string(auth_json.encode())
    return urllib.parse.quote(encoded, safe='')


def build_token_string(token: str, refresh_token: str, expire_time: int) -> str:
    """
    构造 TokenString 参数
    "%s\n%s\n%d" → encodeToString → URL-escape
    """
    formatted = f"{token}\n{refresh_token}\n{expire_time}"
    encoded = encode_to_string(formatted.encode())
    return urllib.parse.quote(encoded, safe='')


def parse_auth_string(auth_str: str) -> dict:
    """
    解析 Auth 参数 (V3 格式: JSON)
    URL-unescape → decodeString → JSON parse
    """
    unescaped = urllib.parse.unquote(auth_str)
    decoded = decode_string(unescaped)
    return json.loads(decoded.decode())


def parse_auth_v2(params: dict) -> dict:
    """
    V2 参数解析 (IDA @ parseAuthInfoV2 0x141a21800)
    支持 auth/token 或 aid/uid/name

    返回: {uid, aid, name, token, refresh_token, expire_time}
    """
    result = {}

    if "auth" in params:
        # V2 格式: auth = CustomDecryptParts(3) → [UID, AID, Name]
        auth_encoded = params["auth"]
        parts = custom_decrypt_parts(auth_encoded, 3)
        if len(parts) >= 3:
            result.update({
                "uid": parts[0],
                "aid": parts[1],
                "name": parts[2],
            })
            print(f"  [V2] auth decoded: UID={parts[0][:20]}... AID={parts[1][:20]}... Name={parts[2][:30]}...")
    elif "aid" in params and "uid" in params:
        # V1 兼容格式
        result.update({
            "uid": params.get("uid", ""),
            "aid": params.get("aid", ""),
            "name": params.get("name", ""),
        })
        print(f"  [V1] params: UID={result['uid'][:20]}... AID={result['aid'][:20]}... Name={result['name'][:30]}...")

    if "token" in params:
        # V2 格式: token = parseAuthToken(token) → [Token, RefreshToken, ExpireTime]
        token_encoded = params["token"]
        parts = custom_decrypt_parts(token_encoded, 3)
        if len(parts) >= 3:
            expire_time = 0
            try:
                expire_time = int(parts[2])
            except ValueError:
                pass
            result.update({
                "token": parts[0],
                "refresh_token": parts[1],
                "expire_time": expire_time,
            })
            print(f"  [V2] token decoded: Token={parts[0][:20]}... Expire={expire_time}")

    return result


# ============================================================
# PKCE 工具
# ============================================================
def generate_nonce() -> str:
    """生成 nonce (UUID 去横线)"""
    return uuid.uuid4().hex


def generate_pkce() -> tuple:
    """PKCE: (code_verifier, code_challenge_s256)"""
    verifier = secrets.token_urlsafe(32)[:43]
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
    return verifier, challenge


def build_oauth_url(nonce: str, port: int, challenge: str, machine_id: str) -> str:
    """构造 OAuth URL (IDA @ PrepareLoginRequest 0x141a198a0)"""
    params = urllib.parse.urlencode({
        "nonce": nonce,
        "port": port,
        "state": nonce,
        "challenge": challenge,
        "challenge_method": "S256",
        "machine_id": machine_id,
    })
    return f"{OAUTH_BASE_URL}?{params}"


# ============================================================
# LSP WebSocket 通信
# ============================================================
def make_lsp_frame(method: str, params: dict = None, msg_id: int = 1) -> str:
    body = {"jsonrpc": "2.0", "method": method, "id": msg_id}
    if params:
        body["params"] = params
    content = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
    return f"Content-Length: {len(content.encode('utf-8'))}\r\n\r\n{content}"


def parse_lsp_frames(payload: bytes) -> list:
    msgs = []
    offset = 0
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
    """通过 Lingma LSP auth/login 获取 login URL"""
    import websocket as ws_lib

    print("[*] 连接到 Lingma WebSocket...")
    ws = ws_lib.create_connection(f"ws://127.0.0.1:{LSP_PORT}", timeout=10)

    result = {}

    try:
        # Initialize
        ws.send(make_lsp_frame("initialize", {
            "processId": None,
            "clientInfo": {"name": "lingma-37510-sim", "version": "3.0"},
            "rootUri": "file:///C:/sim",
            "capabilities": {},
            "workspaceFolders": [{"uri": "file:///C:/sim", "name": "sim"}],
        }, 1))
        ws.settimeout(3)
        try:
            ws.recv()
        except:
            pass

        # 调用 auth/login
        print("[*] 调用 auth/login...")
        ws.send(make_lsp_frame("auth/login", {}, 3))
        ws.settimeout(30)

        login_url = None
        login_result = None
        auth_report = None
        deadline = time.time() + 25

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
                    login_result = r
                    result_str = json.dumps(r)
                    urls = re.findall(r'https?://[^\s"\']+', result_str)
                    if urls:
                        login_url = urls[0]
                if m.get("method") == "auth/report":
                    auth_report = m.get("params", {})

        ws.close()

        if login_url:
            parsed = urllib.parse.urlparse(login_url)
            qp = urllib.parse.parse_qs(parsed.query)
            params = {k: v[0] for k, v in qp.items()}

            result.update({
                "login_url": login_url,
                "url_params": params,
                "login_result": login_result,
                "auth_report": auth_report or {},
            })
            return result

    except Exception as e:
        print(f"  [!] LSP Error: {e}")
    finally:
        try:
            ws.close()
        except:
            pass

    return {}


# ============================================================
# 后端 API 调用 (模拟 fetchAuthStatusWithUri)
# ============================================================
def call_user_status(machine_id: str, uid: str) -> tuple:
    """
    调用 /api/v3/user/status (IDA @ fetchAuthStatusWithUri 0x141a1f260)
    """
    body = json.dumps({"uid": uid}, separators=(",", ":"))
    url = f"{BIG_MODEL_ENDPOINT}/api/v3/user/status"
    date_str = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
    headers = build_headers(body, machine_id, date_str=date_str)

    req = urllib.request.Request(url, data=body.encode(), headers=headers, method="POST")
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        resp = urllib.request.urlopen(req, context=ctx, timeout=30)
        resp_body = resp.read().decode()
        return resp.status, json.loads(resp_body) if resp_body else {}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode(errors="replace")
        return e.code, {"error": str(e), "body": err_body}
    except Exception as e:
        return 0, {"error": str(e)}


def call_user_login(machine_id: str, aid: str, uid: str, name: str) -> tuple:
    """调用 /api/v3/user/login (模拟 CompleteLoginWithSelectAccount 中的远程调用)"""
    body = json.dumps({"aid": aid, "uid": uid, "name": name}, separators=(",", ":"))
    url = f"{BIG_MODEL_ENDPOINT}/api/v3/user/login"
    date_str = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
    headers = build_headers(body, machine_id, date_str=date_str)

    req = urllib.request.Request(url, data=body.encode(), headers=headers, method="POST")
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        resp = urllib.request.urlopen(req, context=ctx, timeout=30)
        resp_body = resp.read().decode()
        return resp.status, json.loads(resp_body) if resp_body else {}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode(errors="replace")
        return e.code, {"error": str(e), "body": err_body}
    except Exception as e:
        return 0, {"error": str(e)}


# ============================================================
# 37510 HTTP 回调处理
# ============================================================
class CallbackHandler(http.server.BaseHTTPRequestHandler):
    """
    37510 HTTP 回调处理器

    处理流程 (IDA @ LoginCallback 0x141a133a0):
      1. 解析 query 参数
      2. 查找 nonce 验证
      3. parseAuthInfo (V1: aid/uid/name | V2: auth/token)
      4. 返回 HTML 结果页面
    """
    captured = None
    result_event = threading.Event()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        flat = {k: v[0] for k, v in params.items()}

        # 设置 CORS header (模拟 IDA: Access-Control-Allow-Origin: *)
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Connection", "close")
        self.end_headers()

        state = flat.get("state", "")
        has_auth = "auth" in flat
        has_token = "token" in flat
        has_aid = "aid" in flat

        # 验证 nonce
        nonce_valid = state in _nonce_map if state else False

        print(f'\n{"="*60}')
        print(f'[*] 收到 OAuth 回调~ φ(≧ω≦*)♪')
        print(f'  Path: {self.path[:120]}')
        print(f'  State: {state[:40]}...')
        print(f'  Nonce valid: {nonce_valid}')
        print(f'  Format: {"V2 (auth+token)" if has_auth else "V1 (aid/uid/name)" if has_aid else "unknown"}')

        # 解析认证参数 (模拟 parseAuthInfo/parseAuthInfoV2)
        auth_data = parse_auth_v2(flat)

        CallbackHandler.captured = {
            "path": self.path,
            "query_params": flat,
            "auth_data": auth_data,
            "timestamp": time.time(),
            "nonce_valid": nonce_valid,
        }

        # 渲染结果页面 (模拟 loginResultPageWithStep)
        if auth_data.get("uid"):
            uid = auth_data["uid"]
            aid = auth_data.get("aid", uid)
            name = auth_data.get("name", "")
            html = f"""<html><body style="font-family:sans-serif;text-align:center;margin-top:100px">
<h1>✅ 登录成功</h1>
<p>UID: {uid[:20]}...</p>
<p>Name: {name[:30]}</p>
<p>Token: {'✅' if auth_data.get('token') else '❌'}</p>
<p style="color:#888;font-size:12px">你可以关闭此窗口</p>
</body></html>"""
        else:
            html = """<html><body style="font-family:sans-serif;text-align:center;margin-top:100px">
<h1>❌ 登录失败</h1>
<p>未获取到认证参数</p>
</body></html>"""

        self.wfile.write(html.encode('utf-8'))
        CallbackHandler.result_event.set()

    def log_message(self, format, *args):
        pass


# ============================================================
# 凭据保存
# ============================================================
def save_portable_creds(credentials: dict) -> Path:
    config_dir = Path.home() / ".lingma"
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "portable_config.json"

    with open(config_path, "w") as f:
        json.dump(credentials, f, indent=2, ensure_ascii=False)

    print(f"\n[*] 便携凭据已保存到: {config_path}")
    return config_path


# ============================================================
# 主流程
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="Lingma 37510 回调模拟服务器 v3.0")
    parser.add_argument("--standalone", action="store_true",
                        help="完全独立模式 (不依赖 Lingma LSP)")
    parser.add_argument("--port", type=int, default=CALLBACK_PORT,
                        help=f"回调端口 (默认: {CALLBACK_PORT})")
    parser.add_argument("--machine-id", help="Machine ID (自动生成)")
    args = parser.parse_args()

    port = args.port
    machine_id = args.machine_id or str(uuid.uuid4())
    standalone = args.standalone

    print("=" * 60)
    print("Lingma 37510 回调模拟服务器 v3.0")
    print("基于 IDA Pro 逆向 v2.11.2")
    print(f"模式: {'完全独立' if standalone else '通过 Lingma LSP'}")
    print("=" * 60)

    # ========== Phase 1: 获取/生成 Login URL ==========
    print(f"\n{'='*60}")
    print(f"Phase 1: {'生成' if standalone else '获取'} Login URL")
    print(f"{'='*60}")

    if standalone:
        # 完全独立模式: 自己生成 PKCE OAuth URL
        nonce = generate_nonce()
        verifier, challenge = generate_pkce()
        login_url = build_oauth_url(nonce, port, challenge, machine_id)
        login_info = {
            "login_url": login_url,
            "url_params": {"state": nonce, "nonce": nonce},
        }
        # 存储 nonce 上下文 (模拟 qword_1460D9528)
        _nonce_map[nonce] = {"timestamp": time.time(), "verifier": verifier}
        print(f"  [*] Nonce: {nonce[:20]}...")
        print(f"  [*] PKCE Verifier: {verifier[:20]}...")
        print(f"  [*] Login URL: {login_url[:120]}...")
    else:
        login_info = get_login_url_via_lsp()
        if not login_info.get("login_url"):
            print("[!] 获取 login URL 失败，请确保 Lingma 正在运行")
            print("  提示: 使用 --standalone 模式可完全独立运行")
            sys.exit(1)

        login_url = login_info["login_url"]
        url_params = login_info.get("url_params", {})
        state = url_params.get("state", "")
        if state:
            _nonce_map[state] = {"timestamp": time.time(), "via_lsp": True}
        auth_report = login_info.get("auth_report", {})
        if auth_report:
            print(f"  [*] auth/report 推送: {json.dumps(auth_report, ensure_ascii=False)[:200]}")

    # ========== Phase 2: 启动 37510 服务器 ==========
    print(f"\n{'='*60}")
    print(f"Phase 2: 启动回调服务器 :{port}")
    print(f"{'='*60}")

    server = http.server.HTTPServer(("127.0.0.1", port), CallbackHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    print(f"  [*] http://127.0.0.1:{port}/auth/callback")

    # ========== Phase 3: 打开浏览器 ==========
    print(f"\n{'='*60}")
    print(f"Phase 3: 打开浏览器完成登录")
    print(f"{'='*60}")

    final_url = login_info["login_url"]
    # 确保回调端口正确
    if "port=" in final_url and not standalone:
        final_url = re.sub(r'port=(\d+)', f'port={port}', final_url)

    print(f"  URL: {final_url[:120]}...")
    print(f"  请在浏览器中完成认证...")
    webbrowser.open(final_url)

    # ========== Phase 4: 等待回调 ==========
    print(f"\n{'='*60}")
    print(f"Phase 4: 等待 OAuth 回调 (超时 180s)")
    print(f"{'='*60}")

    if not CallbackHandler.result_event.wait(timeout=180):
        print("\n[!] 超时: 未收到回调")
        server.shutdown()
        sys.exit(1)

    server.shutdown()

    callback_data = CallbackHandler.captured
    if not callback_data:
        print("[!] 未捕获到回调数据")
        sys.exit(1)

    params = callback_data.get("query_params", {})
    auth_data = callback_data.get("auth_data", {})

    cb_aid = auth_data.get("aid", params.get("aid", ""))
    cb_uid = auth_data.get("uid", params.get("uid", ""))
    cb_name = auth_data.get("name", params.get("name", ""))
    cb_token = auth_data.get("token", params.get("token", ""))
    cb_refresh = auth_data.get("refresh_token", "")

    if not cb_uid:
        print("[!] 回调中未获取到用户信息")
        print(f"  参数: {json.dumps(params, ensure_ascii=False)[:200]}")
        sys.exit(1)

    # ========== Phase 5: 后端 API 交互 ==========
    print(f"\n{'='*60}")
    print(f"Phase 5: 后端 API 交互")
    print(f"{'='*60}")

    # 5a: 构造 Auth 参数 (IDA @ ToLoginAuthCallbackParam 0x141a1ce00)
    print(f"\n  [*] 构造 Auth/Token 参数...")
    auth_encoded = build_auth_string(cb_uid, cb_aid, cb_name)
    print(f"  Auth ({len(auth_encoded)} chars)")
    if cb_token and cb_refresh:
        expire = int(time.time() * 1000) + 86400000
        token_encoded = build_token_string(cb_token, cb_refresh, expire)
        print(f"  TokenString ({len(token_encoded)} chars)")

    # 5b: 调用 /api/v3/user/login
    print(f"\n  [*] 调用 /api/v3/user/login ...")
    login_status, login_resp = call_user_login(machine_id, cb_aid, cb_uid, cb_name)
    print(f"  -> HTTP {login_status}")
    if login_status == 200:
        print(f"  response: {json.dumps(login_resp, ensure_ascii=False)[:200]}")
    else:
        err = login_resp.get("body", str(login_resp))[:200]
        print(f"  error: {err}")

    # 5c: 调用 /api/v3/user/status (IDA @ GetQuotaAndTokenById)
    print(f"\n  [*] 调用 /api/v3/user/status ...")
    status_code, status_resp = call_user_status(machine_id, cb_uid)
    print(f"  -> HTTP {status_code}")
    if status_code == 200:
        print(f"  response: {json.dumps(status_resp, ensure_ascii=False)[:300]}")

    # ========== Phase 6: 凭据保存 ==========
    print(f"\n{'='*60}")
    print(f"Phase 6: 凭据保存")
    print(f"{'='*60}")

    creds = {
        "machine_id": machine_id,
        "user_id": cb_uid,
        "aid": cb_aid,
        "name": cb_name,
        "security_oauth_token": cb_token,
        "refresh_token": cb_refresh,
        "timestamp": int(time.time()),
    }

    config_path = save_portable_creds(creds)
    print(f"\n[*] 完成! 凭据已保存到 {config_path}")
    print(f"\n  使用 Chat API 测试:")
    print(f"  python -c \"from lingma_remote_api import LingmaRemoteAPI;")
    print(f"  api=LingmaRemoteAPI(portable_config=r'{config_path}');")
    print(f"  print(api.chat('你好'))\"")


if __name__ == "__main__":
    main()
