#!/usr/bin/env python3
"""
Lingma 37510 回调模拟服务器 — 完整实现
基于 IDA Pro 逆向分析 v2.11.2

实现链路:
  auth/login LSP → DeviceLogin (nonce管理+Auth编码)
  → 浏览器认证 → 回调37510 → HandleAuthCallback
  → GetQuotaAndTokenById → fetchAuthStatusWithUri
  → CompleteUserLogin → 凭据保存

使用方法:
  1. 确保 Lingma 正在运行 (提供 LSP WebSocket 获取 login URL)
  2. python tools/lingma_37510_server.py
  3. 浏览器中完成登录
  4. COSY 凭据自动保存
"""
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

# Cosy-Key (IDA @ addBigModelSignatureHeaders)
COSY_KEY = "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="
ALT_COSY_KEY = "&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe"

# API 端点
BIG_MODEL_ENDPOINT = "https://lingma.alibabacloud.com/algo"

# 自定义 base64 字母表 (IDA: encodeToString 逆向)
ALPHA = '_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!'
STD_B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

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


# ============================================================
# 签名算法 (IDA @ addBigModelSignatureHeaders 0x14087e5e0)
# ============================================================
def md5_sign(encoded_body: str, date_str: str, use_alt_key: bool = False) -> str:
    """
    MD5(payload + "&" + key + "&" + date)
    - payload = base64(body) = Cosy-User header
    - key = Cosy-Key (硬编码)
    - date = RFC1123
    """
    key = ALT_COSY_KEY if use_alt_key else COSY_KEY
    raw = f"{encoded_body}&{key}&{date_str}"
    return hashlib.md5(raw.encode()).hexdigest()


# ============================================================
# 请求头构造 (IDA @ addBasicHeaders 0x14087ef20)
# ============================================================
def build_headers(body_str: str, machine_id: str, client_type: str = "2",
                  cosy_version: str = "20", date_str: str = None) -> dict:
    """构造完整请求头 (基础头 + 签名头)"""
    if date_str is None:
        date_str = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')

    encoded = base64.b64encode(body_str.encode()).decode()

    headers = {
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
    return headers


# ============================================================
# Auth/TokenString 编码 (IDA @ ToLoginAuthCallbackParam 0x141a1ce00)
# ============================================================
def build_auth_string(uid: str, aid: str, name: str, org_id: str = "") -> str:
    """
    构造 Auth 参数
    1. JSON marshal CallbackAuthInfo {UID, AID, Name, OrgId}
    2. encodeToString (自定义base64)
    3. URL-escape
    """
    auth_info = {"UID": uid, "AID": aid, "Name": name}
    if org_id:
        auth_info["OrgId"] = org_id
    auth_json = json.dumps(auth_info, ensure_ascii=False, separators=(",", ":"))
    encoded = encode_to_string(auth_json.encode())
    return urllib.parse.quote(encoded, safe='')


def build_token_string(token: str, refresh_token: str, expire_time: int) -> str:
    """
    构造 TokenString 参数
    1. fmt.Sprintf("%s\n%s\n%d", token, refresh_token, expireTime)
    2. encodeToString
    3. URL-escape
    """
    formatted = f"{token}\n{refresh_token}\n{expire_time}"
    encoded = encode_to_string(formatted.encode())
    return urllib.parse.quote(encoded, safe='')


def parse_auth_string(auth_str: str) -> dict:
    """
    解析 Auth 参数 (IDA @ parseAuthInfoV3 0x141a21b80)
    1. URL-unescape
    2. decodeString (自定义base64)
    3. JSON parse
    """
    unescaped = urllib.parse.unquote(auth_str)
    decoded = decode_string(unescaped)
    return json.loads(decoded.decode())


# ============================================================
# PKCE 工具
# ============================================================
def generate_nonce() -> str:
    """生成 nonce (UUID 去横线) — 对应 github.com/google/uuid + strings.Replace"""
    return uuid.uuid4().hex  # 32 chars, no dashes


def generate_pkce() -> tuple:
    """PKCE: (code_verifier, code_challenge_s256)"""
    verifier = secrets.token_urlsafe(32)[:43]
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
    return verifier, challenge


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
    """
    通过 Lingma LSP auth/login 获取 login URL
    同时捕获 auth/report 推送的 token 信息
    """
    import websocket as ws_lib

    print("[*] 连接到 Lingma WebSocket...")
    ws = ws_lib.create_connection(f"ws://127.0.0.1:{LSP_PORT}", timeout=10)

    result = {}

    try:
        # Initialize
        ws.send(make_lsp_frame("initialize", {
            "processId": None,
            "clientInfo": {"name": "lingma-37510-sim", "version": "2.0"},
            "rootUri": "file:///C:/sim",
            "capabilities": {},
            "workspaceFolders": [{"uri": "file:///C:/sim", "name": "sim"}],
        }, 1))
        ws.settimeout(3)
        try:
            ws.recv()
        except:
            pass

        # 先获取当前状态
        ws.send(make_lsp_frame("auth/getStatus", {}, 2))
        ws.settimeout(5)
        try:
            raw = ws.recv()
            for m in parse_lsp_frames(raw.encode() if isinstance(raw, str) else raw):
                r = m.get("result", {})
                if r:
                    result["pre_status"] = r
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
            except Exception as e:
                print(f"  [!] {e}")
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

            print(f"  [*] Login URL: {login_url[:100]}...")
            return result
        else:
            print("  [!] 未获取到 login URL")
            return {}

    except Exception as e:
        print(f"  [!] LSP Error: {e}")
        return {}
    finally:
        try:
            ws.close()
        except:
            pass


# ============================================================
# 后端 API 调用 (模拟 fetchAuthStatusWithUri)
# ============================================================
def call_user_status(machine_id: str, uid: str) -> tuple:
    """
    调用 /api/v3/user/status 获取用户状态和凭据
    对应 IDA: fetchAuthStatusWithUri("/api/v3/user/status")
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
    """调用 /api/v3/user/login 进行登录"""
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
# 回调处理 (模拟 HandleAuthCallback 0x141a18dc0)
# ============================================================
class CallbackHandler(http.server.BaseHTTPRequestHandler):
    """37510 HTTP 回调处理器"""
    captured = None
    result_event = threading.Event()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        flat = {k: v[0] for k, v in params.items()}

        CallbackHandler.captured = {
            "path": self.path,
            "query_params": flat,
            "timestamp": time.time(),
        }

        print(f'\n{"="*60}')
        print(f'[*] 收到 OAuth 回调喵~ φ(≧ω≦*)♪')
        print(f'  state: {flat.get("state", "N/A")}')
        print(f'  aid:   {flat.get("aid", "N/A")}')
        print(f'  uid:   {flat.get("uid", "N/A")}')
        print(f'  name:  {flat.get("name", "N/A")}')

        # 返回 HTML (模拟 loginResultPageWithStep)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(
            b"<html><body><h1>Login successful</h1>"
            b"<p>You may close this window.</p></body></html>"
        )

        CallbackHandler.result_event.set()

    def log_message(self, format, *args):
        pass


# ============================================================
# 凭据保存
# ============================================================
def save_portable_creds(credentials: dict) -> Path:
    """保存便携凭据"""
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
    print("=" * 60)
    print("Lingma 37510 回调模拟服务器 v2.0")
    print("基于 IDA Pro 逆向分析 v2.11.2")
    print("=" * 60)

    # 生成 machine_id
    machine_id = str(uuid.uuid4())
    print(f"[*] Machine ID: {machine_id}")

    # ── Phase 1: 获取 login URL ──
    print(f"\n{'='*60}")
    print(f"Phase 1: 获取 Login URL (LSP :{LSP_PORT})")
    print(f"{'='*60}")

    login_info = get_login_url_via_lsp()
    if not login_info.get("login_url"):
        print("[!] 获取 login URL 失败")
        print("  请确保 Lingma 正在运行")
        sys.exit(1)

    login_url = login_info["login_url"]
    auth_report = login_info.get("auth_report", {})
    url_params = login_info.get("url_params", {})

    # 从 url_params 提取 state 和其他参数
    state = url_params.get("state", "")
    print(f"\n  state: {state[:40]}...")

    # 检查是否已有 auth/report (已登录状态)
    if auth_report:
        print(f"\n  [*] auth/report 推送:")
        for k in ("token", "refreshToken", "uid", "name"):
            if k in auth_report:
                v = str(auth_report[k])[:40]
                print(f"    {k}: {v}...")

    # ── Phase 2: 启动 37510 服务器 ──
    print(f"\n{'='*60}")
    print(f"Phase 2: 启动回调服务器 :{CALLBACK_PORT}")
    print(f"{'='*60}")

    server = http.server.HTTPServer(("127.0.0.1", CALLBACK_PORT), CallbackHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    print(f"  [*] http://127.0.0.1:{CALLBACK_PORT}/auth/callback")

    # ── Phase 3: 打开浏览器 ──
    print(f"\n{'='*60}")
    print(f"Phase 3: 打开浏览器完成登录")
    print(f"{'='*60}")

    # 如果 URL 中的 redirect_port 不是 37510，修改 URL
    final_url = login_url
    if "port=" in login_url:
        # 修改 redirect_uri 中的端口
        final_url = re.sub(r'port=(\d+)', f'port={CALLBACK_PORT}', login_url)
        # 也要修改 redirect_uri 参数中的端口
        final_url = re.sub(
            r'redirect_uri=[^&]*127\.0\.0\.1%3A\d+',
            f'redirect_uri=http%3A%2F%2F127.0.0.1%3A{CALLBACK_PORT}%2Fauth%2Fcallback',
            final_url
        )

    print(f"  URL: {final_url[:120]}...")
    webbrowser.open(final_url)

    # ── Phase 4: 等待回调 ──
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
    cb_aid = params.get("aid", "")
    cb_uid = params.get("uid", "")
    cb_name = params.get("name", "")
    cb_state = params.get("state", "")

    # ── Phase 5: 处理后端 API 交互 ──
    print(f"\n{'='*60}")
    print(f"Phase 5: 后端 API 交互")
    print(f"{'='*60}")

    # 5a: 构造 Auth 和 TokenString (模拟 ToLoginAuthCallbackParam)
    print(f"\n  [*] 构造 Auth 参数...")
    auth = build_auth_string(cb_uid, cb_aid, cb_name)
    print(f"  Auth ({len(auth)} chars): {auth[:60]}...")

    # 如果 auth/report 中有 token，构造 TokenString
    token = auth_report.get("token", "") if auth_report else ""
    refresh_token = auth_report.get("refreshToken", "") if auth_report else ""
    expire_time = auth_report.get("tokenExpireTime", 0) if auth_report else 0

    if token and refresh_token:
        token_str = build_token_string(token, refresh_token, int(time.time() * 1000) + 86400000)
        print(f"  TokenString ({len(token_str)} chars)")
    else:
        token_str = ""
        print(f"  TokenString: (空)")

    # 5b: 调用 /api/v3/user/login
    print(f"\n  [*] 调用 /api/v3/user/login ...")
    login_status, login_resp = call_user_login(machine_id, cb_aid, cb_uid, cb_name)
    print(f"  -> HTTP {login_status}")

    if login_status == 200:
        print(f"  response: {json.dumps(login_resp, ensure_ascii=False)[:200]}")
    elif login_status != 0:
        err = login_resp.get("body", str(login_resp))[:200]
        print(f"  error: {err}")
    else:
        print(f"  error: {login_resp.get('error', 'unknown')}")

    # 5c: 调用 /api/v3/user/status
    print(f"\n  [*] 调用 /api/v3/user/status ...")
    status_code, status_resp = call_user_status(machine_id, cb_uid)
    print(f"  -> HTTP {status_code}")

    user_data = {}
    if status_code == 200:
        print(f"  response keys: {list(status_resp.keys())[:10]}")
        user_data = status_resp
    elif status_code != 0:
        err = status_resp.get("body", str(status_resp))[:200]
        print(f"  error: {err}")

    # ── Phase 6: 结果 ──
    print(f"\n{'='*60}")
    print(f"Phase 6: 结果")
    print(f"{'='*60}")

    if status_code == 200:
        print(f"\n  [✓] 后端 API 调用成功！")
        print(f"  用户状态: {json.dumps(user_data, ensure_ascii=False)[:300]}")
    elif login_status == 200:
        print(f"\n  [~] Login 成功但 Status 失败")
    else:
        print(f"\n  [✗] 后端 API 调用失败")
        print(f"  API 可能被 WAF 拦截，需要检查签名和请求头是否正确")
        print(f"\n  建议:")
        print(f"  1. 使用 Frida 抓包对比 lingma 的实际请求")
        print(f"  2. 检查 endpoint 是否匹配 ({BIG_MODEL_ENDPOINT})")
        print(f"  3. 尝试国内端点")

    # 保存凭据 (如果已从 auth/report 获取)
    if auth_report:
        creds = {
            "machine_id": machine_id,
            "user_id": auth_report.get("uid", cb_uid),
            "user_name": auth_report.get("name", cb_name),
            "security_oauth_token": auth_report.get("token", ""),
            "refresh_token": auth_report.get("refreshToken", ""),
            "expire_time": auth_report.get("tokenExpireTime", 0),
        }
        save_path = save_portable_creds(creds)
        print(f"\n  使用方式:")
        print(f"    from lingma_remote_api import LingmaRemoteAPI")
        print(f"    api = LingmaRemoteAPI(config_file=r'{save_path}')")
        print(f"    api.chat('你好')")

    print(f"\n[*] 完成！喵~ o(*￣︶￣*)o")


if __name__ == "__main__":
    main()
