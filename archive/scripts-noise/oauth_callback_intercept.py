#!/usr/bin/env python3
"""
Lingma OAuth 回调拦截器 — 脱离本地 Lingma 的干净凭据引导方案.

在本地启动 HTTP 服务器，拦截 OAuth/登录回调，捕获凭据信息.
成功后导出的凭据可移植到任意机器使用.

用法:
    # 方案 A: 独立拦截 (停止 Lingma, 占用 37510 端口)
    python oauth_callback_intercept.py --standalone

    # 方案 B: 监听自定义端口 (需要 Lingma 运行, 修改 login URL 的 port 参数)
    python oauth_callback_intercept.py --port 37511

    # 方案 C: 仅观察当前 login 流程 (不拦截, 仅分析 login URL)
    python oauth_callback_intercept.py --analyze-only

工作原理:
    OAuth PKCE 流程:
    1. 生成 PKCE code_verifier → S256 code_challenge
    2. 构建 login URL → 浏览器完成认证
    3. 拦截回调 → 获取 authorization code
    4. 交换 code → 获取 bearer token (需要 client_id)

    Lingma 特有流程:
    - login URL 由 Lingma 服务器生成 (client_id 在服务器端)
    - 回调域名 = localhost:<port> (port 默认为 37510)
    - 回调后 Lingma 服务器返回凭据 (key + encrypt_user_info + tokens)
"""
import base64
import hashlib
import http.server
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import time
import urllib.parse
import uuid
import webbrowser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from lingma_remote_api import LingmaRemoteAPI


# ===== PKCE 工具 =====

def generate_pkce() -> tuple:
    """生成 PKCE 参数: (code_verifier, code_challenge)"""
    verifier = secrets.token_urlsafe(32)[:43]  # 43 chars
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
    return verifier, challenge


# ===== OAuth 回调 HTTP 服务器 =====

class OAuthCallbackHandler(http.server.BaseHTTPRequestHandler):
    captured = None  # 类级别存储

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        OAuthCallbackHandler.captured = {
            'path': self.path,
            'query_params': {k: v[0] if len(v) == 1 else v for k, v in params.items()},
            'headers': dict(self.headers),
            'client_address': self.client_address,
            'timestamp': time.time(),
        }

        # 提取关键参数
        code = params.get('code', [None])[0]
        state = params.get('state', [None])[0]
        error = params.get('error', [None])[0]

        print(f'\n{"="*60}')
        print(f'[*] 收到 OAuth 回调喵~ φ(≧ω≦*)♪')
        print(f'  Path:      {self.path}')
        print(f'  Code:      {code[:50] if code else "N/A"}...' if code and len(code) > 50 else f'  Code:      {code}')
        print(f'  State:     {state}')
        print(f'  Error:     {error}')
        for k, v in (OAuthCallbackHandler.captured['query_params'] or {}).items():
            if k not in ('code', 'state', 'error'):
                print(f'  {k}:  {str(v)[:100]}')

        if code:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(b'<h1>OK - Authorization code captured</h1><p>You may close this window.</p>')
        else:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'Error: no code')

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length else b''

        OAuthCallbackHandler.captured = {
            'path': self.path,
            'method': 'POST',
            'body': body.decode('utf-8', errors='replace'),
            'body_hex': body.hex(),
            'headers': dict(self.headers),
            'client_address': self.client_address,
            'timestamp': time.time(),
        }

        print(f'\n{"="*60}')
        print(f'[*] 收到 POST 回调喵~')
        print(f'  Path:      {self.path}')
        print(f'  Body:      {body[:500]}')
        print(f'  Body len:  {len(body)}')

        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'OK')

    def log_message(self, format, *args):
        pass  # 禁用 HTTP 日志


def run_callback_server(port: int, timeout: int = 120):
    """启动 HTTP 回调服务器，等待 OAuth 回调"""
    server = http.server.HTTPServer(('127.0.0.1', port), OAuthCallbackHandler)
    server.timeout = 1

    print(f'[*] HTTP 回调服务器已启动: http://127.0.0.1:{port}')
    print(f'[*] 等待 OAuth 回调 (超时 {timeout}s)...')

    deadline = time.time() + timeout
    while time.time() < deadline and OAuthCallbackHandler.captured is None:
        server.handle_request()

    server.server_close()
    return OAuthCallbackHandler.captured


# ===== Lingma WebSocket 通信 =====

def make_frame(method, params=None, msg_id=1):
    body = {"jsonrpc": "2.0", "method": method, "id": msg_id}
    if params is not None:
        body["params"] = params
    content = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
    return f"Content-Length: {len(content.encode('utf-8'))}\r\n\r\n{content}"


def parse_frames(payload):
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


def ws_initialize(ws):
    ws.send(make_frame("initialize", {
        "processId": None,
        "clientInfo": {"name": "oauth-interceptor", "version": "1.0"},
        "rootUri": "file:///C:/test",
        "capabilities": {},
        "workspaceFolders": [{"uri": "file:///C:/test", "name": "workspace"}],
    }, 1))
    ws.settimeout(3)
    try:
        ws.recv()
    except Exception:
        pass


def ws_get_login_url(ws, force_fresh=False) -> dict:
    """获取登录 URL 及所有参数"""
    import websocket as wslib

    ws_initialize(ws)

    if force_fresh:
        print('[*] 调用 auth/logout 清除会话...')
        ws.send(make_frame("auth/logout", {}, 2))
        ws.settimeout(3)
        try:
            ws.recv()
        except Exception:
            pass

    print('[*] 调用 auth/login 获取登录 URL...')
    ws.send(make_frame("auth/login", {}, 3))
    ws.settimeout(30)

    login_result = None
    auth_report = None

    deadline = time.time() + 25
    while time.time() < deadline:
        try:
            raw = ws.recv()
        except wslib.WebSocketTimeoutException:
            continue
        except Exception as e:
            print(f'  err: {e}')
            break

        for m in parse_frames(raw.encode('utf-8') if isinstance(raw, str) else raw):
            if 'result' in m and 'url' in str(m.get('result', {})):
                login_result = m['result']
            if m.get('method') == 'auth/report':
                auth_report = m.get('params', {})

            if login_result and auth_report:
                break

    # 解析 login URL
    info = {'result': login_result, 'auth_report': auth_report}

    if login_result:
        result_str = json.dumps(login_result)
        urls = re.findall(r'https?://[^\s"\']+', result_str)
        if urls:
            info['login_url'] = urls[0]
            parsed = urllib.parse.urlparse(urls[0])
            url_params = urllib.parse.parse_qs(parsed.query)
            info['url_params'] = {k: v[0] for k, v in url_params.items()}

    return info


# ===== 主流程 =====

def analyze_only():
    """仅分析 login 流程，不拦截回调"""
    import websocket as wslib

    print("[*] 连接到 Lingma WebSocket...")
    ws = wslib.create_connection("ws://127.0.0.1:37010", timeout=10)

    info = ws_get_login_url(ws)
    print(f'\n{"="*60}')
    print('=== Login URL 分析 ===')
    print(f'URL: {info.get("login_url", "N/A")}')

    url_params = info.get('url_params', {})
    if url_params:
        print(f'\nURL 参数:')
        for k, v in url_params.items():
            print(f'  {k}: {v[:80] if len(str(v)) > 80 else v}')

    auth_report = info.get('auth_report', {})
    if auth_report:
        print(f'\nauth/report 推送:')
        for k, v in auth_report.items():
            print(f'  {k}: {str(v)[:80]}')

    # 显示 state 含义
    state = url_params.get('state', '')
    if state.startswith('2-'):
        print(f'\n[!] state=2- 表示已登录 (会跳过浏览器认证)')
        print(f'    如需完整 OAuth 流程，需要先 auth/logout 清除会话')
    elif state.startswith('1-'):
        print(f'[*] state=1- 表示需要完整 OAuth 登录')

    ws.close()
    return info


def standalone_intercept():
    """停止 Lingma，独立拦截回调"""
    import websocket as wslib

    # 1. 获取 login URL (需要 Lingma)
    print("[*] 连接到 Lingma WebSocket...")
    ws = wslib.create_connection("ws://127.0.0.1:37010", timeout=10)

    info = ws_get_login_url(ws, force_fresh=True)
    ws.close()

    login_url = info.get('login_url')
    if not login_url:
        print('[!] 无法获取登录 URL，可能需要先完成首次登录')
        return

    print(f'\n[*] 登录 URL: {login_url[:150]}...')

    # 2. 停止 Lingma 释放 37510 端口
    print('\n[*] 停止 Lingma 以释放 37510 端口...')
    subprocess.run(['taskkill', '/f', '/im', 'Lingma.exe'],
                   capture_output=True, timeout=10)
    time.sleep(2)

    # 3. 启动我们的 HTTP 服务器
    print('[*] 启动拦截服务器...')

    # 解析 port 参数
    url_params = info.get('url_params', {})
    port = int(url_params.get('port', 37510))

    # 在后台线程启动服务器
    import threading
    captured = [None]
    server_started = threading.Event()

    def serve():
        server = http.server.HTTPServer(('127.0.0.1', port), OAuthCallbackHandler)
        server.timeout = 1
        server_started.set()
        deadline = time.time() + 180
        while time.time() < deadline and captured[0] is None:
            server.handle_request()
        server.server_close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    server_started.wait()

    # 4. 打开浏览器
    print(f'\n[*] 打开浏览器完成登录...')
    print(f'    URL: {login_url[:120]}...')
    webbrowser.open(login_url)

    # 5. 等待回调
    print(f'[*] 等待 OAuth 回调到 http://127.0.0.1:{port} ...')
    t.join(timeout=180)

    captured_data = OAuthCallbackHandler.captured

    # 6. 恢复 Lingma
    print('\n[*] 恢复 Lingma...')
    subprocess.Popen(
        [r'C:\Users\Zipper\.lingma\bin\2.11.2\x86_64_windows\Lingma.exe', 'start'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # 7. 分析结果
    if captured_data:
        print(f'\n{"="*60}')
        print('=== 拦截结果 ===')
        code = captured_data.get('query_params', {}).get('code')
        if code:
            print(f'Authorization Code: {code}')
            print(f'\n[*] 授权码已获得！可以用于获取 COSY 凭据')
            print(f'[*] 但由于 client_id 在服务器端，需要额外步骤交换凭据')
        else:
            print(f'完整回调数据: {json.dumps(captured_data, indent=2, ensure_ascii=False)}')
    else:
        print('\n[!] 未收到回调 (可能 OAuth 已在 Lingma 进程中完成)')

    return captured_data


def main():
    if '--analyze-only' in sys.argv:
        analyze_only()
    elif '--standalone' in sys.argv:
        standalone_intercept()
    elif '--port' in sys.argv:
        idx = sys.argv.index('--port')
        port = int(sys.argv[idx + 1]) if idx + 1 < len(sys.argv) else 37511
        print(f'[*] 监听端口 {port}')
        run_callback_server(port, timeout=300)
    else:
        print(__doc__)
        print('\n请选择运行模式喵~')
        print('  --analyze-only   仅分析 login 流程')
        print('  --standalone     独立拦截 (停止 Lingma)')
        print('  --port PORT      监听自定义端口')


if __name__ == '__main__':
    main()
