#!/usr/bin/env python3
"""
Lingma OAuth 半自动获取脚本 — 基于 IDA Pro 逆向分析结果 (๑•̀ㅂ•́)✧

工作原理：
1. 独立生成登录链接（无需 Lingma 运行）：基于逆向分析的 URL 构造逻辑
2. 本地监听 35710 端口，等待 OAuth 回调
3. 捕获认证结果（nonce、auth code、token 等）

用法:
    python lingma_oauth_capture.py              # 默认模式：生成链接 + 监听
    python lingma_oauth_capture.py --port 35711  # 自定义端口
    python lingma_oauth_capture.py --link-only   # 仅生成登录链接，不监听
    python lingma_oauth_capture.py --fresh       # 强制生成新链接（清除旧会话）

IDA 分析发现的关键信息：
- 本地 HTTP 服务器端口：37510（LINGMA_HTTP_PORT 环境变量可配置）
- 登录 URL 路径：/lingma/login（国际版入口）
- OAuth 回调路径：auth/callback
- 国际版登录 URL：https://lingma.alibabacloud.com/lingma/login
- 认证服务器：https://account.alibabacloud.com/login/login.htm
- 嵌套 URL 结构：logout.htm → login.htm → lingma/login（见 callback.html 第 53 行）
"""
import base64
import hashlib
import http.server
import json
import os
import re
import secrets
import sys
import threading
import time
import urllib.parse
import uuid
import webbrowser
from pathlib import Path


# ===== PKCE 工具 =====

def generate_pkce() -> tuple:
    """生成 PKCE 参数: (code_verifier, code_challenge)"""
    verifier = secrets.token_urlsafe(32)[:43]
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
    return verifier, challenge


# ===== 独立生成登录 URL =====

def generate_login_url_standalone(port: int = 35710, region: str = 'intl') -> dict:
    """
    独立生成 Lingma 登录 URL，无需运行 Lingma 程序 (๑•̀ㅂ•́)✧

    基于 IDA Pro 逆向分析的 PrepareLoginRequest 函数逻辑：
    1. 生成 nonce（UUID 去掉 "-"）
    2. 生成 PKCE challenge（verifier + SHA256 challenge）
    3. 构造最内层 URL：https://lingma.alibabacloud.com/lingma/login?...
    4. 嵌套三层 URL 结构（见 callback.html 第 53 行）：
       - 最外层：account.alibabacloud.com/logout/logout.htm?oauth_callback=<middle>
       - 中间层：account.alibabacloud.com/login/login.htm?oauth_callback=<inner>
       - 最内层：lingma.alibabacloud.com/lingma/login?state=...&challenge=...

    Args:
        port: 本地 HTTP 回调服务器端口（默认 35710）
        region: 区域，'intl'（国际版）或 'cn'（国内版）

    Returns:
        dict 包含：
        - login_url: 完整的嵌套登录 URL
        - inner_url: 最内层 lingma/login URL
        - nonce: UUID 去掉 "-"
        - verifier: PKCE code_verifier
        - challenge: PKCE code_challenge
        - machine_id: 生成的设备 ID
    """
    # 1. 生成 nonce（UUID 去掉 "-"，32 字符）
    nonce = uuid.uuid4().hex  # 等同于 uuid4().replace("-", "")

    # 2. 生成 PKCE challenge
    verifier, challenge = generate_pkce()

    # 3. 生成 machine_id（UUID 格式，IDA 分析发现）
    machine_id = str(uuid.uuid4()).upper()

    # 4. 构造 state（格式：1-<nonce>，1- 表示需要完整 OAuth 登录）
    state = f"1-{nonce}"

    # 5. 构造最内层 URL（lingma/login）
    inner_params = {
        'state': state,
        'challenge': challenge,
        'challenge_method': 'S256',
        'machine_id': machine_id,
        'nonce': nonce,
        'port': str(port),
    }
    inner_query = urllib.parse.urlencode(inner_params)

    if region == 'cn':
        # 国内版使用 devops.aliyun.com
        inner_url = f"https://devops.aliyun.com/lingma/login?{inner_query}"
    else:
        # 国际版使用 lingma.alibabacloud.com
        inner_url = f"https://lingma.alibabacloud.com/lingma/login?{inner_query}"

    # 6. 构造中间层 URL（login.htm?oauth_callback=<inner_url_encoded>）
    middle_url = f"https://account.alibabacloud.com/login/login.htm?oauth_callback={urllib.parse.quote(inner_url, safe='')}"

    # 7. 构造最外层 URL（logout.htm?oauth_callback=<middle_url_encoded>）
    # 这是实际打开的 URL，会先清除旧会话，然后跳转到登录页
    full_url = f"https://account.alibabacloud.com/logout/logout.htm?oauth_callback={urllib.parse.quote(middle_url, safe='')}"

    return {
        'login_url': full_url,
        'middle_url': middle_url,
        'inner_url': inner_url,
        'nonce': nonce,
        'verifier': verifier,
        'challenge': challenge,
        'machine_id': machine_id,
        'state': state,
    }


def get_login_url_standalone(port: int = 35710, region: str = 'intl', force_fresh: bool = False) -> dict:
    """
    获取登录 URL（独立生成模式）

    Args:
        port: 本地回调端口
        region: 区域 ('intl' 或 'cn')
        force_fresh: 是否强制生成新链接（总是 True，因为独立生成不需要缓存）

    Returns:
        包含 login_url 等信息的 dict
    """
    return generate_login_url_standalone(port=port, region=region)


# ===== 旧 WebSocket 模式（保留作为备用） =====

def make_frame(method, params=None, msg_id=1):
    """构造 WebSocket JSON-RPC 帧"""
    body = {"jsonrpc": "2.0", "method": method, "id": msg_id}
    if params is not None:
        body["params"] = params
    content = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
    return f"Content-Length: {len(content.encode('utf-8'))}\r\n\r\n{content}"


def parse_frames(payload):
    """解析 Content-Length 分隔的 JSON-RPC 消息"""
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
    """初始化 WebSocket 连接 (发送 initialize)"""
    ws.send(make_frame("initialize", {
        "processId": None,
        "clientInfo": {"name": "oauth-capture", "version": "1.0"},
        "rootUri": "file:///C:/test",
        "capabilities": {},
        "workspaceFolders": [{"uri": "file:///C:/test", "name": "workspace"}],
    }, 1))
    ws.settimeout(3)
    try:
        ws.recv()  # 忽略 initialize 响应
    except Exception:
        pass


def ws_get_login_url(ws, force_fresh=False) -> dict:
    """通过 auth/login 获取真实有效的登录 URL"""
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


# ===== OAuth 回调 HTTP 服务器 =====

class OAuthCallbackHandler(http.server.BaseHTTPRequestHandler):
    """处理 Lingma OAuth 回调的 HTTP 处理器"""
    captured = None  # 类级别存储，用于线程间共享

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        # 保存回调数据
        OAuthCallbackHandler.captured = {
            'method': 'GET',
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
        nonce = params.get('nonce', [None])[0]

        print(f'\n{"="*60}')
        print(f'[*] 收到 OAuth 回调喵~ φ(≧ω≦*)♪')
        print(f'  Path:      {self.path}')
        if code and len(code) > 50:
            print(f'  Code:      {code[:50]}...')
        else:
            print(f'  Code:      {code}')
        print(f'  State:     {state}')
        print(f'  Nonce:     {nonce}')
        print(f'  Error:     {error}')

        # 打印其他参数
        for k, v in OAuthCallbackHandler.captured['query_params'].items():
            if k not in ('code', 'state', 'error', 'nonce'):
                print(f'  {k}:  {str(v)[:100]}')

        if code:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            response_html = '''
            <html><body style="font-family: system-ui; padding: 40px; text-align: center;">
                <h1 style="color: #4CAF50;">✓ OAuth 认证成功喵~</h1>
                <p>授权码已成功捕获，可以关闭此窗口了。</p>
            </body></html>
            '''
            self.wfile.write(response_html.encode('utf-8'))
        elif error:
            self.send_response(400)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(f'<h1>OAuth 错误: {error}</h1>'.encode('utf-8'))
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(b'<h1>Waiting for authentication...</h1>')

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length else b''

        OAuthCallbackHandler.captured = {
            'method': 'POST',
            'path': self.path,
            'body': body.decode('utf-8', errors='replace'),
            'body_hex': body.hex(),
            'headers': dict(self.headers),
            'client_address': self.client_address,
            'timestamp': time.time(),
        }

        print(f'\n{"="*60}')
        print(f'[*] 收到 POST 回调喵~')
        print(f'  Path:      {self.path}')
        print(f'  Body len:  {len(body)}')
        if len(body) < 2000:
            print(f'  Body:      {body.decode("utf-8", errors="replace")}')

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def log_message(self, format, *args):
        pass  # 禁用默认 HTTP 日志


# ===== 登录链接获取 =====

def get_login_url_from_lingma(force_fresh=False) -> dict:
    """
    通过 WebSocket 连接 Lingma 获取真实登录 URL

    这是唯一可靠的方式，因为 URL 包含：
    - PKCE code_challenge (SHA256)
    - nonce (防重放)
    - verifier (服务器端生成)
    - 正确的 redirect_uri 和 port 参数
    """
    try:
        import websocket as wslib
    except ImportError:
        print('[!] 缺少 websocket-client 库，请安装: pip install websocket-client')
        print('[!] 回退到手动模式，但 URL 可能无效...')
        return {'login_url': None, 'error': 'websocket-client not installed'}

    try:
        ws = wslib.create_connection("ws://127.0.0.1:37010", timeout=10)
    except Exception as e:
        print(f'[!] 无法连接 Lingma WebSocket (ws://127.0.0.1:37010): {e}')
        print('[!] 请确保 Lingma.exe 正在运行')
        return {'login_url': None, 'error': str(e)}

    try:
        info = ws_get_login_url(ws, force_fresh=force_fresh)
        ws.close()
        return info
    except Exception as e:
        print(f'[!] 获取登录 URL 失败: {e}')
        try:
            ws.close()
        except Exception:
            pass
        return {'login_url': None, 'error': str(e)}


def link_only(force_fresh=False):
    """仅生成登录链接，不监听回调（独立模式，无需 Lingma 运行）"""
    print('[*] 正在独立生成登录链接喵~ (｡♡‿♡｡)')
    print('[*] 基于 IDA Pro 逆向分析的 URL 构造逻辑')
    print()

    info = get_login_url_standalone(force_fresh=force_fresh)
    login_url = info.get('login_url')

    if login_url:
        print('=== 登录链接 (独立生成) ===')
        print(f'完整 URL（三层嵌套）: {login_url[:200]}...')
        print()

        print('URL 结构解析:')
        print(f'  最内层 (lingma/login):')
        print(f'    state:    {info["state"]}')
        print(f'    challenge:{info["challenge"][:40]}...')
        print(f'    nonce:    {info["nonce"]}')
        print(f'    machine:  {info["machine_id"]}')
        print(f'    port:     35710')
        print()
        print(f'  中间层 (login.htm):  account.alibabacloud.com/login/login.htm')
        print(f'  最外层 (logout.htm): account.alibabacloud.com/logout/logout.htm')
        print()

        # 检查 state 含义
        if info['state'].startswith('2-'):
            print('[!] state=2- 表示已登录 (会跳过浏览器认证)')
            print(f'    如需完整 OAuth 流程，使用 --fresh 参数')
        elif info['state'].startswith('1-'):
            print('[*] state=1- 表示需要完整 OAuth 登录')
    else:
        print(f'[!] 无法生成登录 URL: {info.get("error", "未知错误")}')

    return info


# ===== 主流程 =====

def full_capture(port: int = 35710, timeout: int = 300, force_fresh=False):
    """完整流程：生成链接 + 监听回调（独立模式，无需 Lingma 运行）"""
    print('[*] Lingma OAuth 半自动获取脚本启动喵~ φ(≧ω≦*)♪')
    print(f'[*] 监听端口: {port}')
    print(f'[*] 超时时间: {timeout}s')
    print('[*] 模式：独立生成（基于逆向分析，无需 Lingma 运行）')
    print()

    # 1. 独立生成登录链接
    print('[*] 步骤 1/4: 生成登录 URL (独立模式)...')
    info = get_login_url_standalone(port=port)
    login_url = info.get('login_url')

    if not login_url:
        print(f'[!] 无法生成登录 URL: {info.get("error", "未知错误")}')
        return None

    print(f'[*] 已生成登录 URL ({len(login_url)} 字符)')
    print()

    # 2. 在后台启动 HTTP 回调服务器
    print('[*] 步骤 2/4: 启动 HTTP 回调服务器...')
    server_started = threading.Event()

    def serve():
        server = http.server.HTTPServer(('127.0.0.1', port), OAuthCallbackHandler)
        server.timeout = 1
        server_started.set()

        deadline = time.time() + timeout
        while time.time() < deadline and OAuthCallbackHandler.captured is None:
            server.handle_request()
        server.server_close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    server_started.wait()

    print(f'[*] HTTP 回调服务器已启动: http://127.0.0.1:{port}')
    print()

    # 3. 打开浏览器
    print('[*] 步骤 3/4: 打开浏览器完成登录...')
    print('[*] 是否自动打开浏览器？(Y/n)')
    try:
        choice = input('> ').strip().lower()
    except (EOFError, KeyboardInterrupt):
        choice = 'y'

    if choice != 'n':
        print('[*] 打开浏览器...')
        webbrowser.open(login_url)
    else:
        print('[*] 请手动在浏览器中打开上述链接喵~')

    print()
    print(f'[*] 步骤 4/4: 等待 OAuth 回调 (超时 {timeout}s)...')
    print('    在浏览器中完成登录后，回调数据将显示在这里喵~')

    # 4. 等待回调
    t.join(timeout=timeout + 5)

    # 5. 分析结果
    captured_data = OAuthCallbackHandler.captured

    if captured_data:
        print(f'\n{"="*60}')
        print('=== 拦截结果 ===')

        query_params = captured_data.get('query_params', {})
        code = query_params.get('code')
        state = query_params.get('state')
        nonce = query_params.get('nonce')
        error = query_params.get('error')

        if code:
            print(f'✓ Authorization Code: {code}')
            print(f'✓ State:              {state}')
            if nonce:
                print(f'✓ Nonce:              {nonce}')
            print()
            print(f'[*] 认证成功！授权码已获得喵~ o(*￣︶￣*)o')
            print(f'[*] 可以使用此授权码获取 COSY 凭据')
        elif error:
            print(f'✗ OAuth 错误: {error}')
            print(f'  完整回调数据: {json.dumps(captured_data, indent=2, ensure_ascii=False)}')
        else:
            print(f'完整回调数据: {json.dumps(captured_data, indent=2, ensure_ascii=False)}')

        # 导出结果到文件
        output_file = Path(__file__).parent / 'oauth_result.json'
        with open(output_file, 'w') as f:
            json.dump(captured_data, f, indent=2, ensure_ascii=False)
        print(f'\n[*] 结果已导出到: {output_file}')

        return captured_data
    else:
        print('\n[!] 未收到 OAuth 回调 (可能超时或认证未完成)')
        print('[!] 请检查：')
        print('    1. 是否正确打开了登录链接')
        print('    2. 是否在浏览器中完成了登录')
        print('    3. 回调地址是否正确 (应与 URL 中的 port 参数一致)')
        return None


def main():
    port = 35710  # 默认端口
    timeout = 300  # 5 分钟超时
    region = 'intl'  # 默认国际版
    force_fresh = '--fresh' in sys.argv  # 强制生成新链接

    # 解析命令行参数
    if '--port' in sys.argv:
        idx = sys.argv.index('--port')
        if idx + 1 < len(sys.argv):
            port = int(sys.argv[idx + 1])

    if '--timeout' in sys.argv:
        idx = sys.argv.index('--timeout')
        if idx + 1 < len(sys.argv):
            timeout = int(sys.argv[idx + 1])

    if '--region' in sys.argv:
        idx = sys.argv.index('--region')
        if idx + 1 < len(sys.argv):
            region = sys.argv[idx + 1]
            if region not in ('intl', 'cn'):
                print(f'[!] 无效区域: {region}，使用默认 intl')
                region = 'intl'

    if '--link-only' in sys.argv:
        link_only(force_fresh=force_fresh)
        return

    full_capture(port, timeout, force_fresh=force_fresh)


if __name__ == '__main__':
    main()
