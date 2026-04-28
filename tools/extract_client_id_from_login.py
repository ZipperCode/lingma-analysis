#!/usr/bin/env python3
"""
从 Lingma WebSocket 获取 login URL，然后跟踪 HTTP 重定向链来提取 client_id。

原理：
  Lingma 的 login/generateUrl 返回的 URL 会 302 到 signin.aliyun.com/oauth2/v1/auth，
  其中包含 client_id 参数。我们通过跟踪 HTTP 302 链来提取它。

使用：
  python tools/extract_client_id_from_login.py
"""

import urllib.request
import urllib.error
import ssl
import re
import json
import sys
import websocket

LSP_PORT = 37010


def get_login_url_from_lingma(port=LSP_PORT):
    """通过 WebSocket login/generateUrl 获取 login URL"""
    ws = websocket.create_connection(f"ws://127.0.0.1:{port}", timeout=10)

    def send_lsp(method, params=None, msg_id=1):
        body = json.dumps({
            "jsonrpc": "2.0", "id": msg_id,
            "method": method,
            "params": params or {}
        }, ensure_ascii=False)
        frame = f"Content-Length: {len(body.encode('utf-8'))}\r\n\r\n{body}"
        ws.send(frame)

    def recv_lsp(timeout=5):
        ws.settimeout(timeout)
        try:
            raw = ws.recv()
            text = raw if isinstance(raw, str) else raw.decode()
            # 解析 LSP frame
            if '\r\n\r\n' in text:
                headers, body = text.split('\r\n\r\n', 1)
                for line in headers.split('\r\n'):
                    if line.lower().startswith('content-length:'):
                        length = int(line.split(':')[1].strip())
                        return json.loads(body[:length])
            return json.loads(text)
        except:
            return None

    # Initialize
    send_lsp("initialize", {
        "processId": None,
        "clientInfo": {"name": "client-id-extractor", "version": "1.0"},
        "rootUri": "file:///tmp/extract",
        "capabilities": {},
        "workspaceFolders": [{"uri": "file:///tmp/extract", "name": "extract"}],
    }, 1)
    recv_lsp(3)  # 跳过 init 响应

    # 获取 login URL
    send_lsp("login/generateUrl", {}, 2)
    resp = recv_lsp(10)
    ws.close()

    if resp is None:
        print("[!] No response from login/generateUrl")
        return None

    result = resp.get("result", {})
    login_url = result.get("loginUrl", "")

    if login_url:
        print(f"[*] loginUrl: {login_url}")
        print(f"[*] verifier: {result.get('verifier', 'N/A')[:20]}...")
        print(f"[*] challenge: {result.get('challenge', 'N/A')[:20]}...")
        return login_url

    print(f"[!] No loginUrl in response: {json.dumps(resp, ensure_ascii=False)[:500]}")
    return None


def follow_redirect_chain(start_url, max_redirects=10):
    """跟踪 HTTP 302 重定向链，在每个 URL 中搜索 client_id"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # 不自动跟随重定向
    class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(NoRedirectHandler)
    handler = urllib.request.HTTPCookieProcessor()
    opener.add_handler(handler)

    current_url = start_url
    found_client_id = None

    for i in range(max_redirects):
        print(f"\n[{i}] GET {current_url[:150]}")

        # search URL for client_id
        if 'client_id=' in current_url or 'client_id%3D' in current_url:
            match = re.search(r'client_id[=%]3D([a-zA-Z0-9_\-\.]+)', current_url, re.IGNORECASE)
            if match:
                found_client_id = match.group(1)
                print(f"  >>> CLIENT_ID FOUND: {found_client_id} <<<")

        req = urllib.request.Request(current_url, method='GET')
        req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')

        try:
            resp = opener.open(req, timeout=30)
        except urllib.error.HTTPError as e:
            print(f"  HTTP {e.code}")
            # 读取响应体，可能包含登录页面
            body = e.read().decode('utf-8', errors='replace')[:500]
            # 从页面内容中搜索 client_id
            for pat in [r'client_id[=:]\s*([a-zA-Z0-9_\-\.]{4,100})',
                         r'client_id%3D([a-zA-Z0-9_\-\.]+)',
                         r'"client_id"\s*:\s*"([^"]+)"']:
                match = re.search(pat, body, re.IGNORECASE)
                if match:
                    found_client_id = match.group(1)
                    print(f"  >>> CLIENT_ID FOUND IN BODY: {found_client_id} <<<")
            break
        except Exception as e:
            print(f"  Error: {e}")
            break

        print(f"  Status: {resp.status}")

        # 检查最终 URL（如果被重定向了）
        final_url = resp.geturl()
        if final_url != current_url:
            print(f"  -> {final_url[:150]}")
            if 'client_id=' in final_url:
                match = re.search(r'client_id=([a-zA-Z0-9_\-\.]+)', final_url)
                if match:
                    found_client_id = match.group(1)
                    print(f"  >>> CLIENT_ID FOUND: {found_client_id} <<<")

        # 检查 Location header
        location = resp.headers.get('Location', '')
        if location:
            print(f"  Location: {location[:150]}")

            if 'client_id=' in location:
                match = re.search(r'client_id=([a-zA-Z0-9_\-\.]+)', location)
                if match:
                    found_client_id = match.group(1)
                    print(f"  >>> CLIENT_ID FOUND IN REDIRECT: {found_client_id} <<<")

            # 处理相对 URL
            if location.startswith('/'):
                from urllib.parse import urljoin
                current_url = urljoin(current_url, location)
            else:
                current_url = location

            # 检查是否是登录页面（需要浏览器交互）
            if 'login' in location.lower() and ('account.aliyun.com' in location or 'account.alibabacloud.com' in location):
                print(f"\n  [!] Redirected to login page.")
                print(f"  [!] This requires browser-based login. client_id may NOT be visible until after login.")
                print(f"  [!] Use the browser method in docs/topics/client-id-extraction.md")
                break
        else:
            # 没有 Location header，可能是最终页面或登录页面
            body = resp.read().decode('utf-8', errors='replace')[:5000]
            # 搜索可能嵌入的 redirect URL
            for pat in [
                r'https?://signin\.(?:aliyun|alibabacloud)\.com/oauth2/v1/auth\?[^"\'\s]{0,300}',
                r'client_id[=:]\s*([a-zA-Z0-9_\-\.]{4,100})',
            ]:
                matches = re.findall(pat, body, re.IGNORECASE)
                for m in matches:
                    print(f"  Found in body: {m[:200]}")
                    if 'client_id=' in m:
                        cid_match = re.search(r'client_id=([a-zA-Z0-9_\-\.]+)', m)
                        if cid_match and not found_client_id:
                            found_client_id = cid_match.group(1)
                            print(f"  >>> CLIENT_ID FOUND: {found_client_id} <<<")
            break

        if found_client_id:
            break

    return found_client_id


def main():
    print("=" * 60)
    print("Lingma client_id Extractor — via Login URL Redirect Chain")
    print("=" * 60)

    # 方法 1: 从 Lingma WebSocket 获取 login URL
    print("\n[*] Getting login URL from Lingma WebSocket...")
    login_url = get_login_url_from_lingma()

    if not login_url:
        print("[!] Failed to get login URL. Is Lingma running?")
        print("[!] Make sure Lingma is running and port 37010 is accessible.")
        sys.exit(1)

    # 方法 2: 跟踪 HTTP 302 重定向链
    print("\n[*] Following HTTP redirect chain to find client_id...")
    print("    (This may not work if login page requires browser cookies/session)")
    client_id = follow_redirect_chain(login_url)

    if client_id:
        print("\n" + "=" * 60)
        print(f"SUCCESS! client_id = {client_id}")
        print("=" * 60)
        print("\nSave it for later use:")
        print(f"  echo '{client_id}' > lingma2api/configs/client_id.txt")
    else:
        print("\n" + "=" * 60)
        print("client_id NOT found via HTTP redirect chain.")
        print("This is expected — the OAuth redirect only happens AFTER browser login.")
        print("=" * 60)
        print("\nRecommended next steps:")
        print("1. Use the browser method: docs/topics/client-id-extraction.md")
        print("2. Open this URL in a browser and check DevTools Network:")
        print(f"   {login_url}")
        print("3. Or use Frida to hook the binary during refresh operations:")
        print("   python tools/frida_find_client_id.py")


if __name__ == '__main__':
    main()
