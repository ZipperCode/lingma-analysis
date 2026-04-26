"""Test auth/login flow via WebSocket — understand OAuth bootstrap."""
import json
import time
import uuid
import websocket
import sys
import re

def make_frame(method, params=None, msg_id=1):
    body = {"jsonrpc": "2.0", "method": method, "id": msg_id}
    if params is not None: body["params"] = params
    content = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
    return f"Content-Length: {len(content.encode('utf-8'))}\r\n\r\n{content}"

def parse_frames(payload):
    msgs = []
    offset = 0
    marker = b"\r\n\r\n"
    while offset < len(payload):
        header_end = payload.find(marker, offset)
        if header_end < 0: break
        header = payload[offset:header_end].decode("ascii", errors="replace")
        cl = None
        for line in header.split("\r\n"):
            if line.lower().startswith("content-length:"):
                cl = int(line.split(":", 1)[1].strip()); break
        if cl is None: break
        body_start = header_end + len(marker)
        body_end = body_start + cl
        if body_end > len(payload): break
        msgs.append(json.loads(payload[body_start:body_end]))
        offset = body_end
    return msgs

print("[*] Connecting to Lingma WebSocket...")
ws = websocket.create_connection("ws://127.0.0.1:37010", timeout=10)

# Initialize
ws.send(make_frame("initialize", {
    "processId": None,
    "clientInfo": {"name": "login-flow-test", "version": "1.0"},
    "rootUri": "file:///C:/test",
    "capabilities": {},
    "workspaceFolders": [{"uri": "file:///C:/test", "name": "workspace"}],
}, 1))
ws.settimeout(3)
try:
    raw = ws.recv()
    for m in parse_frames(raw.encode('utf-8') if isinstance(raw, str) else raw):
        print(f"  init: {json.dumps(m, ensure_ascii=False)[:200]}")
except: pass

# Check current auth status
print("\n=== auth/status ===")
ws.send(make_frame("auth/status", {}, 2))
ws.settimeout(5)
status_data = None
try:
    raw = ws.recv()
    for m in parse_frames(raw.encode('utf-8') if isinstance(raw, str) else raw):
        r = m.get('result', {})
        print(f"  status: {json.dumps(r, ensure_ascii=False)[:300]}")
        status_data = r
except: pass

# Get full auth info (might have more details)
print("\n=== auth/getStatus ===")
ws.send(make_frame("auth/getStatus", {}, 3))
ws.settimeout(5)
try:
    raw = ws.recv()
    for m in parse_frames(raw.encode('utf-8') if isinstance(raw, str) else raw):
        print(f"  getStatus: {json.dumps(m, ensure_ascii=False)[:500]}")
except: pass

# Try auth/getLoginUrl or similar
for method in ["auth/getLoginUrl", "auth/loginUrl", "auth/getAuthUrl", "auth/oauth", "auth/deviceCode"]:
    print(f"\n=== {method} ===")
    ws.send(make_frame(method, {}, 4))
    ws.settimeout(3)
    try:
        raw = ws.recv()
        for m in parse_frames(raw.encode('utf-8') if isinstance(raw, str) else raw):
            if 'error' in m:
                print(f"  error: {m['error'].get('message', m['error'])[:150]}")
            else:
                print(f"  response: {json.dumps(m, ensure_ascii=False)[:500]}")
    except websocket.WebSocketTimeoutException:
        print("  (timeout)")
    except Exception as e:
        print(f"  err: {e}")

# Try sending empty auth/login to trigger login flow
print("\n=== auth/login (trigger) ===")
# Without params - should return login URL
ws.send(make_frame("auth/login", {}, 5))
ws.settimeout(30)  # Login might take longer
login_result = None
try:
    raw = ws.recv()
    for m in parse_frames(raw.encode('utf-8') if isinstance(raw, str) else raw):
        print(f"  login response: {json.dumps(m, ensure_ascii=False)[:800]}")
        if 'result' in m:
            login_result = m['result']
            # Check for login URL
            result_str = json.dumps(m['result'], ensure_ascii=False)
            urls = re.findall(r'https?://[^\s"\']+', result_str)
            for u in urls:
                print(f"\n    URL: {u}")
                # Parse URL params
                from urllib.parse import urlparse, parse_qs
                parsed = urlparse(u)
                params = parse_qs(parsed.query)
                for k, v in params.items():
                    print(f"      {k}: {v[0][:100]}")
except websocket.WebSocketTimeoutException:
    print("  (timeout - login might be waiting for browser)")
except Exception as e:
    print(f"  err: {e}")

# Also listen for push notifications (auth/report)
print("\n[*] Waiting for auth/report push...")
ws.settimeout(15)
try:
    raw = ws.recv()
    for m in parse_frames(raw.encode('utf-8') if isinstance(raw, str) else raw):
        method = m.get('method', '')
        print(f"  push: {method}")
        if method == 'auth/report':
            params = m.get('params', {})
            print(f"    AUTH REPORT: {json.dumps(params, ensure_ascii=False)[:500]}")
except websocket.WebSocketTimeoutException:
    print("  (no push)")
except Exception as e:
    print(f"  err: {e}")

ws.close()
print("\n[*] Done!")
