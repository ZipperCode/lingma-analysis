#!/usr/bin/env python3
"""Track OAuth redirect chain to find client_id."""
import json, re, time, urllib.parse
import websocket
import urllib3
urllib3.disable_warnings()
import requests


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


print("[*] Connecting WebSocket...")
ws = websocket.create_connection("ws://127.0.0.1:37010", timeout=10)
ws.send(make_frame("initialize", {
    "processId": None, "clientInfo": {"name": "test", "version": "1.0"},
    "rootUri": "file:///C:/test", "capabilities": {},
    "workspaceFolders": [{"uri": "file:///C:/test", "name": "workspace"}],
}, 1))
ws.settimeout(3)
try:
    ws.recv()
except Exception:
    pass

# Call auth/logout to force fresh login
print("[*] Calling auth/logout...")
ws.send(make_frame("auth/logout", {}, 2))
ws.settimeout(5)
try:
    ws.recv()
except Exception:
    pass

# Call auth/login for fresh URL
print("[*] Calling auth/login...")
ws.send(make_frame("auth/login", {}, 3))
ws.settimeout(30)

login_url = None
deadline = time.time() + 25
while time.time() < deadline:
    try:
        raw = ws.recv()
    except websocket.WebSocketTimeoutException:
        continue
    except Exception:
        break
    payload_bytes = raw.encode("utf-8") if isinstance(raw, str) else raw
    for m in parse_frames(payload_bytes):
        result_str = json.dumps(m.get("result", {}))
        urls = re.findall(r'https?://[^\s"]+', result_str)
        if urls and "login" in urls[0]:
            login_url = urls[0]
            break
    if login_url:
        break

ws.close()

if not login_url:
    print("[!] No login URL found")
    exit(1)

print(f"Login URL: {login_url[:150]}...")
print()

print("[*] Following redirect chain...")
session = requests.Session()
session.verify = False

r = session.get(login_url, allow_redirects=False, timeout=15)
print(f"Status: {r.status_code}")
loc = r.headers.get("Location", "")
print(f"Location: {loc[:250] if loc else 'none'}")

# Follow the chain
step = 0
while loc and step < 5:
    step += 1
    if "oauth2/v1/auth" in loc:
        parsed = urllib.parse.urlparse(loc)
        params = urllib.parse.parse_qs(parsed.query)
        print()
        print("=== OAuth Authorize URL Parameters ===")
        for k, v in params.items():
            val = v[0]
            if k == "client_id":
                print(f"  *** {k}: {val} *** <- CLIENT_ID FOUND!")
            else:
                print(f"  {k}: {val[:120]}")
        break

    print(f"Following: {loc[:150]}")
    r = session.get(loc, allow_redirects=False, timeout=15)
    print(f"  Status: {r.status_code}")
    loc = r.headers.get("Location", "")
    if loc:
        print(f"  -> {loc[:250]}")
