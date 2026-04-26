"""Try all WebSocket auth methods to extract client_id from Lingma process."""
import json, time, re
import websocket

def make_frame(method, params=None, msg_id=1):
    body = {"jsonrpc": "2.0", "method": method, "id": msg_id}
    if params is not None: body["params"] = params
    content = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
    return f"Content-Length: {len(content.encode('utf-8'))}\r\n\r\n{content}"

def parse_frames(payload):
    msgs, offset, marker = [], 0, b"\r\n\r\n"
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

def recv_all(ws, timeout=5):
    results = []
    ws.settimeout(timeout)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            raw = ws.recv()
        except websocket.WebSocketTimeoutException:
            break
        except: break
        payload_bytes = raw.encode("utf-8") if isinstance(raw, str) else raw
        results.extend(parse_frames(payload_bytes))
    return results

print("[*] Connecting to Lingma WebSocket...")
ws = websocket.create_connection("ws://127.0.0.1:37010", timeout=10)
ws.send(make_frame("initialize", {
    "processId": None, "clientInfo": {"name": "client-id-extractor", "version": "1.0"},
    "rootUri": "file:///C:/test", "capabilities": {},
    "workspaceFolders": [{"uri": "file:///C:/test", "name": "workspace"}],
}, 1))
ws.settimeout(3)
try: ws.recv()
except: pass

# Try ALL possible auth methods
methods_to_try = [
    ("auth/status", {}),
    ("auth/getStatus", {}),
    ("auth/login", {}),
    ("auth/getLoginUrl", {}),
    ("auth/getAuthUrl", {}),
    ("auth/getClientId", {}),      # Maybe this exists!
    ("auth/getClientID", {}),
    ("auth/clientId", {}),
    ("auth/oauthConfig", {}),
    ("auth/getOAuthConfig", {}),
    ("auth/config", {}),
    ("auth/getConfig", {}),
    ("auth/info", {}),
    ("auth/getInfo", {}),
    ("getConfig", {}),
    ("client/register", {}),
    ("client/registerClient", {}),
]

for method, params in methods_to_try:
    ws.send(make_frame(method, params, 10))

results = recv_all(ws, timeout=15)

print(f"\n=== Results from {len(results)} responses ===")
for i, m in enumerate(results):
    method = m.get("method", "")
    msg_id = m.get("id", "?")
    result = m.get("result", {})
    error = m.get("error", {})

    if error:
        print(f"\n[{i}] id={msg_id} ERROR: {error.get('message', str(error))[:150]}")
    elif method:
        print(f"\n[{i}] PUSH method={method}")
        params = m.get("params", {})
        result_str = json.dumps(params, ensure_ascii=False)
        print(f"    {result_str[:300]}")
        # Search for client_id in push
        for key, val in params.items():
            if "client" in key.lower() or "id" in key.lower():
                print(f"    *** {key}: {val} ***")
    elif result:
        result_str = json.dumps(result, ensure_ascii=False)
        print(f"\n[{i}] id={msg_id} RESULT ({len(result_str)} chars)")
        print(f"    {result_str[:400]}")
        # Search for client_id patterns
        if isinstance(result, dict):
            for key, val in result.items():
                if "client" in key.lower():
                    print(f"    *** {key}: {val} ***")
        urls = re.findall(r'https?://[^\s"]+', result_str)
        for u in urls:
            if "client_id" in u or "oauth2" in u:
                print(f"    *** URL with client_id: {u} ***")
    else:
        print(f"\n[{i}] id={msg_id} UNKNOWN RESPONSE: {json.dumps(m, ensure_ascii=False)[:200]}")

ws.close()
print("\n[*] Done!")
