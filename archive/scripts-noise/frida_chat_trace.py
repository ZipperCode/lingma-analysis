"""Frida trace Lingma chat request — capture auth headers and remote endpoints."""
import frida
import json
import os
import time
import uuid
import websocket

SCRIPT_PATH = os.path.join(os.path.dirname(__file__), 'frida_minimal_hook.js')

print("[*] Frida Chat Trace — will capture all remote connections")

with open(SCRIPT_PATH, 'r') as f:
    hook_js = f.read()

events = []
def on_message(msg, data):
    if msg['type'] == 'send':
        p = msg['payload']
        t = p.get('type','?')
        if t == 'sni':
            print(f"[FRIDA SNI] {p['sni']}")
        elif t == 'connect':
            print(f"[FRIDA CONNECT] {p['ip']}:{p['port']}")
        elif t == 'http':
            print(f"[FRIDA HTTP SEND] {p['data'][:300]}")
        elif t == 'http_recv':
            print(f"[FRIDA HTTP RECV] {p['data'][:300]}")
        events.append(p)
    elif msg['type'] == 'log':
        print(f"[FRIDA LOG] {msg['payload']}")

# Attach Frida
print("[*] Attaching Frida...")
device = frida.get_local_device()
lingma = [p for p in device.enumerate_processes() if p.name and 'lingma' in p.name.lower()]
session = device.attach(lingma[0].pid)
script = session.create_script(hook_js)
script.on('message', on_message)
script.load()
time.sleep(1)

# Now trigger a chat request to force Lingma to make HTTP calls
def make_frame(method, params=None, msg_id=1):
    body = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        body["params"] = params
    body["id"] = msg_id
    content = json.dumps(body, ensure_ascii=False)
    return f"Content-Length: {len(content.encode('utf-8'))}\r\n\r\n{content}"

def parse_frame(text):
    if '\r\n\r\n' in text:
        headers, body = text.split('\r\n\r\n', 1)
        for line in headers.split('\r\n'):
            if line.lower().startswith('content-length:'):
                length = int(line.split(':')[1].strip())
                return json.loads(body[:length])
        return json.loads(body)
    return json.loads(text)

print("[*] Connecting WebSocket...")
ws = websocket.create_connection("ws://127.0.0.1:37010", timeout=10)

# Initialize
ws.send(make_frame("initialize", {
    "processId": os.getpid(),
    "clientInfo": {"name": "frida-chat", "version": "1.0"},
    "locale": "zh-CN",
    "rootPath": "C:/test",
    "capabilities": {}
}, 1))
ws.settimeout(3)
try: ws.recv()
except: pass

# Try chat/ask to trigger real API call
import uuid
request_id = uuid.uuid4().hex
chat_params = {
    "requestId": request_id,
    "sessionId": "s1",
    "chatId": "c1",
    "message": "hello",
    "task": "FREE_INPUT",
    "mode": "normal",
    "knowledge": [],
    "model": "",
    "stream": False
}

print(f"[*] Sending chat/ask (id={request_id})...")
print("[*] Watch for Frida events above...")
ws.send(make_frame("chat/ask", chat_params, 2))

# Collect responses
ws.settimeout(30)
start = time.time()
while time.time() - start < 25:
    try:
        raw = ws.recv()
        resp = parse_frame(raw)
        method = resp.get('method', resp.get('id', '?'))
        if 'method' in resp:
            print(f"[WS PUSH] method={resp['method'][:80]}")
            if 'params' in resp:
                print(f"  params keys: {list(resp['params'].keys()) if isinstance(resp['params'], dict) else '...'}")
        else:
            rid = resp.get('id', '?')
            if 'result' in resp:
                r = resp['result']
                if isinstance(r, dict):
                    print(f"[WS RESP id={rid}] keys: {list(r.keys())[:10]} text_preview: {str(r.get('text','') or r.get('delta',''))[:100]}")
                else:
                    print(f"[WS RESP id={rid}] {str(r)[:200]}")
            elif 'error' in resp:
                print(f"[WS ERR id={rid}] {resp['error']}")
    except websocket.WebSocketTimeoutException:
        print(f"[WS] (timeout)")
        break
    except Exception as e:
        print(f"[WS] error: {e}")
        break

print(f"\n[*] Total Frida events: {len(events)}")
for e in events:
    t = e.get('type','?')
    if t in ('connect', 'sni'):
        print(f"  [{t}] {json.dumps(e, ensure_ascii=False)[:200]}")

ws.close()
script.unload()
session.detach()
print("[*] Done!")
