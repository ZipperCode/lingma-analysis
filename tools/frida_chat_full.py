"""Proper LSP chat flow with Frida — send required setup messages before chat."""
import frida
import json
import os
import time
import uuid
import websocket

SCRIPT_PATH = os.path.join(os.path.dirname(__file__), 'frida_minimal_hook.js')

with open(SCRIPT_PATH, 'r') as f:
    hook_js = f.read()

events = []
def on_message(msg, data):
    if msg['type'] == 'send':
        p = msg['payload']
        t = p.get('type','?')
        if t == 'sni':
            print(f"[SNI] {p['sni']}")
        elif t == 'connect':
            print(f"[CONNECT] {p['ip']}:{p['port']}")
        elif t == 'http':
            print(f"[HTTP>>] {p['data'][:200]}")
        events.append(p)
    elif msg['type'] == 'log':
        l = msg['payload']
        if 'SNI' in l or 'CONNECT' in l or 'HTTP' in l:
            print(f"[Frida] {l[:300]}")

print("[*] Attaching Frida...")
device = frida.get_local_device()
lingma = [p for p in device.enumerate_processes() if p.name and 'lingma' in p.name.lower()]
session = device.attach(lingma[0].pid)
script = session.create_script(hook_js)
script.on('message', on_message)
script.load()
time.sleep(1)

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

def recv_all(ws, timeout=3):
    """Read all available messages."""
    results = []
    ws.settimeout(timeout)
    while True:
        try:
            raw = ws.recv()
            results.append(parse_frame(raw))
        except websocket.WebSocketTimeoutException:
            break
        except Exception as e:
            break
    return results

print("[*] Connecting...")
ws = websocket.create_connection("ws://127.0.0.1:37010", timeout=10)

# Step 1: Initialize
print("[1] initialize...")
ws.send(make_frame("initialize", {
    "processId": os.getpid(),
    "clientInfo": {"name": "frida-chat", "version": "1.0"},
    "locale": "zh-CN",
    "rootPath": "C:/test",
    "capabilities": {
        "textDocument": {"completion": {"completionItem": {"snippetSupport": True}}}
    }
}, 1))
time.sleep(1)
for r in recv_all(ws, 2):
    print(f"    init: {json.dumps(r, ensure_ascii=False)[:200]}")

# Step 2: Send initialized (notification, no id)
print("[2] initialized...")
init_done = {"jsonrpc": "2.0", "method": "initialized", "params": {}}
content = json.dumps(init_done, ensure_ascii=False)
ws.send(f"Content-Length: {len(content.encode('utf-8'))}\r\n\r\n{content}")
time.sleep(1)

# Step 3: Check auth status
print("[3] auth/status...")
ws.send(make_frame("auth/status", {}, 3))
time.sleep(1)
for r in recv_all(ws, 2):
    print(f"    auth: status={r.get('result',{}).get('status')}, name={r.get('result',{}).get('name')}")

# Step 4: Query models
print("[4] config/queryModels...")
ws.send(make_frame("config/queryModels", {"scene": "chat"}, 4))
time.sleep(2)
for r in recv_all(ws, 3):
    rkeys = list(r.get('result',{}).keys()) if 'result' in r else 'error'
    print(f"    models: {rkeys}")

# Step 5: NOW trigger chat/ask
print("[5] chat/ask...")
request_id = uuid.uuid4().hex
ws.send(make_frame("chat/ask", {
    "requestId": request_id,
    "sessionId": "s1",
    "chatId": "c1",
    "message": "Say hello in one word",
    "task": "FREE_INPUT",
    "mode": "normal",
    "knowledge": [],
    "model": "",
    "stream": False
}, 5))

print("[*] Waiting for chat response (watch for Frida SNI/CONNECT)...")
start = time.time()
while time.time() - start < 25:
    try:
        for r in recv_all(ws, 5):
            method = r.get('method', '')
            rid = r.get('id', '')
            if method:
                print(f"[PUSH] {method[:80]}")
                if 'params' in r:
                    p = r['params']
                    if isinstance(p, dict):
                        if 'delta' in p:
                            print(f"  delta: {str(p.get('delta',''))[:100]}")
                        elif 'text' in p:
                            print(f"  text: {str(p.get('text',''))[:100]}")
                        elif 'choices' in p:
                            print(f"  choices: {len(p['choices'])}")
                        else:
                            print(f"  keys: {list(p.keys())[:8]}")
            elif 'result' in r:
                res = r['result']
                if isinstance(res, dict):
                    print(f"[RESP id={rid}] success={res.get('success')}, err={res.get('errorCode','')} keys={list(res.keys())[:8]}")
            elif 'error' in r:
                print(f"[ERR id={rid}] {r['error']}")
    except:
        pass

print(f"\n[*] Frida events captured: {len(events)}")
for e in events:
    t = e.get('type','?')
    if t in ('connect', 'sni', 'http'):
        print(f"  [{t}] {json.dumps(e, ensure_ascii=False)[:250]}")

ws.close()
script.unload()
session.detach()
print("[*] Done!")
