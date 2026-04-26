"""Hook ALL connect variants + trigger chat — identify Go's actual network API."""
import frida
import json
import time
import uuid
import websocket
import sys
import threading

# ===== Frida Hook Script =====
SCRIPT = r"""
'use strict';

var ws2 = Process.getModuleByName('ws2_32.dll');
var ws2exports = ws2.enumerateExports();

// ---- Hook ALL connect variants in ws2_32.dll ----
var connectFuncs = [];
ws2exports.forEach(function(e) {
    var n = e.name.toLowerCase();
    if (n.indexOf('connect') < 0) return;
    connectFuncs.push(e.name + ' @ ' + e.address);
    console.log('[Found] ' + e.name + ' @ ' + e.address);

    Interceptor.attach(e.address, {
        onEnter: function(args) {
            console.log('[' + e.name + '] called');
            send({type: 'connect_call', fn: e.name, args_count: arguments.length});

            // Try arg positions 1-6 for sockaddr
            for (var ai = 0; ai <= 6; ai++) {
                try {
                    var ptr = args[ai];
                    if (ptr && !ptr.isNull()) {
                        var af = ptr.readU16();
                        if (af === 2 || af === 23) {
                            var port = 0, ip = '';
                            if (af === 2) {
                                port = ptr.add(2).readU16();
                                port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);
                                ip = ptr.add(4).readU8()+'.'+ptr.add(5).readU8()+'.'+ptr.add(6).readU8()+'.'+ptr.add(7).readU8();
                            }
                            console.log('  [' + e.name + '] arg' + ai + ' -> ' + ip + ':' + port + ' af=' + af);
                            send({type: 'connect', fn: e.name, ip: ip, port: port, af: af, arg_idx: ai});

                            // Print stack trace
                            var stack = Thread.backtrace(this.context, Backtracer.ACCURATE);
                            var trace = [];
                            for (var si = 0; si < Math.min(stack.length, 10); si++) {
                                var addr = stack[si];
                                Process.enumerateModules().forEach(function(m) {
                                    if (addr.compare(m.base) >= 0 && addr.compare(m.base.add(m.size)) < 0) {
                                        trace.push(m.name + '+' + addr.sub(m.base).toString(16));
                                    }
                                });
                            }
                            send({type: 'connect_stack', fn: e.name, stack: trace});
                            break;
                        }
                    }
                } catch(ex) {}
            }
        }
    });
    console.log('[Hook] ' + e.name + ' OK');
});
send({type: 'connect_funcs', list: connectFuncs});

// ---- Hook mswsock.dll ConnectEx ----
try {
    var mswsock = Process.getModuleByName('mswsock.dll');
    console.log('[Module] mswsock.dll @ ' + mswsock.base);
    var msexp = mswsock.enumerateExports();
    msexp.forEach(function(e) {
        if (e.name.toLowerCase().indexOf('connect') >= 0) {
            console.log('[mswsock] ' + e.name + ' @ ' + e.address);
            send({type: 'connect_funcs', list: ['mswsock!' + e.name + ' @ ' + e.address]});
            Interceptor.attach(e.address, {
                onEnter: function(args) {
                    console.log('[mswsock!' + e.name + '] called');
                    send({type: 'connect_call', fn: 'mswsock!' + e.name});
                    try {
                        var addr = args[1];
                        if (addr && !addr.isNull()) {
                            var af = addr.readU16();
                            if (af === 2) {
                                var port = addr.add(2).readU16();
                                port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);
                                var ip = addr.add(4).readU8()+'.'+addr.add(5).readU8()+'.'+addr.add(6).readU8()+'.'+addr.add(7).readU8();
                                console.log('  -> ' + ip + ':' + port);
                                send({type: 'connect', fn: 'mswsock!'+e.name, ip: ip, port: port});
                            }
                        }
                    } catch(ex) {}
                }
            });
            console.log('[Hook] mswsock!' + e.name + ' OK');
        }
    });
} catch(e) {
    console.log('[WARN] mswsock.dll not found: ' + e);
}

// ---- Hook DNS - getaddrinfo, GetAddrInfoW, GetAddrInfoExW ----
['getaddrinfo', 'GetAddrInfoW', 'GetAddrInfoExW'].forEach(function(name) {
    var f = ws2exports.filter(function(e) { return e.name === name; });
    if (f.length > 0) {
        Interceptor.attach(f[0].address, {
            onEnter: function(args) {
                try {
                    var host = args[0].readUtf8String();
                    if (host && host.length > 0 && host !== '0.0.0.0') {
                        console.log('[DNS] ' + name + '("' + host + '")');
                        send({type: 'dns', fn: name, host: host});
                    }
                } catch(e) {
                    try {
                        var host = args[0].readUtf16String();
                        if (host && host.length > 0) {
                            console.log('[DNS] ' + name + '(W:"' + host + '")');
                            send({type: 'dns', fn: name, host: host});
                        }
                    } catch(e2) {}
                }
            }
        });
        console.log('[Hook] ' + name + ' OK');
    }
});

// ---- Hook gethostbyname ----
var ghbn = ws2exports.filter(function(e) { return e.name === 'gethostbyname'; });
if (ghbn.length > 0) {
    Interceptor.attach(ghbn[0].address, {
        onEnter: function(args) {
            try {
                var host = args[0].readUtf8String();
                console.log('[DNS] gethostbyname("' + host + '")');
                send({type: 'dns', fn: 'gethostbyname', host: host});
            } catch(e) {}
        }
    });
    console.log('[Hook] gethostbyname OK');
}

// ---- Hook WSASocketW for socket creation ----
var wsaSock = ws2exports.filter(function(e) { return e.name === 'WSASocketW'; });
if (wsaSock.length > 0) {
    Interceptor.attach(wsaSock[0].address, {
        onEnter: function(args) { this.af=args[0].toInt32(); this.type=args[1].toInt32(); this.protocol=args[2].toInt32(); },
        onLeave: function(retval) {
            var sock = retval.toInt32();
            if (sock > 0 && sock < 65535) {
                var proto = 'af='+this.af+' type='+this.type+' proto='+this.protocol;
                if (this.af===2) proto='AF_INET'+proto.replace('af=2 ','');
                console.log('[SOCKET] fd=' + sock + ' ' + proto);
                send({type: 'socket', fd: sock, af: this.af, type: this.type, proto: this.protocol});
            }
        }
    });
    console.log('[Hook] WSASocketW OK');
}

console.log('[ALL HOOKS READY]');
send({type: 'ready'});
"""

# ===== WebSocket LSP helpers =====
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


# ===== Main =====
events = []

def on_msg(msg, data):
    if msg['type'] == 'send':
        p = msg['payload']; t = p.get('type','?')
        if t == 'connect_funcs':
            for item in p.get('list', []):
                print(f"[CONNECT FUNC] {item}")
        elif t == 'connect':
            print(f"[CONNECT] {p.get('fn','?')} -> {p.get('ip','?')}:{p.get('port','?')} (af={p.get('af','?')})")
        elif t == 'connect_call':
            print(f"[CALL] {p['fn']}")
        elif t == 'connect_stack':
            print(f"[STACK] {p.get('fn','?')}:")
            for s in p.get('stack', []):
                print(f"    {s}")
        elif t == 'dns':
            print(f"[DNS] {p.get('fn','?')}: {p['host']}")
        elif t == 'socket':
            print(f"[SOCKET] fd={p['fd']} af={p['af']} type={p['type']} proto={p['proto']}")
        elif t == 'ready':
            print("[*] Frida hooks ready!")
        else:
            print(f"[EVENT] {t}: {json.dumps(p, ensure_ascii=False)[:200]}")
        events.append(p)
    elif msg['type'] == 'log':
        l = msg['payload']
        if any(x in l for x in ['Found', 'Hook', 'Module', 'DNS', 'SOCKET', 'connect', 'ALL HOOKS']):
            print(f"[LOG] {l[:300]}")

# Attach Frida
print("[*] Attaching Frida to Lingma...")
device = frida.get_local_device()
lingma = [p for p in device.enumerate_processes() if p.name and 'lingma' in p.name.lower()]
pid = lingma[0].pid
print(f"[*] PID: {pid}")

session = device.attach(pid)
script = session.create_script(SCRIPT)
script.on('message', on_msg)
script.load()
time.sleep(2)

# Connect WebSocket and trigger chat
print("\n[*] Connecting WebSocket to trigger chat...")
ws = websocket.create_connection("ws://127.0.0.1:37010", timeout=10)

# Initialize
ws.send(make_frame("initialize", {
    "processId": None,
    "clientInfo": {"name": "frida-connect-test", "version": "1.0"},
    "rootUri": "file:///C:/test",
    "capabilities": {},
    "workspaceFolders": [{"uri": "file:///C:/test", "name": "workspace"}],
}, 1))
ws.settimeout(3)
try:
    raw = ws.recv()
    for m in parse_frames(raw.encode('utf-8') if isinstance(raw, str) else raw):
        print(f"    init ok")
except: pass

# Send chat question
request_id = uuid.uuid4().hex
print(f"\n[*] Sending chat/ask (id={request_id[:16]}...)")
ws.send(make_frame("chat/ask", {
    "requestId": request_id,
    "chatTask": "FREE_INPUT",
    "chatContext": None,
    "sessionId": "",
    "codeLanguage": "",
    "isReply": False,
    "source": 1,
    "questionText": "What is 1+1?",
    "stream": True,
    "taskDefinitionType": "",
    "extra": None,
    "sessionType": "chat",
    "targetAgent": "",
    "pluginPayloadConfig": None,
    "mode": "normal",
    "shellType": "",
    "customModel": None,
}, 3))

# Wait for step_end
print("[*] Waiting for step_end...")
got_step_end = False
deadline = time.time() + 60
ws.settimeout(5)
while time.time() < deadline and not got_step_end:
    try:
        raw = ws.recv()
    except websocket.WebSocketTimeoutException:
        continue
    except Exception as e:
        print(f"    ws error: {e}")
        break
    for m in parse_frames(raw.encode('utf-8') if isinstance(raw, str) else raw):
        method = m.get("method", "")
        params = m.get("params", {})
        if method == "chat/process_step_callback":
            step = params.get("step", "")
            print(f"    step: {step}")
            if step == "step_end" and params.get("requestId") == request_id:
                got_step_end = True
                print("    >>> GOT step_end!")
        elif method:
            print(f"    push: {method[:60]}")

if got_step_end:
    # Send trigger
    trigger_id = uuid.uuid4().hex
    ws.send(make_frame("chat/ask", {
        "requestId": trigger_id,
        "chatTask": "FREE_INPUT",
        "chatContext": None, "sessionId": "", "codeLanguage": "",
        "isReply": True, "source": 1, "questionText": "OK",
        "stream": True, "taskDefinitionType": "", "extra": None,
        "sessionType": "chat", "targetAgent": "",
        "pluginPayloadConfig": None, "mode": "normal",
        "shellType": "", "customModel": None,
    }, 4))
    # Collect answer
    answer = []
    ws.settimeout(10)
    t0 = time.time()
    while time.time() - t0 < 15:
        try:
            raw = ws.recv()
        except websocket.WebSocketTimeoutException:
            if answer: break
            continue
        except: break
        for m in parse_frames(raw.encode('utf-8') if isinstance(raw, str) else raw):
            if m.get("method") == "chat/answer":
                text = m.get("params", {}).get("text", "")
                if text:
                    answer.append(text)
                    print(f"    answer: {text[:80]}")
    print(f"\n=== ANSWER: {''.join(answer)[:300]} ===")
else:
    print("[!] No step_end received!")

ws.close()

# Wait additional time for any delayed connections
print("\n[*] Waiting 10s more for delayed events...")
time.sleep(10)

# Print summary
print(f"\n{'='*60}")
print(f"=== SUMMARY ({len(events)} events) ===")
print(f"{'='*60}")
connect_events = [e for e in events if e.get('type') == 'connect']
connect_call_events = [e for e in events if e.get('type') == 'connect_call']
dns_events = [e for e in events if e.get('type') == 'dns']
socket_events = [e for e in events if e.get('type') == 'socket']
connect_stack_events = [e for e in events if e.get('type') == 'connect_stack']
func_events = [e for e in events if e.get('type') == 'connect_funcs']

print(f"Connect functions found: {len(func_events)} groups")
print(f"Sockets created: {len(socket_events)}")
print(f"DNS lookups: {len(dns_events)}")
print(f"Connect calls: {len(connect_call_events)}")
print(f"Connect details: {len(connect_events)}")
print(f"Connect stacks: {len(connect_stack_events)}")

if dns_events:
    print("\n=== DNS EVENTS ===")
    for e in dns_events:
        print(f"  {e.get('fn','?')}: {e.get('host','?')}")

if connect_events:
    print("\n=== CONNECT EVENTS ===")
    for e in connect_events:
        print(f"  {e.get('fn','?')} -> {e.get('ip','?')}:{e.get('port','?')}")

if connect_stack_events:
    print("\n=== CONNECT STACKS ===")
    for e in connect_stack_events:
        print(f"  {e.get('fn','?')}:")
        for s in e.get('stack', []):
            print(f"    {s}")

# Show ALL events for debugging
print(f"\n=== ALL EVENTS ===")
for e in events:
    print(f"  [{e.get('type','?')}] {json.dumps(e, ensure_ascii=False)[:300]}")

script.unload()
session.detach()
print("\n[*] Done!")
