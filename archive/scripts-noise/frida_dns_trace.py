"""Hook DNS resolution + ALL socket operations in Lingma."""
import frida, json, time, sys

SCRIPT = r"""
'use strict';

var ws2 = Process.getModuleByName('ws2_32.dll');
var ws2exports = ws2.enumerateExports();

// Hook getaddrinfo — DNS resolution
var gai = ws2exports.filter(function(e) { return e.name === 'getaddrinfo'; });
if (gai.length > 0) {
    Interceptor.attach(gai[0].address, {
        onEnter: function(args) {
            try {
                var host = args[0].readUtf8String();
                if (host && host.length > 0) {
                    console.log('[DNS] getaddrinfo("' + host + '")');
                    send({type: 'dns', host: host});
                }
            } catch(e) {}
        }
    });
    console.log('[Hook] getaddrinfo OK');
}

// Hook gethostbyname
var ghbn = ws2exports.filter(function(e) { return e.name === 'gethostbyname'; });
if (ghbn.length > 0) {
    Interceptor.attach(ghbn[0].address, {
        onEnter: function(args) {
            try {
                var host = args[0].readUtf8String();
                console.log('[DNS] gethostbyname("' + host + '")');
                send({type: 'dns2', host: host});
            } catch(e) {}
        }
    });
    console.log('[Hook] gethostbyname OK');
}

// Hook WSASocketW — all socket creation
var wsaSock = ws2exports.filter(function(e) { return e.name === 'WSASocketW'; });
if (wsaSock.length > 0) {
    Interceptor.attach(wsaSock[0].address, {
        onEnter: function(args) { this.af = args[0]; this.type = args[1]; this.protocol = args[2]; },
        onLeave: function(retval) {
            var sock = retval.toInt32();
            if (sock > 0 && sock < 65535) {
                var af = this.af.toInt32(), tp = this.type.toInt32(), pr = this.protocol.toInt32();
                console.log('[SOCKET] fd=' + sock + ' af=' + af + ' type=' + tp + ' proto=' + pr);
                send({type: 'socket', fd: sock, af: af, type: tp, proto: pr});
            }
        }
    });
    console.log('[Hook] WSASocketW OK');
}

// Hook connect
var conn = ws2exports.filter(function(e) { return e.name === 'connect'; });
if (conn.length > 0) {
    Interceptor.attach(conn[0].address, {
        onEnter: function(args) {
            var addr = args[1];
            try {
                var family = addr.readU16();
                if (family === 2) {
                    var port = addr.add(2).readU16();
                    port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);
                    var b1=addr.add(4).readU8(), b2=addr.add(5).readU8(), b3=addr.add(6).readU8(), b4=addr.add(7).readU8();
                    var ip = b1+'.'+b2+'.'+b3+'.'+b4;
                    console.log('[CONNECT] fd=' + args[0].toInt32() + ' -> ' + ip + ':' + port);
                    send({type: 'connect', fd: args[0].toInt32(), ip: ip, port: port});
                }
            } catch(e) {}
        }
    });
    console.log('[Hook] connect OK');
}

// Hook send/sendto
['send', 'sendto', 'WSASend'].forEach(function(name) {
    var f = ws2exports.filter(function(e) { return e.name === name; });
    if (f.length > 0) {
        Interceptor.attach(f[0].address, {
            onEnter: function(args) {
                var sock = args[0].toInt32();
                var buf = (name === 'WSASend') ? null : args[1];
                var len = (name === 'WSASend') ? 0 : args[2].toInt32();

                if (name === 'WSASend') {
                    // Parse WSABUF array
                    var lpBuffers = args[1];
                    var dwBufferCount = args[2].toInt32();
                    for (var i = 0; i < dwBufferCount && i < 4; i++) {
                        var wsaBuf = lpBuffers.add(i * 16);
                        len = wsaBuf.readUInt();
                        buf = wsaBuf.add(8).readPointer();
                        if (len > 0) break;
                    }
                }

                if (len > 5 && len < 65536 && buf) {
                    try {
                        var data = buf.readByteArray(Math.min(len, 16));
                        var arr = new Uint8Array(data);
                        // Check if it looks like TLS or HTTP
                        if (arr[0] === 0x16 || arr[0] === 0x17) {
                            // TLS record — likely to external server
                            console.log('[' + name + ' TLS] fd=' + sock + ' len=' + len + ' type=0x' + arr[0].toString(16));
                            send({type: 'tls_send', fd: sock, len: len});
                        }
                    } catch(e) {}
                }
            }
        });
    }
});

console.log('[ALL HOOKS READY]');
send({type: 'ready'});
"""

device = frida.get_local_device()
lingma = [p for p in device.enumerate_processes() if p.name and 'lingma' in p.name.lower()]
pid = lingma[0].pid
print(f"[*] PID: {pid}")

session = device.attach(pid)

all_events = []
def on_msg(msg, data):
    if msg['type'] == 'send':
        p = msg['payload']; t = p.get('type','?')
        if t == 'dns': print(f"[DNS] {p['host']}")
        elif t == 'dns2': print(f"[DNS2] {p['host']}")
        elif t == 'socket': print(f"[SOCKET] fd={p['fd']} af={p['af']} type={p['type']} proto={p['proto']}")
        elif t == 'connect': print(f"[CONNECT] fd={p['fd']} -> {p['ip']}:{p['port']}")
        elif t == 'tls_send': print(f"[TLS SEND] fd={p['fd']} len={p['len']}")
        elif t == 'ready': print("[*] Ready!")
        all_events.append(p)
    elif msg['type'] == 'log':
        l = msg['payload']
        if any(x in l for x in ['DNS', 'CONNECT', 'SOCKET', 'TLS']):
            print(f"[LOG] {l[:300]}")

script = session.create_script(SCRIPT)
script.on('message', on_msg)
script.load()
time.sleep(1)

print("\n[*] Hooks active! Trigger a chat in another terminal:")
print("    python tools/frida_chat_real.py")
print("[*] Waiting 120s...")
time.sleep(120)

print(f"\n=== Events ({len(all_events)}) ===")
for e in all_events:
    print(f"  [{e.get('type','?')}] {json.dumps(e, ensure_ascii=False)[:200]}")

script.unload()
session.detach()
