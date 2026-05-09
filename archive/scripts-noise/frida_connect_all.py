"""Hook ALL Windows connection APIs — ConnectEx, WSAConnect, etc."""
import frida, json, time, sys

SCRIPT = r"""
'use strict';

var ws2 = Process.getModuleByName('ws2_32.dll');
var ws2exports = ws2.enumerateExports();

// Print ALL ws2 exports to find connect variants
var connectFuncs = [];
ws2exports.forEach(function(e) {
    var n = e.name.toLowerCase();
    if (n.indexOf('connect') >= 0) {
        connectFuncs.push(e.name + ' @ ' + e.address);
        console.log('[Found] ' + e.name + ' @ ' + e.address);
    }
});
send({type: 'connect_funcs', list: connectFuncs});

// Hook ALL connect functions
ws2exports.forEach(function(e) {
    var n = e.name.toLowerCase();
    if (n.indexOf('connect') < 0) return;

    Interceptor.attach(e.address, {
        onEnter: function(args) {
            console.log('[' + e.name + '] called');
            send({type: 'connect_call', fn: e.name});
            // Try different arg positions for sockaddr
            for (var ai = 1; ai <= 6; ai++) {
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
                            break;
                        }
                    }
                } catch(ex) {}
            }
        }
    });
    console.log('[Hook] ' + e.name + ' OK');
});

// Hook getaddrinfo AND GetAddrInfoW, GetAddrInfoExW
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
                    // Wide string?
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

// Also hook mswsock.dll ConnectEx
var mswsock = Process.getModuleByName('mswsock.dll');
if (mswsock) {
    console.log('[Module] mswsock.dll @ ' + mswsock.base);
    var msexp = mswsock.enumerateExports();
    msexp.forEach(function(e) {
        if (e.name.toLowerCase().indexOf('connect') >= 0) {
            console.log('[mswsock] ' + e.name + ' @ ' + e.address);
            Interceptor.attach(e.address, {
                onEnter: function(args) {
                    console.log('[mswsock!' + e.name + '] called');
                    send({type: 'connect_call', fn: 'mswsock!' + e.name});
                    // ConnectEx(s, addr, addrlen, sendbuf, sendbuflen, bytesSent, overlapped)
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
}

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
        if t == 'connect_funcs':
            print(f"[Connect funcs]: {p['list']}")
        elif t == 'connect':
            print(f"[CONNECT] {p.get('fn','?')} -> {p.get('ip','?')}:{p.get('port','?')}")
        elif t == 'connect_call':
            print(f"[CALL] {p['fn']}")
        elif t == 'dns':
            print(f"[DNS] {p.get('fn','?')}: {p['host']}")
        elif t == 'ready': print("[*] Ready!")
        all_events.append(p)
    elif msg['type'] == 'log':
        if 'connect' not in msg['payload']:
            print(f"[LOG] {msg['payload'][:200]}")

script = session.create_script(SCRIPT)
script.on('message', on_msg)
script.load()
time.sleep(2)

print("\n[*] Now trigger chat! Run in another terminal:")
print("    python tools/frida_chat_real.py")
print("[*] Waiting 60s...")
time.sleep(60)

print(f"\n=== Connect/DNS events ===")
for e in all_events:
    t = e.get('type','?')
    if t in ('connect', 'connect_call', 'dns', 'connect_funcs'):
        print(f"  {json.dumps(e, ensure_ascii=False)[:250]}")

script.unload()
session.detach()
