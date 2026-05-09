"""Hook Go's net.Dial and crypto/tls to capture ALL connections at Go level."""
import frida
import json
import time
import sys

SCRIPT = r"""
'use strict';

var mod = Process.getModuleByName('Lingma.exe');
var base = mod.base;
var exports = mod.enumerateExports();
console.log('Module: ' + mod.name + ' base=' + base + ' size=' + mod.size.toString(16));

// List ALL exports
var goExports = [];
exports.forEach(function(e) {
    goExports.push(e.name + ' @ ' + e.address);
});
console.log('Total exports: ' + exports.length);
send({type: 'exports', list: goExports});

// Try to hook Go runtime functions that make syscalls
// Go's network poller uses WSAPoll, WSASocketW, etc.
var ws2 = Process.getModuleByName('ws2_32.dll');
var ws2exports = ws2.enumerateExports();

// Hook WSASocketW — this creates ALL sockets
var found = ws2exports.filter(function(e) { return e.name === 'WSASocketW'; });
if (found.length > 0) {
    Interceptor.attach(found[0].address, {
        onEnter: function(args) {
            this.af = args[0].toInt32();
            this.type = args[1].toInt32();
            this.protocol = args[2].toInt32();
        },
        onLeave: function(retval) {
            var sock = retval.toInt32();
            if (sock > 0 && sock < 65535) {
                var proto = '';
                if (this.af === 2) proto += 'AF_INET';
                else if (this.af === 23) proto += 'AF_INET6';
                else proto += 'AF_' + this.af;
                if (this.type === 1) proto += '/SOCK_STREAM';
                else if (this.type === 2) proto += '/SOCK_DGRAM';
                else proto += '/type' + this.type;
                if (this.protocol === 6) proto += '/TCP';
                else if (this.protocol === 17) proto += '/UDP';
                else if (this.protocol !== 0) proto += '/prot' + this.protocol;

                var stack = Thread.backtrace(this.context, Backtracer.ACCURATE);
                var stackStr = '';
                for (var i = 0; i < Math.min(stack.length, 8); i++) {
                    var addr = stack[i];
                    var modName = '';
                    Process.enumerateModules().forEach(function(m) {
                        if (addr.compare(m.base) >= 0 && addr.compare(m.base.add(m.size)) < 0) {
                            modName = m.name + '+' + addr.sub(m.base).toString(16);
                        }
                    });
                    if (modName) stackStr += '\n    ' + modName;
                }

                console.log('[WSASocketW] fd=' + sock + ' ' + proto + stackStr);
                send({type: 'socket', fd: sock, proto: proto, stack: stackStr});
            }
        }
    });
    console.log('[Hook] WSASocketW OK');
}

// Hook connect
var connectExp = ws2exports.filter(function(e) { return e.name === 'connect'; });
if (connectExp.length > 0) {
    Interceptor.attach(connectExp[0].address, {
        onEnter: function(args) {
            var sock = args[0].toInt32();
            var addr = args[1];
            try {
                var family = addr.readU16();
                if (family === 2) {
                    var port = addr.add(2).readU16();
                    port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);
                    var ip = addr.add(4).readU8() + '.' + addr.add(5).readU8() + '.' +
                            addr.add(6).readU8() + '.' + addr.add(7).readU8();
                    console.log('[connect] fd=' + sock + ' -> ' + ip + ':' + port);
                    send({type: 'connect', fd: sock, ip: ip, port: port});

                    // Print stack trace
                    var stack = Thread.backtrace(this.context, Backtracer.ACCURATE);
                    for (var i = 0; i < Math.min(stack.length, 6); i++) {
                        var addr = stack[i];
                        Process.enumerateModules().forEach(function(m) {
                            if (addr.compare(m.base) >= 0 && addr.compare(m.base.add(m.size)) < 0) {
                                console.log('  ' + m.name + '+' + addr.sub(m.base).toString(16));
                            }
                        });
                    }
                }
            } catch(e) {}
        }
    });
    console.log('[Hook] connect OK');
}

// Also hook WSAConnect
var wsaConnectExp = ws2exports.filter(function(e) { return e.name === 'WSAConnect'; });
if (wsaConnectExp.length > 0) {
    Interceptor.attach(wsaConnectExp[0].address, {
        onEnter: function(args) {
            var sock = args[0].toInt32();
            var addr = args[1];
            try {
                var family = addr.readU16();
                if (family === 2) {
                    var port = addr.add(2).readU16();
                    port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);
                    var ip = addr.add(4).readU8() + '.' + addr.add(5).readU8() + '.' +
                            addr.add(6).readU8() + '.' + addr.add(7).readU8();
                    console.log('[WSAConnect] fd=' + sock + ' -> ' + ip + ':' + port);
                    send({type: 'wsa_connect', fd: sock, ip: ip, port: port});
                }
            } catch(e) {}
        }
    });
    console.log('[Hook] WSAConnect OK');
}

console.log('[All hooks ready]');
send({type: 'ready'});
"""

# Attach to running Lingma
device = frida.get_local_device()
lingma = [p for p in device.enumerate_processes() if p.name and 'lingma' in p.name.lower()]
if not lingma:
    print("Lingma not running!")
    sys.exit(1)

pid = lingma[0].pid
print(f"[*] Attaching to PID {pid}")

session = device.attach(pid)

def on_msg(msg, data):
    if msg['type'] == 'send':
        p = msg['payload']
        t = p.get('type','?')
        if t == 'exports':
            for e in p.get('list', []):
                if any(x in e.lower() for x in ['dial', 'connect', 'http', 'socket', 'tls', 'roundtrip']):
                    print(f"  [EXPORT] {e}")
        elif t in ('connect', 'wsa_connect', 'socket'):
            print(f"[{t.upper()}] {json.dumps(p, ensure_ascii=False)[:200]}")
        elif t == 'ready':
            print("[*] Hooks ready!")
        else:
            pass
    elif msg['type'] == 'log':
        l = msg['payload']
        if any(x in l for x in ['WSASocketW', 'connect', 'WSAConnect']):
            print(f"[LOG] {l[:400]}")

script = session.create_script(SCRIPT)
script.on('message', on_msg)
script.load()
time.sleep(2)

print("\n[*] Now trigger a chat request from another terminal (python tools/frida_chat_real.py)")
print("[*] Waiting for connections (30s)...")
time.sleep(30)

print("\n[*] Done!")
script.unload()
session.detach()
