"""
Frida Hook v15: Hook WSASend 捕获网络流量中的签名头
通过拦截底层 socket 发送来捕获签名
"""
import frida
import time
import subprocess
import json

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

HOOK_SCRIPT = r"""
'use strict';

// Hook WSASend on Windows
var WSASend = Module.getExportByName('ws2_32.dll', 'WSASend');
console.log('[Hook] WSASend at ' + WSASend);

Interceptor.attach(WSASend, {
    onEnter: function(args) {
        // WSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, ...)
        var socket = args[0];
        var lpBuffers = args[1];
        var dwBufferCount = args[2].toInt32();

        // Read the buffer
        for (var i = 0; i < dwBufferCount && i < 4; i++) {
            var buf = lpBuffers.add(i * 16);  // WSABUF is 16 bytes on x64
            var len = buf.readUInt();
            var ptr = buf.add(8).readPointer();

            if (len > 0 && len < 100000) {
                try {
                    var data = ptr.readUtf8String(Math.min(len, 2000));
                    // Filter for HTTP requests (look for "POST" or "Signature" header)
                    if (data.indexOf('POST') >= 0 || data.indexOf('Signature') >= 0 ||
                        data.indexOf('Timestamp') >= 0 || data.indexOf('algo') >= 0) {
                        console.log('[WSASend] socket=' + socket + ' len=' + len);
                        console.log('  DATA: ' + data.substring(0, 2000));
                    }
                } catch(e) {}
            }
        }
    }
});

console.log('[Hook] WSASend hook installed');

// Also hook connect to see what servers we connect to
var connect = Module.getExportByName('ws2_32.dll', 'connect');
console.log('[Hook] connect at ' + connect);

Interceptor.attach(connect, {
    onEnter: function(args) {
        // sockaddr_in: family(2) + port(2) + addr(4) + ...
        var addr = args[1];
        try {
            var family = addr.readU16();
            if (family === 2) {  // AF_INET
                var port = (addr.add(2).readU16() >> 8) | ((addr.add(2).readU16() & 0xFF) << 8);
                var ip = (addr.add(4).readU8()) + '.' +
                        (addr.add(5).readU8()) + '.' +
                        (addr.add(6).readU8()) + '.' +
                        (addr.add(7).readU8());
                console.log('[connect] ' + ip + ':' + port);
            }
        } catch(e) {}
    }
});

console.log('[Hook] connect hook installed');
console.log('[Hook] Ready!');
"""

def on_message(msg, data):
    payload = msg.get('payload', '')
    if payload:
        print(f"[MSG] {payload}")

def main():
    device = frida.get_local_device()

    for p in device.enumerate_processes():
        if 'lingma' in p.name.lower():
            print(f"Killing: {p.name} (PID: {p.pid})")
            device.kill(p.pid)

    print("Starting Lingma...")
    proc = subprocess.Popen([LINGMA, "start"])
    time.sleep(10)

    processes = device.enumerate_processes()
    lingma_procs = [p for p in processes if 'lingma' in p.name.lower()]
    if not lingma_procs:
        print("Not found!")
        proc.kill()
        return

    pid = lingma_procs[0].pid
    print(f"PID: {pid}")

    session = device.attach(pid)
    script = session.create_script(HOOK_SCRIPT)
    script.on('message', on_message)
    script.load()

    print("\nWaiting 30s for network activity...")
    time.sleep(30)

    print("--- Done ---")
    try:
        script.unload()
    except:
        pass
    session.detach()
    proc.kill()

if __name__ == '__main__':
    main()
