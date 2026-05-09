"""
Hook WSASend 捕获签名 - 正确的 API
"""
import frida
import time
import subprocess
import urllib.request
import json

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

HOOK_SCRIPT = r"""
// Hook WSASend
var ws2 = Process.getModuleByName('ws2_32.dll');
var exports = ws2.enumerateExports();

var wsasendExp = exports.filter(function(e) { return e.name === 'WSASend'; });
if (wsasendExp.length > 0) {
    console.log('[Hook] WSASend at ' + wsasendExp[0].address);
    Interceptor.attach(wsasendExp[0].address, {
        onEnter: function(args) {
            var socket = args[0].toInt32();
            var lpBuffers = args[1];
            var dwBufferCount = args[2].toInt32();

            for (var i = 0; i < dwBufferCount && i < 8; i++) {
                var buf = lpBuffers.add(i * 16);
                var len = buf.readUInt();
                var ptr = buf.add(8).readPointer();

                if (len > 0 && len < 200000) {
                    try {
                        var data = ptr.readUtf8String(Math.min(len, 10000));
                        // Filter for anything interesting
                        if (data.indexOf('POST') >= 0 || data.indexOf('GET') >= 0 ||
                            data.indexOf('Signature') >= 0 || data.indexOf('Timestamp') >= 0 ||
                            data.indexOf('algo') >= 0 || data.indexOf('HTTP/1') >= 0 ||
                            data.indexOf('heartbeat') >= 0 || data.indexOf('dashscope') >= 0 ||
                            data.indexOf('Authorization') >= 0 || data.indexOf('Secret') >= 0 ||
                            data.indexOf('sign') >= 0 || data.indexOf('md5') >= 0) {
                            console.log('[WSASend] socket=' + socket + ' len=' + len);
                            console.log('  ' + data.substring(0, 10000));
                        }
                    } catch(e) {
                        // Not UTF-8 data, try reading as bytes
                    }
                }
            }
        }
    });
    console.log('[Hook] WSASend installed');
}

// Also hook sendto
var sendtoExp = exports.filter(function(e) { return e.name === 'sendto'; });
if (sendtoExp.length > 0) {
    Interceptor.attach(sendtoExp[0].address, {
        onEnter: function(args) {
            var len = args[2].toInt32();
            console.log('[sendto] len=' + len);
        }
    });
    console.log('[Hook] sendto installed');
}

// Hook connect to see where it connects
var connectExp = exports.filter(function(e) { return e.name === 'connect'; });
if (connectExp.length > 0) {
    Interceptor.attach(connectExp[0].address, {
        onEnter: function(args) {
            var addr = args[1];
            try {
                var family = addr.readU16();
                if (family === 2) {
                    var port = addr.add(2).readU16();
                    port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);
                    var ip = addr.add(4).readU8() + '.' + addr.add(5).readU8() + '.' +
                            addr.add(6).readU8() + '.' + addr.add(7).readU8();
                    console.log('[connect] -> ' + ip + ':' + port);
                } else if (family === 23) {
                    // AF_INET6
                    console.log('[connect] -> IPv6');
                }
            } catch(e) {}
        }
    });
    console.log('[Hook] connect installed');
}

console.log('[Hook] Setup complete');
"""

def on_message(msg, data):
    payload = msg.get('payload', '')
    if payload:
        print(f"[MSG] {payload}")

def main():
    device = frida.get_local_device()

    for p in device.enumerate_processes():
        if 'lingma' in p.name.lower():
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

    # Make requests to trigger traffic
    print("\nMaking requests...")
    endpoints = ['/', '/algo', '/api', '/status']
    for ep in endpoints:
        try:
            urllib.request.urlopen(f'http://127.0.0.1:37510{ep}', timeout=3)
        except:
            pass

    # Wait for heartbeat/remote calls
    print("Waiting 60s for remote traffic...")
    for i in range(60):
        time.sleep(1)
        if i % 10 == 0:
            print(f"  {i}s")

    print("--- Done ---")
    try:
        script.unload()
    except:
        pass
    session.detach()
    proc.kill()

if __name__ == '__main__':
    main()
