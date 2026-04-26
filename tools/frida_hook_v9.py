"""
Frida Hook v9: 发送正确的 API 请求来触发签名计算
"""
import frida
import time
import subprocess
import urllib.request
import urllib.error
import json

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

HOOK_SCRIPT = r"""
'use strict';

var mod = Process.findModuleByName('Lingma.exe');
if (!mod) {
    console.log('[Hook] Module not found');
} else {
    var base = mod.base;
    console.log('[Hook] Module at ' + base);

    // Hook all known functions
    var hooks = [
        {name: 'trimQueryPath', offset: 0x882c80},
        {name: 'getAuthSignature', offset: 0x890140},
        {name: 'getAuthPayload', offset: 0x890380},
    ];

    hooks.forEach(function(h) {
        var addr = base.add(h.offset);
        try {
            Interceptor.attach(addr, {
                funcName: h.name,
                onEnter: function(args) {
                    console.log('[!] ' + this.funcName + ' ENTER');
                    try {
                        var str = this.context.rcx.readUtf8String(200);
                        if (str) console.log('    rcx: ' + str);
                    } catch(e) {}
                    try {
                        var rdx = this.context.rdx.readUtf8String(200);
                        if (rdx) console.log('    rdx: ' + rdx);
                    } catch(e) {}
                    try {
                        var r8 = this.context.r8.readUtf8String(200);
                        if (r8) console.log('    r8: ' + r8);
                    } catch(e) {}
                },
                onLeave: function(retval) {
                    console.log('[!] ' + this.funcName + ' LEAVE, retval=' + retval);
                    try {
                        var str = this.context.rax.readUtf8String(200);
                        if (str) console.log('    rax: ' + str);
                    } catch(e) {}
                }
            });
            console.log('[OK] ' + h.name + ' hooked');
        } catch(e) {
            console.log('[FAIL] ' + h.name + ': ' + e.message);
        }
    });

    console.log('[Hook] Setup complete');
}
"""

def main():
    device = frida.get_local_device()

    # Kill existing
    for p in device.enumerate_processes():
        if 'lingma' in p.name.lower():
            print(f"Killing: {p.name} (PID: {p.pid})")
            device.kill(p.pid)

    # Start server
    print("Starting Lingma server...")
    # Don't capture stdout - let it print to console
    proc = subprocess.Popen([LINGMA, "start"])

    # Wait for startup
    print("Waiting for server...")
    time.sleep(8)

    # Find PID
    processes = device.enumerate_processes()
    lingma_procs = [p for p in processes if 'lingma' in p.name.lower()]
    if not lingma_procs:
        print("No Lingma found!")
        proc.kill()
        return

    pid = lingma_procs[0].pid
    print(f"PID: {pid}")

    # Attach and hook
    session = device.attach(pid)
    script = session.create_script(HOOK_SCRIPT)
    script.on('message', lambda m, d: print(f"[MSG] {m.get('payload', '')}"))
    script.load()

    # Now send requests that trigger signature computation
    print("\n=== Sending requests ===")

    # Try the known algo endpoints
    endpoints = [
        'http://127.0.0.1:37510/',
        'http://127.0.0.1:37510/health',
        'http://127.0.0.1:37510/algo',
        'http://127.0.0.1:37510/algo/',
        'http://127.0.0.1:37510/algo/ping',
    ]

    for url in endpoints:
        try:
            req = urllib.request.Request(url)
            req.add_header('Content-Type', 'application/json')
            resp = urllib.request.urlopen(req, timeout=5)
            data = resp.read().decode()
            print(f"GET {url} -> {resp.status}: {data[:200]}")
        except urllib.error.HTTPError as e:
            body = e.read().decode() if hasattr(e, 'read') else ''
            print(f"GET {url} -> HTTP {e.code}: {body[:200]}")
        except Exception as e:
            print(f"GET {url} -> Error: {e}")

    # Try POST with heartbeat payload
    try:
        url = 'http://127.0.0.1:37510/algo/heartbeat'
        data = json.dumps({"type": "ping"}).encode()
        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header('Content-Type', 'application/json')
        resp = urllib.request.urlopen(req, timeout=5)
        print(f"POST {url} -> {resp.status}: {resp.read().decode()[:200]}")
    except Exception as e:
        print(f"POST heartbeat -> Error: {e}")

    # Wait for hooks
    print("\nWaiting 20s for hooks...")
    time.sleep(20)

    print("--- Done ---")
    try:
        script.unload()
    except:
        pass
    session.detach()
    proc.kill()

if __name__ == '__main__':
    main()
