"""
Frida Hook v10: 启动服务器 + hook + 通过本地 API 触发签名
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

    // Hook known functions
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
                    console.log('[!HIT] ' + this.funcName);
                    try {
                        var str = this.context.rcx.readUtf8String(300);
                        if (str) console.log('  rcx: ' + str);
                    } catch(e) {}
                },
                onLeave: function(retval) {
                    console.log('[!LEAVE] ' + this.funcName);
                    try {
                        var str = this.context.rax.readUtf8String(300);
                        if (str) console.log('  rax: ' + str);
                    } catch(e) {}
                }
            });
            console.log('[OK] ' + h.name);
        } catch(e) {
            console.log('[FAIL] ' + h.name + ': ' + e.message);
        }
    });

    console.log('[Hook] Ready');
}
"""

def send_request(method, path, body=None):
    """Send request to local Lingma server"""
    url = f'http://127.0.0.1:37510{path}'
    data = json.dumps(body).encode() if body else None
    try:
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header('Content-Type', 'application/json')
        resp = urllib.request.urlopen(req, timeout=5)
        return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode() if hasattr(e, 'read') else str(e)
    except Exception as e:
        return 0, str(e)

def main():
    device = frida.get_local_device()

    # Kill existing
    for p in device.enumerate_processes():
        if 'lingma' in p.name.lower():
            print(f"Killing: {p.name} (PID: {p.pid})")
            device.kill(p.pid)

    # Start server
    print("Starting server...")
    proc = subprocess.Popen([LINGMA, "start"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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

    # Explore local API
    print("\n=== Exploring local API ===")

    paths = [
        ('GET', '/'),
        ('GET', '/api'),
        ('GET', '/api/health'),
        ('GET', '/api/v1'),
        ('GET', '/api/v1/health'),
        ('GET', '/api/v1/signature'),
        ('GET', '/api/v1/algo'),
        ('GET', '/api/v1/auth'),
        ('GET', '/api/v1/user'),
        ('GET', '/api/v1/status'),
        ('GET', '/status'),
        ('GET', '/user'),
        ('GET', '/auth'),
        ('GET', '/algo'),
        ('GET', '/signature'),
    ]

    for method, path in paths:
        status, body = send_request(method, path)
        body_preview = body[:150] if body else ''
        print(f"  {method} {path} -> {status}: {body_preview}")

    # Try POST requests that might trigger signature
    post_requests = [
        ('POST', '/api/v1/signature', {'path': '/algo/ping', 'timestamp': int(time.time())}),
        ('POST', '/api/v1/sign', {'path': '/algo/ping'}),
        ('POST', '/api/v1/auth/sign', {}),
    ]

    print("\n=== POST requests ===")
    for method, path, body in post_requests:
        status, response = send_request(method, path, body)
        print(f"  {method} {path} -> {status}: {response[:200]}")

    # Wait for hooks
    print("\nWaiting 15s...")
    time.sleep(15)

    print("--- Done ---")
    try:
        script.unload()
    except:
        pass
    session.detach()
    proc.kill()

if __name__ == '__main__':
    main()
