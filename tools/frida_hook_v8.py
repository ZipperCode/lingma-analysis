"""
Frida Hook v8: 正确启动 Lingma 服务器后 attach
使用 "lingma start" 命令启动服务器（会持续运行）
"""
import frida
import time
import subprocess
import signal

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

HOOK_SCRIPT = r"""
'use strict';

var mod = Process.findModuleByName('Lingma.exe');
if (!mod) {
    console.log('[Hook] ERROR: Module not found');
} else {
    var base = mod.base;
    console.log('[Hook] Module base: ' + base + ' size: ' + mod.size);

    // Known offsets
    var functions = {
        'trimQueryPath': 0x882c80,
        'getAuthSignature': 0x890140,
        'getAuthPayload': 0x890380,
    };

    for (var name in functions) {
        var addr = base.add(functions[name]);
        try {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    console.log('[' + this.currentFunctionName + '] ENTER');
                    try {
                        var str = this.context.rcx.readUtf8String(200);
                        if (str && str.length > 0 && str.length < 500) {
                            console.log('  input: ' + str);
                        }
                    } catch(e) {}
                },
                onLeave: function(retval) {
                    console.log('[' + this.currentFunctionName + '] LEAVE');
                    try {
                        var str = this.context.rax.readUtf8String(200);
                        if (str && str.length > 0 && str.length < 500) {
                            console.log('  output: ' + str);
                        }
                    } catch(e) {}
                }
            });
            console.log('[Hook] ' + name + ' at ' + addr + ' OK');
        } catch(e) {
            console.log('[Hook] ' + name + ' FAILED: ' + e.message);
        }
    }

    // Search for getAppSalt in symbols
    try {
        var symbols = Process.enumerateSymbols();
        var getAppSalt = symbols.filter(function(s) {
            return s.name.indexOf('getAppSalt') >= 0;
        });
        if (getAppSalt.length > 0) {
            getAppSalt.forEach(function(s) {
                console.log('[Found] getAppSalt: ' + s.name + ' -> ' + s.address);
                // Hook it!
                try {
                    Interceptor.attach(s.address, {
                        onEnter: function(args) {
                            console.log('[getAppSalt] HIT!');
                        },
                        onLeave: function(retval) {
                            console.log('[getAppSalt] RETURN:');
                            try {
                                var ptr = this.context.rax;
                                var len = this.context.rcx;
                                console.log('  ptr=' + ptr + ' len=' + len);
                                var str = ptr.readUtf8String(len.toInt32());
                                console.log('  value: ' + str);
                            } catch(e) {
                                console.log('  read error: ' + e.message);
                            }
                        }
                    });
                    console.log('[Hook] getAppSalt hook installed at ' + s.address);
                } catch(e) {
                    console.log('[Hook] getAppSalt hook error: ' + e.message);
                }
            });
        } else {
            console.log('[Search] No getAppSalt symbol found by name');

            // Try to find cosy/remoting functions
            var remoting = symbols.filter(function(s) {
                return s.name.indexOf('cosy/remoting') >= 0 ||
                       s.name.indexOf('remoting') >= 0;
            });
            console.log('[Search] cosy/remoting symbols: ' + remoting.length);
            remoting.slice(0, 30).forEach(function(s) {
                console.log('  ' + s.name + ' -> ' + s.address);
            });
        }
    } catch(e) {
        console.log('[Search] Symbol enumeration error: ' + e.message);
    }
}

console.log('[Hook] Setup complete');
"""

def main():
    device = frida.get_local_device()

    # Kill existing Lingma processes
    for p in device.enumerate_processes():
        if 'lingma' in p.name.lower():
            print(f"Killing: {p.name} (PID: {p.pid})")
            device.kill(p.pid)

    # Start Lingma server
    print("Starting Lingma server...")
    proc = subprocess.Popen([LINGMA, "start"],
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)

    # Wait for server to start
    print("Waiting 10 seconds for server startup...")
    time.sleep(10)

    # Find Lingma process
    processes = device.enumerate_processes()
    lingma_procs = [p for p in processes if 'lingma' in p.name.lower()]

    if not lingma_procs:
        print("ERROR: No Lingma process found!")
        proc.kill()
        return

    pid = lingma_procs[0].pid
    print(f"Found Lingma PID: {pid}")

    # Attach
    print("Attaching...")
    session = device.attach(pid)
    print("Attached!")

    script = session.create_script(HOOK_SCRIPT)
    script.on('message', lambda msg, data: print(f"[MSG] {msg.get('payload', '')}"))
    script.load()
    print("Script loaded!")

    # Now trigger some activity by making HTTP requests to the server
    print("\nSending test request to trigger signature computation...")
    import urllib.request
    import json

    try:
        req = urllib.request.Request('http://127.0.0.1:37510/health')
        resp = urllib.request.urlopen(req, timeout=5)
        print(f"Health check: {resp.read().decode()}")
    except Exception as e:
        print(f"Health check failed: {e}")

    # Wait for hook output
    print("\nWaiting 30 seconds for hooks to fire...")
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
