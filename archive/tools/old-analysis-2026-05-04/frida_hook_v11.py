"""
Frida Hook v11: Attach 到运行中的 Lingma 服务器
然后用 WebSocket 触发签名计算
"""
import frida
import time
import subprocess
import json

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

HOOK_SCRIPT = r"""
'use strict';

var mod = Process.findModuleByName('Lingma.exe');
if (!mod) {
    console.log('[Hook] ERROR: Module not found');
    console.log('Modules:');
    Process.enumerateModules().forEach(function(m) {
        console.log('  ' + m.name + ' base=' + m.base);
    });
} else {
    var base = mod.base;
    console.log('[Hook] Module at ' + base + ' size=' + mod.size);

    // Hook trimQueryPath
    var trimAddr = base.add(0x882c80);
    console.log('[Hook] trimQueryPath addr: ' + trimAddr);

    try {
        Interceptor.attach(trimAddr, {
            onEnter: function(args) {
                console.log('[trimQueryPath] HIT!');
                try {
                    var str = this.context.rcx.readUtf8String(300);
                    console.log('  rcx=' + str);
                } catch(e) { console.log('  rcx err: ' + e.message); }
                try {
                    var str = this.context.rdx.readUtf8String(300);
                    console.log('  rdx=' + str);
                } catch(e) {}
                try {
                    var str = this.context.r8.readUtf8String(300);
                    console.log('  r8=' + str);
                } catch(e) {}
            },
            onLeave: function(retval) {
                console.log('[trimQueryPath] LEAVE');
                try {
                    var str = this.context.rax.readUtf8String(300);
                    console.log('  rax=' + str);
                } catch(e) { console.log('  rax err: ' + e.message); }
            }
        });
        console.log('[Hook] trimQueryPath OK');
    } catch(e) {
        console.log('[Hook] trimQueryPath FAIL: ' + e.message);
    }

    // Hook getAuthSignature
    var authSigAddr = base.add(0x890140);
    try {
        Interceptor.attach(authSigAddr, {
            onEnter: function(args) {
                console.log('[getAuthSignature] HIT!');
            },
            onLeave: function(retval) {
                console.log('[getAuthSignature] LEAVE, retval=' + retval);
                try {
                    var str = this.context.rax.readUtf8String(300);
                    console.log('  rax=' + str);
                } catch(e) {}
                try {
                    var len = this.context.rcx;
                    console.log('  rcx(len)=' + len);
                } catch(e) {}
            }
        });
        console.log('[Hook] getAuthSignature OK');
    } catch(e) {
        console.log('[Hook] getAuthSignature FAIL: ' + e.message);
    }

    // Hook getAuthPayload
    var authPayAddr = base.add(0x890380);
    try {
        Interceptor.attach(authPayAddr, {
            onEnter: function(args) {
                console.log('[getAuthPayload] HIT!');
            },
            onLeave: function(retval) {
                console.log('[getAuthPayload] LEAVE');
                try {
                    var str = this.context.rax.readUtf8String(300);
                    console.log('  rax=' + str);
                } catch(e) {}
            }
        });
        console.log('[Hook] getAuthPayload OK');
    } catch(e) {
        console.log('[Hook] getAuthPayload FAIL: ' + e.message);
    }

    // Search for getAppSalt in symbols
    try {
        var symbols = Process.enumerateSymbols();
        var getAppSalt = symbols.filter(function(s) {
            return s.name.indexOf('getAppSalt') >= 0;
        });
        if (getAppSalt.length > 0) {
            getAppSalt.forEach(function(s) {
                console.log('[SYM] getAppSalt: ' + s.name + ' -> ' + s.address);
                // Hook it!
                try {
                    Interceptor.attach(s.address, {
                        onEnter: function() { console.log('[getAppSalt] ENTER!'); },
                        onLeave: function() {
                            console.log('[getAppSalt] LEAVE!');
                            try {
                                var ptr = this.context.rax;
                                var len = this.context.rcx;
                                var str = ptr.readUtf8String(len.toInt32());
                                console.log('  RETURN: ' + str);
                            } catch(e) {
                                console.log('  read err: ' + e.message);
                                console.log('  rax=' + this.context.rax + ' rcx=' + this.context.rcx);
                            }
                        }
                    });
                    console.log('[Hook] getAppSalt installed at ' + s.address);
                } catch(e) {
                    console.log('[Hook] getAppSalt error: ' + e.message);
                }
            });
        } else {
            console.log('[SYM] No getAppSalt symbol found');
            // Show cosy/remoting functions
            var remoting = symbols.filter(function(s) {
                return s.name.indexOf('cosy/remoting') >= 0;
            });
            console.log('[SYM] cosy/remoting: ' + remoting.length);
            remoting.forEach(function(s) {
                console.log('  ' + s.name + ' -> ' + s.address);
            });
        }
    } catch(e) {
        console.log('[SYM] Error: ' + e.message);
    }

    console.log('[Hook] Setup complete!');
}
"""

def on_message(msg, data):
    payload = msg.get('payload', '')
    if payload:
        print(f"[MSG] {payload}")

def main():
    device = frida.get_local_device()

    # Find running Lingma
    processes = device.enumerate_processes()
    lingma_procs = [p for p in processes if 'lingma' in p.name.lower()]

    if not lingma_procs:
        print("No running Lingma process! Starting it...")
        proc = subprocess.Popen([LINGMA, "start"])
        time.sleep(8)
        processes = device.enumerate_processes()
        lingma_procs = [p for p in processes if 'lingma' in p.name.lower()]
        if not lingma_procs:
            print("Still not found!")
            proc.kill()
            return

    pid = lingma_procs[0].pid
    print(f"Attaching to Lingma PID: {pid}")

    session = device.attach(pid)
    print("Attached!")

    script = session.create_script(HOOK_SCRIPT)
    script.on('message', on_message)
    script.load()
    print("Script loaded!")

    # Now send WebSocket requests to trigger signature
    print("\n=== Sending WebSocket requests ===")
    try:
        import websocket
        ws_url = "ws://127.0.0.1:37010"
        print(f"Connecting to {ws_url}...")
        ws = websocket.create_connection(ws_url, timeout=5)

        # Send initialize
        init_msg = json.dumps({
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "processId": 12345,
                "clientInfo": {"name": "test", "version": "1.0"},
                "locale": "en-US",
                "rootPath": "C:/",
            },
            "id": 1
        })
        ws.send(init_msg)
        result = ws.recv()
        print(f"initialize: {result[:200]}")

        time.sleep(0.5)

        # Send ping
        ping_msg = json.dumps({"jsonrpc": "2.0", "method": "ping", "params": {}})
        ws.send(ping_msg)
        result = ws.recv()
        print(f"ping: {result[:200]}")

        time.sleep(0.5)

        # Send ide/update (might trigger heartbeat with signature)
        ide_msg = json.dumps({
            "jsonrpc": "2.0",
            "method": "ide/update",
            "params": {
                "type": "online",
            },
        })
        ws.send(ide_msg)
        try:
            result = ws.recv()
            print(f"ide/update: {result[:200]}")
        except:
            pass

        ws.close()
    except Exception as e:
        print(f"WebSocket error: {e}")
        print("Trying HTTP instead...")
        try:
            import urllib.request
            req = urllib.request.Request('http://127.0.0.1:37510/')
            req.add_header('Content-Type', 'application/json')
            resp = urllib.request.urlopen(req, timeout=3)
        except Exception as e2:
            print(f"HTTP error: {e2}")

    # Wait for hooks
    print("\nWaiting 10s for hook output...")
    time.sleep(10)

    print("--- Done ---")
    try:
        script.unload()
    except:
        pass
    session.detach()

if __name__ == '__main__':
    main()
