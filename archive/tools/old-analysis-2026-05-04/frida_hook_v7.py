"""
Frida Hook v7: 修复版 - 确认进程存活 + 等待 + 主动触发
基于最小测试的成功经验，我们知道 JS 可以执行
"""
import frida
import time
import subprocess
import sys

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

HOOK_SCRIPT = r"""
'use strict';

var mod = Process.findModuleByName('Lingma.exe');
if (!mod) {
    console.log('[Hook] ERROR: Module not found');
} else {
    var base = mod.base;
    console.log('[Hook] Module base: ' + base + ' size: ' + mod.size);

    // Known offset for trimQueryPath
    var trimOffset = 0x882c80;
    var trimAddr = base.add(trimOffset);
    console.log('[Hook] trimQueryPath at: ' + trimAddr);

    // Read and verify it looks like a function
    try {
        var bytes = trimAddr.readByteArray(16);
        var arr = new Uint8Array(bytes);
        var hex = Array.from(arr).map(function(b) {
            return b.toString(16).padStart(2, '0');
        }).join(' ');
        console.log('[Hook] trimQueryPath bytes: ' + hex);

        // 49 3b 66 10 = CMP RSP, [R14+0x10] (Go prologue)
        if (arr[0] === 0x49 && arr[1] === 0x3b && arr[2] === 0x66 && arr[3] === 0x10) {
            console.log('[Hook] Confirmed: looks like a Go function prologue');
        }
    } catch(e) {
        console.log('[Hook] Cannot read bytes: ' + e.message);
    }

    // Hook trimQueryPath
    try {
        Interceptor.attach(trimAddr, {
            onEnter: function(args) {
                console.log('[trimQueryPath] HIT!');
                try {
                    var str = this.context.rcx.readUtf8String(200);
                    console.log('[trimQueryPath] input: ' + str);
                } catch(e) {
                    console.log('[trimQueryPath] rcx read error: ' + e.message);
                }
            },
            onLeave: function(retval) {
                console.log('[trimQueryPath] LEAVE');
                try {
                    var str = this.context.rax.readUtf8String(200);
                    console.log('[trimQueryPath] output: ' + str);
                } catch(e) {
                    console.log('[trimQueryPath] rax read error: ' + e.message);
                }
            }
        });
        console.log('[Hook] trimQueryPath hook installed successfully');
    } catch(e) {
        console.log('[Hook] trimQueryPath hook failed: ' + e.message);
    }

    // Also hook getAuthSignature at 0x890140
    var authSigOffset = 0x890140;
    var authSigAddr = base.add(authSigOffset);
    try {
        Interceptor.attach(authSigAddr, {
            onEnter: function(args) {
                console.log('[getAuthSignature] HIT!');
            },
            onLeave: function(retval) {
                console.log('[getAuthSignature] LEAVE');
            }
        });
        console.log('[Hook] getAuthSignature hook installed');
    } catch(e) {
        console.log('[Hook] getAuthSignature hook failed: ' + e.message);
    }

    // Search for getAppSalt function by name in symbols
    var symbols = Process.enumerateSymbols();
    var getAppSaltSyms = symbols.filter(function(s) {
        return s.name.indexOf('getAppSalt') >= 0 || s.name.indexOf('AppSalt') >= 0;
    });
    if (getAppSaltSyms.length > 0) {
        getAppSaltSyms.forEach(function(s) {
            console.log('[Symbol] getAppSalt: ' + s.name + ' -> ' + s.address);
        });
    } else {
        console.log('[Symbol] No getAppSalt symbol found');
    }

    // Find all cosy/remoting functions
    var remotingSyms = symbols.filter(function(s) {
        return s.name.indexOf('cosy/remoting') >= 0;
    });
    console.log('[Symbol] cosy/remoting functions: ' + remotingSyms.length);
    remotingSyms.slice(0, 50).forEach(function(s) {
        console.log('  ' + s.name + ' -> ' + s.address);
    });

    // Also find cosy/auth functions
    var authSyms = symbols.filter(function(s) {
        return s.name.indexOf('cosy/auth') >= 0;
    });
    console.log('[Symbol] cosy/auth functions: ' + authSyms.length);
    authSyms.slice(0, 20).forEach(function(s) {
        console.log('  ' + s.name + ' -> ' + s.address);
    });
}

console.log('[Hook] Setup complete, waiting for function calls...');
console.log('[Hook] Script will stay alive until unloaded');
"""

def on_message(message, data):
    payload = message.get('payload', '')
    if message['type'] == 'send':
        print(f"[Frida] {payload}")
    elif message['type'] == 'error':
        print(f"[Error] {message.get('stack', '')}")

def main():
    device = frida.get_local_device()

    # Kill existing
    for p in device.enumerate_processes():
        if 'lingma' in p.name.lower():
            print(f"Killing: {p.name} (PID: {p.pid})")
            device.kill(p.pid)

    print("Spawning Lingma...")
    pid = device.spawn([BINARY_PATH])
    print(f"Spawned PID: {pid}")

    # Check if process is alive
    procs = device.enumerate_processes()
    alive = any(p.pid == pid for p in procs)
    print(f"Process alive after spawn: {alive}")

    print("Attaching...")
    session = device.attach(pid)
    print("Attached!")

    script = session.create_script(HOOK_SCRIPT)
    script.on('message', on_message)
    script.load()
    print("Script loaded!")

    # The JS runs synchronously during load(), so we've already seen its output
    # Now we need to RESUME the process and wait for functions to be called
    print("Resuming process...")
    device.resume(pid)
    print("Process resumed!")

    # Wait for the process to call our hooked functions
    # The process needs time to initialize and make API calls
    print("Waiting 60 seconds for function calls...")
    for i in range(60):
        time.sleep(1)
        # Check if process is still alive
        try:
            procs = device.enumerate_processes()
            if not any(p.pid == pid for p in procs):
                print(f"Process died after {i} seconds!")
                break
            if i % 10 == 0:
                print(f"  {i}s elapsed, process still alive")
        except:
            print(f"Process check failed at {i}s")
            break

    print("--- Done ---")
    try:
        script.unload()
    except:
        pass
    try:
        session.detach()
    except:
        pass
    try:
        device.kill(pid)
    except:
        pass

if __name__ == '__main__':
    main()
