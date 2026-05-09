"""
Frida Hook v6: spawn + 立即注入 + 等待模块加载
使用 Module.load 事件来确保模块加载后再 hook
"""
import frida
import sys
import time

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

HOOK_SCRIPT = r"""
'use strict';

// Log everything
console.log('[JS] Script loaded');

var mod = Process.findModuleByName('Lingma.exe');
console.log('[JS] Module check: ' + (mod ? mod.base.toString() : 'not found'));

if (!mod) {
    console.log('[JS] Waiting for module to load...');

    Process.enumerateModules().forEach(function(m) {
        console.log('[JS] Loaded module: ' + m.name + ' base=' + m.base);
    });

    // Wait and retry
    setTimeout(function() {
        mod = Process.findModuleByName('Lingma.exe');
        if (!mod) {
            console.log('[JS] STILL no module! Process may be exiting.');
            console.log('[JS] Process threads: ' + Process.enumerateThreads().length);
            return;
        }
        doHook(mod);
    }, 2000);
} else {
    doHook(mod);
}

function doHook(mod) {
    console.log('[JS] Module found at ' + mod.base + ' size=' + mod.size);

    // Verify module base by reading first bytes (MZ header)
    var mz = mod.base.readU16();
    console.log('[JS] First 2 bytes: 0x' + mz.toString(16) + ' (should be 0x5a4d for MZ)');

    // Known offset test
    var addr = mod.base.add(0x882c80);
    console.log('[JS] trimQueryPath address: ' + addr);

    // Read first bytes at the target address
    try {
        var bytes = addr.readByteArray(16);
        console.log('[JS] First 16 bytes at trimQueryPath:');
        var arr = new Uint8Array(bytes);
        var hex = '';
        for (var i = 0; i < arr.length; i++) {
            hex += arr[i].toString(16).padStart(2, '0') + ' ';
        }
        console.log('[JS]   ' + hex);
    } catch(e) {
        console.log('[JS] Cannot read at trimQueryPath address: ' + e.message);
    }

    // Try hook
    try {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                console.log('[trimQueryPath] HIT!');
                try {
                    var str = this.context.rcx.readUtf8String(200);
                    console.log('[trimQueryPath] path=' + str);
                } catch(e) { console.log('[trimQueryPath] rcx err=' + e.message); }
            },
            onLeave: function(retval) {
                console.log('[trimQueryPath] LEAVE');
            }
        });
        console.log('[JS] Hook installed successfully at trimQueryPath');
    } catch(e) {
        console.log('[JS] Hook failed: ' + e.message + '\n' + e.stack);
    }

    // Also enumerate ALL symbols that contain "getApp"
    try {
        var symbols = Process.enumerateSymbols().filter(function(s) {
            return s.name.indexOf('getApp') >= 0 || s.name.indexOf('AppSalt') >= 0;
        });
        console.log('[JS] Found ' + symbols.length + ' getApp/AppSalt symbols');
        symbols.forEach(function(s) {
            console.log('  ' + s.name + ' -> ' + s.address);
        });
    } catch(e) {
        console.log('[JS] Symbol enumeration failed: ' + e.message);
    }
}
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

    print("Spawning...")
    pid = device.spawn([BINARY_PATH])
    print(f"Spawned PID: {pid}")

    # Check if process is still alive
    try:
        processes = device.enumerate_processes()
        pids = [p.pid for p in processes]
        print(f"Process alive: {pid in pids}")
    except:
        pass

    print("Attaching...")
    session = device.attach(pid)
    print("Attached!")

    script = session.create_script(HOOK_SCRIPT)
    script.on('message', on_message)
    script.load()
    print("Script loaded!")

    # Give it time
    print("Waiting 15 seconds...")
    time.sleep(15)

    # Check if process still alive
    try:
        processes = device.enumerate_processes()
        pids = [p.pid for p in processes]
        print(f"Process still alive: {pid in pids}")
    except:
        print("Process died")

    print("--- Done ---")
    try:
        script.unload()
    except:
        pass
    session.detach()
    try:
        device.kill(pid)
    except:
        pass

if __name__ == '__main__':
    main()
