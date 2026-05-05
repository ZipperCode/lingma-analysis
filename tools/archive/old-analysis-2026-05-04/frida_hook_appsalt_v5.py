"""
Frida Hook v5: Attach 模式 (原始成功的方式)
先用 attach 模式 hook 已知的 trimQueryPath (0x882c80) 来验证 offset 有效性
"""
import frida
import sys
import time
import subprocess

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

HOOK_SCRIPT = r"""
console.log('[Script] Starting attach-mode hook...');

var mod = Process.findModuleByName('Lingma.exe');
if (!mod) {
    console.log('[Hook] Module NOT found! Listing modules...');
    Process.enumerateModules().forEach(function(m) {
        if (m.name.toLowerCase().indexOf('lingma') >= 0) {
            console.log('  Found: ' + m.name + ' base=' + m.base + ' size=' + m.size);
        }
    });
} else {
    console.log('[Hook] Lingma.exe at ' + mod.base + ' size=' + mod.size);

    // Try known offset
    var offset = 0x882c80;
    var addr = mod.base.add(offset);
    console.log('[Hook] trimQueryPath at ' + addr);

    try {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                console.log('[trimQueryPath] ENTER');
                try {
                    var str = this.context.rcx.readUtf8String(200);
                    console.log('[trimQueryPath] path=' + str);
                } catch(e) {
                    console.log('[trimQueryPath] rcx read failed: ' + e.message);
                }
            },
            onLeave: function(retval) {
                console.log('[trimQueryPath] LEAVE');
                try {
                    var str = this.context.rax.readUtf8String(200);
                    console.log('[trimQueryPath] result=' + str);
                } catch(e) {
                    console.log('[trimQueryPath] rax read failed: ' + e.message);
                }
            }
        });
        console.log('[Hook] SUCCESS: hooked trimQueryPath at 0x882c80');
    } catch(e) {
        console.log('[Hook] FAILED trimQueryPath: ' + e.message);
    }

    // Also try getAuthSignature at 0x890140
    var addr2 = mod.base.add(0x890140);
    try {
        Interceptor.attach(addr2, {
            onEnter: function(args) {
                console.log('[getAuthSignature] ENTER');
            },
            onLeave: function(retval) {
                console.log('[getAuthSignature] LEAVE');
            }
        });
        console.log('[Hook] SUCCESS: hooked getAuthSignature at 0x890140');
    } catch(e) {
        console.log('[Hook] FAILED getAuthSignature: ' + e.message);
    }
}

// Search for getAppSalt function by name
var allSymbols = Process.enumerateSymbols();
var getAppSalt = allSymbols.filter(function(s) {
    return s.name.indexOf('getAppSalt') >= 0;
});
if (getAppSalt.length > 0) {
    getAppSalt.forEach(function(s) {
        console.log('[Found] getAppSalt symbol: ' + s.name + ' -> ' + s.address);
    });
} else {
    console.log('[Search] No getAppSalt symbol found by name');
}

// Search for all cosy/remoting functions
var remoting = allSymbols.filter(function(s) {
    return s.name.indexOf('remoting') >= 0 || s.name.indexOf('cosy') >= 0;
});
if (remoting.length > 0) {
    console.log('[Search] Found ' + remoting.length + ' cosy/remoting symbols');
    remoting.slice(0, 30).forEach(function(s) {
        console.log('  ' + s.name + ' -> ' + s.address);
    });
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

    # Start Lingma normally
    print("Starting Lingma.exe...")
    proc = subprocess.Popen([BINARY_PATH])
    time.sleep(5)  # Wait for startup

    # Find Lingma process
    processes = device.enumerate_processes()
    lingma_pids = [p for p in processes if 'lingma' in p.name.lower()]

    if not lingma_pids:
        print("ERROR: No Lingma process found after startup!")
        proc.kill()
        return

    pid = lingma_pids[0].pid
    print(f"Found Lingma PID: {pid}")

    # Attach
    print("Attaching to PID...")
    session = device.attach(pid)
    print("Attached!")

    script = session.create_script(HOOK_SCRIPT)
    script.on('message', on_message)
    script.load()
    print("Script loaded!")

    # Wait for output
    print("Waiting 25 seconds for hook output...")
    time.sleep(25)

    print("--- Timeout ---")
    try:
        script.unload()
    except:
        pass
    session.detach()
    proc.kill()

if __name__ == '__main__':
    main()
