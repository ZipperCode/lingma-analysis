"""
Frida Hook v13: 只 attach + 等待，让 Lingma 自动调用签名函数
Lingma 有 heartbeat 模块会自动发送心跳请求
"""
import frida
import time
import subprocess

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

HOOK_SCRIPT = r"""
'use strict';

var mod = Process.findModuleByName('Lingma.exe');
if (!mod) {
    console.log('[Hook] Module not found');
} else {
    var base = mod.base;

    // Hook all known functions with full logging
    var hooks = [
        {name: 'trimQueryPath', offset: 0x882c80},
        {name: 'getAuthSignature', offset: 0x890140},
        {name: 'getAuthPayload', offset: 0x890380},
    ];

    hooks.forEach(function(h) {
        try {
            Interceptor.attach(base.add(h.offset), {
                funcName: h.name,
                onEnter: function(args) {
                    var ts = new Date().toISOString();
                    console.log(ts + ' [!] ' + this.funcName + ' ENTER');
                    try {
                        var str = this.context.rcx.readUtf8String(500);
                        if (str) console.log('    rcx: ' + str);
                    } catch(e) {}
                    try {
                        var str = this.context.rdx.readUtf8String(500);
                        if (str) console.log('    rdx: ' + str);
                    } catch(e) {}
                    try {
                        var str = this.context.r8.readUtf8String(500);
                        if (str) console.log('    r8: ' + str);
                    } catch(e) {}
                },
                onLeave: function(retval) {
                    console.log(new Date().toISOString() + ' [!] ' + this.funcName + ' LEAVE');
                    try {
                        var str = this.context.rax.readUtf8String(500);
                        if (str) console.log('    rax: ' + str);
                    } catch(e) {
                        console.log('    rax ptr: ' + this.context.rax);
                    }
                }
            });
            console.log('[OK] ' + h.name + ' at ' + base.add(h.offset));
        } catch(e) {
            console.log('[FAIL] ' + h.name + ': ' + e.message);
        }
    });

    // Also hook HTTP request sending
    // Look for functions that set HTTP headers
    try {
        var symbols = Process.enumerateSymbols();
        var headerFuncs = symbols.filter(function(s) {
            return s.name.indexOf('Header') >= 0 || s.name.indexOf('header') >= 0;
        });
        console.log('[Search] Found ' + headerFuncs.length + ' header-related symbols');
        headerFuncs.slice(0, 10).forEach(function(s) {
            console.log('  ' + s.name + ' -> ' + s.address);
        });
    } catch(e) {}

    console.log('[Hook] Setup complete at ' + new Date().toISOString());
}
"""

def on_message(msg, data):
    payload = msg.get('payload', '')
    if payload:
        print(f"[MSG] {payload}")

def main():
    device = frida.get_local_device()

    # Kill and restart
    for p in device.enumerate_processes():
        if 'lingma' in p.name.lower():
            print(f"Killing: {p.name} (PID: {p.pid})")
            device.kill(p.pid)

    print("Starting Lingma...")
    proc = subprocess.Popen([LINGMA, "start"])
    time.sleep(10)

    # Find PID
    processes = device.enumerate_processes()
    lingma_procs = [p for p in processes if 'lingma' in p.name.lower()]
    if not lingma_procs:
        print("Not found!")
        proc.kill()
        return

    pid = lingma_procs[0].pid
    print(f"PID: {pid}")

    # Attach and hook
    session = device.attach(pid)
    script = session.create_script(HOOK_SCRIPT)
    script.on('message', on_message)
    script.load()

    # Now just wait - the heartbeat module should trigger remote calls
    print("\nWaiting 60 seconds for heartbeat to trigger signature...")
    for i in range(60):
        time.sleep(1)
        if i % 10 == 0:
            print(f"  {i}s elapsed")

    print("--- Done ---")
    try:
        script.unload()
    except:
        pass
    session.detach()
    proc.kill()

if __name__ == '__main__':
    main()
