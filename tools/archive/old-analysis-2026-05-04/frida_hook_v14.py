"""
Frida Hook v14: Hook Go HTTP 传输层来捕获签名
Hook net/http 的 RoundTrip 函数
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

    // Search for net/http related functions
    try {
        var symbols = Process.enumerateSymbols();

        // Find RoundTrip
        var roundTrip = symbols.filter(function(s) {
            return s.name.indexOf('RoundTrip') >= 0 ||
                   s.name.indexOf('roundTrip') >= 0 ||
                   s.name.indexOf('net/http') >= 0;
        });
        console.log('[Search] net/http symbols: ' + roundTrip.length);
        roundTrip.slice(0, 30).forEach(function(s) {
            console.log('  ' + s.name + ' -> ' + s.address);
        });

        // Find any function with "signature" or "sign" in the name
        var signFuncs = symbols.filter(function(s) {
            return s.name.indexOf('Sign') >= 0 ||
                   s.name.indexOf('sign') >= 0 ||
                   s.name.indexOf('Secret') >= 0 ||
                   s.name.indexOf('secret') >= 0;
        });
        console.log('[Search] Sign/Secret symbols: ' + signFuncs.length);
        signFuncs.slice(0, 30).forEach(function(s) {
            console.log('  ' + s.name + ' -> ' + s.address);
        });

        // Find any function with "cosy" in the name
        var cosyFuncs = symbols.filter(function(s) {
            return s.name.indexOf('cosy') >= 0;
        });
        console.log('[Search] cosy symbols: ' + cosyFuncs.length);
        cosyFuncs.slice(0, 30).forEach(function(s) {
            console.log('  ' + s.name + ' -> ' + s.address);
        });

    } catch(e) {
        console.log('[Search] Error: ' + e.message);
    }

    console.log('[Hook] Setup complete');
}
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
    time.sleep(8)

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

    time.sleep(5)

    print("--- Done ---")
    try:
        script.unload()
    except:
        pass
    session.detach()
    proc.kill()

if __name__ == '__main__':
    main()
