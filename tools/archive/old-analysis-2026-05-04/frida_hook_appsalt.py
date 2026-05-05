"""
Frida Hook: 搜索并 hook getAppSalt 函数
"""
import frida
import sys
import time

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

HOOK_SCRIPT = r"""
console.log('[Script] Starting...');

function waitForModule(moduleName, callback, timeout) {
    timeout = timeout || 15000;
    var start = Date.now();
    var interval = setInterval(function() {
        if (Date.now() - start > timeout) {
            clearInterval(interval);
            console.log('[Hook] Timeout waiting for ' + moduleName);
            return;
        }
        var mod = Process.findModuleByName(moduleName);
        if (mod) {
            clearInterval(interval);
            console.log('[Hook] Module loaded: ' + moduleName + ' at ' + mod.base);
            callback(mod);
        }
    }, 100);
}

waitForModule('Lingma.exe', function(mod) {
    console.log('[Hook] Searching symbols...');

    try {
        var symbols = Process.enumerateSymbols();
        console.log('[Hook] Total symbols: ' + symbols.length);

        // Search for getAppSalt
        var matches = symbols.filter(function(sym) {
            return sym.name.indexOf('getAppSalt') >= 0 ||
                   sym.name.indexOf('AppSalt') >= 0;
        });

        console.log('[Hook] getAppSalt matches: ' + matches.length);
        matches.forEach(function(sym) {
            console.log('  ' + sym.name + ' -> ' + sym.address);
        });

        // Search for all remoting functions
        var remotingSymbols = symbols.filter(function(sym) {
            return sym.name.indexOf('remoting') >= 0;
        });

        console.log('[Hook] Remoting symbols (first 30):');
        remotingSymbols.slice(0, 30).forEach(function(sym) {
            console.log('  ' + sym.name + ' -> ' + sym.address);
        });

        // Also search for signature-related functions
        var sigSymbols = symbols.filter(function(sym) {
            return sym.name.indexOf('Signature') >= 0 ||
                   sym.name.indexOf('signature') >= 0 ||
                   sym.name.indexOf('Sign') >= 0;
        });

        console.log('[Hook] Signature symbols (first 30):');
        sigSymbols.slice(0, 30).forEach(function(sym) {
            console.log('  ' + sym.name + ' -> ' + sym.address);
        });
    } catch(e) {
        console.log('[Hook] Error: ' + e.message);
    }
});
"""

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[{message.get('payload', '')}]")
    elif message['type'] == 'error':
        print(f"[Error] {message.get('stack', '')}")

def main():
    device = frida.get_local_device()
    print("Spawning Lingma.exe...")

    pid = device.spawn([BINARY_PATH])
    print(f"Spawned PID: {pid}")

    session = device.attach(pid)
    print("Attached!")

    script = session.create_script(HOOK_SCRIPT)
    script.on('message', on_message)
    script.load()
    print("Script loaded, resuming...")

    device.resume(pid)
    print("Process resumed, waiting for output...")

    # Give it time to start and enumerate symbols
    time.sleep(20)
    print("--- Timeout ---")

    script.unload()
    session.detach()
    try:
        device.kill(pid)
    except:
        pass

if __name__ == '__main__':
    main()
