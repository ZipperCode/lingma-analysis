"""
Frida Hook v2: 使用 Module.findExportByName 和 DebugSymbol
"""
import frida
import sys
import time

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

HOOK_SCRIPT = r"""
// Use send() to pass messages back
function sendLog(msg) {
    send(msg);
}

function findFunctions() {
    var mod = Process.getModuleByName('Lingma.exe');
    sendLog('Module: Lingma.exe at ' + mod.base + ', size: ' + mod.size);

    // Try to resolve function by name using DebugSymbol
    var funcNames = [
        'cosy/remoting.getAppSalt',
        'cosy/remoting.addBigModelSignatureHeaders',
        'cosy/remoting.createHTTPRequest',
        'cosy/auth/user.getAuthSignature',
        'cosy/auth/user.getAuthPayload',
    ];

    for (var i = 0; i < funcNames.length; i++) {
        var name = funcNames[i];
        var addr = DebugSymbol.fromName(name);
        if (addr && addr.address) {
            sendLog('FOUND: ' + name + ' -> ' + addr.address);
        } else {
            sendLog('NOT FOUND: ' + name);
        }
    }

    // Try to find any function containing 'getApp'
    try {
        var allSymbols = Process.enumerateSymbols();
        sendLog('Total symbols: ' + allSymbols.length);

        var getAppFunctions = allSymbols.filter(function(sym) {
            return sym.name.indexOf('getApp') >= 0;
        });

        sendLog('getApp functions: ' + getAppFunctions.length);
        getAppFunctions.forEach(function(sym) {
            sendLog('  ' + sym.name + ' -> ' + sym.address);
        });

        // Find all cosy/remoting functions
        var remotingFunctions = allSymbols.filter(function(sym) {
            return sym.name.indexOf('remoting') >= 0;
        });

        sendLog('remoting functions: ' + remotingFunctions.length);
        remotingFunctions.slice(0, 50).forEach(function(sym) {
            sendLog('  ' + sym.name + ' -> ' + sym.address);
        });
    } catch(e) {
        sendLog('Symbol enumeration error: ' + e.message);
    }
}

setTimeout(function() {
    findFunctions();
}, 3000);
"""

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[Frida] {message.get('payload', '')}")
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
    print("Process resumed, waiting...")

    # Wait for the hook script to complete
    time.sleep(25)
    print("--- Done ---")

if __name__ == '__main__':
    main()
