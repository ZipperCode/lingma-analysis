"""
方案 B: Hook MD5 计算来反向追踪签名输入
不需要知道 getAppSalt 的地址, 只需捕获 MD5 调用并检查输入
"""
import frida
import sys
import time
import hashlib

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

HOOK_SCRIPT = r"""
console.log('[Script] Starting MD5 interceptor...');

// Hook Go's md5.Sum function
// In Go, md5.Sum writes to a fixed-size array [16]byte
// The function takes a pointer to the hash output and a pointer to the data

// Alternative: Hook the Go runtime's hash function
// Go's md5 implementation uses crypto/md5.block

// Let's try to intercept by hooking known HTTP request functions
// and reading the headers that get set

function findHTTPFunctions() {
    var mod = Process.getModuleByName('Lingma.exe');
    console.log('[Hook] Module at ' + mod.base);

    // Search for all symbols
    var symbols = Process.enumerateSymbols();
    console.log('[Hook] Total symbols: ' + symbols.length);

    // Find cosy/remoting functions that set headers
    var headerFuncs = symbols.filter(function(sym) {
        return sym.name.indexOf('addBigModel') >= 0 ||
               sym.name.indexOf('Signature') >= 0 ||
               sym.name.indexOf('getAppSalt') >= 0 ||
               sym.name.indexOf('remoting') >= 0;
    });

    console.log('[Hook] Header-related functions:');
    headerFuncs.slice(0, 50).forEach(function(sym) {
        console.log('  ' + sym.name + ' -> ' + sym.address);
    });
}

// Try to find the moduledata and pclntab
function findPclntab() {
    var mod = Process.getModuleByName('Lingma.exe');
    var base = mod.base;
    var size = mod.size;

    // Search memory for Go version string
    var versionPattern = '67 6f 31 2e 32 33 2e 30 00';  // "go1.23.0\0"
    var results = Memory.scan(base, size, versionPattern, {
        onMatch: function(address, size) {
            console.log('[Scan] Found Go version at ' + address);
        },
        onComplete: function() {
            console.log('[Scan] Memory scan complete');
        },
        onError: function(error) {
            console.log('[Scan] Error: ' + error.message);
        }
    });
}

setTimeout(function() {
    findHTTPFunctions();
}, 5000);
"""

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[Frida] {message.get('payload', '')}")
    elif message['type'] == 'error':
        print(f"[Error] {message.get('stack', '')}")

def main():
    device = frida.get_local_device()

    # Kill any existing Lingma processes
    processes = device.enumerate_processes()
    for p in processes:
        if 'lingma' in p.name.lower():
            print(f"Killing existing Lingma process: {p.name} (PID: {p.pid})")
            device.kill(p.pid)

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
    print("Process resumed, waiting 30 seconds...")

    time.sleep(30)
    print("--- Timeout ---")

if __name__ == '__main__':
    main()
