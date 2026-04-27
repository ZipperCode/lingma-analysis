#!/usr/bin/env python3
"""
Force Lingma login and hook Md5Encode to capture exact inputs.
"""
import frida
import sys
import time

LINGMA_BIN = r"C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe"

SCRIPT = """
function readGoStr(addr, len) {
    if (addr.isNull() || len === 0 || len > 4096) return '';
    try {
        return addr.readUtf8String(len);
    } catch (e) {
        return '<read error: ' + e + '>';
    }
}

function myHexdump(addr, len) {
    if (addr.isNull() || len === 0 || len > 4096) return '';
    try {
        var bytes = addr.readByteArray(len);
        if (!bytes) return '<null>';
        var hex = '';
        var arr = new Uint8Array(bytes);
        for (var i = 0; i < arr.length && i < 128; i++) {
            hex += ('0' + arr[i].toString(16)).slice(-2);
        }
        return hex;
    } catch (e) {
        return '<hex error: ' + e + '>';
    }
}

function findLingmaBase() {
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
        if (mods[i].name.indexOf('Lingma') !== -1) {
            return mods[i].base;
        }
    }
    return null;
}

// Hook Md5Encode at 0x4563c0
function hookMd5Encode() {
    var base = findLingmaBase();
    if (!base) {
        console.log('[!] Cannot hook Md5Encode: base not found');
        return;
    }
    var addr = base.add(0x4563c0);
    console.log('[*] Hooking Md5Encode at ' + addr);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            // Go 1.17+ ABI: RAX=slice ptr, RBX=slice len, RCX=slice cap
            var arrPtr = this.context.rax;
            var count = this.context.rbx.toInt32();

            console.log('\\n[Md5Encode] count=' + count + ' arr=' + arrPtr);

            for (var i = 0; i < count; i++) {
                var ptr = arrPtr.add(i * 16).readPointer();
                var len = arrPtr.add(i * 16 + 8).readU64().toNumber();
                var s = readGoStr(ptr, len);
                var hx = myHexdump(ptr, Math.min(len, 64));
                console.log('  [' + i + '] ptr=' + ptr + ' len=' + len + ' str="' + s + '"');
                console.log('  [' + i + '] hex=' + hx);
            }

            // Also print backtrace
            console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress).join('\\n'));
        },
        onLeave: function(retval) {
            var ptr = retval;
            var len = this.context.rbx.toInt32();
            var output = readGoStr(ptr, len);
            console.log('[Md5Encode] OUTPUT len=' + len + ' str="' + output + '"');
        }
    });
}

// Also hook addBigModelSignatureHeaders to read stack at call site
function hookAddBigModel() {
    var base = findLingmaBase();
    if (!base) return;

    // Hook at the Md5Encode call inside addBigModelSignatureHeaders (0x8829b2)
    var addr = base.add(0x8829b2);
    console.log('[*] Hooking addBigModelSignatureHeaders::callMd5Encode at ' + addr);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            console.log('\\n[ADSIG::Md5Encode] About to call Md5Encode');

            // Read flag from [rsp+0x40]
            var flag = this.context.rsp.add(0x40).readU64();
            console.log('  flag = ' + flag);

            // Read the string array from [rsp+0xb8]
            var arr = this.context.rsp.add(0xb8);
            console.log('  array at rsp+0xb8:');
            for (var i = 0; i < 3; i++) {
                var ptr = arr.add(i * 16).readPointer();
                var len = arr.add(i * 16 + 8).readU64().toNumber();
                var s = readGoStr(ptr, len);
                var hx = myHexdump(ptr, Math.min(len, 64));
                console.log('    [' + i + '] ptr=' + ptr + ' len=' + len + ' str="' + s + '"');
                console.log('    [' + i + '] hex=' + hx);
            }

            // Also read [rsp+0xe8] which might be the date
            var datePtr = this.context.rsp.add(0xe8).readPointer();
            var dateLen = this.context.rsp.add(0xf0).readU64().toNumber();
            var dateStr = readGoStr(datePtr, dateLen);
            console.log('  date@rsp+0xe8: ptr=' + datePtr + ' len=' + dateLen + ' str="' + dateStr + '"');
        }
    });
}

console.log('[*] Starting hooks...');
hookMd5Encode();
hookAddBigModel();
console.log('[*] All hooks installed');
"""

def main():
    cmd = [LINGMA_BIN, "start"]
    print(f"[*] Spawning Lingma with command: {cmd}")
    device = frida.get_local_device()
    pid = device.spawn(cmd)
    session = device.attach(pid)
    print(f"[*] Attached to PID {pid}")

    script = session.create_script(SCRIPT)

    def on_message(message, data):
        if message['type'] == 'send':
            print("[MSG]", message['payload'])
        elif message['type'] == 'error':
            print("[ERR]", message.get('description', message))
        else:
            print("[?]", message)

    script.on('message', on_message)
    script.load()
    device.resume(pid)
    print("[*] Lingma resumed. Waiting for 60 seconds...")
    time.sleep(60)
    print("[*] Detaching...")
    session.detach()
    print("[*] Done. Restoring config...")

    import shutil
    shutil.copy(r"C:/Users/Zipper/.lingma/portable_config.json.bak",
                r"C:/Users/Zipper/.lingma/portable_config.json")
    print("[*] Config restored from backup.")

if __name__ == "__main__":
    main()
