#!/usr/bin/env python3
"""
Hook Md5Encode and addBigModelSignatureHeaders to capture old Signature preimage.
"""
import frida
import sys
import time

LINGMA_BIN = r"C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe"

SCRIPT = """
var inSignatureHeaders = false;
var sigHeaderCallId = 0;

function readGoStr(addr, len) {
    if (addr.isNull() || len === 0 || len > 4096) return '';
    try {
        return addr.readUtf8String(len);
    } catch (e) {
        return '';
    }
}

function readStringArray(baseAddr, count) {
    var parts = [];
    for (var i = 0; i < count; i++) {
        var ptr = baseAddr.add(i * 16).readPointer();
        var len = baseAddr.add(i * 16 + 8).readU64();
        var s = readGoStr(ptr, len.toNumber());
        parts.push(s);
    }
    return parts;
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
            var arrPtr = this.context.rax;
            var count = this.context.rbx.toInt32();
            var tag = inSignatureHeaders ? '[Md5Encode/SIG]' : '[Md5Encode/OTHER]';
            var parts = readStringArray(arrPtr, count);
            var fullInput = parts.join('|');
            console.log(tag + ' count=' + count + ' input=' + fullInput);
            this.inputParts = parts;
        },
        onLeave: function(retval) {
            var ptr = retval;
            var len = this.context.rbx;
            var output = readGoStr(ptr, len.toInt32());
            var tag = inSignatureHeaders ? '[Md5Encode/SIG]' : '[Md5Encode/OTHER]';
            console.log(tag + ' output=' + output);
        }
    });
}

function hookAddBigModelSignatureHeaders() {
    var base = findLingmaBase();
    if (!base) {
        console.log('[!] Cannot hook addBigModelSignatureHeaders: base not found');
        return;
    }
    var addr = base.add(0x882760);
    console.log('[*] Hooking addBigModelSignatureHeaders at ' + addr);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            inSignatureHeaders = true;
            sigHeaderCallId++;
            console.log('[addBigModelSignatureHeaders] ENTER call=' + sigHeaderCallId);
        },
        onLeave: function(retval) {
            console.log('[addBigModelSignatureHeaders] LEAVE call=' + sigHeaderCallId);
            inSignatureHeaders = false;
        }
    });
}

console.log('[*] Starting hooks...');
hookMd5Encode();
hookAddBigModelSignatureHeaders();
console.log('[*] All hooks installed');
"""

def main():
    if len(sys.argv) > 1:
        cmd = sys.argv[1:]
    else:
        cmd = [LINGMA_BIN, "status"]

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
    print("[*] Lingma resumed. Waiting for 30 seconds...")
    time.sleep(30)
    print("[*] Detaching...")
    session.detach()
    print("[*] Done")

if __name__ == "__main__":
    main()
