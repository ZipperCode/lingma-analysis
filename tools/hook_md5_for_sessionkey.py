#!/usr/bin/env python3
"""
Spawn Lingma, hook Md5Encode + addBigModelSignatureHeaders to capture
old Signature preimage.
"""
import frida
import sys
import json
import time

LINGMA_BIN = r"C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe"

# Known offsets (relative to module base / ImageBase 0x140000000)
OFF_Md5Encode = 0x4563c0
OFF_addBigModelSignatureHeaders = 0x882760

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

function findLingmaBase() {
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
        if (mods[i].name.indexOf('Lingma') !== -1) {
            console.log('[*] Found module: ' + mods[i].name + ' @ ' + mods[i].base);
            return mods[i].base;
        }
    }
    console.log('[!] Lingma module not found, modules: ' + mods.map(function(m){return m.name;}).join(', '));
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
            var ptr = this.context.rax;
            var len = this.context.rbx;
            var input = readGoStr(ptr, len.toInt32());
            var tag = inSignatureHeaders ? '[Md5Encode/SIG]' : '[Md5Encode/OTHER]';
            console.log(tag + ' len=' + len + ' input=' + input);
            this.inputStr = input;
        },
        onLeave: function(retval) {
            var ptr = retval;
            var output = readGoStr(ptr, 32);
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
    print("[*] Spawning Lingma with 'start' command...")
    device = frida.get_local_device()
    pid = device.spawn([LINGMA_BIN, "start"])
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
    print("[*] Lingma resumed. Waiting for 20 seconds...")
    time.sleep(20)
    print("[*] Detaching...")
    session.detach()
    print("[*] Done")

if __name__ == "__main__":
    main()
