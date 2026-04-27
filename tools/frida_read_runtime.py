#!/usr/bin/env python3
"""
Frida attach to running Lingma: read .data runtime values + hook Md5Encode.
Key insight: .data section values (cosy_ptr, cosy_len) can be modified at runtime.
This script reads the ACTUAL runtime values and hooks Md5Encode.
"""
import frida
import sys
import time
import json
import os

LINGMA_EXE = r"C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe"
WORKDIR = os.path.join(os.environ.get("TEMP", "C:/temp"), "lingma-frida-attach")

SCRIPT = r"""
'use strict';

// .data section RVAs (from static analysis of 2.11.1)
var COSY_PTR_RVA = ptr(0x5fa7cc0);
var COSY_LEN_RVA = ptr(0x5fa7cc8);
var MD5ENCODE_RVA = ptr(0x4563c0);

function readGoStr(addr, len) {
    if (addr.isNull() || len === 0 || len > 4096) return '';
    try {
        return addr.readUtf8String(Math.min(len, 512));
    } catch (e) {
        return '<err:' + e + '>';
    }
}

// Find Lingma module base
var lingmaMod = null;
var mods = Process.enumerateModules();
for (var i = 0; i < mods.length; i++) {
    if (mods[i].name.toLowerCase().indexOf('lingma') !== -1) {
        lingmaMod = mods[i];
        break;
    }
}

if (!lingmaMod) {
    send(JSON.stringify({type: 'error', msg: 'Lingma module not found!'}));
} else {
    var base = lingmaMod.base;
    send(JSON.stringify({type: 'info', msg: 'Lingma base: ' + base + ' name: ' + lingmaMod.name}));

    // Read cosy_ptr from .data at runtime
    var cosyPtrAddr = base.add(COSY_PTR_RVA);
    var cosyLenAddr = base.add(COSY_LEN_RVA);

    try {
        var cosyPtr = cosyPtrAddr.readPointer();
        var cosyLen = cosyLenAddr.readU64();
        send(JSON.stringify({
            type: 'runtime_values',
            cosy_ptr_addr: cosyPtrAddr.toString(),
            cosy_ptr_value: cosyPtr.toString(),
            cosy_len: cosyLen.toNumber(),
            cosy_str: readGoStr(cosyPtr, cosyLen.toNumber()),
        }));
    } catch (e) {
        send(JSON.stringify({type: 'error', msg: 'Failed to read .data: ' + e}));
    }

    // Hook Md5Encode
    var md5encodeAddr = base.add(MD5ENCODE_RVA);
    send(JSON.stringify({type: 'info', msg: 'Hooking Md5Encode at ' + md5encodeAddr}));

    Interceptor.attach(md5encodeAddr, {
        onEnter: function(args) {
            // Go 1.17+ register ABI: RAX=arg0 (ptr to string array), RBX=arg1 (count)
            var arrPtr = this.context.rax;
            var count = this.context.rbx.toInt32();

            if (count <= 0 || count > 100) return;

            var parts = [];
            for (var i = 0; i < count; i++) {
                var ptr = arrPtr.add(i * 16).readPointer();
                var len = arrPtr.add(i * 16 + 8).readU64().toNumber();
                var s = readGoStr(ptr, Math.min(len, 1024));
                parts.push(s);
            }

            var preimage = parts.join('');
            send(JSON.stringify({
                type: 'md5encode',
                count: count,
                parts: parts,
                preimage: preimage,
                preimageLen: preimage.length,
                timestamp: new Date().toISOString(),
            }));

            this.parts = parts;
        },
        onLeave: function(retval) {
            if (!this.parts) return;
            // Go 1.17+: RAX=ret0 (ptr to string), RBX=ret1 (length)
            var ptr = this.context.rax;
            var len = this.context.rbx.toInt32();
            var output = readGoStr(ptr, Math.min(len, 64));
            send(JSON.stringify({
                type: 'md5encode_output',
                output: output,
                outputLen: len,
            }));
        }
    });

    send(JSON.stringify({type: 'info', msg: 'Md5Encode hook installed. Waiting for calls...'}));
}
"""

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        try:
            obj = json.loads(payload)
            msg_type = obj.get('type', '')
            if msg_type == 'runtime_values':
                print('\n========== [RUNTIME .DATA VALUES] ==========')
                print(f"  cosy_ptr: {obj['cosy_ptr_value']}")
                print(f"  cosy_len: {obj['cosy_len']}")
                print(f"  cosy_str: {repr(obj['cosy_str'])}")
                print('=============================================')
            elif msg_type == 'md5encode':
                print('\n========== [Md5Encode CAPTURED] ==========')
                print(f"  Count: {obj['count']}")
                for i, p in enumerate(obj['parts']):
                    print(f"  Part[{i}] (len={len(p)}): {repr(p[:200])}")
                print(f"  PREIMAGE ({obj['preimageLen']} chars): {repr(obj['preimage'][:500])}")
                print(f"  Timestamp: {obj.get('timestamp', 'N/A')}")
            elif msg_type == 'md5encode_output':
                print(f"  MD5 OUTPUT: {obj['output']} (len={obj['outputLen']})")
                print('==========================================')
            elif msg_type == 'info':
                print(f'[*] {obj["msg"]}')
            elif msg_type == 'error':
                print(f'[!] ERROR: {obj["msg"]}')
            else:
                print(f'[MSG] {payload[:300]}')
        except Exception as e:
            print(f'[MSG] {payload[:200]} (parse err: {e})')
    elif message['type'] == 'error':
        print(f'[ERR] {message.get("description", message)}')

def main():
    device = frida.get_local_device()

    # List processes
    print('[*] Looking for Lingma processes...')
    target_pid = None
    for proc in device.enumerate_processes():
        if 'Lingma' in proc.name or 'lingma' in proc.name.lower():
            print(f'  Found: PID {proc.pid} name={proc.name}')
            target_pid = proc.pid

    if not target_pid:
        print('[!] No Lingma process found. Starting Lingma...')
        os.makedirs(WORKDIR, exist_ok=True)
        pid = device.spawn([LINGMA_EXE, 'start', f'--workDir={WORKDIR}'])
        print(f'[*] Spawned PID {pid}')
        session = device.attach(pid)
        script = session.create_script(SCRIPT)
        script.on('message', on_message)
        script.load()
        device.resume(pid)
        print('[*] Lingma resumed. Waiting for events...')
    else:
        print(f'[*] Attaching to PID {target_pid}')
        session = device.attach(target_pid)
        script = session.create_script(SCRIPT)
        script.on('message', on_message)
        script.load()
        print('[*] Attached. Waiting for Md5Encode calls...')

    # Wait for events
    try:
        print('[*] Press Ctrl+C to stop (or wait 120s)...')
        for i in range(120):
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    session.detach()
    print('[*] Done')

if __name__ == '__main__':
    main()
