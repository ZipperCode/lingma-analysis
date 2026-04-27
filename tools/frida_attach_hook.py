#!/usr/bin/env python3
"""
Start Lingma WITHOUT Frida spawn, then attach Frida + hook Md5Encode.
Key: start Lingma via subprocess first, wait for it to stabilize, THEN attach.
"""
import frida
import sys
import time
import json
import os
import subprocess
import signal

LINGMA_EXE = r"C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe"
WORKDIR = os.path.join(os.environ.get("TEMP", "C:/temp"), "lingma-attach-test")

SCRIPT = r"""
'use strict';

var COSY_PTR_RVA = ptr(0x5fa7cc0);
var COSY_LEN_RVA = ptr(0x5fa7cc8);
var MD5ENCODE_RVA = ptr(0x4563c0);

function readGoStr(addr, len) {
    if (addr.isNull() || len === 0 || len > 4096) return '';
    try { return addr.readUtf8String(Math.min(len, 512)); }
    catch (e) { return '<err>'; }
}

var lingmaMod = null;
var mods = Process.enumerateModules();
for (var i = 0; i < mods.length; i++) {
    if (mods[i].name.toLowerCase().indexOf('lingma') !== -1) {
        lingmaMod = mods[i];
        break;
    }
}

if (!lingmaMod) {
    send(JSON.stringify({type: 'error', msg: 'Lingma module not found'}));
} else {
    var base = lingmaMod.base;
    send(JSON.stringify({type: 'info', msg: 'Base: ' + base}));

    // Read .data runtime values
    try {
        var cosyPtr = base.add(COSY_PTR_RVA).readPointer();
        var cosyLen = base.add(COSY_LEN_RVA).readU64();
        send(JSON.stringify({
            type: 'runtime_values',
            cosy_ptr: cosyPtr.toString(),
            cosy_len: cosyLen.toNumber(),
            cosy_str: readGoStr(cosyPtr, cosyLen.toNumber()),
        }));
    } catch (e) {
        send(JSON.stringify({type: 'error', msg: 'Read .data: ' + e}));
    }

    // Also read the key strings at runtime
    // Try to find them by scanning near the known .rodata offsets

    // Hook Md5Encode
    Interceptor.attach(base.add(MD5ENCODE_RVA), {
        onEnter: function(args) {
            var arrPtr = this.context.rax;
            var count = this.context.rbx.toInt32();
            if (count <= 0 || count > 100) return;

            var parts = [];
            for (var i = 0; i < count; i++) {
                var ptr = arrPtr.add(i * 16).readPointer();
                var len = arrPtr.add(i * 16 + 8).readU64().toNumber();
                parts.push(readGoStr(ptr, Math.min(len, 1024)));
            }

            var preimage = parts.join('');
            send(JSON.stringify({
                type: 'md5encode',
                count: count,
                parts: parts,
                preimage: preimage,
                preimageLen: preimage.length,
            }));
            this.parts = parts;
        },
        onLeave: function(retval) {
            if (!this.parts) return;
            var ptr = this.context.rax;
            var len = this.context.rbx.toInt32();
            send(JSON.stringify({
                type: 'md5encode_output',
                output: readGoStr(ptr, Math.min(len, 64)),
                outputLen: len,
            }));
        }
    });
    send(JSON.stringify({type: 'info', msg: 'Md5Encode hooked'}));
}
"""

def on_message(message, data):
    if message['type'] == 'send':
        try:
            obj = json.loads(message['payload'])
            t = obj.get('type', '')
            if t == 'runtime_values':
                print(f'\n*** RUNTIME VALUES: cosy_ptr={obj["cosy_ptr"]} len={obj["cosy_len"]} str={repr(obj["cosy_str"])}')
            elif t == 'md5encode':
                print(f'\n*** Md5Encode: count={obj["count"]} preimage={repr(obj["preimage"][:500])}')
                for i, p in enumerate(obj['parts']):
                    print(f'    Part[{i}] (len={len(p)}): {repr(p[:200])}')
            elif t == 'md5encode_output':
                print(f'    MD5={obj["output"]}')
            elif t == 'info':
                print(f'  [info] {obj["msg"]}')
            elif t == 'error':
                print(f'  [ERR] {obj["msg"]}')
            else:
                print(f'  [{t}] {str(obj)[:200]}')
        except:
            print(f'  [raw] {message["payload"][:200]}')
    elif message['type'] == 'error':
        print(f'  [FERR] {message.get("description", message)}')

def main():
    os.makedirs(WORKDIR, exist_ok=True)

    # Kill any existing Lingma
    print('[*] Killing existing Lingma...')
    device = frida.get_local_device()
    for proc in device.enumerate_processes():
        if 'Lingma' in proc.name or 'lingma' in proc.name.lower():
            try:
                device.kill(proc.pid)
                print(f'  Killed PID {proc.pid}')
            except:
                pass
    time.sleep(2)

    # Start Lingma via subprocess (NOT Frida spawn)
    print(f'[*] Starting Lingma in {WORKDIR}...')
    lingma_proc = subprocess.Popen(
        [LINGMA_EXE, 'start', f'--workDir={WORKDIR}'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print(f'[*] Lingma PID: {lingma_proc.pid}')

    # Wait for it to initialize
    print('[*] Waiting 5s for Lingma to initialize...')
    time.sleep(5)

    if lingma_proc.poll() is not None:
        print(f'[!] Lingma exited with code {lingma_proc.returncode}')
        return

    print('[*] Attaching Frida...')
    try:
        session = device.attach(lingma_proc.pid)
    except Exception as e:
        print(f'[!] Attach failed: {e}')
        lingma_proc.terminate()
        return

    script = session.create_script(SCRIPT)
    script.on('message', on_message)
    script.load()
    print('[*] Frida attached. Waiting for Md5Encode calls (60s max)...')

    # Wait for events
    for i in range(60):
        time.sleep(1)
        if lingma_proc.poll() is not None:
            print(f'[!] Lingma exited with code {lingma_proc.returncode}')
            break

    print('[*] Cleaning up...')
    session.detach()
    try:
        lingma_proc.terminate()
        time.sleep(2)
        if lingma_proc.poll() is None:
            lingma_proc.kill()
    except:
        pass
    print('[*] Done')

if __name__ == '__main__':
    main()
