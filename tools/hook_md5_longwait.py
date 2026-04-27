#!/usr/bin/env python3
"""
Simple attach: hook Md5Encode in any Lingma process and monitor for a long time.
Designed to capture ANY Md5Encode call, not just from addBigModelSignatureHeaders.
"""
import frida
import sys
import time
import json
import subprocess

SCRIPT = """
function readGoStr(addr, len) {
    if (addr.isNull() || len === 0 || len > 4096) return '';
    try { return addr.readUtf8String(len); } catch (e) { return '<err>'; }
}

function installHook() {
    var mod = Process.enumerateModules().filter(function(m) {
        return m.name.toLowerCase().indexOf('lingma') !== -1;
    })[0];

    if (!mod) { console.log('[!] No Lingma module yet'); return false; }

    var base = mod.base;
    var addr = base.add(0x4563c0);
    console.log('[*] Hook Md5Encode @ ' + addr + ' (base=' + base + ')');

    Interceptor.attach(addr, {
        onEnter: function(args) {
            var arrPtr = this.context.rax;
            var count = this.context.rbx.toInt32();
            if (count <= 0 || count > 50) return;

            console.log('');
            console.log('======== [Md5Encode] count=' + count + ' ========');
            var parts = [];
            for (var i = 0; i < count; i++) {
                var ptr = arrPtr.add(i * 16).readPointer();
                var len = arrPtr.add(i * 16 + 8).readU64().toNumber();
                var s = readGoStr(ptr, Math.min(len, 512));
                parts.push(s);
                console.log('  [' + i + '] len=' + len + ' str=' + s);
            }
            var joined = parts.join('');
            console.log('  JOINED (' + joined.length + ' chars): ' + joined);
            this.parts = parts;
        },
        onLeave: function(retval) {
            var outPtr = retval;
            var outLen = this.context.rbx.toInt32();
            var outStr = readGoStr(outPtr, outLen);
            console.log('  OUTPUT: ' + outStr);
            console.log('==========================================');
        }
    });
    return true;
}

// Try repeatedly until module loads
var hooked = false;
for (var i = 0; i < 300; i++) {
    if (installHook()) { hooked = true; break; }
    Thread.sleep(0.5);
}
if (!hooked) console.log('[!] Never found Lingma module');
"""

def main():
    # Restore config and wipe only cosy
    cfg_path = r"C:/Users/Zipper/.lingma/portable_config.json"
    with open(cfg_path, 'r') as f:
        config = json.load(f)

    config.pop('cosy_key', None)
    config.pop('encrypt_user_info', None)
    config['expire_time'] = 0

    with open(cfg_path, 'w') as f:
        json.dump(config, f)
    print('[*] Wiped cosy_key')

    # Spawn
    device = frida.get_local_device()
    cmd = [r"C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe", "start-remote-agent"]
    print(f'[*] Spawning: {cmd}')
    pid = device.spawn(cmd)
    session = device.attach(pid)

    script = session.create_script(SCRIPT)

    def on_message(message, data):
        if message['type'] == 'send':
            print("[MSG]", message['payload'])
        elif message['type'] == 'error':
            print("[ERR]", message.get('description', message))

    script.on('message', on_message)
    script.load()
    device.resume(pid)
    print(f'[*] PID {pid} running. Monitoring 180s...')

    time.sleep(180)
    session.detach()
    print('[*] Done. Restoring config...')

    import shutil
    shutil.copy(cfg_path + '.bak', cfg_path)
    print('[*] Restored')

if __name__ == "__main__":
    main()
