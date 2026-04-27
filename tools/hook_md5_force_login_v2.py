#!/usr/bin/env python3
"""
Monitor all Lingma processes and hook Md5Encode.
Deletes all cached tokens to force full re-login.
"""
import frida
import sys
import time
import json

LINGMA_BIN = r"C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe"

SCRIPT = """
function readGoStr(addr, len) {
    if (addr.isNull() || len === 0 || len > 4096) return '';
    try {
        return addr.readUtf8String(len);
    } catch (e) {
        return '<err>';
    }
}

function hookMd5Encode() {
    var mod = null;
    // Wait for Lingma module to load
    var attempts = 0;
    while (!mod && attempts < 200) {
        var mods = Process.enumerateModules();
        for (var i = 0; i < mods.length; i++) {
            if (mods[i].name.toLowerCase().indexOf('lingma') !== -1) {
                mod = mods[i];
                break;
            }
        }
        if (!mod) Thread.sleep(0.1);
        attempts++;
    }

    if (!mod) {
        console.log('[!] Lingma module not found after ' + attempts + ' attempts');
        return;
    }

    var base = mod.base;
    console.log('[*] Lingma base: ' + base);

    var addr = base.add(0x4563c0);
    console.log('[*] Hooking Md5Encode at ' + addr);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            var arrPtr = this.context.rax;
            var count = this.context.rbx.toInt32();
            if (count <= 0 || count > 100) return;

            var parts = [];
            console.log('\\n========== [Md5Encode] count=' + count + ' ==========');
            for (var i = 0; i < count; i++) {
                var ptr = arrPtr.add(i * 16).readPointer();
                var len = arrPtr.add(i * 16 + 8).readU64().toNumber();
                var s = readGoStr(ptr, len);
                parts.push(s);
                console.log('  [' + i + '] len=' + len + ' str="' + s + '"');
            }

            // Compute MD5 for verification
            var preimage = parts.join('');
            console.log('  FULL PREIMAGE: "' + preimage + '"');
            console.log('  PREIMAGE LEN: ' + preimage.length);

            this.parts = parts;
        },
        onLeave: function(retval) {
            var ptr = retval;
            var len = this.context.rbx.toInt32();
            var output = readGoStr(ptr, len);
            console.log('  MD5 OUTPUT: "' + output + '" (len=' + len + ')');
            console.log('==========================================\\n');
        }
    });
}

hookMd5Encode();
console.log('[*] Hook setup done');
"""

def find_lingma_pids():
    device = frida.get_local_device()
    pids = []
    for proc in device.enumerate_processes():
        if 'Lingma' in proc.name or 'lingma' in proc.name:
            pids.append(proc.pid)
    return pids

def main():
    # Wipe all tokens
    cfg_path = r"C:/Users/Zipper/.lingma/portable_config.json"
    with open(cfg_path, 'r') as f:
        config = json.load(f)

    # Keep necessary tokens, remove only cosy_key and encrypt_user_info
    keep_keys = ['machine_id', 'user_id', 'user_name', 'security_oauth_token', 'refresh_token']
    new_config = {k: config[k] for k in keep_keys if k in config}
    new_config['expire_time'] = 0

    with open(cfg_path, 'w') as f:
        json.dump(new_config, f)
    print('[*] Config wiped: removed all tokens')
    print(json.dumps(new_config, indent=2))

    # Kill existing Lingma
    device = frida.get_local_device()
    for pid in find_lingma_pids():
        try:
            device.kill(pid)
            print(f'[*] Killed Lingma PID {pid}')
        except:
            pass

    time.sleep(1)

    # Spawn Lingma with start-remote-agent
    cmd = [LINGMA_BIN, "start-remote-agent"]
    print(f'[*] Spawning: {cmd}')
    pid = device.spawn(cmd)
    print(f'[*] Spawned PID {pid}')

    session = device.attach(pid)
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
    print('[*] Resumed. Monitoring for 120 seconds...')

    start = time.time()
    while time.time() - start < 120:
        # Check for new child processes
        current = set(find_lingma_pids())
        if pid not in current:
            print(f'[*] Main process {pid} exited. Checking for children...')
            for child_pid in current:
                try:
                    session2 = device.attach(child_pid)
                    script2 = session2.create_script(SCRIPT)
                    script2.on('message', on_message)
                    script2.load()
                    print(f'[*] Attached to child PID {child_pid}')
                except Exception as e:
                    print(f'[!] Cannot attach to {child_pid}: {e}')
            break
        time.sleep(1)

    time.sleep(60)  # Extra wait
    print('[*] Done monitoring')

    # Restore config from backup
    import shutil
    shutil.copy(cfg_path + '.bak', cfg_path)
    print('[*] Config restored')

if __name__ == "__main__":
    main()
