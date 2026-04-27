#!/usr/bin/env python3
"""
Read key memory locations from running Lingma process.
"""
import frida
import time

def main():
    device = frida.get_local_device()

    target_pid = None
    for proc in device.enumerate_processes():
        if 'Lingma' in proc.name:
            target_pid = proc.pid
            print(f"[*] Found Lingma process: PID {proc.pid}")
            break

    if not target_pid:
        print("[!] Lingma process not found.")
        return

    session = device.attach(target_pid)

    script = session.create_script("""
        var modules = Process.enumerateModules();
        var lingmaMod = null;
        for (var i = 0; i < modules.length; i++) {
            if (modules[i].name.toLowerCase().indexOf('lingma') !== -1) {
                lingmaMod = modules[i];
                break;
            }
        }

        if (!lingmaMod) {
            console.log('[!] Lingma module not found');
            console.log('[*] Modules: ' + modules.map(function(m){return m.name;}).join(', '));
        } else {
            var base = lingmaMod.base;
            console.log('[*] Lingma module: ' + lingmaMod.name + ' @ ' + base);

            var flagAddr = base.add(0x613b86f);
            console.log('[*] Flag byte: ' + flagAddr.readU8());

            var globalAddr = base.add(0x5fa7cc0);
            var gPtr = globalAddr.readPointer();
            var gLen = globalAddr.add(8).readU64();
            console.log('[*] Global string: ptr=' + gPtr + ' len=' + gLen);

            if (!gPtr.isNull() && gLen > 0 && gLen < 256) {
                try {
                    var gs = gPtr.readUtf8String(gLen.toNumber());
                    console.log('[*] Global string content: \"' + gs + '\"');
                } catch (e) {
                    console.log('[!] Failed to read string: ' + e);
                }
            }

            var shortKeyAddr = base.add(0x24ee3cd);
            var fullKeyAddr = base.add(0x24ee3ad);

            try {
                var shortKey = shortKeyAddr.readUtf8String(64);
                console.log('[*] Short key (64): \"' + shortKey + '\"');
            } catch (e) {
                console.log('[!] Failed to read short key: ' + e);
            }

            try {
                var fullKey = fullKeyAddr.readUtf8String(96);
                console.log('[*] Full key (96): \"' + fullKey + '\"');
            } catch (e) {
                console.log('[!] Failed to read full key: ' + e);
            }
        }
    """)

    def on_message(message, data):
        if message['type'] == 'send':
            print("[MSG]", message['payload'])
        elif message['type'] == 'error':
            print("[ERR]", message.get('description', message))
        else:
            print("[?]", message)

    script.on('message', on_message)
    script.load()
    time.sleep(2)
    print("[*] Done")
    session.detach()

if __name__ == "__main__":
    main()
