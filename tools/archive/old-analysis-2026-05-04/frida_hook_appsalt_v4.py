"""
Frida Hook v4: 等待模块加载后 hook
"""
import frida
import sys
import time

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

# Simplest possible hook script - just log module loads
HOOK_SCRIPT = r"""
console.log('[Script] Starting hook...');

// Hook trimQueryPath at known offset
function hook() {
    var mod = Process.findModuleByName('Lingma.exe');
    if (!mod) {
        console.log('[Hook] Module not found yet');
        return;
    }

    console.log('[Hook] Module found at ' + mod.base);

    var offset = 0x882c80;
    var addr = mod.base.add(offset);

    console.log('[Hook] Trying to hook trimQueryPath at ' + addr);

    try {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                console.log('[trimQueryPath] ENTER');
                var str = this.context.rcx.readUtf8String(200);
                console.log('[trimQueryPath] path: ' + str);
            },
            onLeave: function(retval) {
                console.log('[trimQueryPath] LEAVE');
                var str = this.context.rax.readUtf8String(200);
                console.log('[trimQueryPath] result: ' + str);
            }
        });
        console.log('[Hook] Successfully hooked trimQueryPath');
    } catch(e) {
        console.log('[Hook] Failed to hook: ' + e.message);
    }
}

// Try hooking after a delay
setTimeout(hook, 3000);
"""

def on_message(message, data):
    payload = message.get('payload', '')
    if message['type'] == 'send':
        print(f"[Frida] {payload}")
    elif message['type'] == 'error':
        print(f"[Error] {message.get('stack', '')}")

def main():
    device = frida.get_local_device()

    # Kill any existing Lingma
    for p in device.enumerate_processes():
        if 'lingma' in p.name.lower():
            print(f"Killing: {p.name} (PID: {p.pid})")
            device.kill(p.pid)

    print("Spawning Lingma...")
    pid = device.spawn([BINARY_PATH])
    print(f"Spawned PID: {pid}")

    # Wait a moment for process initialization
    time.sleep(2)

    print("Attaching...")
    session = device.attach(pid)
    print("Attached!")

    script = session.create_script(HOOK_SCRIPT)
    script.on('message', on_message)
    script.load()
    print("Script loaded")

    print("Resuming process...")
    device.resume(pid)

    # Wait for output
    print("Waiting 30 seconds for hook output...")
    time.sleep(30)

    print("--- Timeout ---")
    try:
        script.unload()
    except:
        pass
    session.detach()
    try:
        device.kill(pid)
    except:
        pass

if __name__ == '__main__':
    main()
