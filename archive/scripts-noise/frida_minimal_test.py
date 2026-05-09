"""
最小 Frida 测试: 只 spawn + attach + 打印基本信息
"""
import frida
import time

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

SCRIPT = r"""
console.log('=== JS START ===');
console.log('Process ID: ' + Process.id);
console.log('Process arch: ' + Process.arch);
console.log('Platform: ' + Process.platform);

var mod = Process.findModuleByName('Lingma.exe');
console.log('Lingma.exe module: ' + (mod ? mod.base + ' size=' + mod.size : 'NOT FOUND'));

// List all loaded modules
var modules = Process.enumerateModules();
console.log('Total modules: ' + modules.length);
modules.slice(0, 10).forEach(function(m) {
    console.log('  ' + m.name + ' base=' + m.base + ' size=' + m.size);
});

// Try to find ANY function by known offset
if (mod) {
    var addr = mod.base.add(0x882c80);
    console.log('trimQueryPath addr: ' + addr);
    try {
        var bytes = addr.readByteArray(8);
        var arr = new Uint8Array(bytes);
        var hex = Array.from(arr).map(function(b) { return b.toString(16).padStart(2,'0'); }).join(' ');
        console.log('First 8 bytes: ' + hex);
    } catch(e) {
        console.log('Cannot read at addr: ' + e.message);
    }
}

// Try a simple hook
try {
    Interceptor.attach(ptr(Process.id), {
        onEnter: function() { console.log('BAD: attached to invalid ptr'); }
    });
} catch(e) {
    console.log('Expected error attaching to invalid ptr: ' + e.message);
}

console.log('=== JS END ===');
"""

def main():
    device = frida.get_local_device()

    # Kill existing
    for p in device.enumerate_processes():
        if 'lingma' in p.name.lower():
            print(f"Killing: {p.name} (PID: {p.pid})")
            device.kill(p.pid)

    print("Spawning...")
    try:
        pid = device.spawn([BINARY_PATH])
        print(f"Spawned PID: {pid}")
    except Exception as e:
        print(f"Spawn failed: {e}")
        return

    # Immediately check if process exists
    print("\nChecking if process is alive...")
    try:
        procs = device.enumerate_processes()
        alive = any(p.pid == pid for p in procs)
        print(f"Process alive: {alive}")
        if alive:
            proc = next(p for p in procs if p.pid == pid)
            print(f"Process name: {proc.name}")
    except Exception as e:
        print(f"Error checking: {e}")

    # Try to attach
    print("\nAttaching...")
    try:
        session = device.attach(pid)
        print("Attached!")
    except Exception as e:
        print(f"Attach failed: {e}")
        return

    # Load script
    print("Creating script...")
    script = session.create_script(SCRIPT)

    messages = []
    def on_message(msg, data):
        payload = msg.get('payload', '')
        messages.append(payload)
        print(f"[MSG] {payload}")

    script.on('message', on_message)

    print("Loading script...")
    script.load()
    print("Script loaded!")

    time.sleep(5)

    print(f"\nTotal messages received: {len(messages)}")
    if messages:
        print("All messages:")
        for m in messages:
            print(f"  {m}")
    else:
        print("NO MESSAGES RECEIVED! JS script didn't execute or process died.")

    # Cleanup
    try:
        script.unload()
    except:
        pass
    try:
        session.detach()
    except:
        pass
    try:
        device.kill(pid)
    except:
        print("Process already dead")

if __name__ == '__main__':
    main()
