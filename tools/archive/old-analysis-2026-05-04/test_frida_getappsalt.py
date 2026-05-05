"""
测试 Frida 基本功能 - 逐步验证 getAppSalt hook
"""
import frida
import time
import subprocess

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

def main():
    device = frida.get_local_device()

    # Kill existing
    for p in device.enumerate_processes():
        if 'lingma' in p.name.lower():
            device.kill(p.pid)

    print("Starting Lingma...")
    proc = subprocess.Popen([LINGMA, "start"])
    time.sleep(10)

    processes = device.enumerate_processes()
    lingma_procs = [p for p in processes if 'lingma' in p.name.lower()]
    if not lingma_procs:
        print("Not found!")
        proc.kill()
        return

    pid = lingma_procs[0].pid
    print(f"PID: {pid}")

    # Test 1: Simple module enumeration
    print("\n=== Test 1: Module enumeration ===")
    test_script = """
    'use strict';
    var mods = Process.enumerateModules().filter(m => m.name.includes('Lingma'));
    console.log('Found modules:');
    mods.forEach(function(m) {
        console.log('  ' + m.name + ' base=' + m.base + ' size=' + m.size);
    });

    if (mods.length > 0) {
        var base = mods[0].base;
        console.log('\\nBase address: ' + base);
        console.log('getAppSalt target: ' + base.add(0x882760));
        console.log('Module at 0x882760 offset: ' + base.add(0x882760));

        // Try to read a byte at getAppSalt
        try {
            var byteVal = base.add(0x882760).readU8();
            console.log('Byte at getAppSalt: 0x' + byteVal.toString(16));
        } catch(e) {
            console.log('Cannot read at getAppSalt: ' + e.message);
        }
    }
    """

    session = device.attach(pid)
    script = session.create_script(test_script)
    script.on('message', lambda m, d: print(f"[MSG] {m}"))
    script.load()
    time.sleep(2)
    script.unload()

    # Test 2: Try hooking a known Windows export first
    print("\n=== Test 2: Hook WSASend ===")
    test_script2 = """
    'use strict';
    var ws2 = Module.findBaseAddress('ws2_32.dll');
    console.log('ws2_32.dll base: ' + ws2);
    var exports = Module.enumerateExports('ws2_32.dll');
    var wsasend = exports.filter(function(e) { return e.name === 'WSASend'; });
    if (wsasend.length > 0) {
        console.log('WSASend at: ' + wsasend[0].address);
        Interceptor.attach(wsasend[0].address, {
            onEnter: function(args) {
                console.log('WSASend called!');
            }
        });
        console.log('WSASend hooked successfully');
    }
    """

    session2 = device.attach(pid)
    script2 = session2.create_script(test_script2)
    script2.on('message', lambda m, d: print(f"[MSG] {m}"))
    script2.load()
    time.sleep(2)
    script2.unload()

    # Test 3: Try hooking getAppSalt with proper pointer handling
    print("\n=== Test 3: Hook getAppSalt ===")
    test_script3 = """
    'use strict';
    var mods = Process.enumerateModules().filter(m => m.name.includes('Lingma'));
    if (mods.length === 0) {
        console.log('Lingma module not found!');
    } else {
        var base = mods[0].base;
        var getAppSalt = base.add(0x882760);
        console.log('Attempting to hook getAppSalt at: ' + getAppSalt);

        try {
            Interceptor.attach(getAppSalt, {
                onEnter: function(args) {
                    console.log('getAppSalt ENTERED!');
                    console.log('  rcx=' + this.context.rcx);
                },
                onLeave: function(retval) {
                    console.log('getAppSalt RETURNED');
                    console.log('  rax=' + this.context.rax);
                    console.log('  rcx=' + this.context.rcx);
                    try {
                        var ptr = this.context.rax;
                        var len = this.context.rcx.toInt32();
                        console.log('  string ptr=0x' + ptr.toString(16) + ' len=' + len);
                        if (len > 0 && len < 100) {
                            var str = ptr.readUtf8String(len);
                            console.log('  SALT: "' + str + '"');
                        }
                    } catch(e) {
                        console.log('  Error reading return: ' + e.message);
                    }
                }
            });
            console.log('getAppSalt hook installed successfully!');
        } catch(e) {
            console.log('Failed to hook getAppSalt: ' + e.message);
            // Try reading the memory at that address
            try {
                console.log('Byte at getAppSalt: 0x' + getAppSalt.readU8().toString(16));
                console.log('4 bytes: ' + getAppSalt.readU32().toString(16));
            } catch(e2) {
                console.log('Cannot read memory at getAppSalt: ' + e2.message);
            }
        }
    }
    """

    session3 = device.attach(pid)
    script3 = session3.create_script(test_script3)
    script3.on('message', lambda m, d: print(f"[MSG] {m}"))
    script3.load()
    time.sleep(3)
    script3.unload()

    print("\nWaiting 10s to see if getAppSalt is called...")
    time.sleep(10)

    print("--- Done ---")
    proc.kill()

if __name__ == '__main__':
    main()
