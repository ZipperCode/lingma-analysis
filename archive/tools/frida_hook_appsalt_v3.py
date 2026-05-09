"""
Hook getAppSalt 使用与原始 Frida trace 相同的方法
原始脚本成功 hook 了 trimQueryPath 等函数 (offset 0x882c80)
我们需要找到 getAppSalt 的 offset
"""
import frida
import sys
import time

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

# From the original Frida trace that worked:
# trimQueryPath: offset 0x882c80 from module base
# getAuthSignature: offset 0x890140
# getAuthPayload: offset 0x890380

# From the pclntab name analysis, getAppSalt is very close to trimQueryPath
# and addBigModelSignatureHeaders in the same package

# The original trimQueryPath offset is 0x882c80
# getAppSalt should be nearby (within ~0x20000 bytes)
# Let's calculate based on the name string ordering in pclntab

# trimQueryPath name: .rdata RVA 0x3b9f3ed
# getAppSalt name: .rdata RVA 0x3b9f3a6
# They're 0x47 apart in the name table

# If code ordering follows name ordering approximately:
# getAppSalt offset ≈ 0x882c80 - some_delta
# where delta is proportional to the name difference

# But this is unreliable. Let's try a brute-force approach:
# scan the .text region around 0x882c80 for the getAppSalt function

# Actually, let's use a smarter Frida approach:
# Hook all functions in the remoting package region

# The remoting functions are in the range 0x800000 - 0x900000 (approx)
# Let's scan this range for small functions that return string constants

# But scanning 1MB would take too long...

# Alternative: use Frida's Interceptor to hook at runtime by
# searching for the function signature pattern

# getAppSalt() likely has this Go calling convention:
# Input: receiver pointer (in RAX for method, or nothing for function)
# Output: Go string (pointer in RAX, length in RCX)

# Let's try a different approach: use Frida to intercept
# the HTTP request building process and read the signature header

HOOK_SCRIPT = r"""
console.log('[Script] Starting...');

function findAndHookFunctions() {
    var mod = Process.getModuleByName('Lingma.exe');
    var base = mod.base;
    console.log('[Hook] Lingma.exe at ' + base + ', size: ' + mod.size);

    // Known offsets from original Frida trace
    var trimQueryPath = base.add(0x882c80);
    var getAuthSignature = base.add(0x890140);
    var getAuthPayload = base.add(0x890380);

    // Try to hook these known functions first to verify offsets
    console.log('[Hook] Trying known function offsets...');

    var knownOffsets = {
        'trimQueryPath': 0x882c80,
        'getAuthSignature': 0x890140,
        'getAuthPayload': 0x890380,
    };

    // Search for getAppSalt near trimQueryPath
    // getAppSalt is called by addBigModelSignatureHeaders
    // Both are in cosy/remoting
    // Let's search +/- 0x20000 from trimQueryPath

    var searchStart = 0x882c80 - 0x20000;
    var searchEnd = 0x882c80 + 0x20000;

    console.log('[Hook] Searching for getAppSalt near trimQueryPath...');
    console.log('[Hook] Search range: 0x' + searchStart.toString(16) + ' - 0x' + searchEnd.toString(16));

    // Go function getAppSalt likely returns a string constant
    // Pattern: LEA RAX, [rip+offset]; MOV RCX, length; RET
    // Or: LEA RCX, [rip+offset]; (string pointer)

    // Let's try to find getAppSalt by scanning for the pattern
    // that loads a Go string and returns

    // We'll hook potential candidates and check what they return

    // First, let's hook addBigModelSignatureHeaders and trace its calls
    // addBigModelSignatureHeaders name RVA: 0x3b9f37c
    // Its code offset should be near getAppSalt

    // Since we can't easily find getAppSalt, let's try all small offsets
    // from trimQueryPath and see which one returns a string

    var candidates = [];
    // Scan in 16-byte increments (Go function alignment)
    for (var offset = searchStart; offset < searchEnd; offset += 16) {
        var addr = base.add(offset);
        // Read first few bytes and check for RET instruction
        var firstBytes = addr.readByteArray(16);
        var bytes = new Uint8Array(firstBytes);

        // Look for RET (0xC3) in first 32 bytes
        for (var i = 0; i < Math.min(32, bytes.length); i++) {
            if (bytes[i] === 0xC3) {
                // This function has a RET
                // Check if it loads a string (LEA to .rdata region)
                // This is complex to do in JS, so let's just hook it
                candidates.push(offset);
                break;
            }
        }
    }

    console.log('[Hook] Found ' + candidates.length + ' candidate functions');

    // This is too many candidates. Let's narrow it down.
    // getAppSalt should be a very small function (< 64 bytes)
    // that returns a string constant

    // Let's focus on a smaller range around trimQueryPath
    // and try to hook the most likely candidates

    // Actually, let's try a completely different approach:
    // Hook the HTTP header setting code
    // addBigModelSignatureHeaders sets the Signature header
    // It must call getAppSalt to get the signing key

    // Let's search for the function that calls getAppSalt
    // by looking for call instructions near getAppSalt's name

    // For now, let's just try to hook a range of functions
    // and find one that returns a Go string

    // Try hooking functions at specific offsets
    var testOffsets = [
        0x882c80 - 0x1000,
        0x882c80 - 0x800,
        0x882c80 - 0x400,
        0x882c80 - 0x200,
        0x882c80 - 0x100,
        0x882c80 - 0x80,
        0x882c80 - 0x40,
        0x882c80 - 0x20,
        0x882c80,  // trimQueryPath
        0x882c80 + 0x20,
        0x882c80 + 0x40,
        0x882c80 + 0x80,
        0x882c80 + 0x100,
        0x882c80 + 0x200,
    ];

    console.log('[Hook] Testing ' + testOffsets.length + ' offsets near trimQueryPath...');
    testOffsets.forEach(function(off) {
        console.log('[Hook]   offset 0x' + off.toString(16));
    });

    // Hook trimQueryPath to verify our offset is correct
    try {
        Interceptor.attach(trimQueryPath, {
            onEnter: function(args) {
                var str = this.context.rcx.readUtf8String(100);
                console.log('[trimQueryPath] ENTER: ' + str);
            },
            onLeave: function(retval) {
                var str = this.context.rax.readUtf8String(100);
                console.log('[trimQueryPath] LEAVE: ' + str);
            }
        });
        console.log('[Hook] Successfully hooked trimQueryPath at ' + trimQueryPath);
    } catch(e) {
        console.log('[Hook] Failed to hook trimQueryPath: ' + e.message);
    }
}

setTimeout(findAndHookFunctions, 5000);
"""

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[Frida] {message.get('payload', '')}")
    elif message['type'] == 'error':
        print(f"[Error] {message.get('stack', '')}")

def main():
    device = frida.get_local_device()

    # Kill any existing Lingma
    processes = device.enumerate_processes()
    for p in processes:
        if 'lingma' in p.name.lower():
            print(f"Killing: {p.name} (PID: {p.pid})")
            device.kill(p.pid)

    print("Spawning Lingma...")
    pid = device.spawn([BINARY_PATH])
    print(f"Spawned PID: {pid}")

    session = device.attach(pid)
    print("Attached!")

    script = session.create_script(HOOK_SCRIPT)
    script.on('message', on_message)
    script.load()
    print("Script loaded, resuming...")

    device.resume(pid)
    print("Process resumed, waiting 30 seconds...")

    time.sleep(30)
    print("--- Timeout ---")

if __name__ == '__main__':
    main()
