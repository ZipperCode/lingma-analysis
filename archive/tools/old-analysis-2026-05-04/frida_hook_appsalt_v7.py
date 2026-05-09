"""
Hook getAppSalt 和签名相关函数，直接获取 salt 值和签名结果
使用已知的函数偏移地址
"""
import frida
import time
import subprocess
import json

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

def get_pipe_path():
    import os
    info_path = os.path.expandvars(r'C:\Users\Zipper\.lingma\.info.json')
    with open(info_path, 'r') as f:
        info = json.load(f)
    return info.get('ipcServerPath')

HOOK_SCRIPT = r"""
'use strict';
var base = Module.getBaseAddress();

// === Hook getAppSalt (offset 0x882c80 - same as trimQueryPath?) ===
// Actually, getAppSalt name is at file offset 0x3b9dbba
// The function name ordering: addBigModelSignatureHeaders -> getAppSalt -> addBigModelAuthorizationHeaders
// Previous analysis found trimQueryPath at offset 0x882c80
// The function name table ordering suggests getAppSalt code is near trimQueryPath

// Let's hook at the offset where getAppSalt SHOULD be.
// From function name ordering analysis:
// - trimQueryPath name follows getAppSalt name in the name table
// - trimQueryPath code is at 0x882c80
// - So getAppSalt is likely the function BEFORE trimQueryPath in code too
// - The function before 0x882c80 is at 0x882ba0 (size 224 bytes)

function tryHook(offset, name) {
    try {
        var addr = base.add(offset);
        Interceptor.attach(addr, {
            onEnter: function(args) {
                this.name = name;
                console.log('>>> ENTER ' + name + ' (0x' + offset.toString(16) + ')');
                // Go 1.22+ calling convention: RCX, RDX, R8, R9 for first 4 args
                // RAX for return values (on leave)
                console.log('  RCX=' + this.context.rcx + ' RDX=' + this.context.rdx);
                console.log('  R8=' + this.context.r8 + ' R9=' + this.context.r9);
            },
            onLeave: function(retval) {
                console.log('<<< LEAVE ' + this.name + ' retval=' + retval);
                // Go string return: (ptr, len) in RAX, RCX
                console.log('  RAX=' + this.context.rax + ' RCX=' + this.context.rcx);
                // Try reading as Go string (ptr in RAX, length in RCX)
                try {
                    var ptr = this.context.rax;
                    var len = this.context.rcx.toInt32();
                    if (len > 0 && len < 10000) {
                        var str = ptr.readUtf8String(Math.min(len, 500));
                        console.log('  RETURN VALUE: "' + str + '"');
                    }
                } catch(e) {
                    console.log('  Could not read return value: ' + e.message);
                }
            }
        });
        console.log('[OK] ' + name + ' at 0x' + offset.toString(16));
        return true;
    } catch(e) {
        console.log('[FAIL] ' + name + ' at 0x' + offset.toString(16) + ': ' + e.message);
        return false;
    }
}

// Hook all candidates in the 0x882000-0x890000 range
var candidates = [
    [0x882ba0, "func_before_trimQueryPath"],
    [0x882c80, "trimQueryPath"],
    [0x882e40, "func_after_trimQueryPath"],
    [0x890140, "getAuthSignature"],
    [0x890380, "getAuthPayload"],
];

// Also try offsets AROUND trimQueryPath to find getAppSalt
// getAppSalt name is only 0x47 bytes before trimQueryPath name in the table
// So getAppSalt code is likely within ~0x300 bytes of trimQueryPath
for (var off = 0x882800; off < 0x883200; off += 0x10) {
    // Skip known ones
    var known = false;
    candidates.forEach(function(c) { if (c[0] === off) known = true; });
    if (known) continue;

    try {
        // Read first 4 bytes - should be Go prologue: 49 3b 66 XX or similar
        var bytes = base.add(off).readByteArray(4);
        var b = new Uint8Array(bytes);
        // Go function prologue patterns
        if (b[0] === 0x49 && b[1] === 0x3b && b[2] === 0x66) {
            tryHook(off, "unknown_0x" + off.toString(16));
        }
    } catch(e) {}
}

// Hook the known candidates too
candidates.forEach(function(c) { tryHook(c[0], c[1]); });

console.log('[Hook] All setup complete. Waiting for function calls...');
"""

def on_message(msg, data):
    payload = msg.get('payload', '')
    if payload:
        print(f"[MSG] {payload}")

def send_rpc(handle, method, params=None, msg_id=None):
    body = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        body["params"] = params
    if msg_id is not None:
        body["id"] = msg_id
    content = json.dumps(body)
    header = f"Content-Length: {len(content)}\r\n\r\n"
    full_msg = header + content
    try:
        import win32file
        win32file.WriteFile(handle, full_msg.encode('utf-8'))
        print(f"  Sent: {method}")
    except Exception as e:
        print(f"  Send failed: {e}")

def read_response(handle, timeout_ms=3000):
    import win32file
    import win32event
    import pywintypes
    overlapped = pywintypes.OVERLAPPED()
    overlapped.hEvent = win32event.CreateEvent(None, True, False, None)
    try:
        err, data = win32file.ReadFile(handle, 65536, overlapped)
        if err == 997:
            result = win32event.WaitForSingleObject(overlapped.hEvent, timeout_ms)
            if result != win32event.WAIT_OBJECT_0:
                return None
            data = bytes(overlapped.GetOverlappedResult())
        else:
            data = bytes(data)
    except:
        return None
    if not data:
        return None
    text = data.decode('utf-8', errors='replace')
    if '\r\n\r\n' in text:
        _, body = text.split('\r\n\r\n', 1)
        return body[:2000]
    return text[:2000]

def main():
    device = frida.get_local_device()

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

    # Attach FIRST (before any activity)
    print("Attaching Frida...")
    session = device.attach(pid)
    script = session.create_script(HOOK_SCRIPT)
    script.on('message', on_message)
    script.load()
    time.sleep(3)  # Let hooks install

    # Now connect via pipe
    pipe_path = get_pipe_path()
    print(f"Pipe: {pipe_path}")

    import win32file
    try:
        handle = win32file.CreateFile(
            pipe_path,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0, None, win32file.OPEN_EXISTING,
            win32file.FILE_FLAG_OVERLAPPED, None
        )
        print("Connected!")

        # Initialize
        print("\n[1] initialize")
        send_rpc(handle, "initialize", {
            "processId": 12345,
            "clientInfo": {"name": "vscode", "version": "1.95.0"},
            "locale": "en-US",
            "rootPath": "C:/test"
        }, msg_id=1)
        time.sleep(1)
        read_response(handle)

        # Chat/ask - might trigger auth functions
        print("\n[2] chat/ask")
        send_rpc(handle, "chat/ask", {
            "sessionId": "test-1",
            "chatId": "chat-1",
            "message": "test",
            "stream": False,
            "chatContext": {}
        }, msg_id=2)
        time.sleep(5)
        read_response(handle, timeout_ms=10000)

        # Wait for any auth calls
        print("\nWaiting 30s...")
        for i in range(30):
            if i % 5 == 0:
                print(f"  {i}s")
            time.sleep(1)

        win32file.CloseHandle(handle)
    except Exception as e:
        print(f"Pipe error: {e}")

    print("--- Done ---")
    try:
        script.unload()
    except:
        pass
    session.detach()
    proc.kill()

if __name__ == '__main__':
    main()
