"""
扫描 0x882000-0x891000 范围内的所有 Go 函数
然后 hook 它们来观察哪些被调用
"""
import frida
import time
import subprocess
import json
import struct

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

def get_pipe_path():
    import os
    info_path = os.path.expandvars(r'C:\Users\Zipper\.lingma\.info.json')
    with open(info_path, 'r') as f:
        info = json.load(f)
    return info.get('ipcServerPath')

def find_functions_in_range(binary_path, start_rva, end_rva):
    """Find all Go function entry points in the given RVA range"""
    with open(binary_path, 'rb') as f:
        data = f.read()

    functions = []
    # Go function prologue patterns:
    # 49 3b 66 XX  - cmp rsp, [r14+XX] (Go 1.17+ stack check)
    # 48 83 ec XX  - sub rsp, XX
    # 4c 8d 64 XX  - lea r12, [rsp+XX] (Go stack allocation)

    patterns = [
        bytes([0x49, 0x3b, 0x66]),  # cmp rsp, [r14+XX]
        bytes([0x4c, 0x8d, 0x64]),  # lea r12/13/14/15, [rsp/r12/13/14+XX]
    ]

    # File offset = 0x400 + rva - 0x1000
    file_start = 0x400 + start_rva - 0x1000
    file_end = 0x400 + end_rva - 0x1000

    for pat in patterns:
        idx = file_start
        while idx < file_end:
            pos = data.find(pat, idx, file_end)
            if pos < 0:
                break
            rva = pos - 0x400 + 0x1000
            # Align to instruction boundary (should already be)
            functions.append((rva, pat.hex()))
            idx = pos + 1

    # Deduplicate and sort
    functions = sorted(set(f[0] for f in functions))
    return functions

def main():
    device = frida.get_local_device()

    # Find functions in range
    print("Scanning for functions...")
    funcs = find_functions_in_range(LINGMA, 0x882000, 0x891000)
    print(f"Found {len(funcs)} function candidates")

    # Show first 30
    for rva in funcs[:30]:
        print(f"  0x{rva:x}")

    # Generate Frida hook script for ALL functions
    hook_lines = []
    for rva in funcs:
        hook_lines.append(f"""
    tryHook(0x{rva:x});""")

    hook_script = """
'use strict';
var base = Module.getBaseAddress();
var callCounts = {};

function tryHook(offset) {
    try {
        var addr = base.add(offset);
        Interceptor.attach(addr, {
            onEnter: function(args) {
                this.offset = offset;
                var key = '0x' + offset.toString(16);
                callCounts[key] = (callCounts[key] || 0) + 1;
                var count = callCounts[key];
                // Only print first few calls
                if (count <= 3) {
                    console.log('>>> ENTER func@0x' + offset.toString(16) + ' (call #' + count + ')');
                    console.log('  RCX=' + this.context.rcx + ' RDX=' + this.context.rdx);
                }
            },
            onLeave: function(retval) {
                var key = '0x' + this.offset.toString(16);
                var count = callCounts[key];
                if (count <= 3) {
                    console.log('<<< LEAVE func@0x' + this.offset.toString(16) + ' retval=' + retval);
                    // Try to read return string
                    try {
                        var ptr = this.context.rax;
                        var len = this.context.rcx.toInt32();
                        if (len > 0 && len < 5000) {
                            var str = ptr.readUtf8String(Math.min(len, 500));
                            console.log('  RETURN: "' + str.replace(/\\n/g, '\\\\n').substring(0, 300) + '"');
                        }
                    } catch(e) {
                        // Check stack for return value
                        try {
                            var stack_ret = this.context.rsp.readPointer();
                            console.log('  Stack RET: 0x' + stack_ret.toString(16));
                        } catch(e2) {}
                    }
                }
            }
        });
    } catch(e) {
        // Ignore errors
    }
}

// Hook all found functions
""" + "".join(hook_lines) + """

console.log('[Hook] ' + """ + str(len(funcs)) + """ + ' functions installed');
console.log('[Hook] Waiting for calls...');
"""

    # Start Lingma
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

    # Attach and install hooks
    print("Installing hooks...")
    session = device.attach(pid)
    script = session.create_script(hook_script)
    script.on('message', lambda m, d: None)
    script.load()
    time.sleep(3)

    # Connect via pipe and trigger
    pipe_path = get_pipe_path()
    print(f"Pipe: {pipe_path}")

    import win32file
    import win32event
    import pywintypes

    try:
        handle = win32file.CreateFile(
            pipe_path,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0, None, win32file.OPEN_EXISTING,
            win32file.FILE_FLAG_OVERLAPPED, None
        )
        print("Connected!")

        # Initialize
        def send_rpc(method, params=None, msg_id=None):
            body = {"jsonrpc": "2.0", "method": method}
            if params:
                body["params"] = params
            if msg_id is not None:
                body["id"] = msg_id
            content = json.dumps(body)
            header = f"Content-Length: {len(content)}\r\n\r\n"
            win32file.WriteFile(handle, (header + content).encode('utf-8'))

        def read_resp(timeout_ms=3000):
            overlapped = pywintypes.OVERLAPPED()
            overlapped.hEvent = win32event.CreateEvent(None, True, False, None)
            try:
                err, data = win32file.ReadFile(handle, 65536, overlapped)
                if err == 997:
                    result = win32event.WaitForSingleObject(overlapped.hEvent, timeout_ms)
                    if result == win32event.WAIT_OBJECT_0:
                        data = bytes(overlapped.GetOverlappedResult())
                    else:
                        return None
                else:
                    data = bytes(data)
            except:
                return None
            if data:
                text = data.decode('utf-8', errors='replace')
                if '\r\n\r\n' in text:
                    _, body = text.split('\r\n\r\n', 1)
                    return body[:500]
            return None

        send_rpc("initialize", {"processId": 12345, "clientInfo": {"name": "vscode", "version": "1.95.0"}, "locale": "en-US", "rootPath": "C:/test"}, 1)
        time.sleep(1)
        read_resp()

        send_rpc("chat/ask", {"sessionId": "t1", "chatId": "c1", "message": "hello", "stream": False}, 2)
        time.sleep(5)
        read_resp(10000)

        print("\nWaiting 15s for any function calls...")
        time.sleep(15)

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
