"""
Simple Frida hook for getAppSalt at 0x882760.
Just hooks the function and waits for calls triggered by RPC requests.
"""
import frida
import time
import subprocess
import json
import win32file
import win32event
import pywintypes

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

HOOK_SCRIPT = r"""
'use strict';

var mods = Process.enumerateModules().filter(m => m.name.includes('Lingma'));
if (mods.length === 0) {
    send({type: 'error', msg: 'Lingma module not found!'});
} else {
    var baseAddr = mods[0].base;
    send({type: 'log', msg: 'Lingma base: ' + baseAddr});

    var getAppSaltAddr = baseAddr.add(0x882760);
    send({type: 'log', msg: 'getAppSalt target: ' + getAppSaltAddr});

    // First byte check
    try {
        var firstByte = getAppSaltAddr.readU8();
        send({type: 'log', msg: 'First byte at getAppSalt: 0x' + firstByte.toString(16)});
    } catch(e) {
        send({type: 'error', msg: 'Cannot read getAppSalt: ' + e.message});
    }

    // Hook getAppSalt
    Interceptor.attach(getAppSaltAddr, {
        onEnter: function(args) {
            send({type: 'log', msg: '\n========== getAppSalt ENTER =========='});
            send({type: 'log', msg: 'RCX=' + this.context.rcx});
            send({type: 'log', msg: 'RDX=' + this.context.rdx});
            send({type: 'log', msg: 'R8=' + this.context.r8});
            send({type: 'log', msg: 'R9=' + this.context.r9});
        },
        onLeave: function(retval) {
            send({type: 'log', msg: '\n========== getAppSalt LEAVE =========='});
            send({type: 'log', msg: 'RAX=' + this.context.rax});
            send({type: 'log', msg: 'RCX=' + this.context.rcx});
            send({type: 'log', msg: 'RDX=' + this.context.rdx});

            // Go string return: RAX = ptr, RCX = len
            var ptr = this.context.rax;
            var len = this.context.rcx.toUInt32();
            send({type: 'log', msg: 'Return: ptr=' + ptr + ', len=' + len});

            if (len > 0 && len < 10000) {
                try {
                    var str = ptr.readUtf8String(len);
                    send({type: 'log', msg: '>>> SALT STRING: "' + str + '"'});
                } catch(e) {
                    send({type: 'log', msg: 'Cannot read as string: ' + e.message});
                    // Dump hex
                    try {
                        var bytes = ptr.readByteArray(64);
                        send({type: 'log', msg: 'Hex dump:\n' + hexdump(bytes)});
                    } catch(e2) {}
                }
            }

            // Try reading as Go slice header {ptr, len, cap} at RAX
            try {
                var slicePtr = ptr.readPointer();
                var sliceLen = ptr.add(8).readUInt();
                var sliceCap = ptr.add(16).readUInt();
                send({type: 'log', msg: 'As slice header: data=' + slicePtr + ', len=' + sliceLen + ', cap=' + sliceCap});

                // Read string elements from slice
                if (sliceLen > 0 && sliceLen < 20) {
                    for (var i = 0; i < sliceLen; i++) {
                        var elemPtr = slicePtr.add(i * 16).readPointer();
                        var elemLen = slicePtr.add(i * 16 + 8).readUInt();
                        if (elemLen > 0 && elemLen < 1000) {
                            var elemStr = elemPtr.readUtf8String(elemLen);
                            send({type: 'log', msg: '  [' + i + '] = "' + elemStr + '"'});
                        }
                    }
                }
            } catch(e) {
                send({type: 'log', msg: 'Not a slice header at RAX: ' + e.message});
            }
        }
    });

    send({type: 'log', msg: 'getAppSalt hook installed!'});

    // Also hook the caller at 0x880da0 to see when remoting is triggered
    var callerAddr = baseAddr.add(0x880da0);
    Interceptor.attach(callerAddr, {
        onEnter: function(args) {
            send({type: 'log', msg: '\n--- Caller 0x880da0 ENTER ---'});
        },
        onLeave: function(retval) {
            send({type: 'log', msg: '--- Caller 0x880da0 LEAVE ---'});
        }
    });
    send({type: 'log', msg: 'Caller 0x880da0 hook installed!'});
}
"""

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

    print("Installing hooks...")
    session = device.attach(pid)
    script = session.create_script(HOOK_SCRIPT)
    script.on('message', lambda m, d: print(f"[FRIDA] {m.get('payload', m)}"))
    script.load()
    time.sleep(3)

    # Now try RPC
    info_path = 'C:/Users/Zipper/.lingma/.info.json'
    try:
        with open(info_path, 'r') as f:
            info = json.load(f)
        pipe_path = info.get('ipcServerPath')
        print(f"Pipe: {pipe_path}")

        handle = win32file.CreateFile(
            pipe_path,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0, None, win32file.OPEN_EXISTING,
            win32file.FILE_FLAG_OVERLAPPED, None
        )
        print("Connected!")

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

        # Initialize
        print("\nSending initialize...")
        send_rpc("initialize", {
            "processId": 12345, "clientInfo": {"name": "vscode", "version": "1.95.0"},
            "locale": "en-US", "rootPath": "C:/test"
        }, 1)
        time.sleep(2)
        resp = read_resp()
        if resp: print(f"  Response: {resp[:200]}")

        # Completion
        print("Sending textDocument/completion...")
        send_rpc("textDocument/completion", {
            "textDocument": {"uri": "file:///C:/test/hello.py"},
            "position": {"line": 0, "character": 0}
        }, 2)
        time.sleep(5)
        resp = read_resp(5000)
        if resp: print(f"  Response: {resp[:200]}")

        # Chat
        print("Sending chat/ask...")
        send_rpc("chat/ask", {
            "sessionId": "t1", "chatId": "c1",
            "message": "hello", "stream": False
        }, 3)
        time.sleep(10)
        resp = read_resp(10000)
        if resp: print(f"  Response: {resp[:200]}")

        print("\nWaiting 30s for getAppSalt...")
        for i in range(30):
            time.sleep(1)
            if i % 10 == 0:
                print(f"  {i}s elapsed")

        win32file.CloseHandle(handle)
    except Exception as e:
        print(f"Pipe error: {e}")

    print("--- Done ---")
    script.unload()
    session.detach()
    proc.kill()

if __name__ == '__main__':
    main()
