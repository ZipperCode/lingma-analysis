"""
Frida v3: 使用 Interceptor.replace 避免 Go GC 崩溃
简化版本，减少复杂的回调逻辑
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

var mods = Process.enumerateModules().filter(function(m) { return m.name.includes('Lingma'); });
if (mods.length === 0) {
    send({type: 'error', msg: 'Lingma module not found!'});
} else {
    var baseAddr = mods[0].base;
    send({type: 'log', msg: 'Lingma base: ' + baseAddr});

    var getAppSaltAddr = baseAddr.add(0x882760);
    send({type: 'log', msg: 'getAppSalt target: ' + getAppSaltAddr});

    var firstByte = getAppSaltAddr.readU8();
    send({type: 'log', msg: 'First byte at getAppSalt: 0x' + firstByte.toString(16)});

    // Store results globally for inspection
    var capturedResults = [];

    // ---- getAppSalt: Use Interceptor.attach but with minimal callback ----
    // Try attach with a very simple callback first
    send({type: 'log', msg: 'Installing getAppSalt hook...'});

    try {
        Interceptor.attach(getAppSaltAddr, {
            onEnter: function(args) {
                send({type: 'log', msg: 'GETAPPSALT ENTER'});
                this.enterTime = Date.now();
            },
            onLeave: function(retval) {
                var elapsed = Date.now() - this.enterTime;
                send({type: 'log', msg: 'GETAPPSALT LEAVE after ' + elapsed + 'ms'});
                send({type: 'log', msg: '  RAX=' + this.context.rax);
                send({type: 'log', msg: '  RCX=' + this.context.rcx);
                send({type: 'log', msg: '  RDX=' + this.context.rdx);

                // Try reading as string
                try {
                    var ptr = this.context.rax;
                    var len = this.context.rcx.toUInt32();
                    send({type: 'log', msg: '  String: ptr=' + ptr + ' len=' + len});

                    if (len > 0 && len < 10000) {
                        var str = ptr.readUtf8String(len);
                        send({type: 'log', msg: '  >>> SALT: "' + str + '"'});
                    }
                } catch(e) {
                    send({type: 'log', msg: '  Not a string: ' + e.message});
                }

                // Try reading as slice header
                try {
                    var ptr = this.context.rax;
                    var sliceData = ptr.readPointer();
                    var sliceLen = ptr.add(8).readUInt();
                    var sliceCap = ptr.add(16).readUInt();
                    send({type: 'log', msg: '  Slice: data=' + sliceData + ' len=' + sliceLen + ' cap=' + sliceCap);

                    if (sliceLen > 0 && sliceLen < 10) {
                        for (var i = 0; i < sliceLen; i++) {
                            var elemPtr = sliceData.add(i * 16).readPointer();
                            var elemLen = sliceData.add(i * 16 + 8).readUInt();
                            if (elemLen > 0 && elemLen < 500) {
                                var elemStr = elemPtr.readUtf8String(elemLen);
                                send({type: 'log', msg: '    [' + i + '] = "' + elemStr + '"'});
                            }
                        }
                    }
                } catch(e) {
                    send({type: 'log', msg: '  Not a slice: ' + e.message});
                }

                // Capture for later
                capturedResults.push({
                    rax: this.context.rax.toString(),
                    rcx: this.context.rcx.toString(),
                    rdx: this.context.rdx.toString(),
                    time: this.enterTime
                });
            }
        });
        send({type: 'log', msg: 'getAppSalt hook installed successfully!'});
    } catch(e) {
        send({type: 'error', msg: 'Failed to hook getAppSalt: ' + e.message});
    }

    // ---- Caller at 0x880da0 (simpler) ----
    try {
        var callerAddr = baseAddr.add(0x880da0);
        Interceptor.attach(callerAddr, {
            onEnter: function(args) {
                send({type: 'log', msg: 'CALLER 0x880da0 ENTER'});
            },
            onLeave: function(retval) {
                send({type: 'log', msg: 'CALLER 0x880da0 LEAVE'});
            }
        });
        send({type: 'log', msg: 'Caller hook installed'});
    } catch(e) {
        send({type: 'error', msg: 'Failed to hook caller: ' + e.message});
    }

    send({type: 'log', msg: 'All hooks installed. Waiting for calls...'});

    // Expose captured results
    rpc.exports = {
        getCaptured: function() {
            return JSON.stringify(capturedResults);
        }
    };
}
"""

def send_rpc(handle, method, params=None, msg_id=None):
    body = {"jsonrpc": "2.0", "method": method}
    if params:
        body["params"] = params
    if msg_id is not None:
        body["id"] = msg_id
    content = json.dumps(body)
    header = "Content-Length: {}\r\n\r\n".format(len(content))
    win32file.WriteFile(handle, (header + content).encode('utf-8'))

def read_resp(handle, timeout_ms=3000):
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
    print("PID: {}".format(pid))

    print("Installing hooks...")
    session = device.attach(pid)
    script = session.create_script(HOOK_SCRIPT)

    call_count = [0]
    def on_message(msg, data):
        payload = msg.get('payload', msg)
        if isinstance(payload, dict):
            msg_type = payload.get('type', '')
            if msg_type == 'log':
                print("[FRIDA] {}".format(payload.get('msg', '')))
                if 'ENTER' in payload.get('msg', '') or 'SALT' in payload.get('msg', ''):
                    call_count[0] += 1
            elif msg_type == 'error':
                print("[FRIDA ERROR] {}".format(payload.get('msg', '')))
        else:
            print("[FRIDA] {}".format(payload))

    script.on('message', on_message)
    script.load()
    time.sleep(3)

    # Try RPC
    info_path = 'C:/Users/Zipper/.lingma/.info.json'
    try:
        with open(info_path, 'r') as f:
            info = json.load(f)
        pipe_path = info.get('ipcServerPath')
        print("Pipe: {}".format(pipe_path))

        handle = win32file.CreateFile(
            pipe_path,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0, None, win32file.OPEN_EXISTING,
            win32file.FILE_FLAG_OVERLAPPED, None
        )
        print("Connected!")

        # Initialize
        print("\nSending initialize...")
        send_rpc(handle, "initialize", {
            "processId": 12345,
            "clientInfo": {"name": "vscode", "version": "1.95.0"},
            "locale": "en-US", "rootPath": "C:/test"
        }, 1)
        time.sleep(2)
        resp = read_resp(handle)
        if resp:
            print("  Response: {}".format(resp[:200]))

        # Completion
        print("Sending textDocument/completion...")
        send_rpc(handle, "textDocument/completion", {
            "textDocument": {"uri": "file:///C:/test/hello.py"},
            "position": {"line": 0, "character": 0}
        }, 2)
        time.sleep(5)
        resp = read_resp(handle, 5000)
        if resp:
            print("  Response: {}".format(resp[:200]))

        # Chat
        print("Sending chat/ask...")
        send_rpc(handle, "chat/ask", {
            "sessionId": "t1", "chatId": "c1",
            "message": "hello", "stream": False
        }, 3)
        time.sleep(10)
        resp = read_resp(handle, 10000)
        if resp:
            print("  Response: {}".format(resp[:200]))

        print("\nWaiting 30s for getAppSalt calls...")
        print("Calls captured so far: {}".format(call_count[0]))
        for i in range(30):
            time.sleep(1)
            if i % 10 == 0:
                print("  {}s elapsed, calls: {}".format(i, call_count[0]))

        # Get captured results
        try:
            results = script.exports_sync.get_captured()
            print("\nCaptured results: {}".format(results))
        except:
            pass

        win32file.CloseHandle(handle)
    except Exception as e:
        import traceback
        print("Pipe error: {}".format(e))
        traceback.print_exc()

    print("--- Done ---")
    script.unload()
    session.detach()
    proc.kill()

if __name__ == '__main__':
    main()
