"""
Frida Hook getAppSalt 验证并提取返回值
"""
import frida
import time
import subprocess
import json
import win32file
import win32event
import pywintypes

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

def get_pipe_path():
    info_path = 'C:/Users/Zipper/.lingma/.info.json'
    with open(info_path, 'r') as f:
        info = json.load(f)
    return info.get('ipcServerPath')

# Hook script to capture getAppSalt return value
HOOK_SCRIPT = r"""
'use strict';

var base = Module.getBaseAddress();

// === getAppSalt at 0x882760 ===
var getAppSaltAddr = base.add(0x882760);
console.log('[Hook] getAppSalt target: 0x' + getAppSaltAddr.toString(16));

Interceptor.attach(getAppSaltAddr, {
    onEnter: function(args) {
        console.log('\n========== getAppSalt ENTER ==========');
        console.log('RCX=' + this.context.rcx);
        console.log('RDX=' + this.context.rdx);
        console.log('R8=' + this.context.r8);
        console.log('R9=' + this.context.r9);
        console.log('Stack:');
        for (var i = 0; i < 8; i++) {
            try {
                var val = this.context.rsp.add(i * 8).readPointer();
                console.log('  [rsp+' + (i*8) + ']=0x' + val.toString(16));
            } catch(e) {}
        }
    },
    onLeave: function(retval) {
        console.log('\n========== getAppSalt LEAVE ==========');
        console.log('retval=' + retval);
        console.log('RAX=' + this.context.rax);
        console.log('RCX=' + this.context.rcx);
        console.log('RDX=' + this.context.rdx);

        // Go returns string as (ptr, len) in RAX, RCX
        // Or Go returns slice as (ptr, len, cap) in RAX, RCX, RDX
        try {
            var ptr = this.context.rax;
            var len = this.context.rcx.toInt32();
            var cap = this.context.rdx.toInt32();
            console.log('Return: ptr=0x' + ptr.toString(16) + ' len=' + len + ' cap=' + cap);

            if (len > 0 && len < 1000) {
                // Try reading as string
                try {
                    var str = ptr.readUtf8String(len);
                    console.log('String result: "' + str + '"');
                } catch(e) {}

                // Try reading as Go slice of strings
                try {
                    console.log('Slice content (hex):');
                    var hex = ptr.readByteArray(Math.min(len, 256));
                    console.log(hex);
                } catch(e) {}
            }
        } catch(e) {
            console.log('Error reading return value: ' + e);
        }
    }
});

// === Hook addBigModelSignatureHeaders at 0x882680 ===
var sigHeadersAddr = base.add(0x882680);
console.log('[Hook] addBigModelSignatureHeaders: 0x' + sigHeadersAddr.toString(16));

Interceptor.attach(sigHeadersAddr, {
    onEnter: function(args) {
        console.log('\n--- addBigModelSignatureHeaders ENTER ---');
    },
    onLeave: function(retval) {
        console.log('--- addBigModelSignatureHeaders LEAVE ---');
        try {
            var ptr = this.context.rax;
            var len = this.context.rcx.toInt32();
            if (len > 0 && len < 50000) {
                var str = ptr.readUtf8String(Math.min(len, 5000));
                console.log('Return data: ' + str.substring(0, 5000));
            }
        } catch(e) {}
    }
});

// === Hook addBigModelAuthorizationHeaders at 0x882ba0 ===
var authHeadersAddr = base.add(0x882ba0);
console.log('[Hook] addBigModelAuthorizationHeaders: 0x' + authHeadersAddr.toString(16));

Interceptor.attach(authHeadersAddr, {
    onEnter: function(args) {
        console.log('\n--- addBigModelAuthorizationHeaders ENTER ---');
    },
    onLeave: function(retval) {
        console.log('--- addBigModelAuthorizationHeaders LEAVE ---');
    }
});

// === Hook trimQueryPath at 0x882c80 ===
var trimAddr = base.add(0x882c80);
console.log('[Hook] trimQueryPath: 0x' + trimAddr.toString(16));

Interceptor.attach(trimAddr, {
    onEnter: function(args) {
        console.log('\n--- trimQueryPath ENTER ---');
        try {
            var ptr = this.context.rcx;
            var len = this.context.rdx.toInt32();
            if (len > 0 && len < 10000) {
                var str = ptr.readUtf8String(Math.min(len, 5000));
                console.log('Input: ' + str.substring(0, 5000));
            }
        } catch(e) {}
    },
    onLeave: function(retval) {
        console.log('--- trimQueryPath LEAVE ---');
        try {
            var ptr = this.context.rax;
            var len = this.context.rcx.toInt32();
            if (len > 0 && len < 10000) {
                var str = ptr.readUtf8String(Math.min(len, 5000));
                console.log('Output: ' + str.substring(0, 5000));
            }
        } catch(e) {}
    }
});

console.log('[Hook] All hooks installed');
"""

def send_rpc(handle, method, params=None, msg_id=None):
    body = {"jsonrpc": "2.0", "method": method}
    if params:
        body["params"] = params
    if msg_id is not None:
        body["id"] = msg_id
    content = json.dumps(body)
    header = f"Content-Length: {len(content)}\r\n\r\n"
    win32file.WriteFile(handle, (header + content).encode('utf-8'))

def read_resp(handle, timeout_ms=5000):
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
    print(f"PID: {pid}")

    print("Installing hooks...")
    session = device.attach(pid)
    script = session.create_script(HOOK_SCRIPT)
    script.on('message', lambda m, d: print(f"[MSG] {m}"))
    script.load()
    time.sleep(2)

    pipe_path = get_pipe_path()
    print(f"Pipe: {pipe_path}")

    try:
        handle = win32file.CreateFile(
            pipe_path,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0, None, win32file.OPEN_EXISTING,
            win32file.FILE_FLAG_OVERLAPPED, None
        )
        print("Connected!")

        # Initialize
        send_rpc(handle, "initialize", {
            "processId": 12345, "clientInfo": {"name": "vscode", "version": "1.95.0"},
            "locale": "en-US", "rootPath": "C:/test"
        }, 1)
        time.sleep(1)
        read_resp(handle)

        # Trigger various methods
        send_rpc(handle, "textDocument/completion", {
            "textDocument": {"uri": "file:///C:/test/hello.py"},
            "position": {"line": 0, "character": 0}
        }, 2)
        time.sleep(3)
        read_resp(handle, 5000)

        send_rpc(handle, "chat/ask", {
            "sessionId": "t1", "chatId": "c1",
            "message": "hello world", "stream": False
        }, 3)
        time.sleep(5)
        read_resp(handle, 10000)

        print("\nWaiting 30s for any function calls...")
        for i in range(30):
            time.sleep(1)

        win32file.CloseHandle(handle)
    except Exception as e:
        print(f"Pipe error: {e}")

    print("--- Done ---")
    script.unload()
    session.detach()
    proc.kill()

if __name__ == '__main__':
    main()
