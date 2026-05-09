"""
Frida Hook v12: Attach 到运行中的 Lingma + 监控签名计算
关键: 用正确的 WebSocket 协议通信
"""
import frida
import time
import subprocess
import json
import socket

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

HOOK_SCRIPT = r"""
'use strict';

var mod = Process.findModuleByName('Lingma.exe');
if (!mod) {
    console.log('[Hook] Module not found');
} else {
    var base = mod.base;

    // Hook trimQueryPath
    try {
        Interceptor.attach(base.add(0x882c80), {
            onEnter: function(args) {
                console.log('[trimQueryPath] ENTER');
                try { console.log('  rcx=' + this.context.rcx.readUtf8String(300)); } catch(e) {}
            },
            onLeave: function(retval) {
                console.log('[trimQueryPath] LEAVE');
                try { console.log('  rax=' + this.context.rax.readUtf8String(300)); } catch(e) {}
            }
        });
        console.log('[OK] trimQueryPath');
    } catch(e) { console.log('[FAIL] trimQueryPath: ' + e.message); }

    // Hook getAuthSignature
    try {
        Interceptor.attach(base.add(0x890140), {
            onEnter: function(args) { console.log('[getAuthSignature] ENTER'); },
            onLeave: function(retval) {
                console.log('[getAuthSignature] LEAVE');
                try {
                    var ptr = this.context.rax;
                    var len = this.context.rcx;
                    var str = ptr.readUtf8String(len.toInt32());
                    console.log('  result: ' + str);
                } catch(e) { console.log('  read error: ' + e.message); }
            }
        });
        console.log('[OK] getAuthSignature');
    } catch(e) { console.log('[FAIL] getAuthSignature: ' + e.message); }

    // Hook getAuthPayload
    try {
        Interceptor.attach(base.add(0x890380), {
            onEnter: function(args) { console.log('[getAuthPayload] ENTER'); },
            onLeave: function(retval) {
                console.log('[getAuthPayload] LEAVE');
                try { console.log('  rax=' + this.context.rax.readUtf8String(300)); } catch(e) {}
            }
        });
        console.log('[OK] getAuthPayload');
    } catch(e) { console.log('[FAIL] getAuthPayload: ' + e.message); }

    // Hook MD5
    // Go's md5.Sum uses crypto/md5.block
    // Let's hook all functions that contain "md5" or "hash"
    try {
        var syms = Process.enumerateSymbols();
        var md5Syms = syms.filter(function(s) {
            return s.name.indexOf('md5') >= 0 || s.name.indexOf('MD5') >= 0;
        });
        console.log('[Search] Found ' + md5Syms.length + ' md5 symbols');
        md5Syms.slice(0, 20).forEach(function(s) {
            console.log('  ' + s.name + ' -> ' + s.address);
        });
    } catch(e) { console.log('[Search] Error: ' + e.message); }

    console.log('[Hook] Ready!');
}
"""

def on_message(msg, data):
    payload = msg.get('payload', '')
    if payload:
        print(f"[MSG] {payload}")

def main():
    device = frida.get_local_device()

    # Find running Lingma
    processes = device.enumerate_processes()
    lingma_procs = [p for p in processes if 'lingma' in p.name.lower()]
    if not lingma_procs:
        print("Starting Lingma...")
        proc = subprocess.Popen([LINGMA, "start"])
        time.sleep(8)
        processes = device.enumerate_processes()
        lingma_procs = [p for p in processes if 'lingma' in p.name.lower()]
        if not lingma_procs:
            print("Not found!")
            proc.kill()
            return

    pid = lingma_procs[0].pid
    print(f"PID: {pid}")

    session = device.attach(pid)
    script = session.create_script(HOOK_SCRIPT)
    script.on('message', on_message)
    script.load()

    # Now connect via WebSocket and send requests that need signatures
    print("\n=== Connecting via WebSocket ===")

    # Use raw socket to see what we get
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(('127.0.0.1', 37010))
    print("TCP connected!")

    # Send a WebSocket frame manually
    # WebSocket text frame opcode=1
    msg = json.dumps({
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {"processId": 12345},
        "id": 1
    })

    # Build WebSocket frame
    payload_bytes = msg.encode('utf-8')
    frame = bytearray()
    frame.append(0x81)  # FIN + text
    if len(payload_bytes) < 126:
        frame.append(len(payload_bytes))  # no mask (server side)
    frame.extend(payload_bytes)

    sock.sendall(bytes(frame))
    print(f"Sent: {msg}")

    # Read response
    try:
        data = sock.recv(4096)
        print(f"Received {len(data)} bytes: {data}")
    except socket.timeout:
        print("No response (timeout)")

    time.sleep(1)

    # Send ping
    ping = json.dumps({"jsonrpc": "2.0", "method": "ping", "params": {}})
    payload_bytes = ping.encode('utf-8')
    frame = bytearray()
    frame.append(0x81)
    frame.append(len(payload_bytes))
    frame.extend(payload_bytes)
    sock.sendall(bytes(frame))
    print(f"Sent ping")

    try:
        data = sock.recv(4096)
        print(f"Received {len(data)} bytes: {data}")
    except socket.timeout:
        print("No response to ping")

    sock.close()

    # Wait for hooks
    print("\nWaiting 10s...")
    time.sleep(10)

    print("--- Done ---")
    try:
        script.unload()
    except:
        pass
    session.detach()

if __name__ == '__main__':
    main()
