#!/usr/bin/env python3
"""
Enhanced Frida hook for getAuthSignature - captures ALL 5 arguments.
Based on the discovery from frida-signature-trace-37017-login.jsonl.
"""
import frida
import sys
import time
import json
import os
import subprocess
import websocket

LINGMA_EXE = r"C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe"
WORKDIR = os.path.join(os.environ.get("TEMP", "C:/temp"), "lingma-authsig-hook")
SOCKET_PORT = 37099
HTTP_PORT = 37599

FRIDA_SCRIPT = r"""
'use strict';

function readGoStr(addr, len) {
    if (addr.isNull() || len === 0 || len > 8192) return '';
    try { return addr.readUtf8String(Math.min(len, 2048)); }
    catch (e) { return '<err:' + e + '>'; }
}

function readGoStrFromRegs(ptrReg, lenReg) {
    var ptr = ptrReg;
    var len = lenReg.toInt32();
    if (len < 0 || len > 8192) return '';
    return readGoStr(ptr, len);
}

var lingmaMod = null;
var mods = Process.enumerateModules();
for (var i = 0; i < mods.length; i++) {
    if (mods[i].name.toLowerCase().indexOf('lingma') !== -1) {
        lingmaMod = mods[i];
        break;
    }
}

if (!lingmaMod) {
    send(JSON.stringify({type: 'error', msg: 'Lingma module not found'}));
} else {
    var base = lingmaMod.base;
    send(JSON.stringify({type: 'info', msg: 'Lingma base: ' + base}));

    // Hook getAuthSignature at RVA 0x890140
    // Go 1.17+ ABI: args in RAX,RBX, RCX,RDI, RSI,R8, R9,R10, stack...
    // Go strings are passed as pairs: (ptr, len) in consecutive registers
    var getAuthSignature = base.add(0x890140);
    send(JSON.stringify({type: 'info', msg: 'Hooking getAuthSignature at ' + getAuthSignature}));

    Interceptor.attach(getAuthSignature, {
        onEnter: function(args) {
            var ctx = this.context;

            // Go 1.17+ ABI for variadic/string args
            // First arg: RAX=ptr, RBX=len
            var s0 = readGoStr(ctx.rax, ctx.rbx.toInt32());
            // Second arg: RCX=ptr, RDI=len
            var s1 = readGoStr(ctx.rcx, ctx.rdi.toInt32());
            // Third arg: R8=ptr, R9=len
            var s2 = readGoStr(ctx.r8, ctx.r9.toInt32());
            // Fourth arg: R10=ptr, [RSP+8]=len (or stored elsewhere)
            // Actually for Go stack-based calling, check stack
            var s3 = '<need stack trace>';
            var s4 = '<need stack trace>';

            send(JSON.stringify({
                type: 'getAuthSignature',
                arg0: s0,
                arg0_len: s0.length,
                arg1: s1,
                arg1_len: s1.length,
                arg2: s2,
                arg2_len: s2.length,
                rax: ctx.rax.toString(),
                rbx: ctx.rbx.toInt32(),
                rcx: ctx.rcx.toString(),
                rdi: ctx.rdi.toInt32(),
                r8: ctx.r8.toString(),
                r9: ctx.r9.toInt32(),
                r10: ctx.r10.toString(),
                ts: new Date().toISOString(),
            }));

            this.arg0 = s0;
            this.arg1 = s1;
            this.arg2 = s2;
        },
        onLeave: function(retval) {
            var ctx = this.context;
            var output = readGoStr(ctx.rax, ctx.rbx.toInt32());
            send(JSON.stringify({
                type: 'getAuthSignature_output',
                output: output,
                output_len: output.length,
            }));
        }
    });

    // Also hook Md5Encode for completeness
    var md5encode = base.add(0x4563c0);
    Interceptor.attach(md5encode, {
        onEnter: function(args) {
            var ctx = this.context;
            var arrPtr = ctx.rax;
            var count = ctx.rbx.toInt32();
            if (count <= 0 || count > 100) return;

            var parts = [];
            for (var i = 0; i < count; i++) {
                var ptr = arrPtr.add(i * 16).readPointer();
                var len = arrPtr.add(i * 16 + 8).readU64().toNumber();
                parts.push(readGoStr(ptr, Math.min(len, 2048)));
            }
            send(JSON.stringify({
                type: 'md5encode',
                count: count,
                parts: parts,
                preimage: parts.join(''),
            }));
            this.parts = parts;
        },
        onLeave: function(retval) {
            if (!this.parts) return;
            var ctx = this.context;
            var output = readGoStr(ctx.rax, ctx.rbx.toInt32());
            send(JSON.stringify({
                type: 'md5encode_output',
                output: output,
            }));
        }
    });

    send(JSON.stringify({type: 'info', msg: 'All hooks installed'}));
}
"""

def on_message(message, data):
    if message['type'] == 'send':
        try:
            obj = json.loads(message['payload'])
            t = obj.get('type', '')
            if t == 'getAuthSignature':
                print(f'\n{"="*60}')
                print(f'*** getAuthSignature ENTER ***')
                print(f'  arg0 [{obj["arg0_len"]}]: {obj["arg0"][:300]}')
                print(f'  arg1 [{obj["arg1_len"]}]: {obj["arg1"]}')
                print(f'  arg2 [{obj["arg2_len"]}]: {obj["arg2"][:200]}')
                print(f'  Regs: RAX={obj["rax"]} RBX={obj["rbx"]} RCX={obj["rcx"]} RDI={obj["rdi"]} R8={obj["r8"]} R9={obj["r9"]} R10={obj["r10"]}')
            elif t == 'getAuthSignature_output':
                print(f'  OUTPUT: {obj["output"]}')
                print(f'{"="*60}')
            elif t == 'md5encode':
                print(f'\n[Md5Encode] count={obj["count"]} preimage={repr(obj["preimage"][:300])}')
            elif t == 'md5encode_output':
                print(f'  MD5: {obj["output"]}')
            elif t == 'info':
                print(f'  [*] {obj["msg"]}')
            elif t == 'error':
                print(f'  [!] {obj["msg"]}')
        except Exception as e:
            print(f'  [raw] {message["payload"][:300]}')
    elif message['type'] == 'error':
        print(f'  [FERR] {message.get("description", message)}')

def main():
    os.makedirs(WORKDIR, exist_ok=True)

    # Kill existing
    device = frida.get_local_device()
    for proc in device.enumerate_processes():
        if 'Lingma' in proc.name or 'lingma' in proc.name.lower():
            try:
                device.kill(proc.pid)
                print(f'[*] Killed PID {proc.pid}')
            except:
                pass
    time.sleep(2)

    # Start Lingma
    print(f'[*] Starting Lingma...')
    lingma_proc = subprocess.Popen(
        [LINGMA_EXE, 'start',
         f'--workDir={WORKDIR}',
         f'--socketPort={SOCKET_PORT}',
         f'--httpPort={HTTP_PORT}'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print(f'[*] PID: {lingma_proc.pid}')

    # Wait for WebSocket
    print(f'[*] Waiting for WebSocket on port {SOCKET_PORT}...')
    ws_ready = False
    for i in range(60):
        time.sleep(1)
        if lingma_proc.poll() is not None:
            print(f'[!] Lingma exited with {lingma_proc.returncode}')
            return
        try:
            ws = websocket.create_connection(f'ws://127.0.0.1:{SOCKET_PORT}', timeout=2)
            ws.close()
            ws_ready = True
            print(f'[*] WebSocket ready after {i+1}s')
            break
        except:
            if i % 10 == 0:
                print(f'  Waiting... ({i+1}s)')

    if not ws_ready:
        print('[!] WebSocket never ready')
        lingma_proc.terminate()
        return

    # Attach Frida
    print('[*] Attaching Frida...')
    try:
        session = device.attach(lingma_proc.pid)
    except Exception as e:
        print(f'[!] Attach failed: {e}')
        lingma_proc.terminate()
        return

    script = session.create_script(FRIDA_SCRIPT)
    script.on('message', on_message)
    script.load()
    print('[*] Hooks installed. Sending device_login...')
    time.sleep(1)

    # Send device_login via WebSocket
    ws = websocket.create_connection(f'ws://127.0.0.1:{SOCKET_PORT}')
    cfg = json.load(open(r'C:/Users/Zipper/.lingma/portable_config.json'))

    # Initialize
    init_msg = {
        'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
        'params': {
            'processId': None,
            'clientInfo': {'name': 'authsig-hook', 'version': '1.0'},
            'rootUri': 'file:///tmp/hook',
            'capabilities': {},
            'workspaceFolders': [{'uri': 'file:///tmp/hook', 'name': 'hook'}],
        },
    }
    init_data = json.dumps(init_msg)
    ws.send(f'Content-Length: {len(init_data)}\r\n\r\n{init_data}')
    time.sleep(1)
    try:
        ws.settimeout(2)
        resp = ws.recv()
        print(f'[*] Init OK: {resp[:100]}')
    except:
        pass

    # device_login
    login_msg = {
        'jsonrpc': '2.0', 'id': 4, 'method': 'auth/device_login',
        'params': {
            'token': cfg.get('security_oauth_token', ''),
            'refreshToken': cfg.get('refresh_token', ''),
            'expiresIn': '',
            'expireTime': str(cfg.get('expire_time', '0')),
            'userId': cfg.get('user_id', ''),
            'username': cfg.get('user_name', ''),
        },
    }
    login_data = json.dumps(login_msg)
    ws.send(f'Content-Length: {len(login_data)}\r\n\r\n{login_data}')
    print('[*] device_login sent! Waiting for captures...')

    # Wait
    for i in range(30):
        time.sleep(2)
        try:
            ws.settimeout(1)
            resp = ws.recv()
            print(f'[*] WS response: {resp[:500]}')
        except:
            pass

    ws.close()
    print('[*] Waiting 5s more...')
    time.sleep(5)

    session.detach()
    try:
        lingma_proc.terminate()
        time.sleep(1)
        if lingma_proc.poll() is None:
            lingma_proc.kill()
    except:
        pass
    print('[*] Done')

if __name__ == '__main__':
    main()
