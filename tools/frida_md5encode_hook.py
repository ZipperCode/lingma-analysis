#!/usr/bin/env python3
"""
Minimal Frida hook for Md5Encode @ CORRECT RVA 0x456320.
Previous crash was because we hooked 0x4563C0 (epilogue, not entry).
"""
import frida
import sys
import time
import json
import hashlib
import os
import subprocess
import websocket

LINGMA_EXE = r"C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe"
WORKDIR = os.path.join(os.environ.get("TEMP", "C:/temp"), f"lingma-md5-{os.getpid()}")
SOCKET_PORT = 37099
HTTP_PORT = 37599
LOG_FILE = os.path.join(WORKDIR, "capture.jsonl")

FRIDA_SCRIPT = r"""
'use strict';

function readGoStr(addr, len) {
    if (addr.isNull() || len <= 0 || len > 8192) return '';
    try { return addr.readUtf8String(Math.min(len, 4096)); }
    catch (e) { return '<err>'; }
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
    send(JSON.stringify({type: 'error', msg: 'Module not found'}));
} else {
    var base = lingmaMod.base;
    send(JSON.stringify({type: 'info', msg: 'Base: ' + base}));

    // ====== Md5Encode @ CORRECT RVA 0x456320 ======
    // Go ABI: input string (ptr=RAX, len=RBX), output string (ptr=RAX, len=RBX)
    Interceptor.attach(base.add(0x456320), {
        onEnter: function(args) {
            this.rax_saved = this.context.rax;
            this.rbx_saved = this.context.rbx;
            this.rsp_saved = this.context.rsp;
            // DON'T read strings here - just save register values
        },
        onLeave: function(retval) {
            var ctx = this.context;
            var output_ptr = ctx.rax;
            var output_len = ctx.rbx.toInt32();

            // Now read the input string (we saved the ptr and len from onEnter)
            var input_ptr = this.rax_saved;
            var input_len = this.rbx_saved.toInt32();

            if (input_len <= 0 || input_len > 8192) return;

            var input_str = readGoStr(input_ptr, Math.min(input_len, 4096));
            var output_str = readGoStr(output_ptr, Math.min(output_len, 64));

            send(JSON.stringify({
                type: 'md5encode',
                input: input_str,
                input_len: input_str.length,
                output: output_str,
                output_len: output_str.length,
                ts: new Date().toISOString(),
            }));
        }
    });

    // ====== addBigModelSignatureHeaders @ 0x882760 ======
    // Debug: dump ALL registers to understand the true calling convention
    Interceptor.attach(base.add(0x882760), {
        onEnter: function(args) {
            var ctx = this.context;

            send(JSON.stringify({
                type: 'addBigSig',
                regs_all: {
                    rax: ctx.rax.toString(), rbx: ctx.rbx.toString(),
                    rcx: ctx.rcx.toString(), rdi: ctx.rdi.toString(),
                    rsi: ctx.rsi.toString(), r8: ctx.r8.toString(),
                    r9: ctx.r9.toString(), r10: ctx.r10.toString(),
                    r11: ctx.r11.toString(), r12: ctx.r12.toString(),
                    r13: ctx.r13.toString(), r14: ctx.r14.toString(),
                },
                ts: new Date().toISOString(),
            }));
        }
    });

    send(JSON.stringify({type: 'info', msg: 'Md5Encode (0x456320) + addBigSig hooks installed'}));
}
"""

captured = []

def on_message(message, data):
    if message['type'] == 'send':
        try:
            obj = json.loads(message['payload'])
            t = obj.get('type', '')
            # Save ALL events
            with open(LOG_FILE, 'a') as f:
                f.write(json.dumps(obj) + '\n')

            if t == 'md5encode':
                captured.append(obj)
                print(f'\n{"="*60}')
                print(f'*** Md5Encode CAPTURED! ***')
                print(f'  Input [{obj["input_len"]}]: {repr(obj["input"][:300])}')
                print(f'  Output: {obj["output"]}')
                # Compute MD5 and verify
                expected = hashlib.md5(obj['input'].encode()).hexdigest()
                match = 'MATCH!' if expected == obj['output'] else 'MISMATCH'
                print(f'  Verify: {match} (computed={expected})')
                print(f'{"="*60}')
            elif t == 'addBigSig':
                print(f'\n  [addBigSig] {obj["regs_all"]}')
            elif t == 'info':
                print(f'  [*] {obj["msg"]}')
            elif t == 'error':
                print(f'  [!] {obj["msg"]}')
        except Exception as e:
            print(f'  [raw] {message["payload"][:300]}  err={e}')
    elif message['type'] == 'error':
        print(f'  [FERR] {message.get("description", message)}')

def main():
    os.makedirs(WORKDIR, exist_ok=True)
    with open(LOG_FILE, 'w') as f:
        f.write('')

    device = frida.get_local_device()

    # Kill existing Lingma
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

    # Attach Frida EARLY
    print('[*] Attaching Frida early...')
    time.sleep(1.5)
    if lingma_proc.poll() is not None:
        print(f'[!] Lingma exited early with {lingma_proc.returncode}')
        return

    try:
        session = device.attach(lingma_proc.pid)
    except Exception as e:
        print(f'[!] Attach failed: {e}')
        lingma_proc.terminate()
        return

    script = session.create_script(FRIDA_SCRIPT)
    script.on('message', on_message)
    script.load()
    print('[*] Hooks installed!')

    # Wait for WebSocket
    print(f'[*] Waiting for WebSocket...')
    for i in range(60):
        time.sleep(1)
        if lingma_proc.poll() is not None:
            print(f'[!] Lingma exited with {lingma_proc.returncode}')
            break
        try:
            ws = websocket.create_connection(f'ws://127.0.0.1:{SOCKET_PORT}', timeout=2)
            ws.close()
            print(f'[*] WebSocket ready after {i+1}s')
            break
        except:
            pass

    # Send device_login
    time.sleep(2)
    cfg = json.load(open(r'C:/Users/Zipper/.lingma/portable_config.json'))
    ws = websocket.create_connection(f'ws://127.0.0.1:{SOCKET_PORT}')

    init_data = json.dumps({
        'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
        'params': {
            'processId': None,
            'clientInfo': {'name': 'md5-hook', 'version': '1.0'},
            'rootUri': 'file:///tmp/hook',
            'capabilities': {},
            'workspaceFolders': [{'uri': 'file:///tmp/hook', 'name': 'hook'}],
        },
    })
    ws.send(f'Content-Length: {len(init_data)}\r\n\r\n{init_data}')
    time.sleep(2)
    try:
        ws.settimeout(5)
        ws.recv()
    except:
        pass

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
    print('[*] device_login sent!')

    # Wait for captures
    print('[*] Waiting 20s for captures...')
    for i in range(10):
        time.sleep(2)
        try:
            ws.settimeout(1)
            resp = ws.recv()
            print(f'[*] WS: {resp[:150]}')
        except:
            pass
        if captured:
            print(f'  [{len(captured)} Md5Encode captures so far]')

    ws.close()
    time.sleep(5)

    # Cleanup
    session.detach()
    try:
        lingma_proc.terminate()
        time.sleep(1)
        if lingma_proc.poll() is None:
            lingma_proc.kill()
    except:
        pass

    print(f'\n{"="*60}')
    print(f'RESULTS: {len(captured)} Md5Encode captures')
    for i, cap in enumerate(captured):
        print(f'\n  Capture #{i+1}:')
        print(f'    Input: {repr(cap["input"][:200])}')
        print(f'    Output: {cap["output"]}')
        # Check if input contains oracle dates
        if '1777011796' in cap['input'] or '1777016140' in cap['input']:
            print(f'    *** CONTAINS ORACLE DATE! ***')
        if 'signtest' in cap['input']:
            print(f'    (test call)')

    print(f'\n[*] Log: {LOG_FILE}')
    print('[*] Done')

if __name__ == '__main__':
    main()
