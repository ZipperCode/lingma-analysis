#!/usr/bin/env python3
"""
Minimal Frida hook for getAuthSignature with CORRECTED s4 stack reading.
Based on Md5Encode call site analysis: join order is [s0, s4, s3, s2, s1]
"""
import frida
import sys
import time
import json
import os
import subprocess
import hashlib
import websocket

LINGMA_EXE = r"C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe"
WORKDIR = os.path.join(os.environ.get("TEMP", "C:/temp"), f"lingma-sig-v2-{os.getpid()}")
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

    // getAuthSignature @ RVA 0x890140
    // Go 1.17+ ABI for 5 string args (10 words):
    //   s0: ptr=RAX, len=RBX
    //   s1: ptr=RCX, len=RDI
    //   s2: ptr=RSI, len=R8
    //   s3: ptr=R9,  len=R10
    //   s4: ptr=[RSP+8], len=[RSP+16]  (both on stack!)
    // JOIN ORDER (verified via Md5Encode call site): [s0, s4, s3, s2, s1]

    Interceptor.attach(base.add(0x890140), {
        onEnter: function(args) {
            var ctx = this.context;

            var s0_ptr = ctx.rax;
            var s0_len = ctx.rbx.toInt32();
            var s0_str = readGoStr(s0_ptr, s0_len);

            var s1_ptr = ctx.rcx;
            var s1_len = ctx.rdi.toInt32();
            var s1_str = readGoStr(s1_ptr, s1_len);

            var s2_ptr = ctx.rsi;
            var s2_len = ctx.r8.toInt32();
            var s2_str = readGoStr(s2_ptr, s2_len);

            var s3_ptr = ctx.r9;
            var s3_len = ctx.r10.toInt32();
            var s3_str = readGoStr(s3_ptr, s3_len);

            // s4: BOTH ptr and len on stack
            var s4_ptr = ctx.rsp.add(8).readPointer();
            var s4_len = ctx.rsp.add(16).readU64().toNumber();
            var s4_str = readGoStr(s4_ptr, s4_len);

            this.args_in_order = [s0_str, s4_str, s3_str, s2_str, s1_str];

            send(JSON.stringify({
                type: 'getAuthSignature',
                s0: s0_str, s0_len: s0_str.length,
                s1: s1_str, s1_len: s1_str.length,
                s2: s2_str, s2_len: s2_str.length,
                s3: s3_str, s3_len: s3_str.length,
                s4: s4_str, s4_len: s4_str.length,
                regs: {
                    rax: s0_ptr.toString(), rbx: s0_len,
                    rcx: s1_ptr.toString(), rdi: s1_len,
                    rsi: s2_ptr.toString(), r8: s2_len,
                    r9: s3_ptr.toString(), r10: s3_len,
                    s4_ptr: s4_ptr.toString(), s4_len: s4_len,
                },
                ts: new Date().toISOString(),
            }));
        },
        onLeave: function(retval) {
            var ctx = this.context;
            var output = readGoStr(ctx.rax, ctx.rbx.toInt32());
            send(JSON.stringify({
                type: 'getAuthSignature_output',
                output: output,
                output_len: output.length,
            }));

            if (this.args_in_order) {
                var preimage = this.args_in_order.join('\n');
                send(JSON.stringify({
                    type: 'reconstructed',
                    preimage: preimage,
                    preimage_len: preimage.length,
                    join_order: 's0,s4,s3,s2,s1',
                }));
            }
        }
    });

    send(JSON.stringify({type: 'info', msg: 'All hooks installed'}));

    // Also hook addBigModelSignatureHeaders @ 0x882760
    // Go 1.17+ ABI for 3 string args:
    //   s0: ptr=RAX, len=RBX  ("cosy")
    //   s1: ptr=RCX, len=RDI  (KEY - this is what we need!)
    //   s2: ptr=RSI, len=R8   (date)
    Interceptor.attach(base.add(0x882760), {
        onEnter: function(args) {
            var ctx = this.context;

            // DUMP ALL REGISTERS for debugging
            var regDump = {
                rax: ctx.rax.toString(), rbx: ctx.rbx.toString(),
                rcx: ctx.rcx.toString(), rdi: ctx.rdi.toString(),
                rsi: ctx.rsi.toString(), r8: ctx.r8.toString(),
                r9: ctx.r9.toString(), r10: ctx.r10.toString(),
                r11: ctx.r11.toString(), r12: ctx.r12.toString(),
            };

            // Try reading strings at ALL pointer-like registers
            function tryRead(ptr, maxLen) {
                if (ptr.isNull()) return '(nil)';
                try {
                    var s = ptr.readUtf8String(maxLen);
                    return s.length > 0 ? s : '(empty at ' + ptr + ')';
                } catch(e) {
                    // Try reading as bytes
                    try {
                        var bytes = ptr.readByteArray(Math.min(maxLen, 64));
                        if (!bytes) return '(no bytes at ' + ptr + ')';
                        var hex = '';
                        var arr = new Uint8Array(bytes);
                        for (var i = 0; i < Math.min(arr.length, 32); i++) {
                            hex += ('0' + arr[i].toString(16)).slice(-2);
                        }
                        return 'HEX[' + arr.length + ']: ' + hex;
                    } catch(e2) {
                        return '(unreadable: ' + e2 + ')';
                    }
                }
            }

            // Read strings at each interesting pointer
            var reads = {};
            // RDI = 0x7FF750BF56E3 → this is a MODULE address (static string!)
            reads.rdi_str = tryRead(ctx.rdi, 64);
            // RCX - heap pointer
            reads.rcx_str = tryRead(ctx.rcx, 64);
            // RAX - heap pointer but len=0
            reads.rax_str = tryRead(ctx.rax, 64);
            // R9 - heap pointer
            reads.r9_str = tryRead(ctx.r9, 64);
            // R11 - heap pointer
            reads.r11_str = tryRead(ctx.r11, 64);

            send(JSON.stringify({
                type: 'old_sig_debug',
                regDump: regDump,
                reads: reads,
                // Also try standard mapping
                rsi_r8_str: readGoStr(ctx.rsi, ctx.r8.toInt32()),
                ts: new Date().toISOString(),
            }));

            var s0 = readGoStr(ctx.rax, ctx.rbx.toInt32());
            var s1 = readGoStr(ctx.rcx, 64);
            var s2 = readGoStr(ctx.rsi, ctx.r8.toInt32());

            send(JSON.stringify({
                type: 'old_sig_enter',
                s0: s0, s0_len: s0.length,
                s1: s1, s1_len: s1.length,
                s2: s2, s2_len: s2.length,
                regs: {
                    rax: ctx.rax.toString(), rbx: ctx.rbx.toInt32(),
                    rcx: ctx.rcx.toString(), rdi: ctx.rdi.toInt32(),
                    rsi: ctx.rsi.toString(), r8: ctx.r8.toInt32(),
                },
                ts: new Date().toISOString(),
            }));

            this.args = [s0, s1, s2];
        },
        onLeave: function(retval) {
            var ctx = this.context;
            var output = readGoStr(ctx.rax, ctx.rbx.toInt32());
            send(JSON.stringify({
                type: 'old_sig_leave',
                output: output,
                output_len: output.length,
            }));

            if (this.args) {
                var preimage = this.args.join('');
                send(JSON.stringify({
                    type: 'old_sig_preimage',
                    preimage: preimage,
                    preimage_len: preimage.length,
                    formula: 's0+s1+s2 (cosy+key+date)',
                }));
            }
        }
    });

    send(JSON.stringify({type: 'info', msg: 'Old sig hook also installed'}));
}
"""

def on_message(message, data):
    if message['type'] == 'send':
        try:
            obj = json.loads(message['payload'])
            t = obj.get('type', '')
            # Save ALL events
            with open(LOG_FILE, 'a') as f:
                f.write(json.dumps(obj) + '\n')

            if t == 'getAuthSignature':
                print(f'\n{"="*60}')
                print(f'*** getAuthSignature ***')
                print(f'  s0 [{obj["s0_len"]}]: {obj["s0"][:120]}...')
                print(f'  s1 [{obj["s1_len"]}]: {repr(obj["s1"])}')
                print(f'  s2 [{obj["s2_len"]}]: {repr(obj["s2"])}')
                print(f'  s3 [{obj["s3_len"]}]: {repr(obj["s3"])}')
                print(f'  s4 [{obj["s4_len"]}]: {repr(obj["s4"][:120])}')
                print(f'  Regs: {obj.get("regs", {})}')
            elif t == 'old_sig_debug':
                print(f'\n{"="*60}')
                print(f'*** OLD SIG DEBUG ***')
                print(f'  RegDump: {obj["regDump"]}')
                reads = obj.get("reads", {})
                for k, v in reads.items():
                    print(f'  {k}: {repr(v)}')
                print(f'  rsi_r8_str: {repr(obj.get("rsi_r8_str", ""))}')
                print(f'{"="*60}')
            elif t == 'old_sig_enter':
                print(f'\n{"="*60}')
                print(f'*** OLD SIGNATURE (addBigModelSignatureHeaders) ***')
                print(f'  s0 (cosy)  [{obj["s0_len"]}]: {repr(obj["s0"])}')
                print(f'  s1 (KEY!)  [{obj["s1_len"]}]: {repr(obj["s1"])}')
                print(f'  s2 (date)  [{obj["s2_len"]}]: {repr(obj["s2"])}')
                print(f'  Regs: {obj.get("regs", {})}')
            elif t == 'old_sig_leave':
                print(f'  OLD SIG OUTPUT: {obj["output"]}')
                print(f'{"="*60}')
            elif t == 'old_sig_preimage':
                print(f'  OLD SIG PREIMAGE ({obj["preimage_len"]} chars): {repr(obj["preimage"])}')
                print(f'  Formula: {obj.get("formula", "?")}')
            elif t == 'getAuthSignature_output':
                print(f'  OUTPUT: {obj["output"]}')
                print(f'{"="*60}')
            elif t == 'reconstructed':
                pre = obj['preimage']
                print(f'  PREIMAGE ({obj["preimage_len"]} chars) order={obj.get("join_order","?")}:')
                if len(pre) > 200:
                    print(f'    {pre[:100]}')
                    print(f'    ...')
                    print(f'    {pre[-100:]}')
                else:
                    print(f'    {repr(pre)}')
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
    # Clear log file
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

    # Attach Frida EARLY - before Lingma finishes initialization (don't wait for WS first!)
    print('[*] Attaching Frida early (before WebSocket ready)...')
    time.sleep(1.5)  # Brief wait for process to start loading
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

    # Now wait for WebSocket
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

    # Connect and trigger device_login
    time.sleep(2)
    cfg = json.load(open(r'C:/Users/Zipper/.lingma/portable_config.json'))
    ws = websocket.create_connection(f'ws://127.0.0.1:{SOCKET_PORT}')

    # Initialize
    init_data = json.dumps({
        'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
        'params': {
            'processId': None,
            'clientInfo': {'name': 'sig-v2', 'version': '1.0'},
            'rootUri': 'file:///tmp/hook',
            'capabilities': {},
            'workspaceFolders': [{'uri': 'file:///tmp/hook', 'name': 'hook'}],
        },
    })
    ws.send(f'Content-Length: {len(init_data)}\r\n\r\n{init_data}')
    time.sleep(2)
    try:
        ws.settimeout(5)
        resp = ws.recv()
        print(f'[*] Init: {resp[:100]}')
    except Exception as e:
        print(f'[*] Init recv: {e}')

    # Send device_login to trigger COSY flow
    print('[*] Sending device_login...')
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
    time.sleep(5)

    try:
        ws.settimeout(3)
        resp = ws.recv()
        print(f'[*] WS response: {resp[:200]}')
    except:
        pass

    ws.close()
    print('[*] Waiting 10s more for captures...')
    time.sleep(10)

    # Cleanup
    session.detach()
    try:
        lingma_proc.terminate()
        time.sleep(1)
        if lingma_proc.poll() is None:
            lingma_proc.kill()
    except:
        pass

    # Verify MD5
    print(f'\n{"="*60}')
    print('VERIFICATION:')
    with open(LOG_FILE) as f:
        lines = [json.loads(l) for l in f if l.strip()]

    sigs = [l for l in lines if l['type'] == 'getAuthSignature']
    outputs = [l for l in lines if l['type'] == 'getAuthSignature_output']
    old_sigs = [l for l in lines if l['type'] == 'old_sig_enter']
    old_outputs = [l for l in lines if l['type'] == 'old_sig_leave']

    for i, (sig, out) in enumerate(zip(sigs, outputs)):
        join_order = ['s0', 's4', 's3', 's2', 's1']
        parts = [sig['s0'], sig['s4'], sig['s3'], sig['s2'], sig['s1']]
        preimage = '\n'.join(parts)
        md5 = hashlib.md5(preimage.encode()).hexdigest()
        expected = out['output']
        match = 'MATCH!' if md5 == expected else 'MISMATCH'
        print(f'\nCOSY Capture #{i+1}: {match}')
        print(f'  Computed: {md5}')
        print(f'  Expected: {expected}')
        print(f'  Parts: s0={len(sig["s0"])} s4={len(sig["s4"])} s3={len(sig["s3"])} s2={len(sig["s2"])} s1={len(sig["s1"])}')

    for i, (sig, out) in enumerate(zip(old_sigs, old_outputs)):
        preimage = sig['s0'] + sig['s1'] + sig['s2']
        md5 = hashlib.md5(preimage.encode()).hexdigest()
        expected = out['output']
        match = 'MATCH!' if md5 == expected else 'MISMATCH'
        print(f'\nOLD SIG Capture #{i+1}: {match}')
        print(f'  Computed: {md5}')
        print(f'  Expected: {expected}')
        print(f'  Key (s1): {repr(sig["s1"])}')
        print(f'  Date (s2): {repr(sig["s2"])}')

    print(f'\n[*] Log: {LOG_FILE}')
    print('[*] Done')

if __name__ == '__main__':
    main()
