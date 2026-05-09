#!/usr/bin/env python3
"""
Corrected Frida hook for getAuthSignature with proper Go 1.17+ ABI register mapping.
String layout: {ptr, len} pairs in RAX/RBX, RCX/RDI, RSI/R8, R9/R10, R11/[stack]
"""
import frida
import sys
import time
import json
import os
import subprocess
import websocket

LINGMA_EXE = r"C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe"
WORKDIR = os.path.join(os.environ.get("TEMP", "C:/temp"), "lingma-sig-correct")
SOCKET_PORT = 37099
HTTP_PORT = 37599

FRIDA_SCRIPT = r"""
'use strict';

function readGoStr(addr, len) {
    if (addr.isNull() || len <= 0 || len > 8192) return '';
    try { return addr.readUtf8String(Math.min(len, 2048)); }
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

    // Hook the actual Md5Encode CALL SITE inside getAuthSignature @ 0x8902ef
    // At this point RAX = ptr to string array, RBX = count
    Interceptor.attach(base.add(0x8902ef), {
        onEnter: function(args) {
            var ctx = this.context;
            var arrPtr = ctx.rax;
            var count = ctx.rbx.toInt32();
            if (count <= 0 || count > 100) return;

            var parts = [];
            for (var i = 0; i < count; i++) {
                var ptr = arrPtr.add(i * 16).readPointer();
                var len = arrPtr.add(i * 16 + 8).readU64().toNumber();
                parts.push({
                    idx: i,
                    len: Math.min(len, 4096),
                    text: readGoStr(ptr, Math.min(len, 4096)),
                });
            }

            var joined = parts.map(function(p) { return p.text; }).join('');
            send(JSON.stringify({
                type: 'md5encode_call_site',
                count: count,
                parts: parts,
                joined: joined,
                joinedLen: joined.length,
                arrPtr: arrPtr.toString(),
                ts: new Date().toISOString(),
            }));
        }
    });

    // getAuthSignature @ RVA 0x890140
    // Go 1.17+ ABI for 5 string args (10 words):
    //   s0: ptr=RAX, len=RBX
    //   s1: ptr=RCX, len=RDI
    //   s2: ptr=RSI, len=R8
    //   s3: ptr=R9,  len=R10
    //   s4: ptr=[RSP+8], len=[RSP+16]  (both on stack!)

    Interceptor.attach(base.add(0x890140), {
        onEnter: function(args) {
            var ctx = this.context;

            var s0_ptr = ctx.rax;
            var s0_len = ctx.rbx.toInt32();
            var s0 = readGoStr(s0_ptr, s0_len);

            var s1_ptr = ctx.rcx;
            var s1_len = ctx.rdi.toInt32();
            var s1 = readGoStr(s1_ptr, s1_len);

            // CORRECTED: s2 is RSI(ptr) + R8(len)
            var s2_ptr = ctx.rsi;
            var s2_len = ctx.r8.toInt32();
            var s2 = readGoStr(s2_ptr, s2_len);

            // s3 is R9(ptr) + R10(len)
            var s3_ptr = ctx.r9;
            var s3_len = ctx.r10.toInt32();
            var s3 = readGoStr(s3_ptr, s3_len);

            // s4: BOTH ptr and len on stack at [RSP+8] and [RSP+16]
            var s4_ptr = ctx.rsp.add(8).readPointer();
            var s4_len = ctx.rsp.add(16).readU64().toNumber();
            var s4 = readGoStr(s4_ptr, s4_len);

            send(JSON.stringify({
                type: 'getAuthSignature',
                s0: s0, s0_len: s0.length,
                s1: s1, s1_len: s1.length,
                s2: s2, s2_len: s2.length,
                s3: s3, s3_len: s3.length,
                s4: s4, s4_len: s4.length,
                // Raw register values for debugging
                regs: {
                    rax: s0_ptr.toString(), rbx: s0_len,
                    rcx: s1_ptr.toString(), rdi: s1_len,
                    rsi: s2_ptr.toString(), r8: s2_len,
                    r9: s3_ptr.toString(), r10: s3_len,
                    r11: s4_ptr.toString(),
                },
                ts: new Date().toISOString(),
            }));

            this.all_args = [s0, s4, s3, s2, s1];  // CORRECT order from Md5Encode call site
        },
        onLeave: function(retval) {
            var ctx = this.context;
            var output = readGoStr(ctx.rax, ctx.rbx.toInt32());
            send(JSON.stringify({
                type: 'getAuthSignature_output',
                output: output,
            }));

            // Reconstruct the preimage
            if (this.all_args) {
                var preimage = this.all_args.join('\n');
                send(JSON.stringify({
                    type: 'reconstructed',
                    preimage: preimage,
                    preimage_len: preimage.length,
                }));
            }
        }
    });

    // Also hook addBigModelSignatureHeaders @ 0x882760
    // Go 1.17+ ABI for 3 string args:
    //   s0: ptr=RAX, len=RBX  ("cosy")
    //   s1: ptr=RCX, len=RDI  (KEY - this is what we need!)
    //   s2: ptr=RSI, len=R8   (date)
    Interceptor.attach(base.add(0x882760), {
        onEnter: function(args) {
            var ctx = this.context;

            var s0_ptr = ctx.rax;
            var s0_len = ctx.rbx.toInt32();
            var s0 = readGoStr(s0_ptr, s0_len);

            var s1_ptr = ctx.rcx;
            var s1_len = ctx.rdi.toInt32();
            var s1 = readGoStr(s1_ptr, s1_len);

            var s2_ptr = ctx.rsi;
            var s2_len = ctx.r8.toInt32();
            var s2 = readGoStr(s2_ptr, s2_len);

            send(JSON.stringify({
                type: 'addBigModelSignatureHeaders_enter',
                s0: s0, s0_len: s0.length,
                s1: s1, s1_len: s1.length,
                s2: s2, s2_len: s2.length,
                regs: {
                    rax: s0_ptr.toString(), rbx: s0_len,
                    rcx: s1_ptr.toString(), rdi: s1_len,
                    rsi: s2_ptr.toString(), r8: s2_len,
                },
                ts: new Date().toISOString(),
            }));

            this.s0 = s0;
            this.s1 = s1;
            this.s2 = s2;
        },
        onLeave: function(retval) {
            var ctx = this.context;
            var output = readGoStr(ctx.rax, ctx.rbx.toInt32());
            send(JSON.stringify({
                type: 'addBigModelSignatureHeaders_leave',
                output: output,
                output_len: output.length,
            }));

            // Reconstruct preimage
            if (this.s0 !== undefined) {
                var preimage = this.s0 + this.s1 + this.s2;
                send(JSON.stringify({
                    type: 'addBigModelSignatureHeaders_preimage',
                    preimage: preimage,
                    preimage_len: preimage.length,
                    formula: 's0+s1+s2 (cosy+key+date)',
                }));
            }
        }
    });

    send(JSON.stringify({type: 'info', msg: 'All hooks installed'}));
}
"""

captured = []
LOG_FILE = os.path.join(WORKDIR, "frida_capture.jsonl")

def on_message(message, data):
    if message['type'] == 'send':
        try:
            obj = json.loads(message['payload'])
            t = obj.get('type', '')
            # Save ALL events to file for full data preservation
            with open(LOG_FILE, 'a') as f:
                f.write(json.dumps(obj) + '\n')

            if t == 'getAuthSignature':
                print(f'\n{"="*60}')
                print(f'*** getAuthSignature ***')
                print(f'  s0 [{obj["s0_len"]}]: {obj["s0"][:200]}')
                print(f'  s1 [{obj["s1_len"]}]: {repr(obj["s1"])}')
                print(f'  s2 [{obj["s2_len"]}]: {repr(obj["s2"])}')
                print(f'  s3 [{obj["s3_len"]}]: {repr(obj["s3"])}')
                print(f'  s4 [{obj["s4_len"]}]: {repr(obj["s4"])}')
                print(f'  Regs: {obj.get("regs", {})}')
                captured.append(obj)
            elif t == 'md5encode_call_site':
                print(f'\n{"="*60}')
                print(f'*** Md5Encode CALL SITE (inside getAuthSignature) ***')
                print(f'  count={obj["count"]} joinedLen={obj["joinedLen"]}')
                for p in obj['parts']:
                    print(f'  Part[{p["idx"]}] len={p["len"]}: {repr(p["text"][:300])}')
                print(f'  JOINED: {repr(obj["joined"])}')
                captured.append(obj)
            elif t == 'getAuthSignature_output':
                print(f'  OUTPUT: {obj["output"]}')
                print(f'{"="*60}')
            elif t == 'reconstructed':
                print(f'  RECONSTRUCTED PREIMAGE ({obj["preimage_len"]} chars):')
                # Show first 100 and last 100
                pre = obj['preimage']
                if len(pre) > 300:
                    print(f'    {pre[:150]}')
                    print(f'    ...')
                    print(f'    {pre[-150:]}')
                else:
                    print(f'    {pre}')
            elif t == 'addBigModelSignatureHeaders_enter':
                print(f'\n{"="*60}')
                print(f'*** addBigModelSignatureHeaders ENTER ***')
                print(f'  s0 (cosy)  [{obj["s0_len"]}]: {repr(obj["s0"])}')
                print(f'  s1 (KEY!)  [{obj["s1_len"]}]: {repr(obj["s1"])}')
                print(f'  s2 (date)  [{obj["s2_len"]}]: {repr(obj["s2"])}')
                print(f'  Regs: {obj.get("regs", {})}')
            elif t == 'addBigModelSignatureHeaders_leave':
                print(f'  OUTPUT: {obj["output"]}')
                print(f'{"="*60}')
            elif t == 'addBigModelSignatureHeaders_preimage':
                print(f'  PREIMAGE ({obj["preimage_len"]} chars): {repr(obj["preimage"])}')
                print(f'  Formula: {obj.get("formula", "unknown")}')
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

    # Wait for WebSocket
    print(f'[*] Waiting for WebSocket...')
    for i in range(60):
        time.sleep(1)
        if lingma_proc.poll() is not None:
            print(f'[!] Lingma exited with {lingma_proc.returncode}')
            return
        try:
            ws = websocket.create_connection(f'ws://127.0.0.1:{SOCKET_PORT}', timeout=2)
            ws.close()
            print(f'[*] WebSocket ready after {i+1}s')
            break
        except:
            if i % 10 == 0:
                print(f'  Waiting... ({i+1}s)')

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
    print('[*] Hooks installed!')

    # Send device_login to trigger getAuthSignature (COSY flow)
    time.sleep(3)  # Wait longer after Frida attach
    ws = websocket.create_connection(f'ws://127.0.0.1:{SOCKET_PORT}')
    cfg = json.load(open(r'C:/Users/Zipper/.lingma/portable_config.json'))

    # Step 1: Initialize
    init_data = json.dumps({
        'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
        'params': {
            'processId': None,
            'clientInfo': {'name': 'corrected-hook', 'version': '1.0'},
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
        print(f'[*] Init response: {resp[:200]}')
    except Exception as e:
        print(f'[*] Init recv: {e}')

    # Step 2: Send auth/device_login
    print('[*] Sending auth/device_login...')
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
    try:
        ws.send(f'Content-Length: {len(login_data)}\r\n\r\n{login_data}')
        print('[*] device_login sent!')
    except Exception as e:
        print(f'[!] device_login send failed: {e}')
        # Reconnect and retry
        try:
            ws.close()
        except:
            pass
        time.sleep(2)
        ws = websocket.create_connection(f'ws://127.0.0.1:{SOCKET_PORT}')
        ws.send(f'Content-Length: {len(init_data)}\r\n\r\n{init_data}')
        time.sleep(2)
        try:
            ws.settimeout(3)
            ws.recv()
        except:
            pass
        ws.send(f'Content-Length: {len(login_data)}\r\n\r\n{login_data}')
        print('[*] device_login sent (retry)!')

    # Read responses for up to 30s
    for i in range(15):
        try:
            ws.settimeout(2)
            resp = ws.recv()
            if len(resp) > 200:
                print(f'[*] WS {i+1}: {resp[:200]}...')
            else:
                print(f'[*] WS {i+1}: {resp}')
        except:
            pass

    ws.close()
    print('[*] Waiting 10s for captures...')
    time.sleep(10)

    session.detach()
    try:
        lingma_proc.terminate()
        time.sleep(1)
        if lingma_proc.poll() is None:
            lingma_proc.kill()
    except:
        pass
    print('[*] Done')
    print(f'[*] Log saved to: {LOG_FILE}')
    if captured:
        print(f'[*] {len(captured)} events captured')

if __name__ == '__main__':
    main()
