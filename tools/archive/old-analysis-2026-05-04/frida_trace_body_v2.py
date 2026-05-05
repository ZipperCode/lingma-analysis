"""Improved Frida hook to capture encodeRequestBody input/output and shouldEncryptBody decision."""

import argparse
import json
import pathlib
import sys
import time

import frida

JS_SOURCE = r"""
function readGoString(ptr, lenHex) {
    const len = parseInt(String(lenHex), 16);
    const p = new NativePointer(String(ptr));
    if (p.isNull() || len === 0) {
        return { ptr: p.toString(), len: 0, text: "" };
    }
    if (len > 0x100000) {
        return { ptr: p.toString(), len: len, text: "", error: "too-long" };
    }
    try {
        const text = p.readUtf8String(len);
        return { ptr: p.toString(), len: len, text: text || "" };
    } catch (e) {
        return { ptr: p.toString(), len: len, text: "", error: String(e) };
    }
}

function readBytes(ptr, len) {
    const p = new NativePointer(String(ptr));
    const l = parseInt(String(len), 16);
    if (p.isNull() || l === 0 || l > 0x100000) {
        return { ptr: p.toString(), len: l, hex: "", base64: "" };
    }
    try {
        const buf = p.readByteArray(Math.min(l, 1024));
        const arr = new Uint8Array(buf);
        let hex = "";
        for (let i = 0; i < arr.length; i++) {
            hex += ("0" + arr[i].toString(16)).slice(-2);
        }
        // base64
        const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        let b64 = "";
        for (let i = 0; i < arr.length; i += 3) {
            const a = arr[i], b = i+1 < arr.length ? arr[i+1] : 0, c = i+2 < arr.length ? arr[i+2] : 0;
            const triple = (a << 16) | (b << 8) | c;
            b64 += alphabet[(triple >> 18) & 0x3f];
            b64 += alphabet[(triple >> 12) & 0x3f];
            b64 += i+1 < arr.length ? alphabet[(triple >> 6) & 0x3f] : "=";
            b64 += i+2 < arr.length ? alphabet[triple & 0x3f] : "=";
        }
        return { ptr: p.toString(), len: l, hex: hex, base64: b64 };
    } catch (e) {
        return { ptr: p.toString(), len: l, hex: "", base64: "", error: String(e) };
    }
}

function dumpRegisters(ctx) {
    const regs = {};
    ["rax","rbx","rcx","rdx","rdi","rsi","r8","r9","r10","r11","r12","r13","r14","r15","rsp","rbp"].forEach(r => {
        regs[r] = String(ctx[r]);
    });
    return regs;
}

// Go string from (ptr, len) pair
function dumpGoPair(ptrReg, lenReg) {
    return readGoString(ptrReg, lenReg);
}

function installHooks() {
    const main = Process.enumerateModules()[0];
    const base = ptr(main.base);

    const targets = {
        encodeRequestBody: base.add(0x881820),
        shouldEncryptBody: base.add(0x882680),
    };

    send({
        event: "module",
        name: main.name,
        base: main.base.toString(),
        size: main.size,
        targets: Object.fromEntries(
            Object.entries(targets).map(([k, v]) => [k, v.toString()])
        ),
    });

    // Hook encodeRequestBody
    // Go calling convention on amd64: arguments on stack
    // But the function signature is likely: encodeRequestBody(method, url, body) -> (encodedBody string, err error)
    // On enter: read args from stack
    // On leave: read return values from rax/rbx (string ptr, len)

    Interceptor.attach(targets.encodeRequestBody, {
        onEnter(args) {
            // In Go amd64 ABI, args are on stack after return address
            // The function likely receives: method string (ptr+len), url string (ptr+len), body string (ptr+len)
            // Stack layout: [rsp+0x08] = ret addr, [rsp+0x10+] = args
            // But Go's stack layout varies. Let's dump everything we can find.

            this.methodStr = dumpGoPair(
                this.context.rax || this.context.rcx,
                this.context.rbx || this.context.rdx
            );
            this.urlStr = dumpGoPair(
                this.context.rsi,
                this.context.r8
            );
            this.bodyStr = dumpGoPair(
                this.context.r9,
                this.context.r10
            );

            // Also try stack-based args (Go 1.17+ uses registers for first 6 args)
            // Stack offsets for args beyond register args
            this.stackArgs = [];
            for (let i = 0; i < 8; i++) {
                const stackPtr = this.context.rsp.add(0x08 + i * 0x08);
                this.stackArgs.push({
                    offset: 0x08 + i * 0x08,
                    value: String(stackPtr.readPointer()),
                });
            }

            send({
                event: "encodeRequestBody.enter",
                method: this.methodStr,
                url: this.urlStr,
                body: this.bodyStr,
                stackPreview: this.stackArgs,
                registers: dumpRegisters(this.context),
            });
        },

        onLeave(retval) {
            // Return values in Go are placed after input args on stack (or in registers for Go 1.17+)
            // For a function returning (string, error), the return is:
            // string ptr, string len, error interface (type ptr, data ptr)

            // Try reading return from stack (old ABI) or registers (new ABI)
            // For Go 1.17+, string return is in rax (ptr) and rbx (len)
            // For old ABI, it would be on stack

            const retPtr = this.context.rax;
            const retLen = this.context.rbx;

            const retStr = dumpGoPair(retPtr, retLen);

            // Also try reading from stack at expected return offset
            // For old Go ABI, return values start after all input args
            // Approximate: stack at rsp + 0x50 (after 6 register args spilled)
            let stackRet = null;
            try {
                const stackRetPtr = this.context.rsp.add(0x50);
                const stackRetLen = this.context.rsp.add(0x58);
                stackRet = dumpGoPair(stackRetPtr, stackRetLen);
            } catch (e) {}

            // Also check rcx/rdx which might hold return in some conventions
            const rcxRdxRet = dumpGoPair(this.context.rcx, this.context.rdx);

            send({
                event: "encodeRequestBody.leave",
                retval: String(retval),
                retRegister: retStr,       // rax/rbx pair
                retStack: stackRet,        // stack-based return attempt
                retRcxRdx: rcxRdxRet,      // rcx/rdx pair
                registers: dumpRegisters(this.context),
            });
        },
    });

    // Hook shouldEncryptBody
    Interceptor.attach(targets.shouldEncryptBody, {
        onEnter(args) {
            this.methodStr = dumpGoPair(this.context.rax, this.context.rbx);
            this.urlStr = dumpGoPair(this.context.rcx, this.context.rdi);
            this.bodyStr = dumpGoPair(this.context.rsi, this.context.r8);

            send({
                event: "shouldEncryptBody.enter",
                method: this.methodStr,
                url: this.urlStr,
                body: this.bodyStr,
                registers: dumpRegisters(this.context),
            });
        },

        onLeave(retval) {
            // Returns bool - whether to encrypt the body
            send({
                event: "shouldEncryptBody.leave",
                retval: String(retval),
                registers: dumpRegisters(this.context),
            });
        },
    });

    // Hook the actual encoding function if we can find it
    // code.alibaba-inc.com/cosy/encrypt.* functions
    // Try to find common encoding functions by scanning

    send({ event: "hooks_installed", count: Object.keys(targets).length });
}

installHooks();
"""

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--output", default="capture/frida-body-trace-v2.jsonl")
    parser.add_argument("--duration", type=float, default=120.0)
    args = parser.parse_args()

    output_path = pathlib.Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[*] Attaching to PID {args.pid}")
    print(f"[*] Logging to {output_path}")
    print(f"[*] Duration: {args.duration}s")

    session = frida.attach(args.pid)
    script = session.create_script(JS_SOURCE)

    event_count = 0
    with output_path.open("a", encoding="utf-8") as fh:
        def on_message(message, data):
            nonlocal event_count
            event_count += 1
            row = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "seq": event_count,
                "message": message.get("payload", message),
            }
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            fh.flush()

            payload = message.get("payload", {})
            event = payload.get("event", message.get("type", "unknown"))

            if event == "encodeRequestBody.enter":
                body = payload.get("body", {})
                print(f"\n[ENCODE ENTER] method={body.get('text','')[:50] if body else 'N/A'}")
                print(f"  URL={payload.get('url', {}).get('text', '')[:100]}")
                body_text = body.get('text', '') if body else ''
                if body_text:
                    print(f"  Body ({body.get('len', '?')} chars): {body_text[:200]}")
                else:
                    print(f"  Body: (empty or not found in expected registers)")
                    # Show what we did find
                    for reg_pair in ["retRegister", "retStack", "retRcxRdx"]:
                        pair = payload.get(reg_pair, {})
                        if pair.get('text'):
                            print(f"    {reg_pair}: {pair['text'][:100]}")

            elif event == "encodeRequestBody.leave":
                ret = payload.get("retRegister", {})
                print(f"\n[ENCODE LEAVE] rax/rbx return: ptr={ret.get('ptr','?')} len={ret.get('len','?')}")
                if ret.get('text'):
                    print(f"  Encoded body ({ret.get('len', '?')} chars): {ret['text'][:200]}")

                # Check alternative return locations
                for alt in ["retStack", "retRcxRdx"]:
                    alt_data = payload.get(alt, {})
                    if alt_data.get('text') and alt_data.get('len', 0) > 0:
                        print(f"  Alternative return ({alt}): {alt_data['text'][:100]}")

            elif event == "shouldEncryptBody.enter":
                method = payload.get("method", {}).get("text", "")
                url = payload.get("url", {}).get("text", "")
                print(f"\n[SHOULD ENCRYPT] method={method} url={url[:80]}")

            elif event == "shouldEncryptBody.leave":
                retval = payload.get("retval", "")
                print(f"  -> encrypt={retval}")

            elif event == "module":
                print(f"[*] Module: {payload['name']} base={payload['base']} size={payload['size']}")
                for name, addr in payload.get("targets", {}).items():
                    print(f"    {name}: {addr}")

            elif event == "hooks_installed":
                print(f"[*] Hooks installed: {payload['count']} functions")

        script.on("message", on_message)
        script.load()
        print("[*] Script loaded. Waiting for events...")
        try:
            time.sleep(args.duration)
        finally:
            session.detach()

    print(f"\n[*] Done. {event_count} events logged to {output_path}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
