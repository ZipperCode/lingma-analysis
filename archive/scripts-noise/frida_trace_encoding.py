"""
Ultimate Frida script to capture body encoding in Lingma.exe.

Hooks:
- encodeRequestBody (RVA 0x881820): captures input JSON and output encoded body
- (*encoding).encodeToString (RVA 0x1010a0): captures bytes -> custom base64 output
- (*encoding).encodeTo (RVA 0x101340): lower-level encoding
- AesEncryptWithBase64 (RVA 0x103c00): AES encryption
- CustomDecryptParts (RVA 0x103880): custom decryption/decoding

RVA calculations (module base = 0x140000000):
  encodeRequestBody          = 0x881820
  shouldEncryptBody          = 0x882680
  encrypt.encodeToString     = 0x1010a0
  encrypt.encodeTo           = 0x101340
  encrypt.decodeQuantum      = 0x101840
  encrypt.decodeString       = 0x101b00
  encrypt.decode             = 0x102120
  encrypt.CustomDecryptParts = 0x103880
  encrypt.AesEncryptWithBase64 = 0x103c00
  encrypt.AesDecryptWithBase64 = 0x103da0
  encrypt.RsaEncrypt         = 0x103f80
"""

import argparse
import json
import pathlib
import sys
import time

import frida

JS_SOURCE = r"""
function readGoString(ptr, lenVal) {
    const p = new NativePointer(String(ptr));
    const len = typeof lenVal === 'number' ? lenVal : parseInt(String(lenVal), 16);
    if (p.isNull() || len === 0 || len > 0x200000) {
        return { ptr: p.toString(), len: len, text: "" };
    }
    try {
        const text = p.readUtf8String(len);
        return { ptr: p.toString(), len: len, text: text || "" };
    } catch (e) {
        return { ptr: p.toString(), len: len, text: "", error: String(e).substring(0, 100) };
    }
}

function readGoBytes(ptr, lenVal) {
    const p = new NativePointer(String(ptr));
    const len = typeof lenVal === 'number' ? lenVal : parseInt(String(lenVal), 16);
    if (p.isNull() || len === 0 || len > 0x200000) {
        return { ptr: p.toString(), len: len, hex: "", base64: "" };
    }
    try {
        const size = Math.min(len, 256);
        const buf = p.readByteArray(size);
        const arr = new Uint8Array(buf);
        let hex = "";
        for (let i = 0; i < arr.length; i++) hex += ("0" + arr[i].toString(16)).slice(-2);
        return { ptr: p.toString(), len: len, hex: hex, base64: btoa(String.fromCharCode.apply(null, arr)) };
    } catch (e) {
        return { ptr: p.toString(), len: len, hex: "", base64: "", error: String(e).substring(0, 100) };
    }
}

function hex(addr) { return "0x" + ptr(addr).toString(16); }

function installHooks() {
    const main = Process.enumerateModules()[0];
    const base = ptr(main.base);

    send({
        event: "module",
        name: main.name,
        base: main.base.toString(),
        size: main.size,
    });

    // Calculate RVAs
    const targets = {
        encodeRequestBody:       base.add(0x881820),
        shouldEncryptBody:       base.add(0x882680),
        encodeToString:          base.add(0x1010a0),
        encodeTo:                base.add(0x101340),
        decodeQuantum:           base.add(0x101840),
        decodeString:            base.add(0x101b00),
        decode:                  base.add(0x102120),
        CustomDecryptParts:      base.add(0x103880),
        AesEncryptWithBase64:    base.add(0x103c00),
        AesDecryptWithBase64:    base.add(0x103da0),
        RsaEncrypt:              base.add(0x103f80),
    };

    for (const [name, addr] of Object.entries(targets)) {
        send({ event: "hook", name: name, address: addr.toString() });
    }

    // === encodeRequestBody ===
    // Go 1.17+ uses registers: method(str ptr, str len), url(str ptr, str len), body(str ptr, str len)
    // Returns: (encodedBody str ptr, str len, err interface)
    Interceptor.attach(targets.encodeRequestBody, {
        onEnter(args) {
            this.method = readGoString(this.context.rcx, this.context.rdx);
            this.url = readGoString(this.context.r8, this.context.r9);
            // Body might be on stack for 3rd string arg
            // Go 1.17+ rsi/r8 for 5th/6th args, but we need 3rd string = 5th/6th params
            // Actually Go calling convention: first 6 args in RCX, RDX, R8, R9, [RSP+0x28], [RSP+0x30]
            // For (method_ptr, method_len, url_ptr, url_len, body_ptr, body_len):
            // RCX=method_ptr, RDX=method_len, R8=url_ptr, R9=url_len, [RSP+0x28]=body_ptr, [RSP+0x30]=body_len
            const bodyPtr = this.context.rsp.add(0x28).readPointer();
            const bodyLen = this.context.rsp.add(0x30).readUInt64();
            this.body = readGoString(bodyPtr, bodyLen);

            send({
                event: "encodeRequestBody.enter",
                method: this.method,
                url: this.url,
                body: this.body,
            });
        },
        onLeave(retval) {
            // Return: rax=string_ptr, rdx=string_len (Go returns in consecutive positions)
            // For string return: ptr in first return reg, len in second
            const retPtr = this.context.rax;
            const retLen = this.context.rdx;
            const retStr = readGoString(retPtr, retLen);

            send({
                event: "encodeRequestBody.leave",
                retval: String(retval),
                encoded: retStr,
            });
        },
    });

    // === shouldEncryptBody ===
    Interceptor.attach(targets.shouldEncryptBody, {
        onEnter(args) {
            // Likely: (method string, url string) -> bool
            this.method = readGoString(this.context.rcx, this.context.rdx);
            this.url = readGoString(this.context.r8, this.context.r9);
        },
        onLeave(retval) {
            send({
                event: "shouldEncryptBody",
                method: this.method.text,
                url: this.url.text.substring(0, 120),
                encrypt: retval.toString() !== "0x0" && retval.toString() !== "0x1" ? retval.toString() : (parseInt(String(retval), 16) !== 0 ? "true" : "false"),
            });
        },
    });

    // === (*encoding).encodeToString ===
    // This is a method on *encoding, so first arg is receiver (rcx)
    // Then the bytes to encode (rdx/rdi = ptr/len or stack)
    Interceptor.attach(targets.encodeToString, {
        onEnter(args) {
            this.recv = this.context.rcx;
            // Check if bytes are in rdx/rdi (Go 1.17+ register convention)
            this.dataPtr = this.context.rdx;
            this.dataLen = this.context.rdi;

            // Also read from stack as fallback
            const stackPtr = this.context.rsp.add(0x08).readPointer();
            const stackLen = this.context.rsp.add(0x10).readUInt64();

            this.inputReg = readGoBytes(this.dataPtr, this.dataLen);
            this.inputStack = readGoBytes(stackPtr, stackLen);

            send({
                event: "encodeToString.enter",
                receiver: hex(this.recv),
                inputReg: this.inputReg,
                inputStack: this.inputStack,
            });
        },
        onLeave(retval) {
            // Returns string (ptr in rax, len in rdx)
            const retPtr = this.context.rax;
            const retLen = this.context.rdx;
            const retStr = readGoString(retPtr, retLen);

            send({
                event: "encodeToString.leave",
                retval: String(retval),
                output: retStr,
            });
        },
    });

    // === (*encoding).encodeTo ===
    Interceptor.attach(targets.encodeTo, {
        onEnter(args) {
            this.recv = this.context.rcx;
            send({
                event: "encodeTo.enter",
                receiver: hex(this.recv),
            });
        },
        onLeave(retval) {
            send({
                event: "encodeTo.leave",
                retval: String(retval),
            });
        },
    });

    // === AesEncryptWithBase64 ===
    Interceptor.attach(targets.AesEncryptWithBase64, {
        onEnter(args) {
            this.dataPtr = this.context.rcx;
            this.dataLen = this.context.rdx;
            this.keyPtr = this.context.r8;
            this.keyLen = this.context.r9;
            this.input = readGoBytes(this.dataPtr, this.dataLen);
            send({
                event: "AesEncryptWithBase64.enter",
                input: this.input,
                keyPtr: hex(this.keyPtr),
                keyLen: String(this.keyLen),
            });
        },
        onLeave(retval) {
            const retPtr = this.context.rax;
            const retLen = this.context.rdx;
            const retStr = readGoString(retPtr, retLen);
            send({
                event: "AesEncryptWithBase64.leave",
                output: retStr,
            });
        },
    });

    // === CustomDecryptParts ===
    Interceptor.attach(targets.CustomDecryptParts, {
        onEnter(args) {
            send({
                event: "CustomDecryptParts.enter",
            });
        },
        onLeave(retval) {
            send({
                event: "CustomDecryptParts.leave",
            });
        },
    });

    send({ event: "hooks_installed", count: Object.keys(targets).length });
}

installHooks();
"""

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True, help="PID of Lingma.exe")
    parser.add_argument("--output", default="capture/frida-body-trace-ultimate.jsonl")
    parser.add_argument("--duration", type=float, default=180.0)
    args = parser.parse_args()

    output_path = pathlib.Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[*] Attaching to PID {args.pid}")
    print(f"[*] Logging to {output_path}")
    print(f"[*] Duration: {args.duration}s")
    print(f"[*] Trigger some requests in Lingma to capture body encoding!")

    session = frida.attach(args.pid)
    script = session.create_script(JS_SOURCE)

    event_count = 0

    def format_go_string(gs: dict) -> str:
        if gs.get("text"):
            return f"len={gs['len']} text={gs['text'][:200]}"
        if gs.get("error"):
            return f"len={gs.get('len', '?')} error={gs['error'][:80]}"
        return f"ptr={gs.get('ptr', '?')} len={gs.get('len', '?')}"

    def on_message(message, data):
        nonlocal event_count
        event_count += 1
        payload = message.get("payload", message)
        event = payload.get("event", message.get("type", "unknown"))

        row = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "seq": event_count,
            "message": payload,
        }
        with output_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            fh.flush()

        if event == "module":
            print(f"[*] Module: {payload['name']} base={payload['base']} size={payload['size']}")

        elif event == "hook":
            print(f"  hook: {payload['name']} @ {payload['address']}")

        elif event == "hooks_installed":
            print(f"[*] {payload['count']} hooks installed, waiting for events...")

        elif event == "encodeRequestBody.enter":
            body = payload.get("body", {})
            method = payload.get("method", {})
            url = payload.get("url", {})
            print(f"\n{'='*60}")
            print(f"[ENCODE BODY ENTER] method={method.get('text','?')} url={url.get('text','?')[:100]}")
            if body.get("text"):
                print(f"  Body: {body['text'][:500]}")
                print(f"  Body len: {body.get('len', '?')} chars")
                # Try to parse as JSON
                try:
                    data = json.loads(body["text"])
                    print(f"  Parsed JSON keys: {list(data.keys())[:10]}")
                except:
                    pass
            else:
                print(f"  Body: (empty) ptr={body.get('ptr','?')} len={body.get('len','?')}")

        elif event == "encodeRequestBody.leave":
            encoded = payload.get("encoded", {})
            print(f"[ENCODE BODY LEAVE]")
            if encoded.get("text"):
                print(f"  Encoded: {encoded['text'][:500]}")
                print(f"  Encoded len: {encoded.get('len', '?')} chars")
            else:
                print(f"  Encoded: (not found) ptr={encoded.get('ptr','?')} len={encoded.get('len','?')}")
                if encoded.get("error"):
                    print(f"    Error: {encoded['error']}")

        elif event == "encodeToString.enter":
            input_reg = payload.get("inputReg", {})
            input_stack = payload.get("inputStack", {})
            print(f"\n[ENCODE TOSTRING ENTER] recv={payload.get('receiver','?')}")
            if input_reg.get("hex"):
                print(f"  Input (reg): {input_reg['len']} bytes, hex={input_reg['hex'][:100]}")
            if input_stack.get("hex") and input_stack.get("len", 0) > 0:
                print(f"  Input (stack): {input_stack['len']} bytes, hex={input_stack['hex'][:100]}")

        elif event == "encodeToString.leave":
            output = payload.get("output", {})
            print(f"[ENCODE TOSTRING LEAVE]")
            if output.get("text"):
                print(f"  Output: {output['text'][:300]}")
                print(f"  Output len: {output.get('len', '?')} chars")

        elif event == "shouldEncryptBody":
            print(f"\n[SHOULD ENCRYPT] method={payload.get('method','?')} encrypt={payload.get('encrypt','?')}")
            print(f"  URL: {payload.get('url','')[:100]}")

        elif event == "AesEncryptWithBase64.enter":
            inp = payload.get("input", {})
            if inp.get("hex"):
                print(f"\n[AES ENCRYPT] input={inp['len']} bytes hex={inp['hex'][:80]}")

        elif event == "AesEncryptWithBase64.leave":
            out = payload.get("output", {})
            if out.get("text"):
                print(f"[AES ENCRYPT LEAVE] output={out['text'][:200]}")

    script.on("message", on_message)
    script.load()
    print("[*] Script loaded.")

    try:
        time.sleep(args.duration)
    finally:
        session.detach()

    print(f"\n[*] Done. {event_count} events logged.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
