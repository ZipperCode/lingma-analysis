import argparse
import json
import pathlib
import sys
import time

import frida


JS_SOURCE = r"""
function asPtr(value) {
    return new NativePointer(String(value));
}

function bytesToBase64(u8) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let out = "";
    for (let i = 0; i < u8.length; i += 3) {
        const a = u8[i];
        const b = i + 1 < u8.length ? u8[i + 1] : 0;
        const c = i + 2 < u8.length ? u8[i + 2] : 0;
        const triple = (a << 16) | (b << 8) | c;
        out += alphabet[(triple >> 18) & 0x3f];
        out += alphabet[(triple >> 12) & 0x3f];
        out += i + 1 < u8.length ? alphabet[(triple >> 6) & 0x3f] : "=";
        out += i + 2 < u8.length ? alphabet[triple & 0x3f] : "=";
    }
    return out;
}

function readUtf8(ptrValue, lenValue) {
    try {
        const p = asPtr(ptrValue);
        const length = parseInt(String(lenValue), 16);
        if (p.isNull()) {
            return { ok: true, ptr: p.toString(), len: length, text: "" };
        }
        if (!Number.isFinite(length) || length < 0 || length > 0x40000) {
            return { ok: false, ptr: p.toString(), len: length, error: "invalid-length" };
        }
        return {
            ok: true,
            ptr: p.toString(),
            len: length,
            text: p.readUtf8String(length),
        };
    } catch (e) {
        return { ok: false, error: String(e) };
    }
}

function readBytes(ptrValue, lenValue) {
    try {
        const p = asPtr(ptrValue);
        const length = parseInt(String(lenValue), 16);
        if (p.isNull()) {
            return { ok: true, ptr: p.toString(), len: length, utf8: "", hexPreview: "", base64Preview: "" };
        }
        if (!Number.isFinite(length) || length < 0 || length > 0x40000) {
            return { ok: false, ptr: p.toString(), len: length, error: "invalid-length" };
        }
        const size = Math.min(length, 512);
        const bytes = p.readByteArray(size);
        const u8 = new Uint8Array(bytes);
        let hex = "";
        for (let i = 0; i < u8.length; i++) {
            hex += ("0" + u8[i].toString(16)).slice(-2);
        }
        let text = "";
        try {
            text = p.readUtf8String(size);
        } catch (e) {
            text = "";
        }
        return {
            ok: true,
            ptr: p.toString(),
            len: length,
            utf8: text,
            hexPreview: hex,
            base64Preview: bytesToBase64(u8),
        };
    } catch (e) {
        return { ok: false, error: String(e) };
    }
}

function u64(addr) {
    return asPtr(addr).readPointer();
}

function pairDump(ptrReg, lenReg) {
    return {
        rawPtr: String(ptrReg),
        rawLen: String(lenReg),
        string: readUtf8(ptrReg, lenReg),
        bytes: readBytes(ptrReg, lenReg),
    };
}

function captureRegs(context, includeStack) {
    const regs = {
        raw: {
            rax: String(context.rax),
            rbx: String(context.rbx),
            rcx: String(context.rcx),
            rdi: String(context.rdi),
            rsi: String(context.rsi),
            r8: String(context.r8),
            r9: String(context.r9),
            r10: String(context.r10),
            rsp: String(context.rsp),
        },
        rax_rbx: pairDump(context.rax, context.rbx),
        rcx_rdi: pairDump(context.rcx, context.rdi),
        rsi_r8: pairDump(context.rsi, context.r8),
        r9_r10: pairDump(context.r9, context.r10),
    };

    if (includeStack) {
        const rsp = context.rsp;
        regs.stack_08_10 = pairDump(u64(rsp.add(0x08)), u64(rsp.add(0x10)));
        regs.stack_18_20 = pairDump(u64(rsp.add(0x18)), u64(rsp.add(0x20)));
    }

    return regs;
}

function installHooks() {
    const main = Process.enumerateModules()[0];
    const targets = {
        encodeRequestBody: ptr(main.base).add(0x881820),
        shouldEncryptBody: ptr(main.base).add(0x882680),
    };

    send({
        event: "module",
        name: main.name,
        base: main.base.toString(),
        size: main.size,
        targets: Object.fromEntries(Object.entries(targets).map(([k, v]) => [k, v.toString()])),
    });

    Interceptor.attach(targets.encodeRequestBody, {
        onEnter(args) {
            send({
                event: "encodeRequestBody.enter",
                regs: captureRegs(this.context, true),
            });
        },
        onLeave(retval) {
            send({
                event: "encodeRequestBody.leave",
                retval: String(retval),
                regs: captureRegs(this.context, false),
            });
        },
    });

    Interceptor.attach(targets.shouldEncryptBody, {
        onEnter(args) {
            send({
                event: "shouldEncryptBody.enter",
                regs: captureRegs(this.context, true),
            });
        },
        onLeave(retval) {
            send({
                event: "shouldEncryptBody.leave",
                retval: String(retval),
                regs: captureRegs(this.context, false),
            });
        },
    });
}

installHooks();
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--output", default="capture/frida-body-trace.jsonl")
    parser.add_argument("--duration", type=float, default=60.0)
    args = parser.parse_args()

    output_path = pathlib.Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    session = frida.attach(args.pid)
    script = session.create_script(JS_SOURCE)

    with output_path.open("a", encoding="utf-8") as fh:
        def on_message(message, data):
            row = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "message": message,
            }
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            fh.flush()
            stream = sys.stderr if message.get("type") != "send" else sys.stdout
            print(json.dumps(message.get("payload", message), ensure_ascii=False), file=stream)

        script.on("message", on_message)
        script.load()
        try:
            time.sleep(args.duration)
        finally:
            session.detach()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
