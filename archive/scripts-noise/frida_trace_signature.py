import argparse
import json
import pathlib
import sys
import time

import frida


JS_SOURCE = r"""
function readGoString(ptrValue, lenValue) {
    try {
        const ptrText = String(ptrValue);
        const lenText = String(lenValue);
        const p = new NativePointer(ptrText);
        const length = parseInt(lenText, 16);
        if (p.isNull()) {
            return { ok: true, ptr: p.toString(), len: length, text: "" };
        }
        if (!Number.isFinite(length) || length < 0 || length > 0x20000) {
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

function u64(addr) {
    return new NativePointer(String(addr)).readPointer();
}

function installHooks() {
    const main = Process.enumerateModules()[0];
    const targets = {
        trimQueryPath: ptr(main.base).add(0x882c80),
        getAuthSignature: ptr(main.base).add(0x890140),
        getAuthPayload: ptr(main.base).add(0x890380),
    };

    send({
        event: "module",
        name: main.name,
        base: main.base.toString(),
        size: main.size,
        targets: Object.fromEntries(Object.entries(targets).map(([k, v]) => [k, v.toString()])),
    });

    Interceptor.attach(targets.trimQueryPath, {
        onEnter(args) {
            this.enterRsp = this.context.rsp;
            send({
                event: "trimQueryPath.enter",
                regs: {
                    rax_rbx: readGoString(this.context.rax, this.context.rbx),
                    rcx_rdi: readGoString(this.context.rcx, this.context.rdi),
                },
            });
        },
        onLeave(retval) {
            send({
                event: "trimQueryPath.leave",
                regs: {
                    rax_rbx: readGoString(this.context.rax, this.context.rbx),
                },
            });
        },
    });

    Interceptor.attach(targets.getAuthPayload, {
        onEnter(args) {
            send({
                event: "getAuthPayload.enter",
                regs: {
                    rax_rbx: readGoString(this.context.rax, this.context.rbx),
                    rcx_rdi: readGoString(this.context.rcx, this.context.rdi),
                },
            });
        },
        onLeave(retval) {
            send({
                event: "getAuthPayload.leave",
                regs: {
                    rax_rbx: readGoString(this.context.rax, this.context.rbx),
                },
            });
        },
    });

    Interceptor.attach(targets.getAuthSignature, {
        onEnter(args) {
            const rsp = this.context.rsp;
            send({
                event: "getAuthSignature.enter",
                regs: {
                    rax_rbx: readGoString(this.context.rax, this.context.rbx),
                    rcx_rdi: readGoString(this.context.rcx, this.context.rdi),
                    rsi_r8: readGoString(this.context.rsi, this.context.r8),
                    r9_r10: readGoString(this.context.r9, this.context.r10),
                    stack_08_10: readGoString(u64(rsp.add(0x08)), u64(rsp.add(0x10))),
                    stack_18_20: readGoString(u64(rsp.add(0x18)), u64(rsp.add(0x20))),
                },
            });
        },
        onLeave(retval) {
            send({
                event: "getAuthSignature.leave",
                regs: {
                    rax_rbx: readGoString(this.context.rax, this.context.rbx),
                },
            });
        },
    });
}

installHooks();
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--output", default="capture/frida-signature-trace.jsonl")
    parser.add_argument("--duration", type=float, default=90.0)
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
            if message.get("type") == "send":
                payload = message.get("payload", {})
                print(json.dumps(payload, ensure_ascii=False))
            else:
                print(json.dumps(message, ensure_ascii=False), file=sys.stderr)

        script.on("message", on_message)
        script.load()
        try:
            time.sleep(args.duration)
        finally:
            session.detach()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
