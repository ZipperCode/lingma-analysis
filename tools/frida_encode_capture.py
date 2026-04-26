"""
Frida script for capturing encodeRequestBody and shouldEncryptBody in Lingma.exe.
Targets version 2.11.1 (RVAs from GoReSym analysis).

Usage:
    1. Start Lingma via JetBrains IDE
    2. Find PID: tasklist | findstr Lingma
    3. Run: python tools/frida_encode_capture.py --pid <PID>
    4. Trigger a chat request in the IDE
"""
import argparse
import json
import pathlib
import sys
import time
import frida

JS = r"""
const mod = Process.enumerateModules()[0];
const base = ptr(mod.base);
send({event:"info", module:mod.name, base:mod.base.toString(), size:mod.size});

function goStr(p, n) {
    if (p.isNull() || n <= 0 || n > 0x400000) return {ptr:p.toString(),len:n,text:""};
    try { return {ptr:p.toString(),len:n,text:p.readUtf8String(Math.min(n,2000))}; }
    catch(e) { return {ptr:p.toString(),len:n,text:"",err:e.message.substring(0,60)}; }
}
function goBytes(p, n) {
    if (p.isNull() || n <= 0 || n > 0x400000) return {ptr:p.toString(),len:n,hex:""};
    try {
        var sz = Math.min(n, 512);
        var b = p.readByteArray(sz);
        var a = new Uint8Array(b);
        var h = ""; for(var i=0;i<a.length;i++) h+=("0"+a[i].toString(16)).slice(-2);
        return {ptr:p.toString(),len:n,hex:h};
    } catch(e) { return {ptr:p.toString(),len:n,hex:"",err:e.message.substring(0,60)}; }
}

// encodeRequestBody: RVA 0x881820
// Go 1.22 register ABI: rax, rbx, rcx, rdi, rsi, r8, r9, ...
Interceptor.attach(base.add(0x881820), {
    onEnter(args) {
        // From disasm: rax=type_ptr, rbx=data_ptr of interface
        this.typePtr = this.context.rax;
        this.dataPtr = this.context.rbx;
        // Method string at rcx/rdi, URL at rsi/r8 (from buildRequest context)
        send({
            event: "encodeRequestBody_enter",
            rax: this.context.rax.toString(),
            rbx: this.context.rbx.toString(),
            rcx: this.context.rcx.toString(),
        });
    },
    onLeave(retval) {
        // Returns: rax=encoded_ptr/data, rbx=encoded_len, rcx=cap
        // rdi=error_type, rsi=error_data
        var rax = this.context.rax;
        var rbx = this.context.rbx;
        var rcx = this.context.rcx;
        var rdi = this.context.rdi;
        var rsi = this.context.rsi;
        var hasErr = !rdi.isNull();
        if (!hasErr && !rax.isNull() && rbx.toInt32() > 0) {
            var result = goStr(rax, rbx.toInt32());
            send({
                event: "encodeRequestBody_leave",
                result_len: rbx.toInt32(),
                result_preview: result.text ? result.text.substring(0, 500) : "",
                has_dollar: result.text ? result.text.indexOf("$") >= 0 : false,
                dollar_count: result.text ? (result.text.match(/\$/g)||[]).length : 0,
            });
        } else {
            send({
                event: "encodeRequestBody_leave",
                result_len: rbx.toInt32(),
                error: hasErr,
                rax: rax.toString(),
            });
        }
    }
});

// shouldEncryptBody: RVA 0x882680
Interceptor.attach(base.add(0x882680), {
    onEnter(args) {
        // rax=method_ptr, rbx=method_len, rcx=url_ptr, rdi=url_len
        this.method = goStr(this.context.rax, this.context.rbx.toInt32());
        this.url = goStr(this.context.rcx, this.context.rdi.toInt32());
    },
    onLeave(retval) {
        send({
            event: "shouldEncryptBody",
            method: this.method.text,
            url: this.url.text ? this.url.text.substring(0, 120) : "",
            result: this.context.rax.toInt32() !== 0,
        });
    }
});

// (*encoding).encodeToString: RVA 0x4549e0
Interceptor.attach(base.add(0x4549e0), {
    onEnter(args) {
        // receiver in rax, src bytes in rbx(ptr)/rcx(len)/rdi(cap)
        this.srcLen = this.context.rcx.toInt32();
        this.srcPreview = goBytes(this.context.rbx, this.context.rcx.toInt32());
        send({
            event: "encodeToString_enter",
            src_len: this.srcLen,
            src_hex_preview: this.srcPreview.hex.substring(0, 200),
        });
    },
    onLeave(retval) {
        var outLen = this.context.rbx.toInt32();
        var outStr = goStr(this.context.rax, outLen);
        send({
            event: "encodeToString_leave",
            out_len: outLen,
            out_preview: outStr.text ? outStr.text.substring(0, 300) : "",
            has_dollar: outStr.text ? outStr.text.indexOf("$") >= 0 : false,
        });
    }
});

send({event:"hooks_installed", count:3});
"""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--output", default="capture/frida-encode-trace.jsonl")
    ap.add_argument("--duration", type=float, default=120)
    args = ap.parse_args()

    out = pathlib.Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)

    print(f"[*] Attaching to PID {args.pid}")
    session = frida.attach(args.pid)
    script = session.create_script(JS)

    seq = [0]

    def on_msg(msg, data):
        seq[0] += 1
        p = msg.get("payload", msg)
        ev = p.get("event", "?")
        row = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "seq": seq[0], "msg": p}
        with out.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

        if ev == "info":
            print(f"[*] Module: {p['module']} base={p['base']}")
        elif ev == "hooks_installed":
            print(f"[*] {p['count']} hooks installed. Trigger a request!")
        elif ev == "encodeRequestBody_enter":
            print(f"\n[ENCODE ENTER]")
        elif ev == "encodeRequestBody_leave":
            rl = p.get("result_len", 0)
            dc = p.get("dollar_count", 0)
            preview = p.get("result_preview", "")[:100]
            print(f"[ENCODE LEAVE] len={rl} dollar={dc} preview={preview}")
        elif ev == "shouldEncryptBody":
            print(f"[SHOULD_ENCRYPT] {p.get('method','')} result={p.get('result','')} url={p.get('url','')[:80]}")
        elif ev == "encodeToString_enter":
            print(f"[ENCODE_TOSTRING ENTER] src_len={p.get('src_len',0)}")
        elif ev == "encodeToString_leave":
            print(f"[ENCODE_TOSTRING LEAVE] out_len={p.get('out_len',0)} has_dollar={p.get('has_dollar','')}")

    script.on("message", on_msg)
    script.load()
    print(f"[*] Logging to {out}. Duration: {args.duration}s")

    try:
        time.sleep(args.duration)
    finally:
        session.detach()
    print(f"\n[*] Done. {seq[0]} events.")

if __name__ == "__main__":
    sys.exit(main())
