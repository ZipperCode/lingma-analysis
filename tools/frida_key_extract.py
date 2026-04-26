"""
Frida 脚本：自动从 Lingma 进程中提取 AES session key。

工作原理：
  Hook AesEncryptWithBase64 / AesDecryptWithBase64，
  在首次调用时捕获 16-byte AES key 并保存到文件。

使用方式：
  python tools/frida_key_extract.py                     # 自动附加
  python tools/frida_key_extract.py --pid 12345         # 指定 PID
  python tools/frida_key_extract.py --output key.json   # 自定义输出

输出文件 (aes_key.json):
  {"aes_key": "QbgzpWzN7tfe43gf", "aes_key_hex": "5162677a...", "timestamp": "..."}
"""

import argparse
import json
import pathlib
import sys
import time

try:
    import frida
except ImportError:
    print("请安装 frida: pip install frida frida-tools")
    sys.exit(1)

JS = r"""
const mod = Process.enumerateModules()[0];
const base = ptr(mod.base);

function goStr(p, n) {
    if (p.isNull() || n <= 0 || n > 0x400000) return "";
    try { return p.readUtf8String(Math.min(n, 512)); }
    catch(e) { return ""; }
}

function toHex(bytes) {
    if (!bytes) return "";
    var a = new Uint8Array(bytes);
    var h = "";
    for (var i = 0; i < a.length; i++) h += ("0" + a[i].toString(16)).slice(-2);
    return h;
}

var keyCaptured = false;
var capturedKey = null;
var capturedKeyHex = null;

/* AesEncryptWithBase64: RVA 0x455da0
   Go 1.22 ABI: rax=key_slice, rbx=data_slice, rcx=enc_ptr, rdi=?
   key slice header: [ptr, len, cap] at stack or in registers
   The key is a Go slice passed by value through registers:
     rax = key.ptr (pointer to key bytes)
     rbx = key.len (16)
     rcx = enc pointer
*/
Interceptor.attach(base.add(0x455da0), {
    onEnter(args) {
        if (keyCaptured) return;
        try {
            // rax = key slice ptr (Go passes []byte as {ptr, len, cap})
            // First try: rax is the key data pointer
            var keyPtr = this.context.rax;
            var keyLen = 16;  // AES-128 key is 16 bytes

            if (!keyPtr.isNull()) {
                // Read 16 bytes at the pointer
                var keyBytes = keyPtr.readByteArray(keyLen);
                var keyStr = "";
                try { keyStr = keyPtr.readUtf8String(keyLen); } catch(e) {}
                var keyHex = toHex(keyBytes);

                // Verify: all printable ASCII and exactly 16 chars
                var allPrintable = true;
                for (var i = 0; i < keyLen; i++) {
                    var b = keyPtr.add(i).readU8();
                    if (b < 32 || b > 126) { allPrintable = false; break; }
                }

                if (allPrintable && keyLen === 16) {
                    capturedKey = keyStr;
                    capturedKeyHex = keyHex;
                    keyCaptured = true;
                    send({
                        event: "AES_KEY_CAPTURED",
                        key: capturedKey,
                        key_hex: capturedKeyHex,
                        source: "AesEncryptWithBase64"
                    });
                }
            }
        } catch(e) {
            send({event: "ERROR", msg: e.message});
        }
    }
});

// Also hook AesDecryptWithBase64 for earlier capture
Interceptor.attach(base.add(0x455f40), {
    onEnter(args) {
        if (keyCaptured) return;
        try {
            var keyPtr = this.context.rax;
            var keyLen = 16;
            if (!keyPtr.isNull()) {
                var allPrintable = true;
                for (var i = 0; i < keyLen; i++) {
                    var b = keyPtr.add(i).readU8();
                    if (b < 32 || b > 126) { allPrintable = false; break; }
                }
                if (allPrintable) {
                    capturedKey = keyPtr.readUtf8String(keyLen);
                    capturedKeyHex = toHex(keyPtr.readByteArray(keyLen));
                    keyCaptured = true;
                    send({
                        event: "AES_KEY_CAPTURED",
                        key: capturedKey,
                        key_hex: capturedKeyHex,
                        source: "AesDecryptWithBase64"
                    });
                }
            }
        } catch(e) {
            send({event: "ERROR", msg: e.message});
        }
    }
});

send({event: "READY", base: base.toString()});
"""


def main():
    ap = argparse.ArgumentParser(description="Lingma AES Key Extractor")
    ap.add_argument("--pid", type=int, help="Lingma process PID")
    ap.add_argument("--output", default="capture/aes_key.json", help="输出文件路径")
    ap.add_argument("--timeout", type=int, default=60, help="等待超时(秒)")
    args = ap.parse_args()

    out_path = pathlib.Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # 附加到 Lingma 进程
    if args.pid:
        try:
            session = frida.attach(args.pid)
        except frida.ProcessNotFoundError:
            print(f"[-] PID {args.pid} 未找到")
            sys.exit(1)
    else:
        try:
            session = frida.attach("Lingma.exe")
            print(f"[+] 已附加到 Lingma.exe (PID: {session.pid})")
        except frida.ProcessNotFoundError:
            # 尝试列出所有 Lingma 相关进程
            print("[-] Lingma.exe 未运行。正在搜索类似进程...")
            for p in frida.enumerate_processes():
                if 'lingma' in p.name.lower():
                    print(f"  发现: {p.name} (PID: {p.pid})")
            print("\n请先启动 Lingma (通过 IDE 打开项目触发)，然后重试。")
            print("或使用: python tools/frida_key_extract.py --pid <PID>")
            sys.exit(1)

    script = session.create_script(JS)

    result = {"status": "waiting"}
    deadline = time.time() + args.timeout

    def on_msg(msg, data):
        p = msg.get("payload", msg)
        event = p.get("event", "")

        if event == "READY":
            print(f"[*] Hooks 已安装 (base={p.get('base', '?')})")
            print("[*] 请在 IDE 中触发一次聊天（或等待自动触发）...")
        elif event == "AES_KEY_CAPTURED":
            result["status"] = "captured"
            result["aes_key"] = p["key"]
            result["aes_key_hex"] = p["key_hex"]
            result["source"] = p.get("source", "?")
            result["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
            print(f"\n{'='*60}")
            print(f"[+] AES Key 已捕获!")
            print(f"    Key:      {p['key']}")
            print(f"    Hex:      {p['key_hex']}")
            print(f"    Source:   {p.get('source', '?')}")
            print(f"{'='*60}\n")
            # 保存到文件
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            print(f"[+] 已保存到: {out_path}")
        elif event == "ERROR":
            print(f"[-] Error: {p.get('msg', '?')}")

    script.on("message", on_msg)
    script.load()

    # 等待捕获
    print(f"[*] 等待 AES 密钥出现 (超时: {args.timeout}s)...")
    while time.time() < deadline and result["status"] == "waiting":
        time.sleep(0.5)

    if result["status"] == "waiting":
        print("[-] 超时：未捕获到 AES 密钥。")
        print("    可能原因：")
        print("    1. Lingma 已完全启动但未触发加密请求")
        print("    2. 尝试在 IDE 中发送一条聊天消息触发加密")
        print("    3. 增长 --timeout 参数")
    else:
        print(f"[+] 完成！密钥已保存，可用于 lingma_remote_api.py")

    session.detach()


if __name__ == "__main__":
    main()
