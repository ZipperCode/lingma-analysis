/**
 * md5encode_dump.js
 *
 * Frida 脚本：Hook Lingma 二进制中的
 *   code.alibaba-inc.com/cosy/encrypt.Md5Encode
 *
 * 用法（spawn 模式，推荐）：
 *   frida -f path\to\lingma.exe -l tools\md5encode_dump.js \
 *         -o tools\md5encode_dump.log
 *
 * 说明：
 * - Go 1.17+ 内部 ABI（x86_64）使用寄存器传参：整数参数顺序为
 *   AX, BX, CX, DI, SI, R8, R9, R10, R11。
 * - string 拆成 (ptr, len)。
 * - 本脚本在 onEnter 同时打印多个候选寄存器的字符串内容（不依赖固定 ABI），
 *   在 onLeave 打印 MD5 结果。
 */

const RVA = "0x882760"; // 默认 RVA，请用 GoReSym 重新确认后修改

function resolveRva() {
    return parseInt(RVA, 16);
}

function readGoString(ptr, len) {
    if (ptr.isNull() || len === 0 || len > 4096) {
        return { hex: "", utf8: "" };
    }
    try {
        const bytes = Memory.readByteArray(ptr, len);
        const hex = hexdump(bytes, { offset: 0, length: Math.min(len, 128), header: false });
        const utf8 = Memory.readUtf8String(ptr, Math.min(len, 256));
        return { hex, utf8 };
    } catch (e) {
        return { hex: "[read error]", utf8: "[read error]" };
    }
}

function tryRegAsString(ctx, regName, maxLen) {
    const ptr = ctx[regName];
    if (!ptr || ptr.isNull()) return null;
    return readGoString(ptr, maxLen);
}

function attachAtRva(rvaHex) {
    const mod = Process.enumerateModules()[0];
    const target = mod.base.add(parseInt(rvaHex, 16));
    console.log("[*] Attaching to " + mod.name + " @ " + target);

    Interceptor.attach(target, {
        onEnter: function (args) {
            this.tag = "[Md5Encode] " + Date.now();
            console.log("\n" + this.tag + " INPUT ==============================");

            // Go 内部 ABI 候选寄存器（ptr, len 可能分布其中）
            const ctx = this.context;
            const candidates = [
                { name: "rax", len: 256 },
                { name: "rbx", len: 64 },
                { name: "rcx", len: 256 },
                { name: "rdx", len: 64 },
                { name: "r8",  len: 256 },
                { name: "r9",  len: 64 }
            ];

            for (const c of candidates) {
                const s = tryRegAsString(ctx, c.name, c.len);
                if (s && s.utf8.length > 0) {
                    console.log("  [" + c.name + "] utf8: " + s.utf8);
                }
            }
        },
        onLeave: function (retval) {
            const ctx = this.context;
            const outPtr = retval;
            // 尝试读取 32 字节作为 MD5 hex
            const out = readGoString(outPtr, 32);
            console.log(this.tag + " OUTPUT =============================");
            console.log("  md5(rax): " + out.utf8);
            // 若 Go 返回 string 时 len 在 rbx，也可尝试从 rbx 读取
            const altPtr = ctx.rbx;
            if (altPtr && !altPtr.equals(outPtr)) {
                const alt = readGoString(altPtr, 32);
                if (alt.utf8.length === 32) {
                    console.log("  md5(rbx): " + alt.utf8);
                }
            }
        }
    });
}

rpc.exports = {
    setRva: attachAtRva
};

// 自动 attach（如果 RVA 已知）
const mod = Process.enumerateModules()[0];
if (mod) {
    const rva = resolveRva();
    attachAtRva("0x" + rva.toString(16));
}
