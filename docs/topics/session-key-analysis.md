# Lingma session_key 解析过程

> 日期：2026-04-27
> 目标：找到 old Signature 链路所需的 `session_key`，使 `DeriveCredentialsRemotely` 在无本地 Lingma 的情况下也能成功登录。

## 结论（已确认）

**session_key = `d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw==`**（base64 字面量，32 字符，解码后为 "war, war never changes"）

**公式**：`MD5("cosy&" + key + "&" + RFC1123_Date)`

**验证**：对 3 个已知 oracle 中的 RFC1123 样本命中（1/3）；另外 2 个 Unix 时间戳 oracle 可能来自不同流程（COSY）或版本。代码已回填至 `internal/auth/remote_login.go`。

**发现路径**：B1 静态代码结构还原成功，通过 capstone 反汇编 `addBigModelSignatureHeaders` @ RVA 0x882760，追踪 LEA 指令加载的字符串地址，定位到 `.rdata` 中的 key 表。

---

## 1. 技术背景

### 1.1 两条独立链路

Lingma 的 HTTP 端点存在两套认证：

1. **Bearer COSY**（已解析）：`Authorization: Bearer COSY <cosy_key>`，由本地 Lingma 进程与服务器协商生成。
2. **old Signature**（已解析）：`Signature: <md5_hex>`，用于 `POST /algo/api/v3/user/login` 等早期端点。

`DeriveCredentialsRemotely` 走的是 old Signature 链路：在请求头中附加 `Date` + `Signature`，服务器验证通过后才返回 `cosy_key` 和 `encrypt_user_info`。

### 1.2 已知事实

| 事实 | 出处 |
|---|---|
| `addBigModelSignatureHeaders` @ RVA `0x882760` 调用 `code.alibaba-inc.com/cosy/encrypt.Md5Encode` | `getappsalt_analysis_v2.md` |
| Signature 计算不含 body（同秒不同端点 Signature 相同） | `docs/lingma-analysis-endpoint-auth.md` |
| Bearer COSY 与 old Signature 彼此独立 | 同上 |

### 1.3 Oracle（已知明文 ↔ MD5 对）

```
Date: Fri, 24 Apr 2026 07:54:36 GMT  ↔  Signature: e8b434d0a2596ca2ff99c60c4756a1ff  ← 已命中！
Unix: 1777011796                      ↔  Signature: 8d915d7d99452c143dc52ce040b9a355  ← 未命中（可能来自 COSY 流程）
Unix: 1777016140                      ↔  Signature: 0f6648253e94ed37c37f33bd3851c25c  ← 未命中（可能来自 COSY 流程）
```

---

## 2. 解析过程

### 2.1 B3: Frida hook（失败 → 获得关键线索）

**尝试**：动态拦截 `Md5Encode` 函数入口（RVA 0x456320）以捕获明文输入。

**结果**：
- `Md5Encode` hook **从未触发** → 确认该函数在所有调用点被**内联（inlined）**
- 全 `.text` 段搜索：**0 条直接 CALL 指令**指向 Md5Encode
- `addBigModelSignatureHeaders` 的钩子**仅触发 4 次测试调用**（date="signtestJuneJ"），输出均为空
- v2.11.1 在 COSY 可用时**不走 old Signature 生产流程** → old flow 实为死代码

**关键线索**：
- Frida 捕获的寄存器值：`RDI = 0x7ff750bf56e3` → RVA `0x24A56E3`（`.rdata` 中的字符串表）
- `RSI = 0x7ff750bdf21e` → RVA `0x248F21E` → 字符串 "signtestJuneJ"（测试日期）
- 从寄存器分析确认了 Go 1.17+ ABI 的 string 传递方式：`{ptr, len}` 对

### 2.2 B2: 字典攻击（失败 → 缩小搜索范围）

**尝试**：枚举已知候选 key × 公式族 × 3 个 oracle，自动化查找匹配。

**结果**：
- 2,984,517 组合测试（331,613 个 `.rdata` 唯一字符串 × 多种公式）→ **0 命中**
- 所有已知静态候选（`&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe`、base64 解码、hex 尾部等）+ 所有变体公式 → **0 命中**
- 结论：key 不是简单的 ASCII 字符串拼接，公式必须包含非直观的部分（如额外的分隔符 `&`）

### 2.3 B1: 静态代码结构还原（成功！）

**工具**：Python capstone + pefile，反汇编 `addBigModelSignatureHeaders` @ RVA `0x882760`。

**关键发现**：

#### 2.3.1 LEA 指令追踪

函数内多处 `LEA` 指令加载字符串地址。计算 RIP-relative 目标：

| 指令地址 | 目标 RVA | 字符串内容 |
|---|---|---|
| `0x8827DA` | `0x24E0C9D` | Go 时间格式字符串 `Mon, 02 Jan 2006 15:04:05 GMT...` |
| `0x882844` | `0x248EEDE` | 类型元数据 `DateMathListint8uint...` |
| `0x88291A` | `0x248EEDE` | 同上 |
| `0x882978` | **`0x24EE3CD`** | **`d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw==`** ← **KEY (选项 A)** |
| `0x88297F` | **`0x24EE3AD`** | **`&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe`** ← **KEY (选项 B)** |

#### 2.3.2 三字符串连续表

RVA `0x24EE3AD` 起，三个 32 字符的字符串在 `.rdata` 中**连续排列**（无分隔符）：

```
偏移         内容
0x24EE3AD    &Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe    (选项 B: prefix key)
0x24EE3CD    d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw==    (选项 A: base64 key)
0x24EE3ED    9f1dff714a390b20aeb19175ecc496e6    (hex 校验和？)
```

#### 2.3.3 条件选择逻辑

```asm
0x0088290E: movzx    esi, byte ptr [rip + 0x58b8f5a]  ; 加载 flag 字节
0x00882915: mov      qword ptr [rsp + 0x40], rsi
...
0x00882970: mov      rdx, [rsp + 0x40]                 ; rdx = flag
0x00882975: test     rdx, rdx                           ; test rdx
0x00882978: lea      rdx, [rip + 0x1c6ba4e]            ; rdx = option A (base64)
0x0088297F: lea      rsi, [rip + 0x1c6ba27]            ; rsi = option B (&Q3C3...)
0x00882986: cmovne   rdx, rsi                           ; if flag != 0: rdx = option B
```

Flag 字节在文件中的值为 `0x01`（非零），运行时默认选择 **选项 B**（`&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe`）。但 oracle 匹配的是**选项 A**（base64 key），说明 oracle 来自 flag=0 的场景（或不同版本）。

#### 2.3.4 Md5Encode 调用

```asm
0x008829A2: lea      rax, [rsp + 0xb8]    ; rax = 3 元素 string 数组
0x008829AA: mov      ebx, 3                ; count = 3
0x008829AF: mov      rcx, rbx              ; rcx = 3
0x008829B2: call     0x4563c0              ; 调用 string-join+MD5 函数
```

数组内容：`[s0="cosy"(len=4), s1=key(len=32), s2=date(len=var)]`

#### 2.3.5 拼接符确认

函数 `0x4563C0` 是专用的 "& 拼接 + MD5" 包装函数（与 COSY 内联的 "\n 拼接" 版本不同）。通过 oracle 反推确认拼接符为 `&`：

- `MD5("cosy&d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw==&Fri, 24 Apr 2026 07:54:36 GMT")`
- = `e8b434d0a2596ca2ff99c60c4756a1ff` ✓ **MATCH**

### 2.4 最终公式

```
Signature = MD5("cosy&" + key + "&" + RFC1123_Date)
```

其中：
- `key` = `d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw==`（32 字符 base64 字面量）
- `RFC1123_Date` = Go `time.RFC1123` 格式，如 `Fri, 24 Apr 2026 07:54:36 GMT`
- 备选 key = `&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe`（当 `.data` 中 flag 字节非零时）

---

## 3. 代码集成

已回填至 `lingma2api/internal/auth/remote_login.go`：

- 新增常量 `OldSignatureKey` = `"d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="`
- 新增常量 `OldSignatureKeyAlt` = `"&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe"`
- `buildSignatureStrategies()` 更新为正确的公式：`MD5("cosy&" + key + "&" + rfc1123)`
- 当用户未提供 `--session-key` 时，自动尝试两个默认 key

---

## 4. 未解决：Unix 时间戳 Oracle

两个 Unix 时间戳 oracle 仍未命中：

| Unix TS | Expected MD5 | 状态 |
|---|---|---|
| `1777011796` | `8d915d7d99452c143dc52ce040b9a355` | 未命中 |
| `1777016140` | `0f6648253e94ed37c37f33bd3851c25c` | 未命中 |

可能原因：
1. 这些 oracle 来自 COSY 流程（使用 "\n" 拼接，5 参数），而非 old Signature 流程
2. 使用了不同版本的 key 或公式
3. Date header 格式不是 RFC1123

对实际功能无影响：`POST /algo/api/v3/user/login` 使用 RFC1123 格式的 Date header，已覆盖。

---

## 5. 参考文件

- `lingma2api/internal/auth/remote_login.go` — `buildSignatureStrategies` 回填目标
- `D:/Project/lingma/tools/frida_sig_v2.py` — COSY + old sig Frida hook 脚本
- `D:/Project/lingma/tools/frida_md5encode_hook.py` — Md5Encode hook 尝试（确认内联）
- `D:/Project/lingma/tools/constraint_oracle_attack.py` — B2 字典攻击（失败记录）
- `D:/Project/lingma/docs/lingma-analysis-endpoint-auth.md` — Signature 链路原始分析
- `D:/Project/lingma/docs/superpowers/specs/2026-04-27-client-id-and-session-key-analysis.md` — 综合方案文档
