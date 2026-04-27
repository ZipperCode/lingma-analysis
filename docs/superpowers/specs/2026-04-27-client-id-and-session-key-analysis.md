# Lingma client_id 与 session_key 分析

更新时间: `2026-04-27`

## 背景

`lingma2api` 纯远程 bootstrap 需要两个密钥：
1. **OAuth client_id** — 用于构造 Alibaba OAuth authorize URL
2. **old Signature session_key** — 用于 `POST /algo/api/v3/user/login` 的 Signature 头

本文档记录分析过程、发现和当前阻塞点。

## 1. OAuth client_id

### 核心结论

**client_id ≠ machine_id**。实测将真实 machine_id (`43303747-3630-492d-8151-366d4e59432d`) 用作 OAuth client_id：
```
GET https://signin.alibabacloud.com/oauth2/v1/auth?client_id=43303747-...
Response: {"error":"invalid_client","error_description":"App not exists:..."}
```

client_id 是 **Lingma 应用的共享 OAuth App ID**（所有 Lingma 用户共用），由 Alibaba Cloud OAuth 平台预注册。它在 OAuth 重定向链中暴露，但仅在浏览器完成 Alibaba 登录后才可见。

### 重定向链

```
lingma.alibabacloud.com/lingma/login (Lingma 服务器)
  → 302 account.alibabacloud.com/login/login.htm?oauth_callback=... (Alibaba 登录页)
  → 用户浏览器登录
  → signin.alibabacloud.com/oauth2/v1/auth?client_id=<REAL_ID>&... (OAuth authorize)
```

client_id 在第 3 步的 URL 参数中。**无法在无浏览器交互的情况下获取**。

### 提取方法

唯一可行路径：在浏览器中完成一次 Alibaba Cloud 登录，从地址栏的 OAuth authorize URL 中复制 `client_id` 参数值。

替代方案：如果已有完成登录后的 callback HTML 页面，使用 `callback_html.go` 中的 `extractMachineIDFromURL()` 从 `window.login_url` 提取重定向链中的参数。

## 2. old Signature session_key

### 核心结论

**session_key 公式未破解**。进行了以下尝试：

#### 二进制字符串提取

从 macOS aarch64 Lingma 2.11.1 二进制中提取到候选常量：
```
&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTed2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw==9f1dff714a390b20aeb19175ecc496e6
```
解析：
- 前缀 31 字节: `&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe`
- Base64 32 字节: `d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw==` → `"war, war never changes"` (哨兵)
- Hex 32 字节: `9f1dff714a390b20aeb19175ecc496e6` (疑似 MD5 自校验，但 MD5("war, war never changes") ≠ 该值)

#### MD5 猜解尝试

用以下公式对三个已知 (date, signature) 对进行测试，**全部未命中**：
- `MD5(date + key)`, `MD5(key + date)`
- `MD5(date + "\n" + key)`, `MD5(key + "\n" + date)`
- `MD5(date + key + endpoint_path)` (COSY 风格)
- key 候选: prefix, full, sentinel, hex, aes_key 等 15+ 个变体

#### 函数符号

- Windows x86_64: `addBigModelSignatureHeaders` @ RVA `0x882760` (旧称 `getAppSalt`)
- 调用 `code.alibaba-inc.com/cosy/encrypt.Md5Encode`
- macOS aarch64: 符号存在但 nm 无法读取（Go 二进制 strip 了符号表）

#### 未尝试的路径

1. **Ghidra/IDA arm64 反编译** — 定位 macOS 二进制中 `addBigModelSignatureHeaders`，追踪 key 加载指令到具体 `.rodata` 偏移
2. **Frida 动态 hook** — 需先对 macOS 二进制做 ad-hoc 重签名 (`codesign --remove-signature && codesign -s -`)
3. **已知 (Date, Signature) 字典攻击** — 从运行中 Lingma 捕获真实 heartbeat 请求，用该对反推

### 已知的 (Date, Signature) 验证对

来自 `docs/lingma-analysis-endpoint-auth.md`:
```
Date: Fri, 24 Apr 2026 07:54:36 GMT
Signature: e8b434d0a2596ca2ff99c60c4756a1ff  (user/status + user/login)
Signature: 460e2aba79cd5e919885ba6f5b1c9289  (ping + heartbeat, 另一 session)
```

来自 `docs/topics/encryption-analysis.md`:
```
Unix: 1777011796  Signature: 8d915d7d99452c143dc52ce040b9a355  (session1)
Unix: 1777016140  Signature: 0f6648253e94ed37c37f33bd3851c25c  (session2)
```

## 3. 当前可用方案

### 方案 A: Lingma Bridge（已实现，推荐）

使用本地 Lingma 二进制完成一次 bootstrap，导出 `credentials.json`。之后 `lingma2api` 运行时完全远程。

```bash
go run ./cmd/lingma-auth-bootstrap --output ./auth/credentials.json
```

凭证文件可在任意机器使用（已验证 `GET /v1/models` 通过 COSY Bearer 返回 200）。

### 方案 B: 纯远程（需密钥提取）

待 client_id 和 session_key 获取后可用：

```bash
go run ./cmd/lingma-auth-bootstrap \
  --client-id <REAL_CLIENT_ID> \
  --session-key <SESSION_KEY> \
  --use-lingma=false
```

### 方案 C: client_id 快速提取

1. 浏览器访问 `https://account.alibabacloud.com/logout/logout.htm?oauth_callback=...`
2. 登录 Alibaba 账号
3. 在地址栏捕获 `signin.alibabacloud.com/oauth2/v1/auth?client_id=<HERE>`
4. 将 client_id 传入 `--client-id` 参数

## 4. 方案 D：refresh 续命（Stage C 已完成）

`lingma-auth-bootstrap` 现已支持 `--refresh` 子模式，在 access_token 过期后无需重新走浏览器登录即可续命。

```bash
go run ./cmd/lingma-auth-bootstrap \
  --refresh ./auth/credentials.json \
  --client-id <REAL_CLIENT_ID>
```

实现细节见 `docs/topics/refresh-token-flow.md`。

## 5. 方案 E：session_key 破解（Stage B 进行中）

已建立三条并行路径：

1. **B3（Frida hook）**：`tools/md5encode_dump.js` hook `code.alibaba-inc.com/cosy/encrypt.Md5Encode`
2. **B2（字典攻击）**：`tools/session_key_oracle.py` 枚举候选 key × 公式，用 3 组已知 oracle 交叉验证
3. **B1（静态反编译）**：IDA/Ghidra 从 `addBigModelSignatureHeaders` 向下追踪 key 的 `.rodata` 偏移

详细过程见 `docs/topics/session-key-cracking.md`。

## 6. 关键文件索引

| 文件 | 内容 |
|------|------|
| `internal/auth/remote_login.go` | 纯远程 user/login 实现，含多策略 Signature 尝试 |
| `internal/auth/encode1.go` | Encode=1 + AES 编解码（Go 移植） |
| `internal/auth/token_exchange.go` | OAuth code → access_token 交换 + refresh_token 续命 |
| `internal/auth/credential_derive.go` | Lingma Bridge 凭据派生 |
| `cmd/lingma-auth-bootstrap/main.go` | Bootstrap CLI，支持 `--use-lingma`、`--session-key`、`--capture-client-id`、`--refresh` |
| `tools/forge_signing.py` | 二进制提取的 SECRET_FULL 字符串 |
| `tools/getappsalt_analysis_v2.md` | addBigModelSignatureHeaders 反编译分析 |
| `tools/md5encode_dump.js` | Frida hook Md5Encode（B3 主路径） |
| `tools/session_key_oracle.py` | 字典攻击 + 交叉验证（B2 fallback） |
| `docs/lingma-analysis-endpoint-auth.md` | 两套签名系统完整文档 |
| `docs/topics/client-id-extraction.md` | Stage A 过程文档 |
| `docs/topics/refresh-token-flow.md` | Stage C 过程文档 |
| `docs/topics/session-key-cracking.md` | Stage B 过程文档 |
