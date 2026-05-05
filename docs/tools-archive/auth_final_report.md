# Lingma CTF - 认证分析最终报告

## 执行摘要

从 HTML (`通义灵码 · Lingma.html`) 提取的认证信息:
- **securityOauthToken**: `pt-SpgVj8cEmNKy09m8cXUpGpwg`
- **refreshToken**: `rt-J6C5hybLMOeykNndfoJOn9bo`
- **user_id**: `5930676910898027`
- **machine_id**: `35346164-3866-492d-a339-30773a32652d`
- 登录账号: `zhang640@blny.de`

## 已验证的端点

| 端点 | 方法 | 状态 | 说明 |
|------|------|------|------|
| `/algo/api/v1/ping` | GET | **200 OK** | 公开健康检查 |
| `/algo/api/v1/heartbeat` | POST | 403 | 需要认证，Entry-Timestamp 确认到达应用层 |
| `/algo/api/v1/tracking` | POST | 403 | 同上 |
| `/algo/api/v1/organizations` | GET | 404 | 路径不存在 |
| `/algo/api/v1/service/next_edit_predict` | POST | 404 | 路径不存在 |

**403 响应格式**:
```json
{"success":false,"errorMessage":"Request discarded","errorCode":"Forbidden","httpStatusCode":403}
```

## 已发现的 HTTP 请求头格式

从二进制结构分析，Lingma 客户端发送的完整请求头包含:

```
Date: <RFC1123 timestamp>
Signature: <computed signature>
Appcode: cosy
Cosy-Key: <key value>
Cosy-Date: <timestamp>
Cosy-User: <user_id>
Cosy-MachineToken: <machine token>
Authorization: Bearer <token>
Content-Type: application/json
User-Agent: Lingma/2.11.1
```

## 签名组件 (用于 MD5 验证)

从二进制中提取的签名观测信息:
1. Payload (base64): 请求体的 base64 编码
2. Key (Cosy-Key): 签名密钥
3. Timestamp (Cosy-Date): 时间戳
4. Body: 请求体内容

**注意**: 这是 AI agent 的工具提示中的观测信息，不是实际的服务端验证逻辑。

## 实际使用的哈希算法

- **SHA-256** (函数 0x4563c0，含标准 SHA-256 IV 常量)
- 签名密钥: `&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTed2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw==9f1dff714a390b20aeb19175ecc496e6`
- Base64 解码: `war, war never changes`

## 核心阻塞问题

### HTML Token 与 Desktop Token 的区别

`securityOauthToken` (`pt-*`) 是 **Web OAuth Token**，用于浏览器会话。
桌面客户端使用 **Machine Token**，通过 PKCE 流程交换获取。

### 登录流程

1. 客户端启动本地回调服务器 (端口 37510)
2. 打开浏览器进行 OAuth 登录 (account.alibabacloud.com)
3. 登录成功后重定向回 `lingma.alibabacloud.com/lingma/login?state=...&challenge=...&machine_id=...`
4. 回调携带授权码
5. 客户端用 `code_verifier` 交换 `machine_token`

### 当前状态

- `machine_token.json` 的 token 字段为 **空字符串**
- 登录回调页面显示"登录成功"，但 machine token 未持久化
- 客户端进程 (PID 456) 在内存中运行且有有效会话
- LSP 协议可以正常通信 (完成请求返回空是因为无 AI 调用)

### 无法伪造请求的原因

1. **缺少 Machine Token**: `/heartbeat` 和 `/tracking` 需要有效的机器令牌
2. **签名算法未验证**: 虽然知道 SHA-256 和密钥，但 string-to-sign 的精确格式无法确认
3. **无法触发签名流程**: 外部无法调用 `getAppSalt` (需要 Go 运行时上下文)

## 可能的突破方向

### 方向 1: 完成 PKCE Token Exchange

登录 URL 中的参数:
- `challenge=ZdVug10Z0hO-9vQQY5kSn1aVfihBFDzHQ7aHBx9pQ-s`
- `challenge_method=S256`
- `machine_id=35346164-3866-492d-a339-30773a32652d`
- `state=2-dc5ca773af3b4cd7a78934b40f7c4f80`

需要 `code_verifier` 才能完成交换。该值在客户端内存中生成。

### 方向 2: 通过 LSP 触发实际 AI 请求

LSP 协议已验证可用，但:
- `textDocument/completion` 返回空 (可能因为客户端未触发远程 AI 调用)
- `workspace/executeCommand` 不支持
- 需要找到能触发后端 API 调用的 LSP 方法

### 方向 3: 拦截运行中进程的 HTTP 请求

- 使用 Frida hook Go 的 `net/http.(*Transport).RoundTrip`
- 之前尝试因 Go 1.23 GC 栈扫描冲突导致崩溃
- 可尝试 `Stalker` (非侵入式执行追踪) 替代 `Interceptor.attach`

### 方向 4: 直接使用已知的签名密钥

虽然无法验证签名是否正确，但可以尝试用提取的密钥和已知的各种 string-to-sign 格式直接发送请求。

## 数据库发现

SQLite 数据库 (`local.db`) 包含:
- 两个用户 ID: `1018962419830324` (旧) 和 `5930676910898027` (新)
- 多个已完成的聊天会话
- `supabase_token` 表为空 (无缓存的 API 令牌)

## 文件清单

| 文件 | 说明 |
|------|------|
| `forge_get_requests.py` | GET 请求测试脚本 |
| `forge_signing.py` | 签名算法测试脚本 |
| `forge_auth_complete.py` | 完整认证头测试脚本 |
| `forge_all_endpoints.py` | 全端点测试脚本 |
| `deep_heartbeat.py` | /heartbeat 深度测试 |
| `deep_trace_signing.py` | 二进制签名流程分析 |
| `frida_hook_http.py` | Frida HTTP 拦截脚本 |
| `lsp_trigger.py` | LSP 协议触发脚本 |
| `lsp_ai_completion.py` | LSP AI 完成请求脚本 |
| `token_exchange.py` | Token 交换测试 |
| `mitm_capture.py` | Mitmproxy 捕获脚本 |
| `signing_final.md` | 签名分析报告 |
