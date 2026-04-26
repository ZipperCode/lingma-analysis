# lingma2api Design Spec

## Overview

A Go-based proxy server that wraps the Lingma remote API behind an OpenAI-compatible interface. Enables Claude Code, Codex, OpenCode, and any OpenAI-compatible client to use Lingma models without the Lingma IDE plugin or local Lingma process.

**Chat API POST body is plain JSON** — no Encode=1, no template replay, no binary part needed. Full body construction from scratch is already working (see `lingma_remote_api.py`).

## Architecture

```
Client (OpenAI-compatible)
        │
        ▼  HTTP :8080
┌───────────────────────────────────┐
│           lingma2api              │
│                                   │
│  OpenAI API Handler               │
│      ↓                            │
│  Session Manager                  │
│      ↓                            │
│  Credential Manager               │
│      ↓                            │
│  Signature Engine                 │
│      ↓                            │
│  Lingma HTTP Client (utls + SSE) │
└───────────────────────────────────┘
        │
        ▼  HTTPS (utls fingerprint)
  lingma.alibabacloud.com
  lingma-api.tongyi.aliyun.com
```

Five core modules:

1. **OpenAI API Handler** — External interface layer
2. **Session Manager** — Server-side conversation context, multi-turn history injection
3. **Credential Manager** — Credential lifecycle (read, monitor, refresh)
4. **Signature Engine** — Bearer COSY token generation
5. **Lingma HTTP Client** — TLS-fingerprinted remote communication, JSON body construction

## API Surface

### Public Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/chat/completions` | POST | Chat completions (streaming/non-streaming) |
| `/v1/models` | GET | Available model list |

### Admin Endpoints

Protected by `admin_token` in config (simple Bearer auth). Only enforced when `admin_token` is non-empty. Default bind to `127.0.0.1` limits exposure, but token is recommended if binding to `0.0.0.0`.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/admin/status` | GET | Credential status, expiry, session count |
| `/admin/refresh` | POST | Manually re-read credentials from cache/user |
| `/admin/sessions` | GET | List active sessions |
| `/admin/sessions/{id}` | DELETE | Remove a specific session |

### Request Format

Standard OpenAI chat completion:

```json
{
  "model": "qwen3-coder",
  "messages": [
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": "Hello"}
  ],
  "stream": true
}
```

Session binding via `X-Session-Id` header or `extra_body.session_id`.

### Model Mapping

| OpenAI-style Name | Lingma Internal Key |
|--------------------|---------------------|
| `qwen3-coder` | `dashscope_qwen3_coder` |
| `qwen3-coder-default` | `dashscope_qwen3_coder_default` |
| `qwen-plus-thinking` | `dashscope_qwen_plus_20250428_thinking` |
| `qwen-max` | `dashscope_qwen_max_latest` |
| `auto` | `auto` |

Model list is dynamically fetched from `GET /algo/api/v2/model/list` on startup and cached. Dynamic models are preferred; the static mapping table above serves as fallback when the remote fetch fails. New models returned by the remote API are auto-mapped: underscores and `dashscope_` prefix are stripped, remaining segments are joined with `-`.

## Module Details

### 1. OpenAI API Handler

Accepts standard OpenAI requests, converts to internal representation, dispatches to Session Manager, and converts Lingma SSE responses back to OpenAI SSE format.

**Streaming response conversion:**

Lingma SSE:
```
data: {"body": "{\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}"}
```

Converted to OpenAI SSE:
```
data: {"id":"chatcmpl-xxx","object":"chat.completion.chunk","choices":[{"delta":{"content":"Hello"}}]}
```

### 2. Session Manager

Full conversation context is injected into the messages array of each Lingma request. The Session Manager:

- Stores server-side conversation history per `session_id` (UUID)
- Accumulates messages across turns (system, user, assistant)
- Injects full history into the Lingma POST body's `messages` array on each request
- Supports stateless fallback (single `session_id` per request, no lookup)
- Auto-cleanup after 30 minutes of inactivity (configurable)
- Thread-safe with `sync.RWMutex`

Since the Lingma body is plain JSON freely constructed, multi-turn conversation works by simply appending all prior messages to the `messages` array — no template or binary constraints.

### 3. Credential Manager

**Source priority:**
1. Config file (`config.yaml`) explicit fields
2. Environment variables (`LINGMA_COSY_KEY`, `LINGMA_ENCRYPT_USER_INFO`, `LINGMA_USER_ID`, `LINGMA_MACHINE_ID`)
3. Portable config file (`~/.lingma/portable_config.json`)
4. Local Lingma cache (`~/.lingma/cache/user` + `~/.lingma/cache/id`)

This enables **complete independence from local Lingma** — credentials can be extracted once and used anywhere.

**Decryption (仅方式 4 需要):**
```
machineKey = read(cache/id)
aesKey = machineKey[:16]   // first 16 ASCII bytes
iv = aesKey                // key == iv
plaintext = AES-128-CBC.decrypt(base64decode(cache/user), aesKey, iv)
strip PKCS7 padding
parse JSON → CosyUserInfo (20 fields)
```

**Key fields extracted:**
- `key` (172 chars) → `Cosy-Key` header
- `encrypt_user_info` (664 chars) → `Authorization.info`
- `uid` → `Cosy-User` header
- `security_oauth_token` → stored for future use
- `refresh_token` → stored for future use
- `expire_time` → expiry monitoring (int64 millis timestamp)

**重要:** `cosy_key` 和 `encrypt_user_info` **不在** `auth/report` WebSocket 推送中（推送仅含 OAuth token 和用户元信息）。COSY 凭据在初始 OAuth 登录时由 Lingma 后端返回并直接写入 `cache/user`，之后仅通过解密缓存文件获取。

**Token Refresh — 现状分析 (Frida 实时抓包确认):**

**`auth/refreshToken` 角色澄清:**
- `auth/refreshToken` 是 **LSP WebSocket 协议层接口**（IDE 插件 ↔ 本地 Lingma 进程通信）
- 它**不是** Lingma 程序的完整刷新逻辑 —— 它是本地 LSP 封装层
- Frida 实时抓包：调用期间无任何远程网络活动（零 DNS/connect/TLS）
- 输入参数原样返回 (`securityOauthToken` + `refreshToken` + `expireTime`)，不做远端刷新
- **实际结论:** 本地 Lingma 进程中 COSY 凭据长期有效；OAuth token 刷新走的是 LSP 协议的本地缓存路径，不是远程 API

**实际不需要 OAuth token 刷新**：
- Chat API 使用 COSY Bearer 签名认证（`cosy_key` + `encrypt_user_info`）
- COSY 凭据来自 `cache/user` 解密后，持久有效
- OAuth token（`security_oauth_token`/`refresh_token`）仅用于 IDE 插件与本地 Lingma 进程之间的 LSP 会话认证
- `lingma_remote_api.py` 已证实仅凭 COSY 凭据即可无限次调用 Chat API

**远端 token 刷新端点状态：**
- 国际服：`/algo/api/v3/user/refresh_token` → **404**（未部署）
- 国内服：`/algo/api/v3/user/refresh_token` → **403**（WAF/ALB 拦截，真实 Lingma 进程也不走此端点）

**Lifecycle:**
- COSY 凭据无需刷新，`cache/user` 解密后长期有效
- `/admin/refresh` 仅用于重新读取 `cache/user` 文件（如 VS Code 插件更新了凭据）

### 4. Signature Engine

**Bearer structure:** `COSY.<base64_payload>.<32hex_signature>`

**Payload:**
```json
{
  "cosyVersion": "2.11.2",
  "ideVersion": "",
  "info": "<encrypt_user_info>",
  "requestId": "<new-uuid-per-request>",
  "version": "v1"
}
```

**Signature formula:**
```
normalized_path = strip "/algo" prefix from path
preimage = base64(payload) + "\n" + cosy_key + "\n" + unix_timestamp + "\n" + slot4 + "\n" + normalized_path
signature = md5(preimage).hex()
```

- GET: `slot4 = ""`
- POST: `slot4 = full_http_body`

**Required headers per request:**
```
Authorization: Bearer COSY.<payload>.<signature>
Cosy-Date: <unix_timestamp>
Cosy-Key: <from cache/user.key>
Cosy-User: <from cache/user.uid>
Cosy-Machineid: <from cache/id>
Cosy-Clientip: 198.18.0.1
Cosy-Clienttype: 2
Cosy-Machineos: x86_64_windows
Cosy-Machinetoken: <empty>
Cosy-Machinetype: <empty>
Cosy-Version: 2.11.2
Appcode: cosy
Login-Version: v2
User-Agent: Go-http-client/1.1
```

### 5. Lingma HTTP Client

**TLS fingerprint:** Uses `github.com/refraction-networking/utls` to present a Chrome TLS fingerprint. Python `requests` is rejected; `curl` works; utls Chrome preset should work.

**Remote endpoints:**
- Model list: `GET https://lingma.alibabacloud.com/algo/api/v2/model/list`
- Chat: `POST https://lingma.alibabacloud.com/algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common`

**Chat body construction (plain JSON — no encoding):**

The POST body is standard JSON built from scratch. No Encode=1, no template replay, no binary part.

```json
{
  "request_id": "<uuid>",
  "request_set_id": "",
  "chat_record_id": "<same-uuid>",
  "stream": true,
  "image_urls": null,
  "is_reply": false,
  "is_retry": false,
  "session_id": "",
  "code_language": "",
  "source": 0,
  "version": "3",
  "chat_prompt": "",
  "parameters": {"temperature": 0.1},
  "aliyun_user_type": "personal_standard",
  "agent_id": "agent_common",
  "task_id": "question_refine",
  "model_config": {
    "key": "<model_key or empty for auto>",
    "display_name": "", "model": "", "format": "",
    "is_vl": false, "is_reasoning": false, "api_key": "", "url": "",
    "source": "", "max_input_tokens": 0, "enable": false,
    "price_factor": 0, "original_price_factor": 0,
    "is_default": false, "is_new": false,
    "exclude_tags": null, "tags": null, "icon": null, "strategies": null
  },
  "messages": [
    {"role": "system", "content": "<system_prompt>", "response_meta": {...}, "reasoning_content_signature": ""},
    {"role": "user", "content": "<user_message>", "response_meta": {...}, "reasoning_content_signature": ""}
  ],
  "business": {
    "product": "jb_plugin",
    "version": "2.11.2",
    "type": "memory",
    "id": "<uuid>",
    "begin_at": <unix_millis>,
    "stage": "start",
    "name": "memory_intent_recognition_<request_id>"
  }
}
```

Key points:
- `messages` array freely constructed — arbitrary content, no byte budget
- Multi-turn: append prior assistant/user turns to `messages`
- `model_config.key`: empty string = auto model selection
- `response_meta` and `reasoning_content_signature` use fixed empty/zero values
- `business.id`, `business.begin_at`, `business.name` are per-request unique

**Reference implementation:** `lingma_remote_api.py:_build_chat_body()`

**SSE parsing:**
- Read `data:` lines from response stream
- Parse outer JSON: `{"body": "<inner JSON>", "statusCodeValue": 200}`
- Skip `[DONE]` body
- Parse inner JSON: standard OpenAI-format chat completion chunk
- Extract `choices[].delta.content`
- Forward as OpenAI-format SSE chunks
- Final event: `event:finish` with timing metadata

**Encode=1 codec** (retained for other endpoints that may need it):
- Custom base64 alphabet: `_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!`
- Algorithm: custom base64 → 3-block reversal → $ padding
- Not used by Chat API; may be needed for login/heartbeat endpoints
- Implemented in `lingma_remote_api.py:lingma_encode()/lingma_decode()`

## Configuration

`config.yaml`:
```yaml
server:
  host: "127.0.0.1"
  port: 8080
  admin_token: ""         # Bearer token for /admin/* endpoints; empty = no auth

credential:
  lingma_dir: ""          # default: ~/.lingma
  cache_dir: ""           # override: direct path to cache/
  # Future: explicit key/info fields

session:
  ttl_minutes: 30
  max_sessions: 100

lingma:
  base_url: "https://lingma.alibabacloud.com"
  cosy_version: "2.11.2"
```

Environment variable overrides:
- `LINGMA_LISTEN` — `host:port`
- `LINGMA_CACHE_DIR` — path to cache directory

## Project Structure

```
lingma2api/
├── main.go
├── go.mod
├── go.sum
├── config.yaml
├── internal/
│   ├── api/
│   │   ├── handler.go        // OpenAI API handler
│   │   ├── models.go         // /v1/models
│   │   ├── chat.go           // /v1/chat/completions
│   │   └── admin.go          // /admin/* endpoints
│   ├── session/
│   │   └── manager.go        // Session Manager
│   ├── credential/
│   │   └── manager.go        // Credential Manager + AES decrypt
│   ├── signature/
│   │   └── engine.go         // Bearer COSY signature
│   ├── lingma/
│   │   ├── client.go         // Lingma HTTP client (utls)
│   │   ├── codec.go          // Custom base64 codec (for non-chat endpoints)
│   │   ├── sse.go            // SSE parser
│   │   └── body.go           // Chat body JSON constructor
│   └── config/
│       └── config.go         // Configuration loading
└── README.md
```

## OAuth 登录/刷新流程 (2026-04-26 分析)

### 脱离本地环境 — 凭据引导方案

**核心发现:** `cosy_key` 和 `encrypt_user_info` **不在** `auth/report` WebSocket 推送中，仅存储在 `cache/user` 文件。这些 COSY 凭据长期有效，可用于完全脱离 Lingma 本地程序。

**引导流程:**

```
机器 A (有 Lingma)                          机器 B (无 Lingma)
─────────────────                          ─────────────────
1. 启动 Lingma
2. credential_extractor.py
   → 读取 cache/id + cache/user
   → AES-128-CBC 解密
   → 导出 cosy_key + encrypt_user_info
3. portable_config.json                 ──→  复制到机器 B
       或 环境变量                           或设置 ENV VARs
                                            LingmaRemoteAPI(config_file=...)
                                                    ↓
                                            Chat API 直连 ✓
```

**三种凭据获取方式:**

| 方式 | 脚本 | 适用场景 |
|------|------|---------|
| 便携导出 | `tools/credential_extractor.py` | **推荐** — 从现有 Lingma 导出凭据 |
| 回调拦截 | `tools/oauth_callback_intercept.py --standalone` | 干净引导 — 拦截 OAuth 回调获取凭据 |
| 流分析 | `tools/oauth_callback_intercept.py --analyze-only` | 仅分析 — 观察登录流程不拦截 |

**`LingmaRemoteAPI` 凭据加载优先级:**
1. 直接构造函数参数 (`cosy_key=`, `encrypt_user_info=`)
2. 环境变量 (`LINGMA_COSY_KEY`, `LINGMA_ENCRYPT_USER_INFO`, `LINGMA_USER_ID`, `LINGMA_MACHINE_ID`)
3. 便携配置文件 (`~/.lingma/portable_config.json`)
4. 本地 Lingma 缓存 (`cache/user` + `cache/id`，需安装 Lingma)

**OAuth 回调拦截原理:**

```
auth/login (WebSocket) → login URL
    ↓
https://lingma.alibabacloud.com/lingma/login
    ?nonce={nonce}&port=37510
    &state=2-{nonce}        ← 2- 表示已登录; 1- 表示需认证
    &challenge={pkce_S256}
    &challenge_method=S256
    &machine_id={id}
    ↓
OAuth Provider (signin.alibabacloud.com)
    ↓ 用户认证后
redirect → http://localhost:37510?code={auth_code}&state={state}
    ↓
Lingma 本地服务器接收 code → 交换令牌
    ↓
Lingma 后端返回凭据 → 写入 cache/user (AES-128-CBC 加密)
    ↓
auth/report 推送 → 仅含 OAuth token，**不含** cosy_key
```

关键约束：OAuth 回调拦截可获取 `authorization_code`，但**直接交换令牌需要 `client_id`**（服务器端密钥，不在本地 binary）。因此：
- 拦截脚本 `--standalone` 模式可捕获回调，但无法独立完成凭据获取
- **推荐方案**：使用 `credential_extractor.py` 一次导出，后续完全脱离 Lingma

### 完整 OAuth 流程

Lingma 使用 **PKCE (Proof Key for Code Exchange) + OIDC** 认证：

```
1. IDE 触发 LSP auth/login
2. 本地 Lingma 生成 PKCE code_verifier + code_challenge (S256)
3. 构建登录 URL: https://lingma.alibabacloud.com/lingma/login
      ?state=2-{nonce}
      &challenge={code_challenge}
      &challenge_method=S256
      &machine_id={from cache/id}
      &nonce={nonce}
      &port=37510
4. 重定向到: https://account.alibabacloud.com/login/login.htm
      ?oauth_callback=https://lingma.alibabacloud.com/lingma/login?...
5. 用户登录 Alibaba 账号
6. 授权后跳转到: https://signin.alibabacloud.com/oauth2/v1/auth
      ?client_id=XXX (服务器端)
      &response_type=code
      &scope=openid+aliuid+profile
      &code_challenge={challenge}
      &code_challenge_method=S256
      &redirect_uri={lingma_server_callback}
      &state={state}
7. 授权码通过 localhost:37510 (本地回调服务器) 返回
8. 授权码交换为 token (服务器端或本地)
9. 结果存入 ~/.lingma/cache/user (AES-128-CBC 加密)

### OAuth 端点 (OIDC Discovery)

**国际站:**
- Discovery: https://oauth.alibabacloud.com/.well-known/openid-configuration
- Authorization: https://signin.alibabacloud.com/oauth2/v1/auth
- Token: https://oauth.alibabacloud.com/v1/token
- Revoke: https://oauth.alibabacloud.com/v1/revoke
- UserInfo: https://oauth.alibabacloud.com/v1/userinfo

**国内站:**
- Discovery: https://oauth.aliyun.com/.well-known/openid-configuration
- Authorization: https://signin.aliyun.com/oauth2/v1/auth
- Token: https://oauth.aliyun.com/v1/token

### Token 刷新

- **本地路径 (可用):** WebSocket `auth/refreshToken` (LSP)，参数 `securityOauthToken` + `refreshToken` + `tokenExpireTime`
- **远端路径 (已分析):** `/algo/api/v3/user/refresh_token` — 见下方"远端 Token 刷新接口分析"
- **独立刷新:** 需要发现 `client_id`（服务器端密钥，不在本地 binary 中）

### 远端 Token 刷新接口分析 (2026-04-26 深入分析)

#### 二进制中发现的 API 路径

通过遍历 Lingma 二进制文件，找到完整的 `/api/v3/user/` 路径族：

| 路径 | 用途 |
|------|------|
| `/api/v3/user/login` | 用户登录 |
| `/api/v3/user/status` | 用户状态查询 |
| `/api/v3/user/logout` | 用户登出 |
| `/api/v3/user/region` | 区域查询 |
| `/api/v3/user/remoteToken` | 远程 Token 管理 |
| `/api/v3/user/data_region` | 数据区域 |
| `/api/v3/user/refresh_token` | **Token 刷新 (目标接口)** |
| `/api/v3/user/grantAuthInfos` | 授权信息查询 |
| `/api/v3/user/oauth2/deviceToken/poll` | OAuth2 设备码轮询 |

#### 请求/响应结构 (GoReSym Types 反编译)

**请求体 (`definition.RefreshTokenParams`):**
```go
type RefreshTokenParams struct {
    SecurityOauthToken string `json:"securityOauthToken"`
    RefreshToken       string `json:"refreshToken"`
    TokenExpireTime    int64  `json:"tokenExpireTime"`
}
```

**响应体 (`definition.RefreshTokenResult`):**
```go
type RefreshTokenResult struct {
    BaseResult      definition.BaseResult
    Success         bool   `json:"success"`
    Uid             string `json:"uid,omitempty"`
    Name            string `json:"name,omitempty"`
    TokenExpireTime int64  `json:"tokenExpireTime,omitempty"`
}
```

#### 端点可达性测试 (GET 方法 — 确认端点存在性)

所有 `/api/v3/user/` 端点对 GET 返回 400 "method not supported"（存在）或 404（不存在），无需认证即可区分：

| 路径 | 国际站 | 国内站 |
|------|--------|--------|
| `/algo/api/v3/user/login` | EXISTS (400) | EXISTS (400) |
| `/algo/api/v3/user/status` | EXISTS (400) | EXISTS (400) |
| `/algo/api/v3/user/logout` | EXISTS (400) | EXISTS (400) |
| `/algo/api/v3/user/grantAuthInfos` | EXISTS (400) | EXISTS (400) |
| `/algo/api/v3/user/refresh_token` | **NOT FOUND (404)** | **EXISTS (400)** |
| `/algo/api/v3/user/region` | NOT FOUND (404) | EXISTS (403) |
| `/algo/api/v3/user/remoteToken` | NOT FOUND (404) | EXISTS (403) |
| `/algo/api/v3/user/data_region` | NOT FOUND (404) | NOT FOUND (404) |

#### 403 "Request discarded" 根因分析

POST 到 `/algo/api/v3/user/` 端点均返回 403，**无论使用何种认证方式**：

| 测试 | 结果 |
|------|------|
| COSY Bearer 签名（完整 Cosy-* 头） | 403 |
| OAuth Bearer Token (securityOauthToken) | 403 |
| 无认证头（纯 JSON POST） | 403 |
| Body 为空 | SSL EOF（服务器关闭连接） |
| Non-existent endpoint POST | **404**（非 403，证明 403 非全局规则） |
| `/algo/api/v1/ping` POST | **200** "pong"（基础 POST 正常） |

**关键发现：**
- 国内站与国际站使用**不同的 COSY 凭证体系**（国内站拒绝国际站 cosy_key 返回 "Login timeout"）
- `/api/v3/user/refresh_token` 仅在国内站存在，国际站为 404
- 403 来自 COSY 框架认证层，非 WAF/ALB 层（GET 可正常到达应用层返回 400）
- OAuth 直达端点 `https://oauth.aliyun.com/v1/token` **可达**（返回 400 "invalid_grant"），但需要 `client_id`
- `client_id` 为服务器端密钥（**已确认不在 binary 中**），由 Lingma 服务器代理 OAuth token 交换
- 架构：客户端 → `/api/v3/user/refresh_token` (Lingma 代理) → `oauth.aliyun.com/v1/token` (OAuth 提供方)

#### 服务端配置 (来自 binary config block)

```json
{
  "big_model_endpoint": "https://lingma.alibabacloud.com/algo",      // 国际站
  "big_model_endpoint": "https://lingma-api.tongyi.aliyun.com/algo", // 国内站
  "login_url": "https://lingma.alibabacloud.com/lingma/login",
  "auth_logout_url": "https://account.alibabacloud.com/logout/logout.htm",
  "auth_login_url": "https://account.alibabacloud.com/login/login.htm",
  "message_encode": "1",
  "login_encode": "2"
}
```

#### 关键结论

1. **远端 HTTP 刷新端点 `/algo/api/v3/user/refresh_token` 在国内站存在但被 403 拦截**
2. **实际 token 刷新通过本地 LSP WebSocket `auth/refreshToken` 完成**（`doRefreshToken` 为 LSP RPC handler）
3. **完全独立的远端 token 刷新需要绕过 403 拦截**，可能需要：
   - 使用正确的 TLS 指纹 (utls Chrome preset)
   - 国内站凭证 (与当前国际站凭证不同)
   - 服务器端 IP 白名单

| Scenario | Behavior |
|----------|----------|
| `cache/user` not found | Startup fails with clear error message pointing to setup steps |
| `cache/id` not found | Startup fails with clear error message |
| `AES decryption failure (machineKey < 16 chars)` | Startup fails with diagnostic message |
| `cache/user` JSON parse failure | Startup fails; may indicate version change |
| Lingma returns non-200 (auth/schema error) | Returns 502 with upstream error details |
| TLS handshake rejected (utls fingerprint mismatch) | Returns 502; logs suggest trying different utls preset |
| SSE stream interrupted mid-response | Returns partial response with finish_reason `"error"`; logs details |
| `cache/user` deleted or invalidated | `/v1/chat/completions` returns 401; user must re-login via VS Code plugin to regenerate cache |
| `/admin/refresh` triggered but cache/user unchanged | Returns 200 with `"no_change": true` |
| Remote model list fetch fails | Falls back to static model mapping table |

## Graceful Shutdown

`main.go` listens for `SIGINT`/`SIGTERM`:

1. Stop accepting new connections
2. Wait up to 30 seconds for in-flight SSE streams to complete
3. Clean up session state
4. Close TLS connection pool
5. Exit

All request handlers receive a `context.Context` derived from the server lifecycle for proper cancellation propagation.

## Unverified Assumptions

Items that are believed to work based on analysis but have not been independently tested:

1. **utls Chrome fingerprint:** Whether `utls.HelloChrome_Auto` is sufficient to pass Lingma's TLS fingerprint check. Known: Python `requests` fails, `curl` works. Go standard library status is unknown.
2. **Cosy-Clientip value:** Whether the server validates this header against the actual source IP. Current value `198.18.0.1` is from captured samples.
3. **Long conversation stability:** Whether very long message histories (50+ turns) are handled correctly by the Lingma backend.
4. **国内站凭证兼容性:** 国内站 (`lingma-api.tongyi.aliyun.com`) 使用不同的 COSY 凭证体系。国际站 cosy_key 在国内站返回 "Login timeout"。国内站独立可用性待测试。

## Frida-已验证结论 (2026-04-26 实时抓包)

以下假设已通过 Frida 实时网络抓包实验证实或否定：

| 假设 | 结论 | 证据 |
|------|------|------|
| `auth/refreshToken` 触发远端 HTTP 请求 | **已否定** | WSAIoctl/GetAddrInfoW/connect 全程无事件 |
| Lingma chat 连接 `lingma.alibabacloud.com` | **已证实** | GetAddrInfoW hook 实时捕获 DNS 解析 |
| Go 使用标准 `connect` API | **已否定** | 全部 7 个 connect 变体 hook 但均未触发 |
| Go 使用 `ConnectEx` (mswsock.dll) | **已证实** | 通过 `WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER)` 动态获取 |
| 国内站 `/api/v3/user/refresh_token` 被真实 Lingma 调用 | **已否定** | Lingma 的 `auth/refreshToken` 全程无网络活动，不走此端点 |
| Python `requests` TLS 被拒 | **已证实** | 仅 `curl` 和 `utls` 可用 |

### Go Windows 网络栈发现

Go on Windows **完全绕过** ws2_32.dll 的标准 connect API：
- 通过 `WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER)` 获取 `ConnectEx` 函数指针
- `ConnectEx` 指针在启动时缓存（Frida 动态 hook 捕获到 AcceptEx，但 ConnectEx 已预缓存）
- `WSAIoctl(SIO_SET_COMPATIBILITY_MODE)` 在每个 socket 创建后调用
- AF_INET6 socket 优先创建，失败后回退到 AF_INET
- 数据模式：293B TLS ClientHello → 64B+86B 握手 → 16KB+ 应用数据块

## Current Constraints

1. ~~Credentials sourced from `~/.lingma/cache/user`~~ — **已突破**: 便携凭据提取器 + 环境变量模式支持完全脱离本地 Lingma
2. COSY 凭据（`cosy_key` + `encrypt_user_info`）长期有效，无需 OAuth token 刷新 —— Chat API 仅依赖 COSY Bearer
3. OAuth 独立刷新已确认不可行：
   - `client_id` 为服务器端密钥（不在本地 binary 中），独立 OAuth PKCE 流程无法完成 token 交换
   - 国际站未部署 `/api/v3/user/` 端点（404）
   - 国内站 `/api/v3/user/refresh_token` 端点返回 403
4. 凭据引导需要一次性本地操作（`credential_extractor.py`），之后完全脱离 Lingma
5. TLS 指纹要求：仅 `curl` 和 `utls` 可通，Python `requests` 被拒
6. 国内站使用不同的 COSY 凭证体系，国际站 cosy_key 在国内站返回 "Login timeout"

## Evolution Roadmap

**Phase 1 (current — functional PoC):**
- GET APIs fully functional (`/v1/models`)
- POST chat with full body construction (arbitrary messages, no template needed)
- Multi-turn conversation via session-scoped message history injection
- Credential auto-read from cache/user
- Session tracking with auto-cleanup
- Admin endpoints: `/admin/status`, `/admin/refresh`（重新读取 cache/user）

**Phase 2 (credential resilience — 已重新评估):**
- ✅ **便携凭据引导**: `credential_extractor.py` 导出 COSY 凭据 → 环境变量/配置文件
- ✅ **多来源凭据加载**: 构造参数 > 环境变量 > portable_config.json > cache/user
- ✅ **脱离本地环境**: `LingmaRemoteAPI` 支持纯环境变量模式，无需本地 Lingma 程序
- ~~本地 LSP WebSocket `auth/refreshToken` 自动刷新~~ — 不需要（COSY 凭据长期有效）
- ~~直接调用远端 `/algo/api/v3/user/refresh_token`~~ — 不可行（国际站 404，国内站 403）
- **OAuth 回调拦截**: `oauth_callback_intercept.py` 分析登录流程；独立拦截受限于 `client_id`（服务器端密钥）
- ✅ **COSY 凭据监控**: 后台 goroutine 监控凭据文件变化，自动重载

**Phase 3 (polish):**
- Multi-user support (credential isolation per user)
- Rate limiting
- Usage statistics
- Encode=1 support for non-chat endpoints if needed (login/heartbeat 等辅助端点)

## 分析工具清单

### Python 参考实现

| 文件 | 用途 |
|------|------|
| `lingma_remote_api.py` | **主客户端** — Chat API 直连（COSY Bearer + 原始 JSON），支持环境变量/便携配置/本地缓存三种凭据源 |
| `lingma_client.py` | 本地 WebSocket 客户端（LSP 协议，绕过 TLS 指纹） |
| `tools/credential_extractor.py` | **便携凭据导出** — 从 Lingma 缓存提取 COSY 凭据为可移植格式 |
| `tools/oauth_callback_intercept.py` | **OAuth 回调拦截** — 分析/拦截登录流程，支持 --analyze-only / --standalone 模式 |
| `tools/test_login_flow.py` | **登录流程测试** — 通过 WebSocket 触发 auth/login，分析登录 URL 和 auth/report 推送 |
| `tools/ws_refresh_test.py` | LSP WebSocket auth/refreshToken 测试 |
| `tools/restore_cache.py` | cache/user 凭据恢复工具 |

### Frida 网络分析脚本

| 文件 | Hook 目标 | 关键发现 |
|------|-----------|---------|
| `tools/frida_minimal_hook.js` | connect, WSASend, WSARecv, TLS SNI | 基础抓包；Go 绕过 connect |
| `tools/frida_connect_all.py` | 全部 ws2 connect 变体 + mswsock ConnectEx | 无一触发 |
| `tools/frida_connect_and_chat.py` | 同上 + GetAddrInfoW + chat 触发 | DNS 首次正确捕获 |
| `tools/frida_dns_trace.py` | getaddrinfo, gethostbyname, WSASocketW, send | TLS 数据流首次捕获 |
| `tools/frida_go_dial.py` | WSASocketW + connect + WSAConnect + 栈追踪 | Go 绕过机制初步定位 |
| `tools/frida_spawn_trace.py` | Frida.spawn() 启动 Lingma + 完整 chat 流 | 启动期也无线程连接事件 |
| `tools/frida_wsaioctl_hook.py` | WSAIoctl（初版，signed/unsigned bug） | SIO_GET_EXTENSION 确认调用 |
| `tools/frida_wsaioctl_v2.py` | WSAIoctl（修复版 + 动态 ConnectEx hook） | AcceptEx 动态 hook 成功；ConnectEx 预缓存 |

### 关键 Go 函数 (GoReSym 定位, Lingma.exe 2.11.2)

| 函数 (FullName) | Offset (from ImageBase 0x140000000) | 用途 |
|-----------------|--------------------------------------|------|
| `cosy/remoting.BuildBigModelSvcRequestWithConfig` | 0x87fc00 | 构建 Chat API 请求入口 |
| `cosy/remoting.BuildBigModelAuthRequest` | 0x8808e0 | 构建认证请求 |
| `cosy/remoting.buildRequest` | 0x880da0 | 构建 HTTP 请求 |
| `cosy/remoting.buildURL` | 0x881480 | 构建请求 URL |
| `cosy/remoting.encodeRequestBody` | 0x881820 | 编码请求体（JSON marshal + 可选 AES） |
| `cosy/remoting.createHTTPRequest` | 0x881980 | 创建 HTTP 请求对象 |
| `cosy/remoting.createCompressedHTTPRequest` | 0x881ce0 | 创建压缩 HTTP 请求 |
| `cosy/remoting.logRequest` | 0x8821e0 | 日志记录请求 |
| `cosy/remoting.addBigModelSignatureHeaders` | 0x882760 | 添加 COSY 签名头 |
| `cosy/remoting.addBigModelAuthorizationHeaders` | 0x882ba0 | 添加 Authorization 头 |
| `cosy/remoting.shouldAddEncodeParam` | 0x882540 | 判断是否需要 Encode=1 |
| `cosy/remoting.shouldEncryptBody` | 0x882680 | 判断是否需要 AES 加密 |
| `cosy/auth/user.doRefreshToken` | 0x140C35B20 (RVA) | auth/refreshToken 实现 |

### 记忆文件

| 文件 | 内容 |
|------|------|
| `memory/lingma-encoding-cracked.md` | Encode=1 完整算法破解 + AES 加密层 |
| `memory/lingma-oauth-analysis.md` | OAuth PKCE 流程 + refreshToken 分析 + 远端端点状态 |
| `memory/lingma-aes-key-source-analysis.md` | AES key 来源分析（session 级，每进程不同） |
| `memory/lingma-analysis-final-status.md` | 远端 Chat API 完整实现状态 |
| `memory/frida-network-analysis.md` | Frida 网络抓包完整分析 |
