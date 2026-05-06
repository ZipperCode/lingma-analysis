# 灵码 37510 回调模拟与完整认证流程架构

> 日期：2026-05-05（更新）
> 状态：**已验证 ✅** Chat API 直连；37510 回调拦截 **已验证 ✅**；后端 API 全链路签名 **已实现但被 WAF 拦截 ⚠️**
> 目标：文档化基于 IDA Pro 逆向的完整认证流程、各阶段的函数地址与算法实现

---

## 1. 总体架构

灵码的认证体系分为 **5 个阶段**，每阶段有独立的函数实现和边界：

```
LSP: auth/login ──▶ LoginHandler ──▶ LoginStart ──▶ PrepareLoginRequest
  │                                                    │
  │ 返回 OAuth URL ◀────────────────────────────────────┘
  │                                                    │
  │ 用户浏览器认证 → 37510 回调 ──▶ auth/device_login ──▶ DeviceLoginHandler
  │                                                       │
  │                                                       ├─ DeviceLogin + ToLoginAuthCallbackParam
  │                                                       └─ HandleAuthCallback
  │                                                            │
  │                                                            ├─ parseAuthInfoV3
  │                                                            ├─ parseAuthToken
  │                                                            └─ CompleteLoginWithSelectAccount
  │                                                                 │
  │                                          COSY 凭据 ◀───────────┘
  │                                              │
  │                                              ▼ AES 加密写入 cache/user
```

每个阶段的**输出**是下一阶段的**输入**：

| 阶段 | 输入 | 输出 | 状态 |
|------|------|------|------|
| Phase 1: OAuth 登录 | 用户浏览器认证 | `auth`/`token`/`state` 回调参数 | ✅ 已验证 |
| Phase 2: 后端 API | 回调参数 + 签名 | COSY 凭据 (`cosy_key`+`encrypt_user_info`) | ⚠️ WAF 拦截 |
| Phase 3: 凭据存储 | COSY 凭据 + `machine_id` | AES 加密写入 `cache/user` | ✅ 已逆向 |
| Phase 4: Chat API | COSY 凭据 | SSE 流式对话 | ✅ **已验证** |
| Phase 5: Token 刷新 | OAuth refresh_token | 新 token 对 | ⚠️ 远程 404/403 |

---

## 2. Phase 1：OAuth 登录（37510 回调）

### 2.1 总体流程（更新于 2026-05-05，基于 IDA 最新反编译）

```
Plugin / IDE                    Lingma (LSP Server)                  Browser/Cloud
  │                                  │                                    │
  │ ① auth/login (LoginType="")     │                                    │
  │ ──────────────────────────────▶ │  LoginHandler @ 0x141aad0a0        │
  │                                 │    └─ LoginStart @ 0x141a10680     │
  │                                 │       └─ PrepareLoginRequest       │
  │  ◄── {Url, Success} ───────────┤          @ 0x141a198a0              │
  │                                 │                                    │
  │ ② 打开浏览器 ◀─────────────────────────────────────────────────────▶│
  │                                 │     用户阿里云 PKCE OAuth 认证     │
  │                                 │    ◄───────────────────────────────│
  │ ③ 回调 127.0.0.1:37510/auth/   │                                    │
  │   callback?state=&auth=&token= │                                    │
  │     (由 Plugin 或 Lingma 本地    │                                    │
  │      HTTP 服务器拦截)           │                                    │
  │                                 │                                    │
  │ ④ auth/device_login             │                                    │
  │   {Token,RefreshToken,UserID,   │                                    │
  │    Username,ExpiresIn}          │                                    │
  │ ──────────────────────────────▶ │  DeviceLoginHandler @ 0x141aac2a0 │
  │                                 │    ├─ DeviceLogin @ 0x141a19ee0   │
  │                                 │    │  └─ ToLoginAuthCallbackParam  │
  │                                 │    └─ HandleAuthCallback           │
  │  ◄── {Success} ────────────────┤       @ 0x141a18dc0                │
  │                                 │       └─ CompleteLoginWith...      │
  │                                 │          → COSY 凭据获取            │
```

### 2.2 LSP Handler 路由表

**函数：** `cosy_core_api_auth.InitHandlers` @ `0x141aadb20`

`auth/login` 的 LSP 处理器在 `cosy_core_api_auth_login_InitHandlers()` 中注册，函数表位于 `off_14361FC70`：

| 方法 | 处理器 | 地址 | 说明 |
|------|--------|------|------|
| **`auth/login`** | **`LoginHandler`** | **`0x141aad0a0`** | **★ 登录入口，3 种模式路由** |
| `auth/logout` | `LogoutHandler` | `0x141aac0c0` | 登出 |
| `auth/device_login` | `DeviceLoginHandler` | `0x141aac2a0` | 设备登录（回调凭据处理） |
| `auth/refreshToken` | `RefreshTokenHandler` | `0x141aaf7e0` | Token 刷新 |
| `auth/status` | `StatusHandler` | `0x141aadd60` | 认证状态查询 |
| `auth/profile/getUrl` | `ProfileGetUrlHandler` | `0x141aad6a0` | 个人资料 URL |
| `auth/profile/getGlobalConfig` | `ProfileGetGlobalConfigHandler` | `0x141aad780` | 全局配置 |
| `auth/profile/update` | `ProfileUpdateHandler` | `0x141aad9a0` | 更新个人资料 |
| `auth/stop_polling` | — | `off_14361FCB0` | 停止轮询 |
| `auth/switchAccount` | — | `off_14361FCB8` | 切换账号 |
| `auth/syncUserInfo` | — | `off_14361FCC0` | 同步用户信息 |
| `auth/grantInfos` | — | `off_14361FC60` | 授权信息列表 |
| `auth/grantInfosWrap` | — | `off_14361FC68` | 授权信息包装 |

### 2.3 LoginHandler——3 种登录模式路由

**函数：** `LoginHandler` @ `0x141aad0a0`

```go
func LoginHandler(ctx context.Context, params *LoginParams) (*LoginStartResult, error) {
    // 1. 可选：检查 regionEnv 参数，切换区域
    if params.RegionEnv != "" {
        CheckSwitchRegion(params.RegionEnv)
    }
    
    // 2. 可选：检查 loginDedicatedType
    if params.LoginDedicatedType == "standards" {
        UpdateEndpoint(...)
    } else if params.LoginDedicatedType == "dedicated" {
        // 专用部署模式
    }
    
    // 3. 根据 LoginType 字段路由
    switch len(params.LoginType) {
    case 5: // "aksks" → AK/SK 登录
        return HttpServer.LoginWithAkSk(params.AccessKey, params.SecretKey, params.OrgId)
    case 14: // "personalToken" → Personal Token 登录
        return HttpServer.LoginWithPersonalToken(params.PersonalToken, params.UserId)
    default: // "" (空) → 默认 OAuth PKCE 设备码登录
        return HttpServer.LoginStart(ctx)
    }
}
```

| LoginType | 分支条件 | 调用函数 | 参数使用 |
|-----------|----------|----------|---------|
| `""` (空, 默认) | `len != 5 && len != 14` | `LoginStart` @ 0x141a10680 | 无参数，走默认 OAuth |
| `"aksks"` | `len == 5` 字节匹配 | `LoginWithAkSk` @ vtable | AccessKey, SecretKey, OrgId |
| `"personalToken"` | `len == 14` 字符串匹配 | `LoginWithPersonalToken` @ vtable | PersonalToken, UserId |

### 2.4 LoginStart——默认设备码登录

**函数：** `LoginStart` @ `0x141a10680`

```
LoginStart(ctx)
  │
  ├─ 日志: "login start..."
  │
  ├─ PrepareLoginRequest(ctx) → LoginRequestResult
  │   ├─ UUID.NewString() → 32-char nonce
  │   ├─ generatePKCEChallenge() → {Verifier, Challenge, error}
  │   ├─ 构造 OAuth URL 参数
  │   ├─ 存储 nonce → ctx 到全局映射 qword_1460D9528
  │   └─ return {LoginUrl, Nonce, Verifier, Challenge, ChallengeMethod}
  │
  ├─ 失败 → 日志 + return {Success: false}
  │
  ├─ 成功 →
  │   ├─ 再次存储 nonce → ctx 到映射
  │   ├─ 日志: "login with url %s"
  │   ├─ 启动 async goroutine: LoginStart_func1 (超时/取消处理)
  │   └─ return {Url: loginUrl, Success: true}
```

### 2.5 PrepareLoginRequest——OAuth URL 构造

**函数：** `PrepareLoginRequest` @ `0x141a198a0`

**PKCE 挑战生成：** `generatePKCEChallenge` @ `0x141a197a0`

- 生成 code_verifier（随机 43 字符）
- S256 哈希生成 code_challenge
- 挑战方法：`"S256"`（硬编码于 `0x1424AC9D0`）

**URL 参数构建（`cosy_util_BuildParameter` @ vtable）：**

| 参数键 | 长度 | 值来源 | 说明 |
|--------|------|--------|------|
| `"nonce"` | 5 | `UUID`(去横线) | PKCE state 参数 |
| `"port"` | 4 | `HttpServer.Port` | 回调端口（37510） |
| `"state"` | 5 | `UUID`(去横线) | 同 nonce |
| `"challenge"` | 9 | PKCE 生成 | S256 code_challenge |
| `"challenge_method"` | 16 | 硬编码 `"S256"` | |
| `"machine_id"` | 10 | `cosy_util.GetMachineId()` | |
| `"redirect"` | 13 | `GenerateModelScopeLoginRedirect()` | 可选重定向参数 |

**最终 OAuth URL 构造：**
```
https://devops.aliyun.com/lingma/login
  ?nonce={uuid_nodashes}
  &port=37510
  &state={uuid_nodashes}
  &challenge={s256_challenge}
  &challenge_method=S256
  &machine_id={machine_uuid}
  [&redirect={redirect_url}]
```

**Base URL 数据：**
- `"https://devops.aliyun.com/lingma/login"` @ `0x14252655e`（38 字符）
- URL 参数拼接：`BuildParameter`(map) → URL 编码键值对 → 前加 `"?"` 拼接

### 2.6 LoginStart_func1——异步超时 goroutine

**函数：** `LoginStart.func1` @ `0x141a10a20`

在 `LoginStart` 返回 URL 后异步启动，负责：
1. 等待 context 取消或超时
2. 超时/取消时清理 nonce 映射（从 `qword_1460D9528` 删除）

### 2.7 HTTP 服务器路由表

**函数：** `cosy_core_transport_handler_http.CreateHttpServer` @ `0x141b48d00`

| 路由 | 处理函数 | 说明 |
|------|---------|------|
| `/auth/start` | `CreateHttpServer.func1` | 认证启动页 |
| **`/auth/callback`** | `LoginCallback_fm` | **OAuth 回调处理** |
| `/auth/loginWithOrganization` | `LoginCallbackWithOrganization_fm` | 组织登录 |
| `/auth/webview` | `HandleWebViewPage_fm` | WebView 页面 |
| `/ws` | `HandleWebViewWebSocket_fm` | WebView WebSocket |
| `/static/` | `RequestStaticResources_fm` | 静态资源 |

### 2.8 回调参数格式

浏览器重定向到 `http://127.0.0.1:37510/auth/callback` 时携带的参数：

**标准 OAuth 格式（Lingma 正常流程）：**
```
state=<nonce>&auth=<encoded>&token=<encoded>
```

- `state`：PKCE nonce（UUID 去横线，32 字符）
- `auth`：`URL-escape(encodeToString(JSON({UID, AID, Name})))`  
- `token`：`URL-escape(encodeToString(fmt.Sprintf("%s\\n%s\\n%d", Token, RefreshToken, ExpireTime)))`

**自定义格式（独立脚本生成 login URL）：**
```
state=<nonce>&aid=<account_id>&uid=<user_id>&name=<email>
```

两种格式取决于 login URL 的生成方式。Lingma 自身的 `auth/login` LSP 使用标准格式，自定义脚本使用简化的直接参数格式。

### 2.9 核心编码算法

#### encodeToString（自定义 base64 + 块反转）

**函数：** `encodeToString` @ `0x1404549e0`（`code.alibaba.inc.com.cosy.encrypt._ptr_encoding.encodeToString`）

**字母表：**
```
_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!
```

对应标准 base64 字母表 `A-Za-z0-9+/`。

**编码步骤：**
1. 标准 base64 编码（去 padding）
2. 按字母表替换
3. 分 3 块：`BS = ceil(len / 3)`
4. 反转块顺序：`b2 + '$'*pad + b1 + b0`
5. `$` 填充到 4 的倍数

**Python 实现：**
```python
def encode_to_string(data: bytes) -> str:
    encoded = _custom_b64_encode(data)
    E = len(encoded)
    BS = math.ceil(E / 3)
    pad = (4 - E % 4) % 4
    b0, b1, b2 = encoded[:BS], encoded[BS:2*BS], encoded[2*BS:]
    return b2 + '$' * pad + b1 + b0
```

**解码步骤：**
1. 找第一个 `$` → 确定 padding 长度
2. 去掉 padding → 恢复 `b0 + b1 + b2`
3. 反转块顺序恢复原序
4. 字母表反向替换
5. 标准 base64 解码

#### Auth 参数构造（V2 vs V3 格式）

**V2 格式（HTTP 37510 回调，当前版本）:**

```python
def build_auth_v2(uid: str, aid: str, name: str) -> str:
    """V2: UID\\nAID\\nName → encodeToString → URL-escape
       对应 CustomDecryptParts(auth, 3) 解码"""
    raw = f"{uid}\n{aid}\n{name}"
    encoded = encode_to_string(raw.encode())
    return urllib.parse.quote(encoded, safe='')
```

> V2 的 auth 参数是 `UID\nAID\nName` 三行换行分隔的纯文本，不是 JSON！

**V3 格式（LSP `auth/device_login` 路径，`ToLoginAuthCallbackParam` @ `0x141a1ce00`）:**

```python
def build_auth_v3(uid: str, aid: str, name: str) -> str:
    """V3: JSON{UID, AID, Name} → encodeToString → URL-escape
       对应 parseAuthInfoV3 解码"""
    auth_info = {"UID": uid, "AID": aid, "Name": name}
    auth_json = json.dumps(auth_info, separators=(",", ":"))
    encoded = encode_to_string(auth_json.encode())
    return urllib.parse.quote(encoded, safe='')
```

#### TokenString 参数构造

```python
def build_token_string(token: str, refresh_token: str, expire_time: int) -> str:
    formatted = f"{token}\n{refresh_token}\n{expire_time}"
    encoded = encode_to_string(formatted.encode())
    return urllib.parse.quote(encoded, safe='')
```

### 2.10 Nonce（PKCE State）管理

Lingma 维护一个全局 nonce → `context.Context` 映射（`qword_1460D9528`，类型 `map[string]context.Context`）。

**Nonce 创建点（Phase 1 — PrepareLoginRequest / LoginStart）：**
1. 生成 UUID（`github.com/google/uuid.NewString`）
2. 去掉横线（`strings.Replace(uuid, "-", "", -1)`）→ 32 字符 nonce
3. 存入全局映射：`nonce → (context.tab, context.data)`
4. 在异步 goroutine `LoginStart_func1` 中，超时/取消时清理

**Nonce 消费点（Phase 3 — HandleAuthCallback）：**
1. 按 nonce 遍历映射查找匹配 `runtime_mapiterinit + runtime_memequal`
2. 匹配到则取出 context，删除映射条目（`runtime_mapdelete_faststr`）
3. 未匹配 → 返回 `"Invalid login nonce or consumed, ignore"` 错误

**二次 Nonce 生成（Phase 3 — DeviceLogin）：**
在 `auth/device_login` LSP 处理中，`DeviceLogin` @ `0x141a19ee0` 同样生成一个 UUID nonce，用于 `ToLoginAuthCallbackParam` 编码处理（这个 nonce 与 Phase 1 的 OAuth nonce 不同）。

**对应脚本实现：** `tools/lingma_37510_server.py` 中的 `_nonce_map` 字典

---

## 3. Phase 2：37510 Callback 完整处理链路（更新于 2026-05-06）

### 3.1 浏览器回调参数格式说明

当用户在阿里云 OAuth 完成认证后，阿里云自定义登录页面 `https://devops.aliyun.com/lingma/login` 会在客户端 JS 中完成 token 交换，然后重定向浏览器到：

```
http://127.0.0.1:37510/auth/callback?state=<nonce>&auth=<encoded>&token=<encoded>
```

| 参数 | 来源 | 解码方式 | 解码后内容 |
|------|------|----------|-----------|
| `state` | UUID 去横线（32 字符） | 明文 | PKCE nonce |
| `auth` | `encodeToString("UID\\nAID\\nName")` | `CustomDecryptParts(auth, 3)` | `[UID, AID, Name]` 3 部分 |
| `token` | `encodeToString("Token\\nRefreshToken\\nExpireTime")` | `parseAuthToken` | `[Token, RefreshToken, ExpireTime]` |

> **注意**：V2 版本（当前二进制 `off_146011C70` 版本字节 = `'2'`）直接从 query 参数读取 `auth` 和 `token`，使用 `CustomDecryptParts` + `split("\n")` 解码为 3 部分。
>
> V1 版本从 query 参数读取 `aid`、`uid`、`name` 三个独立参数。
>
> ⚠️ **重要：V2 回调格式的 auth 参数是 `UID\nAID\nName`（三行换行分隔），不是 JSON 格式！** JSON 格式 (`{UID, AID, Name}`) 仅在 LSP `auth/device_login` 路径的 V3 解析中使用。

### 3.2 LoginCallback——37510 HTTP 回调入口

**函数：** `LoginCallback` @ `0x141a133a0`

```
LoginCallback(ResponseWriter, Request)
  │
  ├─ ① 设置响应头 Access-Control-Allow-Origin: *
  │
  ├─ ② cosy_util_ParseParameters(Request) → 解析 URL query 参数
  │    提取: "state"(5), "auth"(4), "token"(5) 等
  │
  ├─ ③ 提取 "state" 参数 → 查找 nonce 映射
  │    ├─ runtime_mapaccess1_faststr(qword_1460D9528, state)
  │    ├─ 匹配成功 → 取出 context
  │    └─ 失败 → "Invalid login nonce" → 渲染错误页
  │
  ├─ ④ parseAuthInfo(query_params)  ← ★ 解析 auth/token
  │    ├─ V1: 读取 "aid"(3) + "uid"(3) + "name"(4)
  │    └─ V2(当前): 
  │         ├─ "auth"(4) → CustomDecryptParts(auth, 3)
  │         │    ├─ decodeString (自定义 base64 解码)
  │         │    └─ split("\n", 3) → {UID, AID, Name}
  │         └─ "token"(5) → parseAuthToken(token)
  │              ├─ decodeString
  │              └─ split("\n") → {Token, RefreshToken, ExpireTime}
  │
  ├─ ⑤ 结果检查
  │    ├─ 错误 → reportAuthResult + 渲染错误页
  │    ├─ step==4 && "need" → 渲染 "need" 提示页
  │    └─ 成功 → loginWithUserInfo(LoginInfoContext)  ← ★ 后续流程
```

#### 3.2.1 parseAuthInfo——参数解析（V2 版本）

**函数：** `parseAuthInfo` @ `0x141a21660`

```go
func parseAuthInfo(params map[string]string) LoginInfoContext {
    version := *(*byte)off_146011C70  // '2' (ASCII 50)
    
    if version == '1' {
        // V1: 直接从 query 参数读取 aid, uid, name
        aid = params["aid"]
        uid = params["uid"]
        name = params["name"]
        return {Uid: uid, Aid: aid, Name: name}
    } else {
        // V2: CustomDecryptParts 解码 auth
        // auth = encodeToString("UID\nAID\nName")  ← NOT JSON!
        authEncoded := params["auth"]
        parts := CustomDecryptParts(authEncoded, 3)
        // decodeString → split("\n", 3) → [UID, AID, Name]
        
        // 检查条件 byte_14616BD2F: 某些条件下只返回 auth info 不解析 token
        if someCondition {
            return {Uid: parts[0], Aid: parts[1], Name: parts[2]}
        }
        
        // 解码 token (同样 CustomDecryptParts)
        tokenEncoded := params["token"]
        tokenInfo := parseAuthToken(tokenEncoded)
        // decodeString → split("\n") → [Token, RefreshToken, ExpireTime]
        
        return {
            Uid: parts[0], Aid: parts[1], Name: parts[2],
            Token: tokenInfo[0], RefreshToken: tokenInfo[1], ExpireTime: tokenInfo[2],
        }
    }
}
```

### 3.3 loginWithUserInfo——登录信息处理核心

**函数：** `loginWithUserInfo` @ `0x141a10ac0`

该函数是登录的核心处理流程，负责获取用户授权信息、配额、token，最终完成 COSY 凭据获取：

```
loginWithUserInfo(LoginInfoContext{UserInfo, AuthStatus, ...})
  │
  ├─ ① GetGrantAuthInfosWrap(uid) @ vtable
  │    ├─ API: /api/v3/user/grantAuthInfos
  │    └─ → 返回用户加入的组织/授权列表
  │
  ├─ ② 检查授权列表
  │    ├─ 错误 → "get user joined orgs fail." → 继续处理
  │    ├─ 空列表 → "get user auth list empty."
  │    │    └─ 渲染选择账号页 + 启动 async goroutine (func1)
  │    ├─ 单组织 → 检查 orgId 合法性
  │    │    ├─ 匹配 "personalToken" → CompleteUserLogin()
  │    │    └─ 否则 → completeUserLoginWithOrganization()
  │    └─ 多组织 → handleLoginWithMultiAccountInfos()
  │
  ├─ ③ GetQuotaAndTokenById(uid, name) @ 0x141a16120  ← ★ 远程 API
  │    ├─ ReadQuotaCache() → 本地配额缓存
  │    │   ├─ 缓存有效 (status==4) → 直接返回缓存数据
  │    │   └─ 缓存过期/不存在 →
  │    │        └─ fetchAuthStatusWithUri("/api/v3/user/status") → HTTP POST
  │    │             ├─ buildRequest → addBasicHeaders + addBigModelSignatureHeaders
  │    │             ├─ Signature 模式 (magic="none")
  │    │             └─ 响应 → 解析 AuthStatusResult
  │    │        └─ WriteQuotaCache() → 写入配额缓存
  │    │        └─ UpdateOrgInfo() → 更新组织信息
  │    │        └─ UpdateUserTypeTagAndPrivacy() → 更新用户标签
  │    │
  │    └─ 返回 AuthStatusResult 包含:
  │        {Status, Name, Id, Token, Quota, WhitelistStatus,
  │         Email, OrgId, OrgName, YxUid, AvatarUrl, ...}
  │
  ├─ ④ 状态检查
  │    ├─ 错误状态 (status!=5) → 渲染错误页
  │    ├─ PingBigModelServer() → 检查大模型服务
  │    │   ├─ 成功 → reportAuthResult + 渲染成功页 (step=2)
  │    │   └─ 失败 → 渲染 "服务不可用" 页
  │    └─ 正常 → 进 CompleteUserLogin (见 3.5)
```

### 3.4 GetQuotaAndTokenById——配额与 Token 获取

**函数：** `GetQuotaAndTokenById` @ `0x141a16120`

```
GetQuotaAndTokenById(httpServer, uid, name)
  │
  ├─ ReadQuotaCache(uid) → 读取本地配额缓存
  │   ├─ 格式: 缓存文件中的结构化数据
  │   └─ 检查 status==4 → 有效
  │
  ├─ 缓存有效:
  │   └─ 直接返回 {Status, Id, Name, Quota, WhitelistStatus, Email, ...}
  │
  └─ 缓存无效:
      ├─ fetchAuthStatusWithUri("/api/v3/user/status", uid) → HTTP POST
      │   └─ 签名: Signature 模式 (magic="none")
      │
      ├─ WriteQuotaCache() → 写入配额缓存
      │
      ├─ 如果响应包含 org_info:
      │   ├─ UpdateOrgInfo() → 更新组织信息
      │   └─ SaveUserInfo() → 保存用户信息
      │
      ├─ 如果响应包含 user_type_tag:
      │   └─ UpdateUserTypeTagAndPrivacy() → 更新标签
      │
      └─ 构建 AuthStatusResult → 返回
```

### 3.5 CompleteUserLogin——完成登录 & COSY 凭据获取

**函数：** `CompleteUserLogin` @ `0x141a12200`

```
CompleteUserLogin(LoginInfoContext, ResponseWriter)
  │
  ├─ determineUserType() → 确定用户类型标志
  │
  ├─ 构建 UserInfo 结构
  │   {Name, Aid, Uid, ..., SecurityOauthToken, RefreshToken, ExpireTime,
  │    Email, AvatarUrl, PrivacyPolicy, ...}
  │
  ├─ saveUserInfoAndQuota() → ★ 加密保存到磁盘
  │   ├─ AES-128-CBC(key=IV=machine_id[:16]) 加密
  │   ├─ base64 编码
  │   └─ 写入 ~/.lingma/cache/user
  │
  ├─ 失败 → reportAuthResult ERROR + 渲染错误页
  │
  └─ 成功 →
      ├─ 判断登录结果页类型:
      │   ├─ status==6 → 页类型 5
      │   ├─ status==7 → 页类型 6
      │   └─ 否则 → 根据 quota/whitelist 判断
      ├─ 渲染登录成功页
      └─ runtime_newproc → 启动 async goroutine:
           └─ CompleteUserLogin_gowrap1  → 异步后续处理
```

### 3.6 API 端点清单

**来源：** `cosy_remoting_api._ptr_APIPathRegistry.initDefaultPaths` @ `0x140848c60`

| 端点 | 用途 | 实测状态 |
|------|------|---------|
| `/api/v3/user/login` | 用户登录（凭证交换） | ⚠️ WAF 403 |
| `/api/v3/user/status` | 用户状态+配额查询 | ⚠️ WAF 403 |
| `/api/v3/user/logout` | 登出 | — |
| `/api/v3/user/region` | 地域查询 | — |
| `/api/v3/user/remoteToken` | 远程 token 管理 | — |
| `/api/v3/user/data_region` | 数据地域 | — |
| `/api/v3/user/refresh_token` | Token 刷新 | **404** 国际 / **403** 国内 |
| `/api/v3/user/grantAuthInfos` | 授权信息 | — |
| `/api/v3/user/oauth2/deviceToken/poll` | 设备令牌轮询 | — |

### 3.7 完整请求头构造

**函数：** `addBasicHeaders` @ `0x14087ef20` + `addBigModelSignatureHeaders` @ `0x14087e5e0`

```python
headers = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "Accept-Encoding": "gzip",
    "User-Agent": f"Cosy/{version}",
    "X-Forwarded-For": "<machine_ip>",
    "Cosy-MachineId": machine_id,
    "Cosy-MachineToken": "",
    "Cosy-MachineType": "",
    "Cosy-MachineCode": "",
    "Cosy-MachineOS": "x86_64_windows",
    "Cosy-ClientType": "2",    # "0" 或 "2"
    "Cosy-Version": cosy_version,
    "Date": rfc1123_date,
    "Cosy-Date": rfc1123_date,
    "Cosy-User": base64(body),
    "Signature": md5_sign(encoded, date),
}
```

### 3.8 MD5 签名算法

```python
COSY_KEY = "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="          # base64("war, war never changes")
ALT_COSY_KEY = "&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe"     # 备用 key

def md5_sign(encoded_body: str, date_str: str, use_alt_key: bool = False) -> str:
    key = ALT_COSY_KEY if use_alt_key else COSY_KEY
    raw = f"{encoded_body}&{key}&{date_str}"
    return hashlib.md5(raw.encode()).hexdigest()
```

**公式：** `MD5(base64(body) + "&" + key + "&" + RFC1123_date)`

### 3.9 认证模式选择

**函数：** `buildRequest` @ `0x14087cc20`

根据请求路径的 magic 值选择两种认证模式：

| Magic 值 | 模式 | 说明 |
|----------|------|------|
| `0x6e6f6e65` = `"none"` | **Signature 模式** | MD5 签名，用于 refresh_token |
| `0x68747470` = `"http"` | **Authorization 模式** | Bearer token，用于 Chat API |

---

## 4. Phase 3：凭据加密存储

### 4.1 cache/user 结构

Lingma 收到 COSY 凭据后，进行 AES-128-CBC 加密写入 `~/.lingma/cache/user`：

```
COSY 凭据 (JSON)
  ├─ cosy_key: 172 chars          ← Chat API 的 Bearer token
  ├─ encrypt_user_info: 664 chars  ← Chat API 的 X-Cosy-Encrypt-User-Info
  ├─ security_oauth_token: pt-xxx  ← OAuth Bearer token
  ├─ refresh_token: rt-yyyy        ← OAuth 刷新 token
  └─ expire_time: 1782961487221    ← 过期时间戳(ms)
         │
         ▼ AES-128-CBC(key=IV=machine_id[:16])
         ▼ base64 编码
         ▼ 写入 ~/.lingma/cache/user
```

**关键函数：**
- `CompleteUserLogin` @ `0x141a12200` — 完成登录 + 加密存储
- `SaveUserInfo` @ `0x14088e260` — 保存用户信息

### 4.2 解密实现

**工具：** `tools/credential_extractor.py`

```python
def decrypt_cache_user(lingma_dir):
    machine_id = open(lingma_dir / 'cache' / 'id').read().strip()
    encrypted = base64.b64decode(open(lingma_dir / 'cache' / 'user', 'rb').read())
    key = machine_id[:16].encode()
    cipher = Cipher(algorithms.AES(key), modes.CBC(key))
    decrypted = cipher.decryptor().update(encrypted) + cipher.decryptor().finalize()
    decrypted = decrypted[:-decrypted[-1]]  # PKCS7 unpadding
    return json.loads(decrypted.decode())
```

---

## 5. Phase 4：Chat API 调用

### 5.1 确认结论

**Chat API 不需要 Encode=1 编码，直接发送原始 JSON body。**

### 5.2 请求格式

```
POST /algo/api/v2/service/pro/sse/agent_chat_generation
Host: lingma.alibabacloud.com
Authorization: Bearer <cosy_key>
X-Cosy-Encrypt-User-Info: <encrypt_user_info>
Content-Type: application/json

{
    "model": "qwen_max",
    "messages": [{"role": "user", "content": "你好"}],
    "stream": true
}
```

### 5.3 客户端实现

**工具：** `lingma_remote_api.py`

支持 4 种凭据来源：
1. **环境变量**（推荐，完全脱离本地）
2. **便携配置文件** `portable_config.json`
3. **直接传参**
4. **本地 Lingma 缓存**（需安装 Lingma）

### 5.4 验证结果 ✅

```
输入： "你好，用一句话介绍你自己"
输出： "你好，我是Qwen，是通义实验室开发的超大规模语言模型，
        能够帮助你回答问题、创作文字、编程等任务。"
```

---

## 6. Phase 5：Token 刷新

### 6.1 LSP 路径（本地有效）

```
LSP: auth/refreshToken
  └─ doRefreshToken @ 0x14088d660
       └─ BuildBigModelSignRequest(method="POST", path="/api/v3/user/refresh_token", payload)
            └─ buildRequest → addBigModelSignatureHeaders
                 └─ HTTP POST → 响应 → 更新缓存
```

**请求体：**
```json
{
    "UserId": "...",
    "OrgId": "...",
    "SecurityOauthToken": "pt-xxxx",
    "RefreshToken": "rt-yyyy"
}
```

**响应成功条件：** `StatusCode == 200` 且 body 不含 `"success":false`

### 6.2 远程路径（WAF 拦截）

```
POST /algo/api/v3/user/refresh_token
```

- 国际服务器 `lingma.alibabacloud.com`：**404**（未部署）
- 国内服务器 `lingma-api.tongyi.aliyun.com`：**403**（WAF）

---

## 7. 实现状态总览

| 模块 | 脚本/工具 | 状态 |
|------|-----------|------|
| LSP WebSocket 通信 | `lingma_37510_server.py` `get_login_url_via_lsp()` | ✅ |
| 自定义 base64 编码 | `lingma_remote_api.py` `lingma_encode/decode` | ✅ 已验证 |
| MD5 签名 | `lingma_37510_server.py` `md5_sign()` | ✅ |
| 请求头构造 | `lingma_37510_server.py` `build_headers()` | ✅ |
| Auth 参数编码 | `lingma_37510_server.py` `build_auth_string()` | ✅ |
| 37510 HTTP 服务器 | `lingma_37510_server.py` `CallbackHandler` | ✅ 已验证 |
| 凭据解密 | `credential_extractor.py` | ✅ 已验证 |
| Chat API | `lingma_remote_api.py` `chat()` | ✅ **已验证** |
| 后端 API 调用 | `lingma_37510_server.py` `call_user_login/status` | ⚠️ WAF |
| Token 刷新 | — | ⚠️ 阻塞 |
| 自动流程 | `lingma_37510_auto.py` | ✅ 已验证 |

---

## 8. 脚本入口

| 用途 | 命令 |
|------|------|
| 解密本地凭据并使用 | `python tools/credential_extractor.py --save` |
| Chat API 测试 | `python -c "from lingma_remote_api import LingmaRemoteAPI; api=LingmaRemoteAPI(); print(api.chat('你好'))"` |
| 37510 回调模拟（需 Lingma 运行） | `python tools/lingma_37510_auto.py` |
| 仅启动回调服务器 | `python tools/lingma_37510_server.py` |

---

## 附录：IDA 关键函数地址表（更新于 2026-05-05）

### LSP Handler 注册 & 路由

| 函数 | 地址 | 大小 | 作用 |
|------|------|------|------|
| `InitHandlers` | `0x141aadb20` | — | 认证 LSP handler 注册入口 |
| `auth_login.InitHandlers` | — | — | `auth/login` handler 注册 |
| `LoginHandler` | `0x141aad0a0` | — | **LSP `auth/login` 入口，3 种模式路由** |
| `LogoutHandler` | `0x141aac0c0` | — | LSP `auth/logout` |
| `StatusHandler` | `0x141aadd60` | — | LSP `auth/status` |
| `ProfileGetUrlHandler` | `0x141aad6a0` | — | LSP `auth/profile/getUrl` |
| `ProfileGetGlobalConfigHandler` | `0x141aad780` | — | LSP `auth/profile/getGlobalConfig` |
| `ProfileUpdateHandler` | `0x141aad9a0` | — | LSP `auth/profile/update` |

### Phase 1：OAuth 登录 URL 生成

| 函数 | 地址 | 大小 | 作用 |
|------|------|------|------|
| `LoginStart` | `0x141a10680` | — | **默认设备码登录：调用 PrepareLoginRequest + 启动 goroutine** |
| `LoginStart.func1` | `0x141a10a20` | — | 异步 goroutine，超时/取消时清理 nonce |
| `PrepareLoginRequest` | `0x141a198a0` | — | **构造 PKCE OAuth URL（核心 URL 生成）** |
| `generatePKCEChallenge` | `0x141a197a0` | — | PKCE Verifier + S256 Challenge 生成 |
| `LoginCallback` | `0x141a133a0` | — | 37510 HTTP `/auth/callback` 处理器 |
| `LoginCallbackWithOrganization` | `0x141a13d40` | — | 组织登录回调处理器 |
| `LoginCallback_fm` | `0x141b499c0` | `0x77` | 回调 HTTP handler 包装 |
| `CreateHttpServer` | `0x141b48d00` | `0x414` | 37510 HTTP 服务器 |

### Phase 2：37510 Callback 处理 & COSY 凭据获取

| 函数 | 地址 | 大小 | 作用 |
|------|------|------|------|
| `LoginCallback` | `0x141a133a0` | — | **★ 37510 HTTP `/auth/callback` 入口** |
| `parseAuthInfo` | `0x141a21660` | — | V1/V2 参数解析路由 |
| `parseAuthInfoV2` | `0x141a21800` | — | V2: `auth`=`CustomDecryptParts` + `token`=`parseAuthToken` |
| `CustomDecryptParts` | `0x140455ca0` | — | decodeString + split 解码 |
| `loginWithUserInfo` | `0x141a10ac0` | — | **★ 登录处理核心**（授权检查 + 配额获取 + 凭据保存） |
| `loginWithUserInfo.func1` | `0x141a11940` | — | 异步 goroutine（多账号选择超时） |
| `GetQuotaAndTokenById` | `0x141a16120` | `0x9c0` | **★ 用户配额/状态获取**（ReadQuotaCache / fetchAuthStatus） |
| `GetGrantAuthInfosWrap` | — | — | 用户组织/授权信息 API |
| `CompleteUserLogin` | `0x141a12200` | — | **★ 完成登录 + 加密存储 COSY 凭据** |
| `CompleteUserLogin.gowrap1` | `0x141a12a40` | — | 异步 post-login goroutine |
| `completeUserLoginWithOrganization` | `0x141a12c00` | — | 组织指定登录完成 |
| `handleLoginWithMultiAccountInfos` | `0x141a11980` | — | 多账号选择处理 |
| `loginResultPageWithStep` | `0x141a146c0` | — | HTML 结果页面渲染 |
| `reportAuthResult` | `0x141a18940` | — | 认证结果上报 |
| `DeviceLoginHandler` | `0x141aac2a0` | `0x7ad` | LSP `auth/device_login` 处理器 |
| `DeviceLogin` | `0x141a19ee0` | `0x7ad` | nonce 生成 + ToLoginAuthCallbackParam |
| `HandleAuthCallback` | `0x141a18dc0` | `0x720` | LSP 回调处理（parseAuthInfoV3 + parseAuthToken） |
| `CompleteLoginWithSelectAccount` | `0x141a0fee0` | `0x600` | 登录完成 + COSY 凭据获取 |
| `ToLoginAuthCallbackParam` | `0x141a1ce00` | `0x5c0` | auth/token 参数编码（encodeToString + URL 转义） |
| `parseAuthInfoV3` | `0x141a21b80` | — | V3: URL unescape → decodeString → JSON |
| `parseAuthToken` | `0x141a213e0` | — | Token 参数解析 |
| `fetchAuthStatusWithUri` | `0x141a1f260` | — | API 状态查询（HTTP POST + Signature 签名） |
| `saveUserInfoAndQuota` | — | — | AES 加密 + 写入 cache/user |

### 编码 & 加密

| 函数 | 地址 | 大小 | 作用 |
|------|------|------|------|
| `encodeToString` | `0x1404549e0` | — | 自定义 base64 编码（Encode=1） |

### HTTP 请求构造 & 签名

| 函数 | 地址 | 大小 | 作用 |
|------|------|------|------|
| `buildRequest` | `0x14087cc20` | — | HTTP 请求构造 + 认证模式选择 |
| `addBasicHeaders` | `0x14087ef20` | — | 基础请求头 |
| `addBigModelSignatureHeaders` | `0x14087e5e0` | — | MD5 签名头（Signature 模式） |
| `addBigModelAuthorizationHeaders` | `0x14087ea20` | — | Bearer 认证头（Authorization 模式） |
| `Md5Encode` | `0x1404563c0` | — | strings.Join + MD5 |
| `initDefaultPaths` | `0x140848c60` | `0x41cf` | API 路径注册 |

### Token 刷新

| 函数 | 地址 | 大小 | 作用 |
|------|------|------|------|
| `doRefreshToken` | `0x14088d660` | — | Token 刷新远程调用 |
| `RefreshTokenHandler` | `0x141aaf7e0` | — | LSP `auth/refreshToken` 处理器 |
| `RefreshUserInfoSecurityToken` | `0x14088f180` | — | 更新缓存 + 广播 |
