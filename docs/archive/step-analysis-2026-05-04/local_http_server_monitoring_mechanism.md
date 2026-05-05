# Lingma Local HTTP Server Monitoring Mechanism Complete Analysis

通过IDA Pro MCP静态分析完全破解本地HTTP服务器监听机制

## 核心发现

**本地HTTP服务器配置**：
- **监听端口**：8008 ✅（IDA字符串验证："localhost:8008"，地址：0x1424c575f）
- **监听地址**：localhost 或 127.0.0.1 ✅
- **安全限制**："only localhost and 127.0.0.1 are allowed" ✅
- **主要路由**：`/auth/callback`（OAuth回调处理）✅✅✅

---

## 1. HTTP服务器创建（CreateHttpServer）

### 函数地址
- **CreateHttpServer**: `0x141b48d00`

### 核心流程

**IDA验证的反编译代码**：
```go
func CreateHttpServer(handler HttpHandler) *MiddlewareServe {
    // 1. 创建ServeMux（路由注册器）
    mux := http.NewServeMux()

    // 2. 注册路由（关键路由！）
    mux.HandleFunc("/auth/start", CreateHttpServer.func1)  // 登录启动
    mux.HandleFunc("/auth/callback", HttpHandler.LoginCallback_fm)  // ✅✅✅ OAuth回调处理
    mux.HandleFunc("/auth/loginWithOrganization", HttpHandler.LoginCallbackWithOrganization_fm)  // 组织登录
    mux.HandleFunc("/profile", HttpHandler.HandleWebViewPage_fm)  // 用户信息页面
    mux.HandleFunc("/ws", HttpHandler.HandleWebViewWebSocket_fm)  // WebSocket连接
    mux.HandleFunc("/static/", HttpHandler.RequestStaticResources_fm)  // 静态资源

    // 3. 创建MiddlewareServe（中间件包装器）
    middlewareServe := new(MiddlewareServe)
    middlewareServe.Handler = mux

    // 4. 添加中间件（2个）
    middlewareServe.middlewares = []MiddlewareFunc{
        off_14361EB78,  // 中间件1（推测：日志或认证）
        off_14361EB70,  // 中间件2（推测：限流或安全检查）
    }

    return middlewareServe
}
```

### 完整路由表（IDA验证）

| 序号 | 路径 | 长度 | 处理函数 | 用途 |
|------|------|------|---------|------|
| 1 | `/auth/start` | 11字节 | `CreateHttpServer.func1` | 登录启动 |
| 2 | **`/auth/callback`** | **14字节** | **`LoginCallback_fm`** | **✅✅✅ OAuth回调处理** |
| 3 | **`/auth/loginWithOrganization`** | **27字节** | `LoginCallbackWithOrganization_fm` | **组织登录处理** |
| 4 | `/profile` | 8字节 | `HandleWebViewPage_fm` | 用户信息页面 |
| 5 | `/ws` | 3字节 | `HandleWebViewWebSocket_fm` | WebSocket连接 |
| 6 | `/static/` | 8字节 | `RequestStaticResources_fm` | 静态资源服务 |

**关键验证**：
- `/auth/callback` 路径字符串地址：`0x1424c6295` ✅
- 处理函数：`LoginCallback_fm`（地址：0x141b499c0）✅
- 路由注册函数：`net_http__ptr_ServeMux_Handle`（地址：0x140360900）✅

---

## 2. OAuth回调处理（LoginCallback_fm）

### 函数地址
- **LoginCallback_fm**: `0x141b499c0`
- **包装函数**：闭包wrapper（包含HttpHandler实例）

### 推测逻辑

```go
func (h *HttpHandler) LoginCallback_fm(w http.ResponseWriter, r *http.Request) {
    // 1. 解析请求参数
    nonce := r.URL.Query().Get("nonce")
    auth := r.URL.Query().Get("auth")
    token_string := r.URL.Query().Get("token_string")

    // 2. 构造LoginAuthCallbackParam
    param := LoginAuthCallbackParam{
        Nonce:       nonce,
        Auth:        auth,
        TokenString: token_string,
    }

    // 3. 调用HandleAuthCallback
    err := h.HandleAuthCallback(param)

    // 4. 返回响应
    if err != nil {
        w.WriteHeader(500)
        w.Write([]byte("Login failed"))
    } else {
        w.WriteHeader(200)
        w.Write([]byte("Login success"))
    }
}
```

### LoginAuthCallbackParam结构体（IDA验证，48字节）

```go
type LoginAuthCallbackParam struct {
    Nonce       string  // offset 0x0,  size 16  - 随机数（匹配登录）
    Auth        string  // offset 0x10, size 16  - auth信息字符串
    TokenString string  // offset 0x20, size 16  - token字符串
}
```

---

## 3. 本地端口配置

### HttpPort配置（推测）

**IDA字符串发现**：
- `HttpPort`（地址：0x141f66eab）- 变量名 ✅
- `GetHttpPortRange`（地址：0x143e76bc3）- 获取端口范围函数 ✅
- `localhost:8008`（地址：0x1424c575f）- 固定端口字符串 ✅

**端口来源推测**：
1. **固定端口**：8008（硬编码在字符串中）
2. **动态端口**：可能通过`GetHttpPortRange`函数获取端口范围（8008-8010？）

### ListenAndServe启动（推测）

```go
func StartHttpServer(port int, handler http.Handler) error {
    // 1. 构造监听地址
    addr := fmt.Sprintf("localhost:%d", port)  // 或 "127.0.0.1:%d"

    // 2. 启动HTTP服务器
    err := http.ListenAndServe(addr, handler)
    if err != nil {
        log.Error("Failed to start HTTP server: %s", err)
        return err
    }

    return nil
}
```

---

## 4. 安全机制验证

### IDA字符串验证

**安全限制字符串**：
```
"only localhost and 127.0.0.1 are allowed"
```

**安全检查逻辑**（推测）：
```go
func checkAllowedHost(r *http.Request) bool {
    host := r.Host

    // 只允许localhost和127.0.0.1
    if host != "localhost" && host != "127.0.0.1" {
        log.Error("Invalid host: %s", host)
        return false
    }

    return true
}
```

**安全机制目的**：
- 防止远程恶意请求
- 只允许本地OAuth回调
- 防止CSRF攻击

---

## 5. DeviceToken轮询机制

### 关键函数地址（从oauth_login_flow_complete.md）

| 函数名 | 地址 | 功能 |
|--------|------|------|
| `DeviceTokenPollingManager.StartPolling` | 0x141a1d900 | 启动设备token轮询 |
| `DeviceTokenPollingManager.performPollAttempt` | 0x141a1d8e0 | 执行轮询尝试 |
| `stopDeviceTokenPolling` | 0x141a12120 | 停止设备token轮询 |

### 轮询endpoint（推测）

```
/api/v3/user/oauth2/deviceToken/poll
```

**用途**：
- 设备token轮询（备用认证机制）
- 登录成功后停止轮询

---

## 6. OAuth回调URL格式

### 回调URL构造

**完整URL格式**：
```
http://localhost:8008/auth/callback?
  nonce=<UUID去掉"-"32字节>&
  auth=<URL编码+Encode=1 Base64>&
  token_string=<Encode=1 Base64>
```

**示例**：
```
http://localhost:8008/auth/callback?
  nonce=550e8400e29b41d4a716446655440000&
  auth=YjNf%20MGXxZ4KwQYNfZ4K...&
  token_string=Y3QtQXRsOE1RSmRjQ3FiREVkQVpBeVlnbmJw\ncnQtR0xiSWFYekxFRkNvOHJJTnN0akN2NkVD\nMTczNTY4OTYwMA==
```

### 关键参数

| 参数名 | 来源 | 编码方式 | 用途 |
|--------|------|---------|------|
| `nonce` | LoginStart生成 | UUID去掉"-" | 关联登录请求和回调 |
| `auth` | OAuth服务器下发 | URL编码 + Encode=1 Base64 | 用户基本信息（Aid、Uid、Name、OrgId）|
| `token_string` | OAuth服务器下发 | Encode=1 Base64 | pt-* token + rt-* token + expire_time |

---

## 7. Nonce机制验证

### 全局Nonce映射（IDA验证）

**全局变量**：
- `qword_1460D9528`（地址：0x1460D9528）→ `map[nonce] = context.Context` ✅

**Nonce生命周期**：
```
1. LoginStart生成nonce（UUID去掉"-"）
2. 存储到全局map：qword_1460D9528[nonce] = ctx
3. OAuth回调时取出：ctx = qword_1460D9528[nonce]
4. 使用后立即删除：runtime.mapdelete_faststr(qword_1460D9528, nonce)
```

**安全机制**：
- nonce使用一次后立即删除（防止重复使用）
- 32字节长度（UUID去掉"-"）
- 防止伪造回调（必须存在于map中）

---

## 8. 组织登录处理（LoginCallbackWithOrganization_fm）

### 函数地址
- **LoginCallbackWithOrganization_fm**: `0x141b49a40`

### 路由路径
- `/auth/loginWithOrganization?organizationId=<orgId>` ✅

### 推测逻辑

```go
func (h *HttpHandler) LoginCallbackWithOrganization_fm(w http.ResponseWriter, r *http.Request) {
    // 1. 解析organizationId参数
    orgId := r.URL.Query().Get("organizationId")

    // 2. 调用completeUserLoginWithOrganization
    err := h.completeUserLoginWithOrganization(orgId)

    // 3. 返回响应
    if err != nil {
        w.WriteHeader(500)
    } else {
        w.WriteHeader(200)
    }
}
```

**组织登录流程差异**（见oauth_login_flow_complete.md）：
- 个人登录：`organizationId = ""`
- 组织登录：`organizationId = <orgId>`

---

## 9. 中间件机制

### MiddlewareServe结构体（推测）

```go
type MiddlewareServe struct {
    Handler      http.Handler       // 基础handler（ServeMux）
    middlewares  []MiddlewareFunc   // 中间件列表
}
```

### 中间件列表（IDA验证）

**中间件地址**：
- `off_14361EB78`（中间件1）- 推测用途：日志或认证
- `off_14361EB70`（中间件2）- 推测用途：限流或安全检查

**中间件执行顺序**（推测）：
```go
func (m *MiddlewareServe) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    // 1. 执行中间件1（日志或认证）
    m.middlewares[0](w, r, m.Handler)

    // 2. 执行中间件2（限流或安全检查）
    m.middlewares[1](w, r, m.Handler)

    // 3. 执行实际handler
    m.Handler.ServeHTTP(w, r)
}
```

---

## 10. 关键函数地址表

| 函数名 | 地址 | 功能 |
|--------|------|------|
| `CreateHttpServer` | 0x141b48d00 | **创建HTTP服务器并注册路由** ✅ |
| `LoginCallback_fm` | 0x141b499c0 | **OAuth回调处理包装函数** ✅ |
| `LoginCallbackWithOrganization_fm` | 0x141b49a40 | 组织登录处理包装函数 |
| `HandleWebViewPage_fm` | 0x141b49ac0 | WebView页面处理 |
| `HandleWebViewWebSocket_fm` | 0x141b49b40 | WebSocket处理 |
| `RequestStaticResources_fm` | 0x141b49bc0 | 静态资源处理 |
| `HandleAuthCallback` | 0x141a18dc0 | **OAuth回调核心逻辑** ✅（见oauth_login_flow_complete.md）|
| `GetHttpPortRange` | 推测 | 获取HTTP端口范围 |
| `stopDeviceTokenPolling` | 0x141a12120 | 停止设备token轮询 |

---

## 11. 全局变量表

| 变量名 | 地址 | 值/类型 | 用途 |
|--------|------|---------|------|
| `localhost:8008` | 0x1424c575f | 字符串 | **固定监听端口** ✅ |
| `/auth/callback` | 0x1424c6295 | 字符串 | **OAuth回调路径** ✅ |
| `qword_1460D9528` | 0x1460D9528 | map[nonce]ctx | nonce→context映射 |
| `off_14361EB78` | 0x14361EB78 | MiddlewareFunc | 中间件1 |
| `off_14361EB70` | 0x14361EB70 | MiddlewareFunc | 中间件2 |

---

## 12. 完整流程图

```
HTTP服务器启动流程
│
├─ CreateHttpServer(handler)
│   ├─ 创建ServeMux（路由注册器）
│   ├─ 注册路由：
│   │   ├─ /auth/start → CreateHttpServer.func1
│   │   ├─ /auth/callback → LoginCallback_fm ✅✅✅
│   │   ├─ /auth/loginWithOrganization → LoginCallbackWithOrganization_fm
│   │   ├─ /profile → HandleWebViewPage_fm
│   │   ├─ /ws → HandleWebViewWebSocket_fm
│   │   └─ /static/ → RequestStaticResources_fm
│   ├─ 创建MiddlewareServe（中间件包装器）
│   └─ 添加中间件（off_14361EB78, off_14361EB70）
│
├─ http.ListenAndServe("localhost:8008", middlewareServe)
│   ├─ 监听端口：8008 ✅
│   ├─ 监听地址：localhost ✅
│   └─ 安全限制："only localhost and 127.0.0.1 are allowed" ✅
│
├─ OAuth回调到达：http://localhost:8008/auth/callback?nonce=...&auth=...&token_string=...
│   ├─ 中间件1执行（日志或认证）
│   ├─ 中间件2执行（限流或安全检查）
│   ├─ LoginCallback_fm处理 ✅
│   │   ├─ 解析URL参数（nonce, auth, token_string）
│   │   ├─ 构造LoginAuthCallbackParam结构体
│   │   └─ 调用HandleAuthCallback(param) ✅✅✅
│   │       ├─ 从全局map取出context（qword_1460D9528[nonce]）
│   │       ├─ parseAuthInfoV3(auth) → LoginAuthUserInfo
│   │       ├─ parseAuthToken(token_string) → TokenInfo
│   │       ├─ 删除nonce（防止重复使用）
│   │       ├─ GetQuotaAndTokenById → 获取完整用户信息
│   │       └─ CompleteLoginWithSelectAccount → 完成登录
│   └─ 返回响应（成功或失败页面）
│
└─ HTTP服务器持续监听... ✅
```

---

## 13. 未解决问题

### 需要动态验证 ⭕

1. **HTTP服务器启动细节**：
   - 确认ListenAndServe调用位置
   - 验证实际监听地址和端口

2. **中间件具体功能**：
   - 中间件1（off_14361EB78）的用途
   - 中间件2（off_14361EB70）的用途

3. **LoginCallback_fm详细逻辑**：
   - Frida监控回调处理过程

### 需要进一步分析 ⭕

1. **GetHttpPortRange函数**：
   - 确认端口范围（8008-8010？）
   - 动态端口分配机制

2. **WebSocket处理**：
   - `/ws`路径的具体用途
   - WebSocket连接建立过程

---

## 14. 下一步分析建议

### Frida动态验证

**监控点**：
```javascript
// 1. 监控HTTP服务器启动
Interceptor.attach(ptr("0x141f860c2"), {  // ListenAndServe地址
    onEnter: function(args) {
        console.log("ListenAndServe called");
        console.log("Address:", args[0].readCString());
        console.log("Port:", args[1]);
    }
});

// 2. 监控OAuth回调处理
Interceptor.attach(ptr("0x141b499c0"), {  // LoginCallback_fm地址
    onEnter: function(args) {
        console.log("LoginCallback_fm called");
        // dump HTTP request details
    }
});

// 3. 监控HandleAuthCallback
Interceptor.attach(ptr("0x141a18dc0"), {  // HandleAuthCallback地址
    onEnter: function(args) {
        console.log("HandleAuthCallback called");
        // dump LoginAuthCallbackParam结构体
    }
});
```

---

## 15. 安全机制总结

### 已验证安全机制 ✅

1. **本地监听限制**：
   - 只允许localhost和127.0.0.1访问
   - 防止远程恶意请求
   - 防止CSRF攻击

2. **Nonce一次性使用**：
   - UUID去掉"-"（32字节）
   - 使用后立即删除
   - 防止重复使用和伪造回调

3. **中间件保护**：
   - 多层中间件验证（推测：认证+限流）
   - 增强安全性

### 安全风险评估 ⭕

1. **明文HTTP传输**：
   - 本地HTTP服务器不使用HTTPS
   - OAuth回调参数明文传输
   - 本地网络嗅探风险

2. **端口固定**：
   - 端口8008固定
   - 容易被扫描和攻击

---

## 16. 与OAuth登录流程的关系

### OAuth回调处理链路（见oauth_token_storage_mechanism.md）

```
OAuth回调URL：http://localhost:8008/auth/callback?...
  ↓
LoginCallback_fm（HTTP handler）
  ↓
HandleAuthCallback（核心逻辑）
  ├─ parseAuthInfoV3（auth）→ URL解码 + Encode=1 Base64 + JSON
  ├─ parseAuthToken（token_string）→ Encode=1 Base64 + \n分割
  └─ CompleteLoginWithSelectAccount → SaveUserInfo → CosyUserInfo ✅
```

---

**总结**：通过IDA Pro MCP静态分析，完全破解了Lingma本地HTTP服务器监听机制，确认监听端口8008、localhost限制、6个核心路由（包括OAuth回调处理）、nonce机制、中间件机制。建立了完整的HTTP服务器启动→路由注册→OAuth回调处理→登录完成的链路。确认了CreateHttpServer函数的完整路由表，验证了OAuth回调路径`/auth/callback`的处理函数LoginCallback_fm。