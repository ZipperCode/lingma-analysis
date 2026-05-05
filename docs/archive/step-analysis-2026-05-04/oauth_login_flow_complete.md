# Lingma OAuth Login Flow Complete Analysis

通过IDA Pro MCP静态分析完整破解OAuth登录流程

## 流程概述

**完整登录链条**：
```
1. LoginStart (auth/start) → 生成登录URL
2. 用户浏览器操作 → 访问URL并登录
3. OAuth回调 → 重定向到localhost:8008/auth/callback
4. HandleAuthCallback → 解析auth和token，完成登录
```

---

## 1. 登录流程初始化（LoginStart）

### 函数地址

- **LoginStart**: `0x141a10680`
- **PrepareLoginRequest**: `0x141a198a0`
- **generatePKCEChallenge**: `0x141a197a0`

### 核心逻辑

#### Step 1: 生成Nonce（UUID去掉"-"）

```go
uuid := github.com/google/uuid.NewString()  // 生成UUID
nonce := strings.Replace(uuid, "-", "", -1) // 去掉所有"-"
```

**Nonce作用**：
- 关联登录请求和OAuth回调
- 防止重复登录
- 存储在全局map `qword_1460D9528` 中

#### Step 2: 存储Context

```go
qword_1460D9528[nonce] = ctx  // map[nonce] = context
```

**目的**：在OAuth回调时能取出对应的context继续处理

#### Step 3: 生成PKCE Challenge

```go
pkce := generatePKCEChallenge()
```

**返回结构**（推测）：
```go
type PKCEChallenge struct {
    Verifier  string  // code_verifier（随机字符串）
    Challenge string  // code_challenge（SHA256(verifier)）
    Method    string  // "S256"
}
```

**PKCE机制**：
- **Verifier**：客户端生成的随机字符串
- **Challenge**：SHA256哈希后的Verifier
- **Method**：固定值 "S256"
- **作用**：防止授权码拦截攻击

#### Step 4: 构造URL参数

```go
params := map[string]string{
    "nonce":            nonce,              // UUID去掉"-"
    "port":            strconv.FormatInt(HttpPort, 10),  // 8008
    "verifier":        pkce.Verifier,       // code_verifier
    "challenge":       pkce.Challenge,      // code_challenge
    "challenge_method": "S256",             // 固定值（4字节）
    "machine_id":      GetMachineId(),      // 设备ID
}
```

**关键参数确认**：
- `"nonce"`: UUID去掉"-"（长度32字节）
- `"port"`: 本地HTTP服务器端口（8008）
- `"verifier"`: PKCE code_verifier
- `"challenge"`: PKCE code_challenge（SHA256哈希）
- `"challenge_method"`: "S256"（IDA验证，4字节）
- `"machine_id"`: 设备唯一标识

**可选参数**：
- `"redirect"`: ModelScope登录重定向地址

#### Step 5: 构造完整登录URL

```go
queryString := BuildParameter(params)  // URL编码参数
loginUrl := "https://lingma.alibabacloud.com/auth/start?" + queryString
```

**完整URL示例**：
```
https://lingma.alibabacloud.com/auth/start?
  nonce=550e8400e29b41d4a716446655440000&
  port=8008&
  verifier=dGhpcyBpcyBhIHJhbmRvbSB2ZXJpZmllciAxMjM0NTY3ODkw&
  challenge=4e5e6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f&
  challenge_method=S256&
  machine_id=abc123def456&
  redirect=https://modelscope.cn/auth/callback
```

### 返回结构体（LoginRequestResult，120字节）

**IDA验证结构**：
```go
type LoginRequestResult struct {
    LoginUrl        string  // offset 0x0,  size 16  - 完整登录URL
    Nonce           string  // offset 0x10, size 16  - UUID去掉"-"
    Verifier        string  // offset 0x20, size 16  - PKCE code_verifier
    Challenge       string  // offset 0x30, size 16  - PKCE code_challenge
    ChallengeMethod string  // offset 0x40, size 16  - "S256"
    ErrorCode       string  // offset 0x50, size 16  - 错误码（失败时）
    ErrorMsg        string  // offset 0x60, size 16  - 错误消息（失败时）
    Success         bool    // offset 0x70, size 1   - 成功标志
}
```

---

## 2. 浏览器登录操作

### 用户流程

1. **打开登录URL**：浏览器访问生成的 `loginUrl`
2. **选择登录方式**：
   - 个人登录（personal）
   - 组织登录（organization）
3. **输入凭证**：用户名、密码或其他OAuth认证
4. **完成认证**：服务器验证成功

### 服务器响应（推测）

**成功响应**：
```go
type AuthResponse struct {
    Auth        string  // v3格式的auth信息字符串
    TokenString string  // 包含pt-*和rt-* token的字符串
}
```

**Auth字段格式**（推测）：
```json
{
  "aid": "123456789",
  "uid": "5930676910898027",
  "orgId": "org_001",
  "name": "张三",
  "yxUid": "yx_abc123",
  ...
}
```

**TokenString字段格式**（推测）：
```json
{
  "securityOauthToken": "pt-Atl8MQJdcCqbDEdAZAyYgnbp",
  "refreshToken": "rt-GLbIaXzLEFCo8rINstjCv6EC",
  "expireTime": 1735689600
}
```

---

## 3. OAuth回调处理

### 回调URL格式

```
http://localhost:8008/auth/callback?
  nonce=550e8400e29b41d4a716446655440000&
  auth=<base64编码的auth信息>&
  token_string=<base64编码的token信息>
```

**关键点**：
- **localhost:8008**：本地HTTP服务器端口
- **nonce**：匹配登录请求
- **auth**：v3格式的auth信息字符串
- **token_string**：token字符串

### 函数地址

- **HandleAuthCallback**: `0x141a18dc0`
- **parseAuthInfoV3**: `0x141a21b80`
- **parseAuthToken**: `0x141a213e0`

### 核心逻辑

#### Step 1: 通过Nonce匹配Context

```go
func HandleAuthCallback(param LoginAuthCallbackParam) error {
    // param包含：Nonce、Auth、TokenString
    
    // 从map取出context
    ctx := qword_1460D9528[param.Nonce]
    
    if ctx == nil {
        // nonce无效或已被使用
        return errors.New("invalid login nonce")
    }
}
```

**安全机制**：
- nonce必须存在于map中（防止伪造回调）
- nonce使用一次后立即删除（防止重复使用）

#### Step 2: 解析Auth信息（parseAuthInfoV3）

```go
authInfo := parseAuthInfoV3(param.Auth)
```

**返回结构**（推测）：
```go
type LoginUserInfo struct {
    Aid     string  // 阿里云AID
    Uid     string  // 用户ID
    OrgId   string  // 组织ID
    OrgName string  // 组织名称
    Name    string  // 用户名
    YxUid   string  // YX UID
    ...
}
```

#### Step 3: 解析Token字符串（parseAuthToken）

```go
token := parseAuthToken(param.TokenString)
```

**返回结构**（推测）：
```go
type TokenInfo struct {
    SecurityOauthToken string  // pt-* token
    RefreshToken       string  // rt-* token
    TokenExpireTime    int64   // 过期时间
}
```

#### Step 4: 删除Nonce（防止重复使用）

```go
runtime.mapdelete_faststr(qword_1460D9528, param.Nonce)
```

**目的**：确保每个nonce只能使用一次

#### Step 5: 检查用户是否已登录

```go
cachedUser := GetCachedUserInfo()

// 比较uid、orgId、name是否一致
if cachedUser.Uid == authInfo.Uid &&
   cachedUser.OrgId == authInfo.OrgId &&
   cachedUser.Name == authInfo.Name {
    // 用户已登录且信息一致 → 忽略，避免重复登录
    return nil
}
```

**优化逻辑**：
- 避免相同用户重复登录
- 比较uid、orgId、name三个字段

#### Step 6: 完成登录（CompleteLoginWithSelectAccount）

```go
CompleteLoginWithSelectAccount(ctx, authInfo, token)
```

**内部操作**：
- 存储用户信息到CosyUserInfo
- 派生pt-*和rt-* token
- 更新全局用户状态
- 通知UI刷新

---

## 4. LoginAuthCallbackParam结构体（48字节，IDA验证）

```go
type LoginAuthCallbackParam struct {
    Nonce       string  // offset 0x0,  size 16  - 随机数（匹配登录）
    Auth        string  // offset 0x10, size 16  - auth信息字符串
    TokenString string  // offset 0x20, size 16  - token字符串
}
```

---

## 5. 本地HTTP服务器监听机制

### 端口配置

- **端口**：8008（IDA字符串验证：`localhost:8008`）
- **监听地址**：`localhost` 或 `127.0.0.1`
- **协议**：HTTP（接收OAuth回调）

### 限制验证（IDA字符串）

```
"only localhost and 127.0.0.1 are allowed"
```

**安全机制**：
- 只允许localhost和127.0.0.1访问
- 防止远程恶意请求

### DeviceToken轮询机制

**关键函数**：
- `DeviceTokenPollingManager.StartPolling`: `0x141a1d900`
- `DeviceTokenPollingManager.performPollAttempt`: `0x141a1d8e0`
- `stopDeviceTokenPolling`: `0x141a12120`

**轮询endpoint**：
```
/api/v3/user/oauth2/deviceToken/poll
```

**作用**：
- 设备token轮询（备用认证机制）
- 登录成功后停止轮询

---

## 6. Token存储和派生机制

### CosyUserInfo存储（288字节，已验证）

**关键字段**：
```go
SecurityOauthToken  string  // offset 0x80, pt-* token ✅
RefreshToken        string  // offset 0x90, rt-* token ✅
TokenExpireTime     int64   // offset 0xa0, 过期时间
```

### 派生逻辑（推测）

**pt-* token来源**：
- OAuth回调中的 `TokenString.SecurityOauthToken`
- 或从JWT派生（如果使用标准OAuth）

**rt-* token来源**：
- OAuth回调中的 `TokenString.RefreshToken`
- 用于后续token刷新

---

## 7. PKCE机制完整分析

### generatePKCEChallenge函数（推测）

```go
func generatePKCEChallenge() (string, string, string, error) {
    // 1. 生成随机verifier（43-128字符）
    verifier := generateRandomString(43)
    
    // 2. 计算challenge（SHA256）
    challenge := sha256(verifier)
    
    // 3. Base64 URL-safe编码
    challengeEncoded := base64URLEncode(challenge)
    
    return verifier, challengeEncoded, "S256", nil
}
```

**PKCE流程**：
```
1. Client生成随机verifier
2. Client计算challenge = SHA256(verifier)
3. Client发送challenge到服务器（auth/start）
4. 用户登录后，服务器返回authorization code
5. Client回调时发送verifier（验证）
6. 服务器验证SHA256(verifier) == challenge
```

**安全优势**：
- 防止授权码拦截攻击
- 即使攻击者截获authorization code，没有verifier也无法获取token

---

## 8. 组织登录流程

### loginWithOrganization路径

```
/auth/loginWithOrganization?organizationId=<orgId>
```

**JavaScript前端逻辑**（IDA字符串发现）：
```javascript
function loginWithOrganization(orgId) {
    if (orgId === "personal") {
        orgId = "";  // 个人登录
    }
    
    window.location.href = "/auth/loginWithOrganization?" +
        (window.location.search ? window.location.search + "&" : "?") +
        "organizationId=" + orgId;
}
```

**流程差异**：
- 个人登录：`organizationId = ""`
- 组织登录：`organizationId = <orgId>`

---

## 9. 关键函数地址表

| 函数名 | 地址 | 功能 |
|--------|------|------|
| `LoginStart` | 0x141a10680 | 登录启动（生成URL） |
| `PrepareLoginRequest` | 0x141a198a0 | 准备登录请求参数 |
| `generatePKCEChallenge` | 0x141a197a0 | 生成PKCE challenge |
| `HandleAuthCallback` | 0x141a18dc0 | 处理OAuth回调 |
| `parseAuthInfoV3` | 0x141a21b80 | 解析auth信息 |
| `parseAuthToken` | 0x141a213e0 | 解析token字符串 |
| `CompleteLoginWithSelectAccount` | 0x141a0fee0 | 完成登录（选择账户）|
| `GetCachedUserInfo` | 0x140890760 | 获取缓存的用户信息 |
| `DeviceTokenPollingManager.StartPolling` | 0x141a1d900 | 启动设备token轮询 |
| `stopDeviceTokenPolling` | 0x141a12120 | 停止设备token轮询 |

---

## 10. 全局变量表

| 变量名 | 地址 | 类型 | 用途 |
|--------|------|------|------|
| `qword_1460D9528` | 0x1460D9528 | map[string]context.Context | nonce→context映射 |
| `qword_1460D9520` | 0x1460D9520 | *DeviceTokenPollingManager | 设备token轮询管理器 |
| `HttpPort` | - | int | 本地HTTP端口（8008）|

---

## 11. 完整流程示例

### Python模拟（理论实现）

```python
import uuid
import hashlib
import base64
import secrets

def generate_pkce_challenge():
    """生成PKCE verifier和challenge"""
    # 生成随机verifier（43字符）
    verifier = secrets.token_urlsafe(32)
    
    # 计算challenge（SHA256）
    challenge_bytes = hashlib.sha256(verifier.encode()).digest()
    
    # Base64 URL-safe编码
    challenge = base64.urlsafe_b64encode(challenge_bytes).decode().rstrip('=')
    
    return verifier, challenge

def login_start():
    """模拟LoginStart"""
    # 生成nonce（UUID去掉"-"）
    nonce = str(uuid.uuid4()).replace("-", "")
    
    # 生成PKCE
    verifier, challenge = generate_pkce_challenge()
    
    # 构造URL参数
    params = {
        "nonce": nonce,
        "port": "8008",
        "verifier": verifier,
        "challenge": challenge,
        "challenge_method": "S256",
        "machine_id": "machine_abc123"
    }
    
    # 构造完整URL
    query_string = "&".join(f"{k}={v}" for k, v in params.items())
    login_url = f"https://lingma.alibabacloud.com/auth/start?{query_string}"
    
    return {
        "login_url": login_url,
        "nonce": nonce,
        "verifier": verifier,
        "challenge": challenge
    }

def handle_auth_callback(nonce, auth, token_string):
    """模拟HandleAuthCallback"""
    # 1. 验证nonce（从存储中取出context）
    # context = nonce_map.get(nonce)
    
    # 2. 解析auth信息
    # auth_info = parse_auth_info_v3(auth)
    
    # 3. 解析token字符串
    # token_info = parse_auth_token(token_string)
    
    # 4. 删除nonce（防止重复使用）
    # nonce_map.delete(nonce)
    
    # 5. 完成登录
    # complete_login(auth_info, token_info)
    
    return {
        "uid": "...",
        "security_oauth_token": "pt-...",
        "refresh_token": "rt-..."
    }
```

---

## 12. 未解决问题与下一步

### 未解析函数 ⭕

1. **parseAuthInfoV3**（0x141a21b80）：
   - 需要反编译了解auth字符串的解码逻辑
   - 确认是否使用Base64或其他编码

2. **parseAuthToken**（0x141a213e0）：
   - 需要反编译了解token字符串的解析逻辑
   - 确认token格式（JSON、Base64等）

3. **CompleteLoginWithSelectAccount**（0x141a0fee0）：
   - 了解如何存储到CosyUserInfo
   - 了解token派生逻辑

### Frida动态验证需求 ⭕

1. **监控登录URL生成**：
   - 验证实际URL参数值
   - 验证PKCE verifier和challenge

2. **监控OAuth回调**：
   - 验证auth和token_string的实际格式
   - 验证parseAuthInfoV3和parseAuthToken的输入输出

3. **监控token存储**：
   - 验证CosyUserInfo的实际写入过程

---

## 13. 安全机制总结

### 已验证安全机制 ✅

1. **PKCE机制**：
   - 防止授权码拦截攻击
   - Verifier + Challenge + S256方法

2. **Nonce机制**：
   - 防止重复登录
   - 防止伪造回调
   - UUID去掉"-"（32字节）

3. **本地端口限制**：
   - 只允许localhost和127.0.0.1
   - 防止远程恶意请求

4. **一次性使用**：
   - nonce使用后立即删除
   - 防止重放攻击

### 推测安全机制 ⭕

1. **Auth字符串加密**：
   - 可能使用Base64编码
   - 或AES加密（待验证）

2. **Token字符串加密**：
   - 可能使用自定义编码
   - 或JWT格式（待验证）

---

## 14. OAuth流程对比

### Lingma自定义OAuth vs 标准OAuth

| 特性 | Lingma OAuth | 标准OAuth |
|------|-------------|----------|
| **认证方式** | 自定义（auth+token_string）| 标准authorization code |
| **Token格式** | pt-* / rt-*（自定义）| JWT（标准）|
| **PKCE支持** | ✅ 支持（S256）| ✅ 标准支持 |
| **回调方式** | 本地HTTP服务器（8008）| 注册的redirect_uri |
| **Nonce机制** | UUID去掉"-" | state参数（标准）|

---

## 15. 文档索引

### 相关文档

| 文档名 | 内容 |
|--------|------|
| `LINGMA_API_COMPLETE_DOCUMENTATION.md` | 终极API完整文档 |
| `ida-http-refresh-cracked.md` | Authorization和Signature破解 |
| `response_data_structures_complete.md` | CosyUserInfo完整结构 |
| `lingma-oauth-analysis.md` (Memory) | OAuth流程初步分析 |
| `lingma-client-id-extraction-status.md` (Memory) | client_id提取阻塞 |

---

**总结**：通过IDA Pro MCP静态分析，破解了Lingma OAuth登录流程的核心机制，包括LoginStart的URL生成逻辑、PKCE机制、Nonce关联机制、HandleAuthCallback的回调处理流程。确认了LoginRequestResult和LoginAuthCallbackParam的完整结构体定义，验证了本地HTTP服务器监听端口（8008）和限制机制。部分函数（parseAuthInfoV3、parseAuthToken、CompleteLoginWithSelectAccount）需要进一步反编译或Frida动态验证。