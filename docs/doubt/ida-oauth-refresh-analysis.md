# Lingma OAuth Refresh Token IDA Pro 分析报告

> 日期：2026-05-04（更新）
> 分析工具：IDA Pro + ida-pro-mcp
> 目标：完整逆向灵码 token refresh 远程通信流程

---

## 1. 分析概述

本次分析覆盖了灵码 token refresh 的全部两条路径：

| 路径 | 函数 | 地址 | 是否远程调用 |
|------|------|------|-------------|
| **LSP 路径** | `RefreshTokenHandler` | `0x141aaf7e0` | ❌ 仅更新本地缓存 |
| **远程路径** | `doRefreshToken` | `0x14088d660` | ✅ HTTP POST 到服务器 |

---

## 2. 完整调用链

### 2.1 总览

```
Chat API 返回 401 → Token 过期
       │
       ▼
EnsureTokenValid @ 0x14088d220
  └─ refreshTokenConcurrentSafe @ 0x14088d4e0
       └─ doRefreshToken @ 0x14088d660 ← ★ 真正的远程调用
            │
            ├─ MustGetClient() → HTTP Client
            ├─ BuildBigModelSignRequest
            │    ├─ magic = "none" (signature 模式)
            │    ├─ method = "POST"
            │    └─ path = "/api/v3/user/refresh_token"
            ├─ Client.do(request) → HTTP POST
            └─ 解析响应 → RefreshUserInfoSecurityToken → 更新缓存

LSP 路径 (无远程调用):
auth/refreshToken → RefreshTokenHandler @ 0x141aaf7e0
  ├─ 互斥锁 (sync.Mutex)
  ├─ 验证 token 与缓存匹配 → 相同则跳过
  └─ RefreshUserInfoSecurityToken @ 0x14088f180
       ├─ 更新缓存中的 token
       ├─ SaveUserInfo → 写入磁盘
       └─ 广播 auth/syncTokenUpdate → 通知其他 LSP 客户端
```

### 2.2 LSP 路径分析

**函数：** `cosy_core_api_auth.RefreshTokenHandler` @ `0x141aaf7e0`

**注册（InitHandlers @ 0x141aadb20）：**
```go
RegisterTypedHandler<
    struct{SecurityOauthToken, RefreshToken, TokenExpireTime},
    struct{Success, Uid, Name, TokenExpireTime}
>("auth/refreshToken", 17, handler)
```

**请求参数：**
```json
{
    "securityOauthToken": "pt-xxxxx",
    "refreshToken": "rt-yyyyy",
    "tokenExpireTime": 1783091978172
}
```

**返回结果：**
```json
{
    "success": true,
    "uid": "5930676910898027",
    "name": "zhang640@blny.de",
    "tokenExpireTime": 1783091978172
}
```

**处理逻辑：**
1. 互斥锁（`stru_14616C3E0`）
2. 验证 `SecurityOauthToken.len > 0` && `RefreshToken.len > 0`
3. 验证 `TokenExpireTime > 0`（否则视为参数无效）
4. 读取缓存用户 `GetCachedUserInfo()`
5. 对比传入 token 与缓存 token：
   - **完全相同** → 日志 `"Already up to date for uid: %s, skip duplicate refresh"` → 直接返回成功
   - **不同** → 创建 `CosyUserInfo{token, refreshToken, expireTime}`
6. 调用 `RefreshUserInfoSecurityToken()` → 更新缓存 + 广播 `auth/syncTokenUpdate`
7. 日志 `"User token refreshed successfully, securityOauthToken: %s, refreshToken: %s, tokenExpireTime: %d"`

**关键日志：**
- `"Refreshing user token, params: %s"`
- `"Already up to date for uid: %s, skip duplicate refresh"`
- `"User token refreshed successfully, ..."`
- `"REFRESH_FAILED"`（失败）
- `"INVALID_PARAMS"`（参数无效）
- `"USER_NOT_LOGIN"`（未登录）

---

## 3. doRefreshToken 远程调用详解

**函数：** `cosy_auth_user.doRefreshToken` @ `0x14088d660`

### 3.1 完整流程

```python
def doRefreshToken(user_info):
    # 1. 获取 HTTP 客户端 (Go 原生网络栈)
    client = MustGetClient()

    # 2. 构建 AuthQueryParam
    auth_param = {
        "userId": user_info.UserId,
        "orgId": user_info.OrgId,
        "securityOauthToken": user_info.SecurityOauthToken,
        "refreshToken": user_info.RefreshToken,
    }

    # 3. 构建签名请求 (signature 模式)
    payload = HttpPayload{
        RequestId: "",
        Payload: JSON(auth_param),
        EncodeVersion: "",    # 空 = 不编码
    }
    request = BuildBigModelSignRequest(
        method="POST",
        path="/api/v3/user/refresh_token",
        payload=payload,
    )
    # BuildBigModelSignRequest 内部:
    #   → addBasicHeaders()
    #   → magic="none" → addBigModelSignatureHeaders()
    #     → MD5(base64(body) + "&" + key + "&" + date)

    # 4. 发送请求
    response = client.do(request)

    if response.StatusCode == 200:
        body = ReadAll(response.Body)

        if '"success":false' in body:
            log("Renew token got error from auth server")
            return error

        result = JSON.unmarshal(body, UserStatusResponse)
        # UserStatusResponse: {securityOauthToken, refreshToken, expireTime}

        if result.RefreshToken and result.SecurityOauthToken and result.ExpireTime > 0:
            # 更新缓存
            RefreshUserInfoSecurityToken(result)
            log("renew token success. new expire time: %d", result.ExpireTime)
        else:
            return error("renew token response invalid")
    else:
        log("Failed to get renew token response: %s", response.Status)
```

### 3.2 认证模式：signature (magic="none")

`BuildBigModelSignRequest` @ `0x14087cc20` 根据请求路径选择认证模式：

```go
magic = a1[8:9]  // 从路径映射读取

if magic == "none" {  // 0x6e6f6e65
    // signature 模式: MD5 签名
    addBigModelSignatureHeaders(request)
} else { // magic == "http"
    // authorization 模式: Bearer token
    addBigModelAuthorizationHeaders(request, token)
}
```

refresh_token 使用 **signature 模式**，magic 值为 `"none"`（4 字节，对应 `unk_1424AC224`）。

### 3.3 签名算法

**函数：** `addBigModelSignatureHeaders` @ `0x14087e5e0`

```
Signature = MD5(base64(body) + "&" + key + "&" + date)

其中:
  key = "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="
      = base64("war, war never changes")
  date = RFC1123 格式 ("Mon, 02 Jan 2006 15:04:05 GMT")
```

### 3.4 请求头

| Header | 值 | 来源 |
|--------|-----|------|
| Content-Type | `application/json` | addBasicHeaders |
| Accept | `application/json` | addBasicHeaders |
| Accept-Encoding | `gzip` | addBasicHeaders |
| User-Agent | `Cosy/20` | addBasicHeaders |
| X-Forwarded-For | `127.0.0.1` | addBasicHeaders |
| Cosy-MachineId | machine_id | addBasicHeaders |
| Cosy-MachineToken | `""` | addBasicHeaders |
| Cosy-MachineType | `""` | addBasicHeaders |
| Cosy-MachineCode | `""` | addBasicHeaders |
| Cosy-MachineOS | `x86_64_windows` | addBasicHeaders |
| Cosy-ClientType | `"2"` | addBasicHeaders |
| Cosy-Version | `"20"` | addBasicHeaders |
| **Date** | RFC1123 | addBigModelSignatureHeaders |
| **Cosy-Date** | RFC1123 | addBigModelSignatureHeaders |
| **Cosy-User** | `base64(body)` | addBigModelSignatureHeaders |
| **Signature** | `MD5(...)` | addBigModelSignatureHeaders |

### 3.5 请求/响应格式

**请求体（原始 JSON，不需要 Encode=1）：**
```json
{
    "userId": "5930676910898027",
    "orgId": "",
    "securityOauthToken": "pt-xxxxx",
    "refreshToken": "rt-yyyyy"
}
```

**成功响应（UserStatusResponse）：**
```json
{
    "securityOauthToken": "pt-xxxxx-new",
    "refreshToken": "rt-yyyyy-new",
    "expireTime": 1783091978172
}
```

**失败响应**（`"success":false` 在 body 中）→ 服务端返回错误。

---

## 4. RefreshUserInfoSecurityToken 分析

**函数：** `cosy_auth_user.RefreshUserInfoSecurityToken` @ `0x14088f180`

**职责：** 更新本地缓存的 token 信息，异步广播更新事件。

**处理逻辑：**
1. 读取缓存用户信息 `GetCachedUserInfo()`
2. 更新 `CachedUserInfo[16..17]` = 新 SecurityOauthToken
3. 更新 `CachedUserInfo[18..19]` = 新 RefreshToken
4. 更新 `CachedUserInfo[20]` = 新 TokenExpireTime
5. 保存到磁盘 `SaveUserInfo()`
6. 启动 goroutine 广播 `auth/syncTokenUpdate` 事件

**缓存字段布局（CosyUserInfo 结构）：**
| 偏移 | 字段 | 说明 |
|------|------|------|
| `[4..5]` | UserId | 用户 ID |
| `[8..9]` | UserName | 用户名 |
| `[16..17]` | **SecurityOauthToken** | OAuth Token |
| `[18..19]` | **RefreshToken** | Refresh Token |
| `[20]` | **TokenExpireTime** | 过期时间 |

---

## 5. 远程端点状态

| 服务器 | URL | 状态 |
|--------|-----|------|
| 国际 | `https://lingma.alibabacloud.com/algo/api/v3/user/refresh_token` | **404**（未部署） |
| 国内 | `https://lingma-api.tongyi.aliyun.com/algo/api/v3/user/refresh_token` | **403**（WAF） |

---

## 6. 验证过的错误结论（本次更新修正）

| 旧结论 (2026-04-30) | 实际结论 (2026-05-04) | 修正依据 |
|----------------------|----------------------|---------|
| 签名公式 `MD5("cosy&" + key + "&" + date)` | 实际：`MD5(base64(body) + "&" + key + "&" + date)` | `addBigModelSignatureHeaders` @ 0x14087e5e0 |
| 需要 Encode=1 编码 body | **不需要**，用原始 JSON | `doRefreshToken` 中 `EncodeVersion=""` |
| 需要 Authorization Bearer 头 | 不需要，用 `Cosy-User` + `Signature` | `buildRequest` 中 magic="none" 走 signature 模式 |
| `BuildBigModelSignRequest` 内部未知 | 完整分析：`buildRequest` → `addBasicHeaders` + 根据 magic 选择认证方式 | `buildRequest` @ 0x14087cc20 |
| Encode=1/Encode=2 存疑 | refresh_token 路径：magic="none" 时 `shouldEncryptBody=FALSE`，不编码 | `buildRequest` 条件分支 |

---

## 7. 关键函数地址表

| 函数 | 地址 | 大小 | 作用 |
|------|------|------|------|
| `RefreshTokenHandler` | `0x141aaf7e0` | 2123 B | LSP handler |
| `doRefreshToken` | `0x14088d660` | 2767 B | 远程刷新（核心） |
| `RefreshUserInfoSecurityToken` | `0x14088f180` | 613 B | 更新缓存+广播 |
| `refreshTokenConcurrentSafe` | `0x14088d4e0` | 383 B | 并发安全包装 |
| `EnsureTokenValid` | `0x14088d220` | 688 B | Chat API 401 触发 |
| `buildRequest` | `0x14087cc20` | — | HTTP 请求构造 |
| `addBasicHeaders` | `0x14087ef20` | — | 基础请求头 |
| `addBigModelSignatureHeaders` | `0x14087e5e0` | — | MD5 签名头 |
| `addBigModelAuthorizationHeaders` | `0x14087ea20` | — | Bearer 认证头 |
| `BuildBigModelSignRequest` | `0x14087ca20` | — | 签名请求构建入口 |

---

## 8. 相关脚本

| 脚本 | 作用 |
|------|------|
| `tools/lingma_refresh_token.py` | 独立 refresh 脚本（signature 模式，原始 JSON） |
| `tools/lingma_refresh_token_direct.py` | ⚠️ 旧版（签名/编码错误，仅供参考） |
| `tools/credential_extractor.py` | 从 cache/user 解密凭据 |

---

## 9. 验证状态

| 验证项 | 状态 | 方法 |
|--------|------|------|
| LSP `auth/refreshToken` 逻辑 | ✅ | IDA 反编译 `RefreshTokenHandler` |
| 远程 `doRefreshToken` 逻辑 | ✅ | IDA 反编译 `doRefreshToken` |
| 签名公式 | ✅ | `addBigModelSignatureHeaders` 反编译 |
| 请求头构造 | ✅ | `addBasicHeaders` + `addBigModelSignatureHeaders` |
| 响应处理 | ✅ | `doRefreshToken` 中 JSON Unmarshal + 字段验证 |
| 远程 API 调用 | ⚠️ | 国际 404 / 国内 403 (WAF) |
