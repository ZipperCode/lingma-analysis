# 灵码独立 OAuth 认证分析报告

> 日期：2026-04-29（更新）
> 状态：**v3 HTTP 端点走不通**（详见 3.4 节），推荐方案：获取 client_id 后使用标准 OAuth refresh
> 目标：实现完全脱离本地灵码程序的独立 OAuth + Token 刷新机制

## 1. 核心发现

### 1.1 client_id 不存在于客户端

灵码二进制中**没有硬编码的 `client_id`**。所有的 OAuth 操作通过灵码服务端 API 完成，`client_id` 仅在服务端存在。

**已排除的路径：**
- 二进制静态分析：无硬编码值
- 配置文件（`~/.lingma/cache/*`）：无
- WebSocket 方法：无法获取
- 浏览器 302 重定向链：未直接暴露给客户端

### 1.2 灵码使用 Device Token Polling 而非传统 OAuth

灵码二进制使用 **设备令牌轮询**（Device Token Polling）流程，完全绕过标准 OAuth 浏览器重定向。

**源码路径（二进制内）：**
```
cosy/auth/device_token_polling.go  - DeviceTokenPollingManager
cosy/auth/device_token.go          - DeviceTokenResponse
cosy/auth/user/token_refresh.go    - Token 刷新逻辑
cosy/auth/user/doRefreshToken      - 刷新实现
```

**端点：**
```
GET  /algo/api/v3/user/oauth2/deviceToken/poll  - 轮询设备令牌
POST /algo/api/v3/user/refresh_token             - 服务端 token 刷新
POST /algo/api/v3/user/login                     - 用户登录/凭证推导
POST /algo/api/v3/user/logout                    - 登出
POST /algo/api/v3/user/status                    - 用户状态查询
```

**关键日志：**
```
Started device token polling for nonce: %s
Device token polling stopped after successful %s login
Stopping device token polling for nonce: %s
No active device token polling to stop
```

### 1.3 两层认证机制

| 层 | 端点版本 | 认证方式 | 编码 |
|---|---|---|---|
| v1 API（心跳/tracking） | `/algo/api/v1/*` | 旧签名（Date + Signature） | Encode=1（纯自定义 base64） |
| v3 API（认证/token） | `/algo/api/v3/*` | 旧签名（Date + Signature） | Encode=2（未知，待逆向） |
| v2 API（模型/对话） | `/algo/api/v2/*` | COSY Bearer | 无 Encode |

---

## 2. 已验证的技术细节

### 2.1 旧签名公式（已验证 ✅）

```
Signature = MD5("cosy&" + session_key + "&" + RFC1123_date)
```

- `session_key` = `d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw==`（base64 编码，解码为 "war, war never changes"）
- `RFC1123_date` = `Wed, 29 Apr 2026 05:02:30 GMT` 格式
- 备用 key: `&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe`

**验证方法：** 回放截获的心跳请求，签名完全匹配。

### 2.2 Encode=1 编码（已完全逆向 ✅）

Encode=1 是**自定义 base64 编码**，不使用 AES 加密。

**编码算法：**

```python
encode1Alpha = "_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!"
encode1StdB64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def lingma_encode(data: bytes) -> str:
    # 1. 标准 base64 编码，去掉 padding
    std = base64.b64encode(data).decode().rstrip('=')
    
    # 2. 字符映射：标准 base64 -> 自定义字母表
    custom = ''.join(stdToAlpha.get(c, c) for c in std)
    
    # 3. 分块重排
    e = len(custom)
    bs = math.ceil(e / 3.0)  # 块大小
    pad = (4 - e % 4) % 4    # padding 标记数
    
    b0 = custom[:bs]
    b1 = custom[bs:2*bs] if 2*bs <= e else custom[bs:]
    b2 = custom[2*bs:]
    
    # 4. 输出格式：b2 + $padding + b1 + b0
    return b2 + ('$' * pad) + b1 + b0
```

**验证方法：** 编码灵码二进制截获的心跳 JSON，输出与二进制发送的完全一致（912 字节逐字节匹配）。

### 2.3 请求头格式（已验证 ✅）

灵码二进制使用 **CamelCase 头部名**（通过 mitmproxy 截获确认）：

```
User-Agent: Go-http-client/1.1
Accept: application/json
Accept-Encoding: identity
Appcode: cosy
Content-Type: application/json
Cosy-Clientip: 10.8.28.22
Cosy-Clienttype: 2
Cosy-Machinecode:
Cosy-Machineid: 43303747-3630-492d-8151-366d4e59432d
Cosy-Machineos: aarch64_darwin
Cosy-Machinetoken:
Cosy-Machinetype:
Cosy-Version: 2.11.2
Date: Wed, 29 Apr 2026 05:02:30 GMT
Login-Version: v2
Signature: <md5hex>
```

**注意：** HTTP/2 传输时头部名可能被自动转为小写。两种大小写都能工作。

### 2.4 Device Token Polling 端点（已验证 ✅）

```
GET /algo/api/v3/user/oauth2/deviceToken/poll
```

- 使用旧签名认证
- 无需 Encode 参数
- 无活跃轮询时返回 `200 {}`
- POST 方法返回 400 "not supported"

---

## 3. 未解决的问题

### 3.1 v3 端点认证（部分解决 ⚠️）

**重要发现：Encode=1 对 v3 端点的 body 解码也有效！**

测试证明：用 `securityOauthToken` 字段 + 有效 `pt-*` token + Encode=1 编码：
- `/algo/api/v3/user/refresh_token` → **400** "auth payload is invalid"（body 解码成功！）
- `/algo/api/v3/user/status` → **400** "auth payload is invalid"（body 解码成功！）

对比：用无效值（如随机字符串）→ **500**（body 解码失败）

这意味着：
1. ✅ Encode=1 编码对 v3 POST 端点有效
2. ✅ `securityOauthToken` 是正确的字段名
3. ❌ "auth payload is invalid" = body 内容格式不正确

**可能原因：**
- v3 端点需要额外的认证字段（签名、nonce 等）
- `pt-*` token 需要某种转换后才能用于 v3
- v3 端点期望不同的 body 结构（如嵌套对象）

**v3 GET 端点签名问题：**
- `GET /api/v3/user/remoteToken` → 403 "Signature invalid"
- `GET /api/v3/user/oauth2/deviceToken/poll` → 200（特殊端点，可能不需要签名）
- v3 GET 端点可能使用不同于 v1 的签名机制

**二进制中的相关函数链：**
```
cosy/auth/user.doRefreshToken
  → cosy/auth/user.getAuthPayload     (构造请求 payload)
  → cosy/auth/user.getAuthSignature   (计算认证签名)
  → cosy/remoting.encodeRequestBody   (Encode=1/2 编码)
    → cosy/encrypt.CustomEncryptV1    (Encode=1: 自定义 base64)
    → cosy/encrypt.AesEncryptWithBase64 (Encode=2: AES + 自定义 base64)
```

**关键：** `getAuthPayload` 和 `getAuthSignature` 函数可能在 body 中添加了签名信息。

### 3.1.1 自定义 base64 字母表（运行时生成）

二进制中的字母表是**运行时动态生成**的，由以下函数控制：
- `cosy/encrypt.shuffle` - 随机化 base64 字符位置
- `cosy/encrypt.assemble32` - 构建 32 字符子字母表
- `cosy/encrypt.assemble64` - 构建完整 64 字符字母表
- `cosy/encrypt.newEncoding` - 创建编码对象

Encode=1 使用静态字母表（`_doRTgHZBKcGVjlvpC,...`），Encode=2 可能使用 shuffle 后的变体。
但由于 Encode=1 也能解码 v3 body，说明两个编码可能使用相同的字母表。

### 3.2 Device Token Polling 启动流程（待研究 ❌）

轮询端点返回空 `{}`，说明需要先**启动轮询会话**。但启动端点尚未找到。

**测试结果：**
- `POST /algo/api/v3/user/oauth2/deviceToken` → 404（端点不存在）
- `POST /algo/api/v3/user/oauth2/deviceToken/poll` → 400 "POST not supported"
- `GET /algo/api/v3/user/oauth2/deviceToken/poll` → 200 `{}`（空响应，无活跃轮询）

**可能的方式：**
- 通过 WebSocket `login/generateUrl` 启动
- 通过 devops.aliyun.com 间接启动
- 通过其他未发现的 API 端点

### 3.4 v3 HTTP 端点完整测试结果（2026-04-29）

**结论：v3 HTTP 端点无法用于灵码内部 `pt-` 格式 token 的刷新**

经过系统测试，发现 v3 `/algo/api/v3/user/refresh_token` 端点：

1. **需要 `?Encode=1` 查询参数**（否则返回 400 "Required request parameter 'Encode' is not present"）
2. **纯 Encode=1 编码足够**（不需要 AES 加密）
3. **`securityOauthToken` + `refreshToken` 是唯一正确的字段组合**
   - 缺少任一字段 → 500
   - 添加额外字段 → 500（服务端不认识）
   - 字段名变体（如 `securityToken`, `oauthToken`）→ 500
4. **但始终返回 400 "auth payload is invalid"**

**关键发现：**
- `pt-` 格式的 token 是灵码内部格式，不是标准 OAuth token
- v3 HTTP 端点需要**标准 OAuth token**（JWT 格式，`eyJ...`）
- 标准 OAuth token 只能通过标准 OAuth 流程获取（需要 client_id）
- 这意味着：**没有 client_id 就无法使用 v3 HTTP 端点**

**测试矩阵：**

| 测试项 | 结果 | 说明 |
|--------|------|------|
| `securityOauthToken` + `refreshToken` | 400 invalid | 字段正确，值验证失败 |
| 去掉 `pt-` 前缀 | 500 | 服务端不认识该格式 |
| 添加 `loginEnv: "cn"` | 400 invalid | `loginEnv` 被认识，但值仍失败 |
| 添加 `loginEnv: "domestic"` | 500 | 无效值 |
| 添加 `userId`, `machineId`, `expireTime` | 500 | 服务端不认识这些字段 |
| AES+Encode=1 (`QbgzpWzN7tfe43gf`) | 500 | 不需要 AES |
| `securityToken` / `oauthToken` 字段名 | 500 | 错误字段名 |
| 空 body `{}` | 500 | 缺少必需字段 |

**最终结论：**
v3 HTTP 端点是灵码服务端用于标准 OAuth token 刷新的接口，但灵码内部使用自己的 `pt-`/`rt-` token 格式。两种 token 体系不互通。

**可行的路径：**
1. 通过浏览器 OAuth 流程获取标准 OAuth token（需要 client_id）
2. 使用标准 OAuth token 调用 v3 端点
3. 或者继续使用 WebSocket `auth/refreshToken`（不需要 client_id）

---

## 4. 可行的当前方案

### 4.1 直接使用已缓存凭证

灵码二进制会自动刷新 token 并更新 `~/.lingma/cache/user`。当前方案：

```python
# 1. 读取缓存凭证
# 文件：~/.lingma/cache/user（AES-128-CBC 加密，key = machine_id[:16]）
# 包含：cosy_key, encrypt_user_info, security_oauth_token, refresh_token

# 2. 生成 COSY Bearer（用于 v2 API）
# 格式：COSY.<base64_json>.<md5_hex>
# 参考：lingma_remote_api.py 的 _make_bearer() 方法

# 3. 调用 v2 API（模型列表、对话等）
# 端点：/algo/api/v2/*
```

**限制：** 依赖灵码二进制运行来刷新 token。

### 4.2 WS Token 刷新（已有实现）

```go
// lingma2api/internal/auth/ws_refresh.go
// 通过 WebSocket auth/refreshToken 刷新
// 需要灵码二进制运行在 127.0.0.1:37010
```

**限制：** 需要本地灵码二进制运行。

### 4.3 Encode=1 v1 端点（新发现，可用）

v1 端点使用 Encode=1（纯自定义 base64），已完全逆向。可用于：
- 心跳（heartbeat）
- 事件追踪（tracking）
- 其他 v1 端点

---

## 5. 后续计划

### 优先级 1：逆向 Encode=2

**方法 A：截获二进制请求**
```bash
# 1. 确保灵码 token 已过期（或手动使 cache/user 中的 token 失效）
# 2. 启动 mitmproxy：mitmdump -s /tmp/lingma_intercept.py -p 8083
# 3. 设置代理：export HTTP_PROXY=http://127.0.0.1:8083
# 4. 重启灵码，等待 refresh 请求
# 5. 分析截获的 refresh_token 请求 body
```

**方法 B：二进制逆向**
- 分析 `cosy/auth/user/doRefreshToken` 函数
- 查找 Encode=2 相关的编码/加密函数
- 可能需要 Ghidra 或 IDA Pro

### 优先级 2：Device Token Polling 完整流程

- 找到轮询会话启动端点
- 实现完整的 Device Token Polling 流程
- 实现不依赖灵码的独立登录

### 优先级 3：集成到 lingma2api

- 将验证过的编码算法集成到 Go 代码
- 实现独立的 v1 API 调用
- 等 Encode=2 逆向完成后实现 v3 API 调用

---

## 6. 关键文件索引

### 灵码二进制（macOS ARM64）

```
~/.lingma/bin/2.11.2/aarch64_darwin/Lingma     - 主二进制（96MB）
~/.lingma/bin/2.11.2/aarch64_darwin/LingmaLocal - 本地辅助（5MB）
```

### 缓存文件

```
~/.lingma/cache/id          - machine_id（UUID，明文）
~/.lingma/cache/user        - 用户凭证（AES-128-CBC 加密）
~/.lingma/cache/app-config.json - 应用配置（含代理设置）
~/.lingma/cache/cache.json  - 区域配置（regionEnv: cn）
```

### 项目文件

```
lingma2api/internal/auth/token_exchange.go  - OAuth token exchange（需要 client_id）
lingma2api/internal/auth/remote_login.go    - 远程登录（Encode=1 AES 版本）
lingma2api/internal/auth/ws_refresh.go      - WebSocket token 刷新
lingma2api/internal/auth/encode1.go         - Encode=1 编码实现
lingma2api/internal/auth/bootstrap.go       - 登录 URL 构造
lingma_remote_api.py                        - Python 远程 API 客户端
```

### 截获的数据

```
/tmp/lingma_captures/req_*.txt   - 截获的完整请求
/tmp/lingma_captures/resp_*.txt  - 截获的完整响应
/tmp/lingma_creds.json           - 最新缓存凭证
```

---

## 7. 端点完整列表

| 端点 | 方法 | 认证 | 编码 | 状态 |
|------|------|------|------|------|
| `/algo/api/v1/ping` | GET | 旧签名 | 无 | ✅ 200 |
| `/algo/api/v1/heartbeat` | POST | 旧签名 | Encode=1 | ✅ 200 |
| `/algo/api/v1/tracking` | POST | 旧签名 | Encode=1 | ✅ 200 |
| `/algo/api/v2/model/list` | GET | COSY Bearer | 无 | ✅ 可用 |
| `/algo/api/v3/user/oauth2/deviceToken/poll` | GET | 旧签名 | 无 | ✅ 200（空响应） |
| `/algo/api/v3/user/refresh_token` | POST | 旧签名 | Encode=1 | ⚠️ 400 "auth payload is invalid" |
| `/algo/api/v3/user/status` | POST | 旧签名 | Encode=1 | ⚠️ 400 "auth payload is invalid" |
| `/algo/api/v3/user/login` | POST | 旧签名 | Encode=1 | ❌ 500 |
| `/algo/api/v3/user/remoteToken` | GET | ??? | 无 | ❌ 403 "Signature invalid" |
| `/algo/api/v3/user/logout` | POST | ??? | ??? | 未测试 |

---

## 8. 环境变量与配置

### 灵码环境变量

```
LINGMA_COSY_KEY             - COSY 密钥
LINGMA_ENCRYPT_USER_INFO    - 加密用户信息
LINGMA_USER_ID              - 用户 ID
LINGMA_MACHINE_ID           - 机器 ID
LINGMA_CLIENT_ID            - OAuth client_id（需手动提取）
```

### 服务端地址

```
CN:  lingma-api.tongyi.aliyun.com/algo
Intl: lingma.alibabacloud.com/algo
```

### 代理配置（用于截获请求）

```json
// ~/.lingma/cache/app-config.json
{
  "proxyMode": "manual",
  "httpProxy": "http://127.0.0.1:8083"
}
```

启动灵码时需要设置环境变量：
```bash
HTTP_PROXY=http://127.0.0.1:8083 HTTPS_PROXY=http://127.0.0.1:8083 \
  ~/.lingma/bin/2.11.2/aarch64_darwin/Lingma start
```
