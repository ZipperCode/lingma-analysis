# 灵码 HTTP 认证头构造分析（IDA Pro）

> 日期：2026-04-30
> 分析方法：IDA Pro MCP 反编译分析
> 目标：理解灵码 HTTP 请求认证头的完整构造流程

---

## 1. 核心函数调用链

### 1.1 Refresh Token 流程

```
cosy_auth_user.doRefreshToken (0x14088d660)
  → cosy_remoting.buildRequest (0x14087cd20)
    → cosy_remoting.addBigModelSignatureHeaders (0x14087e5e0)
    → cosy_remoting.addBigModelAuthorizationHeaders (0x14087ea20)
      → cosy_auth_user.AuthToken (0x14088b740)
        → cosy_auth_user.getAuthPayload (0x14088c720)
        → cosy_auth_user.getAuthSignature (0x14088c4e0)
    → cosy_remoting.shouldEncryptBody (0x14087e500)
      → cosy_remoting.shouldAddEncodeParam (0x14087e3c0)
    → cosy_remoting.encodeRequestBody (Encode=1)
    → cosy_remoting.createHTTPRequest/createCompressedHTTPRequest
  → net_http.Client.do (POST)
```

---

## 2. 签名头构造 (addBigModelSignatureHeaders)

### 2.1 函数地址

- **函数名**：`cosy_remoting.addBigModelSignatureHeaders`
- **地址**：`0x14087e5e0`
- **大小**：`0x43f` (1087 bytes)

### 2.2 关键逻辑

```c
// 1. 获取当前时间
time.Now()

// 2. 格式化为 RFC1123
time.Time.Format("Mon, 02 Jan 2006 15:04:05 GMT")
// 输出：Wed, 30 Apr 2026 08:30:00 GMT

// 3. Session Key Base64 常量
session_key_b64 = "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="
session_key = base64decode(session_key_b64)  // "war, war never changes"

// 4. 计算签名
sign_input = "cosy&" + session_key + "&" + rfc1123_date
signature = Md5Encode(sign_input)

// 5. 添加请求头
headers["Date"] = rfc1123_date
headers["Signature"] = signature
```

### 2.3 关键常量（IDA 字符串）

| 地址 | 字符串 | 说明 |
|------|--------|------|
| 0x14250bac2 | `d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw==` | Session Key Base64 |
| 0x1424fe2a3 | `Mon, 02 Jan 2006 15:04:05 GMT` | RFC1123 时间格式模板 |
| 0x14250bae2 | `9f1dff714a390b20aeb19175ecc496e6` | MD5 示例值（测试用） |

### 2.4 签名公式

```
Signature = MD5("cosy&" + "war, war never changes" + "&" + RFC1123_date)
```

**示例：**
```python
import hashlib
session_key = "war, war never changes"
date_str = "Wed, 30 Apr 2026 08:30:00 GMT"
sign_input = f"cosy&{session_key}&{date_str}"
signature = hashlib.md5(sign_input.encode()).hexdigest()
# 输出：a1b2c3d4e5f6...
```

---

## 3. 认证头构造 (addBigModelAuthorizationHeaders)

### 3.1 函数地址

- **函数名**：`cosy_remoting.addBigModelAuthorizationHeaders`
- **地址**：`0x14087ea20`
- **大小**：`0xcf` (207 bytes)

### 3.2 关键逻辑

```c
// 1. 获取 AuthProvider 实例
AuthProvider = GetAuthProvider()

// 2. Trim URL path
Path = trimQueryPath(url)

// 3. 调用 AuthenticateRequest
AuthenticateRequest(request, Path, method)
```

### 3.3 AuthenticateRequest 实现

- **函数名**：`cosy_bootstrap_modules_adapter._ptr_remotingAuthProvider.AuthenticateRequest`
- **地址**：`0x141c50020`

```c
return cosy_auth_user.AuthToken(request, path, method);
```

---

## 4. AuthToken 核心函数

### 4.1 函数地址

- **函数名**：`cosy_auth_user.AuthToken`
- **地址**：`0x14088b740`
- **大小**：`0xd85` (3461 bytes)

### 4.2 Authorization Header 格式

**关键字符串常量（IDA 字符串地址 0x1424cefe8）：**
```
Bearer COSY.%s.%s
```

**格式：**
```
Authorization: Bearer COSY.{base64_payload}.{md5_signature}
```

### 4.3 getAuthPayload 函数

- **函数名**：`cosy_auth_user.getAuthPayload`
- **地址**：`0x14088c720`
- **大小**：`0x21e` (542 bytes)

**Payload 构造逻辑：**

```c
// 1. 创建 map
payload = map[string]string{}

// 2. 添加字段
payload["version"] = "v2"
payload["requestId"] = UUID_NewString()  // 生成 UUID
payload["userId"] = userId
payload["securityOauthToken"] = cached_securityOauthToken  // 从全局变量读取
payload["path"] = request_path
payload["method"] = request_method

// 3. JSON 序列化
json_data = json.Marshal(payload)

// 4. Base64 编码
base64_payload = base64.EncodeToString(json_data)
```

**Payload JSON 示例：**
```json
{
  "version": "v2",
  "requestId": "550e8400-e29b-41d4-a716-446655440000",
  "userId": "123456",
  "securityOauthToken": "pt-abc123...",
  "path": "/api/v3/user/refresh_token",
  "method": "POST"
}
```

### 4.4 getAuthSignature 函数

- **函数名**：`cosy_auth_user.getAuthSignature`
- **地址**：`0x14088c4e0`
- **大小**：`0x225` (549 bytes)

**Signature 计算逻辑：**

```c
// 1. 格式化字符串（关键常量地址 0x1424c598f）
format = "%s\n%s\n%s\n%s\n%s"  // 5 个参数，换行分隔

// 2. 参数顺序（推测）
sign_data = sprintf(format,
    userId,                 // a1
    securityOauthToken,     // a10 (推测)
    refreshToken,           // a7 (推测)
    request_path,           // a5
    request_method          // a3
)

// 3. MD5 计算
signature = Md5Encode(sign_data)
```

**签名字符串示例：**
```
123456
pt-abc123...
rt-def456...
/api/v3/user/refresh_token
POST
```

---

## 5. Encode=1 选择逻辑

### 5.1 函数地址

- **函数名**：`cosy_remoting.shouldAddEncodeParam`
- **地址**：`0x14087e3c0`
- **大小**：`0x13e` (318 bytes)

### 5.2 Encode=1 启用条件

```c
// 1. 全局开关检查（地址 0x146011C60）
if (global_encode_flag != '1')  // ASCII 49
    return false;  // 不加密

// 2. 路径排除规则（IDA 字符串）
if (url contains "/api/v1/service/next_edit_predict")  // 地址 0x1425105bd
    return false;

if (url contains "/algo/api/v1/organizations")  // 地址 0x1424f1230
    return false;

// 3. HTTP 方法判断（Go 的方法常量）
if (method == 4) {  // POST
    if (method_str == "POST")  // ASCII 0x54534f50
        return true;  // 需要 Encode=1
}

if (method == 3) {  // PUT
    if (method_str == "PUT" && url contains "/api/v2/remoteAgent/qoder")
        return true;
}

return false;
```

### 5.3 Refresh Token 端点的 Encode 选择

- **URL**：`/api/v3/user/refresh_token`
- **方法**：POST
- **结论**：✅ 需要 Encode=1（不在排除路径，且是 POST 方法）

---

## 6. 其他 Cosy 头字段

### 6.1 关键字符串（IDA 字符串）

| 地址 | 字符串 | 说明 |
|------|--------|------|
| 0x1424da138 | `Cosy-Organization-Id` | 组织 ID |
| 0x1424e1698 | `Cosy-Organization-Tags` | 组织标签 |
| 0x1424cbc6e | `Cosy-Data-Policy` | 数据策略 |
| 0x1424c888d | `Cosy-BodyLength` | Body 长度 |

---

## 7. 完整请求构造流程

### 7.1 Refresh Token 请求示例

**步骤 1：构建 Payload**

```python
import uuid
import json
import base64

payload = {
    "version": "v2",
    "requestId": str(uuid.uuid4()),
    "userId": user_id,
    "securityOauthToken": security_oauth_token,
    "path": "/api/v3/user/refresh_token",
    "method": "POST"
}

payload_json = json.dumps(payload, separators=(',', ':'))
payload_b64 = base64.b64encode(payload_json.encode()).decode()
```

**步骤 2：计算 Signature**

```python
sign_data = f"{user_id}\n{security_oauth_token}\n{refresh_token}\n/api/v3/user/refresh_token\nPOST"
signature = hashlib.md5(sign_data.encode()).hexdigest()
```

**步骤 3：构造 Authorization Header**

```python
authorization = f"Bearer COSY.{payload_b64}.{signature}"
```

**步骤 4：构造其他头字段**

```python
headers = {
    "User-Agent": "Go-http-client/1.1",
    "Accept": "application/json",
    "Appcode": "cosy",
    "Content-Type": "application/json",
    "Cosy-Machineid": machine_id,
    "Cosy-Version": "2.11.2",
    "Cosy-Organization-Id": org_id,
    "Date": rfc1123_date,
    "Signature": md5_signature,
    "Login-Version": "v2",
    "Authorization": authorization
}
```

**步骤 5：Encode=1 编码 Body**

```python
body_json = json.dumps({
    "userId": user_id,
    "orgId": org_id,
    "securityOauthToken": security_oauth_token,
    "refreshToken": refresh_token
})

encoded_body = lingma_encode_v1(body_json.encode())
```

**步骤 6：发送请求**

```python
url = "https://lingma.alibabacloud.com/algo/api/v3/user/refresh_token?Encode=1"
response = requests.post(url, headers=headers, data=encoded_body)
```

---

## 8. 待验证事项

### 8.1 签名参数顺序

**当前推测：**
```
sign_data = "{userId}\n{securityOauthToken}\n{refreshToken}\n{path}\n{method}"
```

**需要验证：**
- 通过 Frida Hook 实时抓取 AuthToken 函数的参数
- 确认 5 个参数的准确含义和顺序

### 8.2 全局变量存储

**需要确认：**
- `off_145FD70C0` - 存储 securityOauthToken 的全局变量
- `off_145FD70C8` - 存储 refreshToken 的全局变量
- 如何在运行时读取这些全局变量的值

### 8.3 Encode=1 全局开关

**需要确认：**
- `off_146011C60` - 存储 Encode 开关状态的全局变量
- 如何在运行时修改此开关（测试 Encode=0 的情况）

---

## 9. 下一步行动

### 9.1 Frida Hook 验证

**Hook 目标函数：**
```javascript
Interceptor.attach(Module.findExportByName(null, "cosy_auth_user.AuthToken"), {
    onEnter: function(args) {
        console.log("[AuthToken] Called");
        console.log("  Request:", args[0]);
        console.log("  Path:", Memory.readUtf8String(args[1], args[2]));
        console.log("  Method:", Memory.readUtf8String(args[3], args[4]));
    },
    onLeave: function(retval) {
        console.log("[AuthToken] Return:", retval);
    }
});
```

**Hook getAuthPayload 和 getAuthSignature：**
```javascript
Interceptor.attach(Module.findExportByName(null, "cosy_auth_user.getAuthPayload"), {
    onEnter: function(args) {
        console.log("[getAuthPayload] userId:", args[0]);
    },
    onLeave: function(retval) {
        console.log("[getAuthPayload] payload:", Memory.readUtf8String(retval));
    }
});

Interceptor.attach(Module.findExportByName(null, "cosy_auth_user.getAuthSignature"), {
    onEnter: function(args) {
        console.log("[getAuthSignature] args:", args);
        // 抓取所有 10 个参数
    },
    onLeave: function(retval) {
        console.log("[getAuthSignature] signature:", Memory.readUtf8String(retval));
    }
});
```

### 9.2 脚本实现

**更新 `tools/lingma_refresh_token_direct.py`：**
- 添加 Authorization header 计算
- 添加 Cosy-Organization-Id 等其他头字段
- 验证签名参数顺序

### 9.3 测试验证

**测试矩阵：**
1. ✅ Encode=1 编码验证
2. ✅ 签名计算验证（Session Key + RFC1123）
3. ⚠️ Authorization header 验证（待 Frida Hook）
4. ⚠️ Payload JSON 字段验证（待 Frida Hook）
5. ⚠️ Signature 参数顺序验证（待 Frida Hook）

---

## 10. 参考文档

- `docs/topics/ida-oauth-refresh-analysis.md` - IDA 分析主文档
- `docs/topics/standalone-oauth-analysis.md` - OAuth 整体分析
- `docs/topics/encode1-complete-analysis.md` - Encode=1 编码还原
- `docs/topics/refresh-token-flow.md` - OAuth refresh token 流程

---

**最后更新：** 2026-04-30
**分析状态：** 进行中（需要 Frida Hook 验证签名参数顺序）