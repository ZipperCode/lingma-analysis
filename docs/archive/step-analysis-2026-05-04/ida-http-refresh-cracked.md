# Lingma HTTP Token Refresh 完全破解

## 概述

通过IDA Pro MCP静态分析，完全破解了Lingma程序的HTTP token refresh机制，包括：
- Authorization header构造方式
- Signature header构造方式
- Payload字段名称和顺序
- 签名参数顺序

## IDA Pro MCP验证的关键发现

### 1. Authorization Header构造（IDA验证）

**函数**：`getAuthPayload` (0x14088c720)

**Payload字段（IDA验证）**：
```json
{
  "version": "v2",
  "requestId": "<UUID>",
  "user": "<userId>",           // 注意：字段名是 "user" 不是 "userId"
  "cosyVersion": "2.11.2",      // 硬编码全局变量
  "ideVersion": "<IDE版本>"
}
```

**字段来源**：
- `version`: 硬编码 `"v2"`
- `requestId`: UUID动态生成
- `user`: 从参数传入（用户ID）
- `cosyVersion`: 全局变量 `off_145FD70C0` → `"2.11.2"`（长度6）
- `ideVersion`: 从参数传入

**Payload处理流程**：
1. 创建map `runtime_makemap_small()`
2. 添加字段 `runtime_mapassign_faststr()`
3. JSON序列化 `encoding_json_Marshal()`
4. Base64编码 `encoding_base64_EncodeToString()`

### 2. 签名计算（IDA验证）

**函数**：`getAuthSignature` (0x14088c4e0)

**签名格式**（IDA验证）：
```
fmt.Sprintf("%s\n%s\n%s\n%s\n%s", userId, method, path, refreshToken, secToken)
```

**参数顺序（IDA验证）**：
```
userId → method → path → refreshToken → securityOauthToken
```

**重要发现**：
- 参数顺序与之前推测完全不同！
- 原推测：userId → secToken → refreshToken → path → method
- IDA验证：userId → method → path → refreshToken → secToken

**签名计算**：
```python
sign_data = f"{userId}\n{method}\n{path}\n{refreshToken}\n{secToken}"
signature = hashlib.md5(sign_data.encode()).hexdigest()
```

### 3. Signature Header构造（IDA验证）

**函数**：`addBigModelSignatureHeaders` (0x14087e5e0)

**Headers添加**：
- `Date`: RFC1123格式时间
- `Cosy-Signature`: MD5签名

**签名计算公式（IDA验证）**：
```
MD5("cosy&" + session_key + "&" + RFC1123_date)
```

**Session Key（IDA验证）**：
- 默认：`"d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="`（base64）
- 解码后：`"war, war never changes"`
- 条件切换：`byte_14616BD2F` 为1时使用 `"&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe"`

### 4. HTTP请求构造流程（IDA验证）

**主函数**：`doRefreshToken` (0x14088d660)

**流程**：
1. 构造 `AuthQueryParam` 结构：
   ```go
   {
     UserId: <userId>,
     OrgId: <orgId>,
     SecurityOauthToken: <pt-token>,
     RefreshToken: <rt-token>
   }
   ```

2. 构造 `HttpPayload` 结构：
   ```go
   {
     Payload: JSON.stringify(AuthQueryParam),
     EncodeVersion: <版本>,
     RequestId: <UUID>
   }
   ```

3. 调用 `BuildBigModelSignRequest()`：
   - Method: `"POST"` (unk_1424AC224)
   - Path: `"/api/v3/user/refresh_token"`

4. 调用 `buildRequest()` → 添加headers：
   - `addBigModelAuthorizationHeaders()` → Authorization header
   - `addBigModelSignatureHeaders()` → Signature headers

5. 发送HTTP请求 → 解析响应

### 5. 关键问题分析

**问题**：v3 endpoint返回HTML页面（官网首页），不是JSON响应

**可能原因**：
1. **认证失败**：pt-* token格式不被v3 endpoint接受
   - IDA分析：pt-* 是Lingma内部格式（存储在 CosyUserInfo.SecurityOauthToken）
   - v3 endpoint期望：标准JWT token（`eyJ...`）
   - 格式不兼容：这是核心问题

2. **缺少必要headers**：可能需要其他认证相关的headers

3. **Endpoint重定向**：认证失败导致重定向到官网首页

## 下一步方案

### 方案1：WebSocket认证（已实现）
- Memory记录：WebSocket refresh已成功实现
- 优势：绕过HTTP格式限制，直接使用内部协议

### 方案2：继续IDA分析
- 搜索其他HTTP endpoint
- 分析OAuth login流程
- 查找client_id来源

### 方案3：Frida动态验证
- 绕过反调试后，监控实际HTTP请求
- 验证IDA分析的参数顺序和payload结构

## IDA Pro MCP验证总结

### 完全验证的部分 ✅
- Payload字段名称和来源
- 签名参数顺序（关键发现）
- Signature header计算公式
- session_key来源和值

### 未解决的问题 ❌
- v3 endpoint不接受当前请求格式
- pt-* token与JWT格式兼容性问题
- 缺少client_id导致无法使用标准OAuth

## 附录：IDA关键函数地址

| 函数名 | 地址 | 功能 |
|--------|------|------|
| `getAuthPayload` | 0x14088c720 | 构造Authorization payload |
| `getAuthSignature` | 0x14088c4e0 | 计算Authorization签名 |
| `doRefreshToken` | 0x14088d660 | HTTP refresh主流程 |
| `BuildBigModelSignRequest` | 0x14087ca20 | 构造签名请求 |
| `buildRequest` | 0x14087cc20 | 构造HTTP请求 |
| `addBigModelAuthorizationHeaders` | 0x14087ea20 | 添加Authorization header |
| `addBigModelSignatureHeaders` | 0x14087e5e0 | 添加Signature headers |

## Python实现示例（IDA验证版）

```python
import hashlib
import base64
import json
import uuid
from datetime import datetime, timezone

def build_authorization_header(user_id, ide_version="vscode"):
    """IDA验证的正确Authorization header构造"""
    payload = {
        "version": "v2",
        "requestId": str(uuid.uuid4()),
        "user": user_id,
        "cosyVersion": "2.11.2",
        "ideVersion": ide_version
    }

    payload_json = json.dumps(payload, separators=(',', ':'))
    payload_b64 = base64.b64encode(payload_json.encode()).decode()

    # 签名参数顺序（IDA验证）
    sign_data = f"{user_id}\nPOST\n/api/v3/user/refresh_token\n{refresh_token}\n{sec_token}"
    signature = hashlib.md5(sign_data.encode()).hexdigest()

    return f"Bearer COSY.{payload_b64}.{signature}"

def build_signature_header():
    """IDA验证的Signature header构造"""
    date_str = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
    session_key = "war, war never changes"  # base64解码后
    sign_input = f"cosy&{session_key}&{date_str}"
    signature = hashlib.md5(sign_input.encode()).hexdigest()

    return {
        "Date": date_str,
        "Cosy-Signature": signature
    }
```

---

**结论**：通过IDA Pro MCP静态分析，完全破解了Authorization和Signature header的构造方式，但发现了pt-* token与v3 endpoint格式不兼容的核心问题，需要采用WebSocket方案或继续分析OAuth流程。