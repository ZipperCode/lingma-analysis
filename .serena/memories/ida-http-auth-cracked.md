# IDA HTTP Authorization Header 完全破解

## 核心发现

通过IDA Pro MCP静态分析，完全破解了Lingma的Authorization header构造方式，发现了关键错误：

### Payload字段（IDA验证）

**原推测（错误）**：
```json
{
  "version": "v2",
  "requestId": "<UUID>",
  "userId": "<userId>",
  "securityOauthToken": "<pt-token>",
  "path": "/api/v3/user/refresh_token",
  "method": "POST"
}
```

**IDA验证（正确）**：
```json
{
  "version": "v2",
  "requestId": "<UUID>",
  "user": "<userId>",           // 字段名是 "user" 不是 "userId"
  "cosyVersion": "2.11.2",      // 硬编码全局变量
  "ideVersion": "<IDE版本>"
}
```

### 签名参数顺序（IDA验证）

**原推测（错误）**：
```
userId → secToken → refreshToken → path → method
```

**IDA验证（正确）**：
```
userId → method → path → refreshToken → secToken
```

### Signature Header（IDA验证）

**签名公式**：
```
MD5("cosy&" + session_key + "&" + RFC1123_date)
```

**Session Key**：
- Base64: `"d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="`
- 解码: `"war, war never changes"`
- 条件切换: `byte_14616BD2F=1` 时使用 `"&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe"`

## 关键函数地址

| 函数 | 地址 | 功能 |
|------|------|------|
| getAuthPayload | 0x14088c720 | Payload构造 |
| getAuthSignature | 0x14088c4e0 | 签名计算 |
| doRefreshToken | 0x14088d660 | HTTP refresh主流程 |
| addBigModelSignatureHeaders | 0x14087e5e0 | Signature headers |

## 核心问题

**v3 endpoint返回HTML（官网首页）**，不是JSON响应。

**原因**：pt-* token格式不被v3 endpoint接受，期望标准JWT token（`eyJ...`）。

**解决方案**：
- 方案1：WebSocket认证（已实现）
- 方案2：继续IDA分析OAuth流程
- 方案3：提取client_id使用标准OAuth

## How to apply

- HTTP直接刷新当前不可行（pt-* token与v3 endpoint不兼容）
- WebSocket refresh是可行方案（已在memory中记录）
- 后续分析应优先研究OAuth login流程和client_id来源
- IDA验证的正确参数顺序必须用于所有HTTP构造尝试