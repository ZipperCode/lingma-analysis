# Lingma 编码与签名分析报告 (更新)

## 最新发现 (2026-04-25)

### Heartbeat Body 编码结构

**关键发现: `$$` 是分隔符, 不是填充符!**

Heartbeat body 格式:
```
[encoded_part1]$$[encoded_part2]
```

- **Part 1** (326 chars → 244 bytes): 设备信息 JSON (截断, 缺失前 ~38 字节)
- **Part 2** (656 chars → 492 bytes): 遥测事件 JSON (截断, 缺失前 ~66 字节)

### 编码方式确认

- **自定义 64 字符字母表**: `_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!`
- **6 bits/字符**, 大端位打包
- **`$` 字符**: 不在字母表中, 用作**分隔符** (分隔两个独立编码的 JSON 片段)
- **无 AES 加密**: Body 为明文 JSON, 仅做了自定义 base64 编码

### HTTP 请求头

所有 `/algo/*` 请求携带以下头部:
```
Appcode: cosy
Content-Type: application/json
Cosy-Clientip: 198.18.0.1
Cosy-Clienttype: 2
Cosy-Machineid: 35346164-3866-492d-a339-30773a32652d
Cosy-Machineos: x86_64_windows
Cosy-Machinetoken: (空)
Cosy-Machinetype: (空)
Cosy-Version: 2.11.1
Date: Fri, 24 Apr 2026 14:23:16 GMT
Login-Version: v2
Signature: 8d915d7d99452c143dc52ce040b9a355
```

### Signature 头分析

**重要发现:**
1. **签名是 32 位十六进制 = MD5**
2. **签名依赖时间戳**: 同一秒内的请求 (ping + heartbeat) 签名相同
3. **签名不依赖路径**: ping (`/algo/api/v1/ping`) 和 heartbeat (`/algo/api/v1/heartbeat?Encode=1`) 在同一时刻签名相同
4. **签名不依赖 Body**: 空 body 的 GET ping 和有 body 的 POST heartbeat 签名相同
5. **跨 Session 不同**: 同一端点在不同 session 中签名不同 (即使同一时间戳)

**推论:** `Signature = MD5(timestamp + session_key)`
- `timestamp`: Unix 时间戳字符串 (如 `1777011796`)
- `session_key`: 登录后的会话密钥, 存储在 `CosyUserInfo` 结构体中

### Frida 签名分析 (v2 API)

从 `frida-signature-trace-37017-login.jsonl`:

1. **trimQueryPath**: 去除 `/algo` 前缀
   - `/algo/api/v2/model/list` → `/api/v2/model/list`

2. **getAuthPayload**: 生成认证 payload
   - 输入: 664 bytes base64 (223 bytes 二进制) - 加密/认证数据
   - 输出: 1040 bytes base64 → JSON `{"cosyVersion":"2.11.1","ideVersion":"","info":"<encrypted>","requestId":"...","version":"v1"}`

3. **getAuthSignature**: 计算签名 (v2 API 认证, 不同于 Signature 头)
   - 函数: `cosy/auth/user.getAuthSignature`
   - 输入: payload JSON (1040 chars b64), path (18 chars), timestamp (10 chars), 栈上值 (172 chars b64 = 128 bytes)
   - 输出: `a0c8bb3de47a955df4f786b4000faa0d` (32 hex chars = MD5)

### 函数调用链 (Go 二进制)

```
cosy/remoting.createHTTPRequest
  → cosy/remoting.encodeRequestBody
    → custom_base64_encode (自定义字母表)
  → cosy/remoting.buildRequest
    → BuildBigModelSignRequest (认证请求签名)
      → cosy/auth/user.getAuthPayload
      → cosy/auth/user.getAuthSignature
  → cosy/remoting.addBigModelSignatureHeaders
    → cosy/remoting.getAppSalt
  → cosy/remoting.addBigModelAuthorizationHeaders
```

### Go 函数列表 (从 pclntab 提取)

**cosy/remoting 包:**
- `trimQueryPath` - 去除 URL 中 `/algo` 前缀
- `BuildBigModelSignRequest` - 构建带签名的请求
- `BuildBigModelAuthRequest` - 构建认证请求
- `addBigModelSignatureHeaders` - 添加 Signature 头
- `addBigModelAuthorizationHeaders` - 添加 Authorization 头
- `getAppSalt` - 获取应用盐值/密钥
- `shouldAddEncodeParam` - 判断是否添加编码参数
- `shouldEncryptBody` - 判断是否加密 body
- `GetMessageEncode` - 获取消息编码方式
- `encodeRequestBody` - 编码请求体

**cosy/auth/user 包:**
- `getAuthSignature` - 计算认证签名
- `getAuthPayload` - 生成认证 payload
- `AuthToken` - 获取认证令牌
- `EnsureTokenValid` - 确保令牌有效
- `refreshTokenConcurrentSafe` - 安全刷新令牌
- `NewCosyUserInfo` - 创建用户信息结构
- `GetCachedUserInfo` - 获取缓存用户信息
- `SaveStatusToFile` / `loadStatusFromFile` - 状态持久化

**cosy/core/heartbeat 包:**
- `InitHeartbeat` - 初始化心跳
- `ReportHeartbeat` - 上报心跳
- `appendDeviceInformation` - 追加设备信息
- `appendIdeInformation` - 追加 IDE 信息
- `appendProfilerInfo` - 追加分析器信息

### 签名算法 (未完全确认)

**Signature 头 (v1 API `/algo/*`):**
- 格式: 32 位十六进制 = MD5
- 依赖: 时间戳 + session_key
- 可能公式: `MD5(timestamp_str + secret)` 其中 secret 来自 `getAppSalt()`
- 已尝试的所有组合均未匹配 (因为 session_key 未知)

**getAuthSignature (v2 API `/api/v2/*`):**
- 格式: 32 位十六进制 = MD5
- 输入: payload JSON base64, path, timestamp, 128 字节密钥
- 输出: MD5 哈希
- 已尝试的所有 MD5/HMAC-MD5 组合均未匹配

### 未解决问题

1. **Body 截断**: 两个 Part 都缺少开头, 可能是 capture 工具的 bug
2. **签名算法**: 未找到精确匹配, 但确认是 MD5 且依赖时间戳
3. **Session Key**: 未知的认证密钥, 可能来自登录流程或本地配置
4. **`encodeRequestBody`**: 未捕获到实际的 POST body 编码过程
5. **Part 1 和 Part 2 的关系**: 为什么分成两部分?
6. **完整的 JSON 结构**: 缺失的前缀需要推断
7. **getAuthPayload 的 664 字节输入**: 加密/认证数据的来源和含义

## 编码管道 (确认部分)

```
明文 JSON → 自定义 base64 编码 → $$ 分隔 → HTTP POST body
```

**没有 AES 加密!** Heartbeat body 是明文 JSON 编码后发送的。

### Heartbeat Part 1 推测结构

缺失前缀 ~38 字节, 可见部分:
```
6-A0BA-64C697DA4599","expr_features":"{}","host_system":"x86_64_windows",
"ide_type":"plugin","ide_types":"","ide_version":"","os_arch":"windows_amd64",
"os_version":"Microsoft Windows [Version 10.0.26200.8037]","product_type":"lingma","tag":""}}
```

推测完整结构:
```json
{
  "uuid": "xxx",
  "device_hardware_id": "PF39BB4E",
  "device_mac_address": "90:2e:16:f8:72:db",
  // ... 更多设备标识 ...
  "expr_features": "{}",
  "host_system": "x86_64_windows",
  "ide_type": "plugin",
  "os_arch": "windows_amd64",
  "os_version": "Microsoft Windows [Version 10.0.26200.8037]",
  "product_type": "lingma"
}
```

### Heartbeat Part 2 推测结构

缺失前缀 ~66 字节, 可见部分:
```
plugin","aid":"","uid":"","rid":"","yid":"","oid":"","event_data":
{"cosy_version":"2.11.1","device_disk_serial_num":"54ad8f9c",
"device_hardware_id":"PF39BB4E","device_mac_address":"90:2e:16:f8:72:db",
"device_machine_serial_num":"58A45399-5D14-4D5{"uuid":"0c6226f8-17ed-4dc1-8946-4de6645c37c2",
"event_time":1777040596228,"event_type":"cosy_heartbeat",
"mid":"35346164-3866-492d-a339-30773a32652d","os_arch":"windows_amd64",
"os_version":"Microsoft Windows [Version 10.0.26200.8037]","ide_type":"
```

推测完整结构 (心跳遥测事件):
```json
{
  "product_type": "plugin",
  "aid": "",
  "uid": "",
  "rid": "",
  "yid": "",
  "oid": "",
  "event_data": {
    "cosy_version": "2.11.1",
    "device_disk_serial_num": "54ad8f9c",
    "device_hardware_id": "PF39BB4E",
    "device_mac_address": "90:2e:16:f8:72:db",
    "device_machine_serial_num": "58A45399-5D14-4D5...",
    "uuid": "0c6226f8-17ed-4dc1-8946-4de6645c37c2",
    "event_time": 1777040596228,
    "event_type": "cosy_heartbeat",
    "mid": "35346164-3866-492d-a339-30773a32652d",
    "os_arch": "windows_amd64",
    "os_version": "Microsoft Windows [Version 10.0.26200.8037]",
    "ide_type": "plugin"
  }
}
```

## 捕获数据汇总

### Capture 1 (body-20260424-222313.jsonl)
| # | 方法 | 路径 | 时间戳 | Signature | body_sha256 |
|---|------|------|--------|-----------|-------------|
| 0 | GET | /algo/api/v1/ping | 1777011796 | 8d915d7d99452c143dc52ce040b9a355 | e3b0c44... (empty) |
| 1 | POST | /algo/api/v1/heartbeat?Encode=1 | 1777011796 | 8d915d7d99452c143dc52ce040b9a355 | 188d3997... |
| 2 | POST | /algo/api/v1/tracking?Encode=1 | 1777011976 | e7d5d7c586d345ad664fff195518b425 | 45aacd9c... |
| 3 | POST | /algo/api/v1/tracking?Encode=1 | 1777012156 | 0a12e309cb9d31686a753ab261deaf15 | caabde8b... |

### Capture 2 (proxynofrida-20260424-235210.jsonl)
| # | 方法 | 路径 | 时间戳 | Signature | body_sha256 |
|---|------|------|--------|-----------|-------------|
| 0 | GET | /algo/api/v1/ping | 1777016140 | 0f6648253e94ed37c37f33bd3851c25c | e3b0c44... |
| 1 | POST | /algo/api/v1/heartbeat?Encode=1 | 1777016141 | a3b99965f8c76aa5398ce78bcc704d57 | 8fb5b678... |

### Frida Trace (frida-signature-trace-37017-login.jsonl)
- trimQueryPath: `/algo/api/v2/model/list` → `/api/v2/model/list`
- getAuthPayload: 664 chars b64 input → 1040 chars b64 output (JSON)
- getAuthSignature: payload + path + timestamp + secret → `a0c8bb3de47a955df4f786b4000faa0d`
