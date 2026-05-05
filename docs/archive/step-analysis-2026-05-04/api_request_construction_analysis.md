# Lingma API Request Construction Analysis

通过IDA Pro MCP反编译分析发现的请求构造模式

## 核心发现：两种请求构造模式

### 1. BuildBigModelSignRequest（签名模式）

**用途**：需要Signature header的API
- `/api/v3/user/login` - 登录
- `/api/v3/user/logout` - 登出
- `/api/v1/heartbeat` - 心跳
- `/api/v3/user/refresh_token` - Token刷新

**函数地址**：`0x14087ca20`

**调用流程**：
```
BuildBigModelSignRequest(method, path, payloadType, payload)
  → buildRequest(...)
    → addBasicHeaders(...)
    → addBigModelAuthorizationHeaders(...)  // 添加Authorization header
    → addBigModelSignatureHeaders(...)        // 添加Signature headers
```

**HTTP Method来源**：
- 地址：`unk_1424AC224`
- 内容：`"POST"`（从字符串前缀分析）

### 2. BuildBigModelAuthRequest（认证模式）

**用途**：需要AuthProvider认证的API
- `/api/v2/model/list` - 模型列表
- `/api/v2/service/*` - 服务类API

**函数地址**：`0x14087c760`

**调用流程**：
```
BuildBigModelAuthRequest(method, path, payloadType, payload)
  → GetAuthProvider()                        // 获取认证提供者
  → AuthProvider.BuildRequest(...)           // 调用提供者构造请求
    → buildRequest(...)
      → addBasicHeaders(...)
      → addBigModelAuthorizationHeaders(...) // 通过AuthProvider添加
```

**HTTP Method来源**：
- 地址：`unk_1424AAADB`
- 内容：`"GET"`（从字符串前缀分析）

## 通用请求构造框架

### buildRequest函数（核心框架）

**函数地址**：`0x14087cc20`

**主要流程**：
1. **路由解析**：
   - `routeEndpoint()` - 确定API endpoint
   - `buildURL()` - 构造完整URL

2. **请求体编码**：
   - `encodeRequestBody()` - 编码body
   - `shouldEncryptBody()` - 判断是否加密
   - 如果加密：`encoding.encodeToString()` - Encode=1编码

3. **创建HTTP请求**：
   - `createHTTPRequest()` - 创建标准请求
   - 或 `createCompressedHTTPRequest()` - 创建压缩请求

4. **添加Headers**：
   - `addBasicHeaders()` - 添加基础headers
   - 根据请求类型添加认证/签名headers

5. **日志记录**：
   - `logRequest()` - 记录请求日志

## Payload参数结构分析

### LogActionParam（登录/登出）

**类型定义**：`cosy_remoting_LogActionParam`

**字段**：
```go
type LogActionParam struct {
    UserId   string  // 用户ID
    OrgId    string  // 组织ID
    ClientIp string  // 客户端IP
}
```

**来源函数**：`performUserLogAction` (0x141a17aa0)

**序列化**：
- `ToJsonStr()` → JSON字符串
- 封装到 `HttpPayload{Payload: json_str, EncodeVersion: "...", RequestId: UUID}`

### CosyReportData（心跳）

**类型定义**：`cosy_core_sls_CosyReportData`

**字段**（大量遥测数据）：
```go
type CosyReportData struct {
    UUid            string  // UUID
    EventTime       int64   // 事件时间戳
    EventType       string  // 事件类型
    MachineId       string  // 机器ID
    OsArch          string  // OS架构
    OsVersion       string  // OS版本
    IdeType         string  // IDE类型
    IdeVersion      string  // IDE版本
    AliyunAid       string  // 阿里云AID
    AliyunUid       string  // 阿里云UID
    RequestId       string  // 请求ID
    YxUid           string  // YX UID
    OrganizationId  string  // 组织ID
    UserRegion      string  // 用户区域
    EventData       interface{} // 事件数据（动态）
}
```

**来源函数**：`PostHeartbeat` (0x140896420)

### AuthQueryParam（Token刷新）

**类型定义**：`cosy_remoting_AuthQueryParam`

**字段**：
```go
type AuthQueryParam struct {
    UserId             string  // 用户ID
    OrgId              string  // 组织ID
    SecurityOauthToken string  // 安全OAuth Token (pt-*)
    RefreshToken       string  // 刷新Token (rt-*)
    Ak                 string  // 可能是AccessKey
}
```

**来源函数**：`doRefreshToken` (0x14088d660)

### ModelConfig（模型列表）

**类型定义**：`map[string][]ModelConfig`

**响应解析**：
```go
var modelConfigs map[string][]ModelConfig
json.Unmarshal(responseBody, &modelConfigs)
```

**来源函数**：`loadRemoteModelsWithRetry` (0x140c93fa0)

## Headers构造详细分析

### Authorization Header（已完全破解）

**构造函数**：`addBigModelAuthorizationHeaders` (0x14087ea20)

**Payload字段（IDA验证）**：
```json
{
  "version": "v2",
  "requestId": "<UUID>",
  "user": "<userId>",
  "cosyVersion": "2.11.2",
  "ideVersion": "vscode"
}
```

**签名公式（IDA验证）**：
```
sign_data = userId + "\n" + method + "\n" + path + "\n" + refreshToken + "\n" + secToken
signature = MD5(sign_data)
Authorization = "Bearer COSY." + base64(payload_json) + "." + signature
```

### Signature Header（已完全破解）

**构造函数**：`addBigModelSignatureHeaders` (0x14087e5e0)

**Headers**：
- `Cosy-Date`: RFC1123格式时间
- `Cosy-Signature`: MD5签名
- `Cosy-User`: 用户信息

**签名公式（IDA验证）**：
```
signature = MD5("cosy&" + session_key + "&" + Cosy-Date)
```

**Session Key**：
- 默认：`"war, war never changes"`（解码base64 `"d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="`）
- 条件切换：`byte_14616BD2F=1` 时使用 `"&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe"`

### Basic Headers

**添加函数**：`addBasicHeaders` (0x14087ef20)

**可能包含**：
- `Content-Type`: `application/json`
- `User-Agent`: Lingma版本信息
- `Accept`: `application/json`
- `X-Request-ID`: 请求追踪ID

## 加密/编码机制

### Encode=1编码（已破解）

**判断函数**：`shouldEncryptBody` (0x14087e500)

**编码流程**：
1. 判断是否需要加密（条件未确定）
2. 如果需要：`encoding.encodeToString(qword_1460D9408, body_bytes)`
3. 编码算法：自定义base64 + block重排（已在memory中记录）

### AES加密（确认不用于API）

**结论**：AES密钥 `"QbgzpWzN7tfe43gf"` 仅用于本地缓存加密，不用于API请求加密

## 响应数据结构分析

### 成功响应模式

**状态码**：200

**JSON结构**：
```json
{
  "success": true,
  "data": { ... },
  "message": "..."
}
```

### 错误响应模式

**AccountErrorMsg结构**：
```go
type AccountErrorMsg struct {
    Code    string  // 错误代码
    Message string  // 错误消息
}
```

**错误码处理**：
- 403：用户无效，停止重试
- 其他错误：重试机制

**cosy_core_errors_Error结构**：
```go
type Error struct {
    Code    int      // 错误码
    Message string   // 错误消息
    Details []string // 详细信息列表
}
```

## 重试机制分析

### loadRemoteModelsWithRetry重试逻辑

**参数**：`maxRetries`（重试次数）

**重试策略**：
1. 失败时重试，最大次数为参数值
2. 建立请求失败：等待5秒重试
3. 发送请求失败：等待 `10秒 * 重试次数` 重试
4. 403错误：停止重试（用户无效）
5. 其他HTTP错误：继续重试直到最大次数

**日志记录**：
- 重试日志：`"loading remote models, attempt %d/%d"`
- 成功日志：`"successfully loaded remote models on attempt %d"`
- 失败日志：详细的失败原因

## HTTP客户端管理

### ClientManager.MustGetClient

**函数地址**：`0x140872740`

**参数**：
- `qword_1460D8F68` - ClientManager实例
- `&unk_1424B24F0` - 客户端配置标识（7字节）
- 内容推测：可能是客户端类型标识（如"lingma"）

**返回**：标准Go HTTP Client

## 下一步分析建议

### 高优先级
1. **AuthProvider分析**：
   - `GetAuthProvider` 函数详细分析
   - 认证提供者的构造逻辑
   - 与Authorization header的关系

2. **Encode=1条件判断**：
   - `shouldEncryptBody` 函数分析
   - 何时启用Encode=1编码

3. **动态路径参数处理**：
   - `%s/api/v1/agent/*` 等动态路径的参数替换逻辑

### 中优先级
1. **更多API的请求参数结构**：
   - Codebase相关API参数
   - RemoteAgent相关API参数
   - MCP相关API参数

2. **响应数据的完整解析**：
   - 成功响应的字段映射
   - 错误处理的分支逻辑

### 低优先级
1. **日志系统的详细分析**：
   - LogReporter完整流程
   - 遥测数据收集机制

2. **压缩请求机制**：
   - `createCompressedHTTPRequest` 分析
   - Gzip压缩的触发条件

---

**总结**：通过IDA Pro MCP分析，发现了两种主要的请求构造模式（签名模式 vs 认证模式），完全破解了Authorization和Signature headers的构造方式，识别了核心API的参数结构，建立了完整的请求构造框架理解。