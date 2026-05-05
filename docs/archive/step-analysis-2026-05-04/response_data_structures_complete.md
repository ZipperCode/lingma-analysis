# Lingma API Response Data Structures Complete Analysis

通过IDA Pro MCP静态分析完整的API响应数据结构

## 核心响应格式

### 标准API响应结构（IDA字符串验证）

**来源**：字符串地址 `0x143dc2809`

**结构定义**：
```go
type StandardResponse struct {
    RequestId    string      `json:"requestId"`
    Success      bool        `json:"success"`
    ErrorCode    string      `json:"errorCode"`
    ErrorMessage string      `json:"errorMessage"`
    Data         interface{} `json:"data"`
}
```

**JSON示例**：
```json
{
  "requestId": "550e8400-e29b-41d4-a716-446655440000",
  "success": true,
  "errorCode": "",
  "errorMessage": "",
  "data": { ... }
}
```

**失败响应示例**：
```json
{
  "requestId": "550e8400-e29b-41d4-a716-446655440000",
  "success": false,
  "errorCode": "403",
  "errorMessage": "User invalid",
  "data": null
}
```

## 1. 错误响应结构

### AccountErrorMsg（地址：0x141fe2f04）

**IDA验证结构体定义**（size 32字节）：
```go
type AccountErrorMsg struct {
    Code    string  // offset 0x0,  size 16  - 错误码（字符串型）
    Message string  // offset 0x10, size 16  - 错误消息
}
```

**JSON示例**：
```json
{
  "Code": "403",
  "Message": "User invalid, stop retry"
}
```

**应用场景**（从api_request_construction_analysis.md）：
- 用户登录失败（403：用户无效，停止重试）
- 其他认证错误

### cosy_core_errors.Error（地址：类型查询）

**IDA验证结构体定义**（size 48字节）：
```go
type Error struct {
    Code    int64      // offset 0x0,  size 8   - 错误码（数值型）
    Message string     // offset 0x8,  size 16  - 错误消息
    Details []string   // offset 0x18, size 24  - 详细信息列表
}
```

**JSON示例**：
```json
{
  "Code": 500,
  "Message": "Internal server error",
  "Details": ["Database connection failed", "Timeout exceeded"]
}
```

**关键差异**：
- `AccountErrorMsg.Code` = **string**（如"403")
- `Error.Code` = **int64**（如500）

### ErrorCode418系列（IDA字符串发现）

**发现的结构标识**：
- `ErrorCode418Delta`
- `ErrorCode418Choice`
- `ErrorCode418Content`
- `ErrorCode418Response`
- `ErrorCode418ErrorDetail`

**推测用途**：HTTP 418错误（I'm a teapot）的详细错误结构

## 2. 用户信息响应

### CosyUserInfo（地址：0x141fa351c）

**IDA验证结构体定义**（size 288字节）：
```go
type CosyUserInfo struct {
    Name                string    // offset 0x0,   size 16  - 用户名
    Aid                 string    // offset 0x10,  size 16  - 阿里云AID
    Uid                 string    // offset 0x20,  size 16  - 用户ID（主键）
    YxUid               string    // offset 0x30,  size 16  - YX UID
    OrgId               string    // offset 0x40,  size 16  - 组织ID
    OrgName             string    // offset 0x50,  size 16  - 组织名称
    StaffId             string    // offset 0x60,  size 16  - 员工ID
    AvatarUrl           string    // offset 0x70,  size 16  - 头像URL
    SecurityOauthToken  string    // offset 0x80,  size 16  - pt-* token（验证）
    RefreshToken        string    // offset 0x90,  size 16  - rt-* token（验证）
    TokenExpireTime     int64     // offset 0xa0,  size 8   - Token过期时间戳
    Key                 string    // offset 0xa8,  size 16  - 密钥（用途未确定）
    EncryptUserInfo     string    // offset 0xb8,  size 16  - 加密用户信息
    UserSourceChannel   string    // offset 0xc8,  size 16  - 用户来源渠道
    UserType            string    // offset 0xd8,  size 16  - 用户类型
    DataPolicyAgreed    bool      // offset 0xe8,  size 1   - 数据策略同意标志
    Email               string    // offset 0xf0,  size 16  - 邮箱地址
    IsDataPolicyModifiable bool   // offset 0x100, size 1   - 数据策略可修改标志
    IsQuotaExceeded     bool      // offset 0x101, size 1   - 配额超限标志
    OrganizationTags    []string  // offset 0x108, size 24  - 组织标签列表
}
```

**JSON示例**：
```json
{
  "Name": "张三",
  "Aid": "123456789",
  "Uid": "5930676910898027",
  "YxUid": "yx_abc123",
  "OrgId": "org_001",
  "OrgName": "阿里巴巴",
  "StaffId": "staff_123",
  "AvatarUrl": "https://...",
  "SecurityOauthToken": "pt-Atl8MQJdcCqbDEdAZAyYgnbp",
  "RefreshToken": "rt-GLbIaXzLEFCo8rINstjCv6EC",
  "TokenExpireTime": 1735689600,
  "Key": "",
  "EncryptUserInfo": "",
  "UserSourceChannel": "aliyun",
  "UserType": "enterprise",
  "DataPolicyAgreed": true,
  "Email": "zhangsan@example.com",
  "IsDataPolicyModifiable": true,
  "IsQuotaExceeded": false,
  "OrganizationTags": ["admin", "developer"]
}
```

**关键验证**：
- `SecurityOauthToken` 字段确实存储 pt-* token ✅
- `RefreshToken` 字段确实存储 rt-* token ✅
- 完整288字节布局确认 ✅

## 3. Token刷新响应

### 推测响应结构（基于doRefreshToken分析）

**成功响应**：
```go
type RefreshTokenResponse struct {
    RequestId string `json:"requestId"`
    Success   bool   `json:"success"`
    Data      struct {
        AccessToken      string `json:"accessToken"`       // 新的access token
        SecurityOauthToken string `json:"securityOauthToken"` // 新的pt-* token        RefreshToken     string `json:"refreshToken"`      // 新的rt-* token        ExpireTime       int64  `json:"expireTime"`        // 过期时间
    } `json:"data"`
}
```

**JSON示例（推测）**：
```json
{
  "requestId": "550e8400-e29b-41d4-a716-446655440000",
  "success": true,
  "data": {
    "accessToken": "eyJ...",
    "securityOauthToken": "pt-NewToken123",
    "refreshToken": "rt-NewRefresh456",
    "expireTime": 1735689600
  }
}
```

**失败响应（v3 endpoint问题）**：
- 状态码200，但返回HTML（官网首页）
- 推测原因：pt-* token格式不被接受

## 4. 模型列表响应

### ModelConfig（IDA字符串发现）

**字符串标识**：
- `*util.ModelConfig`
- `*types.ModelConfig`
- `*config.ModelConfig`
- `*map[string][]types.ModelConfig`

**推测结构**（从api_request_construction_analysis.md）：
```go
type ModelConfig struct {
    ModelId      string `json:"modelId"`      // 模型ID
    ModelName    string `json:"modelName"`    // 模型名称
    ModelType    string `json:"modelType"`    // 模型类型
    MaxTokens    int    `json:"maxTokens"`    // 最大tokens
    Description  string `json:"description"`  - 描述
    Enabled      bool   `json:"enabled"`      // 是否启用
}

type ModelListResponse struct {
    RequestId string                         `json:"requestId"`
    Success   bool                           `json:"success"`
    Data      map[string][]ModelConfig       `json:"data"`  // 按类型分组
}
```

**JSON示例（推测）**：
```json
{
  "requestId": "...",
  "success": true,
  "data": {
    "chat": [
      {"modelId": "qwen-max", "modelName": "Qwen Max", "modelType": "chat", "maxTokens": 8192, "enabled": true}
    ],
    "embedding": [
      {"modelId": "text-embedding-v1", "modelName": "Text Embedding V1", "modelType": "embedding", "maxTokens": 512, "enabled": true}
    ]
  }
}
```

## 5. Codebase响应

### ReadFileResponse / RecommendFileResponse（IDA字符串发现）

**字符串标识**：
- `*codebase.ReadFileResponse`
- `*codebase.RecommendFileResponse`

**推测结构**：
```go
type ReadFileResponse struct {
    RequestId string `json:"requestId"`
    Success   bool   `json:"success"`
    Data      struct {
        FilePath    string `json:"filePath"`    // 文件路径
        Content     string `json:"content"`     // 文件内容
        Language    string `json:"language"`    // 编程语言
        Size        int64  `json:"size"`        // 文件大小
        LineCount   int    `json:"lineCount"`   // 行数
    } `json:"data"`
}
```

## 6. 心跳响应

### HeartbeatResponse（推测）

**推测结构**：
```go
type HeartbeatResponse struct {
    RequestId string `json:"requestId"`
    Success   bool   `json:"success"`
    Data      struct {
        Status      string `json:"status"`      // 状态："ok"
        ServerTime  int64  `json:"serverTime"`  // 服务器时间戳
        Version     string `json:"version"`     // 版本信息
    } `json:"data"`
}
```

## 7. Remote Agent响应

### Qoder Agent任务响应（推测）

**推测结构**：
```go
type TaskResponse struct {
    RequestId string `json:"requestId"`
    Success   bool   `json:"success"`
    Data      struct {
        TaskId      string `json:"taskId"`      // 任务ID
        TaskStatus  string `json:"taskStatus"`  // 任务状态
        TaskName    string `json:"taskName"`    // 任务名称
        Progress    int    `json:"progress"`    // 进度百分比
        Result      string `json:"result"`      // 任务结果（完成后）
        Error       string `json:"error"`       - 错误信息（失败时）
    } `json:"data"`
}
```

## 8. 分页响应结构

### IDA字符串发现的分页标识

**字符串发现**（从cosy_core_errors查询结果）：
- `Page int json:page`
- `PageSize int json:pageSize`
- `Total int json:total`
- `Records []... json:records`

**标准分页响应结构**：
```go
type PageResponse struct {
    RequestId string      `json:"requestId"`
    Success   bool        `json:"success"`
    Total     int         `json:"total"`     // 总记录数
    PageSize  int         `json:"pageSize"`  // 每页大小
    Page      int         `json:"page"`      // 当前页码
    Records   interface{} `json:"records"`   // 记录列表
    Error     Error       `json:"error"`     // 错误信息（可选）
    Reason    string      `json:"reason"`    // 原因（可选）
}
```

**JSON示例**：
```json
{
  "requestId": "...",
  "success": true,
  "total": 100,
  "pageSize": 20,
  "page": 1,
  "records": [...]
}
```

## 9. 响应字段映射表

### 标准响应字段

| 字段名 | 类型 | 必需 | 说明 | 示例值 |
|--------|------|------|------|--------|
| `requestId` | string | ✅ | 请求追踪ID | UUID格式 |
| `success` | bool | ✅ | 成功标志 | `true` / `false` |
| `errorCode` | string | ⭕ | 错误码 | `"403"` |
| `errorMessage` | string | ⭕ | 错误消息 | `"User invalid"` |
| `data` | interface{} | ⭕ | 响应数据 | JSON对象或数组 |

### 分页响应字段

| 字段名 | 类型 | 必需 | 说明 | 示例值 |
|--------|------|------|------|--------|
| `total` | int | ✅ | 总记录数 | `100` |
| `pageSize` | int | ✅ | 每页大小 | `20` |
| `page` | int | ✅ | 当前页码 | `1` |
| `records` | []T | ✅ | 记录列表 | JSON数组 |

### 错误响应字段

| 结构体 | Code类型 | Message | Details | 用途 |
|--------|---------|---------|---------|------|
| `AccountErrorMsg` | **string** | ✅ | ❌ | 账户错误 |
| `Error` | **int64** | ✅ | ✅ | 通用错误 |

## 10. 状态码语义

### HTTP状态码

| 状态码 | 含义 | 响应类型 | 处理策略 |
|--------|------|---------|---------|
| 200 | 成功 | JSON响应 | 解析data字段 |
| 200 | 成功但HTML | HTML页面 | endpoint重定向（v3问题）|
| 403 | 用户无效 | JSON错误 | 停止重试 |
| 500 | 服务器错误 | JSON错误 | 重试机制 |
| 其他 | 其他错误 | JSON错误 | 根据errorCode处理 |

### ErrorCode值（推测）

| ErrorCode | 含义 | HTTP状态码 |
|-----------|------|-----------|
| `"403"` | 用户无效 | 403 |
| `"401"` | 认证失败 | 401 |
| `"500"` | 内部错误 | 500 |
| `"418"` | 特殊错误 | 418 |

## 11. 响应解析逻辑

### 成功判断（IDA分析）

**逻辑流程**：
```go
func parseResponse(response []byte) error {
    var resp StandardResponse
    err := json.Unmarshal(response, &resp)
    if err != nil {
        return err
    }

    if !resp.Success {
        // 失败响应处理
        if resp.ErrorCode == "403" {
            return fmt.Errorf("user invalid, stop retry")
        }
        return fmt.Errorf("error %s: %s", resp.ErrorCode, resp.ErrorMessage)
    }

    // 成功响应处理
    return parseData(resp.Data)
}
```

### 重试机制（loadRemoteModelsWithRetry分析）

**重试策略**（从api_request_construction_analysis.md）：
```go
func loadRemoteModels(maxRetries int) ([]ModelConfig, error) {
    for attempt := 1; attempt <= maxRetries; attempt++ {
        resp, err := sendRequest()
        if err != nil {
            if attempt == maxRetries {
                return nil, err
            }
            sleep(5 * time.Second)  // 建立请求失败：等待5秒
            continue
        }

        if resp.StatusCode == 403 {
            return nil, fmt.Errorf("user invalid")  // 停止重试
        }

        if resp.StatusCode != 200 {
            sleep(10 * time.Second * attempt)  // 发送请求失败：等待10秒 * 重试次数
            continue
        }

        // 解析成功响应
        return parseModels(resp.Body)
    }
}
```

## 12. 关键结构体地址表

| 结构体名 | 地址 | 大小 | 用途 |
|---------|------|------|------|
| `StandardResponse` | 字符串标识 | - | 通用API响应 |
| `AccountErrorMsg` | 0x141fe2f04 | 32字节 | 账户错误 |
| `Error` | 类型查询 | 48字节 | 通用错误 |
| `CosyUserInfo` | 0x141fa351c | 288字节 | 用户信息 |
| `ModelConfig` | 字符串标识 | - | 模型配置 |
| `PageResponse` | 字符串标识 | - | 分页响应 |

## 13. JSON序列化标签验证

### IDA验证的JSON标签

**AccountErrorMsg**：
```go
Code    string  // 无JSON标签（推测）
Message string  // 无JSON标签（推测）
```

**Error**：
```go
Code    int64      // 无JSON标签（推测）
Message string     // 无JSON标签（推测）
Details []string   // 无JSON标签（推测）
```

**CosyUserInfo**：
```go
// 无JSON标签（推测）
// 但从响应解析推测字段名直接映射
Name                → "name" 或 "Name"？
SecurityOauthToken  → "securityOauthToken"
RefreshToken        → "refreshToken"
```

**标准响应**（IDA字符串验证）：
```go
RequestId    string      `json:"requestId"`    ✅
Success      bool        `json:"success"`      ✅
ErrorCode    string      `json:"errorCode"`    ✅
ErrorMessage string      `json:"errorMessage"` ✅
Data         interface{} `json:"data"`         ✅
```

## 14. 下一步分析建议

### 高优先级
1. **ModelConfig结构定义**：反编译loadRemoteModels函数，获取完整结构
2. **Token刷新响应验证**：WebSocket实现验证实际响应格式
3. **更多API响应结构**：Codebase、RemoteAgent、MCP等API响应

### 中优先级
1. **JSON标签确认**：Frida动态监控JSON序列化过程
2. **错误码完整列表**：搜索所有ErrorCode常量定义
3. **分页响应实例**：搜索具体API的分页实现

### 低优先级
1. **ErrorCode418系列分析**：理解418错误的详细结构
2. **响应压缩机制**：分析gzip压缩的响应处理

## 15. 与请求构造的对应关系

### 请求→响应映射表

| API Endpoint | 请求Payload | 响应Data | 文档位置 |
|--------------|------------|----------|---------|
| `/api/v3/user/login` | LogActionParam | CosyUserInfo | api_request_construction_analysis.md |
| `/api/v3/user/refresh_token` | AuthQueryParam | TokenData（推测）| ida-http-refresh-cracked.md |
| `/api/v2/model/list` | 无payload | map[string][]ModelConfig | api_request_construction_analysis.md |
| `/api/v1/heartbeat` | CosyReportData | HeartbeatResponse（推测）| api_request_construction_analysis.md |
| `/ncqs/api/v1/quotas` | 无payload | QuotaData（推测）| api_endpoints_inventory.md |

---

**总结**：通过IDA Pro MCP静态分析，完全破解了Lingma API的核心响应数据结构，包括标准响应格式、错误结构、用户信息结构等关键定义。验证了CosyUserInfo中pt-*和rt-* token的存储位置，识别了分页响应模式，建立了请求→响应的完整映射关系。部分响应结构（ModelConfig、Token响应）仍需动态验证或进一步分析。