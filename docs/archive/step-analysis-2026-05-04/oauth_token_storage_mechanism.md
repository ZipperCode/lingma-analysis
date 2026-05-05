# Lingma OAuth Token Storage Mechanism Complete Analysis

通过IDA Pro MCP静态分析完全破解OAuth token存储机制

## 核心发现

**所有OAuth数据统一使用 Encode=1 自定义Base64编码** ✅

---

## 1. parseAuthInfoV3 - Auth字符串解析

### 函数地址
- **parseAuthInfoV3**: `0x141a21b80`

### 解码流程

**完整链条**：
```
auth字符串（URL编码）
  ↓ net_url.unescape(param, 6)
auth字符串（URL解码后）
  ↓ encoding.decodeString(qword_1460D9408) - Encode=1 Base64解码
解码后的JSON字符串
  ↓ cosy_util.UnmarshalToObject → JSON反序列化
LoginAuthUserInfo结构体
```

### IDA验证的反编译代码

```go
func parseAuthInfoV3(auth string) (*LoginAuthUserInfo, error) {
    // 1. URL解码（参数6表示编码类型）
    decoded, err := net_url.unescape(auth, 6)
    if err != nil {
        return nil, err
    }

    // 2. Encode=1 Base64解码（使用自定义encoding对象）
    jsonBytes, err := encoding.decodeString(qword_1460D9408, decoded)
    if err != nil {
        log.Error("decode auth info failed")
        return nil, err
    }

    // 3. JSON反序列化
    userInfo := new(LoginAuthUserInfo)
    err = cosy_util.UnmarshalToObject(string(jsonBytes), userInfo)
    if err != nil {
        log.Error("unmarshal auth info failed")
        return nil, err
    }

    // 4. 返回LoginAuthUserInfo
    return userInfo, nil
}
```

### LoginAuthUserInfo结构体（推测）

```go
type LoginAuthUserInfo struct {
    Aid     string  // 阿里云AID
    Uid     string  // 用户ID
    Name    string  // 用户名
    OrgId   string  // 组织ID
    OrgName string  // 组织名称（可选）
}
```

### Auth字符串格式总结

**编码方式**：
1. **第一层**：URL编码（`net_url.unescape`，参数6）
2. **第二层**：Encode=1自定义Base64（`encoding.decodeString(qword_1460D9408)`）
3. **第三层**：JSON字符串

**示例**：
```
原始：{"aid":"123","uid":"5930676910898027","name":"张三","orgId":"org_001"}
↓ Encode=1 Base64编码
编码：YjNfMGXxZ4KwQYNfZ4K...（自定义字母表）
↓ URL编码
最终：YjNf%20MGXxZ4KwQYNfZ4K...
```

---

## 2. parseAuthToken - Token字符串解析

### 函数地址
- **parseAuthToken**: `0x141a213e0`

### 解码流程

**完整链条**：
```
token_string
  ↓ CustomDecryptParts(token_string, 3)
Encode=1 Base64解码 + \n分割
  ↓ strings.genSplit(..., "\n", ..., 3)
[pt-* token, rt-* token, expire_time]
```

### CustomDecryptParts函数（地址：0x140455ca0）

**IDA验证的反编译代码**：
```go
func CustomDecryptParts(ciphertext string, parts int) ([]string, error) {
    // 1. Encode=1 Base64解码（使用自定义encoding对象）
    decoded, err := encoding.decodeString(qword_1460D9408, ciphertext)
    if err != nil {
        return nil, err
    }

    // 2. 字节转字符串
    plaintext := string(decoded)

    // 3. 按"\n"分割成指定数量部分
    result := strings.genSplit(plaintext, "\n", 1, parts)

    // 4. 检查分割数量
    if len(result) != parts {
        return nil, fmt.Errorf("plain text length do not match")
    }

    return result, nil
}
```

**关键发现**：
- 分隔符：`\n`（换行符，IDA验证：`unk_14393A1D0 = "\n"`）
- 分割数量：parseAuthToken传入参数 `parts=3`
- 返回：`[pt-* token, rt-* token, expire_time字符串]`

### parseAuthToken完整逻辑

```go
func parseAuthToken(tokenString string) (*TokenInfo, error) {
    // 1. CustomDecryptParts解密（分成3部分）
    parts, err := CustomDecryptParts(tokenString, 3)
    if err != nil {
        // 失败：尝试URL解码后再解密
        decoded, err2 := net_url.unescape(tokenString, 6)
        if err2 == nil {
            parts, err = CustomDecryptParts(decoded, 3)
        }
        if err != nil {
            return nil, errors.New("invalid token format")
        }
    }

    // 2. 解析过期时间（第3部分）
    expireTime, err := strconv.ParseInt(parts[2], 10, 64)
    if err != nil {
        log.Error("invalid token expire time")
        return nil, errors.New("invalid token expire time")
    }

    // 3. 返回TokenInfo
    return &TokenInfo{
        SecurityOauthToken: parts[0],  // pt-* token
        RefreshToken:       parts[1],  // rt-* token
        ExpireTime:         expireTime,
    }, nil
}
```

### TokenInfo结构体（推测）

```go
type TokenInfo struct {
    SecurityOauthToken string  // pt-* token（如：pt-Atl8MQJdcCqbDEdAZAyYgnbp）
    RefreshToken       string  // rt-* token（如：rt-GLbIaXzLEFCo8rINstjCv6EC）
    ExpireTime         int64   // 过期时间戳（如：1735689600）
}
```

### Token字符串格式总结

**编码方式**：
1. **第一层**：Encode=1自定义Base64（`encoding.decodeString(qword_1460D9408)`）
2. **第二层**：`\n`分割的3部分文本

**格式示例**：
```
原始文本：
pt-Atl8MQJdcCqbDEdAZAyYgnbp\nrt-GLbIaXzLEFCo8rINstjCv6EC\n1735689600

↓ Encode=1 Base64编码（自定义字母表）
编码后：Y3QtQXRsOE1RSmRjQ3FiREVkQVpBeVlnbmJw\ncnQtR0xiSWFYekxFRkNvOHJJTnN0akN2NkVD\nMTczNTY4OTYwMA==
（实际编码结果使用自定义字母表）
```

---

## 3. CompleteLoginWithSelectAccount - 登录完成

### 函数地址
- **CompleteLoginWithSelectAccount**: `0x141a0fee0`

### 核心流程

```go
func CompleteLoginWithSelectAccount(ctx context.Context, userInfo LoginUserInfo, token TokenInfo, responseWriter http.ResponseWriter) {
    // 1. 获取完整用户信息和quota
    quotaAndToken := GetQuotaAndTokenById(userInfo.Uid, userInfo.Name)

    // 2. 填充LoginInfoContext.UserInfo（所有字段）
    loginContext.UserInfo.Aid = userInfo.Aid
    loginContext.UserInfo.Uid = userInfo.Uid
    loginContext.UserInfo.Name = userInfo.Name
    loginContext.UserInfo.SecurityOauthToken = token.SecurityOauthToken  // pt-* token ✅
    loginContext.UserInfo.RefreshToken = token.RefreshToken              // rt-* token ✅
    loginContext.UserInfo.ExpireTime = token.ExpireTime                  // 过期时间 ✅

    // 3. 检查WhitelistStatus
    if quotaAndToken.WhitelistStatus == 7 {
        // 需要选择账户
        GrantAccountInfo(uid, name, grantType="password")
        CompleteUserLogin(loginContext)
    } else {
        // 直接完成登录
        CompleteUserLogin(loginContext)
    }
}
```

### GetQuotaAndTokenById函数（地址：0x141a16120）

**流程**：
```go
func GetQuotaAndTokenById(uid string, name string) *AuthStatusResult {
    // 1. 从本地缓存读取quota
    quotaCache := ReadQuotaCache(uid)

    // 2. 如果缓存状态=4（过期）→ 从服务器刷新
    if quotaCache.Status == 4 {
        // 调用/api/v3/user/status获取最新信息
        authStatus := fetchAuthStatusWithUri("/api/v3/user/status", uid, name)

        // 更新本地缓存
        WriteQuotaCache(authStatus)
        UpdateOrgInfo(authStatus.OrgId, authStatus.OrgName)
        UpdateUserTypeTagAndPrivacy(authStatus.UserType, authStatus.PrivacyPolicy)

        return authStatus
    }

    // 3. 缓存有效 → 直接返回缓存数据
    return quotaCache
}
```

**返回结构体**：`AuthStatusResult`（280字节，包含所有用户信息）

---

## 4. CompleteUserLogin - 最终存储

### 函数地址
- **CompleteUserLogin**: `0x141a12200`

### 核心流程

```go
func CompleteUserLogin(ctx context.Context, loginContext LoginInfoContext, responseWriter http.ResponseWriter) error {
    // 1. 确定用户类型
    userType := determineUserType()

    // 2. 构造AuthStatus结构体
    authStatus := AuthStatus{
        SecurityOauthToken: loginContext.UserInfo.SecurityOauthToken,  // pt-* token ✅
        RefreshToken:       loginContext.UserInfo.RefreshToken,        // rt-* token ✅
        ExpireTime:         loginContext.UserInfo.ExpireTime,          // 过期时间 ✅
        // ... 其他所有字段
    }

    // 3. 保存用户信息和quota（关键步骤！）
    err := saveUserInfoAndQuota(authStatus)
    if err != nil {
        // 保存失败 → 返回错误页面
        reportAuthResult(1, "login failed")
        return err
    }

    // 4. 保存成功 → 返回成功页面 + 启动后台任务
    reportAuthResult(0, "login success")
    return nil
}
```

### saveUserInfoAndQuota函数（地址：0x141a11ee0）

**IDA验证的反编译代码**：
```go
func saveUserInfoAndQuota(authStatus AuthStatusResult) error {
    // 1. 保存用户信息到CosyUserInfo（关键步骤！）
    err := SaveUserInfo(authStatus)
    if err != nil {
        log.Error("Failed to write user file: %s", err)
        return err
    }

    // 2. 写入quota缓存
    err = WriteQuotaCache(authStatus.Quota)
    if err != nil {
        log.Error("Failed to write quota file: %s", err)
        return err
    }

    // 3. 成功
    return nil
}
```

**关键发现**：
- `SaveUserInfo` → 最终存储到 **CosyUserInfo结构体** ✅
- `WriteQuotaCache` → 存储quota到本地缓存文件

---

## 5. CosyUserInfo最终存储结构（IDA验证，288字节）

### 结构体定义（完全验证）

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
    SecurityOauthToken  string    // offset 0x80,  size 16  - **pt-* token** ✅✅✅
    RefreshToken        string    // offset 0x90,  size 16  - **rt-* token** ✅✅✅
    TokenExpireTime     int64     // offset 0xa0,  size 8   - Token过期时间戳 ✅
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

**关键验证**：
- `SecurityOauthToken` 字段存储 **pt-* token** ✅（offset 0x80）
- `RefreshToken` 字段存储 **rt-* token** ✅（offset 0x90）
- `TokenExpireTime` 字段存储 **过期时间戳** ✅（offset 0xa0）

---

## 6. 关键函数地址表

| 函数名 | 地址 | 功能 |
|--------|------|------|
| `parseAuthInfoV3` | 0x141a21b80 | 解析auth字符串（URL解码+Encode=1+JSON）|
| `parseAuthToken` | 0x141a213e0 | 解析token_string（Encode=1+\n分割）|
| `CustomDecryptParts` | 0x140455ca0 | Encode=1 Base64解码+分割 |
| `CompleteLoginWithSelectAccount` | 0x141a0fee0 | 登录完成（获取完整信息）|
| `GetQuotaAndTokenById` | 0x141a16120 | 从缓存或服务器获取完整用户信息 |
| `CompleteUserLogin` | 0x141a12200 | 最终登录逻辑 |
| `saveUserInfoAndQuota` | 0x141a11ee0 | 保存用户信息和quota |
| `SaveUserInfo` | 0x14088e260 | **最终存储到CosyUserInfo** ✅ |
| `WriteQuotaCache` | 0x14088abe0 | 写入quota缓存 |

---

## 7. 全局变量表

| 变量名 | 地址 | 值/类型 | 用途 |
|--------|------|---------|------|
| `qword_1460D9408` | 0x1460D9408 | encoding对象 | **Encode=1自定义Base64 encoding对象** ✅ |
| `unk_14393A1D0` | 0x14393A1D0 | "\n" | **token_string分隔符** ✅ |
| `qword_1460D8E10` | 0x1460D8E10 | zap.Logger | 日志记录器 |

---

## 8. Encode=1编码机制统一性

### 核心发现

**所有OAuth数据都使用同一个Encode=1自定义Base64编码对象**：
- **全局encoding对象**：`qword_1460D9408`
- **自定义字母表**：Encode=1的自定义字母表（来源见encode1_mechanism_complete.md）
- **Padding字符**：`'$'`（36）

### 应用场景

| 数据类型 | 编码方式 | 分隔符 | 用途 |
|---------|---------|-------|------|
| **auth字符串** | URL编码 + **Encode=1 Base64** | 无 | 用户基本信息（Aid、Uid、Name、OrgId）|
| **token_string** | **Encode=1 Base64** | `\n` | pt-* token + rt-* token + expire_time |

**统一编码对象**：`encoding.decodeString(qword_1460D9408)` ✅

---

## 9. 完整流程图

```
OAuth回调参数：auth + token_string
│
├─ parseAuthInfoV3 (auth)
│   ├─ net_url.unescape(auth, 6) ──────→ URL解码
│   ├─ encoding.decodeString(qword_1460D9408) ──→ Encode=1 Base64解码 ✅
│   └─ JSON反序列化 ────────────────────────→ LoginAuthUserInfo (Aid, Uid, Name, OrgId)
│
├─ parseAuthToken (token_string)
│   ├─ CustomDecryptParts(token_string, 3)
│   │   ├─ encoding.decodeString(qword_1460D9408) ──→ Encode=1 Base64解码 ✅
│   │   └─ strings.genSplit(plaintext, "\n", 3) ────→ \n分割 ✅
│   └─ strconv.ParseInt(parts[2], 10, 64) ────────→ TokenInfo (pt-*, rt-*, expire_time)
│
├─ CompleteLoginWithSelectAccount
│   ├─ GetQuotaAndTokenById(uid, name)
│   │   ├─ ReadQuotaCache(uid) ────────────────────→ 本地缓存读取
│   │   └─ fetchAuthStatusWithUri("/api/v3/user/status") ─→ 服务器刷新（如果缓存过期）
│   └─ 填充 LoginInfoContext.UserInfo ─────────────→ 所有用户信息字段
│
├─ CompleteUserLogin
│   ├─ determineUserType() ───────────────────────→ 确定用户类型
│   ├─ 构造 AuthStatus 结构体 ────────────────────→ SecurityOauthToken + RefreshToken + ExpireTime ✅
│   ├─ saveUserInfoAndQuota(authStatus)
│   │   ├─ SaveUserInfo(authStatus) ────────────────→ **存储到CosyUserInfo** ✅✅✅
│   │   │   └─ CosyUserInfo.SecurityOauthToken = pt-* token ✅
│   │   │   └─ CosyUserInfo.RefreshToken = rt-* token ✅
│   │   │   └─ CosyUserInfo.TokenExpireTime = expire_time ✅
│   │   └─ WriteQuotaCache(quota) ──────────────────→ quota缓存
│   └─ reportAuthResult() ─────────────────────────→ 返回结果页面
│
└─ OAuth登录完成 ✅
```

---

## 10. 未解决问题

### 需要动态验证 ⭕

1. **auth字符串实际格式**：
   - 验证URL编码后的auth字符串
   - 验证Encode=1 Base64解码后的JSON结构

2. **token_string实际格式**：
   - 验证Encode=1 Base64解码后的plaintext
   - 验证`\n`分割后的3部分内容

3. **SaveUserInfo存储过程**：
   - Frida监控CosyUserInfo结构体的写入过程

---

## 11. 下一步分析建议

### Frida动态验证

**监控点**：
```javascript
// 1. 监控parseAuthInfoV3
Interceptor.attach(ptr("0x141a21b80"), {
    onEnter: function(args) {
        console.log("parseAuthInfoV3 input:", args[0], args[1]);
    },
    onLeave: function(retval) {
        console.log("parseAuthInfoV3 output:", retval);
    }
});

// 2. 监控parseAuthToken
Interceptor.attach(ptr("0x141a213e0"), {
    onEnter: function(args) {
        console.log("parseAuthToken input:", args[0], args[1]);
    },
    onLeave: function(retval) {
        console.log("parseAuthToken output:", retval);
    }
});

// 3. 监控SaveUserInfo
Interceptor.attach(ptr("0x14088e260"), {
    onEnter: function(args) {
        console.log("SaveUserInfo called");
        // dump CosyUserInfo结构体内容
    }
});
```

---

## 12. 安全机制总结

### 已验证安全机制 ✅

1. **Encode=1统一编码**：
   - 所有OAuth数据使用自定义Base64编码
   - 自定义字母表（防止标准Base64解码）
   - Padding字符 `$`（非标准）

2. **多层编码**：
   - auth：URL编码 + Encode=1 Base64 + JSON
   - token_string：Encode=1 Base64 + `\n`分割

3. **Nonce机制**（见oauth_login_flow_complete.md）：
   - UUID去掉"-"（32字节）
   - 使用一次后立即删除

4. **PKCE机制**（见oauth_login_flow_complete.md）：
   - Verifier + SHA256 Challenge + S256方法

### 安全风险 ⭕

1. **自定义编码非加密**：
   - Encode=1是编码而非加密
   - 静态分析已完全破解
   - 无密钥保护

2. **Token明文存储**：
   - pt-*和rt-* token明文存储到CosyUserInfo
   - 本地缓存文件可能包含敏感信息

---

## 13. 与API请求的关系

### Token使用场景（见LINGMA_API_COMPLETE_DOCUMENTATION.md）

**pt-* token用途**：
- **Authorization header签名**：MD5签名的一部分
- **SecurityOauthToken参数**：多个API请求参数

**rt-* token用途**：
- **Token刷新**：`/api/v3/user/refresh_token`请求参数
- **Authorization header签名**：MD5签名的一部分

**expire_time用途**：
- 判断token过期，触发刷新机制

---

**总结**：通过IDA Pro MCP静态分析，完全破解了Lingma OAuth token存储机制，确认所有OAuth数据（auth和token_string）统一使用Encode=1自定义Base64编码，token按`\n`分割成3部分，最终通过SaveUserInfo存储到CosyUserInfo结构体的SecurityOauthToken、RefreshToken、TokenExpireTime字段。建立了完整的OAuth回调→解析→存储链路。