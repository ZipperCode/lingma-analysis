# Lingma OAuth 登录流程 Frida 监控套件

完整的 Frida 脚本套件，用于监控和分析 Lingma 客户端的 OAuth 登录流程。

## 文件列表

### 核心脚本
- **`frida_oauth_monitor.js`** - 完整 OAuth 流程监控脚本
  - 监控 14 个关键函数
  - 完整的 CosyUserInfo 结构体 dump (288 字节)
  - 详细的参数和返回值输出
  - 适合深入分析和调试

- **`frida_token_extractor.js`** - 自动 Token 提取脚本
  - 自动检测和提取 token
  - 智能识别 pt-*, rt-*, at-* token
  - 简洁的输出格式
  - 定期汇总已提取的 token
  - 适合快速提取关键信息

### 启动脚本
- **`quick_start.bat`** - 一键启动脚本
  - 自动检查环境
  - 交互式选择监控模式
  - 支持同时运行两个脚本

- **`run_oauth_monitor.bat`** - 完整监控启动脚本
  - 运行 frida_oauth_monitor.js
  - 适合详细分析场景

### 文档
- **`OAuth_Monitoring_Guide.md`** - 详细使用说明
  - 监控点详解
  - 预期输出示例
  - 关键验证点
  - 故障排除

## 快速开始

### 方式一：一键启动（推荐）
```bash
# 1. 启动 Lingma 客户端
# 2. 运行快速启动脚本
quick_start.bat

# 3. 选择监控模式
#    1 - 完整监控（详细日志）
#    2 - Token 提取（简洁输出）
#    3 - 同时运行两个脚本

# 4. 在 Lingma 中点击登录按钮
# 5. 查看监控输出
```

### 方式二：手动启动
```bash
# 1. 安装 Frida
pip install frida-tools

# 2. 启动 Lingma 客户端

# 3. 运行监控脚本
# 完整监控
frida -n lingma.exe -l frida_oauth_monitor.js

# 或 Token 提取
frida -n lingma.exe -l frida_token_extractor.js

# 4. 在 Lingma 中触发登录
```

## 监控内容

### 1. OAuth 登录启动阶段
- **LoginStart** (0x141a10680)
  - nonce 值
  - PKCE 参数初始化

- **generatePKCEChallenge** (0x141a197a0)
  - PKCE verifier (43-128 字符)
  - PKCE challenge (SHA256 + Base64)

- **PrepareLoginRequest** (0x141a198a0)
  - 授权 URL 构造
  - client_id 参数

### 2. OAuth 回调处理阶段
- **HandleAuthCallback** (0x141a18dc0)
  - LoginAuthCallbackParam 结构体
  - Nonce, Auth, TokenString

- **parseAuthInfoV3** (0x141a21b80)
  - URL 解码
  - Encode=1 Base64 解码
  - JSON 反序列化

- **parseAuthToken** (0x141a213e0)
  - Encode=1 Base64 解码
  - `\n` 分隔符验证
  - pt-*, rt-* token 提取

- **CustomDecryptParts** (0x140455ca0)
  - 自定义解密逻辑
  - 分隔符处理

### 3. Token 存储阶段
- **SaveUserInfo** (0x14088e260) **【关键】**
  - CosyUserInfo 完整结构体 (288 字节)
  - offset 0x80: SecurityOauthToken (pt-*)
  - offset 0x90: RefreshToken (rt-*)
  - offset 0xa0: TokenExpireTime
  - 其他用户信息字段

### 4. HTTP 服务器阶段
- **CreateHttpServer** (0x141b48d00)
  - 本地服务器创建
  - 端口监听

- **LoginCallback_fm** (0x141b499c0)
  - OAuth 回调处理
  - Query 参数提取

## 输出示例

### Token Auto-Extractor 输出
```
[HOOK] generatePKCEChallenge returned
[+] PKCE Verifier: dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
[+] PKCE Challenge: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuG5stw73M4

[HOOK] parseAuthToken
[+] Found tokens in parsing:
    [SECURITY_TOKEN]: pt-xxxxxxxxxxxxx...
    [REFRESH_TOKEN]: rt-xxxxxxxxxxxxx...

[HOOK] SaveUserInfo - SCANNING FOR CosyUserInfo
================================================================================
[SUCCESS] FOUND CosyUserInfo STRUCTURE
================================================================================
[+] Address: 0x1234567890
[+] SecurityToken (pt-*): pt-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
[+] RefreshToken (rt-*): rt-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
[+] ExpireTime: 1714521600 (2024-05-01T00:00:00.000Z)

================================================================================
[EXTRACTED TOKENS SUMMARY]
================================================================================
[*] SecurityToken (pt-*): pt-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
[*] RefreshToken (rt-*): rt-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
[*] ExpireTime: 1714521600 (2024-05-01T00:00:00.000Z)
================================================================================
```

### Full Monitor 输出
```
================================================================================
[HOOK] parseAuthToken
================================================================================
[*] Input parameters:
[*]   Param 0: "cHQtYWJjZGVm...\ncnQtMTIzNDU2..."
[*]   -> Found \n separator in token_string!
[*]   -> Split into 2 parts:
[*]      Part 0: "pt-abcdef123456..."
[*]      Part 1: "rt-123456abcdef..."

================================================================================
[HOOK] SaveUserInfo - DUMPING CosyUserInfo STRUCT (288 bytes)
================================================================================
================================================================================
[DUMP] CosyUserInfo @ 0x1234567890 (288 bytes)
================================================================================
0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
[... 完整十六进制 dump ...]

[KEY FIELDS]
[+] FOUND! SecurityOauthToken (0x80): "pt-xxx..."
[+] FOUND! RefreshToken (0x90): "rt-xxx..."
[*] TokenExpireTime (0xa0): 1714521600 (2024-05-01T00:00:00.000Z)
```

## 验证要点

### ✅ Encode=1 Base64 解码
- **验证内容**：自定义 Base64 字母表和 padding
- **观察点**：parseAuthInfoV3 和 parseAuthToken
- **期望结果**：识别自定义字母表（如有）

### ✅ token_string 分隔符
- **验证内容**：分隔符是否为 `\n`
- **观察点**：parseAuthToken
- **期望结果**：确认使用 `\n` 分割

### ✅ CosyUserInfo 结构体
- **验证内容**：完整 288 字节结构体
- **观察点**：SaveUserInfo
- **期望结果**：
  - offset 0x80: pt-* token
  - offset 0x90: rt-* token
  - offset 0xa0: 过期时间戳

### ✅ OAuth 流程完整性
- **验证内容**：从登录到存储的完整链路
- **观察点**：所有监控点的顺序调用
- **期望结果**：PKCE 生成 → 回调处理 → token 解析 → 本地存储

## 故障排除

### Frida 无法附加
```bash
# 检查进程是否运行
frida-ps | findstr lingma

# 以管理员权限运行
# 关闭杀毒软件或添加例外
```

### 找不到模块
```bash
# 检查 ASLR
# 使用 frida-ps -l 列出所有模块
frida-ps -l lingma.exe
```

### Hook 失败
```bash
# 检查地址是否正确
# 使用 Module.enumerateExports() 查找函数
# 确认 Go 编译选项
```

## 安全提示

⚠️ **重要提示**

- 仅在授权环境中使用
- 提取的 token 仅供本地测试
- 不要将真实 token 上传到公共位置
- 测试完成后及时撤销 token
- 遵守相关法律法规

## 技术细节

### Go 语言调用约定
- 参数通过栈传递
- 返回值在栈上
- 字符串结构：指针 + 长度
- 切片结构：指针 + 长度 + 容量

### CosyUserInfo 结构体布局
```go
type CosyUserInfo struct {
    // offset 0x00 - 0x7f: 其他字段
    UserID           string  // offset 0x00
    UserName         string  // offset 0x10
    // ...

    // 关键字段
    SecurityOauthToken string // offset 0x80 (pt-* token)
    RefreshToken       string // offset 0x90 (rt-* token)
    TokenExpireTime     int64  // offset 0xa0 (Unix timestamp)

    // offset 0xa8 - 0x11f: 其他字段
    // 总大小: 288 字节
}
```

### Frida 脚本技巧
```javascript
// 读取 Go 字符串
function readGoString(ptr) {
    const strPtr = ptr.readPointer();
    const strLen = ptr.add(Process.pointerSize).readU64();
    return strPtr.readUtf8String(Number(strLen));
}

// Hook Go 函数
Interceptor.attach(Module.findBaseAddress('lingma.exe').add(offset), {
    onEnter: function(args) {
        const sp = this.context.sp;
        // 读取栈参数
    },
    onLeave: function(retval) {
        // 读取返回值
    }
});
```

## 参考资料

- [Frida 官方文档](https://frida.re/docs/)
- [Go 语言内部实现](https://golang.org/cmd/compile/)
- [PKCE RFC 7636](https://tools.ietf.org/html/rfc7636)
- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [Lingma 官网](https://lingma.alibabacloud.com/)

## 许可声明

本工具仅供安全研究和学习使用。使用本工具进行任何操作前，请确保：
1. 已获得相应授权
2. 遵守当地法律法规
3. 不用于非法目的
4. 保护提取的敏感信息

---

**作者**：Security Testing Lab
**日期**：2026-05-01
**版本**：1.0