# Lingma OAuth 登录流程 Frida 监控说明

## 执行步骤

### 1. 前置准备
```bash
# 安装 Frida (如果还未安装)
pip install frida-tools

# 验证安装
frida --version
```

### 2. 启动监控

**方法一：使用批处理脚本（推荐）**
```bash
# 启动 Lingma 客户端
# 然后运行监控脚本
run_oauth_monitor.bat
```

**方法二：手动执行**
```bash
# 1. 启动 Lingma 客户端
# 2. 在另一个终端运行：
frida -n lingma.exe -l frida_oauth_monitor.js
```

### 3. 触发 OAuth 登录
在 Frida 脚本注入后，点击 Lingma 客户端的"登录"按钮，脚本将自动捕获完整的 OAuth 流程。

---

## 监控点详解

### 阶段 1：OAuth 登录启动

#### LoginStart (0x141a10680)
- **功能**：启动 OAuth 登录流程
- **捕获内容**：
  - nonce 值（用于防重放攻击）
  - PKCE verifier（验证者）
  - PKCE challenge（挑战值）
- **验证点**：确认 PKCE 流程正确初始化

#### generatePKCEChallenge (0x141a197a0)
- **功能**：生成 PKCE verifier 和 challenge
- **捕获内容**：
  - verifier: 随机字符串（43-128字符）
  - challenge: SHA256(verifier) 的 Base64 URL 编码
- **验证点**：验证 PKCE 算法实现符合 RFC 7636

#### PrepareLoginRequest (0x141a198a0)
- **功能**：构造 OAuth 授权 URL
- **捕获内容**：
  - 完整的授权 URL
  - state 参数
  - redirect_uri
  - client_id（服务器端密钥）
- **验证点**：确认 URL 参数构造正确

---

### 阶段 2：OAuth 回调处理

#### HandleAuthCallback (0x141a18dc0)
- **功能**：处理 OAuth 回调
- **捕获内容**：
  - LoginAuthCallbackParam 结构体完整内容：
    - Nonce: 防 CSRF 标记
    - Auth: 加密的认证信息字符串
    - TokenString: 加密的令牌字符串
- **验证点**：确认回调参数完整性

#### parseAuthInfoV3 (0x141a21b80)
- **功能**：解析 auth 字符串
- **流程**：
  1. URL 解码
  2. Encode=1 Base64 解码（验证字母表和 padding）
  3. JSON 反序列化
- **捕获内容**：
  - 原始 auth 字符串
  - URL 解码后的 Base64 字符串
  - JSON 解析后的明文内容
- **验证点**：确认 Encode=1 算法实现

#### parseAuthToken (0x141a213e0)
- **功能**：解析 token_string 字符串
- **流程**：
  1. Encode=1 Base64 解码
  2. 使用 `\n` 分割字符串
- **捕获内容**：
  - 原始 token_string
  - Base64 解码后的内容
  - 分割后的 token 列表：
    - pt-* (SecurityOauthToken)
    - rt-* (RefreshToken)
- **验证点**：
  - 确认分隔符为 `\n`
  - 提取实际的 pt-* 和 rt-* token

#### CustomDecryptParts (0x140455ca0)
- **功能**：自定义解密逻辑
- **捕获内容**：
  - 分隔符字符
  - 分割后的各部分内容
- **验证点**：确认是否有额外的解密步骤

---

### 阶段 3：Token 存储

#### CompleteLoginWithSelectAccount (0x141a0fee0)
- **功能**：完成账号选择后的登录
- **验证点**：确认多账号处理逻辑

#### CompleteUserLogin (0x141a12200)
- **功能**：完成用户登录
- **验证点**：确认登录状态更新

#### saveUserInfoAndQuota (0x141a11ee0)
- **功能**：保存用户信息和配额
- **验证点**：确认配额字段存储

#### SaveUserInfo (0x14088e260) **【关键监控点】**
- **功能**：保存用户信息到本地
- **捕获内容**：
  - **CosyUserInfo 结构体完整 dump (288 字节)**
  - offset 0x80: SecurityOauthToken (pt-* token)
  - offset 0x90: RefreshToken (rt-* token)
  - offset 0xa0: TokenExpireTime (过期时间戳)
  - 其他字段（用户ID、用户名等）
- **输出格式**：
  ```
  ================================================================================
  [DUMP] CosyUserInfo @ 0x12345678 (288 bytes)
  ================================================================================
  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
  [... 十六进制 dump ...]

  [KEY FIELDS]
  [*] SecurityOauthToken (0x80): "pt-xxx..."
  [*] RefreshToken (0x90): "rt-xxx..."
  [*] TokenExpireTime (0xa0): 1714521600 (2024-05-01T00:00:00.000Z)
  ```

---

### 阶段 4：HTTP 服务器监控

#### CreateHttpServer (0x141b48d00)
- **功能**：创建本地 HTTP 服务器
- **捕获内容**：
  - 监听端口（通常为随机端口）
  - 路由注册信息
- **验证点**：确认回调 URL 处理逻辑

#### LoginCallback_fm (0x141b499c0)
- **功能**：处理 OAuth 回调请求
- **捕获内容**：
  - 完整的 HTTP 请求内容
  - Query 参数（code, state 等）
- **验证点**：确认回调 URL 参数解析

---

## 预期输出示例

### 完整登录流程输出
```
================================================================================
[HOOK] generatePKCEChallenge
================================================================================
[*] Stack Pointer: 0x1234567890
[*]   Ret1: ptr=0xabcdef, len=43
[*]   Verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
[*]   Ret2: ptr=0x123456, len=43
[*]   Challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuG5stw73M4"

================================================================================
[HOOK] HandleAuthCallback
================================================================================
[*]   Param 2: "https://lingma.alibabacloud.com/callback?code=xxx&state=yyy"
[+] Found OAuth callback parameter!

================================================================================
[HOOK] parseAuthToken
================================================================================
[*]   Param 0: "cHQtYWJjZGVm...\ncnQtMTIzNDU2..."
[*]   -> Found \n separator in token_string!
[*]   -> Split into 2 parts:
[*]      Part 0: "pt-abcdef123456..."
[*]      Part 1: "rt-123456abcdef..."

================================================================================
[HOOK] SaveUserInfo - DUMPING CosyUserInfo STRUCT (288 bytes)
================================================================================
[SUCCESS] Found CosyUserInfo structure at 0x12345678

================================================================================
[DUMP] CosyUserInfo @ 0x12345678 (288 bytes)
================================================================================
0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
[... 完整十六进制 dump ...]

[KEY FIELDS]
[+] FOUND! SecurityOauthToken (0x80): "pt-xxxxxxxxxxxxx"
[+] FOUND! RefreshToken (0x90): "rt-xxxxxxxxxxxxx"
[*] TokenExpireTime (0xa0): 1714521600 (2024-05-01T00:00:00.000Z)
```

---

## 关键验证点

### 1. Encode=1 Base64 解码验证
- **目标**：确认自定义 Base64 字母表和 padding 字符
- **观察点**：parseAuthInfoV3 和 parseAuthToken 的解码过程
- **验证方法**：
  - 对比标准 Base64 字母表：`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`
  - 识别自定义字母表替换
  - 确认 padding 字符（通常是 `=` 或其他）

### 2. token_string 分隔符验证
- **目标**：确认分隔符是否为 `\n`
- **观察点**：parseAuthToken 函数
- **验证方法**：
  - 检查 Base64 解码后的内容
  - 确认 `\n` 字符的存在
  - 验证分割后的 token 数量

### 3. CosyUserInfo 结构体验证
- **目标**：完整提取 288 字节结构体内容
- **观察点**：SaveUserInfo 函数
- **验证方法**：
  - dump 完整内存
  - 提取 offset 0x80 (pt-* token)
  - 提取 offset 0x90 (rt-* token)
  - 提取 offset 0xa0 (过期时间)
  - 验证其他字符串字段

### 4. OAuth 流程完整性验证
- **目标**：确认从登录到存储的完整链路
- **观察点**：所有监控点的顺序调用
- **验证方法**：
  - 确认 PKCE 参数生成
  - 确认回调处理正确
  - 确认 token 解析正确
  - 确认本地存储成功

---

## 故障排除

### 问题 1：Frida 无法附加到进程
```
[!] Failed to attach: unable to access process
```
**解决方案**：
1. 以管理员权限运行 Frida
2. 关闭杀毒软件或添加例外
3. 确认 lingma.exe 进程正在运行

### 问题 2：找不到函数地址
```
[!] Error: unable to find module 'lingma.exe'
```
**解决方案**：
1. 确认 lingma.exe 正在运行
2. 使用 `frida-ps -l` 列出所有进程
3. 检查 ASLR 是否影响地址计算

### 问题 3：Hook 失败
```
[!] Error: access violation accessing 0x...
```
**解决方案**：
1. 检查地址计算是否正确（基址 + 偏移）
2. 确认 Go 版本编译选项
3. 尝试使用 `Module.enumerateExports()` 查找函数

---

## 进阶分析

### 修改 Token 值
```javascript
// 在 SaveUserInfo hook 中修改 token
Interceptor.attach(Module.findBaseAddress('lingma.exe').add(0x88e260), {
    onEnter: function(args) {
        const tokenPtr = ... // 找到 token 指针
        const newToken = "pt-fake_token_for_testing";
        Memory.writeUtf8String(tokenPtr, newToken);
    }
});
```

### 导出完整结构体到文件
```javascript
// 在 SaveUserInfo hook 中导出结构体
const fs = require('fs');
const structBytes = maybeStructPtr.readByteArray(288);
fs.writeFileSync('cosy_user_info.bin', Buffer.from(structBytes));
```

### 动态调用函数
```javascript
// 动态调用 parseAuthInfoV3
const parseAuthInfoV3 = new NativeFunction(
    Module.findBaseAddress('lingma.exe').add(0x1a21b80),
    'pointer', ['pointer', 'pointer']
);
const result = parseAuthInfoV3(...);
```

---

## 注意事项

1. **环境要求**：
   - Windows 10/11 x64
   - Python 3.7+
   - Frida 16.0+
   - 管理员权限

2. **隐私保护**：
   - 输出的 token 值仅用于本地测试
   - 不要将真实 token 上传到公共位置
   - 测试完成后及时撤销 token

3. **安全合规**：
   - 仅在授权环境中使用
   - 用于学习和研究目的
   - 遵守相关法律法规

---

## 相关文件

- `frida_oauth_monitor.js` - 主监控脚本
- `run_oauth_monitor.bat` - Windows 启动脚本
- `OAuth_Monitoring_Guide.md` - 本说明文档

## 参考资料

- [Frida 官方文档](https://frida.re/docs/)
- [Go 语言调用约定](https://golang.org/cmd/compile/)
- [PKCE RFC 7636](https://tools.ietf.org/html/rfc7636)
- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)