# 跨文档矛盾注册表

本文件记录项目中已知的跨文档矛盾和未解决问题。

---

## 未解决的矛盾

### 1. 哈希算法：SHA-256 vs MD5
- **signing_final.md / auth_final_report.md** 声明使用 SHA-256（通过 IDA 识别标准 SHA-256 IV 常量）
- **session-key-analysis.md** 通过 Oracle 匹配证明实际使用 MD5
- **分析**：这是两个不同的函数。`getAppSalt`（SHA-256）在当前版本中不会被调用；`Md5Encode`（MD5）才是活跃的签名函数
- **状态**：MD5 有 1/3 Oracle 验证，SHA-256 从未被调用

### 2. getAuthPayload JSON 字段名（两套版本）
- **endpoint-auth.md**：`version, requestId, userId, securityOauthToken, path, method`
- **ida-http-auth-cracked.md**（serena memory）：`version, requestId, user, cosyVersion, ideVersion`（称前者"错误"）
- **状态**：**两套均未验证**，Frida Hook 从未触发

### 3. getAuthSignature 参数顺序（两套版本）
- **endpoint-auth.md**：`userId → secToken → refreshToken → path → method`
- **ida-http-auth-cracked.md**（serena memory）：`userId → method → path → refreshToken → secToken`
- **状态**：**两套均未验证**，Frida Hook 从未触发

### 4. 签名公式格式不一致
- **session-key-analysis.md**：`MD5("cosy&" + key + "&" + RFC1123_Date)`
- **ida-oauth-refresh-analysis.md**：`MD5(base64(body) + "&" + key + "&" + date)`
- **分析**：可能是不同上下文（旧 Signature vs 刷新令牌），但未明确协调
- **状态**：未验证

### 5. 密钥选择：条件标志 vs 固定密钥
- **session-key-analysis.md**：条件标志位决定使用 key_A 还是 key_B
- **standalone-oauth-analysis.md**：仅列出 key_A
- **状态**：部分验证（1/3 Oracle 使用 key_A 匹配）

---

## 已解决的矛盾

### 6. `$` 字符含义
- ~~encoding-alphabet-decoded.md：`$` 是 JSON 和二进制数据的分隔符~~
- **encode1-complete-analysis.md**：`$` 是 4 字节对齐的填充字符
- **结论**：填充字符，无二进制数据

### 7. 心跳体 AES 加密
- ~~encryption-analysis.md：心跳体 736 字节 = 46 AES 块，推测 AES 加密~~
- **heartbeat-body-structure.md**：心跳体使用明文 JSON，无 AES
- **结论**：心跳体不是 AES 加密

### 8. Chat API 需要 Encode=1
- ~~早期文档：Chat API 需要 Encode=1 编码~~
- **当前验证**：Chat API 使用原始 JSON body，不需要 Encode=1
- **结论**：不需要

---

## 未解决的技术缺口

1. **Session key 公式仅 1/3 Oracle 匹配**：另外 2/3 样本无法解释
2. **client_id 从未成功提取**：OAuth 独立化的关键前置条件未满足
3. **心跳体截断**：Part 1 缺 ~30 字节，Part 2 缺 ~66 字节，原因不明
4. **Encode=2**：声称存在但从未解码或确认
5. **v3 端点 400 "auth payload is invalid"**：根因未确定（推测是 pt-* vs JWT 格式不兼容）
6. **Device Token Polling 启动端点**：从未找到
