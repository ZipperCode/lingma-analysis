# 灵码 Token Refresh 直连测试指南

> 日期：2026-04-30
> 脚本：`tools/lingma_refresh_token_direct.py`
> 分析来源：IDA Pro 反编译分析

---

## 1. 快速开始

### 1.1 使用缓存凭证（推荐）

```bash
# 从灵码缓存文件读取（需要 AES 解密）
python tools/lingma_refresh_token_direct.py --credentials ~/.lingma/cache/user
```

**注意：** 缓存文件是 AES-128-CBC 加密的，需要先解密。参考 `lingma_remote_api.py` 的解密方法。

### 1.2 手动提供参数

```bash
python tools/lingma_refresh_token_direct.py \
  --security-token 'pt-...' \
  --refresh-token 'rt-...' \
  --user-id 'xxx' \
  --org-id 'xxx' \
  --machine-id 'UUID-格式'
```

### 1.3 测试国际版端点

```bash
python tools/lingma_refresh_token_direct.py \
  --endpoint 'https://lingma.alibabacloud.com/algo' \
  --security-token 'pt-...' \
  --refresh-token 'rt-...' \
  --user-id 'xxx' \
  --org-id 'xxx' \
  --machine-id 'UUID'
```

---

## 2. 参数说明

| 参数 | 类型 | 说明 | 必需 |
|------|------|------|------|
| `--credentials` | 文件路径 | 灵码缓存文件路径 | 可选（默认 ~/.lingma/cache/user） |
| `--endpoint` | URL | API 端点 | 可选（默认国内版） |
| `--machine-id` | UUID | Machine ID | 必需 |
| `--user-id` | 字符串 | 用户 ID | 必需 |
| `--org-id` | 字符串 | 组织 ID | 必需 |
| `--security-token` | Token | SecurityOauthToken | 必需 |
| `--refresh-token` | Token | RefreshToken | 必需 |

---

## 3. 如何获取参数

### 3.1 从灵码缓存文件提取

**文件位置：**
- Windows：`%USERPROFILE%\.lingma\cache\user`
- macOS：`~/.lingma/cache/user`
- Linux：`~/.lingma/cache/user`

**解密方法：**

```python
from Crypto.Cipher import AES
import base64

# 1. 读取 machine_id（明文）
machine_id = open('~/.lingma/cache/id').read().strip()

# 2. AES key（前 16 字符）
aes_key = machine_id[:16].encode()

# 3. 读取缓存文件（base64）
encrypted_data = base64.b64decode(open('~/.lingma/cache/user').read())

# 4. AES-128-CBC 解密（IV = key）
cipher = AES.new(aes_key, AES.MODE_CBC, aes_key)
decrypted = cipher.decrypt(encrypted_data)

# 5. 解析 JSON
user_info = json.loads(decrypted.rstrip(b'\x00').decode())
```

**提取字段：**
```python
security_token = user_info['security_oauth_token']
refresh_token = user_info['refresh_token']
user_id = user_info['user_id']
org_id = user_info['org_id']
```

### 3.2 从环境变量提取

```bash
export LINGMA_MACHINE_ID=$(cat ~/.lingma/cache/id)
export LINGMA_USER_ID="..."
export LINGMA_ORG_ID="..."
export LINGMA_SECURITY_TOKEN="pt-..."
export LINGMA_REFRESH_TOKEN="rt-..."
```

### 3.3 从 Frida Hook 提取

使用 Frida 脚本实时抓取灵码二进制中的 token：

```bash
frida -l frida_hooks/get_user_info.js -f ~/.lingma/bin/2.11.2/x86_64_windows/Lingma.exe
```

---

## 4. 技术原理

### 4.1 认证机制

**签名公式：**
```
Signature = MD5("cosy&" + session_key + "&" + RFC1123_date)
```

**Session Key：**
```
session_key = "war, war never changes"  # 已确认
session_key_b64 = "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="
```

### 4.2 Encode=1 编码

**算法：** 自定义 base64 + 分块重排

**字母表：**
```
标准：ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
灵码：_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!
```

**重排规则：**
1. 标准 base64 编码（去掉 padding）
2. 字符映射到自定义字母表
3. 分 3 块：b0、b1、b2
4. 输出：`b2 + $padding + b1 + b0`

### 4.3 HTTP 请求结构

**端点：**
```
POST https://lingma.alibabacloud.com/algo/api/v3/user/refresh_token?Encode=1
```

**Headers：**
```
User-Agent: Go-http-client/1.1
Accept: application/json
Appcode: cosy
Content-Type: application/json
Cosy-Machineid: <UUID>
Cosy-Version: 2.11.2
Date: Wed, 30 Apr 2026 08:30:00 GMT
Signature: <MD5_hex>
Login-Version: v2
```

**Body（Encode=1 编码）：**
```json
{
  "userId": "xxx",
  "orgId": "xxx",
  "securityOauthToken": "pt-...",
  "refreshToken": "rt-..."
}
```

---

## 5. 预期结果

### 5.1 成功响应（200）

```json
{
  "success": true,
  "uid": "xxx",
  "name": "用户名",
  "tokenExpireTime": 1717987200,
  "securityOauthToken": "pt-new...",
  "refreshToken": "rt-new..."
}
```

### 5.2 失败响应（400）

```json
{
  "success": false,
  "errorCode": "INVALID_PARAMS",
  "errorMsg": "auth payload is invalid"
}
```

**可能原因：**
- Token 格式不正确（需要标准 OAuth token，而非灵码内部 `pt-` 格式）
- Encode 编码错误
- 签名计算错误
- Token 已过期

---

## 6. 已知限制

### 6.1 v3 端点限制

根据之前的测试（`docs/topics/standalone-oauth-analysis.md`），v3 HTTP 端点存在限制：

- ❌ `pt-*` 格式的灵码内部 token 无法使用
- ✅ 标准 OAuth token（JWT 格式 `eyJ...`）可以使用
- ❌ 标准 OAuth token 需要通过浏览器 OAuth 流程获取（需要 client_id）

### 6.2 解决方案

**方案 A：WebSocket 刷新（推荐）**
- 使用 WebSocket `auth/refreshToken` 方法
- 需要灵码二进制运行在 127.0.0.1:37010
- 参考：`lingma2api/internal/auth/ws_refresh.go`

**方案 B：标准 OAuth refresh**
- 获取 client_id（通过浏览器抓包）
- 使用标准 OAuth `grant_type=refresh_token`
- 参考：`docs/topics/refresh-token-flow.md`

---

## 7. 测试矩阵

| 测试项 | 结果 | 说明 |
|--------|------|------|
| Encode=1 编码验证 | ✅ | 与灵码二进制输出完全一致 |
| 签名计算验证 | ✅ | 与灵码二进制签名完全一致 |
| v3 refresh 端点（pt-token） | ❌ 400 | "auth payload is invalid" |
| v3 refresh 端点（标准 OAuth） | ⚠️ | 需要测试（需要标准 token） |

---

## 8. 后续优化

### 8.1 优先级 1：自动 AES 解密

集成 AES 解密功能到脚本：

```python
# 在 parse_lingma_user_cache() 中添加
from Crypto.Cipher import AES

def decrypt_user_cache(cache_file, machine_id):
    aes_key = machine_id[:16].encode()
    encrypted = base64.b64decode(cache_file.read_text())
    cipher = AES.new(aes_key, AES.MODE_CBC, aes_key)
    decrypted = cipher.decrypt(encrypted).rstrip(b'\x00')
    return json.loads(decrypted.decode())
```

### 8.2 优先级 2：Encode=2 支持

如果 v3 端点需要 Encode=2，添加 AES 加密：

```python
# Encode=2 = AES-128-CBC + 自定义 base64
AES_KEY = "QbgzpWzN7tfe43gf"  # 灵码硬编码常量

def lingma_encode_v2(data: bytes) -> str:
    cipher = AES.new(AES_KEY.encode(), AES.MODE_CBC, AES_KEY.encode())
    encrypted = cipher.encrypt(pad(data))
    return lingma_encode_v1(base64.b64encode(encrypted))
```

---

## 9. 参考文档

- `docs/topics/ida-oauth-refresh-analysis.md` - IDA Pro 分析报告
- `docs/topics/standalone-oauth-analysis.md` - 灵码 OAuth 整体分析
- `docs/topics/encode1-complete-analysis.md` - Encode=1 编码还原
- `docs/topics/refresh-token-flow.md` - OAuth refresh token 流程
- `lingma2api/internal/auth/ws_refresh.go` - WebSocket refresh 实现

---

## 10. 联系与反馈

如有问题或发现新的端点信息，请更新以下文档：

- `docs/topics/ida-oauth-refresh-analysis.md` - IDA 分析更新
- `docs/topics/standalone-oauth-analysis.md` - OAuth 分析更新

---

**最后更新：** 2026-04-30
