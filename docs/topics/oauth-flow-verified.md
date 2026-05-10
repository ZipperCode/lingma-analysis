# Lingma OAuth 流程 — 已验证文档

更新：2026-05-10 | 状态：✅ 端到端验证通过

## 1. 完整 OAuth 重定向链

```
[Client] 生成 PKCE + state="2-{nonce}" + machine_id
    │
    ▼  构造三层嵌套 URL
https://account.alibabacloud.com/logout.htm?oauth_callback=
  https://account.alibabacloud.com/login/login.htm?oauth_callback=
    https://lingma.alibabacloud.com/lingma/login?state=2-{nonce}&challenge={code_challenge}&...
    │
    ▼  用户在阿里云登录页输入凭据
[account.alibabacloud.com] 认证成功 → 重定向到 lingma.alibabacloud.com
    │
    ▼  Lingma 服务端用 confidential client 模式交换 token
[lingma.alibabacloud.com] 服务端处理 OAuth：
    - 用 authorization_code 换取 access_token（client_id/secret 在服务端）
    - 生成 pt-xxx (securityOauthToken) 和 rt-xxx (refreshToken)
    - 用 Encode=1 编码 auth 和 token 参数
    │
    ▼  重定向浏览器
[lingma.alibabacloud.com] → localhost:37510/auth/callback?state=2-{nonce}&auth=<Encode1>&token=<Encode1>
    │
    ▼  本地解码 V2 参数
[Local Server] LoginCallback 解码：
    auth → CustomDecryptParts → split("\n") → [UID, AID, Name]
    token → parseAuthToken → split("\n") → [pt-token, rt-token, expireTime]
    │
    ▼
[完成] 保存凭据到 ~/.lingma/portable_config.json
```

### 重定向链 URL 详情

| 步骤 | URL | 说明 |
|------|-----|------|
| 1 | `account.alibabacloud.com/logout.htm?oauth_callback=...` | 先登出确保干净状态 |
| 2 | `account.alibabacloud.com/login/login.htm?oauth_callback=...` | 阿里云统一登录 |
| 3 | `lingma.alibabacloud.com/lingma/login?state=2-xxx&challenge=xxx&...` | Lingma OAuth 入口 |
| 4 | `localhost:37510/auth/callback?state=2-xxx&auth=<E1>&token=<E1>` | V2 回调 |

## 2. V1 vs V2 回调对比

### 触发条件

| 版本 | state 格式 | 回调内容 |
|------|-----------|---------|
| V1 | `state={raw_nonce}` 或 `state=1-{nonce}` | 只有 `aid`, `uid`, `name` 基本用户信息 |
| V2 | `state=2-{raw_nonce}` | 完整 `auth=<Encode1>&token=<Encode1>` 含所有凭据 |

### V2 回调参数

```
auth = <Encode1 编码的字符串>
  解码后 = "{UID}\n{AID}\n{Name}"
  例：5930676910898027\n5930676910898027\nzhang640@blny.de

token = <Encode1 编码的字符串>
  解码后 = "{pt-token}\n{rt-token}\n{expireTime}"
  例：pt-9E227MqmpxoZAABlcM11cIk3\nrt-ITXAFfARMIHHGuJRTiHBiA6O\n1783605791090
```

## 3. Encode=1 编码算法

### 自定义 Base64 字母表

```
标准: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
自定义: _doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!
```

### 编码步骤

```
输入: raw_bytes
  │
  ▼ 1. 标准 base64 编码 → 去除 '=' 填充
  encoded = base64(raw_bytes).rstrip('=')
  E = len(encoded)
  │
  ▼ 2. 字母表替换
  encoded = ''.join(CUSTOM[STD.index(c)] for c in encoded)
  │
  ▼ 3. 三块重排 + '$' 填充
  f = floor(E/3)          # b0 块大小（关键：用 floor，不是 ceil）
  c = ceil(E/3)
  pad = (4 - E%4) % 4
  b0 = encoded[:f]        # 前 floor(E/3) 个字符
  b1 = encoded[f:2*c]     # 中间 2*ceil(E/3) - floor(E/3) 个字符
  b2 = encoded[2*c:]      # 剩余字符
  │
  ▼ 4. 输出
  output = b2 + '$'*pad + b1 + b0
```

### 解码步骤（逆操作）

```
输入: body
  │
  ▼ 1. 提取并移除 '$' 填充
  找到第一个 '$'，计数连续 '$' 个数 → p
  clean = body 去除所有 '$'
  E = len(clean)
  │
  ▼ 2. 反转块顺序
  c = ceil(E/3)
  f = floor(E/3)
  lb = E - 2*c            # b2 块大小
  b1_size = 2*c - f       # b1 块大小
  b2 = clean[:lb]         # 前 lb 个字符
  b1 = clean[lb:lb+b1_size]
  b0 = clean[lb+b1_size:]
  │
  ▼ 3. 还原顺序 + 字母表逆替换 + base64 解码
  original = b0 + b1 + b2
  std_str = ''.join(STD[CUSTOM.index(c)] for c in original)
  return base64_decode(std_str + '=' * ((4 - len(std_str)%4) % 4))
```

### 关键公式细节

| 参数 | 公式 | 说明 |
|------|------|------|
| b0 长度 | `floor(E/3)` | **关键修正**：此前错误使用 ceil |
| b1 长度 | `2*ceil(E/3) - floor(E/3)` | |
| b2 长度 | `E - 2*ceil(E/3)` | |
| '$' 填充数 | `(4 - E%4) % 4` | 确保 4 字节对齐 |

Go 编译器使用魔数 `0xAAAAAAAAAAAAAAAB` 做除法优化：
- `v24 = floor(E*5/6)` 等价于 `floor(E/3)`（当 E 为正整数时）
- `v7 = ceil(E/6)` 用于其他边界计算

## 4. Token 来源和用途

### Token 类型

| Token | 格式 | 用途 | 有效期 |
|-------|------|------|--------|
| securityOauthToken | `pt-{22字符}` | OAuth 访问令牌 | ~60天 |
| refreshToken | `rt-{22字符}` | 刷新令牌 | ~60天 |
| COSY Bearer | `COSY.{base64}.{md5}` | Chat API 认证 | 每次请求生成 |

### COSY 凭据（Chat API 所需）

COSY 认证需要两个额外参数，存储在本地缓存 `~/.lingma/cache/user` 中（AES-128-CBC 加密）：

- `cosy_key`: 172字符 Base64 字符串
- `encrypt_user_info`: 664字符 Base64 字符串

这些用于构造 `Authorization: Bearer COSY.{payload}.{md5}` 头：
```
payload = base64(json({cosyVersion, info: encrypt_user_info, requestId, version}))
md5 = MD5(payload_b64 + "\n" + cosy_key + "\n" + date + "\n" + body + "\n" + path)
```

### 本地缓存解密

```
key = machine_id[:16] (UTF-8)
IV  = machine_id[:16] (UTF-8)
cipher = AES-128-CBC(key, IV)
plaintext = unpad(cipher.decrypt(base64_decode(cache/user)))
```

## 5. 端到端验证结果

### 测试矩阵

| 测试 | 命令 | 结果 |
|------|------|------|
| T1: URL 生成 | `login --url-only` | ✅ state="2-{nonce}"，三层嵌套 URL |
| T2: Encode 往返 | `decode <test>` | ✅ 解码与原始匹配 |
| T3: 完整登录 | `login --standalone` | ✅ portable_config.json 包含 pt- 和 rt- token |
| T4: Chat API | `lingma_remote_api.py` | ✅ HTTP 200 SSE，回复 "Success" |
| T5: Token 刷新 | `refresh` | ⏸ 远端 API 404(intl)/403(WAF)，待后续处理 |
| T6: 持久化 | 重启后 `status` | ✅ token 匹配上次登录 |

### 实测凭据

```
Machine ID: 35346164-3866-492d-a339-30773a32652d
UID/AID:    5930676910898027
Name:       zhang640@blny.de
Token:      pt-9E227MqmpxoZAABlcM11cIk3 (有效期 ~60天)
Refresh:    rt-ITXAFfARMIHHGuJRTiHBiA6O
```

## 6. 实现文件索引

| 文件 | 用途 |
|------|------|
| `lingma_oauth_complete.py` | 自主 OAuth 登录（PKCE + V2 回调 + Encode=1 解码） |
| `lingma_remote_api.py` | Chat API 客户端（COSY Bearer 签名 + SSE 解析） |
| `tools/credential_extractor.py` | 凭据管理（本地缓存解密 + 便携配置） |
| `callback-37510-simulation.md` | IDA 逆向完整文档（函数地址 + 算法） |

## 7. 已知限制

1. **Token 刷新**: 远端 `/api/v3/user/refresh_token` 返回 404 (国际站) 或 403 (WAF)，当前无可用远程刷新方案
2. **COSY 凭据**: OAuth 登录只能获取 pt/rt token，cosy_key 和 encrypt_user_info 仍需从本地 Lingma 缓存获取
3. **TLS 指纹**: Chat API 需要 curl 发送（TLS 指纹兼容），Python requests 可能被拦截
4. **machine_id**: 首次需要从本地 `~/.lingma/cache/id` 读取，之后持久化
