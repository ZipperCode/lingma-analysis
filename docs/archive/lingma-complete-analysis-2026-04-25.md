# Lingma 协议研究工程 - 完整分析报告

> 分析日期: 2026-04-25
> 目标版本: cosy 2.11.1
> 目标平台: Windows x86_64

本文档是 Lingma 协议研究工程的单一权威参考。所有结论均来自实际流量采集、Frida 追踪、程序结构分析和运行时验证。

---

## 目录

1. [架构总览](#1-架构总览)
2. [自定义 Base64 编码](#2-自定义-base64-编码)
3. [cache/user 解密](#3-cacheuser-解密)
4. [Bearer Token 签名](#4-bearer-token-签名)
5. [已知远端 API](#5-已知远端-api)
6. [本地 37010 协议](#6-本地-37010-协议)
7. [远端直连实现](#7-远端直连实现)
8. [当前限制与阻塞点](#8-当前限制与阻塞点)

---

## 1. 架构总览

系统分为三层：

```
Plugin (IDE)  →  ws://127.0.0.1:37010 (Lingma 本地服务)  →  远端 HTTP/SSE
```

| 层级 | 职责 |
|------|------|
| **Plugin** | IDE 上下文采集、UI 展示、本地 WS 客户端包装 |
| **本地服务** (`~/.lingma/bin/2.11.1/x86_64_windows/Lingma`) | 暴露 37010/37510/38510 端口、维护登录态、生成签名头、编码 body、转发远端请求 |
| **远端** (`https://lingma.alibabacloud.com`) | 执行模型调用、返回 SSE 流式结果 |

**关键结论：**
- Plugin 可绕过 → 直接调用本地 37010（`lingma_client.py` 已实现）
- 本地服务可绕过 → 直接调用远端 HTTP（`lingma_remote_api.py` 已部分实现）

### 本地服务内部五段模型

1. communication server - 暴露本地入口
2. API handler - 接收结构化请求 (`cosy/core/api/agent/chat/ask.go`)
3. remoting 层 - 决定远端 path、Encode=1、body 改写 (`cosy/remoting.encodeRequestBody`)
4. auth provider - 生成 Authorization/Cosy-* 头 (`cosy/auth/user.getAuthPayload/Signature`)
5. transport 层 - 发出真实 HTTP/SSE

---

## 2. 自定义 Base64 编码

### 字母表

```
_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!
```

映射方式：**字符在字母表中的位置索引 = 6-bit 值**

### Python 实现

```python
ALPHA = '_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!'
STD_B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

def enc_b64(data: bytes) -> str:
    std = base64.b64encode(data).decode().rstrip('=')
    return ''.join(ALPHA[STD_B64.index(c)] for c in std)

def dec_b64(encoded: str) -> bytes:
    converted = ''.join(STD_B64[ALPHA.index(c)] for c in encoded if c in ALPHA)
    pad = (4 - len(converted) % 4) % 4
    return base64.b64decode(converted + '=' * pad)
```

### Body 格式

`Encode=1` 端点的 body 使用自定义 base64 编码，不同端点格式不同：

| 端点 | 格式 |
|------|------|
| `user/status` | `custom_b64(Part0)$$custom_b64(Part1)` |
| `heartbeat` | 单一 custom_b64 块 |
| `agent_chat_generation` | `custom_b64(JSON文本)$custom_b64(二进制数据)` |
| `business/finish` | 单一 custom_b64 JSON |

**`$` 是字面分隔符，不属于字母表，不参与编码。**

### agent_chat_generation Body 结构

解码后的 JSON 部分：

```json
{
  "messages": [
    {
      "role": "system",
      "content": "<系统提示词>",
      "response_meta": {"id": "", "usage": {"prompt_tokens": 0}},
      "reasoning_content_signature": ""
    },
    {
      "role": "user",
      "content": "<用户消息>",
      "response_meta": {"id": "", "usage": {"prompt_tokens": 0}},
      "reasoning_content_signature": ""
    }
  ],
  "business": {
    "product": "jb_plugin",
    "version": "2.11.1",
    "type": "memory",
    "id": "<uuid>",
    "begin_at": <unix_ms_timestamp>,
    "stage": "start",
    "name": "memory_intent_recognition_<hash>"
  }
}
```

二进制部分（`$` 后面）：
- 大小：5794 ~ 17020 bytes
- 熵：6.49 bits/byte（有结构，非随机）
- 非 zlib/gzip 压缩
- **与文本内容绑定**：修改系统提示词或 business metadata 会导致 500 错误
- **只能修改用户消息** (`role: "user"` 的 `content` 字段)

---

## 3. cache/user 解密

### 来源

- `~/.lingma/cache/id` → machine_id (UUID)
- `~/.lingma/cache/user` → base64 编码的加密数据

### 解密方法

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# 读取 machine_id
with open('~/.lingma/cache/id') as f:
    machine_id = f.read().strip()

# 解密 cache/user
key = machine_id[:16].encode('utf-8')  # UUID 前 16 字符
cipher = Cipher(algorithms.AES(key), modes.CBC(key))
dec = cipher.decryptor()
decrypted = dec.update(encrypted_data) + dec.finalize()
decrypted = decrypted[:-decrypted[-1]]  # 去除 PKCS7 padding
user_data = json.loads(decrypted.decode('utf-8'))
```

### 解密后字段

| 字段 | 用途 |
|------|------|
| `key` | → HTTP `Cosy-Key` 头 |
| `encrypt_user_info` | → Bearer token 中段 JSON 的 `info` 字段 |
| `uid` | → HTTP `Cosy-User` 头 |
| `name` | 用户名 |
| `security_oauth_token` | OAuth 安全票据 |
| `expire_time` | 过期时间 |
| `user_type` | 用户类型 |

### 验证方法

替换实验已证实：修改 `cache/user.key` → 出站 `Cosy-Key` 同步变化；修改 `encrypt_user_info` → `Authorization.info` 同步变化。

---

## 4. Bearer Token 签名

### 结构

```
Authorization: Bearer COSY.<base64_payload>.<md5_signature>
```

### Payload 结构

```json
{
  "cosyVersion": "2.11.1",
  "ideVersion": "",
  "info": "<encrypt_user_info from cache/user>",
  "requestId": "<uuid>",
  "version": "v1"
}
```

### 签名公式

```
GET:  md5(payload_b64 + "\n" + Cosy-Key + "\n" + Cosy-Date + "\n" + "" + "\n" + normalized_path)
POST: md5(payload_b64 + "\n" + Cosy-Key + "\n" + Cosy-Date + "\n" + body + "\n" + normalized_path)
```

关键差异：
- `normalized_path` = 去除 `/algo` 前缀的路径（`/algo/api/v2/model/list` → `/api/v2/model/list`）
- POST 请求的 slot4 = **完整 HTTP body**（包含 `$` 分隔符的编码后 body）
- GET 请求的 slot4 = 空字符串

### Python 实现

```python
def make_bearer(path, body='', date=None):
    date = date or str(int(time.time()))
    normalized = path[5:] if path.startswith('/algo/') else path

    payload_obj = {
        'cosyVersion': '2.11.1', 'ideVersion': '',
        'info': encrypt_user_info, 'requestId': str(uuid.uuid4()), 'version': 'v1'
    }
    payload_b64 = base64.b64encode(json.dumps(payload_obj, separators=(',', ':')).encode()).decode()

    slot4 = body if body else ''
    preimage = f'{payload_b64}\n{cosy_key}\n{date}\n{slot4}\n{normalized}'
    sig = hashlib.md5(preimage.encode()).hexdigest()

    return f'COSY.{payload_b64}.{sig}', date
```

---

## 5. 已知远端 API

基础 URL: `https://lingma.alibabacloud.com`

### 已验证端点

| 方法 | 路径 | 状态 | 说明 |
|------|------|------|------|
| GET | `/algo/api/v2/model/list` | ✅ 200 | 获取模型列表 |
| GET | `/algo/api/v2/config/getDataPolicy?...` | ✅ 200 | 数据策略 |
| POST | `/algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1` | ✅ 200 (SSE) | 聊天生成 |
| POST | `/algo/api/v3/user/status?Encode=1` | ✅ | 用户状态 |
| POST | `/algo/api/v1/heartbeat?Encode=1` | ✅ | 心跳 |
| POST | `/algo/api/v1/tracking?Encode=1` | ✅ | 遥测上报 |
| POST | `/algo/api/v2/service/business/finish?Encode=1` | ✅ | 业务完成 |
| GET | `/algo/api/v1/ping` | ✅ | Ping |

### 标准请求头

```
Authorization: Bearer COSY.<payload>.<signature>
Content-Type: application/json
Cosy-Date: <unix_timestamp>
Cosy-Key: <from cache/user.key>
Cosy-MachineId: <machine_uuid>
Cosy-User: <user_id>
Cosy-ClientIp: 198.18.0.1
Cosy-ClientType: 2
Cosy-Data-Policy: AGREE
Cosy-MachineOS: x86_64_windows
Cosy-Version: 2.11.1
Login-Version: v2
User-Agent: Go-http-client/1.1
```

POST 额外头：
```
Content-Length: <body_length>
Cache-Control: no-cache
X-Request-Id: <uuid>
Accept: text/event-stream
Accept-Encoding: identity
```

### 可用模型

从 `model/list` 获取，当前主要模型：
- `qwen-plus-2025-04-28`（通义千问，dashscope 提供商，最大 230000 输入 token）

---

## 6. 本地 37010 协议

### 连接

```
ws://127.0.0.1:37010
```

### LSP Framing

```
Content-Length: <n>\r\n\r\n<json>
```

裸 JSON 会触发 `Unknown message header` 错误。

### 最小调用链

1. 建立 WebSocket 连接
2. 发送 `initialize`（带 `rootUri` 和 `workspaceFolders`）
3. 发送 `auth/status` 验证登录态
4. 发送 `chat/ask` 触发聊天
5. 接收异步 `chat/answer` 流式响应

**注意：不要发送 `initialized` notification，服务端会返回 `unknown method`。**

### chat/ask 参数

```json
{
  "requestId": "<uuid>",
  "chatTask": "FREE_INPUT",
  "chatContext": null,
  "sessionId": "",
  "codeLanguage": "",
  "isReply": false,
  "source": 1,
  "questionText": "你的问题",
  "stream": true,
  "taskDefinitionType": "",
  "extra": null,
  "sessionType": "chat",
  "targetAgent": "",
  "pluginPayloadConfig": null,
  "mode": "normal",
  "shellType": "",
  "customModel": null
}
```

### Off-by-one 响应延迟

服务端存在 off-by-one 行为：每个回答实际上是上一个问题的答案。

**解决方案：**
1. 发送真正的问题
2. 等待 `chat/process_step_callback` 的 `step_end`（模型生成完成）
3. 发送 trigger 问题（如 "OK"）
4. 收集 trigger 的 `chat/answer` = 真正问题的回答

### 其他可用方法

| 方法 | 用途 |
|------|------|
| `auth/status` | 读取登录态 |
| `config/queryModels` | 查询模型注册表 |
| `auth/profile/getUrl` | 获取 profile URL |

---

## 7. 远端直连实现

### 工作流程

```
1. 读取 ~/.lingma/cache/id 和 cache/user
2. AES-128-CBC 解密获取 Cosy-Key、encrypt_user_info
3. 从捕获数据中加载二进制上下文
4. 构建 body: custom_b64(modified_JSON) + "$" + custom_b64(binary_context)
5. 生成 Bearer token（含 MD5 签名）
6. 使用 curl 发送请求（绕过 TLS 指纹检测）
7. 解析 SSE 响应
```

### 为什么用 curl

Python `requests` 库的 TLS 指纹被服务器拒绝（403）。`curl` 和 `pycurl` 可以正常工作。

### 文件

- `lingma_client.py` — 本地 37010 客户端（完全可用）
- `lingma_remote_api.py` — 远端 API 直连客户端（部分可用）

---

## 8. 当前限制与阻塞点

### 远端 POST 限制

1. **二进制载荷绑定**：`agent_chat_generation` 的二进制部分（5794+ bytes）与系统提示词和 business metadata 绑定。修改系统提示词会导致 500 错误。只能修改用户消息内容，且需保持原始字节长度。

2. **TLS 指纹**：Python `requests` 被服务器 403 拒绝。必须使用 `curl` 子进程或 TLS 指纹伪装。

3. **二进制载荷来源**：可能是加密的代码上下文、嵌入向量或设备遥测数据。需要 Frida 插桩观察 `encodeRequestBody` 或 `shouldEncryptBody` 来完全理解其生成方式。

### 仍未完全解决的问题

| 问题 | 状态 |
|------|------|
| 自定义 base64 字母表 | ✅ 已解析 |
| Bearer 签名公式 | ✅ 已解析 |
| cache/user 解密 | ✅ 已解析 |
| GET 端点直连 | ✅ 可用 |
| POST 端点直连（仅改用户消息） | ✅ 可用 |
| 独立生成二进制载荷 | ❌ 需要 Frida 插桩观察 |
| TLS 指纹伪装 | ⚠️ curl 可用，纯 Python 不行 |
| 自由修改系统提示词 | ❌ 与二进制载荷绑定 |

### 下一步建议

1. **Frida 插桩观察 `cosy/remoting.encodeRequestBody`** — 分析二进制载荷生成
2. **尝试不同 system prompt 的捕获数据** — 理解二进制载荷与文本的绑定关系
3. **TLS 指纹伪装** — 使用 `curl-impersonate` 或自定义 TLS 配置实现纯 Python 请求
4. **探索不带二进制载荷的请求** — 验证是否可以省略 `$binary_part`
