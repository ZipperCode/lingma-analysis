# Encode=1 Body 编码机制分析

## 分析日期
2026-04-25

## 核心发现

### 1. 编码字母表已确认

使用自定义 64 字符 base64 字母表，字符到 6-bit 值的映射为**位置索引映射**（字符在字母表中的位置 = 6-bit 值）：

```
_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!
```

编码过程：明文 → 自定义字母表 base64 编码 → HTTP body

### 2. 编码映射方法

```python
ALPHA = '_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!'
STD_B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

# 将自定义字母表字符映射到标准 base64 位置
def decode_custom_b64(encoded):
    converted = ''
    for c in encoded:
        if c in ALPHA:
            converted += STD_B64[ALPHA.index(c)]
    pad = (4 - len(converted) % 4) % 4
    converted += '=' * pad
    return base64.b64decode(converted)
```

### 3. 不同端点的 Body 结构

#### user/status (v3 API)
- **编码**: 全 body 自定义 base64
- **分隔符**: `$$`（两个 $ 字符）
- **结构**: `<Part0_encoded>$$<Part1_encoded>`
- **Part 0 解码** (58 bytes): `needRefresh":false,"authInfo":{}}` + `"encodeVersion":"1"}`
- **Part 1 解码** (120 bytes): `"securityOauthToken":"...","refreshToken":"...","payload":{"userId":"...","personalToken...`

#### heartbeat (v1 API)
- **编码**: 全 body 自定义 base64，无分隔符
- **结构**: 单一 base64 编码块（1024 chars → 768 bytes）
- **内容**: 二进制数据（可能是设备信息+遥测的编码格式）

#### agent_chat_generation (v2 API)
- **编码**: 全 body 自定义 base64
- **分隔符**: 单个 `$` 字符（位置 3863）
- **结构**: `<JSON_text_encoded>$<binary_data_encoded>`
- **JSON 部分解码** (2898 bytes):
  ```
  {"messages":[
    {"role":"system","content":"<系统提示词>","response_meta":{"id":"","usage":{...}},"reasoning_content_signature":""},
    {"role":"user","content":"<用户消息>","response_meta":{"id":"","usage":{...}},"reasoning_content_signature":""}
  ],"business":{"product":"jb_plugin","version":"2.11.1","type":"memory","id":"<uuid>","begin_at":<timestamp>,"stage":"start","name":"memory_intent_recognition_<hash>"}}
  ```
- **二进制部分** (5794 bytes): 不可解压（非 zlib/gzip），熵 6.49 bits/byte，可能是加密的代码上下文/嵌入向量

#### business/finish (v2 API)
- **编码**: 全 body 自定义 base64
- **解码内容**: JSON 格式的业务完成信息
  ```
  {"begin_at":<ts>,"end_at":<ts>,"stage":"complete","name":"memory_generate_chat-extract_<hash>"}
  ```

### 4. agent_chat_generation 完整 Body 结构

```
HTTP POST body (custom base64 encoded):
  Decoded = JSON_part + "$" + binary_part

JSON_part (UTF-8 text):
  {
    "messages": [
      {
        "role": "system",
        "content": "<系统提示词，可以很长>",
        "response_meta": {"id":"","usage":{"prompt_tokens":0,...}},
        "reasoning_content_signature": ""
      },
      {
        "role": "user",
        "content": "<用户消息>",
        "response_meta": {"id":"","usage":{"prompt_tokens":0,...}},
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

binary_part (5794 bytes, after "$" separator):
  - 非标准压缩格式（zlib/gzip 解压失败）
  - 熵 6.49 bits/byte（中等，有结构）
  - 可能是加密的代码上下文或嵌入向量
  - 5794 % 16 = 2（非 AES block 对齐）
```

### 5. 请求头结构 (v2 API Bearer 认证)

```
POST /algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1
Authorization: Bearer COSY.<base64_payload>.<md5_signature>
Content-Type: application/json
Cosy-Key: <from cache/user.key>
Cosy-Date: <unix_timestamp>
Cosy-Data-Policy: AGREE
Cosy-Clienttype: 2
Cosy-Machineid: <machine_uuid>
Cosy-Machineos: x86_64_windows
Cosy-User: <user_id>
Cosy-Version: 2.11.1
```

### 7. Body 构造规则（2026-04-25 验证）

- `$` 是**字面分隔符**，将编码后的 body 分为两部分
- Part 1: `custom_base64(JSON文本)` - 系统提示词 + 消息数组 + business 元数据
- Part 2: `custom_base64(二进制数据)` - 与文本内容绑定的二进制载荷
- Body 格式: `<Part1_encoded>$<Part2_encoded>`
- **关键发现**: 二进制数据与文本内容绑定，修改系统提示词或 business metadata 会导致 500
- **可修改范围**: 只能修改用户消息 (`role: "user"` 的 `content` 字段)
- **POST 签名**: `md5(payload + "\n" + Cosy-Key + "\n" + Cosy-Date + "\n" + body + "\n" + normalized_path)`
  - 注意: slot4 = 完整的 HTTP body（包含 `$` 分隔符）

1. **编码是可逆的**: 自定义 base64 字母表的位置映射已完全破解
2. **JSON 部分可独立构造**: messages 数组和 business 对象的结构已完全理解
3. **二进制部分可能是可选的**: 需要验证是否可以不带二进制数据发送请求
4. **签名可独立计算**: Bearer token 的 md5 签名公式已知
5. **下一步**: 尝试构造最小请求（仅 JSON，无二进制部分）直连远端 API

## 捕获数据来源

- 文件: `capture/lingma-http-capture-proxynofrida-20260424-235500.jsonl`
- Line 13: agent_chat_generation (11592 chars encoded, 8693 bytes decoded)
- Line 2/6/9: user/status (240 chars encoded)
- Line 4: heartbeat (1024 chars encoded)
- Line 19: business/finish (852 chars encoded)
