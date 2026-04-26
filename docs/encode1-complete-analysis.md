# Encode=1 编解码链完整分析

> 分析日期: 2026-04-26
> 基于: Lingma 2.11.1 (Go binary, Windows x86_64)
> 
> **⚠️ 重要更正 (2026-04-26): Chat API (`agent_chat_generation`) 不需要 Encode=1 编码，直接发送原始 JSON 即可。Encode=1 可能用于 login、heartbeat 等其他端点。**

## 核心突破

**Encode=1 body 采用「自定义 Base64 + 三块反转」编码方案，而非此前猜测的 AES 加密。**

此前认为的「二进制载荷」实际上是因为错误的解码方式（按 `$` 分割后各自解码）导致的假象。正确的方法是先反转块顺序再整体解码。

---

## 1. 编码算法

### 1.1 自定义 Base64 字母表

```
_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!
```

字符在字母表中的位置索引 = 6-bit 值（标准 base64 位置映射）。

### 1.2 编码流程

```
明文数据 → 自定义 Base64 编码（无 padding） → 三块反转 + $ 填充 → HTTP body
```

详细步骤：

1. **Base64 编码**: 将数据用自定义字母表编码，**不加 `=` padding**
2. **计算块大小**: `BS = ceil(E / 3)`，其中 `E` 是编码后字符数
3. **分割为 3 块**:
   - `Block0 = encoded[0 : BS]`
   - `Block1 = encoded[BS : 2*BS]`
   - `Block2 = encoded[2*BS : ]`（最后一块可能较短）
4. **反转块顺序**: `reversed = Block2 + Block1 + Block0`
5. **插入 `$` 填充**: 在 Block2 后面插入 `(4 - E % 4) % 4` 个 `$` 字符

最终 body = `Block2 + '$' * pad + Block1 + Block0`

### 1.3 解码流程

```
HTTP body → 移除 $ 并反转三块 → 自定义 Base64 解码 → 明文数据
```

详细步骤：

1. **定位 `$`**: 找到第一个 `$` 的位置 `dollar_start`，计算连续 `$` 个数 `pad`
2. **提取各部分**:
   - `before_dollar = body[:dollar_start]`（= Block2，最后一块）
   - `rest = body[dollar_start + pad:]`（= Block1 + Block0）
3. **计算块大小**: `E = len(body) - pad`, `BS = ceil(E / 3)`
4. **分割 rest**: `Block1 = rest[:BS]`, `Block0 = rest[BS:]`
5. **恢复原始顺序**: `original = Block0 + Block1 + Block2`
6. **Base64 解码**: 将自定义字母表映射到标准 base64，补齐 padding 后解码

### 1.4 无 `$` 的情况

当 `E % 4 == 0` 时，不需要 padding，body 中没有 `$`。
此时需要直接计算 BS 并反转 3 块：

```python
BS = ceil(E / 3)
b2_len = E - 2 * BS
Block2 = body[:b2_len]
Block1 = body[b2_len : b2_len + BS]
Block0 = body[b2_len + BS:]
original = Block0 + Block1 + Block2
```

---

## 2. Python 实现

```python
import base64
import math

ALPHA = '_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!'
STD_B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

def custom_b64_encode(data: bytes) -> str:
    std = base64.b64encode(data).decode().rstrip('=')
    return ''.join(ALPHA[STD_B64.index(c)] for c in std)

def custom_b64_decode(encoded: str) -> bytes:
    converted = ''.join(STD_B64[ALPHA.index(c)] for c in encoded if c in ALPHA)
    pad = (4 - len(converted) % 4) % 4
    return base64.b64decode(converted + '=' * pad)

def lingma_encode(data: bytes) -> str:
    """Encode data using Lingma Encode=1 scheme"""
    encoded = custom_b64_encode(data)
    E = len(encoded)
    BS = math.ceil(E / 3)
    pad = (4 - E % 4) % 4

    b0 = encoded[0:BS]
    b1 = encoded[BS:2*BS]
    b2 = encoded[2*BS:]

    return b2 + '$' * pad + b1 + b0

def lingma_decode(body: str) -> bytes:
    """Decode Lingma Encode=1 body"""
    dollar_start = body.find('$')
    if dollar_start < 0:
        # No $ separator: E % 4 == 0, reverse 3 blocks directly
        E = len(body)
        BS = math.ceil(E / 3)
        b2_len = E - 2 * BS
        b2 = body[:b2_len]
        b1 = body[b2_len:b2_len+BS]
        b0 = body[b2_len+BS:]
        return custom_b64_decode(b0 + b1 + b2)

    # Count consecutive $
    pad = 0
    pos = dollar_start
    while pos < len(body) and body[pos] == '$':
        pad += 1
        pos += 1

    E = len(body) - pad
    BS = math.ceil(E / 3)

    b2 = body[:dollar_start]
    rest = body[dollar_start + pad:]
    b1 = rest[:BS]
    b0 = rest[BS:]

    return custom_b64_decode(b0 + b1 + b2)
```

---

## 3. 验证结果

### 3.1 完全验证通过的端点

| 端点 | $ 数量 | 解码结果 | 往返测试 |
|------|--------|---------|---------|
| `user/status` (v3) | 2 | `{"payload":...,"encodeVersion":"1"}` | ✓ |
| `agent_chat_generation` (v2, 11592B) | 1 | 完整 JSON，含 messages + business | ✓ |
| `business/finish` (v2, 852B) | 1 | `{"payload":...,"encodeVersion":"1"}` | ✓ |
| `heartbeat` (v1, 984B) | 2 | JSON (设备信息 + 遥测事件) | ✓ |
| `tracking` (v1, 29184B) | 2 | JSON (遥测事件数组) | ✓ |

### 3.2 解码失败（非 JSON）的端点

部分同类端点的较大/较小 body 解码后不是有效 UTF-8/JSON。
推测原因：这些 body 在 base64 编码前经过了 **AES 加密**（由 `shouldEncryptBody` 决定），
需要先 AES 解密再解析 JSON。

受影响端点：
- `heartbeat` (部分)
- `agent_chat_generation` (部分，尤其是体积较小或较大的请求)
- `finish` (部分)
- `embedding_k2`
- `login`
- `tracking` (部分)

---

## 4. agent_chat_generation 完整 JSON 结构

解码 line 12 (11592 bytes body) 得到的完整 JSON：

```json
{
  "request_id": "<uuid>",
  "request_set_id": "",
  "chat_record_id": "<uuid>",
  "stream": true,
  "image_urls": null,
  "is_reply": false,
  "is_retry": false,
  "session_id": "",
  "code_language": "",
  "source": 0,
  "version": "3",
  "chat_prompt": "",
  "parameters": {
    "temperature": 0.1
  },
  "aliyun_user_type": "personal_standard",
  "agent_id": "agent_common",
  "task_id": "question_refine",
  "model_config": { ... },
  "messages": [
    {
      "role": "system",
      "content": "<系统提示词>",
      "response_meta": {"id":"","usage":{...}},
      "reasoning_content_signature": ""
    },
    {
      "role": "user",
      "content": "<用户输入>",
      "response_meta": {"id":"","usage":{...}},
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

**重要发现**: 此前文档中声称存在「二进制载荷」（`$` 后面的 5794 字节）是 **错误的**。
正确解码后，整个 body 就是一个纯 JSON 对象，没有二进制部分。

---

## 5. 编码函数调用链 (Go binary)

```
cosy/remoting.doBuildRequestWithConfig
  → cosy/remoting.encodeRequestBody (RVA 0x881820, 352 bytes)
    → JSON marshal (通过接口调用)
    → 块反转编码函数 (0x14014c8e0)
      → 自定义 base64 编码
      → 三块反转 + $ 填充
  → cosy/remoting.shouldEncryptBody (RVA 0x882680, 224 bytes)
    → 检查路径排除列表:
      - `/ncqs/api/v1/quotas` → 不加密
      - `/algo/api/v1/organizations` → 不加密
    → 不在排除列表中 → 调用 shouldAddEncodeParam
  → cosy/remoting.shouldAddEncodeParam (RVA 0x882540, 320 bytes)
    → 检查全局开关 (内存标志 == "1")
    → 排除路径:
      - `/api/v1/service/next_edit_predict` → 不编码
      - `/algo/api/v1/organizations` → 不编码
    → POST → Encode=1
    → PUT → 检查 `/api/v2/remoteAgent/qoder` → 有则编码
```

---

## 6. 与此前分析的对比

| 项目 | 此前结论 | 修正后结论 |
|------|---------|-----------|
| Body 格式 | JSON + `$` + 二进制载荷 | 纯 JSON（`$` 是编码填充符） |
| 二进制载荷 | 5794 bytes 加密数据 | 不存在（解码错误导致的假象） |
| `$` 的作用 | 分隔 JSON 和二进制 | Base64 三块反转的填充字符 |
| 自由修改限制 | 只能改用户消息 | 整个 JSON 可自由构造 |
| 独立生成请求 | 需要 Frida hook 二进制载荷 | 直接构造 JSON 即可 |

---

## 7. AES 加密层（Frida 动态验证, 2026-04-26）

### 7.1 编码链完整流程

通过 Frida hook `AesEncryptWithBase64`、`shouldEncryptBody`、`encodeToString` 确认了完整流程:

```
JSON 数据 → encodeRequestBody (JSON marshal)
         → shouldEncryptBody 判断:
            TRUE  → AesEncryptWithBase64(json_bytes, aes_key)
                    → encodeToString(encrypted_bytes) → HTTP body
            FALSE → encodeToString(json_bytes) → HTTP body
```

### 7.2 encodeToString = 块反转编码器

Frida 验证：`(*encoding).encodeToString` 就是块反转+自定义base64编码器。
输入 277 bytes → 输出 372 chars（含 `$$` 在 1/3 位置）。

### 7.3 AES 加密参数

| 参数 | 值 |
|------|------|
| 算法 | AES-128-CBC |
| Key | `QbgzpWzN7tfe43gf` (16 bytes ASCII, session 级) |
| IV | 与 Key 相同 (key=IV) |
| Padding | PKCS5 |
| Key 来源 | 运行时动态值（非 machine_id, 非 Cosy-Key, 可能从服务器下发） |

### 7.4 shouldEncryptBody 行为

- `getDataPolicy` → **FALSE** (GET 请求，不加密)
- `agent_chat_generation` → **TRUE** 
- `business/finish` → **TRUE**
- `embedding_k2` → **TRUE**

### 7.5 解码二进制 body 的完整流程

```
HTTP body → lingma_decode (块反转 + 自定义base64解码)
         → AES-128-CBC-PKCS5 解密 (key=IV=session_aes_key)
         → 明文 JSON
```

### 7.6 密钥来源分析 (2026-04-26 更新)

**调用链定位:**

通过 GoReSym + 反汇编定位了所有 `AesEncryptWithBase64` 和 `AesDecryptWithBase64` 的调用者：

| 函数 | 包 | 用途 |
|------|-----|------|
| `WriteQuotaCache` | cosy/auth/user | 加密 quota 缓存 |
| `SaveUserInfo` (2处) | cosy/auth/user | 加密用户信息缓存 |
| `doEncrypt` | cosy/storage/database | 加密本地 DB |
| `doWikiEncrypt` | cosy/deepwiki/storage | 加密 wiki 存储 |
| `ReadQuotaCache` | cosy/auth/user | 解密 quota 缓存 |
| `GetCachedUserInfo` | cosy/auth/user | 解密用户信息缓存 |
| `doDecrypt` | cosy/storage/database | 解密本地 DB |
| `doWikiDecrypt` | cosy/deepwiki/storage | 解密 wiki 存储 |

**密钥特征:**
- 16 字节 alphanumeric ASCII (非 hex，非 base64)
- 外观随机（包含大写/小写/数字）
- 每 session 不同，但 session 内稳定
- 不持久化到本地任何 cache 文件
- 在 `encrypt.init`（库初始化，构建 base64 表）之后可用

**密钥来源推断:**
1. 不来自 cache/id、cache/user、cache/quota 等本地文件
2. 不来自 machine_id[:16]（与 cache/user 解密 key 不同）
3. 不在 `encrypt.init` 中构建（该函数仅构建 base64 查找表）
4. 很可能来自服务器登录响应，在 `SaveUserInfo` 调用时一并写入
5. 与 `cosy_key` 同周期（随登录更新），但不等同于 `cosy_key`

### 7.7 密钥获取方案

**方案 A: Frida 动态捕获 (推荐)**

```bash
# 1. 启动 Lingma (通过 IDE 打开任意项目)
# 2. 运行密钥提取器
python tools/frida_key_extract.py
# 自动附加到 Lingma.exe，首次 AES 调用时捕获 key
# 保存到 capture/aes_key.json
```

**方案 B: 本地 WS 绕过 (无需 key)**

```bash
python lingma_client.py --question "你好"
# 通过 ws://127.0.0.1:37010 通信，完全绕过 AES 加密层
```

**方案 C: 使用 lingma_remote_api.py (自动加载 key)**

```python
from lingma_remote_api import LingmaRemoteAPI
api = LingmaRemoteAPI()                    # 自动加载 capture/aes_key.json
api = LingmaRemoteAPI(aes_key="Qbgz...")   # 或手动指定
response = api.chat("hello")               # 自动 AES 加密 + 编码
```

## 8. 当前状态

### 8.1 已解决

1. **AES 密钥捕获**: `tools/frida_key_extract.py` 可自动化捕获
2. **密钥存储**: 不在本地文件，每 session 从服务器下发（login 时）
3. **独立构造加密请求**: `lingma_remote_api.py` 已集成 AES 加密层
4. **自动化流程**: Frida 捕获 → 保存 JSON → 自动加载使用

### 8.2 仍待确认

1. **服务器端密钥下发机制**: 具体在 login 响应哪个字段（可能在 `encrypt_user_info` 解密后）
2. **密钥与 cosy_key 的精确关系**: 两者同生命周期但不同值
3. **跨 session 密钥缓存**: 能否从 cache/user 解密后的数据中提取（当前 session 内稳定但重启后变化）

### 8.3 工具清单

| 工具 | 用途 |
|------|------|
| `tools/frida_key_extract.py` | Frida 自动提取 AES session key |
| `lingma_remote_api.py` | 远端 API 直连 (支持 AES) |
| `lingma_client.py` | 本地 WS 客户端 (绕过加密) |
