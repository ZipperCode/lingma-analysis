# Lingma 独立 API 调用指南

脱离 Lingma plugin 和本地服务进程，自主进行大模型 API 调用。

## 前置条件

1. **已登录状态**: `~/.lingma/cache/id` 和 `cache/user` 文件存在
2. **curl 可用**: 服务器有 TLS 指纹检测，Python requests 被 403 拒绝
3. **捕获数据**: 至少一份包含 `agent_chat_generation` body 的捕获文件

## 快速开始

### 方式一：本地 37010 API（推荐，完全自由）

```bash
# 单次提问
python lingma_client.py -q "你好"

# 交互模式
python lingma_client.py --interactive
```

**优势：**
- 完全自由的提问内容（无长度限制、无 system prompt 绑定）
- 不需要捕获数据
- 响应流式拼接

**限制：**
- 需要本地 Lingma 服务运行（登录状态下自动启动）
- 无法脱离本地进程

### 方式二：远端 API 直连（部分自由）

```bash
# 获取模型列表
python lingma_remote_api.py --action models

# 发送聊天请求
python lingma_remote_api.py --action chat -q "你好"

# 指定捕获数据源
python lingma_remote_api.py --action chat -q "你是谁？" --capture capture/my_capture.jsonl
```

**优势：**
- 完全脱离本地 Lingma 进程
- 纯 HTTP 调用

**限制：**
- 只能修改用户消息内容（受原始字节长度限制）
- 系统提示词和二进制载荷来自捕获数据
- 依赖 curl 子进程（TLS 指纹）

## Python 库使用

### 本地 37010 客户端

```python
from lingma_client import LingmaClient

client = LingmaClient()
client.connect()
print(f"已连接! 用户: {client.user_name}")

response = client.ask("写一个 Python 快速排序")
print(response)

client.close()
```

### 远端 API 客户端

```python
from lingma_remote_api import LingmaRemoteAPI

api = LingmaRemoteAPI()

# 获取模型
models = api.get_models()
for m in models:
    print(f'{m["display_name"]} ({m["key"]})')

# 发送聊天
response = api.chat("你好")
print(response)

# 任意 API 请求
result = api.request('GET', '/algo/api/v2/model/list')
print(result.stdout)
```

## 核心模块

| 模块 | 说明 |
|------|------|
| `enc_b64()` / `dec_b64()` | 自定义 base64 编码/解码 |
| `load_credentials()` | 读取并解密 `cache/user` |
| `make_bearer()` | 生成带 MD5 签名的 Bearer token |
| `make_headers()` | 生成完整远端请求头 |
| `BodyTemplate` | 从捕获数据提取 body 模板，支持修改用户消息 |
| `curl_request()` | 使用 curl 发送 HTTP（绕过 TLS 指纹） |
| `parse_sse_response()` | 解析 SSE 流式响应 |

## 签名公式

```
GET:  md5(payload_b64 \n Cosy-Key \n Cosy-Date \n \n normalized_path)
POST: md5(payload_b64 \n Cosy-Key \n Cosy-Date \n body \n normalized_path)

normalized_path = path 去除 "/algo" 前缀
```

## 自定义 Base64 字母表

```
_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!
```

字符在字母表中的位置索引 = 6-bit 值。

## 已知端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/algo/api/v2/model/list` | 模型列表 |
| POST | `/algo/api/v2/service/pro/sse/agent_chat_generation?...&Encode=1` | 聊天生成 |
| GET | `/algo/api/v2/config/getDataPolicy?...` | 数据策略 |
| POST | `/algo/api/v3/user/status?Encode=1` | 用户状态 |
| POST | `/algo/api/v1/heartbeat?Encode=1` | 心跳 |

## 当前限制

1. **远端 POST 二进制载荷**: 与系统提示词绑定，无法独立生成。需要 Frida hook `cosy/remoting.encodeRequestBody` 完全破解。
2. **消息长度限制**: 远端直连时，用户消息需匹配原始捕获的字节长度。
3. **TLS 指纹**: 必须使用 curl，纯 Python HTTP 客户端被拒绝。

## 文档索引

| 文档 | 说明 |
|------|------|
| [lingma-complete-analysis.md](docs/lingma-complete-analysis.md) | 完整逆向分析报告 |
| [lingma-analysis-overview.md](docs/lingma-analysis-overview.md) | 架构总览（旧版入口） |
| [encoding-alphabet-cracked.md](docs/encoding-alphabet-cracked.md) | 编码字母表破解详情 |
| [heartbeat-body-structure.md](docs/heartbeat-body-structure.md) | Heartbeat body 结构 |
