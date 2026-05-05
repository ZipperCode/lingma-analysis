# Lingma 调用与脚本使用指南

更新时间：2026-04-27

这份文件只负责“怎么调用、怎么运行脚本、该看哪份实现”。
如果你要先建立对整个分析仓库的认识，请先看 [`docs/README.md`](./docs/README.md)。

## 前置条件

1. **凭据来源满足其一**:
   - 本地 `~/.lingma/cache/id` 和 `~/.lingma/cache/user`
   - 环境变量
   - 便携配置文件
   - 直接传参
2. **curl 可用**: 服务器有 TLS 指纹检测，Python `requests` 会被拒绝

## 快速开始

### 方式一：本地 `37010` API（推荐，最稳）

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

### 方式二：远端 API 直连（库优先）

```bash
# 直接运行会执行内置 smoke demo
python lingma_remote_api.py
```

更实用的方式是直接按库调用：

```python
from lingma_remote_api import LingmaRemoteAPI

api = LingmaRemoteAPI()
print(api.get_models()[:3])
print(api.chat("你好"))
```

**优势：**
- 完全脱离本地 Lingma 进程
- 纯 HTTP 调用
- Chat body 直接发送原始 JSON
- 支持自由构造 `messages`、系统提示词和模型选择

**限制：**
- 依赖有效凭据
- 依赖 `curl` 子进程处理 TLS 指纹

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
```

## 核心模块

| 模块 | 说明 |
|------|------|
| `lingma_encode()` / `lingma_decode()` | `Encode=1` 编码/解码工具 |
| `LingmaRemoteAPI._read_credentials()` | 读取凭据材料 |
| `LingmaRemoteAPI._make_bearer()` | 生成带 MD5 签名的 Bearer token |
| `LingmaRemoteAPI._make_headers()` | 生成完整远端请求头 |
| `LingmaRemoteAPI._build_chat_body()` | 构造原始 JSON chat body |
| `LingmaRemoteAPI.chat()` | 发起远端聊天请求 |
| `LingmaRemoteAPI.get_models()` | 获取模型列表 |

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
| POST | `/algo/api/v2/service/pro/sse/agent_chat_generation?...` | 聊天生成 |
| GET | `/algo/api/v2/config/getDataPolicy?...` | 数据策略 |
| POST | `/algo/api/v3/user/status?Encode=1` | 用户状态 |
| POST | `/algo/api/v1/heartbeat?Encode=1` | 心跳 |

## 当前限制

1. **凭据依赖**: 远端直连仍依赖 Lingma 登录态导出的凭据材料。
2. **OAuth 独立化未完成**: 登录和刷新链尚未完全脱离现有本地状态。
3. **TLS 指纹**: 必须使用 curl，纯 Python HTTP 客户端被拒绝。

## 文档索引

| 文档 | 说明 |
|------|------|
| [docs/README.md](docs/README.md) | 分析文档总入口 |
| [docs/lingma-analysis-overview.md](docs/lingma-analysis-overview.md) | 当前结论总览 |
| [docs/lingma-analysis-final-status.md](docs/lingma-analysis-final-status.md) | 最新状态总结 |
| [docs/remote-api-direct-connection.md](docs/remote-api-direct-connection.md) | 远端直连现状 |
| [docs/topics/encoding-alphabet-decoded.md](docs/topics/encoding-alphabet-decoded.md) | 编码字母表解析详情 |
| [docs/topics/heartbeat-body-structure.md](docs/topics/heartbeat-body-structure.md) | Heartbeat body 结构 |
