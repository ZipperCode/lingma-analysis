# Lingma 协议研究工程分析 - 当前最终状态

> 目录入口请先看 [README.md](./README.md)。

更新时间：2026-04-30

## 目标

在不依赖 plugin UI 的前提下，稳定复用 Lingma 的模型能力；进一步目标是尽量摆脱本地运行时，直接完成远端 API 调用。

## 当前已经成立的能力

### 1. 远端直连 Chat 已可独立工作

当前仓库已经存在一份可直接运行的远端客户端实现：

- [../lingma_remote_api.py](../lingma_remote_api.py)

已成立能力：

- `POST /algo/api/v2/service/pro/sse/agent_chat_generation` 可直接发送原始 JSON body
- `messages`、系统提示词、模型 key 可自由构造
- SSE 响应已能正确拼接文本增量
- `GET /algo/api/v2/model/list` 可直接获取模型列表

实现入口：

- `_read_credentials()`
- `_make_bearer()`
- `_make_headers()`
- `_build_chat_body()`
- `chat()`
- `get_models()`

### 2. 本地 `37010` 路线仍然是最稳的工程入口

当前仓库已经存在一份可直接使用的本地客户端实现：

- [../lingma_client.py](../lingma_client.py)

已成立能力：

- 连接 `ws://127.0.0.1:37010`
- 发送 `initialize`
- 读取 `auth/status`
- 读取 `config/queryModels`
- 通过 `chat/ask` 发起真实聊天
- 解析 `chat/process_step_callback` 与 `chat/answer`

当前实现里最关键的工程细节是：

- `ask()` 使用“真实提问 -> 等待 `step_end` -> 再发 trigger”的方式规避返回延迟
- `_parse_lsp()` 已实现对 LSP framing 的稳定解析

### 3. 本地凭据材料与缓存解密链已坐实

当前仓库已经把本地缓存读取链写进了远端客户端：

- `~/.lingma/cache/id`
- `~/.lingma/cache/user`

当前已落实到代码的规则：

- `cache/user` 先 base64 解码
- 再按 AES-128-CBC 解密
- `machine_id[:16]` 同时作为 key 和 IV
- 解密结果中可读出：
  - `key`
  - `encrypt_user_info`
  - `uid`

### 4. `Encode=1` 已被完整实现，但不再是当前远端 Chat 前提

当前仓库保留了下面这些能力：

- `lingma_encode()` / `lingma_decode()`
- `aes_encrypt()` / `aes_decrypt()`

当前正确理解应是：

- `Encode=1` 能力已被恢复，仍可用于专项分析、历史端点和复现验证
- 远端直连的 Chat 主线不依赖 `Encode=1`
- AES 在当前仓库实现里主要用于本地缓存处理，不是当前远端 Chat body 的发送前置

## 当前仍未完成的部分

1. 凭据独立化未完成

- 当前远端直连仍依赖现有 Lingma 登录态导出的材料
- 还不能在一个全新环境里完全跳过这一步

2. OAuth 登录 / 刷新链未在本仓库主实现里落地

- `client_id`
- `refresh_token`
- `session_key`
- 标准 OAuth / OIDC 刷新流程

这些话题在文档里已经有专项分析，但主要服务于后续独立化或下游 `lingma2api` 设计，不等于当前仓库根目录脚本已集成。

3. TLS 指纹仍需要 `curl` 或等价传输层

- 当前远端客户端显式依赖 `curl`
- 纯 Python `requests` 路线仍不稳定

## 当前推荐的事实源

如果你要回答“今天这仓库到底已经做成了什么”，优先看：

1. [../lingma_remote_api.py](../lingma_remote_api.py)
2. [../lingma_client.py](../lingma_client.py)
3. [remote-api-direct-connection.md](./remote-api-direct-connection.md)
4. [lingma-analysis-request-flow-pruned.md](./lingma-analysis-request-flow-pruned.md)

如果你要继续追专项细节，再进入：

- [topics/encode1-complete-analysis.md](./topics/encode1-complete-analysis.md)
- [topics/session-key-analysis.md](./topics/session-key-analysis.md)
- [topics/standalone-oauth-analysis.md](./topics/standalone-oauth-analysis.md)

## 文件清单

- [../lingma_remote_api.py](../lingma_remote_api.py)：
  当前远端 API 直连实现
- [../lingma_client.py](../lingma_client.py)：
  当前本地 `37010` 客户端
- [remote-api-direct-connection.md](./remote-api-direct-connection.md)：
  远端直连的当前边界与实现说明
- [lingma-analysis-request-flow-pruned.md](./lingma-analysis-request-flow-pruned.md)：
  本地 `37010` 主线的精简说明
- [superpowers/specs/2026-04-26-lingma2api-design.md](./superpowers/specs/2026-04-26-lingma2api-design.md)：
  下游代理层设计，属于后续工程，不是当前主脚本实现
