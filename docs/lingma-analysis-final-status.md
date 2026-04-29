# Lingma 协议研究工程分析 - 最终状态总结

> 目录入口请先看 `docs/README.md`。

## 分析日期
2026-04-26 (更新)

## 最终目标
脱离 Lingma plugin 和本地服务进程，自主进行 API 调用大模型请求。

## 当前状态：远端直连已完全实现

### 1. Chat API 完全自由构造 ✅

**2026-04-26 突破：** Chat API 的 POST body 直接发送原始 JSON，不需要 Encode=1 编码，不需要模板重放，不需要二进制部分。

- ✅ `POST /algo/api/v2/service/pro/sse/agent_chat_generation` — 任意内容自由调用
- ✅ 多轮对话支持（messages 数组自由构建）
- ✅ 任意系统提示词
- ✅ 模型选择（通过 `model_config.key`）
- ✅ 响应解析（SSE → 外层 JSON → 内层 OpenAI 格式）

**参考实现：** `lingma_remote_api.py:chat()` / `_build_chat_body()`

### 2. 模型列表 ✅

- ✅ `GET /algo/api/v2/model/list` 已实测成功

### 3. 本地 37010 路线 ✅

- ✅ `ws://127.0.0.1:37010` 备用通道
- ✅ `lingma_client.py` 稳定实现

## 关键技术细节

### COSY Bearer 签名
```
preimage = base64(payload) + "\n" + cosy_key + "\n" + unix_timestamp + "\n" + body + "\n" + normalized_path
signature = md5(preimage).hex()
bearer = "COSY." + base64(payload) + "." + signature
```

### 请求头
```
Appcode: cosy
Cosy-Clientip: 198.18.0.1
Cosy-Clienttype: 2
Cosy-Machineid: <from cache/id>
Cosy-Machineos: x86_64_windows
Cosy-Machinetoken: <empty>
Cosy-Machinetype: <empty>
Cosy-Version: 2.11.2
```

### cache/user 解密
AES-128-CBC, key=IV=machineKey[:16]

### Chat POST body 结构
原始 JSON，自由构造 messages 数组。见 `lingma_remote_api.py:_build_chat_body()`。

### Encode=1 编解码
已解析但 Chat API 不需要。保留供其他端点使用。

## 剩余约束

1. 凭据来自 `~/.lingma/cache/user` — 需要 Lingma 至少登录过一次
2. OAuth 登录 / token 刷新未独立实现（refresh_token 远端返回 404）
3. TLS 指纹需要 curl 或 utls（Python requests 被屏蔽）

## 文件清单

- `lingma_remote_api.py` — **远端 API 完整直连客户端**（主要成果）
- `lingma_client.py` — 本地 WebSocket 客户端（备用）
- `docs/superpowers/specs/2026-04-26-lingma2api-design.md` — lingma2api Go 代理设计文档
- `docs/topics/encode1-complete-analysis.md` — Encode=1 算法详解
