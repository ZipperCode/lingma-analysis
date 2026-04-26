# Lingma 远端 API 直连 - 当前状态

## 分析日期
2026-04-26 (更新)

## 核心结论：远端 Chat API 已完全可用

### Chat API 不需要 Encode=1 编码

2026-04-26 实测确认：POST body 直接发原始 JSON，服务器正常返回 SSE 流式响应。

- ✅ `POST /algo/api/v2/service/pro/sse/agent_chat_generation` — 任意消息自由调用
- ✅ `GET /algo/api/v2/model/list` — 模型列表
- ✅ 响应格式：SSE `data:` 行 → 外层 `{"body":"<JSON>","statusCodeValue":200}` → 内层标准 OpenAI chat completion chunk

### 之前误判原因

之前认为 Chat API 需要 Encode=1（自定义 base64 + 三块反转），导致 500 错误。实际测试发现：
- Encode=1 编码的 body → 500 Internal Server Error
- 原始 JSON body → 200 正常响应

### POST 签名公式

```
GET:  md5(payload + "\n" + Cosy-Key + "\n" + Cosy-Date + "\n" + "" + "\n" + normalized_path)
POST: md5(payload + "\n" + Cosy-Key + "\n" + Cosy-Date + "\n" + body + "\n" + normalized_path)
```

POST 的 slot4 = 原始 JSON body（完整 HTTP body）。

### TLS 指纹

- Python `requests` 被拒绝
- `curl` 和 `pycurl` 正常工作
- `lingma_remote_api.py` 使用 curl 子进程

## 当前限制

1. 仍需 `~/.lingma/cache/id` 与 `~/.lingma/cache/user` 凭据
2. OAuth 登录 / token 刷新未独立实现
3. 需要 curl（TLS 指纹要求）

## 文件清单

| 文件 | 说明 |
|------|------|
| `lingma_remote_api.py` | 远端 API 完整直连客户端 |
| `lingma_client.py` | 本地 WebSocket 客户端（备用） |
| `docs/encode1-complete-analysis.md` | Encode=1 算法详解 |
| `docs/superpowers/specs/2026-04-26-lingma2api-design.md` | lingma2api 设计文档 |
