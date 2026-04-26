Lingma 逆向分析最终状态 — 远端 API 直连已完全实现。

**Why:** 实现脱离 plugin 和 Lingma 进程的自主大模型 API 调用。

**How to apply:**
- **远端 Chat API 已完全可用**: `lingma_remote_api.py` — 发送原始 JSON body（不编码），无需 Encode=1 参数
- **关键纠正**: Chat POST body 直接发原始 JSON，之前误以为需要 Encode=1 编码（Encode=1 导致 500）
- **响应格式**: SSE `data:` 行 → 外层 JSON `{"body":"<内层JSON>","statusCodeValue":200}` → 内层 JSON 为标准 OpenAI chat completion chunk
- **认证**: COSY Bearer token — md5(payload_b64 + "\n" + cosy_key + "\n" + date + "\n" + body + "\n" + normalized_path)
- **本地客户端**: `lingma_client.py` 通过 ws://127.0.0.1:37010 通信（需要本地 Lingma 进程）
- **编码算法**: Encode=1 (自定义base64+三块反转) 已破解但仅用于特定端点（非 Chat API）
- **cache/user 解密**: AES-128-CBC，key=IV=machineKey前16字符ASCII
- **凭证刷新**: 仍需要 Lingma 进程进行 OAuth 登录，refresh_token 远端接口返回 404
