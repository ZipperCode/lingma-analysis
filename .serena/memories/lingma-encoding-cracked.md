Lingma Encode=1 编解码链已破解，但确认 Chat API 不需要 Encode=1。

**Why:** 编解码算法正确且可逆，但误判了使用场景。

**How to apply:**
- **编码算法 (encodeToString):** 自定义base64(无padding) → 分3块(BS=ceil(E/3)) → 反转块顺序 → $ 填充到4的倍数
- **解码:** 去$ → 反转恢复原序 → base64解码
- **Chat API 不需要 Encode=1**: POST body 直接发原始 JSON，响应也是原始 JSON in SSE。使用 Encode=1 会导致服务器 500。
- **Encode=1 真正用途**: 可能用于 login、heartbeat 等端点（query string 带 `Encode=1` 参数），需要进一步验证。
- **AES 加密层**: shouldEncryptBody=TRUE 时使用，Chat API 不需要。
- **Python 实现**: `lingma_remote_api.py` 的 `lingma_encode()`/`lingma_decode()` 函数保留供其他端点使用。
- **Frida 脚本**: `tools/frida_encode_capture.py`
- 完整文档: `docs/encode1-complete-analysis.md`
