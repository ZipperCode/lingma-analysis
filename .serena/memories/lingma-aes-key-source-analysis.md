AES session key 分析更新 — Chat API 不需要 AES，`QbgzpWzN7tfe43gf` 是硬编码常量。

**Why:** Chat API 直接发原始 JSON body，无需 AES 加密。之前误以为需要 AES+Encode=1。

**How to apply:**
- **Chat API 不需要 AES 加密**: 直接发原始 JSON POST body，服务器返回 SSE 原始 JSON 响应
- **`QbgzpWzN7tfe43gf`**: 硬编码在二进制 .rdata (2.11.1: 0x24adaf8, 2.11.2: 0x24cac1e)，不是请求体加密密钥
- **AES 密钥用途**: 本地缓存加密（cosy/auth/user 包: WriteQuotaCache, SaveUserInfo, ReadQuotaCache, GetCachedUserInfo）和数据库加密（cosy/storage/database 包: doEncrypt, doDecrypt）
- **调用链已定位**: 
  - AesEncryptWithBase64: WriteQuotaCache(0x88ebe0), SaveUserInfo(0x891ec0, 2处), doEncrypt(0xaf3380), doWikiEncrypt(0xb96f40)
  - AesDecryptWithBase64: ReadQuotaCache(0x88f000), GetCachedUserInfo(0x8943c0), doDecrypt(0xaf3420), doWikiDecrypt(0xb97000)
- **自动化提取**: `tools/frida_key_extract.py` — hook AesEncryptWithBase64(RVA 0x455da0)
- **API 集成**: `lingma_remote_api.py` 现直接发原始 JSON，不需要 AES 加密
