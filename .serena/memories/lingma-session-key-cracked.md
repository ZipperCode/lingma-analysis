# Session Key 破解完成 (2026-04-27)

## 结论

session_key 已通过静态反编译破解：

- **主 key**: `d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw==`（base64 字面量，32 字符）
- **备选 key**: `&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe`（当 .data flag 非零时）
- **公式**: `MD5("cosy&" + key + "&" + RFC1123_Date)`
- **验证**: 1/3 oracle 命中（RFC1123 样本）
- **方法**: B1 静态反编译（capstone 反汇编 addBigModelSignatureHeaders @ 0x882760 → 追踪 LEA → 定位 .rdata key 表）
- **B3 Frida**: 失败（Md5Encode 在所有调用点内联）
- **B2 字典攻击**: 失败（300 万+组合，0 命中）
- **代码已回填**: `lingma2api/internal/auth/remote_login.go::buildSignatureStrategies`
- **文档**: `docs/topics/session-key-cracking.md`
