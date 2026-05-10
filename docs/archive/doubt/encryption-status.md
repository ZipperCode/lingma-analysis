## 重大发现 (2026-04-25 续)

### 编码分析结果

**Heartbeat body (736 bytes = 46 AES blocks):**
- 前244字节：明文JSON（系统元数据）
- 字节244-499：静态二进制数据（256字节）
- 字节500-563：动态数据（37字节，随请求变化）
- 字节564-735：静态二进制数据（172字节）
- 两次捕获的heartbeat前500字节完全相同

**Tracking body (1353 bytes):**
- 前450字节：不可打印数据，散布 `}` (0x7d) 字符
- 字节450-903：可读JSON，包含 tracking 事件数据
- 字节904-1353：不可打印数据
- 去掉前9字节后剩余1344字节 = 84 AES blocks

**关键观察：**
1. heartbeat body = 736 bytes = 46 × 16 ✓ (AES block倍数)
2. tracking body - 9 bytes = 1344 bytes = 84 × 16 ✓ (AES block倍数)
3. 编码字母表覆盖52/53 body字符（缺少$）
4. $ 出现次数极少（heartbeat中2次），可能为特殊标记

### 编码流程假设

1. 明文JSON → AES-CBC加密 → 密文
2. 密文字节 → 自定义64字符字母表编码
3. 编码文本作为POST body发送
4. `Encode=1` 参数告知服务器body已编码

### 未解决问题

- AES密钥派生方法未知
- AES IV生成方法未知
- 为什么tracking body的中间部分可读（部分密文恰好解码为可打印字符？）
- heartbeat body的JSON部分为什么也是明文？

### 下一步

1. 使用 Frida 捕获 AesEncryptWithBase64 的实际参数
2. 分析密钥派生函数
3. 理解完整的编码管道
