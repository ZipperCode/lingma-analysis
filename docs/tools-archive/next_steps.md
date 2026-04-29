# Lingma CTF 下一步行动计划

## 当前结论

1. **getAppSalt (0x882760) 只在认证后的 API 请求中调用** — 未登录时完全不会触发
2. **Frida 与 Go 1.23 不兼容** — 所有 Frida 方案都导致 GC 崩溃
3. **Runtime patching 技术上可行** — JMP 安装成功但目标函数未被调用
4. **Caller 0x880da0 也未被调用** — 整个签名流程只在有认证 token 时激活

## getAppSalt 分析结果

**Map 结构**:
- Key "Date" (4字节) -> 日期格式相关的值
- Key "Signature" (9字节) -> 签名值
- Key "Appcode" (7字节) -> "cosy"

**关键地址**:
- getAppSalt: RVA 0x882760
- Caller (签名请求构建器): RVA 0x880da0
- addBigModelSignatureHeaders: RVA 0x882680
- 全局变量 Appcode: 0x5fa7cc0 -> "cosy"

## 可行方案

### 方案 1: 先登录再提取
1. 通过 LSP pipe 触发登录流程
2. 登录后 getAppSalt 会被调用
3. 用 runtime patching 捕获返回值

### 方案 2: 结构分析签名算法
1. 分析 addBigModelSignatureHeaders (0x882680) 的完整流程
2. 理解 getAppSalt 的 map 如何被用于签名计算
3. 用 Python 复现签名算法

### 方案 3: 动态拦截 HTTP 发送层
1. 找到 net/http 发送函数
2. 动态拦截 它来拦截所有 HTTP 请求（包括签名后的）
3. 直接读取 headers 中的签名值

### 方案 4: 启动时验证 runtime patching
1. 动态拦截 runtime.newproc 或其他启动函数
2. 验证 shellcode 可以正确执行
3. 为后续更精确的 hook 铺路

## 推荐优先级

**方案 3 (动态拦截 HTTP 层)** > **方案 1 (登录)** > **方案 2 (结构分析算法)** > **方案 4 (验证 patching)**

理由:
- 方案 3 最直接 — 如果签名是在 HTTP 请求中加的，hook HTTP 发送就能看到
- 方案 1 需要理解登录流程
- 方案 2 最复杂但最彻底
- 方案 4 只是验证性步骤
