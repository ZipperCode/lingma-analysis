# Lingma getAppSalt 分析总结

## 关键发现

### 1. getAppSalt 函数结构
- **地址**: RVA 0x882760 - 0x882b9f (长度 ~0x43f)
- **功能**: 构建一个包含 3 个键值对的 map
- **键**:
  1. "Date" (4字节)
  2. "Signature" (9字节)
  3. "Appcode" (7字节)
- **值来源**:
  - Date 的值：通过调用 0x102e0 处理日期格式字符串 "Mon, 02 Jan 2006 15:04:05" (0x24e0c9d)
  - Signature 的值：通过 mapassign 流程赋值
  - Appcode 的值：从全局变量 0x5fa7cc0 读取，内容为 "cosy"

### 2. 调用者函数
- **地址**: RVA 0x880da0 - 0x881479
- **调用 getAppSalt 的位置**: RVA 0x88114f
- **关键流程**:
  - 0x880eef: 调用 addBigModelSignatureHeaders (0x882680)
  - 0x88114f: 调用 getAppSalt
  - Go 返回值存储在 [rsp+0x70]

### 3. 为什么 getAppSalt 不被调用
- getAppSalt 只在一个特定的代码路径中被调用
- 该路径需要认证状态/特定的 API 请求才会触发
- 普通启动和未认证的 LSP 请求不会触发此代码路径

### 4. Frida 不可用
- Interceptor.attach/replace 和 Stalker 都与 Go 1.23 GC 冲突
- 导致 `runtime.scanstack` fatal error

### 5. 运行期补丁 问题
- JMP 补丁安装成功但 getAppSalt 从未被调用
- 机器码 执行验证脚本 (verify_shellcode.py) 显示标记值始终为 0

## 新的分析策略

### 策略 A: 触发 getAppSalt 调用
1. 通过 LSP pipe 发送需要签名的请求
2. 分析 caller 函数 (0x880da0) 的触发条件
3. 模拟满足条件的请求

### 策略 B: 动态拦截 会实际执行的函数
1. 查找并 hook 启动时会调用的配置加载函数
2. 动态拦截 cosy/config.parseBigModelHost
3. 动态拦截 cosy/remoting.GetBigModelEndpoint

### 策略 C: 直接提取配置并计算签名
1. 从 binary 提取的配置 JSON 已包含所有必要信息
2. 已知 keys: "Date", "Signature", "Appcode"
3. 分析签名算法，用提取的配置直接计算

### 策略 D: 动态拦截 HTTP 层
1. 动态拦截 net/http.(*Client).Do 或 net/http.(*Transport).roundTrip
2. 拦截所有发出的 HTTP 请求
3. 读取已签名的 headers

## 关键内存地址
- getAppSalt: RVA 0x882760
- Caller: RVA 0x880da0
- Caller's getAppSalt call: RVA 0x88114f
- addBigModelSignatureHeaders: RVA 0x882680
- 全局变量 0x5fa7cc0: "cosy" (Appcode 的值)
- 日期格式字符串: RVA 0x24e0c9d ("Mon, 02 Jan 2006 15:04:05")

## PE 结构
- ImageBase: 0x140000000
- .text: RVA 0x00001000, size 0x1f3f246
- .rdata: RVA 0x01f41000, size 0x3cfc250
- .data: RVA 0x05c3e000, size 0x518d80
- .pdata: RVA 0x06157000, size 0x973ec (函数异常处理表)
