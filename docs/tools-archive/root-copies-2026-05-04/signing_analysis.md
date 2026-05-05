# Lingma CTF 签名系统完整分析

## 函数调用链

```
Caller (0x880da0)
  └── addBigModelSignatureHeaders (0x882680) - 验证签名配置
  └── [endpoint check: "auth" vs "signing" vs "upload"]
  └── getAppSalt (0x882760) - 获取盐值 map
  └── Main Signing Function (0x8821e0) - 签名计算核心
        ├── Helper 0x882e40 (0x189 bytes) - 提取配置值并格式化
        ├── Helper 0x884080 (0x52 bytes)  - 验证标志位
        ├── Helper 0x885620 (0x71 bytes)  - 处理 slice 数据
        └── Helper 0x8840e0 (0xab bytes)  - 添加授权 headers
              └── runtime call 0xb11200 - 最终 HTTP 签名操作
```

## getAppSalt 返回的 map 结构

```go
map[string]string{
    "Date":      time.Now().Format("Mon, 02 Jan 2006 15:04:05"),
    "Signature": <computed signature value>,
    "Appcode":   "cosy",
}
```

### 关键地址

| 项目 | RVA | 说明 |
|------|-----|------|
| getAppSalt | 0x882760 | 构建并返回 map |
| Main Signing | 0x8821e0 | 签名计算主函数 |
| addBigModelSignatureHeaders | 0x882680 | 验证签名配置 |
| Caller | 0x880da0 | 协调调用链 |
| "Date" 字符串 | 0x248eede | 键名 |
| "Signature" 字符串 | 0x249a6cf | 键名 |
| "Appcode" 字符串 | 0x249577e | 键名 |
| "cosy" (Go string) | {ptr=0x14248f216, len=4} | 全局变量 0x5fa7cc0 |
| 日期格式 | 0x24e0c9d | "Mon, 02 Jan 2006 15:04:05" |

## Main Signing Function (0x8821e0) 流程

```
0x32:  检查全局变量 0x5fe1c68 是否为 nil
       -> 如果 nil，跳过预处理
       -> 如果非 nil，转换为字符串

0xc0:  检查全局变量 0x5fe1c78 是否为 nil
       -> 如果非 nil，处理数据

0x134: lea rax, [rip + 0x1c13455] -> 加载字符串
       ebx = 7 (键长度)
       call 0x899800 -> runtime 函数

0x178: lea rcx, [rip + 0x1c13418] -> 加载字符串
       edi = 7 (键长度)
       call 0x8b3e60 -> runtime.mapassign_faststr

0x1d0: call 0xa8b -> 0x882e40
       提取配置值，格式化时间戳等

0x1e0: call 0x1cbb -> 0x884080
       验证标志位，返回布尔值

0x200: call 0x323b -> 0x885620
       处理 slice 数据

0x205: call 0x1cf6 -> 0x8840e0
       添加授权 headers

0x2ad-0x30e: 准备最终参数并调用
       lea rcx, [rip + 0x1c8f1c7] -> 加载错误消息
       r8d = 4 (参数数量)
       call 0xb11200 -> 核心签名/HTTP 操作
```

## 调用条件

getAppSalt 和签名流程只在以下条件满足时执行：
1. API endpoint 不是 "auth" 类型
2. API endpoint 匹配 "sign" 前缀
3. addBigModelSignatureHeaders 验证通过

## 触发方式

### 方法 1: 通过 LSP 触发
- 发送需要签名的 LSP 请求（代码补全、代码分析等）
- 需要有效的认证 token

### 方法 2: 直接 HTTP 请求
- 向 `https://lingma.alibabacloud.com/algo/*` 或 `https://lingma-api.tongyi.aliyun.com/algo/*` 发送请求
- 需要在 headers 中包含正确的签名

### 方法 3: 静态分析
- 完全从 disassembly 还原签名算法
- 需要理解 runtime map 操作、字符串格式化、和最终的加密调用

## 当前结论

1. **Runtime patching 可行但不稳定** - 多次成功写入 JMP，但目标函数不常被调用
2. **Frida 不兼容 Go 1.23** - GC 栈扫描导致崩溃
3. **签名流程复杂** - 涉及多个内部函数和 runtime 调用
4. **需要认证才能触发** - 未登录时整个签名路径不会被执行

## 下一步建议

1. **静态分析 0x882e40**: 这个函数提取实际的签名数据，理解它就能看到签名输入
2. **分析 HTTP 请求结构**: 观察签名如何被用于 headers
3. **尝试登录流程**: 通过 LSP pipe 触发完整的认证流程
4. **Hook 更底层**: 考虑 hook crypto/hash 相关函数（crypto/hmac, crypto/sha256 等）

## 已知配置

### Alibabacloud
- Endpoint: https://lingma.alibabacloud.com/algo
- Login: https://lingma.alibabacloud.com/lingma/login
- message_encode: "1"
- login_encode: "2"

### Tongyi
- Endpoint: https://lingma-api.tongyi.aliyun.com/algo
- Login: https://devops.aliyun.com/lingma/login
- message_encode: "1"
- login_encode: "2"
