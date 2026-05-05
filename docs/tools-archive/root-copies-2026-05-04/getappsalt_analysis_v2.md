# getAppSalt 完整机制分析

## 函数签名与结构

**地址**: RVA 0x882760 - 0x882b8a (长度 ~0x42a 字节)
**功能**: 构建并返回一个包含 3 个键值对的 `map[string]string`

## Map 结构

| 键 | 键 RVA | 长度 | 值来源 | 说明 |
|---|---|---|---|---|
| "Date" | 0x248eede | 4 | time.Format 结果 | HTTP 日期格式时间戳 |
| "Signature" | 0x249a6cf | 9 | 动态计算值 | 签名值 |
| "Appcode" | 0x249577e | 7 | 全局变量 0x5fa7cc0 | "cosy" |

## 键值字符串位置

- "Date" @ RVA 0x248eede (在字符串表中，与 "Math", "uint", "dict" 等重叠)
- "Signature" @ RVA 0x249a6cf (在字符串表中)
- "Appcode" @ RVA 0x249577e (在字符串表中，与 "Tuesday", "Januar" 等重叠)
- "cosy" @ RVA 0x248f216 (通过全局变量 0x5fa7cc0 的 Go string struct {ptr=0x14248f216, len=4} 指向)

## 日期格式字符串

RVA 0x24e0c9d: 包含 "Mon, 02 Jan 2006 15:04:05" (Go 的时间格式模板)

## 关键调用链

### getAppSalt 内部流程
```
0x22:  call 0xffffffffff825b60     -> 获取当前时间
0x7a:  lea rdi, [rip+0x1c5e4bc]   -> 加载日期格式字符串 (RVA 0x24e0c9d)
0x86:  call ...                     -> 调用 time.Format
0x94:  call runtime.makemap       -> 创建 map (容量3，初始大小0)

# 第一个条目: "Date" -> 格式化的时间字符串
0xe4:  lea rax, [rip+...]         -> 加载 "Date" 字符串
0xeb:  mov ebx, 4                  -> 键长度
0x109: call runtime.convTstring   -> 将字符串转为 interface{}
0x160: call runtime.mapassign_faststr -> 赋值 key="Date", value=格式化时间

# 第二个条目: "Signature" -> 签名值
0x276: lea rax, [rip+...]         -> 加载 "Signature" 字符串
0x27d: mov ebx, 9                  -> 键长度
0x2a0: call runtime.convTstring
0x2f4: call runtime.mapassign_faststr -> 赋值 key="Signature", value=计算出的签名

# 第三个条目: "Appcode" -> "cosy"
0x367: lea rax, [rip+...]         -> 加载 "Appcode" 字符串
0x36e: mov ebx, 7                  -> 键长度
0x38c: call runtime.convTstring
0x3e0: call runtime.mapassign_faststr -> 赋值 key="Appcode", value="cosy"
```

### 调用者 (0x880da0) 流程
```
0x14f (offset): call addBigModelSignatureHeaders (0x882680)
  -> 检查签名配置是否有效
  -> 返回 0 表示成功

0x154: test al, al
  -> jne 0x16f: 如果失败，走错误路径
  -> 如果成功，继续

0x247: jle 0x385  -> 如果 slice 非空，检查每个元素

0x385: 开始字符串比较循环
  cmp dword ptr [rsi], 0x68747561  -> "auth" (小端序)
  je 0x3c6  -> 如果是 "auth"，跳过 getAppSalt

0x3a1: cmp dword ptr [rsi], 0x6e676973  -> "sign"
  jne 0x494  -> 如果不是 "sign..."，跳过 getAppSalt

0x3a7: mov rax, [rsp + 0xa8]  -> 准备调用 getAppSalt
0x3af: call 0x19c0  -> 调用 getAppSalt! (0x880da0 + 0x19c0 = 0x882760)
0x3b4: mov rax, [rsp + 0x70]  -> 保存 getAppSalt 返回值
0x3c1: jmp 0x4a1

0x4a1: test rax, rax  -> 检查 getAppSalt 返回值
  jne 0x51e  -> 如果非 nil，继续签名流程

后续:
  0x4f7: mov rax, [rsp+0x98]  -> 加载签名相关数据
  0x504: call 0x1440  -> 实际签名计算/添加 headers
```

### addBigModelSignatureHeaders (0x882680)
```
非常短的函数 (~0x71 字节):
1. 加载配置引用 1 (rip + 0x1c36574)
2. 调用辅助函数 (0xffffffffff8b39c0)
3. 检查结果: test rax, rax; jge 0x91
4. 如果失败，加载配置引用 2 (rip + 0x1c51662)
5. 再次调用辅助函数
6. 如果仍失败，返回错误
7. 如果成功，xor eax, eax; ret (返回 0)
```

## 调用条件

getAppSalt 只在以下情况下被调用:
1. addBigModelSignatureHeaders 返回成功 (al != 0)
2. API endpoint 的某些字符串元素匹配 "sign" 前缀
3.  NOT 匹配 "auth" 的分支

**结论**: getAppSalt 只在发送需要签名的 API 请求时被调用，且该请求不是认证类请求。

## 触发 getAppSalt 的方法

### 方法 1: 通过 LSP 触发签名请求
- 找到触发签名请求的 LSP method
- 可能是代码补全、代码分析等需要云端模型调用的操作

### 方法 2: 直接发送 HTTP 请求
- 如果能找到 Lingma 发送请求的内部 pipe 接口
- 发送一个需要签名的请求来触发 getAppSalt

### 方法 3: 静态分析签名算法
- 分析 call 0x1440 (0x8822e0) 的签名计算逻辑
- 从 disassembly 还原 HMAC 或其他签名算法

## 已知的嵌入配置 (从 binary 提取)

### Alibabacloud 配置
```json
{
  "on_premise": "false",
  "remote_config": {
    "big_model_endpoint": "https://lingma.alibabacloud.com/algo",
    "login_url": "https://lingma.alibabacloud.com/lingma/login",
    "auth_logout_url": "https://account.alibabacloud.com/logout/logout.htm",
    "auth_login_url": "https://account.alibabacloud.com/login/login.htm",
    "big_model_host": "lingma.alibabacloud.com",
    "message_encode": "1",
    "login_encode": "2"
  }
}
```

### Tongyi 配置
```json
{
  "remote_config": {
    "big_model_endpoint": "https://lingma-api.tongyi.aliyun.com/algo",
    "login_url": "https://devops.aliyun.com/lingma/login",
    "big_model_host": "lingma-api.tongyi.aliyun.com",
    "message_encode": "1",
    "login_encode": "2"
  }
}
```

## 下一步

1. **分析 call 0x1440 (0x8822e0)**: 这是实际签名计算的核心函数
2. **分析 HTTP 请求结构**: 了解签名是如何在 headers 中使用的
3. **尝试登录流程**: 通过 LSP pipe 触发登录来获取有效的 session token
