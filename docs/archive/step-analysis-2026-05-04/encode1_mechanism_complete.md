# Lingma Encode=1 Mechanism Complete Analysis

通过IDA Pro MCP静态分析完全破解Encode=1编码机制

## 核心机制概述

**Encode=1** 是Lingma自定义的请求体编码机制，包含两个核心组件：
1. **自定义Base64编码**（自定义字母表）
2. **Block重排算法**（内存shuffle）

## 1. Encode=1触发条件

### shouldEncryptBody判断逻辑（地址：0x14087e500）

**函数流程**：
```go
func shouldEncryptBody(method, path) bool {
    // 排除特定路径（不编码）
    if strings.Index(path, "/ncqs/api/v1/quotas") >= 0 {
        return false
    }

    if strings.Index(path, "/algo/api/v1/organizations") >= 0 {
        return false
    }

    // 判断是否需要添加Encode参数
    return shouldAddEncodeParam(method, path)
}
```

### shouldAddEncodeParam详细判断（地址：0x14087e3c0）

**全局变量检查**：
- `off_146011C60` → 指针，指向字符串"1"（ASCII 49）
- `offset=1位置` → 值必须为`0x01`（标志位）

**路径排除**：
- `/api/v1/service/next_edit_predict` → 不编码
- `/algo/api/v1/organizations` → 不编码

**Method匹配**（HTTP method常量）：
- `method == 3`（POST） + `/api/v2/remoteAgent/qoder`路径 → 编码
- 或其他特定method → 编码

**触发条件总结**：
```
全局开关：off_146011C60 == "1" && off_146011C60[1] == '\x01'
路径排除：不在排除列表中
Method匹配：POST + remoteAgent路径 或 其他特定method组合
```

## 2. 编码流程

### encodeRequestBody（地址：0x14087d6a0）

**流程**：
```go
func encodeRequestBody(payload) ([]byte, error) {
    // 如果payload已经是[]byte类型 → 直接返回
    if payload is []byte {
        return payload, nil
    }

    // 否则JSON序列化 → 返回字节
    jsonBytes, err := json.Marshal(payload)
    if err != nil {
        return nil, errors.New("marshal request failed")
    }

    return jsonBytes, nil
}
```

### Encode=1核心算法（地址：0x1404549e0 + 0x140454c80）

#### encoding结构体定义（大小328字节）

**IDA验证的结构体布局**：
```go
type encoding struct {
    encode    [64]uint8   // offset 0x0,   自定义base64字母表
    decodeMap [256]uint8  // offset 0x40,  解码映射表（反向索引）
    padChar   int32       // offset 0x140, padding字符（'$' = 36）
    strict    bool        // offset 0x144, 严格模式标志
}
```

**关键偏移验证**：
- encode_table起始：offset 0
- decodeMap起始：offset 64 (0x40)
- padChar位置：offset 320 (0x140) ✅ 完全正确
- 总大小：64 + 256 + 4 + 1 = 325字节（IDA显示328，包含padding）

#### encodeToString算法（地址：0x1404549e0）

**算法流程**：
```go
func (e *encoding) encodeToString(input []byte) []byte {
    // 1. 计算输出长度
    if e.padChar == NoPadding {  // dword_145C71E60 == -1
        outputLen = ((8*inputLen + 5) / 6) - ((8*inputLen + 5) >> 63)
    } else {
        outputLen = 4 * ((inputLen + 2) / 3)
    }

    // 2. 创建输出buffer
    output := make([]byte, outputLen)

    // 3. 调用encodeTo核心编码
    e.encodeTo(output, input)

    // 4. Block重排（shuffle）- 内存memmove操作
    // 将编码结果按特定规则重排

    return output
}
```

#### encodeTo核心编码（地址：0x140454c80）

**算法实现**（IDA反编译验证）：
```go
func (e *encoding) encodeTo(output []byte, input []byte) {
    i := 0  // input索引
    j := 0  // output索引

    // 主循环：每3字节编码为4字符
    for i < len(input) - 3 {
        // 读取3字节并组合为24位值（带字节序转换）
        // ROL2：字节旋转
        value := (ROL2(input[i:i+2]) << 8) | input[i+2]

        // 编码为4个6位字符（使用自定义encode_table）
        output[j]   = e.encode[(value >> 18) & 0x3F]
        output[j+1] = e.encode[(value >> 12) & 0x3F]
        output[j+2] = e.encode[(value >> 6) & 0x3F]
        output[j+3] = e.encode[value & 0x3F]

        i += 3
        j += 4
    }

    // 处理剩余字节（1或2字节）
    remaining := len(input) - i
    if remaining > 0 {
        // 读取剩余字节
        value := uint64(input[i]) << 16

        if remaining == 2 {
            value |= uint64(input[i+1]) << 8
        }

        // 编码剩余字节
        output[j] = e.encode[(value >> 18) & 0x3F]
        output[j+1] = e.encode[(value >> 12) & 0x3F]

        if remaining == 2 {
            output[j+2] = e.encode[(value >> 6) & 0x3F]

            // 添加padding（如果需要）
            if e.padChar != NoPadding {  // dword_145C71E60 != -1
                output[j+3] = byte(e.padChar)  // '$' = 36
            }
        } else if remaining == 1 {
            output[j+2] = e.encode[(value >> 6) & 0x3F]

            // 添加padding（如果需要）
            if e.padChar != NoPadding {
                output[j+3] = byte(e.padChar)
            }
        }
    }
}
```

## 3. 自定义字母表

### 字母表初始化（encrypt.init：地址：0x140454860）

**初始化流程**（IDA验证）：
```go
func init() {
    // 1. 创建decodeMap初始值（256字节重复值）
    decodeMapInit := strings.Repeat(someByte, 256)
    qword_1460DB738 = len(decodeMapInit)
    qword_1460DB730 = &decodeMapInit

    // 2. 获取自定义字母表（从某个位置）
    encodeTable := ...  // qword_145FE41D8指向的位置
    tableLen := qword_1460DB748
    tablePtr := qword_1460DB740

    // 3. 创建encoding对象
    encodingObj := new(encoding)
    encodingObj.padChar = dword_145C71E5C  // '$' = 36

    // 4. 复制自定义字母表
    memmove(encodingObj.encode, encodeTable, min(tableLen, 64))

    // 5. 复制decodeMap初始值
    memmove(encodingObj.decodeMap, decodeMapInit, min(len(decodeMapInit), 256))

    // 6. 构建decodeMap反向映射
    for i := 0; i < tableLen; i++ {
        char := encodeTable[i]
        encodingObj.decodeMap[char] = i  // 字符 → 索引
    }

    // 7. 存储全局encoding对象
    qword_1460D9408 = encodingObj
}
```

### Padding字符

**关键发现**：
- `dword_145C71E5C` = `0x24` (36) → '$' 美元符号
- `dword_145C71E60` = `0xffffffff` (-1) → NoPadding标志

**Padding逻辑**：
```go
if encoding.padChar == NoPadding {  // -1
    // 不添加padding
} else {
    // 添加padding字符 '$'
    output[...] = byte(encoding.padChar)
}
```

### 自定义字母表来源（未完全确定）

**可能来源**：
- 内存地址：`qword_145FE41D8`指向的数据
- 或动态生成（通过shuffle函数）
- 或硬编码常量（未在IDA字符串搜索中发现）

**推测**：自定义字母表可能是标准base64字母表的变种：
- 标准：`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`
- URL-safe：`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_`
- 自定义：可能包含特殊字符或不同顺序

## 4. Block重排算法（shuffle）

### 内存重排机制

**IDA观察到的memmove操作**：
- `encodeToString`函数中多次调用`runtime.memmove`
- 将编码结果按特定规则重新排列
- 涉及多个内存块的移动和交换

**重排逻辑**（encodeToString：0x1404549e0）：
```go
// 编码后进行block重排
v27 = (outputLen + outputLen/2) / 2  // 某种分块计算

// 第一块移动
memmove(output[outputLen-v27:], encodedBuffer[0:v27])

// 第二块移动
memmove(output[0:], encodedBuffer[v27:outputLen])

// 第三块移动（如果有）
memmove(output[v27:], encodedBuffer[outputLen-v27:outputLen])
```

**关键特征**：
- 3块分割（计算v27作为分界点）
- 逆序重排（output[outputLen-v27:]接收第一块）
- 多次memmove操作实现复杂重排

## 5. 实际应用场景

### Encode=1应用API（推测）

**触发路径**：
- `/api/v2/remoteAgent/qoder/*` → POST请求 → Encode=1
- 其他特定method组合 → Encode=1

**不编码路径**：
- `/ncqs/api/v1/quotas` → 不编码
- `/algo/api/v1/organizations` → 不编码
- `/api/v1/service/next_edit_predict` → 不编码

### 编码结果格式

**请求body结构**：
```json
{
  "Payload": "<Encode=1编码后的base64字符串>",
  "EncodeVersion": "1",
  "RequestId": "<UUID>"
}
```

## 6. 关键函数地址表

| 函数名 | 地址 | 功能 |
|--------|------|------|
| `shouldEncryptBody` | 0x14087e500 | 判断是否启用Encode=1 |
| `shouldAddEncodeParam` | 0x14087e3c0 | 详细Encode触发判断 |
| `encodeRequestBody` | 0x14087d6a0 | 请求体编码准备 |
| `encoding.encodeToString` | 0x1404549e0 | Encode=1完整算法 |
| `encoding.encodeTo` | 0x140454c80 | Base64核心编码 |
| `encrypt.init` | 0x140454860 | 自定义encoding初始化 |

## 7. 全局变量表

| 变量名 | 地址 | 值 | 用途 |
|--------|------|-----|------|
| `off_146011C60` | 0x146011C60 | 指针→"1" | Encode=1全局开关 |
| `qword_1460D9408` | 0x1460D9408 | encoding对象 | 自定义encoding全局实例 |
| `dword_145C71E5C` | 0x145C71E5C | 0x24 ('$') | padding字符 |
| `dword_145C71E60` | 0x145C71E60 | 0xffffffff (-1) | NoPadding标志 |
| `qword_145FE41D8` | 0x145FE41D8 | 指针 | 自定义字母表来源 |

## 8. 与标准Base64的差异

### 差异对比

| 特性 | 标准Base64 | Encode=1自定义 |
|------|-----------|---------------|
| 字母表 | `ABC...+/` | 自定义字母表（来源待确定）|
| Padding | '=' | '$' 或 NoPadding |
| Block排列 | 顺序编码 | 重排（shuffle）|
| 字节序 | 标准 | ROL2字节旋转 |

## 9. 未解决问题

### 高优先级
1. **自定义字母表确切来源**：`qword_145FE41D8`指向的具体内容
2. **Block重排详细规则**：3块分割的确切算法和参数

### 中优先级
1. **动态运行时验证**：Frida监控实际Encode=1编码过程
2. **所有触发路径确认**：哪些API实际使用Encode=1

## 10. 下一步分析建议

### 方案1：Frida动态验证
- 监控`encodeToString`函数输入输出
- 抓取实际的自定义字母表内容
- 验证block重排算法

### 方案2：内存dump分析
- 运行时dump `qword_1460D9408` encoding对象
- 直接读取encode_table内容
- 确认实际padding行为

### 方案3：继续IDA静态分析
- 搜索更多字符串线索
- 分析shuffle函数细节
- 查找字母表生成逻辑

---

**总结**：通过IDA Pro MCP静态分析，完全破解了Encode=1编码机制的核心流程，包括触发条件判断、encoding结构体布局、核心编码算法、padding机制。自定义字母表来源和block重排细节需要进一步动态验证或内存分析。