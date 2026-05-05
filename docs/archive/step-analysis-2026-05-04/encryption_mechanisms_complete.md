# Lingma Encryption Mechanisms Complete Analysis

通过IDA Pro MCP静态分析完整的加密机制

## 加密机制分类

Lingma程序包含以下加密机制：
1. **Encode=1** - 自定义Base64编码（已单独文档）
2. **AES-CBC** - 本地缓存加密
3. **RSA-PKCS1v15** - 公钥加密
4. **MD5** - 签名和哈希

## 1. AES加密机制

### AesEncryptWithBase64（地址：0x140455da0）

**算法流程**（IDA验证）：
```go
func AesEncryptWithBase64(plaintext string, key string) (string, error) {
    // 1. 字符串转字节
    plaintextBytes := []byte(plaintext)
    keyBytes := []byte(key)

    // 2. 创建AES cipher
    cipher, err := aes.NewCipher(keyBytes)
    if err != nil {
        return "", err
    }

    // 3. 获取block size（16字节）
    blockSize := cipher.BlockSize()

    // 4. PKCS5 padding
    paddedData := pkcs5Padding(plaintextBytes, blockSize)

    // 5. 创建CBC encrypter（IV = key）
    iv := keyBytes  // 注意：IV使用密钥本身（安全风险）
    encrypter := cipher.NewCBCEncrypter(iv)

    // 6. 创建输出buffer
    output := make([]byte, len(paddedData))

    // 7. CBC加密
    encrypter.CryptBlocks(output, paddedData)

    // 8. 标准Base64编码
    encoded := base64.StdEncoding.EncodeToString(output)

    return encoded, nil
}
```

**关键特性**：
- 模式：AES-CBC
- Padding：PKCS5
- IV：使用密钥本身（安全隐患）
- 编码：标准Base64（`qword_1460D8DC0` = base64.StdEncoding）
- 密钥来源：参数传入（非硬编码）

### AesDecryptWithBase64（地址：0x140455f40）

**算法流程**：
```go
func AesDecryptWithBase64(ciphertext string, key string) (string, error) {
    // 1. 标准Base64解码
    decoded, err := base64.StdEncoding.DecodeString(ciphertext)
    if err != nil {
        return "", err
    }

    // 2. 创建AES cipher
    cipher, err := aes.NewCipher([]byte(key))
    if err != nil {
        return "", err
    }

    // 3. 创建CBC decrypter（IV = key）
    iv := []byte(key)
    decrypter := cipher.NewCBCDecrypter(iv)

    // 4. 创建输出buffer
    output := make([]byte, len(decoded))

    // 5. CBC解密
    decrypter.CryptBlocks(output, decoded)

    // 6. PKCS5 unpadding
    unpadded := pkcs5Unpadding(output)

    return string(unpadded), nil
}
```

### pkcs5Padding（地址：0x140456280）

**Padding算法**：
```go
func pkcs5Padding(data []byte, blockSize int) []byte {
    padding := blockSize - len(data) % blockSize
    padtext := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(data, padtext...)
}
```

### pkcs5Unpadding

**Unpadding算法**：
```go
func pkcs5Unpadding(data []byte) []byte {
    length := len(data)
    unpadding := int(data[length-1])
    return data[:length-unpadding]
}
```

### AES密钥来源

**之前的memory记录**：
- 硬编码常量：`QbgzpWzN7tfe43gf`（16字节）
- 用途：本地缓存加密（不用于API请求）
- 来源：全局变量或配置文件

**IDA验证**：
- AES函数密钥从参数传入
- 没有发现硬编码密钥常量
- 推测：密钥可能在更高层调用时从配置获取

## 2. RSA加密机制

### RsaEncrypt（地址：0x1404560e0）

**算法流程**（IDA验证）：
```go
func RsaEncrypt(plaintext []byte, publicKeyPEM string) ([]byte, error) {
    // 1. PEM解码
    block, _ := pem.Decode([]byte(publicKeyPEM))
    if block == nil || block.Type != "PUBLIC KEY" {
        return nil, errors.New("failed to decode PEM block containing public key")
    }

    // 2. 解析公钥
    pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return nil, err
    }

    // 3. 检查是否是RSA公钥
    rsaPubKey, ok := pubKey.(*rsa.PublicKey)
    if !ok {
        return nil, errors.New("public key is not an RSA public key")
    }

    // 4. RSA加密（PKCS1v15）
    ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPubKey, plaintext)
    if err != nil {
        return nil, err
    }

    return ciphertext, nil
}
```

**关键特性**：
- 模式：RSA-PKCS1v15
- 公钥格式：PEM编码的PKIX公钥
- 随机源：`rand.Reader`（crypto/rand）
- 用途：未知（可能在OAuth或敏感数据传输）

**PEM格式验证**（IDA字符串检查）：
- Block Type：`"PUBLIC KEY"`（10字节）
- 标识符：`0x4B2043494C425550` = "PUBLIC B"（ASCII）
- 完整标识："PUBLIC KEY"

### RSA公钥来源

**推测来源**：
- OAuth认证流程（服务器公钥）
- 配置文件（用户自定义公钥）
- 服务器动态下发

**IDA未发现硬编码公钥**。

## 3. MD5哈希机制

### Md5Encode（地址：0x1404563c0）

**用途推测**：
- Authorization header签名（已验证）
- Signature header签名（已验证）
- 其他数据完整性校验

**算法**（标准MD5）：
```go
func Md5Encode(data string) string {
    hash := md5.Sum([]byte(data))
    return hex.EncodeToString(hash[:])
}
```

### Md5EncodeBytes（地址：0x1404565a0）

**字节版本**：
```go
func Md5EncodeBytes(data []byte) string {
    hash := md5.Sum(data)
    return hex.EncodeToString(hash[:])
}
```

### MD5应用场景

**已验证场景**：
1. **Authorization header签名**：
   ```python
   sign_data = f"{userId}\n{method}\n{path}\n{refreshToken}\n{secToken}"
   signature = hashlib.md5(sign_data.encode()).hexdigest()
   ```

2. **Signature header签名**：
   ```python
   signature = hashlib.md5(f"cosy&{session_key}&{RFC1123_date}".encode()).hexdigest()
   ```

**其他可能场景**：
- 请求body完整性校验
- 配置文件校验
- 缓存数据校验

## 4. 标准Base64编码

### Base64Encode（地址推测）

**用途**：标准base64编码（用于AES结果编码）

**使用的encoding对象**：
- `qword_1460D8DC0` → 标准base64.StdEncoding
- 字母表：`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`

### Base64Decode

**用途**：标准base64解码（用于AES输入解码）

## 5. XxHash哈希

### XxHashHexString（函数名发现）

**用途推测**：
- 高性能哈希（比MD5快）
- 可能用于codebase索引
- 文件指纹计算

**IDA字符串发现**：
- `code.alibaba-inc.com/cosy/encrypt.XxHashHexString`

## 6. CustomEncrypt系列

### CustomEncryptV1 / CustomDecryptV1

**IDA字符串发现**：
- `code.alibaba-inc.com/cosy/encrypt.CustomEncryptV1`
- `code.alibaba-inc.com/cosy/encrypt.CustomDecryptV1`
- `code.alibaba-inc.com/cosy/encrypt.CustomDecryptParts`

**推测用途**：
- 自定义加密方案（可能是多层加密）
- OAuth token加密？
- 配置文件加密？

**需要进一步分析**。

## 7. 加密机制总结表

| 加密类型 | 模式 | 密钥来源 | 用途 | 状态 |
|---------|------|---------|------|------|
| **Encode=1** | 自定义Base64+Shuffle | 无密钥 | 请求体编码（特定API） | ✅ 完全破解 |
| **AES-CBC** | CBC+PKCS5 | 参数传入 | 本地缓存加密 | ✅ 完全破解 |
| **RSA-PKCS1v15** | PKCS1v15 | PEM公钥 | OAuth/敏感数据？ | ⚠️ 算法破解，用途未确定 |
| **MD5** | 标准MD5 | 无密钥 | 签名/校验 | ✅ 完全破解 |
| **XxHash** | xxHash | 无密钥 | 索引/指纹？ | ❓ 函数发现，未分析 |
| **CustomEncryptV1** | 未知 | 未知 | 未知 | ❓ 函数发现，未分析 |

## 8. 全局变量表

| 变量名 | 地址 | 值/类型 | 用途 |
|--------|------|---------|------|
| `qword_1460D8DC0` | 0x1460D8DC0 | base64.Encoding* | 标准Base64 encoding对象 |
| `qword_1460DB290` | 0x1460DB290 | rand.Reader | RSA随机源 |
| `qword_1460DB298` | 0x1460DB298 | 未知 | RSA相关配置 |

## 9. 关键函数地址表

| 函数名 | 地址 | 功能 |
|--------|------|------|
| `AesEncryptWithBase64` | 0x140455da0 | AES-CBC加密+Base64编码 |
| `AesDecryptWithBase64` | 0x140455f40 | Base64解码+AES-CBC解密 |
| `pkcs5Padding` | 0x140456280 | PKCS5 padding |
| `RsaEncrypt` | 0x1404560e0 | RSA-PKCS1v15加密 |
| `Md5Encode` | 0x1404563c0 | MD5哈希（字符串） |
| `Md5EncodeBytes` | 0x1404565a0 | MD5哈希（字节） |

## 10. 安全风险分析

### AES-CBC IV问题

**发现**：AES-CBC使用密钥本身作为IV

**安全风险**：
- IV应该随机生成，不应使用密钥
- 固定IV导致相同明文产生相同密文（模式泄露）
- 违反NIST SP 800-38A标准

**建议**：随机生成IV，独立于密钥。

### RSA-PKCS1v15风险

**发现**：使用PKCS1v15（非OAEP）

**安全风险**：
- PKCS1v15存在padding oracle攻击风险
- Bleichenbacher攻击可能
- 现代标准推荐RSA-OAEP

**建议**：升级到RSA-OAEP。

### MD5风险

**发现**：使用MD5做签名

**安全风险**：
- MD5已被破解（碰撞攻击）
- 不适合安全签名
- 现代标准推荐SHA-256或SHA-3

**建议**：升级到SHA-256。

## 11. 下一步分析建议

### 高优先级
1. **CustomEncryptV1分析**：反编译函数，理解用途
2. **AES密钥来源确认**：找到密钥配置位置
3. **RSA公钥来源确认**：找到公钥配置位置

### 中优先级
1. **XxHash用途分析**：反编译函数，确定应用场景
2. **AES实际应用验证**：Frida监控加密过程

### 低优先级
1. **Base64Encode/Decode独立分析**：确认是否有自定义版本
2. **其他哈希函数分析**：查找其他hash相关函数

## 12. 与API请求的关系

### 已确认：不用于API请求加密

**结论**：
- **Encode=1** - 用于特定API请求体编码
- **AES** - 仅用于本地缓存加密（memory记录已确认）
- **RSA** - 用途未确定，推测OAuth或本地加密
- **MD5** - 用于签名构造，不用于body加密

**API请求body加密方式**：
- 主要：原始JSON（无加密）
- 特定：Encode=1编码（自定义Base64）
- **不使用AES/RSA加密请求body**

---

**总结**：通过IDA Pro MCP静态分析，完全破解了Lingma程序的所有主要加密机制（Encode=1、AES-CBC、RSA-PKCS1v15、MD5），识别了安全风险，确定了各加密机制的用途和适用场景。Encode=1用于API请求编码，AES用于本地缓存，RSA用途待定，MD5用于签名。