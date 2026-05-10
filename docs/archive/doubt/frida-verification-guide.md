# Frida Hook 验证签名参数顺序

> 目标：验证 IDA Pro 分析中的签名参数顺序推测
> 日期：2026-04-30

---

## 1. 背景

根据 IDA Pro 反编译分析，`cosy_auth_user.getAuthSignature` 函数接收 10 个参数（5 个 Go string），用于计算 Authorization header 中的签名部分。

**IDA 分析推测的参数顺序：**
```c
getAuthSignature(userId, securityOauthToken, refreshToken, path, method)
```

**签名计算：**
```python
sign_data = "{userId}\n{securityOauthToken}\n{refreshToken}\n{path}\n{method}"
signature = MD5(sign_data)
```

---

## 2. 使用方法

### 2.1 方法 A：Hook 正在运行的灵码进程

**步骤：**

1. **启动灵码程序**
   - 正常启动灵码程序（如果已经在运行，跳过此步）
   - 等待灵码程序需要刷新 token（通常 token 快过期时自动触发）

2. **查找灵码进程 PID**
   ```bash
   # Windows
   ps aux | grep Lingma.exe | grep -v grep
   
   # 或使用 tasklist
   tasklist | findstr Lingma.exe
   ```

3. **运行 Frida Hook**
   ```bash
   # 快速验证（推荐）
   frida -l frida_hooks/quick_verify_signature.js -p <pid>
   
   # 综合监控（详细）
   frida -l frida_hooks/comprehensive_auth_monitor.js -p <pid>
   ```

4. **等待 Hook 触发**
   - 灵码程序会在 token 快过期时自动调用 refresh
   - 或者手动触发 refresh（如果灵码程序支持）

---

### 2.2 方法 B：Frida Spawn 模式（启动新进程）

**步骤：**

1. **运行 Frida Spawn**
   ```bash
   # Windows
   frida -l frida_hooks/comprehensive_auth_monitor.js -f ~/.lingma/bin/2.11.2/x86_64_windows/Lingma.exe
   
   # 或使用完整路径
   frida -l frida_hooks/comprehensive_auth_monitor.js -f C:\Users\Zipper\.lingma\bin\2.11.2\x86_64_windows\Lingma.exe
   ```

2. **等待灵码启动**
   - Frida 会启动灵码程序并注入 Hook
   - 灵码启动后会自动调用 `/api/v3/user/status` 检查用户状态
   - 此时可以看到认证头构造过程

---

## 3. 预期输出

### 3.1 quick_verify_signature.js 输出

```
============================================================
[getAuthSignature] Called!
============================================================

参数解析：
Param[0]: 5930676910898027
Param[1]: pt-Atl8MQJdcCqbDEdAZAyYgnbp
Param[2]: rt-GLbIaXzLEFCo8rINstjCv6EC
Param[3]: /api/v3/user/refresh_token
Param[4]: POST

签名字符串（拼接后）：
5930676910898027
pt-Atl8MQJdcCqbDEdAZAyYgnbp
rt-GLbIaXzLEFCo8rINstjCv6EC
/api/v3/user/refresh_token
POST

[getAuthSignature] Return
Signature (MD5): a1b2c3d4e5f6...
Length: 32

✅ 签名参数顺序验证完成
参数顺序: Param[0], Param[1], Param[2], Param[3], Param[4]
```

### 3.2 comprehensive_auth_monitor.js 输出

```
============================================================
[1/3] getAuthPayload Called
============================================================
UserId: 5930676910898027
Payload (base64, len=XXX):
  eyJ2ZXJzaW9uIjoidjIiLCJyZXF1ZXN0SWQiOi...

✅ Payload 构造完成

============================================================
[2/3] getAuthSignature Called
============================================================
Param[0] (userId (推测)): 5930676910898027
Param[1] (securityOauthToken (推测)): pt-Atl8MQJdcCqbDEdAZAyYgnbp
Param[2] (refreshToken (推测)): rt-GLbIaXzLEFCo8rINstjCv6EC
Param[3] (path (推测)): /api/v3/user/refresh_token
Param[4] (method (推测)): POST

签名字符串（拼接后）：
"5930676910898027\npt-Atl8MQJdcCqbDEdAZAyYgnbp\nrt-GLbIaXzLEFCo8rINstjCv6EC\n/api/v3/user/refresh_token\nPOST"

Signature (MD5): a1b2c3d4e5f6...

✅ 签名计算完成
参数顺序总结:
  0: userId (推测)
  1: securityOauthToken (推测)
  2: refreshToken (推测)
  3: path (推测)
  4: method (推测)

============================================================
[3/3] AuthToken Called
============================================================
Path: /api/v3/user/refresh_token
Method: POST

✅ AuthToken 完成

🎉 检测到 Refresh Token 调用！
  Path: /api/v3/user/refresh_token
  Method: POST

============================================================
[HTTP] 关键请求检测
============================================================
URL: https://lingma.alibabacloud.com/algo/api/v3/user/refresh_token
Response Status: 200 (或 404)
```

---

## 4. 验证标准

**成功验证的标准：**

1. ✅ **参数顺序确认**
   - `Param[0]` = userId（纯数字）
   - `Param[1]` = securityOauthToken（以 `pt-` 开头）
   - `Param[2]` = refreshToken（以 `rt-` 开头）
   - `Param[3]` = path（以 `/api/` 开头）
   - `Param[4]` = method（POST 或 GET）

2. ✅ **签名字符串格式**
   - 5 个参数用换行符 `\n` 拼接
   - 拼接后的字符串长度可计算

3. ✅ **签名结果**
   - MD5 输出是 32 字符的十六进制字符串

**如果参数顺序与预期不符：**
- 记录实际的参数顺序
- 更新 `tools/lingma_refresh_token_direct.py` 中的签名计算逻辑
- 更新 `docs/topics/ida-http-auth-headers-analysis.md` 文档

---

## 5. 故障排查

### 5.1 Hook 未触发

**原因：**
- 灵码程序未调用 refresh token 逻辑
- Token 还未过期，不需要刷新

**解决方案：**
1. 等待 token 快过期（通常 1-2 小时后）
2. 或者，触发灵码程序的用户状态检查（例如切换工作区）

### 5.2 Frida 注入失败

**原因：**
- Frida 版本不兼容
- 灵码程序有运行保护限制（ unlikely）

**解决方案：**
```bash
# 更新 Frida
pip install --upgrade frida-tools

# 检查 Frida 版本
frida --version
```

### 5.3 参数读取失败

**原因：**
- Go string 结构偏移量不正确
- 内存读取地址错误

**解决方案：**
- 查看 Hook 脚本的 Error 输出
- 检查 args[] 数组的实际值
- 根据输出调整偏移量

---

## 6. 后续行动

**验证成功后：**

1. **更新 Python 脚本**
   ```python
   # 如果参数顺序不同，更新 lingma_refresh_token_direct.py
   sign_data = f"{param0}\n{param1}\n{param2}\n{param3}\n{param4}"
   ```

2. **更新文档**
   - 记录实际验证结果
   - 更新参数顺序说明

3. **测试其他端点**
   - `/api/v3/user/status` - 用户状态检查
   - 其他 API 调用 - 验证通用性

---

## 7. 参考资料

- `docs/topics/ida-http-auth-headers-analysis.md` - IDA Pro 分析结果
- `frida_hooks/quick_verify_signature.js` - 快速验证脚本
- `frida_hooks/comprehensive_auth_monitor.js` - 综合监控脚本
- `tools/lingma_refresh_token_direct.py` - Python 实现脚本

---

**最后更新：** 2026-04-30
