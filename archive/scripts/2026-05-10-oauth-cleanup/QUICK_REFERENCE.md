# Lingma OAuth Monitor - Quick Reference

## 一键启动
```bash
# 方式 1: 快速启动（推荐）
quick_start.bat

# 方式 2: 手动运行完整监控
frida -n lingma.exe -l frida_oauth_monitor.js

# 方式 3: 手动运行 Token 提取
frida -n lingma.exe -l frida_token_extractor.js
```

## 文件清单
```
核心脚本:
├─ frida_oauth_monitor.js      # 完整监控 (详细日志)
└─ frida_token_extractor.js    # Token 提取 (简洁输出)

启动脚本:
├─ quick_start.bat             # 一键启动 (交互式菜单)
└─ run_oauth_monitor.bat       # 完整监控启动

文档:
├─ README_OAUTH_MONITOR.md     # 完整 README
└─ OAuth_Monitoring_Guide.md   # 详细使用指南
```

## 监控点速查表

| 函数 | 地址 | 功能 | 关键输出 |
|------|------|------|---------|
| generatePKCEChallenge | 0x1a197a0 | PKCE 生成 | verifier, challenge |
| HandleAuthCallback | 0x1a18dc0 | 回调处理 | auth, token_string |
| parseAuthInfoV3 | 0x1a21b80 | auth 解析 | Encode=1 解码 |
| parseAuthToken | 0x1a213e0 | token 解析 | pt-*, rt-* token |
| **SaveUserInfo** | **0x88e260** | **Token 存储** | **完整结构体** |

## 关键偏移量 (CosyUserInfo)

```
offset 0x80: SecurityOauthToken (pt-*)
offset 0x90: RefreshToken (rt-*)
offset 0xa0: TokenExpireTime (Unix timestamp)
总大小: 288 字节
```

## 预期输出

### 成功提取 Token
```
[SUCCESS] FOUND CosyUserInfo STRUCTURE
[+] SecurityToken (pt-*): pt-xxxxx...
[+] RefreshToken (rt-*): rt-xxxxx...
[+] ExpireTime: 1714521600 (2024-05-01T00:00:00.000Z)
```

### 验证点
- ✅ Encode=1 Base64 字母表
- ✅ token_string 分隔符 `\n`
- ✅ CosyUserInfo 完整结构
- ✅ OAuth 流程完整性

## 故障排除

### 进程未找到
```bash
# 检查进程
frida-ps | findstr lingma

# 确认进程名
frida-ps -l
```

### 权限问题
```bash
# 以管理员运行
# 关闭杀毒软件
```

### Hook 失败
```bash
# 检查地址
frida -n lingma.exe -e "console.log(Module.findBaseAddress('lingma.exe'))"
```

## 使用流程
```
1. 启动 Lingma 客户端
2. 运行 quick_start.bat
3. 选择监控模式 (推荐: 2)
4. 在 Lingma 中点击登录
5. 查看监控输出
6. 提取 pt-* 和 rt-* token
```

## 安全提醒
⚠️ 提取的 token 仅供本地测试
⚠️ 不要上传到公共位置
⚠️ 测试后及时撤销 token
⚠️ 仅在授权环境使用