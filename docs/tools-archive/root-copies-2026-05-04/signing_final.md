# Lingma CTF - 最终分析报告

> 历史说明（2026-04-25）：
> 这份报告保留的是签名链分析阶段结论，不再代表当前仓库的最终总状态。
> 当前已经存在受约束的远端直连实现，因此请把它视为签名专项证据，而不是总览结论。

> 状态说明：这是一份 signer 分支的阶段性总结，里面关于 `SHA-256/getAppSalt` 主导全链的问题定义，已经被后续主文档进一步收缩。当前继续推进时，应优先以 `docs/lingma-analysis-endpoint-auth.md`、`docs/lingma-analysis-request-flow-pruned.md` 和 `docs/continue-analysis-from-current-state.md` 为准，这份文件只保留局部历史价值。

## 当前状态

### 已完成
- [x] 提取签名密钥（3个变体）
- [x] 确认 SHA-256 为哈希算法
- [x] 确认 getAppSalt 函数位于 RVA 0x882760
- [x] 确认完整签名调用链
- [x] 确认 /ping 端点公开可用
- [x] 确认受保护端点需要认证（403 Forbidden）

### 未解决
- [ ] 无法触发签名流程（需要已认证状态）
- [ ] 无法验证签名算法是否正确（受保护端点返回 403）
- [ ] Frida 与 Go 1.23 不兼容

## 关键发现

### 1. 签名密钥

从 getAppSalt 函数（RVA 0x882760）中提取：

```python
SECRET_FULL = "&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTed2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw==9f1dff714a390b20aeb19175ecc496e6"
SECRET_PREFIX = "&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe"
SECRET_B64 = "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="  # 解码: "war, war never changes"
SECRET_HEX_SUFFIX = "9f1dff714a390b20aeb19175ecc496e6"
```

### 2. 签名调用链

```
BuildBigModelAuthRequest (0x881000)
  ├── classifyURL(endpoint) → routeType ("sign" / "auth" / "upload")
  ├── 如果 routeType == "sign":
  │   └── getAppSalt (0x882760)
  │       ├── time.Format("Mon, 02 Jan 2006 15:04:05 GMT") → Date
  │       ├── SHA-256(secret + date + endpoint) → Signature
  │       └── 返回 map: {"Date": ..., "Signature": ..., "Appcode": "cosy", ...}
  ├── addBigModelSignatureHeaders (0x882ba0)
  │   └── 调用 AuthProvider 动态计算签名
  └── MainSigning (0x8821e0)
      ├── ExtractConfig (0x882e40) - 格式化时间戳
      ├── ValidateFlags (0x884080) - 验证标志位
      ├── ProcessSliceData (0x885620) - 处理切片数据
      ├── AddAuthHeaders (0x8840e0) - 添加授权头
      └── FinalHandler (0xb11200) - 最终处理
```

### 3. getAppSalt 返回的 Map 结构

```go
map[string]string{
    "Date":      "Mon, 02 Jan 2006 15:04:05 GMT",  // 格式化的 UTC 时间
    "Signature": "<sha256-hex>",                    // SHA-256 哈希的十六进制
    "Appcode":   "cosy",                            // 固定值
    // 第4个键值对未确定
}
```

### 4. 端点分类逻辑

```assembly
0x88112d: cmp rdx, 4                    ; 长度检查
0x881131: jne skip                      ; 如果不是4字节则跳过
0x881133: cmp [rsi], 0x68747561         ; "auth"
0x881139: je auth_handler
0x88113b: cmp [rsi], 0x6e676973         ; "sign"
0x881141: jne check_upload
0x88114f: call getAppSalt               ; 签名分支
```

路由类型比较：
- "auth" (4字节) → 认证处理
- "sign" (4字节) → 签名处理（调用 getAppSalt）
- "upload" (6字节) → 上传处理

### 5. 服务器响应

| 端点 | 方法 | 状态码 | 说明 |
|------|------|--------|------|
| `/algo/api/v1/ping` | GET | 200 | 返回 "pong" |
| `/algo/api/v1/heartbeat` | POST | 403 | "Request discarded" - 需要认证 |
| `/algo/api/v1/tracking` | POST | 403 | "Request discarded" - 需要认证 |
| `/algo/api/v1/organizations` | GET | 404 | 路径不存在 |
| `/algo/api/v1/service/next_edit_predict` | POST | 404 | 路径不存在 |

### 6. 已知配置

**Alibabacloud 配置:**
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

## 阻塞问题

### 核心障碍
签名验证需要**已认证的会话**才能触发。在未登录状态下：
- `getAppSalt` 不会被调用（routeType 不是 "sign"）
- `addBigModelSignatureHeaders` 返回 "auth provider not initialized"
- 服务器返回 403 "Request discarded"

### 可能的解决路径

1. **启动 Lingma 客户端并登录**
   - 登录后会建立有效的 machine token
   - 签名流程会被触发
   - 可以通过 Frida 或网络抓包捕获签名

2. **通过 LSP 协议触发**
   - Lingma 通过命名管道 `\\.\pipe\lingma-XXXXXX` 通信
   - 发送 LSP 请求可能触发内部签名
   - 需要先启动客户端

3. **直接分析签名算法**
   - 更深入地反汇编 `getAppSalt` 和 `0x4563c0` 函数
   - 精确确定 SHA-256 的输入格式
   - 但无法在服务器上验证

## 下一步建议

### 方案 A: 启动客户端 + 抓包
1. 启动 Lingma.exe
2. 使用 HTTP 代理或网络抓包工具捕获请求
3. 提取完整的签名头和请求数据
4. 离线验证签名算法

### 方案 B: 深入静态分析
1. 分析 `0x4563c0` SHA-256 函数的调用约定
2. 确定 getAppSalt 中 SHA-256 的精确输入
3. 重建完整的签名算法

### 方案 C: 绕过认证
1. 尝试伪造 machine token
2. 或使用环境变量注入认证信息
3. 或直接修改客户端跳过认证检查

## 文件清单

| 文件 | 说明 |
|------|------|
| `forge_get_requests.py` | GET 请求测试脚本 |
| `forge_signing.py` | 签名算法测试脚本 |
| `analyze_auth_funcs.py` | 授权函数分析 |
| `trace_crypto_refs.py` | 加密函数追踪 |
| `resolve_signing_refs.py` | 签名引用解析 |
| `deep_trace_signing.py` | 深度追踪签名流程 |
| `signing_final.md` | 签名分析文档（本文件） |
