# Refresh Token 远程刷新分析

## 概要

Lingma 的 token 刷新采用两层架构：
1. **本地 LSP WebSocket Handler** (`RefreshTokenHandler` @ 0x141aaf7e0)
2. **远程 HTTP API** (`doRefreshToken` @ 0x14088d660)

## 最终结论（2026-05-12 深度诊断）

### 国际版 `lingma.alibabacloud.com` — refresh_token 端点不存在

**确认事实**：
- `/api/v3/user/refresh_token` 返回 **HTTP 404**（Spring Boot 标准路由错误）
- 7 种请求变体全部 404（`need_refresh=true`, 无 Encode=1, PUT, GET, octet-stream, 等）
- 同域可用的端点只有：`user/status`(200), `user/login`(500), `user/grantAuthInfos`(200)
- `user/login` 是**遥测端点**，不是认证入口（`performUserLogAction` 仅上报 login/logout 事件）

### user/status 的隐含续期能力

IDA 分析 `fetchAuthStatusWithUri` (0x141a1f260) 确认：
- `UserStatusResponse` 结构体包含 19 个字段，含 `SecurityOauthToken`, `RefreshToken`, `ExpireTime`
- 成功路径中代码显式提取这些字段并保存到本地
- **但服务端只在特定条件下返回 token 字段**（当前测试中未返回）
- `need_refresh=true` 导致 **500 内部错误**（续期逻辑存在但后端缺失）

### 客户端容错设计

`EnsureTokenValid` (0x14088d220) 的关键行为：
- token 过期 → 调用 `Logout()`
- token 在 1 小时内过期 → 尝试 `doRefreshToken()`，失败仅记录警告
- **刷新失败不阻止使用** — 函数返回 nil (成功)
- 这意味着 Lingma 自身也会遇到此 404，只是静默忽略

## 可用的 API 端点（国际版）

| 端点 | 状态 | 说明 |
|------|------|------|
| `user/status` | 200 OK | 返回用户信息，有条件地返回新 token |
| `user/login` | 500 | 遥测端点（上报事件），非认证 |
| `user/grantAuthInfos` | 200 OK | 返回授权信息列表 |
| `user/refresh_token` | **404** | 路由未注册 |
| `user/remoteToken` | 404 | SSE 会话管理，非刷新 |

## Token 状态

- 当前 token 有效期剩余 ~54 天
- token 过期后需通过 OAuth 重新登录获取
- `user/status` 理论上可以在 token 接近过期时自动续期（如果服务端支持）

## 建议

1. **短期**：token 有效期充足，无需立即刷新
2. **中期**：监控 token 过期时间，在接近过期前尝试 `user/status` 续期
3. **长期**：token 过期后使用 `python lingma_oauth_complete.py login` 重新登录

## IDA 逆向结果

### doRefreshToken (0x14088d660) 调用链

```
1. MustGetClient → 获取 SIGN 模式 HTTP Client
2. 构建 AuthQueryParam (snake_case):
   - UserId, OrgId, SecurityOauthToken, RefreshToken
3. ToJsonStr → JSON 序列化
4. HttpPayload 包装: {RequestId, Payload, EncodeVersion:"1"}
5. BuildBigModelSignRequest(SIGN_MODE=4, "/api/v3/user/refresh_token")
6. POST → 检查 StatusCode == 200
7. 检查响应是否包含 "success":false
8. JSON Unmarshal → UserStatusResponse {RefreshToken, SecurityOauthToken, ExpireTime}
9. 成功 → RefreshUserInfoSecurityToken() 保存新凭据
```

### UserStatusResponse 结构体 (19 字段, 256 字节)

```
Name, Id, AccountId, StaffId, Token, Quota, WhitelistStatus,
OrgId, OrgName, YxUid, AvatarUrl, SecurityOauthToken,
RefreshToken, ExpireTime, IsSubAccount, Email, UserType,
IsPrivacyPolicyModifiable, IsQuotaExceeded
```

JSON tags: `securityOauthToken`, `refreshToken`, `expireTime`, `token`

### GetQuotaAndTokenById (0x141a16120) — 隐含续期路径

```
1. ReadQuotaCache → 检查缓存
2. if WhitelistStatus == "PASS":
3.   fetchAuthStatusWithUri("/api/v3/user/status") → 获取最新状态
4.   从响应中提取 SecurityOauthToken, RefreshToken, ExpireTime
5.   if 新 token 存在:
6.     WriteQuotaCache + SaveUserInfo + UpdateOrgInfo
```

### fetchAuthStatusWithUri (0x141a1f260) — WhitelistStatus 枚举

| 值 | 长度 | 含义 |
|---|---|---|
| PASS | 4 | 通过 |
| FAIL | 4 | 失败 |
| Pending | 7 | 待审核 |
| ApproveDisabled | 14 | 审批被禁 |
| ApproveExpired | 11 | 审批过期 |
| NoLicense | 9 | 无许可证 |
| NoAllow | 7 | 不允许 |
| NoAll | 6 | 全部禁止 |

## 所有 v3 user/ 端点（IDA 确认）

| 端点 | 字符串地址 | 调用函数 |
|---|---|---|
| `/api/v3/user/login` | 0x1424d2ff0 | `performUserLogAction` (遥测) |
| `/api/v3/user/logout` | 0x1424d6c12 | `performUserLogAction` (遥测) |
| `/api/v3/user/status` | 0x1424d6c4b | `fetchAuthStatusWithUri` |
| `/api/v3/user/region` | 0x1424d6c5e | 仅注册 |
| `/api/v3/user/remoteToken` | 0x1424e986e | 仅注册 (SSE) |
| `/api/v3/user/data_region` | 0x1424e9916 | 仅注册 |
| `/api/v3/user/refresh_token` | 0x1424f16f6 | `doRefreshToken` |
| `/api/v3/user/grantAuthInfos` | 0x1424f6301 | `GetGrantAuthInfosWrap` |
| `/api/v3/user/oauth2/deviceToken/poll` | 0x14251e630 | 仅注册 |

## 实现文件

- `lingma_token_refresh.py` — 增强诊断版（requests + diagnose + variants 命令）
- `lingma_v3_api.py` — v3 SIGN 模式客户端 + COSY 凭据本地生成
- `lingma_oauth_complete.py` — OAuth 登录流程
