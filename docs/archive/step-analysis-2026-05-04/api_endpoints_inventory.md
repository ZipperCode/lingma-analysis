# Lingma API Endpoints Inventory

通过IDA Pro MCP搜索发现的完整API endpoint列表

## 搜索统计

- `/api/v1/v2/v3` 系列：100个
- `/algo/api` 系列：2个
- `/ncqs/api` 系列：3个
- `/telemetry/api` 系列：1个
- `/auth` 系列：30个
- `/ws/websocket` 系列：30个
- `/mcp` 系列：21个

**总计：约187个API endpoint**

## 分类整理

### 1. 用户认证相关 (User Auth)

| Endpoint | 版本 | 功能推测 |
|----------|------|----------|
| `/api/v3/user/login` | v3 | 用户登录 |
| `/api/v3/user/logout` | v3 | 用户登出 |
| `/api/v3/user/status` | v3 | 用户状态查询 |
| `/api/v3/user/region` | v3 | 用户区域查询 |
| `/api/v3/user/refresh_token` | v3 | Token刷新（已分析） |
| `/api/v3/user/remoteToken` | v3 | 远程Token |
| `/api/v3/user/data_region` | v3 | 数据区域 |
| `/api/v3/user/grantAuthInfos` | v3 | 授权信息 |
| `/api/v3/user/oauth2/deviceToken/poll` | v3 | OAuth2设备Token轮询 |
| `/api/v2/user/plan` | v2 | 用户计划 |
| `/api/v2/user/customLoginAuth` | v2 | 自定义登录认证 |
| `/auth/start` | - | 认证开始 |
| `/auth/callback` | - | 认证回调 |
| `/auth/loginWithOrganization` | - | 组织登录 |

### 2. 模型服务相关 (Model Service)

| Endpoint | 版本 | 功能推测 |
|----------|------|----------|
| `/api/v2/model/list` | v2 | 模型列表 |
| `/api/v2/service/queryCode` | v2 | 代码查询 |
| `/api/v2/service/embedding` | v2 | Embedding服务 |
| `/api/v2/service/pro/%s/%s` | v2 | Pro服务（动态路径） |
| `/api/v2/service/pro/rerank` | v2 | Rerank服务 |
| `/api/v2/service/ask/finish` | v2 | Ask完成 |
| `/api/v2/service/ask/queue/status` | v2 | Ask队列状态 |
| `/api/v2/service/wiki/queue` | v2 | Wiki队列 |
| `/api/v2/service/wiki/quota` | v2 | Wiki配额 |
| `/api/v2/service/wiki/finish` | v2 | Wiki完成 |
| `/api/v2/service/wiki/quota/deduct` | v2 | Wiki配额扣减 |
| `/api/v2/service/agent/quota` | v2 | Agent配额 |
| `/api/v2/service/queryDocExt` | v2 | 文档扩展查询 |
| `/api/v2/service/queryKBList` | v2 | KB列表查询 |
| `/api/v2/service/refineQuery` | v2 | 查询优化 |
| `/api/v2/service/business/finish` | v2 | Business完成 |
| `/api/v2/service/region/endpoints` | v2 | 区域端点 |
| `/api/v2/service/invoke/choose_model` | v2 | 模型选择 |
| `/api/v2/service/pro/invoke/choose_model` | v2 | Pro模型选择 |
| `/api/v1/service/next_edit_predict` | v1 | 下一编辑预测 |
| `/api/v3/service/region/endpoints` | v3 | 区域端点 |

### 3. Codebase相关

| Endpoint | 版本 | 功能推测 |
|----------|------|----------|
| `/api/v2/service/codebase/ping` | v2 | Codebase ping |
| `/api/v2/service/codebase/embedding` | v2 | Codebase embedding |
| `/api/v2/service/codebase/embedding_k2` | v2 | Codebase embedding K2 |
| `/api/v2/service/codebase/sync/startSync` | v2 | 开始同步 |
| `/api/v2/service/codebase/sync/endSync` | v2 | 结束同步 |
| `/api/v2/service/codebase/sync/refreshLock` | v2 | 刷新锁 |
| `/api/v2/service/codebase/sync/initCodebase` | v2 | 初始化Codebase |
| `/api/v2/service/codebase/sync/getMerkleNode` | v2 | 获取Merkle节点 |
| `/api/v2/service/codebase/file/upload` | v2 | 文件上传 |
| `/api/v2/service/codebase/file/getChunks` | v2 | 获取块 |
| `/api/v2/service/codebase/file/checkStatus` | v2 | 检查状态 |
| `/api/v2/service/codebase/file/checkStatusV2` | v2 | 检查状态V2 |
| `/api/v2/service/codebase/file/bfDiscover` | v2 | BF发现 |
| `/api/v2/service/codebase/operation/getBundle` | v2 | 获取Bundle |

### 4. Remote Agent相关

| Endpoint | 版本 | 功能推测 |
|----------|------|----------|
| `/api/v2/remoteAgent/qoder` | v2 | Qoder远程Agent |
| `/api/v2/remoteAgent/qoder/tasks` | v2 | 任务列表 |
| `/api/v2/remoteAgent/qoder/tasks/%s` | v2 | 单个任务 |
| `/api/v2/remoteAgent/qoder/tasks/%s/status` | v2 | 任务状态 |
| `/api/v2/remoteAgent/qoder/tasks/%s/cancel` | v2 | 取消任务 |
| `/api/v2/remoteAgent/qoder/tasks/%s/resume` | v2 | 恢复任务 |
| `/api/v2/remoteAgent/qoder/tasks/%s/design` | v2 | 任务设计 |
| `/api/v2/remoteAgent/qoder/tasks/%s/reports` | v2 | 任务报告 |
| `/api/v2/remoteAgent/qoder/tasks/%s/messages` | v2 | 任务消息 |
| `/api/v2/remoteAgent/qoder/tasks/%s/executions` | v2 | 任务执行 |
| `/api/v2/remoteAgent/qoder/quotas` | v2 | Quotas |
| `/api/v2/remoteAgent/qoder/workspaces/allocate` | v2 | 工作空间分配 |
| `/api/v2/remoteAgent/qoder/sessions/%s/records` | v2 | 会话记录 |
| `/api/v2/remoteAgent/qoder/tasks/user-stats` | v2 | 用户统计 |
| `%s/api/v1/agent/message` | v1 | Agent消息 |
| `%s/api/v1/agent/activate` | v1 | Agent激活 |
| `%s/api/v1/agent/heartbeat` | v1 | Agent心跳 |
| `%s/api/v1/agent/deactivate` | v1 | Agent停用 |

### 5. 配置相关 (Config)

| Endpoint | 版本 | 功能推测 |
|----------|------|----------|
| `/api/v2/config/getDataPolicy` | v2 | 获取数据策略 |
| `/api/v2/config/updateDataPolicy` | v2 | 更新数据策略 |
| `/api/v2/byok/check` | v2 | BYOK检查 |
| `/api/v2/byok/config` | v2 | BYOK配置 |
| `/api/v1/server/version` | v1 | 服务器版本 |

### 6. 文件/图片相关 (File/Image)

| Endpoint | 版本 | 功能推测 |
|----------|------|----------|
| `/api/v2/image/upload` | v2 | 图片上传 |
| `/api/v2/image/upload?request_id=` | v2 | 图片上传（带请求ID） |
| `/api/v2/file/diagnose/upload` | v2 | 诊断文件上传 |
| `/api/v2/file/diagnose/upload?request_id=` | v2 | 诊断文件上传（带请求ID） |

### 7. 扩展/插件相关 (Extension)

| Endpoint | 版本 | 功能推测 |
|----------|------|----------|
| `/api/v1/extension/vm/download` | v1 | VM扩展下载 |
| `/api/v1/extension/vm/download?os_type=` | v1 | VM扩展下载（指定OS） |
| `/api/v2/extension/config/pull` | v2 | 扩展配置拉取 |
| `/api/v2/extension/script/download` | v2 | 扩展脚本下载 |
| `/api/v2/extension/script/download?ext_id=` | v2 | 扩展脚本下载（指定扩展ID） |

### 8. 组织相关 (Organization)

| Endpoint | 版本 | 功能推测 |
|----------|------|----------|
| `/algo/api/v1/organizations` | algo/v1 | 组织列表 |
| `/api/v1/organizations/%s/tags` | v1 | 组织标签 |
| `/api/v1/organizations/%s/knowledgePolicy` | v1 | 知识策略 |
| `/api/v1/organizations/%s/knowledgeItems/batch` | v1 | 知识项批量操作 |

### 9. 配额相关 (Quota)

| Endpoint | 版本 | 功能推测 |
|----------|------|----------|
| `/ncqs/api/v1/quotas` | ncqs/v1 | 配额列表 |
| `/ncqs/api/v1/quotas/%s` | ncqs/v1 | 单个配额 |
| `/ncqs/api/v1/quotas/%s/instances` | ncqs/v1 | 配额实例 |
| `/api/v2/quota/usage` | v2 | 配额使用 |

### 10. MCP相关 (MCP)

| Endpoint | 版本 | 功能推测 |
|----------|------|----------|
| `/api/v1/mcp/modelscope/server/search` | v1 | ModelScope服务器搜索 |
| `/api/v1/mcp/modelscope/server/recommend` | v1 | ModelScope服务器推荐 |
| `/api/v1/mcp/modelscope/server/info?serverId=%s` | v1 | ModelScope服务器信息 |

### 11. WebSearch相关

| Endpoint | 版本 | 功能推测 |
|----------|------|----------|
| `/api/v1/webSearch/oneSearch` | v1 | 单次搜索 |
| `/api/v1/webSearch/unifiedSearch` | v1 | 统一搜索 |

### 12. 工具调用相关 (Tools)

| Endpoint | 版本 | 功能推测 |
|----------|------|----------|
| `/api/v1/tools/call` | v1 | 工具调用 |

### 13. 反馈/心跳相关 (Feedback/Heartbeat)

| Endpoint | 版本 | 功能推测 |
|----------|------|----------|
| `/api/v1/heartbeat` | v1 | 心跳 |
| `/api/v1/tracking` | v1 | 跟踪 |
| `/api/v2/feedback/dislike` | v2 | 反馈不喜欢 |
| `/telemetry/api/v1/heartbeat` | telemetry/v1 | 遥测心跳 |

### 14. WebSocket相关

| Endpoint | 版本 | 功能推测 |
|----------|------|----------|
| `/ws` | - | WebSocket连接（本地端口） |
| `task/websocketEndpoint` | - | WebSocket端点配置 |

### 15. 其他API

| Endpoint | 版本 | 功能推测 |
|----------|------|----------|
| `/api/v1/ping` | v1 | Ping测试 |
| `/algo/api/v1/ping` | algo/v1 | Algo Ping |

## 特殊模式发现

### 动态路径参数
- `%s/api/v1/agent/*` - Agent相关API（前缀动态）
- `/api/v2/service/pro/%s/%s` - Pro服务（双重动态参数）
- `/api/v2/remoteAgent/qoder/tasks/%s/*` - 任务相关（任务ID动态）

### Query参数
- `?request_id=` - 请求ID追踪
- `?os_type=` - 操作系统类型
- `?ext_id=` - 扩展ID
- `?FetchKeys=%s` - 获取密钥
- `?serverId=%s` - 服务器ID
- `?state=` - 状态参数

## 下一步分析计划

1. **核心认证API**：
   - `/api/v3/user/login` - 登录流程
   - `/api/v3/user/refresh_token` - Token刷新（已完成部分分析）
   - `/auth/*` - OAuth认证流程

2. **核心服务API**：
   - `/api/v2/service/*` - 主要服务接口
   - `/api/v2/model/list` - 模型列表
   - `/api/v2/service/codebase/*` - Codebase服务

3. **Remote Agent API**：
   - `/api/v2/remoteAgent/qoder/*` - 远程Agent完整流程

4. **MCP API**：
   - `/api/v1/mcp/*` - MCP服务器交互

## IDA分析统计

- **字符串搜索工具**：`find_regex`
- **搜索模式**：7种正则模式
- **搜索深度**：覆盖v1/v2/v3/algo/ncqs/telemetry/auth/ws/mcp
- **发现总数**：约187个API endpoint

---

**备注**：此列表基于IDA静态字符串搜索，实际可用API数量可能更多。后续需要通过动态运行和Frida监控验证完整API列表。