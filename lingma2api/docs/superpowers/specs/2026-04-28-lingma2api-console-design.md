# Lingma2API 管理控制台设计文档

> **目标：** 为 lingma2api 添加嵌入式前端管理控制台，提供仪表盘、请求日志、账号管理、模型管理、设置等完整管理功能。

> **架构：** React + TypeScript + Vite 构建前端 SPA，通过 `embed.FS` 嵌入 Go 二进制；SQLite 持久化日志/映射/设置数据；Hash Router 实现多页面路由；Recharts 提供图表支持。

> **技术栈：** Go 1.24 + SQLite (modernc.org/sqlite) / React 18 + TypeScript + Vite + React Router (hash) + Recharts

---

## 1. 整体架构

```
lingma2api/
├── main.go                          # 入口，embed 前端静态文件
├── config.yaml                      # 服务配置
├── internal/
│   ├── api/
│   │   ├── server.go                # 扩展：注册前端 SPA + 管理 API
│   │   └── admin_handlers.go        # 新增：仪表盘/日志/映射/Settings/导出 API
│   ├── db/                          # 新增：数据库层
│   │   ├── store.go                 # SQLite 初始化 + 连接管理
│   │   ├── migrations.go            # 建表 DDL
│   │   ├── logs.go                  # 请求日志 CRUD + 导出
│   │   ├── mappings.go              # 模型映射规则 CRUD
│   │   └── stats.go                 # 统计聚合查询
│   ├── middleware/
│   │   └── logging.go               # 新增：HTTP 中间件，拦截记录请求日志
│   ├── proxy/                       # 已有，不变
│   ├── auth/                        # 已有，不变
│   └── config/                      # 已有，不变
├── frontend/                        # 新增：React 项目
│   ├── package.json
│   ├── vite.config.ts
│   ├── tsconfig.json
│   ├── index.html
│   └── src/
│       ├── main.tsx
│       ├── App.tsx                  # 路由 + 布局 + AdminToken 守卫
│       ├── api/client.ts            # 后端 API 调用封装（fetch + admin token）
│       ├── pages/
│       │   ├── Dashboard.tsx        # 仪表盘
│       │   ├── Logs.tsx             # 请求日志列表
│       │   ├── LogDetail.tsx        # 日志详情
│       │   ├── Account.tsx          # 账号管理
│       │   ├── Models.tsx           # 模型管理 + 映射规则
│       │   └── Settings.tsx         # 设置
│       ├── components/
│       │   ├── Layout.tsx           # 侧边导航 + 顶部栏 + 底部状态栏
│       │   ├── StatCard.tsx         # 仪表盘概览卡片
│       │   ├── TokenChart.tsx       # Token 趋势图 (Recharts)
│       │   ├── SuccessRateChart.tsx # 成功率图 (Recharts)
│       │   ├── ModelPieChart.tsx    # 模型分布饼图 (Recharts)
│       │   ├── CodeViewer.tsx       # JSON 语法高亮查看器
│       │   ├── MappingRuleEditor.tsx# 模型映射规则编辑弹窗
│       │   ├── ReplayModal.tsx      # 请求重发编辑弹窗
│       │   └── Pagination.tsx       # 分页控件
│       ├── hooks/
│       │   ├── useAdminToken.ts     # Admin Token 状态管理
│       │   ├── usePolling.ts        # 自动轮询 hook
│       │   └── useSettings.ts       # 设置状态 hook
│       ├── types/
│       │   └── index.ts             # TypeScript 类型定义
│       └── styles/
│           ├── global.css           # 全局样式 + CSS 变量（主题色）
│           └── code-viewer.css      # JSON 高亮样式
├── frontend-dist/                   # Vite 构建输出 → embed.FS 目标
└── auth/
```

**构建流程：**
```
frontend/  -- Vite build --> frontend-dist/  -- Go embed.FS --> lingma2api.exe
```

**路由设计（Hash Router）：**
```
#/dashboard         → 仪表盘
#/logs              → 请求日志列表
#/logs/:id          → 日志详情
#/account           → 账号管理
#/models            → 模型管理
#/settings          → 设置
```

**Go 服务统一端口（`config.yaml` 中配置，默认 127.0.0.1:8080）：**
- `GET /` — 前端 SPA（`embed.FS` 返回 index.html，Hash Router 处理路由）
- `/v1/chat/completions` — Chat API（已有）
- `/v1/models` — 模型列表（已有）
- `/admin/*` — 管理 API（已有 + 扩展）

---

## 2. 数据库设计

### 2.1 请求日志表 `request_logs`

```sql
CREATE TABLE request_logs (
    id           TEXT PRIMARY KEY,          -- UUID
    created_at   DATETIME NOT NULL,
    session_id   TEXT DEFAULT '',
    model        TEXT NOT NULL,             -- 下游请求的模型名
    mapped_model TEXT NOT NULL,             -- 映射后实际使用的模型
    stream       INTEGER NOT NULL DEFAULT 0,
    status       TEXT NOT NULL,             -- 'success' | 'error'
    error_msg    TEXT DEFAULT '',

    -- 下游（客户端 → lingma2api）
    downstream_method TEXT NOT NULL,
    downstream_path   TEXT NOT NULL,
    downstream_req    TEXT NOT NULL,        -- 请求体 JSON
    downstream_resp   TEXT NOT NULL,        -- 响应体 JSON

    -- 上游（lingma2api → Lingma 远端）
    upstream_req      TEXT NOT NULL,        -- 转换后的请求体
    upstream_resp     TEXT NOT NULL,        -- 原始 SSE 行拼接
    upstream_status   INTEGER NOT NULL,     -- HTTP 状态码

    -- 指标
    prompt_tokens     INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    total_tokens      INTEGER NOT NULL DEFAULT 0,
    ttft_ms           INTEGER NOT NULL DEFAULT 0,  -- 首字延迟
    upstream_ms       INTEGER NOT NULL DEFAULT 0,  -- 上游总耗时
    downstream_ms     INTEGER NOT NULL DEFAULT 0   -- 下游总耗时
);

CREATE INDEX idx_logs_created ON request_logs(created_at DESC);
CREATE INDEX idx_logs_model   ON request_logs(model);
CREATE INDEX idx_logs_status  ON request_logs(status);
```

- **数据方向**：从 Lingma 视角，上游 = Lingma 远端，下游 = 客户端
- **Token 计数**：优先从 Lingma 响应 `usage` 字段提取，无则用 `字符数/4` 估算
- **存储模式**：按设置页的配置（完整/摘要），摘要时截断至配置的长度
- **过期策略**：按设置页的时间配置自动清理（如 7 天/30 天），支持手动触发

### 2.2 模型映射规则表 `model_mappings`

```sql
CREATE TABLE model_mappings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    priority    INTEGER NOT NULL DEFAULT 0,  -- 优先级，越小越高
    name        TEXT NOT NULL,
    pattern     TEXT NOT NULL,               -- 正则表达式（RE2）
    target      TEXT NOT NULL,               -- 目标模型
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  DATETIME NOT NULL,
    updated_at  DATETIME NOT NULL
);
```

### 2.3 设置表 `settings`

```sql
CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
```

预置键值：
| key | 默认值 | 说明 |
|---|---|---|
| `storage_mode` | `full` | 响应体存储模式：`full` / `truncated` |
| `truncate_length` | `102400` | 截断长度（字节），默认 100KB |
| `retention_days` | `30` | 日志保留天数 |
| `polling_interval` | `0` | 仪表盘自动刷新间隔（秒），0=关闭 |
| `theme` | `light` | 主题：`light` / `dark` |
| `request_timeout` | `90` | 请求超时（秒） |

---

## 3. 管理 API 设计

所有 `/admin/*` 端点均受 `X-Admin-Token` 头校验（当 AdminToken 配置非空时）。

### 3.1 仪表盘

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/admin/dashboard?range=24h` | 返回聚合统计 JSON |

响应结构：
```json
{
  "stats": {
    "total_requests": 12345,
    "success_rate": 98.5,
    "avg_ttft_ms": 234,
    "total_tokens": 1200000
  },
  "success_rate_series": [{"time": "2026-04-28T00:00:00Z", "rate": 99.1}, ...],
  "token_series": [{"time": "2026-04-28T00:00:00Z", "prompt": 500, "completion": 200}, ...],
  "model_distribution": [{"model": "lingma-gpt4", "count": 5000}, ...]
}
```

- `range` 参数：`1h` / `24h` / `7d` / `30d`
- 聚合粒度：根据 range 自动调整（1h→1min, 24h→1h, 7d→6h, 30d→1d）

### 3.2 请求日志

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/admin/logs?page=1&limit=50&status=&model=&from=&to=` | 分页日志列表 |
| `GET` | `/admin/logs/:id` | 单条日志详情（含完整请求/响应体） |
| `POST` | `/admin/logs/:id/replay` | 请求重发，body 为可选的修改后请求体 |
| `POST` | `/admin/logs/cleanup` | 手动触发过期日志清理 |
| `GET` | `/admin/logs/export?from=&to=&format=json` | 导出日志为 JSON/CSV |

响应 `GET /admin/logs` 结构：
```json
{
  "items": [
    {
      "id": "req-abc",
      "created_at": "2026-04-28T14:32:15Z",
      "model": "gpt-4o",
      "mapped_model": "lingma-gpt4",
      "status": "success",
      "prompt_tokens": 500,
      "completion_tokens": 200,
      "total_tokens": 700,
      "ttft_ms": 180,
      "upstream_ms": 2300,
      "downstream_ms": 2500
    }
  ],
  "total": 12345,
  "page": 1,
  "limit": 50
}
```

日志详情 `GET /admin/logs/:id` 额外包含：
```json
{
  "downstream_req": "...",
  "downstream_resp": "...",
  "upstream_req": "...",
  "upstream_resp": "...",
  "upstream_status": 200,
  "error_msg": "",
  "session_id": "s1"
}
```

重发 `POST /admin/logs/:id/replay`：
```json
// Request body（可选，不传则使用原请求体）
{
  "model": "gpt-4o",
  "messages": [{"role": "user", "content": "hello"}],
  "stream": true
}
// Response: 同 /v1/chat/completions 的流式或非流式响应
```

### 3.3 账号管理

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/admin/account` | 账号信息 + 凭据状态 + Token 用量 |
| `POST` | `/admin/account/refresh` | 触发 OAuth 凭据刷新 |

### 3.4 模型映射

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/admin/mappings` | 映射规则列表（按 priority 排序） |
| `POST` | `/admin/mappings` | 创建规则 |
| `PUT` | `/admin/mappings/:id` | 更新规则 |
| `DELETE` | `/admin/mappings/:id` | 删除规则 |
| `POST` | `/admin/mappings/test` | 测试正则（body: `{"model": "gpt-4o-mini"}`，返回映射结果和目标） |

### 3.5 设置

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/admin/settings` | 获取所有设置（键值对） |
| `PUT` | `/admin/settings` | 批量更新设置 |

### 3.6 数据导出

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/admin/logs/export?from=&to=&format=json` | 导出请求日志 |
| `GET` | `/admin/stats/export?range=24h&format=json` | 导出统计数据 |

---

## 4. 前端页面设计

### 4.1 整体布局

```
┌──────────────────────────────────────────────┐
│  lingma2api Console          🌙/☀️  ⚙️ 设置  │  ← 顶部栏
├──────────┬───────────────────────────────────┤
│  📊 仪表盘│                                    │
│  📋 日志  │        内容区 (Hash Router)          │
│  👤 账号  │                                    │
│  🤖 模型  │                                    │
│  ⚙️  设置  │                                    │
│          │                                    │
├──────────┴───────────────────────────────────┤
│  v1.0.0  · 运行时间: 3d 12h                    │  ← 底部状态栏
└──────────────────────────────────────────────┘
```

- **顶部栏**：标题 + 深色/浅色切换按钮 + 快捷设置入口
- **侧边栏**（约 200px 宽）：5 个导航项 + 底部凭据状态指示灯（🟢 OK / 🔴 ERR）
- **内容区**：Hash Router 渲染，宽度自适应
- **底部状态栏**：版本号 + 服务运行时间
- **深色/浅色主题**：CSS 变量实现，body 切换 `data-theme` 属性

### 4.2 仪表盘 (Dashboard)

- **4 个概览卡片**：总请求数、成功率（含环比箭头）、平均 TTFT、Token 消耗
- **成功率趋势图**：Recharts LineChart，X 轴时间，Y 轴百分比
- **Token 趋势图**：Recharts BarChart + LineChart 双轴，prompt 和 completion 分色堆叠
- **模型分布饼图**：Recharts PieChart
- **控制栏**：时间范围下拉（1h/24h/7d/30d）+ 刷新按钮 + 自动轮询指示器
- **数据流**：初次加载 → `GET /admin/dashboard?range=24h`，轮询间隔从 Settings hook 读取

### 4.3 请求日志列表 (Logs)

- **筛选栏**：状态下拉（全部/成功/失败）、模型下拉、时间范围、搜索框
- **表格列**：时间 | 模型（下游→映射） | 状态 | TTFT | Token 数 | 操作按钮
- **操作按钮**：👁 查看详情 → 跳转 `#/logs/:id`，↩️ 重发 → 弹出 ReplayModal
- **分页**：`Pagination` 组件，page/limit 参数
- **导出按钮**：`GET /admin/logs/export`，触发浏览器下载
- **数据流**：`GET /admin/logs?page=&limit=&status=&model=&from=&to=`

### 4.4 日志详情 (LogDetail)

- **返回按钮** → `#/logs`
- **概览区**：时间、状态、模型路径、Session ID、三阶段耗时、Token 数
- **四选项卡**：下游请求 | 上游请求 | 上游响应 | 下游响应
- **CodeViewer 组件**：JSON 语法高亮（纯 CSS 实现，不引入重量级编辑器）
- **操作按钮**：📋 复制到剪贴板、↩️ 重发（弹出 ReplayModal 预填请求体）
- **数据流**：`GET /admin/logs/:id`

### 4.5 账号管理 (Account)

- **用户信息卡片**：UserID、MachineID、CosyKey 掩码显示
- **凭据状态卡片**：状态指示灯、加载时间、EncryptUserInfo 掩码
- **Token 用量卡片**：今日/本周/总计的 Token 消耗
- **刷新按钮**：触发 `POST /admin/account/refresh`

### 4.6 模型管理 (Models)

- **可用模型区**：标签云展示从 Lingma 同步的模型列表（已有 `GET /v1/models`）
- **同步按钮**：触发模型列表刷新
- **映射规则表格**：优先级（可拖拽调整）| 名称 | 源匹配正则 | 目标模型 | 启用开关 | 操作（编辑/删除）
- **新增/编辑**：弹出 MappingRuleEditor 弹窗，包含 pattern（正则）、target、name
- **映射测试**：输入框 → 实时预览匹配结果，调用 `POST /admin/mappings/test`
- **数据流**：
  - 列表：`GET /admin/mappings`
  - CRUD：`POST/PUT/DELETE /admin/mappings[/:id]`
  - 测试：`POST /admin/mappings/test`

### 4.7 设置 (Settings)

- **存储**：响应体存储模式（完整/摘要下拉）+ 截断长度输入框 + 日志保留天数下拉
- **仪表盘**：自动刷新间隔下拉（关闭/10s/30s/60s）
- **外观**：主题下拉（浅色/深色）
- **超时**：请求超时秒数输入框
- **安全**：Admin Token 输入框（显示掩码）+ 变更按钮
- **数据**：导出请求日志按钮、导出统计数据按钮、清理过期日志按钮
- **数据流**：`GET /admin/settings` 加载，`PUT /admin/settings` 保存

### 4.7 ReplayModal（请求重发弹窗）

- 可编辑的 JSON 文本框（下游请求体）
- Stream 开关
- 发送后显示响应（流式实时展示或非流式一次性展示）
- 重发产生的请求**自动记录为新日志条目**

### 4.8 Admin Token 守卫

- 首次访问时弹出输入框，输入 token 后存入 `localStorage`
- 后续请求自动在请求头携带 `X-Admin-Token`
- 设置页可修改/清除
- 如果后端 AdminToken 为空，跳过校验，无需输入

---

## 5. 请求日志中间件

### 5.1 拦截点

在 `server.go` 的 `handleChatCompletions` 中，通过包装 `http.ResponseWriter` 来捕获：
- 下游请求体（已解码的 `OpenAIChatRequest`）
- 上游请求体（`RemoteChatRequest` 的 BodyJSON）
- 上游响应（SSE 流，通过 `io.TeeReader` 或缓冲捕获）
- 下游响应（包装 `ResponseWriter` 捕获写入的 body 和状态码）

### 5.2 指标计算

- **Token 计数**：优先从 Lingma 响应体中提取 `usage` 字段；无则用 `len(text)/4` 估算
- **TTFT**：从发送上游请求到收到第一个非空 SSE chunk 的时间差
- **upstream_ms**：上游请求往返总时间
- **downstream_ms**：下游请求处理总时间

### 5.3 存储时机

请求完成后异步写入 SQLite（不阻塞响应），存储模式按当前 setting 决定。

---

## 6. 前端鉴权流程

```
用户打开页面
    ↓
检查 localStorage 是否有 admin_token
    ↓ 有
携带 X-Admin-Token 请求 /admin/status
    ↓
成功 → 进入正常页面
失败 → 弹出 token 输入框
    ↓ 无（localStorage 为空）
弹出 token 输入框
    ↓
用户输入 token → 存入 localStorage → 重新验证
```

如果后端 `AdminToken` 配置为空，跳过所有鉴权步骤。

---

## 7. 非功能需求

- **构建产物大小**：前端 JS/CSS 压缩后控制在 500KB 以内（含 Recharts）
- **数据库体积**：10000 条日志 + 摘要模式 + SQLite 控制在 50MB 以内
- **性能**：仪表盘聚合查询在 2s 内完成（10000 条日志规模）
- **浏览器兼容**：Chrome/Firefox/Edge 最新两个版本
- **日志清理**：后台 goroutine 每 10 分钟执行一次过期日志清理

---

## 8. 不包含的功能（明确的 YAGNI 排除）

- 工具调用的前端可视化/执行（前端只做 Chat）
- 多账号管理（先单账号）
- 用户登录/SSO（仅 Admin Token）
- 移动端适配
- 国际化（i18n）
- 实时 WebSocket 推送（用轮询替代）
- 请求日志的搜索全文检索（仅 SQL LIKE）
