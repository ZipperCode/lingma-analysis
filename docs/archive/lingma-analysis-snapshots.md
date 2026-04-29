> 归档说明：本文件保留原始逐轮快照、动态探测和审核收敛时间线，不再作为日常阅读入口。
>
> 日常查阅建议优先阅读：
>
> - 总览入口：`../lingma-analysis-overview.md`
> - 本地服务 / endpoint / 签名边界：`../lingma-analysis-endpoint-auth.md`
> - token / 登录态 / 模型刷新：`../lingma-analysis-token-flow.md`

# Lingma 分析快照归档

更新时间：2026-04-24

## 目标

- 确认 `plugin` 与 `~/.lingma` 本地服务的职责边界
- 找出大模型请求从 IDE 到远端的真实调用链
- 识别“复用已有 token，绕过 plugin，直接用 API 访问”的可落地入口
- 在分析过程中持续记录证据快照、阶段结论和剩余问题

## 当前结论快照

### 快照 1

- `plugin` 主要负责采集 IDE 上下文、构造本地 RPC 参数、接收流式回推并更新 UI。
- 真正的模型请求构造、endpoint 路由、鉴权头拼装、远端 HTTP 调用在 `~/.lingma/bin/.../Lingma` 本地服务中。
- 插件到本地服务走 `ws://127.0.0.1:<port>` 的 JSON-RPC/LSP，不是插件直接请求远端模型接口。

### 快照 2

- 已复核到本地服务真实发起过远端 HTTP/SSE 请求，目标地址为 `https://lingma.alibabacloud.com/algo/api/v2/service/pro/sse/llm_completion_stream?FetchKeys=&Encode=1`。
- 因此“plugin 只是转发层，本地服务才是远端请求执行主体”不再只是推断，而是运行时日志可证实的结论。
- 当前最大缺口不在 token 是否存在，而在本地服务如何从用户态票据推导出最终请求头、endpoint 与请求体。

### 快照 3

- `plugin -> ~/.lingma` 的主链路已经明确：`BaseChatPanel/InlineChatPanel` 组装 `ChatAskParam`，`CosyServiceImpl` 维护 `requestId` 状态映射，`LanguageWebSocketService` 通过本地 `chat/ask` 发给 `~/.lingma`。
- 本地服务再通过 `chat/answer`、`chat/think`、`chat/finish`、`tool/invoke`、`tool/call/sync` 回推给 plugin；plugin 负责 UI 分发和少量本地工具执行。
- 因此对“直接 API 访问”而言，`plugin` 可绕过，但 `~/.lingma` 本地服务当前还不能直接绕过。

### 快照 4

- 二进制里已经不止有 `addBigModelAuthorizationHeaders`，还明确出现了 `addBigModelSignatureHeaders`，说明远端请求至少分“授权头构造”和“签名头构造”两层。
- 二进制还出现了这些运行期文案：
  - `User token refreshed successfully, securityOauthToken: %s, refreshToken: %s, tokenExpireTime: %d`
  - `User info already synced for uid: %s, securityOauthToken: %s, refreshToken: %s, tokenExpireTime: %d, skip duplicate sync`
  - `SyncUserInfo{... SecurityOauthToken ... RefreshToken ... TokenExpireTime ...}`
- 这意味着 `securityOauthToken` 会进入本地服务用户态管理与刷新逻辑，但是否直接映射为最终远端 `Authorization` 仍未坐实。

### 快照 5

- 请求体也不再是纯黑盒。二进制中已直接出现这些字段命中：
  - `json:"messages"`
  - `json:"max_tokens"`
  - `json:"temperature"`
  - `json:"tool_calls,omitempty"`
  - `json:"function_call,omitempty"`
  - `json:"response_format,omitempty"`
  - `json:"reasoning_tokens"`
  - `json:"completion_tokens"`
- 同时还出现了：
  - `/chat/completions`
  - `llm_completion_stream`
  - `openali chatMessages: %s`
  - `openali failed to marshal chatMessages to JSON: %w`
- 当前更合理的判断是：Lingma 本地服务内部的模型请求体大概率采用 OpenAI-compatible `messages` 结构，只是在外层再补 endpoint 路由、签名头和鉴权头。

### 快照 6

- `Authorization` 的具体值仍未还原，但二进制里已出现明确模板：`Bearer COSY.%s.%s`。
- 当前最合理的高层猜测是：`Authorization` 不是直接塞 `securityOauthToken`，而是某种 `COSY.<opaque-part>.<opaque-part>` 形式的派生凭证。
- `~/.lingma/cache/user` 不是明文 JSON，而是“base64 文本包裹的二进制内容”；解码后也没有直接出现 `securityOauthToken`、`refreshToken`、`Authorization` 等键名。
- `machine_token.json` 里的 `token` 也不是 JWT，而是另一类 opaque token，且与 `Cosy-MachineId` / `Cosy-MachineToken` 命中串一起出现，说明机器态凭证单独存在。
- 这进一步支持：最终 `Authorization` 很可能不是浏览器回调票据原样透传，而是本地服务在“用户态 + 机器态 + 签名态”三层信息上再构造出的结果。

### 快照 7

- `callback.html` 顶层已经拿到 `securityOauthToken + refreshToken + expireTime`，但 `authStatus.token` 仍为空，说明页面暴露的是“安全票据形态”，不是已经标准化后的 `token` 结构。
- 浏览器最终跳回本地 `http://127.0.0.1:37510/auth/callback` 时，query 参数是 `state + auth + token` 编码载荷，不是明文 bearer。
- `Lingma` 二进制同时注册了两套 typed handler：
  - `securityOauthToken/refreshToken/tokenExpireTime -> success/uid/name/tokenExpireTime`
  - `token/refreshToken/expiresIn/expireTime/userId/username -> success/errorCode/errorMsg`
- 当前更稳的判断是：`securityOauthToken` 会先进入 `auth/syncUserInfo` 写入或更新本地用户态，后续续期链则落在标准 `token` 结构的 `auth/refreshToken`；但“标准 token 是否就是远端模型请求使用的 Authorization”仍未坐实。

### 快照 8

- `machine_token.json` 当前只有三项：`token`、`type`、`updateAt`；其中：
  - `token` 长度为 `88`
  - `type` 长度为 `18`
- 二进制里同时出现 `Bearer COSY.%s.%s`，而机器 token 恰好也是两段可直接拼装的字符串，这使“Authorization 至少部分吸收 machine token 信息”成为更强的结构性怀疑。
- 但当前仍不能直接下结论说 `Authorization = Bearer COSY.<type>.<token>`，因为：
  - 二进制还同时存在 `getAppSalt`
  - 还存在 `addBigModelSignatureHeaders`
  - 用户态缓存 `~/.lingma/cache/user` 解码后并无明文 token 痕迹
- 因此当前最稳的判断是：
  - `Authorization` 很可能是 `COSY` 前缀的运行时组合值
  - 机器态信息大概率参与
  - 用户态/签名态也大概率参与
  - 但还没法确认每一段占位的精确来源

### 快照 9

- 当前运行中的 `Lingma` 进程额外监听了三个本地入口：
  - `37010`: 主 websocket 通道
  - `37510`: 本地 HTTP/callback server
  - `38510`: `profile websocket channel`
- 日志已明确写出：
  - `Using http server: 37510`
  - `Using profile websocket channel: 38510`
  - `Communication servers ready - WebSocket: 37010, HTTP: 37510, IPC: ...`
- 动态探测结果：
  - `http://127.0.0.1:37510/auth/callback` 返回登录页 HTML，证明它是 callback/http server
  - `http://127.0.0.1:38510/ws` 返回 `illegal websocket request`，证明 `38510` 不是普通 HTTP，而是本地 websocket 型 profile 通道
  - `/debug/pprof/` 和 `/debug/vars` 在这两个端口上都不是公开入口，统一 404
- 这意味着：
  - 内置 profiling/trace 确实存在
  - 但默认不会通过普通 HTTP 暴露调试页
  - 如果要继续动态抓更细内容，最有价值的入口已经从“HTTP 探测”收敛到“38510 的 websocket profile channel”

### 快照 10

- `38510` 的 profile 通道并不是“任意 websocket 客户端都能连”的开放入口。
- 二进制里带的 web UI 脚本明确写了连接形式：
  - `window.profile_websocket_port='{PROFILE_WEBSOCKET_PORT}'`
  - `ws://localhost:<profile_websocket_port>/ws?state=${to.state}`
  - 连上后会发 `webview/ws/ping`
- 我已用原始 socket 做了两次最小只读 websocket upgrade：
  - `/ws`
  - `/ws?state=test`
- 两次都被本地服务返回 `illegal websocket request`，并且日志里留下了 `illegal websocket request has been denied`。
- 这说明：
  - `38510` 确实是 websocket 型 profile 通道
  - 但 `state` 不是任意值，至少还存在服务端校验
  - 如果继续动态探测，下一步必须先还原 profile 页生成的有效 `state`

### 快照 11

- `37510` 上不仅有 `/auth/callback`，还存在 `/profile` 页面入口。
- 但直接通过 HTTP 拉取 `/profile` 得到的是“未填充占位符的模板页”，例如：
  - `window.profile_websocket_port='{PROFILE_WEBSOCKET_PORT}'`
  - 页面中并没有直接给出有效 `state`
- 这说明 profile 页很可能不是靠单纯 HTTP 请求完成最终渲染，而是还要经过 plugin/webview 侧的数据注入或后续 websocket update。
- 因此当前关于 `38510` 的最稳判断是：
  - 通道真实存在
  - profile 页也真实存在
  - 但 raw HTTP 访问拿不到可直接复用的连接参数
  - 有效 `state` 仍需从 plugin/webview 渲染链继续协议研究

### 快照 12

- `profile` 页的模板占位符本身就在 `Lingma` 本地服务二进制里，而不是在 plugin JAR 里单独维护。
- 二进制里同时出现：
  - `{PROFILE_WEBSOCKET_PORT}`
  - `webview/profile/update/renderPage`
  - `new profile page render success`
  - `faied to get webview saved params`
  - `Failed to obtain webview saved params and the workspace path`
- 日志中 `new profile page render success` 后紧跟：
  - `Request has no connection specified, may not be able to respond`
  - `0 client has received the message`
- 这说明 profile 页并不是简单静态文件，而是本地服务里一条“读取 saved params/workspace -> 渲染模板 -> 试图通过连接推送 renderPage”的链路。
- 当前更合理的判断是：
  - profile 页最终参数注入更偏向 `Lingma` 本地服务自己的 webview/render 管线
  - plugin 更像只是这个页面的宿主或消息接收者，不是占位符替换主体

### 快照 13

- `37510/profile` 本身也不是“无参即可得到成品页”的静态入口。
- 日志中已经出现多次：
  - `missing request url parameters`
  - `profile request url parameters`
- 这与动态探测现象吻合：
  - 直接访问 `/profile` 只能拿到带占位符的模板页
  - 而 profile 前端 bundle 自己又会从 `window.location.search` 读取参数，再拼 `ws://localhost:<profile_websocket_port>/ws?state=...`
- 当前更稳的判断是：
  - `/profile` 至少依赖一组 URL query 参数
  - 有效 `state` 也属于这组参数链的一部分
  - 缺这些参数时，服务端不会渲染出可直接使用的 profile 页
- 因而当前最值得追的点已经从“找 profile 页”切换成“找 profile 请求 URL 参数的生成位置”

### 快照 14

- `state` 现在已经可以高置信地看成“服务端持有的一次性状态值”，而不是普通展示参数。
- 新增证据包括：
  - `state don't exist in param`
  - `state don't match: saved state (%s) != param state (%s)`
  - `Invalid login nonce`
  - `cosy/core/api/auth/login/generate_nonce.go`
- 这与登录 callback 链已经确认的 `state = nonce` 机制高度同构。
- 当前最合理的高置信判断是：
  - `/profile` 所需的 `state` 很可能就是本地服务内部保存的一份 nonce/state
  - profile websocket 的 `state` 校验机制与登录回调的 `nonce/state` 校验属于同一个设计族
- 但还未坐实“profile state”和“login nonce”是否共用同一份存储或生成器

### 快照 15

- plugin 侧打开 profile 页的真正入口已经坐实：
  - `LingmaToolWindowPanel.openProfilePage()`
  - `LingmaToolWindowPanel.initProfilePage()`
  - `LingmaToolWindowPanel.getProfilerUrl()`
- 这里不是直接写死 `/profile` URL，而是：
  1. plugin 先构造 `GetProfileUrlParams`
  2. 再通过 `Cosy.INSTANCE.getLanguageService(project).getProfileUrl(params)` 发给本地服务
  3. 本地服务返回 `GetProfileUrlResult.url`
  4. JCEF 或外部浏览器再去加载这个完整 URL
- `GetProfileUrlParams` 已确认只包含：
  - IDE 主题颜色
  - locale
  - ideType
  - product
  - memoryId
  - mcpListView
- 也就是说：
  - profile 页真正需要的 `state`、`PROFILE_WEBSOCKET_PORT` 等关键参数并不是 plugin 自己拼出来的
  - 这些参数一定在 `Lingma` 本地服务里生成并注入到返回的 URL 中
- 因而当前最关键的未解点再次收敛成：
  - 本地服务的 `auth/profile/getUrl` handler 是如何生成这个 URL 的

### 快照 16

- `auth/profile/getUrl` 的方向已经进一步明确：
  - plugin 调用它时，并不会传入 `state`、`profile_websocket_port` 这类关键参数
  - plugin 只传“页面展示/环境”类字段
  - 返回值则只有一个完整 `url`
- 已确认的 plugin 入参字段包括：
  - 主题颜色：`fontColor`、`fontColorGray`、`bg`、`activeBg`、`selectBg`、`cardBg`
  - 边框/滚动条：`focusBorder`、`scrollbarBg`、`scrollbarThumbBg`、`widgetBorder`、`widgetShadow`
  - 页面展示：`tooltipBgColor`、`tooltipBorderColor`、`tooltipFontColor`、`popupBgColor`、`popupBorderColor`
  - 环境：`locale`、`ideType`、`product`
  - 业务：`memoryId`、`mcpListView`
- 因此当前可以高置信确认：
  - `/profile` 真正需要的 query 参数是在 `Lingma` 本地服务里生成的
  - `state`/`PROFILE_WEBSOCKET_PORT` 并不来自 plugin 的显式入参
  - `auth/profile/getUrl` 是当前整条 profile 链的单一关键服务端入口

### 快照 17

- profile 前端 bundle 已能确认它实际消费的 URL query 参数集合，而不是“任意参数都可能有用”。
- 从前端 bundle 中围绕 `var to = ce(window.location.search)` 的消费点，当前能确认这些 `to.xxx` 参数被读取：
  - `activeBg`
  - `bg`
  - `locale`
  - `mcpListView`
  - `memoryId`
  - `scrollbarBg`
  - `scrollbarThumbBg`
  - `state`
- 其中：
  - `memoryId` 决定是否打开 Memory 视图
  - `mcpListView` 决定是否打开 MCP 视图
  - `bg/activeBg/scrollbar*` 等用于页面主题
  - `state` 用于连接 `38510` 的 profile websocket
- 这意味着：
  - `auth/profile/getUrl` 返回的 URL 至少要覆盖这组 query 参数
  - plugin 本地构造的 `GetProfileUrlParams` 只覆盖了其中一部分
  - 剩余部分尤其是 `state` 必然由服务端补齐

### 快照 18

- 真实的 `reload profiler url:` 样本已经从 IDEA 日志中取到，可以直接观察 `auth/profile/getUrl` 的输出结果。
- 当前样本的 `/profile?...` 实际 URL query key 集合为：
  - `activeBg`
  - `bg`
  - `buttonBg`
  - `buttonHoverBg`
  - `buttonTextColor`
  - `cardBg`
  - `dividerColor`
  - `editorBackground`
  - `focusBorder`
  - `fontColor`
  - `fontColorGray`
  - `fontSize`
  - `inputBg`
  - `locale`
  - `mcpListView`
  - `mcpMarketView`
  - `memoryId`
  - `popupBgColor`
  - `popupBorderColor`
  - `scrollbarBg`
  - `scrollbarThumbBg`
  - `selectBg`
  - `state`
  - `tabColor`
  - `textLinkColor`
  - `themeColor`
  - `tooltipBgColor`
  - `tooltipBorderColor`
  - `tooltipFontColor`
  - `widgetBorder`
  - `widgetShadow`
- 与 plugin `GetProfileUrlParams` 对账后，可得：
  - plugin 明确传入且最终出现在 URL 里的字段：
    - `activeBg`
    - `bg`
    - `memoryId`
    - `locale`
    - 以及大部分颜色/展示参数
  - 服务端额外新增或改名后才出现在 URL 里的字段：
    - `state`：服务端新增
    - `mcpMarketView`：服务端新增
    - `fontSize`：服务端新增或补默认空值
    - `buttonHoverBg`：更像由 plugin 的 `buttonHoverColor` 映射/改名而来
  - plugin 传了但 URL 里未出现的字段：
    - `ideType`
    - `product`
- 因此当前最稳结论是：
  - `auth/profile/getUrl` 不只是“透传 plugin 参数”
  - 它至少做了：
    - 参数筛选
    - 参数补默认值
    - 字段名改写
    - 插入服务端生成的 `state`
    - 插入 `mcpMarketView` 这类 plugin 未显式传入字段
    - `ideType/product` 更可能不走 URL，而走页面模板注入或后续 websocket 更新

### 快照 19

- 真实的 `reload profiler url:` 样本已经足够证明 `auth/profile/getUrl` 的输出形状，而不是只停留在静态字段推断。
- 现有 IDEA 2025.1 日志样本显示，服务端返回的 URL 形如：
  - `http://127.0.0.1:37510/profile?...&state=<32位hex>...`
- 从这些真实样本可以直接确认：
  - `state` 一定在最终 URL query 中
  - `mcpMarketView` 会出现在最终 URL query 中，即使 plugin 本地 params 里没有这个字段
  - `fontSize` 也会出现在最终 URL query 中，即使 plugin 本地 params 里没有显式设置
  - `buttonHoverColor` 在最终 URL 中表现为 `buttonHoverBg`
  - `ideType`、`product` 不出现在最终 URL query 中
- 另外一个有价值的历史对比是：
  - 2024.3 的旧样本里，URL query 更短，主要只有 `state + fontColor + fontColorGray + cardBg + bg + locale`
  - 2025.1 的新样本里，URL query 明显扩展，包含更多主题和页面控制字段
- 这说明：
  - `auth/profile/getUrl` 的输出逻辑是版本演进过的
  - `state` 在多个版本样本中都稳定存在，属于真正的核心字段，而不是偶然附带字段

### 快照 20

- profile 页的业务子页切换能力在 plugin 入口上已经明确存在：
  - `openProfilePage(null, false)`：普通 profile 页
  - `openProfilePage(memoryId, false)`：Memory 详情页入口
  - `openProfilePage(null, true)`：MCP 视图入口
- 这对应到 plugin 传给 `auth/profile/getUrl` 的两个业务字段：
  - `memoryId`
  - `mcpListView`
- 前端 bundle 也已确认会消费：
  - `to.memoryId`
  - `to.mcpListView`
- 但当前手头的 `reload profiler url:` 日志样本中：
  - `memoryId` 始终为空
  - `mcpListView` 目前也都是空值
- 因此当前能确认的是：
  - 这两个业务入口真实存在
  - 服务端最终 URL 也为它们保留了 query 字段
  - 只是我们还没有抓到触发 Memory/MCP 子页时的真实 URL 样本

## 主代理审核后的阶段结论

### 结论 1：plugin 只是本地 RPC 转发层，不是远端模型请求执行层

- 主聊天和 Inline Chat 都会先构造 `ChatAskParam`。
- `CosyServiceImpl.chatAsk()` 做的是 `requestId -> project/sessionType` 等状态映射维护。
- `LanguageWebSocketService.chatAsk()` 调的是本地 JSON-RPC `chat/ask`，不是远端模型 HTTP。
- plugin 侧真正的本地逻辑主要是 UI、重试、超时、登录态检查、以及 `tool/invoke` 的 IDE 工具执行。

### 结论 2：远端模型调用由 `~/.lingma` 本地服务负责

- 运行时日志已证明本地服务向 `https://lingma.alibabacloud.com/algo/api/v2/service/pro/sse/llm_completion_stream?FetchKeys=&Encode=1` 发起过请求。
- 二进制中同时出现 `openaiclient.(*Client).CreateChat`、`anthropicclient.(*Client).CreateCompletion`，说明本地服务内置模型适配层。
- endpoint 不是固定常量，而是本地服务按 region / route 规则计算。
- 请求头也由本地服务统一构造，至少包含 `Authorization` 与 `Cosy-*` 头体系。

### 结论 3：已有 token 只能证明“登录态可用”，还不足以直接复现远端 API 调用

- `callback.html` 明确给出了 `securityOauthToken`、`refreshToken`、`expireTime`。
- 但浏览器最终跳到本地 `/auth/callback` 时，传给本地服务的是 `state/auth/token` 编码载荷，不是直接把 Bearer token 交给 plugin。
- 本地服务内部同时存在两套票据结构：
  - `securityOauthToken/refreshToken/tokenExpireTime`
  - `token/refreshToken/expiresIn/expireTime/userId/username`
- 这说明远端请求前大概率还要经过 `auth/syncUserInfo`、`auth/refreshToken` 之类的同步或换票过程。
- 新增证据表明本地服务内部至少实现了：
  - 用户信息去重同步
  - token 刷新成功路径
  - `SyncUserInfo` 结构化状态输出
- 但仍未拿到“刷新后标准 token 如何进入远端请求头”的明确映射。

### 结论 4：当前对“直接 API 访问”的可行性判断是“部分可行”

- 可行部分：
  - 可以绕过 plugin。
  - 已掌握登录态核心输入票据。
- 暂不可直接落地的部分：
  - 还没还原 `securityOauthToken -> 最终 Authorization` 的映射规则。
  - 还没还原 `Cosy-Key/Cosy-Date/Cosy-User` 的签名生成算法。
  - 虽然已经看到 `messages/max_tokens/temperature/tool_calls/response_format` 这类字段，但还没拿到完整请求体组装规则与模型选择字段。
  - 还没还原 refresh / sync 的真实 HTTP 调用契约。
  - 还没确认 `Bearer COSY.%s.%s` 两个占位分别来自用户态、机器态、签名态中的哪一层。
  - 还没确认 `machine_token.json` 的 `type/token` 是否直接进入 `Authorization`，还是仅作为其中一部分输入。

### 当前最小缺口清单

- endpoint 路由规则
- token 同步 / 换票 / 续期规则
- `Cosy-*` 签名头算法
- 远端请求体字段的完整组装规则
- 标准 token 与最终 `Authorization` 头的精确映射关系
- `Bearer COSY.%s.%s` 两段 opaque 值的来源
- `38510` profile websocket channel 的协议与可观测内容
- profile websocket 所需 `state` 的生成/校验规则
- `/profile` 页面的参数注入链
- `webview saved params` 的存储位置与读取逻辑
- `/profile` 请求 URL 参数的生成位置
- `profile state` 与 `login nonce` 的关系
- `auth/profile/getUrl` 的服务端 URL 生成逻辑
- `auth/profile/getUrl` 的 typed request/response 结构
- `/profile` 前端实际消费的 query 参数集合
- `auth/profile/getUrl` 输出 URL 的真实字段集合
- `auth/profile/getUrl` 的真实 URL 样本
- Memory/MCP 子页入口字段的现有观测边界

### 下一轮分析建议

- 直接聚焦 `Lingma` 二进制中的这条链：
  - `auth/syncUserInfo`
  - `auth/refreshToken`
  - `addBigModelSignatureHeaders`
  - `addBigModelAuthorizationHeaders`
  - `/chat/completions` 或 `llm_completion_stream`
- 目标不是再证明“本地服务会发请求”，而是把“最小可复现请求”抠到字段级。

## 本轮新增证据

- `strings ~/.lingma/bin/2.11.1/aarch64_darwin/Lingma` 命中：
  - `cosy/remoting.addBigModelSignatureHeaders`
  - `User token refreshed successfully, securityOauthToken: %s, refreshToken: %s, tokenExpireTime: %d`
  - `User info already synced for uid: %s, securityOauthToken: %s, refreshToken: %s, tokenExpireTime: %d, skip duplicate sync`
  - `SyncUserInfo{Status: %d, ... SecurityOauthToken: %q, RefreshToken: %q, TokenExpireTime: %d, ...}`
  - `Failed to refresh token: %v`
  - `renew token response invalid`
  - `invalid tokenExpireTime`
  - `json:"messages"`
  - `json:"max_tokens"`
  - `json:"temperature"`
  - `json:"tool_calls,omitempty"`
  - `json:"function_call,omitempty"`
  - `json:"response_format,omitempty"`
  - `json:"reasoning_tokens"`
  - `json:"completion_tokens"`
  - `/chat/completions`
  - `llm_completion_stream`
  - `openali chatMessages: %s`
  - `openali failed to marshal chatMessages to JSON: %w`
  - `Bearer COSY.%s.%s`
  - `Using profile websocket channel: %d`
  - `Profile server quit`
  - `failed to get port for profile server, skip it`
  - `/debug/pprof/`
  - `window.profile_websocket_port='{PROFILE_WEBSOCKET_PORT}'`
  - `ws://localhost:".concat(window.profile_websocket_port||e,"/ws?state=").concat(to.state)`
  - `webview/ws/ping`
  - `webview/profile/update/renderPage`
  - `new profile page render success`
  - `faied to get webview saved params`
  - `Failed to obtain webview saved params and the workspace path`
  - `missing request url parameters`
  - `profile request url parameters`

这些命中进一步支持：

- 本地服务确实实现了完整的用户态同步/续期链。
- 签名头构造与授权头构造是分开的。
- 请求体核心很像 OpenAI-compatible schema。
- `Authorization` 很可能是本地派生出来的 `COSY` 格式凭证，而不是页面 token 原样透传。
- 但仅凭 `securityOauthToken` 还不足以直接重放远端模型请求。

## 本轮动态探测

- `ps eww -p 36481` 显示当前进程为 `/Users/Zipper/.lingma/bin/2.11.1/aarch64_darwin/Lingma start`，未显式设置 `COSY_TRACE_LOG`、`COSY_LOCAL_DEV`、`COSY_PROFILING` 等环境变量。
- `lsof` 已确认当前本地监听：
  - `127.0.0.1:37010`
  - `127.0.0.1:37510`
  - `127.0.0.1:38510`
- 日志锚点：
  - `~/.Trash/lingma.log:20143` `Using http server: 37510`
  - `~/.Trash/lingma.log:20144` `Using profile websocket channel: 38510`
  - `~/.Trash/lingma.log:20146` `Communication servers ready - WebSocket: 37010, HTTP: 37510, IPC: ...`
- 只读 HTTP 探测结果：
  - `http://127.0.0.1:37510/auth/callback` -> `200 OK`，返回 Lingma 登录页 HTML
  - `http://127.0.0.1:37510/profile` -> `200 OK`，返回 profile 模板页 HTML
  - `http://127.0.0.1:38510/ws` -> `200 OK`，返回 `illegal websocket request`
  - `http://127.0.0.1:37510/debug/pprof/` -> `404`
  - `http://127.0.0.1:38510/debug/pprof/` -> `404`
- 只读 websocket 握手结果：
  - 对 `ws://127.0.0.1:38510/ws`
  - 对 `ws://127.0.0.1:38510/ws?state=test`
  - 两次最小 upgrade 都返回明文 `illegal websocket request`
  - 对应日志新增：
    - `~/.Trash/lingma.log:381373`
    - `~/.Trash/lingma.log:381428`
    - `~/.Trash/lingma.log:381716`
- `http://127.0.0.1:37510/profile` 页面中可见未替换占位符：
  - `window.profile_websocket_port='{PROFILE_WEBSOCKET_PORT}'`
  - 说明 raw HTTP 拉到的是模板，不是最终注入后的 webview 页面
- profile 渲染相关日志：
  - `~/.Trash/lingma.log:343748` `new profile page render success`
  - `~/.Trash/lingma.log:343749` `Request has no connection specified, may not be able to respond`
  - `~/.Trash/lingma.log:343750` `0 client has received the message`
- profile URL 参数相关日志：
  - `~/.Trash/lingma.log:382420` `missing request url parameters`
  - `~/.Trash/lingma.log:382435` `missing request url parameters`
  - `~/.Trash/lingma.log:385866` `missing request url parameters`
- state 校验相关证据：
  - `~/.Trash/lingma.log:381372` `state don't exist in param`
  - `~/.Trash/lingma.log:381427` `state don't exist in param`
  - `~/.Trash/lingma.log:386249` `state don't exist in param`
  - 二进制命中 `state don't match: saved state (%s) != param state (%s)`
  - 二进制命中 `cosy/core/api/auth/login/generate_nonce.go`
  - 登录链已有证据表明 callback `state` 本质就是 `nonce`
- plugin -> profile URL 正向调用链：
  - `/tmp/lingma_decomp/LingmaToolWindowPanel.java:813` `openProfilePage`
  - `/tmp/lingma_decomp/LingmaToolWindowPanel.java:838` `initProfilePage`
  - `/tmp/lingma_decomp/LingmaToolWindowPanel.java:870` `getProfilerUrl`
  - `/tmp/lingma_decomp/LingmaToolWindowPanel.java:876` `getGetProfileUrlParams`
  - `/tmp/lingma_decomp/LanguageWebSocketService.java:844` `getProfileUrl`
- 参数结构证据：
  - `GetProfileUrlParams` 只包含颜色、locale、ideType、product、memoryId、mcpListView 等字段
  - `GetProfileUrlResult` 只返回 `url`
  - 二进制字符串中已出现与 `GetProfileUrlParams` 对应的一组 JSON 字段：
    - `json:"fontColor"`
    - `json:"fontColorGray"`
    - `json:"locale"`
    - `json:"ideType"`
    - `json:"memoryId"`
    - `json:"mcpListView"`
    - `json:"tooltipBgColor"`
    - `json:"popupBorderColor"`
    - `json:"tooltipFontColor"`
    - `json:"scrollbarThumbBg"`
    - `json:"editorBackground"`
  - 二进制字符串中同时存在 `json:"url"` 与 `auth/profile/getUrl`
- 前端 bundle query 参数消费证据：
  - 围绕 `var to=ce(window.location.search)` 的代码已确认消费：
    - `to.activeBg`
    - `to.bg`
    - `to.locale`
    - `to.mcpListView`
    - `to.memoryId`
    - `to.scrollbarBg`
    - `to.scrollbarThumbBg`
    - `to.state`
- IDEA 日志里的真实 URL 样本：
  - `/Users/Zipper/Library/Logs/JetBrains/IdeaIC2025.1/idea.log:8033`
  - `/Users/Zipper/Library/Logs/JetBrains/IdeaIC2025.1/idea.log:8086`
  - `/Users/Zipper/Library/Logs/JetBrains/IdeaIC2025.1/idea.log:8266`
  - `/Users/Zipper/Library/Logs/JetBrains/IdeaIC2025.1/idea.log:8312`
  - `/Users/Zipper/Library/Logs/JetBrains/IdeaIC2025.1/idea.log:9893`
  - `/Users/Zipper/Library/Logs/JetBrains/IdeaIC2025.1/idea.log:10267`
  - `/Users/Zipper/Library/Logs/JetBrains/IdeaIC2025.1/idea.log:10298`
  - 旧版本对照样本：
    - `/Users/Zipper/Library/Logs/JetBrains/IdeaIC2024.3/idea.7.log:74908`
    - `/Users/Zipper/Library/Logs/JetBrains/IdeaIC2024.3/idea.5.log:7182`
    - `/Users/Zipper/Library/Logs/JetBrains/IdeaIC2024.3/idea.4.log:16839`
    - `/Users/Zipper/Library/Logs/JetBrains/IdeaIC2024.3/idea.8.log:5453`
- Memory/MCP 入口证据：
  - `/tmp/lingma_decomp/LingmaToolWindowPanel.java:805` `openMemoryRecordPage(String memoryId)`
  - `/tmp/lingma_decomp/LingmaToolWindowPanel.java:809` `openMcpTool()`
  - `/tmp/lingma_decomp/LingmaToolWindowPanel.java:876` `getGetProfileUrlParams(String memoryId, boolean openMcpView)`
  - 前端 bundle 已确认消费：
    - `to.memoryId`
    - `to.mcpListView`

## 任务 B：已有 token 到本地用户态 / 标准 token 的同步与续期链

### 审核结论

- 已确认本地服务存在两套不同的 token 数据结构，而不是单一 `securityOauthToken` 直通到底。
- 已确认 `auth/syncUserInfo` 的入参结构是 `securityOauthToken + refreshToken + tokenExpireTime`，更像“登录成功后的安全票据同步入本地用户态”。
- 已确认 `auth/refreshToken` 的入参结构是 `token + refreshToken + expiresIn + expireTime + userId + username`，更像“标准 token 结构上的续期”。
- 已确认 callback 页面对外暴露的是 `securityOauthToken + refreshToken + expireTime`，而不是 `authStatus.token`。
- 已确认浏览器回调给本地服务的是 `state/auth/token` 编码参数，不是直接把 `securityOauthToken` 明文塞进本地 callback。
- 已确认本地服务内部存在 `doSyncUserInfoForSave`、`doSyncUserInfoForUpdate`、`doRefreshToken`，并且有“重复同步跳过”和“刷新成功”的运行期文案。
- 因此当前最合理的链路是：浏览器回调载荷 -> 本地解析/交换 -> `securityOauthToken` 形态进入 `auth/syncUserInfo` -> 本地用户态保存/更新 -> 在另一套标准 token 结构上执行 `auth/refreshToken`。
- 但到目前为止，还不能确认 `securityOauthToken` 一定会先被换成标准 `token` 才能请求模型，也不能确认刷新后的标准 `token` 就是远端模型请求里的最终 `Authorization`。

### 证据快照

- `callback.html:50` 显示顶层 `window.user_info` 含 `securityOauthToken`、`refreshToken`、`expireTime`，同一结构内 `authStatus.token` 与 `authStatus.refreshToken` 为空。
- `login.har:155`、`login.har:167`、`login.har:215` 显示浏览器最终回跳到 `http://127.0.0.1:37510/auth/callback?state=...&auth=...&token=...`。
- `docs/lingma-analysis-token-flow.md` 已整理出 `auth/syncUserInfo` 的入参/返回结构，以及 `doSyncUserInfoForSave`、`doSyncUserInfoForUpdate`、`validateOauthTokens` 和缺参报错。
- `docs/lingma-analysis-token-flow.md` 已整理出 `auth/refreshToken` 对应的另一套标准 token 结构。
- `docs/lingma-analysis-endpoint-auth.md` 已独立确认两套 token 结构并存。
- `Lingma` 二进制命中：
  - `cosy/core/api/auth.doSyncUserInfoForSave`
  - `cosy/core/api/auth.doSyncUserInfoForUpdate`
  - `cosy/auth/user.doRefreshToken`
  - `cosy/core/api/auth.RefreshTokenHandler`
  - `missing required params: securityOauthToken, refreshToken`
  - `User token refreshed successfully, securityOauthToken: %s, refreshToken: %s, tokenExpireTime: %d`
  - `User info already synced for uid: %s, securityOauthToken: %s, refreshToken: %s, tokenExpireTime: %d, skip duplicate sync`
  - `SyncUserInfo{Status: %d, ... SecurityOauthToken: %q, RefreshToken: %q, TokenExpireTime: %d, ...}`

### 已确认与仍是推断

- 已确认：
  - `securityOauthToken` 会被本地服务消费，不只是页面展示字段。
  - 本地服务内存在 `syncUserInfo` 与 `refreshToken` 两条不同 handler。
  - 两条 handler 使用的入参结构不同。
  - 本地服务内部确实有同步保存、更新、续期这几类流程。
- 仍是推断：
  - callback 中的 `auth` 与 `token` 编码载荷在本地如何解码、各自职责是什么。
  - `securityOauthToken` 是否一定先换成标准 `token` 后才参与模型请求。
  - `auth/refreshToken` 产出的标准 token 是否直接进入远端模型请求头。
  - 是否还存在第三层临时票据、签名派生或换票逻辑。

## 关键证据

### Plugin -> Local Service

- `LanguageWebSocketService.createService()` 直接连接本地 `ws://127.0.0.1:<port>`，不是远端模型地址。
- `ChatService` 通过 `@JsonSegment("chat")` 暴露 `ask/replyRequest/stop/...` 等本地 JSON-RPC 方法。
- `BaseChatPanel` / `InlineChatPanel` 会先构造 `ChatAskParam`，再交给 `CosyServiceImpl.chatAsk()`。
- `CosyServiceImpl.chatAsk()` 主要做 `requestId -> project/sessionType` 映射维护，然后调用 `LanguageWebSocketService.chatAsk()`。
- `LanguageWebSocketService.chatAsk()` 最终调用的是 `server.getChatService().ask(params)`，即本地服务提供的 `chat/ask`。

证据锚点：

- `/tmp/lingma_decomp/LanguageWebSocketService.java:163`
- `/tmp/lingma_decomp/ChatService.java:23`
- `/tmp/lingma_decomp/BaseChatPanel.java:947`
- `/tmp/lingma_decomp/InlineChatPanel.java:1130`
- `/tmp/lingma_decomp/CosyServiceImpl.java:139`
- `/tmp/lingma_decomp/LanguageWebSocketService.java:300`

### Local Service -> Remote Model

- 现有日志中多次出现 `Remote model request parameters` 和 `Building remote model request`，说明远端模型请求由本地 `Lingma` 进程组装。
- 运行时日志已经出现对 `https://lingma.alibabacloud.com/algo/api/v2/service/pro/sse/llm_completion_stream?FetchKeys=&Encode=1` 的 `Post` 超时报错，这是本地服务发起远端 HTTP/SSE 的直接证据。
- 本地二进制字符串中可见 `openaiclient.(*Client).CreateChat`、`anthropicclient.(*Client).CreateCompletion`、`addBigModelAuthorizationHeaders`、`X-Model-Name`、`Authorization` 等符号，说明 endpoint 路由、鉴权头、模型适配层都在本地服务。
- 二进制中同时存在 `tool_calls`、`parallel_tool_calls`、`function_call`，说明模型适配层兼容工具调用 schema。

证据锚点：

- `/Users/Zipper/.Trash/lingma.log:8826`
- `/Users/Zipper/.Trash/lingma.log:8827`
- `/Users/Zipper/.Trash/lingma.log:370213`
- `/Users/Zipper/.Trash/lingma.log:370214`
- `../lingma-analysis-endpoint-auth.md`
- `../lingma-analysis-token-flow.md`

### Token / Auth / Model Refresh

- 当前 docs 已确认浏览器回调页拿到的是 `securityOauthToken + refreshToken + expireTime`。
- 已有协议研究笔记显示本地服务内部存在 `auth/syncUserInfo`、`auth/refreshToken`、`auth/report`、`config/refreshModels` 等链路。
- 登录成功后，本地服务会触发 endpoint/model refresh，再把用户态和模型态同步回 plugin。

证据锚点：

- `../lingma-analysis-token-flow.md`
- `../lingma-analysis-endpoint-auth.md`

### Direct API Reuse

- 当前只能确认“plugin 不是直连远端模型，核心远端调用在本地服务”。
- 但尚不能确认 `securityOauthToken` 是否就是远端 HTTP 可直接复用的 bearer token。
- 现阶段更保守的判断是：直接拿已有 token 手写 API 调用，暂时缺少“远端 endpoint + 头部签名/换票规则 + 请求体字段”的完整闭环证据。
- `callback.html` 中能直接看到顶层 `securityOauthToken`、`refreshToken`、`expireTime`，说明浏览器回调页确实拿到了可用票据。
- 但本地二进制同时出现了 `auth/syncUserInfo`、`auth/refreshToken`、`addBigModelAuthorizationHeaders`、`GetAuthorizationHeader`、`Authorization: %s`、`Cosy-Key`、`Cosy-Date`、`Cosy-User`，说明票据进入远端模型调用前仍有本地服务侧处理。

阶段判断：

- `plugin` 层绕过是可行的，因为它只是本地 RPC 转发层。
- `~/.lingma` 本地服务层是否也能绕过，当前证据还不够。

补充证据锚点：

- `/Users/Zipper/Github/lingma/callback.html`
- `/Users/Zipper/Github/lingma/login.har`
- `/Users/Zipper/.lingma/bin/2.11.1/aarch64_darwin/Lingma`

## 待确认问题

- 远端实际请求体是否可从日志、流量采集或本地二进制进一步还原到字段级
- `securityOauthToken` 与远端调用使用的 `Authorization` 之间是否存在二次换票
- 是否存在可直接复用的公开 endpoint，还是必须复用本地服务的签名/路由逻辑

## 2026-04-24 增量快照

### 快照 21

- `state` 的校验落点现在可以从“服务端某处保存”进一步收敛到 `WebViewAuth`。
- 新增日志证据：
  - `~/.Trash/lingma.log:381715`：`test don't exist in WebViewAuth`
  - `~/.Trash/lingma.log:381716`：`illegal websocket request has been denied`
  - `~/.Trash/lingma.log:386249`：`state don't exist in param`
  - `~/.Trash/lingma.log:386250`：`profile request url parameters`
- 这说明 profile websocket 的 `state` 校验不是前端自校验，而是 `Lingma` 本地服务在 `WebViewAuth` 上下文里做存在性检查后决定是否放行。
- 当前更稳的判断是：
  - `auth/profile/getUrl` 生成 URL 时，同时把 `state` 注册进 `WebViewAuth`
  - `/profile` 页再拿这个 `state` 去连 `38510/ws?state=...`
  - `38510` 通过 `WebViewAuth` 查验该 `state` 是否存在
- 仍未坐实的部分：
  - `WebViewAuth` 是纯内存 map、带 TTL 的 nonce 池，还是还会额外持久化
  - 是否还有“一次性消费 / 绑定连接 / 绑定 workspace”一类更强校验

### 快照 22

- plugin 除了请求 `auth/profile/getUrl` 之外，还会主动把当前 profile 展示参数回推给本地服务。
- 新增 plugin 侧证据：
  - `/tmp/lingma_decomp/LingmaToolWindowPanel.java:870-873`
  - `/tmp/lingma_decomp/LingmaToolWindowPanel.java:876-964`
  - `/tmp/lingma_decomp/LingmaToolWindowPanel.java:1077-1078`
- 已确认：
  - `getProfilerUrl()` 只是把 `GetProfileUrlParams` 交给 `Cosy.INSTANCE.getLanguageService(project).getProfileUrl(...)`
  - `GetProfileUrlParams` 仍然只有颜色、`locale`、`ideType`、`product`、`memoryId`、`mcpListView`
  - plugin 初始化工具窗时还会执行 `updateProfile(getGetProfileUrlParams(null, false))`
- 这与二进制中的这些命中形成闭环：
  - `faied to get webview saved params`
  - `Failed to obtain webview saved params and the workspace path`
  - `webview/profile/update/renderPage`
- 当前更合理的高置信判断是：
  - `auth/profile/update` 很可能就是“保存/刷新 webview saved params”的入口
  - `auth/profile/getUrl` 更像“生成首屏访问 URL + state”的入口
  - 两者配合后，本地服务才具备渲染 `/profile` 模板和后续 websocket 推送的上下文

### 快照 23

- `auth/profile/getUrl` 与 `auth/profile/update` 作为 JSON-RPC/LSP 方法名，现在已经从 JAR 常量池拿到直接证据，不再只是从代码结构还原调用链反推。
- 新增证据：
  - `javap -v lib/cosy-intellij-2.11.1.jar com.alibabacloud.intellij.cosy.core.lsp.model.LanguageServer`
  - 常量池直接出现：
    - `getProfileUrl`
    - `auth/profile/getUrl`
    - `updateProfile`
    - `auth/profile/update`
- 因此当前可以直接确认：
  - plugin 到本地服务的 profile 入口就是这两个方法
  - `LanguageWebSocketService.getProfileUrl(...)` / `updateProfile(...)` 只是本地 websocket client 的包装层
  - profile URL 的生成主体一定在 `~/.lingma/bin/.../Lingma`，而不在 plugin JAR

### 快照 24

- `state` 与 login nonce 属于同一设计族的判断，本轮又得到了一层结构性补强。
- 新增二进制证据：
  - `state don't match: saved state (%s) != param state (%s)`
  - `failed to generate nonce`
  - `Invalid login nonce or consumed, ignore`
  - `cosy/core/api/auth/login/generate_nonce.go`
  - `cosy/core/api/auth/login/auth_callback.go`
  - `cosy/core/api/auth/login/generate_url.go`
- 新增运行时对照证据：
  - `idea.log:8033` 与 `idea.log:8086` 在极短时间内得到两个不同的 `/profile?...&state=...`
  - 说明 `reload profiler url` 不只是返回固定 URL，`state` 很可能每次 reload 都重新生成
- 当前更稳的判断是：
  - profile `state` 大概率就是本地服务按 nonce/state 机制新生成并保存的一次性或短时态值
  - 但还不能直接写成“profile state 与 login nonce 共用同一生成器/存储”
  - 现阶段只能说它们极大概率属于同一套状态管理范式

## 2026-04-24 审核后收敛

- 现在已经可以把 profile 链路收敛成下面这条高置信路径：
  1. plugin 组装展示参数并调用 `auth/profile/update`，刷新本地服务保存的 webview 参数
  2. plugin 再调用 `auth/profile/getUrl`
  3. 本地服务生成完整 `/profile?...&state=...` URL，并把 `state` 注册到 `WebViewAuth`
  4. JCEF 加载 `37510/profile?...`
  5. 页面脚本从 query 里读取 `state`、颜色参数、`memoryId`、`mcpListView`
  6. 页面脚本用 `ws://localhost:<profile_websocket_port>/ws?state=...` 连 `38510`
  7. 本地服务按 `WebViewAuth` 校验 `state`
  8. 通过 `webview/profile/update/renderPage` 等消息继续驱动页面更新
- 这条链路里仍然没有直接源码级实现体的环节只有两处：
  - `auth/profile/getUrl` handler 如何拼最终 URL
  - `WebViewAuth` 内部如何保存、失效和消费 `state`

## 2026-04-24 下一轮最优先

- 继续只围绕 `auth/profile/getUrl` 与 `WebViewAuth/state` 两个点，不再扩散到其他支线。
- 最优先检索目标：
  - `Webview client %s registered`
  - `call auth webview method >> %s`
  - `webview/profile/update/renderPage`
  - `faied to get webview saved params`
  - `Failed to obtain webview saved params and the workspace path`
  - `state don't match: saved state (%s) != param state (%s)`
- 若服务仍在运行且允许只读动态探测，优先目标不再是盲连 `38510`，而是想办法拿到“当前进程生成的最新有效 profile URL 样本”，再观察它是否能触发不同于模板页的返回。

## 2026-04-24 第二轮增量快照

### 快照 25

- `LanguageWebSocketService.getProfileUrl(...)` 与 `updateProfile(...)` 的方法体已经拿到，不再只是接口常量级证据。
- 新增字节码证据：
  - `javap -c lib/cosy-intellij-2.11.1.jar com.alibabacloud.intellij.cosy.core.lsp.LanguageWebSocketService`
  - `getProfileUrl(...)` 的核心逻辑是：
    - 直接调用 `server.getProfileUrl(params)`
    - 等待 `CompletableFuture.get(10000ms)`
    - 结果解析为 `GetProfileUrlResult`
    - 只返回 `result.getUrl()`
  - `updateProfile(...)` 的核心逻辑是：
    - 直接调用 `server.updateProfile(params)`
    - 不等待返回值，属于 fire-and-forget
- 因而当前可以明确确认：
  - plugin 侧 `getProfileUrl` 没有额外本地补参逻辑
  - plugin 侧 `updateProfile` 也没有任何 `state`/`renderPage` 相关的本地处理
  - 这两个方法都只是本地 websocket client 对 `LanguageServer` 的薄包装

### 快照 26

- plugin 侧 JCEF/webview 链已经可以拆成两条完全独立的桥：
  - 出站桥：`auth/profile/getUrl` / `auth/profile/update`
  - 入站桥：页面 `window.postMessage(...) -> window.cefQuery(...) -> CefMessageRouterHandler.onQuery(...)`
- 新增证据：
  - `/tmp/lingma_decomp/LingmaToolWindowPanel.java:813-873`
  - `/tmp/lingma_decomp/LingmaToolWindowPanel.java:987-999`
  - `/tmp/lingma_decomp/LingmaToolWindowPanel.java:1061-1078`
  - `javap -c lib/cosy-intellij-2.11.1.jar com.alibabacloud.intellij.cosy.util.JCefUtil$3`
  - `javap -c lib/cosy-intellij-2.11.1.jar com.alibabacloud.intellij.cosy.handle.CefMessageRouterHandler`
- 已确认：
  - `reloadProfiler()` 会重新调用 `getProfilerUrl(null, false)` 并 `loadURL(url)`
  - `updateUiTexts()` 会调用 `updateProfile(getGetProfileUrlParams(null, false))`
  - `JCefUtil$3.onLoadEnd()` 会向页面注入：
    - `window.addEventListener('message', ...)`
    - 回调里调用 `window.cefQuery({ request: JSON.stringify(event.data) })`
  - `CefMessageRouterHandler.onQuery()` 只处理这些类型：
    - `MSG_BACK_TO_CHAT`
    - `MSG_TYPE_OPEN_MCP_CONFIG`
    - `MSG_TYPE_OPERATE_RULE_FILE`
    - `MSG_TYPE_FIX_MCP_ERROR`
    - `MSG_TYPE_EXPERIENCE_MCP_CASE`
    - `MSG_BACK_TO_SETTING`
    - `MSG_TYPE_OPEN_INDEX_IGNORE_CONFIG`
- 当前高置信结论：
  - plugin 侧 JCEF handler 只是一条“页面动作 -> IDE 本地能力”的入站桥
  - 它不参与 `state` 生成、`WebViewAuth` 校验、`renderPage` 推送
  - 因此 `state/WebViewAuth` 仍然完全在 `~/.lingma` 本地服务侧

### 快照 27

- `renderPage` 推送链现在可以进一步确认“不走普通 LSP client 广播”。
- 新增日志证据：
  - `~/.Trash/lingma.log:344583`：`Client 0x14008870330 is registered`
  - `~/.Trash/lingma.log:344584`：`active client count now 3`
  - `idea.log:8033`：plugin 收到 `reload profiler url:http://127.0.0.1:37510/profile?...&state=46b718657dd541539c927a85b200ca50...`
  - `idea.log:8035`：`end to reload profile in main panel`
  - `~/.Trash/lingma.log:344657`：`new profile page render success`
  - `~/.Trash/lingma.log:344658`：`Request has no connection specified, may not be able to respond`
  - `~/.Trash/lingma.log:344659`：`0 client has received the message`
  - `idea.log:8086`：同秒再次拿到新的 `/profile?...&state=451f81defe1d456380c7072ac4dddf84`
- 这些时序关系说明：
  - 普通 `Client 0x...` 注册后，profile render success 仍然会出现“无 connection / 0 client received”
  - 因此这里尝试投递的接收方并不是主 websocket/LSP 的普通 client 列表
  - 更合理的解释是：`new profile page render success` 之后，本地服务尝试向某个独立的 auth webview / profile webview 连接上下文推送
- 当前更稳的判断是：
  - `webview/profile/update/renderPage` 大概率就是这条推送链上的方法名
  - 只是当前日志没有把该方法名字面落地打印出来

### 快照 28

- `state` 校验失败现在已经能区分出三种不同层级，而不是单一失败分支。
- 已确认的失败类型：
  - 缺 `state`：
    - `~/.Trash/lingma.log:381372`
    - `~/.Trash/lingma.log:386249`
  - `state` 不在 `WebViewAuth`：
    - `~/.Trash/lingma.log:381715`：`test don't exist in WebViewAuth`
  - 缺整组 `/profile` URL 参数：
    - `~/.Trash/lingma.log:382420`
    - `~/.Trash/lingma.log:382435`
    - `~/.Trash/lingma.log:386250`
- 因而当前关于 `WebViewAuth/state` 的最佳收敛是：
  - `/profile` 不是只要有一个 `state` 就足够
  - profile websocket 也不是只检查 query 里有没有 `state`
  - 本地服务至少同时关心：
    - query 中是否带 `state`
    - 该 `state` 是否已登记在 `WebViewAuth`
    - `/profile` URL 参数集合是否完整

## 2026-04-24 第二轮审核后收敛

- 当前整个 profile 体系可以拆成三层职责：
  1. plugin 出站层：
     - `updateProfile(params)` 同步展示参数
     - `getProfileUrl(params)` 获取成品 URL
  2. local service 渲染与状态层：
     - 生成 `/profile?...&state=...`
     - 保存 `webview saved params`
     - 维护 `WebViewAuth`
     - 渲染 profile 页面
  3. webview/profile 通道层：
     - 页面读取 query 与模板变量
     - 页面连接 `38510/ws?state=...`
     - 本地服务向独立 webview 连接上下文推送 `renderPage` 一类更新
- 现在已经可以明确排除的一点是：
  - plugin 自己并没有任何 `state`/`WebViewAuth`/`renderPage` 实现逻辑
  - 它只是“拿 URL + 加载页面 + 注入 JS bridge + 接少量页面动作回调”

## 2026-04-24 第三轮增量快照

### 快照 29

- `GetProfileUrlParams` / `GetProfileUrlResult` / `UpdateProfileParams` 的类定义已经拿到，字段级对账可以再收紧一层。
- 新增证据：
  - `javap -p lib/cosy-intellij-2.11.1.jar com.alibabacloud.intellij.cosy.core.lsp.model.params.GetProfileUrlParams`
  - `javap -p lib/cosy-intellij-2.11.1.jar com.alibabacloud.intellij.cosy.core.lsp.model.params.GetProfileUrlResult`
  - `javap -p lib/cosy-intellij-2.11.1.jar com.alibabacloud.intellij.cosy.core.lsp.model.params.UpdateProfileParams`
- 已确认：
  - `GetProfileUrlResult` 只有一个字段：`url`
  - `GetProfileUrlParams` 只有这些与页面展示相关的字段：
    - `fontColor`
    - `fontColorGray`
    - `locale`
    - `ideType`
    - `cardBg`
    - `bg`
    - `activeBg`
    - `selectBg`
    - `memoryId`
    - `focusBorder`
    - `inputBg`
    - `scrollbarBg`
    - `scrollbarThumbBg`
    - `mcpListView`
    - `textLinkColor`
    - `widgetBorder`
    - `widgetShadow`
    - `dividerColor`
    - `tabColor`
    - `themeColor`
    - `buttonBg`
    - `buttonTextColor`
    - `buttonHoverColor`
    - `editorBackground`
    - `product`
    - `tooltipBgColor`
    - `tooltipBorderColor`
    - `popupBgColor`
    - `popupBorderColor`
    - `tooltipFontColor`
  - `UpdateProfileParams` 是一个更早、更小的参数类，只包含：
    - `fontColor`
    - `fontColorGray`
    - `locale`
    - `ideType`
    - `cardBg`
    - `bg`
  - 但当前 `LanguageServer.updateProfile(...)` 实际签名用的是 `GetProfileUrlParams`，不是 `UpdateProfileParams`
- 这带来两个很重要的收敛：
  - `fontSize`、`mcpMarketView` 根本不在 `GetProfileUrlParams` 类里，因此它们一定不是 plugin 传参“漏赋值”，而是本地服务后补字段
  - `buttonHoverBg` 也不在 `GetProfileUrlParams` 类里，类里只有 `buttonHoverColor`，所以最终 URL 中的 `buttonHoverBg` 基本可以确定是本地服务做了字段改名或归一化

### 快照 30

- profile reload 与登录态变化的关系现在也有了更直接的 plugin 侧证据。
- 新增证据：
  - `/tmp/lingma_decomp/LingmaToolWindowPanel.java:518-537`
  - `/tmp/lingma_decomp/LingmaToolWindowPanel.java:356-377`
- 已确认：
  - `delayInit()` 会订阅 `LingmaProfilerReloadNotifier.PROFILER_RELOAD_NOTIFIER_TOPIC`
  - `changeLoginState(...)` 结束时无条件调用 `reloadProfiler()`
  - `reloadProfiler()` 会重新调用 `getProfilerUrl(null, false)` 并重新 `loadURL`
- 这说明：
  - profile URL 的刷新不只是手动打开 profile 页时触发
  - 登录态变化、语言/UI 文本刷新、以及 profiler reload topic，都可能再次触发 `auth/profile/getUrl`
  - 这也与 `idea.log` 中同一时间窗口内多次拿到不同 `state` 的现象一致

## 2026-04-24 第三轮审核后收敛

- 关于 `auth/profile/getUrl` 的输出字段，当前已经可以分成三类：
  1. plugin 明确传入且类定义存在：
     - 如 `bg`、`activeBg`、`memoryId`、`mcpListView`、`buttonHoverColor`
  2. 类定义存在但当前 plugin 代码未设置：
     - 当前未发现新的高价值例子
  3. 类定义里根本不存在、只能由本地服务补齐或改名：
     - `state`
     - `fontSize`
     - `mcpMarketView`
     - `buttonHoverBg`
- 因而现在对 `auth/profile/getUrl` 的最佳描述已经不是“透传 + 少量补参”，而是：
  - 一个真正的服务端 URL 组装入口
  - 它至少负责：
    - 注入 `state`
    - 注入 `fontSize`
    - 注入 `mcpMarketView`
    - 把 `buttonHoverColor` 归一化为 `buttonHoverBg`
    - 结合 `updateProfile` 已保存的参数生成最终成品 URL

## 2026-04-24 第四轮增量快照

### 快照 31

- `UpdateProfileParams` 很可能是旧模型残留，当前 profile 主链实际统一使用的是 `GetProfileUrlParams`。
- 新增证据：
  - `javap -p lib/cosy-intellij-2.11.1.jar com.alibabacloud.intellij.cosy.core.lsp.model.params.UpdateProfileParams`
  - `javap -v lib/cosy-intellij-2.11.1.jar com.alibabacloud.intellij.cosy.core.lsp.model.LanguageServer`
  - `javap -c lib/cosy-intellij-2.11.1.jar com.alibabacloud.intellij.cosy.core.lsp.LanguageWebSocketService`
- 已确认：
  - `UpdateProfileParams` 只含 6 个字段：`fontColor/fontColorGray/locale/ideType/cardBg/bg`
  - 但 `LanguageServer.updateProfile(...)` 的真实签名用的是 `GetProfileUrlParams`
  - `LanguageWebSocketService.updateProfile(...)` 也直接把 `GetProfileUrlParams` 传给 `server.updateProfile(...)`
- 当前更合理的判断是：
  - `UpdateProfileParams` 更像历史遗留类型
  - 当前 profile 体系已经统一到 `GetProfileUrlParams`
  - 因此 `updateProfile` 与 `getProfileUrl` 使用的是同一套展示参数模型，只是用途不同

### 快照 32

- `profile` webview 通道在二进制里不只有 `renderPage`，还至少暴露了一组同簇方法名与保活痕迹。
- 新增二进制证据：
  - `webview client %s: received ping`
  - `webview/profile/update/dataPolicy`
  - `webview/profile/update/renderPage`
  - `call auth webview method >> %s`
- 这些字符串位于同一段方法名/日志簇附近，而这附近还同时出现：
  - `faied to get webview saved params`
  - `missing request url parameters`
  - `profile request url parameters`
  - `Update profile data failed: %v`
- 当前更稳的判断是：
  - profile webview 通道至少支持：
    - ping/pong 或等价保活
    - renderPage 更新
    - dataPolicy 更新
  - `auth/profile/update` 不一定直接等于 `webview/profile/update/renderPage`
  - 更可能是：
    - `auth/profile/update` 先更新本地服务保存态
    - 本地服务再按需要调用 `webview/profile/update/renderPage` 或 `webview/profile/update/dataPolicy`

### 快照 33

- profile 页打开的不同入口现在也有了明确的 plugin 侧证据，不再只是从 query 参数名字反推。
- 新增证据：
  - `/tmp/lingma_decomp/LingmaToolWindowPanel.java:735-740`
  - `/tmp/lingma_decomp/LingmaToolWindowPanel.java:805-810`
  - `/tmp/lingma_decomp/LingmaToolWindowPanel.java:813-842`
- 已确认：
  - 点击 profile 菜单时走 `openProfilePage(null, false)`
  - 打开 memory 记录页时走 `openProfilePage(memoryId, false)`
  - 打开 MCP 工具页时走 `openProfilePage(null, true)`
  - 三者最终都会进入同一个 `getProfilerUrl(memoryId, openMcpView)`
- 这说明：
  - `memoryId` 与 `mcpListView` 不是前端自发控制项，而是 plugin 在入口时明确区分的业务参数
  - `auth/profile/getUrl` 至少需要根据这两个入口参数输出不同的成品 URL

## 2026-04-24 第四轮审核后收敛

- 当前对 `auth/profile/update` 与 `auth/profile/getUrl` 的分工，可以进一步精炼成：
  - `auth/profile/update`：
    - 同步一组完整的展示/环境参数到本地服务保存态
    - 供 profile 页面后续渲染与更新使用
  - `auth/profile/getUrl`：
    - 在保存态和当前入口参数基础上生成成品 `/profile?...` URL
    - 注入 `state`
    - 注入服务端补齐字段
    - 返回唯一的 `url`
- 当前对 profile webview 通道的最佳判断是：
  - 它是本地服务自管的一条独立更新通道
  - 至少支持 `ping`、`renderPage`、`dataPolicy`
  - 不经过 plugin 的 `CefMessageRouterHandler`

## 2026-04-24 第五轮增量快照

### 快照 34

- `auth/profile/getUrl`、`auth/profile/update`、`renderPage`、`WebViewAuth` 已经从“字符串关键词”下钻到具体 Go 实现包名层。
- 新增二进制实现名证据：
  - `cosy/core/api/auth.ProfileGetUrlHandler`
  - `cosy/core/api/auth.ProfileUpdateHandler`
  - `cosy/core/api/auth/login.GenerateNonceHandler`
  - `cosy/core/api/auth/login.AuthCallbackHandler`
  - `cosy/auth.(*HttpServer).HandleWebViewWebSocket`
  - `cosy/auth.(*HttpServer).HandleWebViewPage`
  - `cosy/auth.getWebviewSavedParams`
  - `cosy/auth.checkParamsValidity`
  - `cosy/auth.(*HttpServer).fillProfilePageWithParams`
  - `cosy/auth.(*HttpServer).GenerateProfileUrl`
  - `cosy/auth.(*HttpServer).UpdateWebViewPage`
  - `cosy/auth.InitWebViewClientManager`
  - `cosy/auth.(*WebViewClientManager).Run`
  - `cosy/auth.(*WebViewClientManager).DispatchMethod`
  - `cosy/auth.(*WebViewClientManager).BroadcastClient`
  - `cosy/auth.(*WebViewClient).watchTimeout`
  - `cosy/core/api/webview.ProfileUpdateRenderPageHandler`
  - `cosy/core/api/webview.ProfileUpdateDataPolicyHandler`
- 这意味着当前整条链已经可以高置信落到如下模块边界：
  - `cosy/core/api/auth/profile.go` 一类 handler 层负责 `auth/profile/getUrl` / `auth/profile/update`
  - `cosy/auth/webview*.go` 一类 service/transport 层负责：
    - page handler
    - websocket handler
    - saved params
    - state 校验
    - webview client manager
  - `cosy/core/api/webview/profile.go` 一类 handler 层负责 `renderPage` / `dataPolicy`

### 快照 35

- `WebViewAuth/state` 的生命周期模型现在可以进一步具体化。
- 新增二进制证据：
  - `state don't match: saved state (%s) != param state (%s)`
  - `failed to generate nonce: %v`
  - `Invalid login nonce or consumed, ignore`
  - `cosy/auth.(*WebViewClient).watchTimeout`
  - `%s don't exist in WebViewAuth`
- 当前更稳的判断是：
  - `state` 不是无状态 query 字段
  - 它至少有：
    - 生成阶段：`GenerateNonceHandler` / `GenerateProfileUrl`
    - 保存阶段：`getWebviewSavedParams` / `WebViewClientManager`
    - 校验阶段：`checkParamsValidity` / `HandleWebViewWebSocket`
    - 生命周期管理：`watchTimeout`
  - `WebViewAuth` 高概率是本地服务进程内存态，而不是 DB/文件持久化
  - profile `state` 是否“一次性消费”还没完全坐实，但“saved / match / consumed / timeout”这套语义已经基本明确

### 快照 36

- `auth/profile/getUrl` 使用的真实参数模型也进一步坐实了。
- 新增二进制/类型证据：
  - `rpc.TypedHandlerFunc[cosy/definition.WebViewParams,cosy/definition.WebViewUrlParams]`
  - `rpc.TypedHandlerFunc[cosy/definition.WebViewParams,cosy/definition.Response]`
  - `rpc.TypedHandlerFunc[cosy/definition.WebViewRenderPageParams,cosy/definition.Response]`
  - `func(*definition.WebViewParams) (string, definition.WebViewUrlParams)`
  - `type:.eq.cosy/definition.WebViewParams`
  - `type:.eq.cosy/definition.WebViewUrlParams`
  - `type:.eq.cosy/definition.WebViewRenderPageParams`
- 这说明：
  - `auth/profile/getUrl` 的服务端内部形状不是“随手拼字符串”
  - 它至少是：
    - 输入 `WebViewParams`
    - 生成一组 `WebViewUrlParams`
    - 再得到最终 URL 字符串
  - `webview/profile/update/renderPage` 则使用独立的 `WebViewRenderPageParams`
- 因而当前关于三者分工的最佳收敛是：
  - `WebViewParams`：plugin/服务端共享的展示与环境输入
  - `WebViewUrlParams`：服务端产出的 URL/query 层结果
  - `WebViewRenderPageParams`：服务端推给 webview 的后续页面更新载荷

### 快照 37

- “拿到真实 `/profile?...&state=` URL 后，直接 HTTP 访问是否能得到成品页”这件事本轮已经做了只读动态验证。
- 新增动态证据：
  - 对日志中真实样本 `http://127.0.0.1:37510/profile?...&state=451f81defe1d456380c7072ac4dddf84...` 发起 localhost-only GET
  - 返回 `HTTP/1.1 200 OK`
  - 但正文仍然是模板/半模板页，关键表现包括：
    - `window.error_code = 2`
    - `window.user_info = '{}'`
    - `window.login_url = ''`
    - `window.profile_websocket_port = '{PROFILE_WEBSOCKET_PORT}'`
    - `window.user_tag = '{USER_TAG}'`
    - `window.role_name = '{ROLE_NAME}'`
- 这条证据非常关键，它说明：
  - 即便拿到了本地服务生成的真实 `/profile?...&state=` URL
  - 直接用裸 HTTP 去访问 `37510/profile`
  - 仍然拿不到“可独立复用的成品 HTML”
- 当前更稳的判断是：
  - `getUrl` 产物本身是“webview/profile 管线的入口 URL”，不是离开该管线后可独立消费的完整成品页
  - profile 页面还依赖：
    - 本地服务内的 saved params
    - 独立 webview client 连接上下文
    - 后续 websocket/renderPage/dataPolicy 推送

### 快照 38

- `buttonHoverBg` 来自服务端字段模型，而不只是最终 URL 拼接时的偶然重命名，这点本轮也更清楚了。
- 新增证据：
  - 二进制里存在 `json:"buttonHoverBg"`
  - 二进制里未发现 `json:"buttonHoverColor"`
  - plugin/JAR 类定义里只有 `buttonHoverColor`
- 这说明：
  - Java/plugin 模型与 Go/service 模型在该字段上并不完全同构
  - 服务端的 `WebViewParams` / `WebViewUrlParams` 层本身就更偏向 `buttonHoverBg`
  - plugin 到服务端之间至少存在一次字段归一化/映射

## 2026-04-24 第五轮审核后收敛

- 当前 `auth/profile/getUrl` 的最佳结构化描述已经可以写成：
  1. plugin 提交 `GetProfileUrlParams`
  2. 本地 websocket client 把它交给 `LanguageServer.getProfileUrl`
  3. Go 侧 `ProfileGetUrlHandler` 将输入映射到 `definition.WebViewParams`
  4. `GenerateProfileUrl` 生成 `state` 与 `WebViewUrlParams`
  5. `/profile` 页通过 `HandleWebViewPage` / `fillProfilePageWithParams` 返回入口 HTML
  6. 页面再依赖 `HandleWebViewWebSocket` + `WebViewClientManager` + `renderPage/dataPolicy` 完成后续更新
- 当前 `WebViewAuth` 的最佳结构化描述已经可以写成：
  - 一个本地服务进程内的 webview 状态/连接管理体系
  - 它与 `state`、saved params、webview client、timeout 生命周期绑定
  - 但还没坐实其具体容器类型与是否首次成功连接后立即消费 `state`

## 2026-04-24 第六轮增量快照

### 快照 39

- 本轮对 `38510` 做了一次 localhost-only websocket Upgrade 控制探测，目标是验证“旧的真实 `state` 是否仍能被 websocket 接受”。
- 探测方式：
  - 对 `http://127.0.0.1:38510/ws?state=451f81defe1d456380c7072ac4dddf84`
  - 发送标准 Upgrade 头：
    - `Connection: Upgrade`
    - `Upgrade: websocket`
    - `Sec-WebSocket-Version: 13`
    - `Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==`
- 返回结果：
  - `HTTP/1.1 200 OK`
  - 响应体：`illegal websocket request`
- 这条结果说明：
  - 即便使用的是从 `idea.log` 真实抓到的历史 profile URL 里的 `state`
  - profile websocket 也不会无条件接受握手
- 当前更稳的判断是：
  - 旧 `state` 很可能已经失效，或与当前连接上下文不匹配
  - 也不能排除还缺少其他握手前提，例如更完整的上下文/页面阶段
  - 但至少已经可以确认：profile websocket 不是“拿到任何历史 `state` 就能直接复用”的静态入口

### 快照 40

- 本轮又补到了一条对 `renderPage/dataPolicy` 链很有价值的二进制上下文。
- 新增二进制同簇证据：
  - `webview client %s: received ping`
  - `Profile Invalid login parameters`
  - `webview/profile/update/dataPolicy`
  - `webview/profile/update/renderPage`
  - `illegal websocket request has been denied`
  - `watchTimeout`
- 当前更合理的高置信判断是：
  - profile webview 不是一次性静态页面，而是一个带保活、带会话校验、带增量更新的独立通道
  - page handler 与 websocket handler 之间还存在“登录态/参数完整性/连接上下文”这类门禁
  - 因此“复用已有 token 直接访问 API”的真正障碍已经不只是 token 本身，还包括本地服务管理的 webview/state 生命周期

## 2026-04-24 第六轮审核后收敛

- 当前关于 profile websocket 的最佳描述可以补成：
  - 它需要的不只是一个 query `state`
  - 它至少还依赖：
    - `WebViewAuth` 中当前仍有效的保存态
    - webview client manager 维护的连接生命周期
    - 页面渲染阶段与参数完整性检查
  - 历史 URL 中抓到的 `state` 不能直接当作稳定凭证复用

## 2026-04-24 第七轮增量快照

### 快照 41

- 当前活跃 `Lingma` 进程的实时日志路径已经确认，不应再把 `~/.Trash/lingma.log` 视为唯一运行时日志来源。
- 新增进程级证据：
  - `lsof -p 4625` 显示：
    - `cwd = /Users/Zipper/.lingma`
    - 正在写入的日志文件是 `/Users/Zipper/.lingma/logs/lingma.log`
- 这意味着：
  - 4 月 24 日继续分析时，`~/.Trash/lingma.log` 更适合作为历史样本
  - 当前活跃会话的动态探测结果，应优先以 `/Users/Zipper/.lingma/logs/lingma.log` 为准

### 快照 42

- “历史真实 state 已失效”现在已经从推测升级成当前活跃服务的实时日志证据。
- 新增实时日志证据：
  - `/Users/Zipper/.lingma/logs/lingma.log:29822`
    - `451f81defe1d456380c7072ac4dddf84 don't exist in WebViewAuth`
  - `/Users/Zipper/.lingma/logs/lingma.log:29823`
    - `profile request url parameters`
  - `/Users/Zipper/.lingma/logs/lingma.log:29987`
    - `451f81defe1d456380c7072ac4dddf84 don't exist in WebViewAuth`
  - `/Users/Zipper/.lingma/logs/lingma.log:29988`
    - `illegal websocket request has been denied`
- 对应探测动作：
  - 一次是对历史真实 `/profile?...&state=451f81defe1d456380c7072ac4dddf84...` 的 HTTP GET
  - 一次是对 `38510/ws?state=451f81defe1d456380c7072ac4dddf84` 的标准 websocket Upgrade
- 当前可以直接确认：
  - 这个历史 `state` 在当前活跃服务里已经不存在于 `WebViewAuth`
  - 同一个失效 `state` 在：
    - 页面请求路径里会触发 `profile request url parameters`
    - websocket 握手路径里会触发 `illegal websocket request has been denied`
- 因而现在关于 `state` 生命周期的判断可以进一步收紧成：
  - `state` 不是长期稳定凭证
  - 它至少与当前运行中的 `WebViewAuth` 内存态强绑定
  - 旧会话中抓到的真实 `state`，到了新的活跃服务周期里会失效

## 2026-04-24 第七轮审核后收敛

- 当前关于 profile `state` 的最佳运行时描述已经可以写成：
  - `state` 是当前活跃 `Lingma` 进程内保存态的一部分
  - 它不只是“格式正确的随机串”
  - 即便是从真实 plugin 日志里抓到的历史 `state`
  - 只要当前进程里的 `WebViewAuth` 已经没有对应项，就会同时失去：
    - `/profile` 页面路径复用能力
    - `38510/ws` websocket 握手能力

## 2026-04-24 第八轮增量快照

### 快照 43

- 当前活跃日志里没有出现任何新的 profile webview 会话建立证据。
- 本轮对 `/Users/Zipper/.lingma/logs/lingma.log` 的实时检索结果是：
  - 只看到：
    - `451f81defe1d456380c7072ac4dddf84 don't exist in WebViewAuth`
    - `profile request url parameters`
    - `illegal websocket request has been denied`
  - 没有看到：
    - `webview client %s: received ping`
    - `new profile page render success`
    - `Request has no connection specified`
    - `0 client has received the message`
    - `Webview client %s unregistered`
- 这说明：
  - 本轮探测期间，当前活跃 `Lingma` 进程里并没有一个真实在线的 profile webview 会话可供观察
  - 因而当前能证明的是“旧 state 已失效”，还不能进一步证明“fresh state 在当前进程里会被立即接受”

### 快照 44

- 当前关于下一步动态验证的边界也更清楚了。
- 已确认：
  - 旧 `state` 的失败路径已经有实时日志闭环
  - 但 2026-04-24 的 IDEA 日志里没有新的 `reload profiler url:` 样本
  - 当前活跃日志里也没有新的 profile webview 建连事件
- 因而下一轮若要继续向下坐实：
  - 最有价值的不是继续复用 2026-04-23 的历史 `state`
  - 而是要拿到“当前活跃进程刚生成的新 `reload profiler url` 样本”
  - 再立即对对应 `state` 做 HTTP 与 websocket 双探测
- 在拿不到 fresh `state` 之前，当前最稳结论已经足够明确：
  - `state` 与当前进程内的 `WebViewAuth` 强绑定
  - 历史 `state` 不能作为稳定复用凭证

## 2026-04-24 第八轮审核后收敛

- 当前对 `state` 生命周期的最佳保守表述应更新为：
  - 已证实：
    - 历史真实 `state` 会过期
    - 过期后会同时失去页面路径与 websocket 握手能力
  - 尚未证实：
    - fresh `state` 的精确有效窗口
    - 是否首次成功 websocket 握手后立即消费
    - `watchTimeout` 是唯一失效条件，还是和首次消费并存

## 2026-04-24 第九轮增量快照

### 快照 45

- `WebViewClient/watchTimeout` 这一支又补到了一组很有价值的结构性证据。
- 新增二进制证据：
  - `cosy/auth.(*WebViewClient).watchTimeout`
  - `cosy/auth.InitWebViewClientManager`
  - `cosy/auth.(*WebViewClientManager).Run`
  - `cosy/auth.(*WebViewClientManager).Run.(*Conn).SetPingHandler.func3`
  - `cosy/auth.(*WebViewClientManager).DispatchMethod`
  - `cosy/auth.(*WebViewClientManager).BroadcastClient`
  - `json:"mtx"`
  - 字段名簇：
    - `ResponseChan`
    - `attemptCount`
    - `GetTimeoutCount`
- 同一簇日志文案还包括：
  - `webview client %s: received ping`
  - `timer reset to idle timeout (%v)`
  - `Webview client %s unregistered`
  - `call auth webview method >> %s`
- 当前更稳的判断是：
  - `WebViewClientManager.Run` 会给 websocket 连接注册 `SetPingHandler`
  - ping 到达后会触发“重置 idle timeout”
  - `watchTimeout` 负责在无 ping/无活动时推进超时失效
  - `DispatchMethod` / `BroadcastClient` 负责把 `renderPage`、`dataPolicy` 这类方法分发到当前活跃 webview client
- 这意味着：
  - `state`/`WebViewAuth` 并不是一次生成后独立存在的一张静态票据
  - 它更像和某个 `WebViewClient` 的连接生命周期绑定
  - 连接断开或长时间无活动后，对应保存态大概率会被回收

### 快照 46

- `GenerateProfileUrl` 与 `renderPage/dataPolicy` 的分工也可以更精确一点。
- 当前最佳收敛是：
  - `GenerateProfileUrl`
    - 负责生成入口 URL 与 `WebViewUrlParams`
    - 关联/保存 `state`
  - `HandleWebViewPage` / `fillProfilePageWithParams`
    - 负责返回入口 HTML
  - `WebViewClientManager`
    - 负责维护已连接 webview client
  - `ProfileUpdateRenderPageHandler`
    - 负责页面主体内容/参数的增量更新
  - `ProfileUpdateDataPolicyHandler`
    - 负责数据策略相关增量更新
- 因而现在已经可以排除一种更简单的错误模型：
  - 不是“`getUrl` 直接吐出完全渲染好的最终页，websocket 只是可选增强”
  - 而是“`getUrl` 只给入口，真正可用的 profile 页面需要后续 webview client 会话和增量更新”

### 快照 47

- 当前活跃日志里还没有 fresh profile 会话，这个边界需要明确记录。
- 新增实时观察：
  - 在 `/Users/Zipper/.lingma/logs/lingma.log` 当前会话窗口里
  - 没看到新的：
    - `webview client %s: received ping`
    - `new profile page render success`
    - `call auth webview method >> %s`
  - 只看到了对历史 state 的失败：
    - `don't exist in WebViewAuth`
    - `profile request url parameters`
    - `illegal websocket request has been denied`
- 因而本轮能坐实的是：
  - 旧 state 已失效
  - `watchTimeout/ping` 机制在代码结构上存在
- 但本轮还不能坐实：
  - 当前活跃进程里是否已有 fresh webview client 在线
  - fresh state 到底是“首连即消费”还是“超时后失效”

## 2026-04-24 第九轮审核后收敛

- 当前关于 `state` 生命周期的最佳模型已经可以更新为：
  1. `GenerateProfileUrl` 生成 `state` 并写入当前进程保存态
  2. `HandleWebViewWebSocket` 用 `checkParamsValidity` + `WebViewAuth` 做校验
  3. 握手成功后 `WebViewClientManager` 接管连接
  4. `SetPingHandler` 与 `watchTimeout` 共同管理 idle 生命周期
  5. `DispatchMethod/BroadcastClient` 负责后续页面更新方法分发
- 当前仍未坐实但已经高度收敛的问题只剩两个：
  - `state` 是否在首次成功 websocket 建连后立即消费
  - `WebViewAuth` 的具体容器类型到底是 map、cache 还是带 TTL 的 manager 封装

## 2026-04-24 第十轮增量快照

### 快照 48

- `37010` 主 websocket 现在已经被直接复用成功，可以不经过 plugin UI，手工调用 `auth/profile/getUrl` 拿 fresh `state`。
- 这次不是推断，而是实测成功：
  1. 连接 `ws://127.0.0.1:37010`
  2. 发送 LSP over websocket 消息：
     - 必须使用 `Content-Length: <n>\\r\\n\\r\\n<json>` 封装
     - 不能发送裸 JSON；裸 JSON 会在实时日志里触发 `Unknown message header`
  3. 发送 `initialize` 请求
  4. 再发送 `auth/profile/getUrl`
- 实测结果：
  - `initialize` 成功返回 `InitializeResultExt`
  - `auth/profile/getUrl` 成功返回：
    - `http://127.0.0.1:37510/profile?...&state=678efe42aef2414cb55315fbfb1938da...`
  - 再次执行同样流程，又拿到新的 fresh `state`：
    - `3a847730edc646efaa6546fde3f1c28c`
- 这说明：
  - 至少在“获取 fresh profile URL/state”这个目标上，plugin 已经可以完全绕过
  - 只要能连本地 `37010` 并按 LSP framing 发请求，就能直接复用本地服务能力

### 快照 49

- `37010` 的初始化协议也进一步坐实了。
- 新增实时日志证据：
  - `/Users/Zipper/.lingma/logs/lingma.log:120`
  - `/Users/Zipper/.lingma/logs/lingma.log:186`
  - `/Users/Zipper/.lingma/logs/lingma.log:27197`
- 当前活跃服务日志会直接打印 plugin 发送的初始化参数：
  - `WorkspaceFolders=[{URI:/Users/Zipper/Git/... Name:...}]`
  - `IdeSeries=JetBrains`
  - `IdePlatform=Android Studio`
  - `IdeVersion=Panda 2 | 2025.3.2`
  - `PluginVersion=2.11.1`
  - `PluginPublisher=aliyun`
  - `PluginName=Lingma`
  - `PreferredLanguage=zh`
  - `IsEnableAutoMemory=false`
  - `AllowStatistics=true`
- 同时也新增了 `Cosy.startup()` 侧证据：
  - plugin 在 `connect` 成功后会显式调用 `server.initialize(params)`
  - `addConfigToInitializeParams(...)` 会填充上述 IDE/plugin 配置
- 当前更稳的判断是：
  - `37010` 的最小可复现入口不是“直接调业务方法”
  - 而是：
    - 先 `initialize`
    - 再调业务方法

### 快照 50

- `initialized` 通知对这个服务并不是必需步骤，甚至当前服务会把它当成未知方法。
- 新增实时日志证据：
  - `/Users/Zipper/.lingma/logs/lingma.log:35388` 左右
  - `err occur in initialized, isReq: false, err: unknown method: initialized`
- 实测现象：
  - 我手工发送 `initialized` notification 后
  - 服务端记录了 `unknown method: initialized`
  - 但后续 `auth/profile/getUrl` 仍然成功
- 当前更稳的判断是：
  - 当前 Lingma 本地服务虽然长得像 LSP4J JSON-RPC 接口
  - 但它并不完整实现标准 LSP 的 `initialized` notification
  - 对我们的最小复现来说，只要 `initialize` 成功即可

### 快照 51

- fresh `state` 的行为已经和历史 `state` 明确分化。
- 已确认：
  - 历史 `state=451f81defe1d456380c7072ac4dddf84`
    - 当前实时日志里会报：
      - `don't exist in WebViewAuth`
      - `illegal websocket request has been denied`
  - fresh `state=678efe42aef2414cb55315fbfb1938da`
    - 实时日志里报：
      - `678efe42ae ws build success`
  - fresh `state=3a847730edc646efaa6546fde3f1c28c`
    - 实时日志里报：
      - `3a847730ed ws build success`
    - 客户端实测：
      - `WS_CONNECTED=1`
      - `PING_PONG=1`
- 这意味着：
  - fresh `state` 在生成后可以立即通过 `38510/ws?state=...` 建立 websocket
  - 历史 `state` 则会被当前进程拒绝
  - 因而“fresh vs expired”的边界已经在运行时被直接分开

### 快照 52

- fresh `/profile?...&state=` 的 HTTP 返回也和历史失效 `state` 有明显差异。
- 对历史失效 `state` 的页面请求：
  - `window.error_code = 2`
  - `window.user_name = ''`
  - `window.user_info = '{}'`
  - `window.profile_websocket_port = '{PROFILE_WEBSOCKET_PORT}'`
- 对 fresh `state` 的页面请求：
  - `window.error_code = 0`
  - `window.user_name = 'zhang640@blny.de'`
  - `window.profile_websocket_port = '38510'`
  - `window.edition = 'Individual'`
  - `window.is_personal_version = 'true'`
- 但 fresh 页面仍然不是完全成品页，仍能看到未填充项，例如：
  - `window.user_info = '{}'`
  - `window.login_url = '{LOGIN_URL}'`
  - `window.grant_account_infos = '{GRANT_ACCOUNT_INFOS}'`
- 这说明：
  - fresh `state` + fresh URL 会让 `/profile` 至少进入“成功态入口页”
  - 但页面完整可用仍然依赖后续 webview/renderPage/dataPolicy 通道

## 2026-04-24 第十轮审核后收敛

- 当前关于“绕过 plugin”已经可以拆成两层确定结论：
  1. 绕过 plugin UI：
     - 已证实可行
     - 直接连 `37010`，按 LSP `Content-Length` framing 调 `initialize -> auth/profile/getUrl` 即可
  2. 绕过本地服务直连远端 HTTP API：
     - 仍未完成
     - 因为远端模型调用的签名、鉴权头、换票逻辑还在 `~/.lingma` 本地服务内部
- 当前关于 fresh `state` 的最佳描述已经可以升级为：
  - fresh `state` 可立即建立 `38510` websocket
  - expired `state` 会被 `WebViewAuth` 拒绝
  - `state` 的有效性与当前进程内的保存态强绑定

## 2026-04-24 第十一轮增量快照

### 快照 53

- `37010` 的直接 JSON-RPC 复用已经不仅限于 `auth/profile/getUrl`，还可以直接读取当前活跃登录态。
- 新增实测证据：
  - 连接 `ws://127.0.0.1:37010`
  - 使用 LSP `Content-Length` framing
  - 先发送 `initialize`
  - 再发送 `auth/status`
- 实测返回：
  - `status = 2`
  - `name = zhang640@blny.de`
  - `id / accountId = 5930676910898027`
  - `token = pt-...`
  - `refreshToken = rt-...`
  - `userType = personal_standard`
  - `privacyPolicyAgreed = true`
  - `cloudType = individual_intl`
- 这条证据非常关键，因为它说明：
  - 当前活跃用户态票据并不是只能从浏览器 callback 页面侧拿到
  - 本地 `37010` 服务本身就直接暴露了程序化 `auth/status` 读取能力
  - 至少在“获取当前登录态票据 + fresh state”这个层面，plugin 可以完全绕过

### 快照 54

- `config/queryModels` 也已通过 `37010` 直连成功，能直接拿到本地服务当前可用模型注册表。
- 新增实测结果：
  - `config/queryModels` 返回了 `assistant/chat/developer/inline` 等场景的模型列表
  - 当前样本中的系统模型包括：
    - `dashscope_qwen3_coder_default` / `Auto`
    - `dashscope_qwen3_coder` / `qwen3-coder`
    - `dashscope_qwen_plus_20250428_thinking` / `qwen3-thinking`
    - `dashscope_qwen_max_latest` / `qwen2.5-max`
  - 每项里可以看到：
    - `format = openai`
    - `source = system`
    - `isReasoning = true/false`
- 同时也有一个重要边界：
  - `url = ""`
  - `apiKey = ""`
  - `model = ""`
- 这说明：
  - 本地服务的模型表足以告诉我们“场景 -> 模型 key/displayName/format/source”
  - 但还不会直接把远端 base URL、API key、上游 provider 模型名明文返回
  - 因而它更像“路由/能力注册表”，不是完整上游调用配置泄漏点

### 快照 55

- `user/plan` 通过 `37010` 直连当前会返回错误，而不是稳定返回套餐信息。
- 新增实测结果：
  - `user/plan` 返回：
    - `code = -32603`
    - `message = failed to get user plan info: HTTP status 404`
- 这说明：
  - `37010` 暴露的方法并不都能稳定成功
  - 它们仍然受远端服务侧接口状态和当前账号/区域路由影响

### 快照 56

- `initialized` notification 的处理边界，现在也可以明确写成“服务端不支持，但不影响最小复现”。
- 新增运行时证据：
  - 我手工发送 `initialized`
  - 当前活跃日志记录：
    - `err occur in initialized, isReq: false, err: unknown method: initialized`
  - 但：
    - `initialize` 本身成功
    - 后续 `auth/profile/getUrl` 成功
    - fresh `state` 也成功建立 `38510` websocket
- 因此当前最小复现流程可以正式收敛为：
  - `connect 37010`
  - `initialize`
  - 直接调目标 JSON-RPC 方法
  - 不需要额外发送 `initialized`

## 2026-04-24 第十一轮审核后收敛

- 当前已经可以把“本地服务可程序化复用”写成稳定结论：
  - `37010` 是一个真实可复用的本地 JSON-RPC API 面
  - 它至少已被实测验证可直接调用：
    - `auth/status`
    - `auth/profile/getUrl`
    - `config/queryModels`
  - 调用前提：
    - websocket 连接到 `37010`
    - 使用 LSP `Content-Length` framing
    - 先发 `initialize`
- 当前对“如何在不碰 plugin UI 的情况下复用已有登录态”已经有了明确答案：
  - 可直接调用本地 `37010`
  - 读取当前 `auth/status`
  - 再调 `auth/profile/getUrl` 获取 fresh `state`
  - 甚至可继续读模型注册表 `config/queryModels`
- 但关于“如何直接绕过本地服务，重放远端 HTTP API”仍保持原判断不变：
  - 还没有还原远端模型请求所需的签名/鉴权头/换票规则
  - 因此目前已经落地的是“直接调用本地服务 API”，还不是“直接调用远端大模型 HTTP API”

## 2026-04-24 第十二轮增量快照

### 快照 57

- `37010` 的直接 API 面已经不仅能读状态，还能启动真实聊天请求。
- 新增实测：
  - 通过 `37010`
  - 发送：
    - `initialize`
    - `chat/ask`
  - 使用的最小参数集包括：
    - `requestId`
    - `chatTask = FREE_INPUT`
    - `sessionId`
    - `codeLanguage = text`
    - `isReply = false`
    - `source = 1`
    - `questionText = "Say hello in one short sentence."`
    - `stream = true`
    - `sessionType = chat`
    - `pluginPayloadConfig = { isEnableAutoMemory: false }`
    - `mode = chat`
- 实测返回与回推：
  - `chat/ask` 的同步响应立即返回 `success = true`
  - 随后收到：
    - `chat/process_step_callback`
    - `session/title/update`
    - `chat/answer`
  - 流式文本内容里已经出现实际模型输出：
    - `你好`
- 这说明：
  - 从“启动一轮真实模型回答”的角度看
  - `37010` 已经可以被视为一个可直接程序化调用的大模型入口
  - plugin UI 对聊天本身不是必需条件

### 快照 58

- `chat/ask` 的服务端处理链，也通过实时日志被进一步坐实了。
- 新增实时日志证据：
  - `|Chat| doAsk params.SessionType: chat, ChatMode: chat`
  - `Async chat, request id: 24f4f17b-df36-4f2f-9aed-886a066d422e`
  - `[TOKEN_USAGE]: {"completion_tokens":62,"prompt_tokens":495,"request_id":"24f4f17b-df36-4f2f-9aed-886a066d422e","total_tokens":557}`
  - `finish chat answer requestId: 24f4f17b-df36-4f2f-9aed-886a066d422e cost: 6.51920325s`
- 还可以看到一个关键副现象：
  - `|Outbound| request ... chat/answer ... failed: no response from client, timeout reached`
  - `session/title/update ... failed: no response from client, timeout reached`
  - `Client ... is closed, ignore request`
- 当前更稳的判断是：
  - 本地服务会把聊天结果通过“服务端 -> client”的请求/通知推回给前端
  - plugin 正常情况下会对其中一部分消息做响应
  - 我们的最小脚本虽然已经能接收结果，但还没有完整实现 plugin 那套 client 侧应答协议
- 这说明：
  - “直接调用本地服务聊天”已经成立
  - 但若要做成稳定外部客户端，还需要补一层 `37010` 的 client 回调/ack 兼容

### 快照 59

- `37010` 的协议形态现在可以写成比之前更完整的描述。
- 已确认：
  - websocket 连接成功后，服务端会把连接注册为普通 `TransManager` client
  - 请求体必须使用：
    - `Content-Length: <n>\\r\\n\\r\\n<json>`
  - 不能发送裸 JSON，否则实时日志会报：
    - `Unknown message header`
  - `initialize` 是必须步骤
  - `initialized` 不是必须，且当前服务会报：
    - `unknown method: initialized`
- 因而 `37010` 的最小调用模板已经可以写成：
  1. websocket connect
  2. LSP framing
  3. `initialize`
  4. 目标业务方法，例如：
     - `auth/status`
     - `config/queryModels`
     - `auth/profile/getUrl`
     - `chat/ask`

### 快照 60

- 本轮把“绕过 plugin UI”和“做成稳定外部客户端”之间的差距也补清楚了。
- 当前已经实测成功的能力：
  - 读取当前登录态：`auth/status`
  - 读取模型注册表：`config/queryModels`
  - 获取 fresh profile URL/state：`auth/profile/getUrl`
  - 建立 profile websocket：`38510/ws?state=<fresh>`
  - 发起真实聊天请求：`chat/ask`
- 当前仍需补齐的部分：
  - 对 `chat/process_step_callback`
  - `session/title/update`
  - `chat/answer`
  - 以及其他 server -> client 请求/通知的处理与必要 ack
- 因而现在最准确的表述是：
  - 已经找到了一个“可直接调用”的本地 API 面
  - 但要把它做成长期稳定的外部客户端，还需要兼容 Lingma 的 client 回调协议

## 2026-04-24 第十二轮审核后收敛

- 当前对“如何直接使用已有登录态进行调用”的最佳落地答案已经分成两层：
  1. 立即可用的方案：
     - 直接连本地 `37010`
     - 用 LSP framing 调：
       - `initialize`
       - `auth/status`
       - `config/queryModels`
       - `auth/profile/getUrl`
       - `chat/ask`
     - 这已经足以绕过 plugin UI 完成读状态、拿 fresh state、起聊天请求
  2. 仍待完善的方案：
     - 把 `37010` 包装成稳定外部客户端
     - 需要继续补齐 server -> client 的回调/ack 语义
- 同时也要保持之前的边界判断不变：
  - 这仍然是在“复用本地服务 API”
  - 不是“直接重放远端 HTTP 大模型接口”

## 2026-04-24 第十三轮增量快照

### 快照 61

- `37010` 的协议细节现在已经可以写成“可重复执行”的最小规范。
- 已确认：
  - 连接目标：`ws://127.0.0.1:37010`
  - 消息不能发裸 JSON
  - 必须使用：
    - `Content-Length: <n>\r\n\r\n<json>`
  - 否则活跃日志会报：
    - `Unknown message header`
- 同时：
  - `initialize` 是必需步骤
  - `initialized` 不是必需，且当前服务会记录：
    - `unknown method: initialized`
- 因而当前最小调用模板已经可以明确写成：
  1. websocket connect
  2. LSP `Content-Length` framing
  3. `initialize`
  4. 目标业务方法

### 快照 62

- `37010` 已经实测可以直接读取当前活跃登录态，而且返回内容比 callback 页面更完整。
- 新增实测结果：
  - 通过 `auth/status` 返回：
    - `status = 2`
    - `name = zhang640@blny.de`
    - `id = 5930676910898027`
    - `accountId = 5930676910898027`
    - `token = pt-...`
    - `refreshToken = rt-...`
    - `userType = personal_standard`
    - `privacyPolicyAgreed = true`
    - `cloudType = individual_intl`
- 这说明：
  - 现活跃 token/refreshToken 并不是只能从浏览器 callback 抓
  - 本地服务已经把当前用户态包装成可直接读取的 JSON-RPC 结果
- 当前更稳的判断是：
  - 若目标是“复用已有登录态做调用”
  - `auth/status` 比抓浏览器 callback 更稳定、更程序化

### 快照 63

- `config/queryModels` 也已经被 `37010` 直连成功，且返回信息足够说明“场景 -> 模型注册表”。
- 新增实测结果：
  - 返回了：
    - `assistant`
    - `chat`
    - `developer`
    - `inline`
  - 每个场景下都有模型项，例如：
    - `dashscope_qwen3_coder_default` / `Auto`
    - `dashscope_qwen3_coder` / `qwen3-coder`
    - `dashscope_qwen_plus_20250428_thinking` / `qwen3-thinking`
    - `dashscope_qwen_max_latest` / `qwen2.5-max`
  - 每项里还能看到：
    - `format = openai`
    - `source = system`
    - `isReasoning = true/false`
- 同时：
  - `url = ""`
  - `apiKey = ""`
  - `model = ""`
- 因而当前可以明确确认：
  - 本地服务确实维护了一份当前可用模型注册表
  - 但它不会直接把上游 endpoint / apiKey 明文暴露出来

### 快照 64

- `chat/ask` 已经被 `37010` 直连成功触发，证明本地服务本身就是真正可调用的大模型入口。
- 新增实测：
  - 构造最小 `ChatAskParam`：
    - `chatTask = FREE_INPUT`
    - `sessionType = chat`
    - `questionText = "Say hello in one short sentence."`
    - `stream = true`
    - 以及必要的：
      - `requestId`
      - `sessionId`
      - `source = 1`
      - `isReply = false`
      - `codeLanguage = text`
      - `pluginPayloadConfig = { isEnableAutoMemory: false }`
      - `mode = chat`
  - `chat/ask` 的同步返回：
    - `success = true`
  - 后续收到了流式回推：
    - `chat/process_step_callback`
    - `session/title/update`
    - `chat/answer`
  - 文本流里出现真实模型输出：
    - `你好`
- 活跃日志对应证据：
  - `|Chat| doAsk params.SessionType: chat, ChatMode: chat`
  - `Async chat, request id: ...`
  - `[TOKEN_USAGE]: ...`
  - `finish chat answer requestId: ...`
- 这说明：
  - 从“启动真实大模型调用”角度，plugin UI 已经不是必要条件
  - `37010` + 正确 framing + 正确参数，就足以直接触发本地服务起远端模型请求

### 快照 65

- 但 `37010` 的聊天调用仍然不是“完整兼容官方客户端”的终点，还差一层 client 回调兼容。
- 新增实测/日志现象：
  - 服务端向我们这个自建 client 回推时，会记录：
    - `chat/process_step_callback ... no response from client, timeout reached`
    - `chat/answer ... no response from client, timeout reached`
    - `session/title/update ... no response from client, timeout reached`
  - 即使如此：
    - 文本结果仍然已经回推到我们脚本端
    - 聊天流程仍然完成
- 当前更稳的判断是：
  - `37010` 这条通道已经足以“直接调用”
  - 但若要做成长期稳定外部客户端，还要继续兼容 server -> client 的请求/ack 行为

## 2026-04-24 第十三轮审核后收敛

- 当前关于“绕过 plugin 和本地程序”的边界可以更精准地重述为：
  1. 绕过 plugin：
     - 已完全成立
     - `37010` 已经可以直接读登录态、读模型表、拿 fresh state、发起聊天
  2. 绕过本地 `Lingma` 程序：
     - 仍未成立
     - 因为真正的远端 HTTP 请求签名/鉴权头构造仍在本地程序内部
- 当前最准确的阶段性答案是：
  - 已经找到了一个“可直接编程调用”的本地 API 面
  - 但要真正做到“脱离本地程序直连远端 API”
  - 还必须继续协议研究 `Authorization + Cosy-*` 头与签名算法

## 2026-04-24 第十四轮增量快照

### 快照 66

- 远端模型 endpoint 现在已经通过实测明确给出拒绝原因：`Signature invalid`。
- 新增实测方法：
  1. 通过本地 `37010` 读取当前活跃 `auth/status.token`
  2. 直接向：
     - `https://lingma.alibabacloud.com/algo/api/v2/service/pro/sse/llm_completion_stream?FetchKeys=&Encode=1`
     发起 `POST`
  3. 请求头只带：
     - `Authorization: Bearer pt-...`
     - `Content-Type: application/json`
     - `Accept: text/event-stream`
  4. 请求体使用 OpenAI 风格最小结构：
     - `model`
     - `messages`
     - `stream`
     - `temperature`
     - `max_tokens`
- 实测结果：
  - HTTP 层返回：
    - `HTTP 200`
    - `Content-Type: text/event-stream`
  - 但 SSE 首条事件正文为：
    - `{"code":"101","message":"Signature invalid"}`
    - 包装在：
      - `data:{"headers":{"Content-Type":["application/json"]},"body":"{\"code\":\"101\",\"message\":\"Signature invalid\"}","statusCodeValue":403,"statusCode":"FORBIDDEN"}`
- 这条证据非常关键，因为它直接说明：
  - 当前活跃 `pt-...` bearer token 本身是能到达远端模型服务的
  - 远端并不是先在网络层直接拒掉 bearer
  - 真正失败点在服务端签名校验

### 快照 67

- 这次远端直连实测，把“本地服务最后剩下的壁垒”精确收敛成了签名链本身。
- 当前已证实：
  - `Authorization: Bearer pt-...` 单独存在时：
    - 足以命中远端 `llm_completion_stream`
    - 但不足以通过业务鉴权
  - 缺的就是：
    - `Cosy-Key`
    - `Cosy-Date`
    - `Cosy-User`
    - 以及对应签名值
- 这与二进制里的本地实现点形成强闭环：
  - `addBigModelSignatureHeaders`
  - `addBigModelAuthorizationHeaders`
  - `GetAuthorizationHeader`
  - `getAppSalt`
  - `getUrlSignInterface`
  - `getDTSignInterface`
  - `getSecurityFactorsInterface`
  - `Expected Signature`

### 快照 68

- 远端签名校验现在可以更精准地表述成“服务端要求 Bearer + Cosy 签名混合模式”。
- 当前证据链已经变成：
  1. 本地 `37010` 可以直接返回当前 `token`
  2. 用这个 `token` 直接打远端 SSE 接口
  3. 远端不回 401/302，而是进入业务流
  4. 业务流内明确返回 `Signature invalid`
- 因而当前最稳结论已经不再是泛化的：
  - “token 可能不够”
- 而是更具体的：
  - “token 本身能过第一层入口，但没有通过服务端签名校验”

## 2026-04-24 第十四轮审核后收敛

- 当前距离“脱离本地程序直连远端 API”只剩最后一段硬缺口：
  - 还原 `Cosy-*` 头及签名值的生成算法
- 已经可以明确排除的错误方向：
  - 不是 endpoint 找错
  - 不是 token 完全无效
  - 不是请求体必须走 plugin UI 才能生成
- 当前最准确的阶段性结论是：
  - `pt-...` token 能让请求进入远端模型服务
  - 但要真正成功，必须再补齐本地 `Lingma` 进程里那套 `Cosy-Key/Cosy-Date/Cosy-User + Signature` 构造链

## 2026-04-24 第十五轮增量快照

### 快照 69

- 本轮对远端模型 endpoint 做了一个很关键的最小对照实验。
- 测试目标：
  - `https://lingma.alibabacloud.com/algo/api/v2/service/pro/sse/llm_completion_stream?FetchKeys=&Encode=1`
- 使用相同请求体，只改变鉴权/签名头，四组对照：
  1. `no_auth`
     - 不带任何 `Authorization`
  2. `pt_only`
     - 只带当前活跃 `Bearer pt-...`
  3. `fake_auth`
     - `Bearer pt-fake-token`
  4. `pt_plus_cosy_stub`
     - `Bearer pt-...`
     - 再加伪造：
       - `Cosy-Key: stub`
       - `Cosy-Date: 1777000000000`
       - `Cosy-User: <uid>`
- 四组实测结果完全一致：
  - HTTP `200`
  - `Content-Type: text/event-stream`
  - 首条 SSE 事件正文统一是：
    - `{"code":"101","message":"Signature invalid"}`
- 这条结果非常关键，因为它说明：
  - 远端模型入口不会优先在 HTTP 层给出“token 无效/未登录”之类的显式差异
  - 至少在我们当前这组 endpoint 上，服务端会统一先落到签名校验失败
  - 因而当前最难的不是“拿 token”，而是“还原正确的签名载荷与头”

### 快照 70

- 这轮结果也帮助修正了上一轮一个过强的表述。
- 之前更保守的说法是：
  - “`pt-...` token 本身能过第一层入口，但签名失败”
- 现在更稳的表述应改为：
  - “当前 endpoint 在无 auth、假 auth、真 auth、伪 Cosy 头这几种情况下，都会统一返回 `Signature invalid`”
  - 所以还不能仅凭这条 endpoint 的返回差异，证明 `Authorization` 单独是否已经被正确验过
  - 但可以明确证明：
    - 只靠 `pt-...` 远远不够
    - 伪造 `Cosy-Key/Cosy-Date/Cosy-User` 也不够
    - 真正决定成败的是完整正确的签名链

## 2026-04-24 第十五轮审核后收敛

- 当前关于远端直连的最佳结论应更新为：
  - 远端 `llm_completion_stream` endpoint 已经被直接命中成功
  - 但无论：
    - 无 token
    - 假 token
    - 真 token
    - 真 token + 伪 Cosy 头
  - 服务端都统一回：
    - `Signature invalid`
- 这意味着：
  - 现在真正要攻克的唯一关键问题就是：
    - 正确签名值放在哪个头/字段里
    - `Cosy-Key/Cosy-Date/Cosy-User` 的真实取值是什么
    - 这些值如何参与 MD5 / salt / native sign 接口计算

## 2026-04-24 第十六轮增量快照

### 快照 71

- 本地签名能力现在已经从“函数名层”进一步下钻到了具体的 ObjC 类/接口对象图。
- 新增 `otool -ov` 证据显示，二进制里真实存在这些 ObjC 类：
  - `SecurityGuardSDKManager`
  - `UrlSignInterface`
  - `IUrlSignInterface`
  - `DTSignInterface`
  - `IDTSignInterface`
  - `UMIDInterface`
  - `IUMIDInterface`
  - `StaticDataStoreInterface`
  - `IStaticDataStoreInterface`
- 同时还能看到对应 selector：
  - `urlSign:method:input:error:`
  - `tokenSign:method:input:error:`
  - `GenerateSignatureBaseString:input:error:`
  - `getSecurityToken:`
  - `initUMID:callback:`
  - `getGeneralConfig:callback:error:`
  - `getSecurityFactors:error:`
  - `encryptWithAppkey:input:method:error:`
  - `decryptWithAppkey:input:method:error:`
  - `getMiniWua::`
- 这说明：
  - 本地签名因子不是纯 Go 逻辑，也不是普通字符串拼接
  - 至少有一部分签名/设备标识能力来自嵌入在 `Lingma` 二进制里的 macOS ObjC 组件
  - `SecurityGuardSDKManager` 是当前最值得关注的本地签名能力入口

### 快照 72

- 远端直连对照实验又进一步修正了“Authorization 的作用边界”。
- 本轮对 `llm_completion_stream` 做了四组对照：
  - `no_auth`
  - `pt_only`
  - `fake_auth`
  - `pt_plus_cosy_stub`
- 四组全都统一返回：
  - `Signature invalid`
- 当前最稳的结论应更新为：
  - 这个 endpoint 至少在当前测试路径上，不会先把 auth/token 差异直接显式暴露出来
  - 它会统一先落到签名校验失败
  - 因而现在真正能区分成败的仍然只有那套本地签名链

### 快照 73

- 目前对本地签名链的最佳结构化描述已经可以写成：
  1. Go 侧：
     - `addBigModelSignatureHeaders`
     - `addBigModelAuthorizationHeaders`
     - `GetAuthorizationHeader`
     - `getAppSalt`
  2. ObjC/native 侧：
     - `SecurityGuardSDKManager`
     - `UrlSignInterface`
     - `DTSignInterface`
     - `UMIDInterface`
     - `StaticDataStoreInterface`
  3. 运行时数据：
     - `machine_token.json`
     - 当前活跃 `pt-/rt-` 用户态票据
     - 机器/系统信息
     - 时间戳
- 结合二进制里的调试模板：
  - `=== Signature Components (used for MD5) ===`
  - `1. Payload (base64)`
  - `2. Key (Cosy-Key)`
  - `3. Timestamp (Cosy-Date)`
  - `4. Body`
  - `Expected Signature`
  - `Cosy-User`
  - `Authorization`
- 当前更合理的高置信判断是：
  - 最终远端请求签名至少是“Go 侧拼装 + ObjC/native 输出因子”混合模式
  - 单靠 `pt-...` token 或手工伪造 `Cosy-*` 头都无法通过

## 2026-04-24 第十六轮审核后收敛

- 当前距离“脱离本地程序直连远端 API”已经不是一个大黑盒，而是一个很具体的剩余问题：
  - 还原 `SecurityGuardSDKManager` 相关接口返回值
  - 还原 `urlSign/tokenSign/GenerateSignatureBaseString` 的输入输出关系
  - 再映射回 `Cosy-Key/Cosy-Date/Cosy-User/Authorization`
- 当前最准确的阶段性结论是：
  - 远端直连失败不是因为不会发请求
  - 也不是因为 token 不存在
  - 而是因为本地程序里这套 SecurityGuard/native 签名链还没被还原

## 2026-04-24 第十七轮增量快照

### 快照 74

- 本轮确认了当前一个现实阻塞：不能直接附加到正在运行的 `Lingma` 进程做动态 插桩观察。
- 新增证据：
  - `lldb -p 4625` 返回：
    - `attach failed (Not allowed to attach to process ...)`
  - `frida -p 4625` 返回：
    - `unable to access process with pid 4625 from the current user account`
- 这说明：
  - 当前 macOS 权限模型阻止了对现活跃 `Lingma` 进程做无侵入附加
  - 因而目前签名链还原只能继续依赖：
    - 静态反汇编
    - ObjC 元数据
    - 黑盒请求对照实验
- 这不是功能性结论，但它解释了为什么当前还拿不到运行时真正的 `Cosy-Key/Cosy-Date/Cosy-User` 明文值

### 快照 75

- `SecurityGuardSDKManager` 的对象图和角色已经可以更具体地写出来。
- 当前静态证据显示：
  - `SecurityGuardSDKManager` 作为顶层类存在
  - 它周围成组存在这些接口对象：
    - `UrlSignInterface`
    - `DTSignInterface`
    - `UMIDInterface`
    - `StaticDataStoreInterface`
  - 同时还有方法：
    - `getUrlSignInterface`
    - `getDTSignInterface`
    - `getUMIDInterface`
    - `getStaticDataStoreInterface`
    - `getSecurityFactorsInterface`
    - `getInstance`
- 当前更合理的高置信推断是：
  - `SecurityGuardSDKManager` 大概率就是本地签名能力的统一入口
  - 其职责不是直接发请求，而是向 Go 侧输出：
    - URL 签名能力
    - DT 签名能力
    - UMID/设备标识能力
    - 静态数据存取能力
    - 安全因子能力
- 这与 Go 侧的：
  - `addBigModelSignatureHeaders`
  - `getAppSalt`
  - `GetAuthorizationHeader`
  形成了明显的上下游分工

### 快照 76

- 现在对“最终剩余问题”的表述可以再压缩一层。
- 不是所有 header 都未知，而是已经可以把未知量限定为：
  1. `SecurityGuardSDKManager` 相关接口的真实返回值
  2. 这些返回值如何进入：
     - `Cosy-Key`
     - `Cosy-Date`
     - `Cosy-User`
     - `Authorization`
  3. `GenerateSignatureBaseString` / `urlSign` / `tokenSign` 的参数顺序与 method code 含义
- 也就是说：
  - endpoint 已知
  - body 结构已知
  - 当前 token 已知
  - 本地 API 面已知
  - 唯一未穿透的，只剩 SecurityGuard/native 签名值

## 2026-04-24 第十七轮审核后收敛

- 当前最准确的阶段性结论已经可以写成：
  - 真正拦住“脱离本地程序直连远端 API”的，不是 plugin，也不是本地 `37010` 协议
  - 而是 macOS 上 `Lingma` 内嵌的 `SecurityGuardSDKManager` 这套 native 签名链
- 当前分析工作已经把问题从“大范围协议研究”压缩成一个非常小的剩余面：
  - 拿到 `SecurityGuardSDKManager -> UrlSign/DTSign/UMID/SecurityFactors` 的真实返回值和组合方式

## 2026-04-24 第十八轮增量快照

### 快照 77

- 常规缓存文件里当前没有直接暴露可复用的 `machineId` 明文。
- 已检查范围：
  - `/Users/Zipper/.lingma`
  - `/Users/Zipper/Library/Caches/.lingma`
  - 排除了二进制与大型索引文件后做关键字检索
- 当前没有发现明文落盘的：
  - `machine_id`
  - `machineId`
  - `Cosy-MachineId`
  - `Cosy-MachineToken`
  - `device_mac_address`
  - `device_hardware_id`
- 这与二进制里的这些文案一致：
  - `Using disk serial number: %s & mac:%s as machineId`
  - `Using serial number: %s as machineId`
  - `Using random string: %s as machineId`
- 当前更稳的判断是：
  - `machineId` 更像运行时计算值，而不是简单缓存值
  - `Cosy-MachineId` 很可能来自“硬件序列号/MAC/随机串”的回退链

### 快照 78

- 当前剩余问题已经进一步压缩成 native 运行时值本身，而不是配置文件或缓存文件。
- 已知：
  - endpoint 已知
  - body 结构已知
  - 活跃 token 已知
  - `37010` API 面已知
  - `SecurityGuardSDKManager` 对象图已知
- 未知只剩：
  - `UrlSign / DTSign / UMID / SecurityFactors` 的真实返回值
  - 这些返回值如何组合成：
    - `Cosy-Key`
    - `Cosy-Date`
    - `Cosy-User`
    - `Authorization`
- 因而当前最准确的阶段性结论是：
  - 继续在 plugin、cache、普通配置文件层面扩搜，收益已经很低
  - 后续若继续推进，要么拿到 native 运行时返回值，要么继续做远端黑盒差分实验

## 2026-04-24 第十八轮审核后收敛

- 当前距离“脱离本地程序直连远端 API”的剩余问题，已经不是调用链问题，而是 native 安全因子问题：
  - `machineId / machine token / security factors / miniWua` 这类运行时值到底是什么
  - 它们如何进入最终签名链

## 2026-04-24 第十九轮增量快照

### 快照 79

- 本轮针对 `Cosy-MachineId / Cosy-MachineToken / Bearer COSY...` 做了更细的远端黑盒差分，结果仍然全部统一落到 `Signature invalid`。
- 新增测试组合包括：
  - `Authorization: Bearer COSY.<type>.<machine_token>`
  - 再叠加不同 `Cosy-MachineId` 候选：
    - `serial + mac`
    - `serial|mac`
    - `IOPlatformUUID`
    - `serial`
    - `mac`
  - 再叠加：
    - `Cosy-MachineToken`
    - `Cosy-MachineOS = darwin`
- 所有组合的结果都一致：
  - HTTP `200`
  - SSE 首条事件：
    - `{"code":"101","message":"Signature invalid"}`
- 这条结果说明：
  - 当前这些 `machineId` 候选值都不足以让服务端走到下一个校验阶段
  - 即使 `Bearer COSY.<type>.<machine_token>` 形式本身是“长得像”正确结构
  - 只要没有正确 native 签名值，服务端仍然统一只回 `Signature invalid`

### 快照 80

- 这轮负面证据的价值在于：进一步排除了“靠常见硬件标识直接猜中 `Cosy-MachineId`”这条低成本路径。
- 当前更稳的判断是：
  - `Cosy-MachineId` 即便和硬件序列号/MAC/UUID有关
  - 也极可能经过了本地 native 层的转换/规整，而不是原样明文拼接
  - 更重要的是：
    - 单独把 `Cosy-MachineId/Cosy-MachineToken/Cosy-MachineOS` 带上去，仍然不够
    - 真正关键的仍然是 `urlSign/tokenSign/GenerateSignatureBaseString` 产出的签名值本身

## 2026-04-24 第十九轮审核后收敛

- 当前关于远端直连的最佳收敛应更新为：
  - 已经没有必要继续在：
    - bearer token 形式
    - `Cosy-MachineId` 候选值
    - `Cosy-MachineToken` 直传
    - `Cosy-MachineOS` 直传
    这些简单头字段组合上反复试探
  - 因为所有这类低成本黑盒组合都统一只落到：
    - `Signature invalid`
  - 因而后续若继续推进，真正有价值的只剩两条：
  1. 想办法获取 native `SecurityGuardSDKManager` 运行时返回值
  2. 继续从静态反汇编里还原 `GenerateSignatureBaseString/urlSign/tokenSign` 的参数语义

## 2026-04-24 第二十轮增量快照

### 快照 81

- 本轮又补到了 `machineId` 输入面的系统级旁证。
- 当前机器上可直接取到的候选硬件标识包括：
  - `IOPlatformSerialNumber = C07G60YAQ6NY`
  - `IOPlatformUUID = 4B1B8889-0618-53BE-ABED-D9B3F1086081`
  - 主网卡 MAC：
    - `en0 = 14:98:77:52:86:f6`
    - `en1 = 14:98:77:5b:7c:cf`
- 结合二进制里的文案：
  - `Using disk serial number: %s & mac:%s as machineId`
  - `Using serial number: %s as machineId`
  - `Using random string: %s as machineId`
  - `Hardware UUID not found`
- 当前最稳的判断是：
  - `machineId` 的输入面至少可能来自：
    - 磁盘/设备序列号
    - MAC 地址
    - 硬件 UUID
    - 随机串回退
  - 但它不是原样落盘值，而是运行时经过本地 native 层处理后的结果

### 快照 82

- 二进制里还补到了签名相关的内部字段名，进一步支持“签名材料是结构化对象，而不是只在日志里临时拼接”。
- 新增字段级字符串证据：
  - `cosy_user`
  - `cosy_date`
  - `body_hash`
  - `expected_signature`
  - `body_is_valid_utf8`
  - `signature_validation_failed`
- 结合已有调试模板：
  - `=== Signature Components (used for MD5) ===`
  - `Payload (base64)`
  - `Key (Cosy-Key)`
  - `Timestamp (Cosy-Date)`
  - `Expected Signature`
  - `Cosy-User`
  - `Authorization`
- 当前更合理的高置信判断是：
  - Go 侧至少维护了一份签名上下文字段集合
  - `body_hash` / `expected_signature` 并不是日志专用临时变量，而是更接近运行时对象字段
  - 这进一步支持：
    - 需要同时还原“签名基串构造”和“native 接口输出”

### 快照 83

- 本轮没有发现新的低成本突破口，反而进一步说明问题已经被压到 native 运行时值这一个面上。
- 已新增的负面证据：
  - 普通缓存文件里没有明文 `machineId`
  - 常见硬件标识候选直接塞 `Cosy-MachineId` 不起作用
  - 伪造 `Cosy-MachineToken/Cosy-MachineOS` 也不起作用
  - 无 auth / 假 auth / 真 auth / 伪 Cosy 头全部统一只回 `Signature invalid`
- 因而当前最准确的状态应表述为：
  - 现在不是“再多试几个 header 组合”就能碰出来
  - 而是已经进入了必须拿到 native 返回值或参数语义的阶段

## 2026-04-24 第二十轮审核后收敛

- 当前关于剩余问题的最小表述可以再收缩成一句话：
  - 只剩 `SecurityGuardSDKManager` 输出的 native 安全因子，以及它们如何被 `GenerateSignatureBaseString/urlSign/tokenSign` 组合成最终签名

## 2026-04-24 第二十一轮增量快照

### 快照 84

- `SecurityGuardSDKManager` 那 6 个 getter 现在可以高置信判断为“薄封装”，主要职责是返回各个 security interface 的单例对象。
- 新增静态反汇编证据：
  - `0x101aeb9d0`
  - `0x101aeba3c`
  - `0x101aebaac`
  - `0x101aebb40`
  - `0x101aebbc4`
  - `0x101aebc50`
- 这些函数的共性很明显：
  - 先加载一个 ObjC class ref
  - 再加载同一个 selector 指针
  - 最后直接走：
    - `objc_msgSend`
- 当前最合理的判断是：
  - 这几段分别对应：
    - `getUrlSignInterface`
    - `getDTSignInterface`
    - `getUMIDInterface`
    - `getStaticDataStoreInterface`
    - `getSecurityFactorsInterface`
    - 以及同簇的另一个 getter
  - 它们本身不负责签名计算
  - 真正的签名/设备因子逻辑在返回的 interface 对象实现体里

### 快照 85

- `UMIDInterface` 这条链也进一步明确了两层职责：
  - 初始化/可用性检查
  - 安全 token/标识获取
- 新增反汇编证据：
  - `0x101aba0f4`
    - 极短函数
    - 调用 `0x101aa46c4`
    - 返回布尔值
    - 当前高置信更像：
      - `initUMID:callback:` 或其包装判断
  - `0x101aba17c`
    - 存在一次性初始化标志位
    - 通过静态字节位做“只初始化一次”判断
    - 调用 `0x101a8a3cc`
    - 再调用 `0x101aa5224`
    - 成功后取对象并返回
  - 二进制字符串也已确认：
    - `No callback registered for UMID initialization`
    - `cosy/auth/umid.InitUMIDModule`
    - `cosy/auth/umid.initUMID`
    - `cosy/auth/umid.cgoInitUMID`
- 当前更稳的判断是：
  - `UMIDInterface` 不是静态常量
  - 它需要初始化
  - 且内部有“只初始化一次”的运行时保护
  - 这与 `machineId / security token` 这类设备态信息由 native 层按需生成的判断一致

### 快照 86

- `DTSignInterface` / `UrlSignInterface` 的 `IMP` 已经明显不是简单 getter，而是会：
  - retain/autorelease 入参
  - 分配临时缓冲区
  - 调用函数指针/虚表入口
  - 组装返回对象或错误对象
- 新增反汇编证据：
  - `0x101a88c94`
  - `0x101a88fd8`
  - `0x101a89524`
- 从结构上能看到：
  - 多个输入对象参与
  - 有 `calloc` / `memcpy`
  - 有错误路径返回 CF/ObjC 对象
  - 有通过对象虚表或 selector 分发的调用
- 当前高置信判断是：
  - 这些方法很可能分别对应：
    - `getSecurityFactors:error:`
    - `getGeneralConfig:callback:error:`
    - `urlSign:method:input:error:` / `tokenSign:method:input:error:` / `GenerateSignatureBaseString:input:error:` 中的一部分
  - 它们确实是 native 核心逻辑所在，而不是普通薄封装

## 2026-04-24 第二十一轮审核后收敛

- 当前 native 安全链可以更明确地拆成两层：
  1. `SecurityGuardSDKManager`
     - 负责提供各 security interface 单例
     - 本身主要是对象分发/工厂层
  2. `UrlSignInterface / DTSignInterface / UMIDInterface`
     - 才是真正进行初始化、取设备因子、签名计算、错误封装的实现层
- 这进一步说明：
  - 后续若继续推进，不该再把精力放在 manager getter 上
  - 而应重点盯住：
    - `UMIDInterface` 初始化链
    - `getSecurityFactors:error:`
    - `getGeneralConfig:callback:error:`
    - `urlSign/tokenSign/GenerateSignatureBaseString`

## 2026-04-24 第二十二轮审核后收敛

- 到当前阶段，文档里的高置信结论已经足够收敛成三句话：
  1. `plugin` 可以绕过，`37010` 本地 JSON-RPC/LSP API 面已经可以被程序化直接复用。
  2. `~/.lingma` 本地服务当前不能被“仅凭已有 token”完全替代，因为远端接口还依赖 native 签名链。
  3. 远端 `llm_completion_stream` 的真实阻塞点已经不是 endpoint、请求体或 bearer 形式，而是 `SecurityGuardSDKManager` 相关的运行时安全因子与签名结果。

- 因而从工程落地角度，当前最稳的实现判断也应同步收敛：
  - 如果目标是“脱离 plugin UI 调用模型”，这件事已经成立，直接复用本地 `37010` 即可。
  - 如果目标是“脱离本地 `Lingma` 程序，直接调用远端 HTTP API”，当前证据只支持结论：
    - 尚未打通
    - 且阻塞点集中在 native 签名与访问控制

- 本文档后续默认不再继续扩写“低成本 header 猜测”这一支线，原因已经足够明确：
  - `auth/status.token` 已能直接读到
  - 远端 endpoint 已能直接命中
  - `Authorization`、`Cosy-MachineId`、`Cosy-MachineToken`、`Cosy-MachineOS` 等简单组合已经反复验证
  - 服务端统一只返回：
    - `Signature invalid`

### 已验证的本地 API 面

- 当前已被反复实测、可以直接程序化复用的入口，集中在：
  - `ws://127.0.0.1:37010`
- 这条通道的最小协议模板已经足够固定：
  1. 建立 websocket 连接
  2. 使用 LSP framing 发送消息：
     - `Content-Length: <n>\r\n\r\n<json>`
  3. 先发 `initialize`
  4. 再发业务方法
- 额外边界也已经明确：
  - 裸 JSON 不行，会落到 `Unknown message header`
  - `initialized` 当前不是必需步骤，服务端会把它当未知方法处理

- 当前应纳入“已验证接口矩阵”的只有这几项：
  - `auth/status`
    - 可直接读取当前活跃登录态
    - 已知返回里包含 `status/name/id/accountId/token/refreshToken/userType/cloudType`
  - `config/queryModels`
    - 可直接读取当前模型注册表
    - 已知可返回 `assistant/chat/developer/inline` 等场景与多个模型项
    - 返回中的 `url/apiKey/model` 当前为空，不能据此直接推出远端开放配置
  - `auth/profile/getUrl`
    - 可直接获取 fresh profile URL 与 fresh `state`
    - 这是“绕过 plugin UI 但继续复用本地服务能力”的最早直接证据之一
  - `chat/ask`
    - 可直接触发真实聊天请求
    - 同步返回 `success = true` 之后，还会异步回推 `chat/process_step_callback`、`session/title/update`、`chat/answer`
    - 因而若要把 `37010` 封装成稳定客户端，还需要兼容服务端回推/ack 语义

- 当前不应并入“已稳定验证接口”的项：
  - `user/plan`
    - 现阶段返回错误，不应视为稳定可复用能力

- 因而当前最稳的工程判断可以再压缩成一句话：
  - 真正稳定、已经坐实、可直接落地的程序化入口是本地 `37010`
  - 不是远端 `llm_completion_stream` 本身

### 建议保留的替代落地方向

- 方向 1：把 `37010` 封装成自己的稳定 API 层。
  - 这是当前唯一已验证、可重复、无需继续协议研究远端签名链的程序化入口。
  - 适合做本地 sidecar、CLI 包装层或自建转发服务。

- 方向 2：优先寻找服务端官方支持的外部接入方式。
  - 现有材料能说明 plugin/login 参数层支持 `personalToken`、`AK/SK`、dedicated domain 等模式。
  - 但当前证据还不足以证明这些模式在你这套 `intl` 环境下可以直接替代 `big_model_endpoint` 的签名链。
  - 因而若要实现“真正脱离本地程序直连远端”，更合理的路径应是官方支持的开放接口，而不是继续依赖客户端签名协议研究。

- 方向 3：把本文档定位为“架构与证据沉淀”，而不是“远端绕过操作手册”。
  - 这样后续维护会更稳定。
  - 也更符合当前已掌握事实：真正稳定可复用的是本地服务能力，不是远端签名链本身。

## 2026-04-24 第二十三轮调试附加与运行时 SecurityGuard 探测

- 本轮先把“为什么一直附加失败”单独收敛掉了。
  - 原始 `~/.lingma/bin/2.11.1/aarch64_darwin/Lingma` 即使由当前账号自行启动，`frida` 与 `lldb` 仍会被系统拒绝附加。
  - 问题不在“是不是同一用户启动”，而在原始签名 / hardened runtime 调试策略。
  - 复制二进制后做 ad-hoc 重签名，并补 `get-task-allow` 等 entitlements 的调试副本，可以成功被 `frida` 和 `lldb` 附加。
  - 当前有效调试副本路径是：
    - `/tmp/lingma-debug/Lingma`

- 这轮把 `SecurityGuardSDKManager` 的运行时对象图真正跑活了，不再只停留在静态字符串层。
  - 已直接枚举到：
    - `DTSignInterface`
    - `UrlSignInterface`
    - `UMIDInterface`
    - `SecurityFactors`
    - `StaticDataStoreInterface`
    - `StaticEncryptInterface`
  - 并确认了各自的方法面：
    - `DTSignInterface`
      - `saveToken:token:version:error:`
      - `tokenSign:method:input:error:`
      - `GenerateSignatureBaseString:input:error:`
    - `UrlSignInterface`
      - `urlSign:method:input:error:`
    - `UMIDInterface`
      - `initUMID:callback:`
      - `getSecurityToken:`
      - `zeroTc:`
    - `SecurityFactors`
      - `getGeneralConfig:callback:error:`
      - `getSecurityFactors:error:`
      - `getMiniWua::`
    - `StaticDataStoreInterface`
      - `getExtraData:error:`
    - `StaticEncryptInterface`
      - `encryptWithAppkey:input:method:error:`
      - `decryptWithAppkey:input:method:error:`

- `UMIDInterface.getSecurityToken:` 首次拿到了真实运行时返回值。
  - 当前看到两类稳定值：
    - 长 token：
      - `P1gAG8XThLpqoN1D9VBAianqTyCn_NlKvtCi1HElzeXUwNrQZds7HUev7PHb6ottSC5-7OX_2_uKmTanGDJZYbGX`
    - 短 token：
      - `ZSN8xcjWeakhsg6VTRxoOVSivrpbIUfU`
  - 其中最关键的对应已经坐实：
    - `machine-info` 返回的 `machineToken` 就是这条长 token
    - `machine-info` 同时还能返回：
      - `machineType = 0a52ba2b917c062fa0`
  - 因而当前至少可以确认：
    - `machineToken` 与 `UMID` 长 token 已一一对上
    - `machineType` 仍未确定是由哪条 native / Go 链最终产出

- `SecurityFactors.getMiniWua::` 也已经确认是活接口，不是假链路。
  - 它的类型签名是：
    - `@32@0:8@16@24`
  - 对多组不同输入，都会快速返回不同的 base64 blob。
  - 这说明：
    - `miniWua` 不是静态常量
    - 而是受输入上下文影响的安全材料
  - 但当前仍未确认它最终流向：
    - `Cosy-Key`
    - `Authorization.info`
    - 还是 `Encode=1` body 的编码链

- 两条“看起来可能有用，但当前证据偏弱”的支线也被顺手排除了。
  - `StaticDataStoreInterface.getExtraData:error:` 对这些 key：
    - `machineId`
    - `machine_token`
    - `token`
    - `umid`
    - `wua`
    - `miniWua`
    - `appKey/appkey/AppKey`
    全部返回：
    - `Error Code=17201`
  - 这说明它不是当前最有希望直接读出机器态/安全态材料的简易 KV 出口。
  - `SecurityFactors.getSecurityFactors:error:` 在 `null` 参数下会返回：
    - `Error Code=16506`
    说明这条链是活接口，但需要额外上下文，不适合继续盲撞参数。

- 一个重要的负面结果也需要保留：
  - 在“启动后再附加”的自然业务流里，即使成功触发了：
    - `auth/device_login`
    - `chat/ask`
    也没有直接在运行中捕到：
    - `UMIDInterface.getSecurityToken:`
    - `SecurityFactors.getMiniWua::`
  - 连用 `lldb` 在启动前挂 `getSecurityToken` / `getMiniWua` 硬件断点，再跑 `machine-info`，也没有命中。
  - 这让当前判断进一步偏向：
    - 真正聊天请求主链很可能主要在 Go 侧实现
    - ObjC 这些接口要么更早阶段已完成缓存，要么只参与部分平台路径，不是当前这条 macOS 聊天主链每次现算都会经过的唯一入口

- 因而本轮结束时，最稳的下一步方向也发生了变化：
  - 不该继续把主要精力放在 ObjC wrapper 的自然命中上
  - 更应该转去追 Go 侧：
    - `cosy/remoting.addBigModelSignatureHeaders`
    - `cosy/remoting.addBigModelAuthorizationHeaders`
    - `GetAuthorizationHeader`
  - 但当前依然保留一个高价值结论：
    - SecurityGuard/native 不是“纯字符串装饰”
    - 至少 `UMID` 与 `miniWua` 这两条能力已经被运行时真实调用证据坐实

- 本轮还补了一条对 `Authorization` 结构的横向对照结论：
  - 在同一批流量采集样本中：
    - `Authorization` 中段 `base64-json` 里的 `info` 只有 1 个唯一值
    - `Cosy-Key` 也只有 1 个唯一值
    - `Authorization` 中段整体会因为 `requestId` 字段变化而变化
    - 末尾 32 位 hex 会随请求变化
  - 并且已经可以排除几种太简单的猜法：
    - 末尾 hex 不是 `md5(json)`
    - 不是 `md5(base64-middle)`
    - 不是 `md5(info)`
    - 不是 `md5(requestId)`
  - 当前更合理的判断是：
    - `info` 与 `Cosy-Key` 更像会话级或环境级稳定材料
    - 真正的 per-request 签名更可能由 `requestId/date` 与稳定密钥材料共同生成
  - 再结合后续新实例流量采集，还可以进一步收敛成：
    - 它们不是机器全局固定常量
    - 而是“单实例稳定、跨重启变化”的材料
    - 更像进程级 / 实例级安全上下文

- 同一轮对更早期的 `signature` 头也补了一条边界判断：
  - 当前流量采集里至少看到了：
    - `heartbeat`
    - `user/status`
    - `user/login`
    这几类请求带 `signature`
  - 并且：
    - `user/status` 与 `user/login` 在同一秒内可以复用同一个 `signature`
  - 这说明：
    - 早期 `signature` 头至少不是“强绑定 body 的逐请求签名”
    - 更像时间窗或固定上下文签名
  - 但当前仍不能据此证明它和后续 `Bearer COSY...` 末尾 32 位 hex 是同一条算法链

- 本轮又做了一个更有判别力的实验：
  - 起一份新的 endpoint 调试副本
  - 尝试用 `frida` override：
    - `UMIDInterface.getSecurityToken:`
    - `SecurityFactors.getMiniWua::`
    返回哨兵值
  - 再触发 `device_login + chat/ask`
- 当前看到的结果是：
  - 新实例的 `Authorization.info` 与 `Cosy-Key` 相比上一实例整体发生了变化
  - 但 override 插桩观察 本身没有出现自然命中日志
  - 且真实请求头里：
    - `Cosy-MachineToken` 仍为空
    - `Cosy-MachineType` 仍为空
  - 这进一步支持：
    - 当前聊天主链不应再优先假设“直接依赖 ObjC 层 `getSecurityToken/getMiniWua` 的自然现算”
    - 更合理的方向仍然是 Go 侧主链与实例级上下文材料

- 随后又补了一条更强的重启实验：
  - 使用同一个 `workDir`：
    - 先起一份 endpoint 调试副本抓到 `Cosy-Key/info`
    - 再杀掉进程
    - 用同一个 `workDir` 起新 PID / 新端口的实例
    - 再触发 `device_login + chat/ask`
  - 结果：
    - `Cosy-Key` 完全相同
    - `Authorization.info` 也完全相同
    - 只有：
      - `requestId`
      - `Cosy-Date`
      - 末尾 32 位 hex
      继续变化
  - 这把边界再次收紧成：
    - `info/Cosy-Key` 不是纯进程级随机值
    - 它们至少是工作目录级持久化或工作目录级派生材料
    - 后续若要再追来源，优先围绕 `workDir/cache/*`、本地 DB、或启动期工作目录初始化链，而不是只盯机器全局常量

- 本轮又对 `cache/id` 做了单点删除实验：
  - 复制当前已稳定的 `workDir`
  - 仅删除：
    - `cache/id`
  - 再起新 PID / 新端口实例并触发 `device_login + chat/ask`
  - 结果：
    - `Cosy-Key` 完全不变
    - `Authorization.info` 也完全不变
  - 这说明：
    - 当前可以进一步排除“`info/Cosy-Key` 直接取决于 `cache/id` 明文内容”这一简单猜法
    - `cache/id` 至少不是决定这两个值的唯一低成本入口

- 随后又对 `cache/user` / `cache/quota` 做了同风格的单点删除实验：
  - 复制同一个已稳定的 `workDir`
  - 删除：
    - `cache/user`
    - `cache/quota`
  - 再起新 PID / 新端口实例并重新 `device_login + chat/ask`
  - 结果：
    - `Cosy-Key` 整体变化
    - `Authorization.info` 也整体变化
  - 这让当前边界进一步收紧成：
    - `cache/id` 不是关键入口
    - `cache/user/quota` 与实例级安全材料存在更强相关
    - 后续若要继续追来源，优先应围绕：
      - `cache/user`
      - `cache/quota`
      - 它们在启动期的解密/恢复链

- 本轮继续把 `cache/user` 与 `cache/quota` 拆成单文件实验：
  - 只删 `cache/user`，保留其余文件：
    - `Cosy-Key` 改变
    - `Authorization.info` 也改变
  - 只删 `cache/quota`，保留其余文件：
    - `Cosy-Key` 不变
    - `Authorization.info` 不变
  - 这把结论进一步压缩成：
    - `cache/user` 是当前最值得优先怀疑的实例级安全材料来源
    - `cache/quota` 当前可以明显降权

- 本轮还把 `machineKey` 和 `cache/id` 的关系单独坐实了：
  - 先故意把 `cache/user` 改成非法 base64，触发启动期日志：
    - `Unable to decrypt user info. Using machineKey: ...`
  - 再把 `cache/id` 人工改成：
    - `ZZZ-ZZZ-ZZZ-ZZZ-ZZZZZZZZZZZZ`
  - 启动日志里的 `machineKey` 会同步变成：
    - `ZZZ-ZZZ-ZZZ-ZZZ-`
  - 这说明：
    - `machineKey` 与 `cache/id` 存在直接对应关系
    - 之前“删掉 `cache/id` 不影响 `Cosy-Key/info`”更合理的解释是：
      - `cache/id` 删除后会按硬件特征重建成同一个值
      - 而不是 `cache/id` 完全无关

- 最后又补了一个恢复实验，把“相关性”提升到了接近“决定性”：
  - 在删 `cache/user` 之后已经生成出新 `cache/user` 的实例上
  - 直接用稳定实例旧版 `cache/user` 覆盖回去
  - 再起新实例并重新 `device_login + chat/ask`
  - 结果：
    - `Cosy-Key` 恢复到旧基线
    - `Authorization.info` 也恢复到旧基线
  - 这说明：
    - `cache/user` 不只是相关文件
    - 它已经接近当前实例级安全材料的关键持久化来源

- 本轮又把这条链从“决定性入口”进一步推进到“直接字段映射”：
  - 先用外部 `openssl` 跑通 `cache/user` 的解密：
    - `AES-128-CBC`
    - key = `machineKey`
    - iv = `machineKey`
  - 解密后得到的明文 JSON 中，已直接看到：
    - `key`
    - `encrypt_user_info`
  - 随后做了替换实验：
    - 把 `key` 改成全 `K`
    - 把 `encrypt_user_info` 改成全 `I`
    - 再按同样 `machineKey` 重新加密写回
  - 新实例真实流量采集结果直接变成：
    - `Cosy-Key = KKK...`
    - `Authorization.info = III...`
  - 这已经足够把结论写死成：
    - `cache/user.key == HTTP Cosy-Key`
    - `cache/user.encrypt_user_info == Authorization.info`

- 随后又做了两个单字段实验，进一步缩小“尾 32 位 hex” 的输入边界：
  - 实验 A：只改 `cache/user.key`
    - `Cosy-Key` 改变
    - `Authorization.info` 保持原值
    - 尾 32 位 hex 仍然改变
  - 实验 B：只改 `cache/user.encrypt_user_info`
    - `Cosy-Key` 保持原值
    - `Authorization.info` 改变
    - 尾 32 位 hex 也仍然改变
  - 这说明：
    - 尾 32 位 hex 至少同时感知 `Cosy-Key` 和 `Authorization.info`
    - 当前不该再把它简化成“只和 requestId/date 相关”的模型

- 紧接着又做了一轮低成本公式枚举，避免后续重复试错：
  - 针对这些显式字段：
    - `Cosy-Key`
    - `Authorization.info`
    - `requestId`
    - `Cosy-Date`
    - `Cosy-User`
    - `method`
  - 枚举了：
    - 2~4 项排列
    - 常见分隔符 `'' ':' '|' ',' '\\n'`
    - 再统一做 `md5`
  - 结果：
    - 没有任何一组命中尾 32 位 hex
  - 这说明：
    - 尾签名不是这些显式字段的简单直接拼接 `md5`
    - 后续若继续协议研究，应优先怀疑：
      - 额外隐藏输入
      - 中间编码步骤
      - 或更复杂的结构化签名基串

- 本轮又把“低成本 HMAC 模型”也一起排除了：
  - 候选 key 覆盖：
    - `machineKey`
    - `Cosy-Key` 文本
    - `Cosy-Key` 解码后二进制
    - `Authorization.info` 解码前后材料
    - `security_oauth_token`
  - 候选消息覆盖：
    - `auth_request_id`
    - `auth_request_id + date`
    - `auth_request_id + key_raw`
    - `auth_request_id + info_raw`
    - `auth_request_id + key_raw + info_raw`
  - 算法覆盖：
    - `HMAC-MD5`
    - `HMAC-SHA1`
    - `HMAC-SHA256`
  - 结果仍然全部不命中尾 32 位 hex
  - 因而当前可以更明确地说：
    - 尾签名不是“可见字段 + 简单 HMAC”的直接模型

- 本轮还补了一条格式侧观察，帮助后续判断 `cache/user` 的容器结构：
  - 直接对比稳定版与重新生成版 `cache/user`
  - 结果不是“全文件完全随机变化”
  - 当前看到：
    - base64 文本长度同为 `1708`
    - 解码后原始长度同为 `1280`
    - 前 `256` 个原始字节完全一致
    - 第一个差异字节出现在偏移 `256`
  - 这让当前更合理的判断变成：
    - `cache/user` 像“固定头部 + 可变 payload”的容器
    - 影响 `Cosy-Key/info` 的关键内容更可能落在偏移 `256` 之后的可变区

- 随后又补了两组互补混合实验：
  - 方案 A：
    - 前半段取稳定版 `cache/user`
    - 后半段取重生成版 `cache/user`
  - 方案 B：
    - 前半段取重生成版
    - 后半段取稳定版
  - 两组实验的结果都很一致：
    - 都会生成第三套新的 `Cosy-Key/info`
    - 既不回到稳定版，也不等于重生成版
  - 这进一步说明：
    - `cache/user` 对实例级安全材料的影响不是“单一尾部字段决定”
    - 更像跨多个区块共同参与派生

- 随后又对 `local.db` 做了对照排除：
  - 复制同一个已稳定的 `workDir`
  - 删除：
    - `cache/db/local.db`
    - `cache/db/local.db-shm`
    - `cache/db/local.db-wal`
  - 但保留：
    - `cache/user`
    - `cache/quota`
  - 再起新 PID / 新端口实例并重新 `device_login + chat/ask`
  - 结果：
    - `Cosy-Key` 完全不变
    - `Authorization.info` 也完全不变
- 这说明：
  - 本地 DB 至少不是恢复 `info/Cosy-Key` 的必要条件
  - 当前最值得优先追的持久化来源已经进一步收敛到：
    - `cache/user`
    - `cache/quota`

## 2026-04-24 第二十四轮 Windows 安装态、缓存布局与数据库补证

### 快照 87

- 这轮回到当前真实 Windows 安装目录：
  - `C:\Users\Zipper\.lingma`
- 先把当前样本的目录结构重新扫了一遍，当前直接看到：
  - `bin`
  - `cache`
  - `extension`
  - `index`
  - `logs`
  - `model`
  - `vscode`
- 其中当前版本由：
  - `C:\Users\Zipper\.lingma\bin\config.json`
  直接写明为：
  - `cosy.core.version = 2.11.1`
- 对应二进制目录里已直接看到：
  - `Lingma.exe`
  - `LingmaLocal.exe`
  - `LingmaWin7.exe`

### 快照 88

- 这轮先补了 Windows 当前样本的本地服务拓扑证据。
- `C:\Users\Zipper\.lingma\logs\lingma.log` 多次重复出现：
  - `Using http server: 37510`
  - `Using profile websocket channel: 38510`
  - `Communication servers ready - WebSocket: 37010, HTTP: 37510, IPC: \\.\pipe\lingma-...`
- 而且这些日志跨多个版本升级点都保持一致。
- 这进一步坐实：
  - `37010` / `37510` / `38510`
  是 Windows 当前产品线里的稳定固定端口组合，不是单次实验现象。

### 快照 89

- 这轮还把当前 Windows 样本的缓存布局重新核了一遍。
- 当前主目录：
  - `C:\Users\Zipper\.lingma\cache`
  下只直接看到：
  - `db/`
  - `policy`
  - `diagnosis*.bin`
- 当前没有直接看到：
  - `cache/user`
  - `cache/id`
  - `cache/quota`
- 但在：
  - `C:\Users\Zipper\.lingma\vscode\sharedClientCache\cache`
  还能看到：
  - `id`
  - `db/local.db`
  - `policy`
  - `config.json`
- 同时这里也没有：
  - `user`
  - `quota`
- 这和前面 macOS / 调试 workDir 样本中已经坐实的 `cache/user/id/quota` 结构并不完全一致。

### 快照 90

- 为了避免把“当前没看到文件”误写成产品规律，这轮又把日志一起对照了。
- 当前日志持续出现：
  - `Deleted user info file.`
  - `Initializing database with path: C:\Users\Zipper\.lingma\cache\db\local.db`
  - `No cached user info, please login.`
- 因而当前更合理的判断是：
  - 这份 Windows 样本处在“用户态已清空或当前未缓存活跃 user info”的状态
  - 所以不能把“当前没看到 `cache/user`”直接外推成所有平台都没有这类文件
  - 更稳的说法应当是：
    - `cache/user/id/quota` 这套链已经在其他调试样本里被坐实
    - 但这份 Windows 当前样本只留下了 DB、policy、diagnosis 和一份旧的 `sharedClientCache/cache/id`

### 快照 91

- 这轮顺手只读扫了当前 Windows 主 DB：
  - `C:\Users\Zipper\.lingma\cache\db\local.db`
- 表结构里当前直接看到：
  - `supabase_token`
  - `chat_session`
  - `chat_record`
  - `lingma_memory`
  - `agent_memory`
  - 以及多张 embedding / wiki / snippet / task 相关表
- 其中最关键的边界是：
  - `supabase_token` 表存在
  - 但当前行数仍为 `0`
- 同时业务表并不是空库：
  - `chat_session = 11`
  - `chat_record = 187`
  - `lingma_memory = 11`
  - `agent_memory = 17`
- 这把当前 Windows 样本的结论进一步收紧成：
  - `local.db` 主要承载聊天、memory、agent 侧数据
  - 至少在这份样本里，它还不是恢复当前登录 token 的直接入口

### 快照 92

- 这轮还对 `LingmaLocal.exe` 做了字符串扫描，当前能直接看到多条内部 Go 包路径：
  - `cosy/core/api/auth/status.go`
  - `cosy/core/api/auth/profile.go`
  - `cosy/core/api/auth/login.go`
  - `cosy/core/api/config/endpoint.go`
  - `cosy/core/api/agent/chat/ask.go`
  - `cosy/core/transport/handler/websocket/websocket.go`
  - `cosy/core/transport/handler/http/http_server.go`
  - `cosy/bootstrap/modules/communication_servers.go`
- 这虽然不是源码，但足够继续坐实：
  - `auth/status`
  - `auth/profile/getUrl`
  - `chat/ask`
  - endpoint 路由
  - websocket / http transport
  确实都属于本地服务二进制自身，而不是 plugin 单独实现的表层逻辑。

## 2026-04-24 第二十五轮 当前 Windows 机器实跑 `lingma start` 与本地 API

### 快照 93

- 这轮直接在当前 Windows 机器上使用官方 CLI 起服务。
- 当前二进制：
  - `C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe`
- 已直接确认：
  - `lingma version` 返回 `2.11.1`
  - `lingma status -o json --workDir C:\Users\Zipper\.lingma` 返回：
    - `logged_in = false`
    - `version = 2.11.1`
  - `lingma start --help` 明确暴露：
    - `--socketPort`
    - `--httpPort`
    - `--transportType`
    - `--workDir`
    - `--endpoint`
- 这说明 Windows 当前产品线存在正式 CLI 启动链，不需要只能依赖 IDE/plugin 唤起本地服务。

### 快照 94

- 直接执行：
  - `lingma start --workDir C:\Users\Zipper\.lingma`
- 当前 `lingma.log` 实时出现：
  - `Using http server: 37510`
  - `Using profile websocket channel: 38510`
  - `Communication servers ready - WebSocket: 37010, HTTP: 37510, IPC: \\.\pipe\lingma-ed76e3`
- 系统监听端口也同步出现：
  - `127.0.0.1:37010`
  - `127.0.0.1:37510`
  - `127.0.0.1:38510`
- 这把“本地服务如何被拉起”从历史日志层推进到了当前机器的实时闭环。

### 快照 95

- 当前机器上直接用 websocket + LSP framing 复现了：
  - `initialize`
  - `auth/status`
  - `config/queryModels`
- 实际返回结果：
  - `initialize`
    - `serverInfo.name = lingma`
    - `serverInfo.version = 2.11.1`
  - `auth/status`
    - `status = 1`
    - `token = ""`
    - `refreshToken = ""`
    - `accountId = ""`
  - `config/queryModels`
    - 返回空结果 `{}`
- 这说明：
  - `37010` API 面当前是活的
  - 但当前样本未登录，所以还没有可用 token 和模型注册表

### 快照 96

- 同样通过：
  - `initialize -> auth/profile/getUrl`
  在当前机器上直接拿到了 fresh URL：
  - `http://127.0.0.1:37510/profile?...&state=3a7fd46062fa440388ca72683c56df5c...`
- 之后又做了两条只读动态验证：
  1. HTTP GET fresh `/profile?...&state=...`
     - 返回 `HTTP 200`
     - 响应体是 HTML
     - 但日志记录：
       - `Profile Invalid login parameters`
  2. 连接：
     - `ws://127.0.0.1:38510/ws?state=3a7fd46062fa440388ca72683c56df5c`
     - websocket 成功 `OPEN`
     - 日志记录：
       - `3a7fd46062 ws build success`
- 这进一步坐实：
  - fresh `state` 当前仍然能驱动 `38510` websocket 建连
  - 但当前机器未登录，所以 profile 页面仍然无法进入完整已登录态

### 快照 97

- 这轮又补了一条关键现实边界：
  - 当前机器虽然已经把本地服务拉起来了
  - `37010` 也已经能直接调用
  - 但因为 `auth/status.token = ""`
  - `config/queryModels = {}`
  所以当前还拿不到“真正可用的大模型访问”
- 因而当前最稳的工程结论是：
  - “本地 API 调用过程”已经在当前机器跑通
  - “当前机器立即拿到可用模型访问凭据”还差真实登录态
  - 一旦登录态补上，最先成立的仍然应该是：
    - 复用本地 `37010`
    - 而不是直连远端 `algo` HTTP API

## 2026-04-24 第二十六轮 当前 Windows 机器已登录态、模型注册表与 `chat/ask` 异步回包

### 快照 98

- 这轮先复核当前机器的正式登录态。
- 直接执行：
  - `Lingma.exe status -o json --workDir C:\Users\Zipper\.lingma`
- 当前返回已经变成：
  - `logged_in = true`
  - `username = zhang640@blny.de`
  - `user_type = personal_standard`
- 再直接打本地 `37010` 的 `auth/status`，当前稳定返回：
  - `status = 2`
  - `id = 5930676910898027`
  - `accountId = 5930676910898027`
  - `token = pt-5zmkcs3cUpPGP8FGb88WGkSJ`
  - `refreshToken = rt-gHWjpgS9NQ4TOhmtvmN55ELZ`
  - `expireTime = 1782107060847`
  - `userType = personal_standard`
  - `whitelist = 3`
  - `cloudType = cloud`
- 这把前一轮“当前机器还未登录”的边界推进成了：
  - 早期未登录快照已经失效
  - 当前机器现已具备真实本地登录态

### 快照 99

- 这轮把 `config/queryModels` 重新在已登录态下补读了一遍。
- 当前直接返回的场景包括：
  - `assistant`
  - `chat`
  - `developer`
  - `inline`
  - `quest`
- 稳定出现的模型 key 包括：
  - `auto`
  - `dashscope_qwen3_coder`
  - `dashscope_qwen_plus_20250428_thinking`
  - `dashscope_qwen_max_latest`
- 每个模型项当前还能直接读到：
  - `displayName`
  - `format = openai`
  - `source = system`
  - `isReasoning`
  - `isVl`
- 这说明：
  - 已登录态下的 `37010` 不只是“有 token”
  - 还已经能稳定给出场景化模型注册表

### 快照 100

- 这轮新增了一个工作区探测脚本：
  - `tools/lingma_probe.py`
- 用它把本地最小顺序链稳定固化成：
  1. `initialize`
  2. `auth/status`
  3. `config/queryModels`
  4. `chat/ask`
- 同时补到两条实现级细节：
  - 当前更推荐在 `initialize` 里带：
    - `rootUri = file:///D:/Project/lingma`
    - `workspaceFolders = [{uri,name}]`
  - 如果额外发送标准 LSP notification：
    - `initialized`
    - 服务端会直接记：
      - `unknown method: initialized`
- 因而当前更稳的协议判断是：
  - `37010` 的 transport 长得像 LSP
  - 但方法生命周期不应按标准 LSP 全套来假设

### 快照 101

- 这轮首次把 `chat/ask` 的异步回包直接抓全了。
- 当前已直接跑通的一组最小参数是：
  - `chatTask = FREE_INPUT`
  - `questionText = Reply with exactly: pong`
  - `stream = true`
  - `sessionType = chat`
  - `mode = normal`
  - 其余大量字段可以保持空串或 `null`
- 同步响应当前立即返回：
  - `success = true`
- 随后又继续收到这些异步方法：
  - `chat/process_step_callback`
    - `step = step_start`
    - `status = done`
  - `chat/process_step_callback`
    - `step = step_end`
    - `status = done`
  - 多条 `chat/answer`
    - `text = "pon"`
    - `text = ""`
    - `text = "g"`
    - `text = ""`
- 把 `chat/answer.text` 分片拼起来，当前实际得到：
  - `pong`
- 同时实时日志把这条远端主链继续补实成：
  - `POST /algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1`
- 这把“最终如何拿到可用 API”进一步收敛成：
  - 本地可编程入口已经明确是 `37010`
  - 回包方法已经明确是 `chat/process_step_callback + chat/answer`
  - 真正仍未攻克的是：
    - 脱离 Lingma 进程后如何自己复刻远端签名与编码链

### 快照 102

- 这轮继续专门验证了一个关键问题：
  - “能不能只靠 plugin jar 就实现脱离 Lingma 进程的远端直连”
- 当前补看的类包括：
  - `LanguageWebSocketService`
  - `ObjectEncoder`
- 当前确认：
  - `LanguageWebSocketService` 负责本地 websocket 的：
    - `chat/ask`
    - `auth/status`
    - `config/queryModels`
  - `ObjectEncoder` 只是在做：
    - URL encode/decode
    - `ChatContextTag` 的 Java serialize + Base64
    - 并加上 `lingma:` 前缀
- 这说明：
  - 当前 plugin jar 里没有直接露出我们要找的远端：
    - `COSY bearer` 生成器
    - `Cosy-Key` 生成器
    - `Encode=1` body 编码器
  - `ObjectEncoder` 与远端 `Encode=1` 不是同一件事

### 快照 103

- 这轮又把 Windows 当前程序本体做了只读字符串补扫：
  - `Lingma.exe`
  - `LingmaLocal.exe`
- 当前直接看到的关键词包括：
  - `Cosy-Key`
  - `Signature invalid`
  - `agent_chat_generation`
  - `Encode=1`
- 这进一步坐实：
  - 远端聊天主链和签名失败分支都在本地程序里
  - 当前真正掌握远端签名/编码链的，更像是：
    - 本地服务二进制
    - 或它依赖的 native 安全组件
- 因而到当前这一步为止，最稳结论已经可以收紧成：
  - “脱离 plugin UI 调用模型” 已经成立
  - “脱离 Lingma 进程本体直连远端 HTTP/SSE” 仍然不能落成一个真实可用实现

## 2026-04-24 第二十七轮 隔离 endpoint 流量采集与真实远端头补证

### 快照 104

- 这轮先把“不要破坏当前主安装态”落实成一套隔离流量采集实验。
- 新增了本地流量采集服务脚本：
  - `tools/lingma_capture_server.py`
- 启动方式是：
  - `python .\tools\lingma_capture_server.py --port 18080 --log .\capture\lingma-http-capture.jsonl`
- 再起一份隔离 Lingma 副本：
  - `Lingma.exe start --workDir D:\Project\lingma\capture\workdir-18080 --copyDataDir C:\Users\Zipper\.lingma --socketPort 37011 --httpPort 37511 --endpoint http://127.0.0.1:18080`
- `capture/workdir-18080/logs/lingma.log` 已直接记录：
  - `Communication servers ready - WebSocket: 37011, HTTP: 37511`
- 这说明当前已经可以：
  - 让 Lingma 本体照常走自己的 native 链
  - 但把它所有真实出站 HTTP 请求落到本地文件：
    - `capture/lingma-http-capture.jsonl`

### 快照 105

- 这轮首先坐实了“早期握手”和“主业务请求”不是同一套认证头。
- 当前抓到的早期请求包括：
  - `GET /algo/api/v1/ping`
    - `Signature = 460e2aba79cd5e919885ba6f5b1c9289`
  - `POST /algo/api/v1/heartbeat?Encode=1`
    - `Signature = 460e2aba79cd5e919885ba6f5b1c9289`
    - `body_len = 984`
  - `POST /algo/api/v3/user/status?Encode=1`
    - `Signature = 8c0c5a3e88297aba157fddc9929cc258`
    - `body_len = 240`
  - `POST /algo/api/v3/user/login?Encode=1`
    - `Signature = 8c0c5a3e88297aba157fddc9929cc258`
    - `body_len = 128`
- 这把前面的判断补得更硬：
  - 早期 `Signature` 头不是最终聊天直连所需的 bearer
  - 远端至少存在：
    - 早期状态/登录同步链
    - 登录后的 `COSY bearer` 主业务链

### 快照 106

- 这轮在隔离实例里注入一次 `auth/device_login` 后，已经直接抓到了完整的主业务请求头集合。
- 当前真实出现的头包括：
  - `Authorization: Bearer COSY.<base64-json>.<32hex>`
  - `Cosy-Date`
  - `Cosy-Key`
  - `Cosy-User`
  - `Cosy-Data-Policy`
  - `Cosy-Machineid`
  - `Cosy-Machineos`
  - `Cosy-Machinetoken = ""`
  - `Cosy-Machinetype = ""`
- 当前直接把 bearer 中段 JSON 解出来后，已看到：
  - `cosyVersion = 2.11.1`
  - `ideVersion = ""`
  - `info = ...`
  - `requestId = ...`
  - `version = v1`
- 同一隔离实例的整轮流量采集里：
  - `info` 保持不变
    - `infoLen = 664`
    - `infoSha256` 前 16 位稳定为：
      - `4a6f229b26eb37b4`
  - `Cosy-Key` 也保持不变
  - bearer 中段 `requestId` 每请求变化
  - bearer 尾 32 位 hex 也每请求变化
- 这说明当前已经掌握：
  - bearer 中段 JSON 的真实字段结构
  - 但还没掌握：
    - 尾 32 位 hex 的生成公式

### 快照 107

- 这轮最关键的新证据，是已经把真实聊天主链直接抓到了：
  - `POST /algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1`
- 同时日志记录：
  - `doAsk params.SessionType: chat, ChatMode: normal`
  - `Async chat, request id: 601e8990a5db44b4ba94aff7192cf64a`
- 远端请求头里则直接出现：
  - `X-Request-Id = 601e8990a5db44b4ba94aff7192cf64a`
- 这把关系坐实成：
  - 本地 `chat/ask.params.requestId`
    - 会进入远端：
      - `X-Request-Id`
  - bearer 中段里还有另一条独立的：
    - `requestId`
    - 它不是这个 `X-Request-Id`
- 同一聊天链这轮至少抓到了三次重试：
  - `X-Request-Id` 保持不变
  - bearer 中段 `requestId` 每次都变
  - bearer 尾 32 位 hex 每次都变
  - `Cosy-Date` 也跟着变化
- 同时聊天请求体当前已直接证明不是明文 JSON：
  - 第一次：
    - `body_len = 11476`
    - `body_sha256 = 93ef473514afeab0d29a055628a5366f7118d8e149656b41d0949ced3a1e0604`
  - 第二次：
    - `body_len = 6608`
    - `body_sha256 = da2e8a955cb87bb520cece09f0d068055643b83cba8d5bd5bf1f1d8f5c47058a`
  - 第三次：
    - `body_len = 34040`
    - `body_sha256 = d128a8bb2e224e4637448fbcc508ba4fb4b272a0fd709efd9abd4d0937f14a3c`
- 当前正文字符集是自定义高密度文本，混合：
  - 大小写字母
  - `@ * & # % ^ _ , . ( ) !`
- 继续按整轮 POST body 统计后，还能直接看到：
  - 所有 body 长度都能被 `4` 整除
  - 全量字符并集当前只有 `65` 个字符：
    - `!#$%&()*,.@ABCDEFGHIJKLMNOPQRSTUVWXYZ^_abcdefghijklmnopqrstuvwxyz`
  - 聊天 body 内当前直接搜不到：
    - `pong`
    - `Reply with exactly`
    - `601e8990a5db44b4ba94aff7192cf64a`
    - `5930676910898027`
  - `$` 出现位置也不是尾部 padding：
    - 第二条聊天 body 只有 1 个 `$`
    - 第三条聊天 body 有 2 个连续 `$`
    - 但都出现在正文中部
- 因而这轮把“为什么仍然不能脱离 Lingma 进程直连远端”明确收紧成两件硬事：
  - bearer 尾 32 位 hex 的生成链
  - `Encode=1` body 的编码链

### 快照 108

- 这轮继续只读扫二进制，又新补到一个高价值常量：
  - `COSYENC1`
- 当前已直接确认：
  - `Lingma.exe` 中能搜到：
    - `COSYENC1`
  - `LingmaLocal.exe` 中当前搜不到：
    - `COSYENC1`
- 同一二进制字符串区附近还能看到：
  - `chatTask`
  - `end_turn`
  - `modelKey`
  - `cosy_key`
- 同时代码段附近还能看到对 `COSYENC1` 的直接比较/写入痕迹。
- 这让当前协议研究方向进一步收敛成：
  - `Encode=1` 很可能不是随便拼出来的文本协议
  - 更像 Lingma 主二进制内部的一种自定义编码容器
  - `COSYENC1` 可能就是它的 magic/version 标记
- 但当前仍需保持克制：
  - 这还不能直接等价成“已经拿到可逆算法”
  - 只能说明下一步真正值得继续抠的是：
    - `COSYENC1`
    - 相关 encode/decode 分支
    - 以及它与 `chatTask / end_turn / modelKey` 这些字段的装包关系

### 快照 109

- 这轮把 `COSYENC1` 相关 `.text` 片段继续往下抠了一层，拿到了两段关键行为：
  - `0x1408a5b0c`
    - 按 `input_len + 9` 分配
    - 写入前 8 字节：
      - `COSYENC1`
    - 再写第 9 字节
    - 再继续复制 payload
  - `0x1408a5179`
    - 先校验前 8 字节是否为：
      - `COSYENC1`
    - 再读取第 9 字节
    - 再继续做后续解包
- 但这轮更关键的新证据，其实来自这些函数引用到的错误串：
  - `encrypted file requires 32-byte key`
  - `key must be 32 bytes for AES-256`
  - `failed to read nonce: %v`
  - `failed to write header: %v`
  - `failed to write encrypted data: %v`
  - `invalid nonce size: expected %d, got %d`
  - `invalid file format or not encrypted`
- 这把当前判断从：
  - “`COSYENC1` 可能就是远端 `Encode=1` body 的 magic”
  收紧修正成：
  - `COSYENC1` 更像 Lingma 本地 AES-256 加密文件容器
  - 它不是当前远端聊天 body 编码链的首选解释

### 快照 110

- 这轮同时补到了样本真实 build info：
  - `Go buildinf:`
    - `go1.22.1`
  - `path`
    - `cosy`
- 再继续扫同一份二进制，已经直接拿到了真正更贴近远端大模型请求构造的模块面：
  - `cosy/remoting.BuildBigModelSvcRequestWithConfig`
  - `cosy/remoting.doBuildRequestWithConfig`
  - `cosy/remoting.BuildBigModelAuthRequest`
  - `cosy/remoting.BuildBigModelSignRequest`
  - `cosy/remoting.buildRequest`
  - `cosy/remoting.GetMessageEncode`
  - `cosy/remoting.encodeRequestBody`
  - `cosy/remoting.createHTTPRequest`
  - `cosy/remoting.createCompressedHTTPRequest`
  - `cosy/remoting.shouldAddEncodeParam`
  - `cosy/remoting.shouldEncryptBody`
  - `cosy/remoting.addBigModelSignatureHeaders`
  - `cosy/remoting.addBigModelAuthorizationHeaders`
  - `cosy/remoting/sse.NewSseAgentChatClient`
  - `cosy/remoting.GetAgentChatClient`
- 以及对应源码路径名：
  - `cosy/remoting/big_model.go`
  - `cosy/remoting/common.go`
  - `cosy/remoting/http_client.go`
  - `cosy/remoting/definition.go`
  - `cosy/remoting/sse/client.go`
  - `cosy/remoting/sse/sse_client.go`
- 因而当前协议研究方向已经明确 pivot：
  - 不再把 `COSYENC1` 当成主突破口
  - 主突破口改成：
    - `BuildBigModelSvcRequestWithConfig`
    - `buildRequest`
    - `encodeRequestBody`
    - `shouldEncryptBody`
    - `addBigModelSignatureHeaders`
    - `addBigModelAuthorizationHeaders`

### 快照 111

- 这轮新增引入了只读 Go 符号解析工具：
  - `tools/goresym/GoReSym.exe`
- 已直接把主链函数映射到具体地址：
  - `cosy/remoting.BuildBigModelSvcRequestWithConfig`
    - `0x14087fc00 - 0x14087fe20`
  - `cosy/remoting.doBuildRequestWithConfig`
    - `0x14087fe20 - 0x140880720`
  - `cosy/remoting.buildRequest`
    - `0x140880da0 - 0x140881480`
  - `cosy/remoting.encodeRequestBody`
    - `0x140881820 - 0x140881980`
  - `cosy/remoting.shouldAddEncodeParam`
    - `0x140882540 - 0x140882680`
  - `cosy/remoting.shouldEncryptBody`
    - `0x140882680 - 0x140882760`
  - `cosy/remoting.addBigModelSignatureHeaders`
    - `0x140882760 - 0x140882ba0`
  - `cosy/remoting.addBigModelAuthorizationHeaders`
    - `0x140882ba0 - 0x140882c80`
- `buildRequest` 内部当前已经直接看清的大致顺序是：
  1. `encodeRequestBody`
  2. `shouldEncryptBody`
  3. `createHTTPRequest / createCompressedHTTPRequest`
  4. `addBigModelSignatureHeaders`
  5. `addBigModelAuthorizationHeaders`
  6. `addBasicHeaders`
  7. `logRequest`

### 快照 112

- 这轮把 `Encode=1` / body 加工的两个判定函数完整抠出来了。
- `shouldAddEncodeParam` 当前已直接坐实：
  - 先检查一个全局开关是否为：
    - `"1"`
  - 再排除路径：
    - `/api/v1/service/next_edit_predict`
    - `/algo/api/v1/organizations`
  - 然后要求方法是：
    - `POST`
    - 或 `PUT`
  - 其中 `PUT` 还要额外命中：
    - `/api/v2/remoteAgent/qoder`
- `shouldEncryptBody` 当前已直接坐实：
  - 先排除：
    - `/ncqs/api/v1/quotas`
    - `/algo/api/v1/organizations`
  - 其他情况再回落到：
    - `shouldAddEncodeParam`
- 因而当前更稳的实现判断是：
  - `Encode=1` 不是全局默认
  - body 加工与 `Encode=1` 高度相关
  - 但 body 加工还额外排除了部分接口

### 快照 113

- 这轮把 `Authorization` 真实生成层直接钉住了。
- `cosy/remoting.addBigModelAuthorizationHeaders`
  - 不自己算 bearer
  - 它会先调：
    - `cosy/remoting.trimQueryPath`
  - 再调：
    - `code.alibaba-inc.com/cosy/common/remoting/provider.GetAuthProvider`
  - 然后走 provider 认证链
- 当前真实 provider 实现已经直接落到：
  - `cosy/bootstrap/modules/adapter.(*remotingAuthProvider).AuthenticateRequest`
    - `0x141c370a0 - 0x141c37120`
- 而这个实现继续转调：
  - `cosy/auth/user.AuthToken`
    - `0x14088f740 - 0x140890140`
- `AuthToken` 内部已直接引用到：
  - `Bearer COSY.%s.%s`
  - `Cosy-User`
  - `Cosy-Date`
  - `Cosy-Key`
  - `Authorization`
  - `Cosy-Organization-Tags`
  - `Cosy-Organization-Id`
  - `Cosy-Data-Policy`
  - `AGREE`
  - `DISAGREE`
- 这说明：
  - bearer 与 `Cosy-*` 头
  - 当前确实是在 `cosy/auth/user` 层统一拼出来的

### 快照 114

- 这轮继续把 `AuthToken` 往里拆，已经直接拿到：
  - `cosy/auth/user.GetCachedUserInfo`
  - `cosy/auth/user.getAuthPayload`
  - `cosy/auth/user.getAuthSignature`
- 其中：
  - `getAuthPayload`
    - 已直接引用字段：
      - `requestId`
      - `info`
      - `cosyVersion`
      - `ideVersion`
  - `getAuthSignature`
    - 最终会调用：
      - `code.alibaba-inc.com/cosy/encrypt.Md5Encode`
- 这把 bearer 尾 32 位 hex 的判断进一步收紧成：
  - 它不是完全黑盒
  - Go 层最后一步已经明确是：
    - `Md5Encode`
- 当前真正仍未完全解开的，只剩：
  - `getAuthSignature` 在进入 `Md5Encode` 之前
  - 究竟按什么顺序拼接：
    - `trimmed path`
    - `Cosy-Date`
    - `requestId`
    - `info`
    - `Cosy-Key`
    - 以及可能的固定盐值

### 快照 115

- 这轮第一次把 `AuthToken` 的关键三段做成了运行时串证，而不再只是静态符号推断。
- 新增动态追踪脚本：
  - `tools/frida_trace_signature.py`
- 成功样本：
  - `capture/frida-signature-trace-37017-login.jsonl`
  - `capture/lingma-http-capture-frida.jsonl`
- 已运行时坐实：
  - `trimQueryPath`
    - 把：
      - `/algo/api/v2/model/list`
    - 归一成：
      - `/api/v2/model/list`
  - `getAuthPayload`
    - 输入：
      - `cache/user.encrypt_user_info`
    - 输出：
      - bearer 中段 payload
- 这意味着：
  - bearer 签名真正吃的是归一路径 `/api/...`
  - `cache/user.encrypt_user_info` 也不是直接原样进最终 `Authorization`

### 快照 116

- 对真实请求：
  - `GET /algo/api/v2/model/list`
- 当前已经从动态 trace 中拿到 `getAuthSignature` 的一组完整实参：
  - `payload`
  - `Cosy-Key`
  - `Cosy-Date`
  - 第四槽位
  - `normalized_path`
- 对应命中的真实尾签名是：
  - `a0c8bb3de47a955df4f786b4000faa0d`
- 独立复算已命中：
  - `md5(payload + "\n" + Cosy-Key + "\n" + Cosy-Date + "\n" + slot4 + "\n" + normalized_path)`
- 在当前样本里：
  - `slot4 == ""`
  - `normalized_path == "/api/v2/model/list"`
- 这把 blocker 从“尾签名算法未知”收缩为：
  - 第四槽位在非空场景下到底代表什么
  - 以及聊天主链的 `Encode=1` body 编码

### 快照 117

- 当前样本还补出了一条很关键的排除结论：
  - HTTP 头里：
    - `Cosy-Data-Policy = DISAGREE`
  - 但 `getAuthSignature` 第四槽位仍然是：
    - `""`
- 这说明：
  - 第四槽位当前不能直接等同于：
    - `Cosy-Data-Policy`
- 再结合同一批 `/model/list` 样本里：
  - `Cosy-Organization-Id == ""`
  - `Cosy-Organization-Tags == ""`
- 当前更合理的保守判断是：
  - 第四槽位是结构上固定保留的可选字段
  - 更像组织 / 项目 / 其他上下文位
  - 但仍需要抓到非空组织场景样本才能正式命名

### 快照 118

- 这轮已经把分析从“可复算”推进到“可离进程直接请求远端”。
- 首先验证的是：
  - 复用已抓到的 bearer 中段 payload
  - 用当前 `Cosy-Date`
  - 按五段公式重算尾签名
  - 直接访问：
    - `https://lingma.alibabacloud.com/algo/api/v2/model/list`
- 结果：
  - `HTTP 200`
  - 返回体已直接给出模型列表

### 快照 119

- 又进一步验证了一个关键自由度：
  - bearer 中段 payload 里的 `requestId`
  - 不需要回放旧值
  - 可以在进程外自行生成新的 UUID
- 用新的：
  - `requestId`
  - `Cosy-Date`
  - 以及已有的：
    - `info`
    - `Cosy-Key`
    - 空第四槽位
    - `normalized_path = /api/v2/model/list`
  重建整个 `Authorization`
- 再次直接访问远端 `/algo/api/v2/model/list`
  - 结果仍然：
    - `HTTP 200`

### 快照 120

- 因而当前能力边界已经可以明确改写为：
  - 对无 body 的 `/algo/api/v2/model/list`
    - 已经可以脱离 `Lingma` 进程直接调用
  - 这不再只是“回放流量采集”
  - 而是可由外部自行生成：
    - 新 `requestId`
    - 新 `Cosy-Date`
    - 新 `Authorization`
- 当前仍未完成的远端直连部分已收缩为：
  - 第四槽位在非空场景下的语义来源
  - 聊天主链 `Encode=1` body 编码

### 快照 121

- 当前外部 PoC 已不再局限于 `/model/list` 单点。
- 用同一套外部签名逻辑，把 endpoint 换成：
  - `/algo/api/v2/config/getDataPolicy?requestId=<uuid>&version=2`
- 归一路径使用：
  - `/api/v2/config/getDataPolicy`
- 结果同样返回：
  - `HTTP 200`
- 这说明当前更合理的边界是：
  - 同一条无 body GET 认证链
  - 已经可以在进程外复用
  - 而不仅是 `/model/list` 特例

### 快照 122

- 当前仓库里已经落了一个最小外部 PoC：
  - `tools/offprocess_model_list.ps1`
- 该脚本当前已实测成功：
  - `/algo/api/v2/model/list`
  - `/algo/api/v2/config/getDataPolicy?...`
- 因而当前剩余工作已经进一步聚焦为：
  - 非空第四槽位的命名
  - 带 `Encode=1` 的 body 编码链

### 快照 123

- 这轮把隔离实例的“带登录态启动方式”补实了：
  - 直接依赖 `--copyDataDir`
    - 无论源是 `C:\Users\Zipper\.lingma`
    - 还是旧的 workdir
    - 当前都不能稳定把 `cache/user` 带进新实例
  - 日志会直接出现：
    - `No cached user info, please login.`
- 但如果先把已有登录态的旧 workdir 整体克隆，再直接把克隆目录作为：
  - `--workDir`
  启动
- 则本地 `auth/status` 可直接读回：
  - `id = 5930676910898027`
  - `token = pt-5zmkcs3cUpPGP8FGb88WGkSJ`
  - `refreshToken = rt-gHWjpgS9NQ4TOhmtvmN55ELZ`
- 因而后续所有“隔离实例 + 动态 插桩观察 + 带登录态复现”场景，当前更稳的启动策略应改成：
  - 直接克隆旧 workdir
  - 不再把 `--copyDataDir` 当成登录态迁移的可靠手段

### 快照 124

- 这轮继续用 `frida` 补了 `encodeRequestBody / shouldEncryptBody` 的动态命中边界。
- 在：
  - `capture/frida-body-trace-loginseed-20260424-222811.jsonl`
  中，`2026-04-24 22:29:14 +0800` 实际命中的是：
  - `encodeRequestBody.enter`
  - `shouldEncryptBody.enter`
- 两者看到的请求都是：
  - `method = GET`
  - `url = http://127.0.0.1:18084/algo/api/v2/model/list`
  - `normalized_path = /api/v2/model/list`
- 同秒对应的 HTTP 捕获：
  - `capture/lingma-http-capture-loginseed-20260424-222811.jsonl`
  也确实是：
  - `GET /algo/api/v2/model/list`
  - `body_len = 0`
- 这把当前结论进一步修正为：
  - `encodeRequestBody / shouldEncryptBody`
    - 并不只服务于 `Encode=1` POST
    - 也会出现在更通用的请求整形路径里
  - 所以“命中这两个函数”
    - 不能再单独视为“已经发生 `Encode=1` body 编码”的铁证
  - 真正判断 body 编码是否发生，仍要同时结合：
    - 方法
    - 路径
    - `Encode=1`
    - 最终实际出站 body

### 快照 125

- 这轮把本地 capture server 推进成了“可录制 + 可转发”的透明代理模式：
  - `tools/lingma_capture_server.py`
  - 新增：
    - `--upstream-base`
    - `--chat-upstream-base`
- 具体实测组合是：
  - 本地 capture：
    - `http://127.0.0.1:18085`
  - 普通上游：
    - `https://lingma.alibabacloud.com`
  - 聊天 SSE 上游：
    - `https://lingma-api.tongyi.aliyun.com`
- 在这个模式下，克隆旧登录态 workdir 后再启动的新实例：
  - `ws://127.0.0.1:37024`
  - 已重新恢复真实可用状态
- 本地 `auth/status` 已直接返回：
  - `status = 2`
  - `name = zhang640@blny.de`
  - `whitelist = 3`
  - `privacyPolicyAgreed = true`
- 本地 `config/queryModels` 也已再次返回完整模型注册表。
- 这说明当前已经拿到一个比“纯 stub”更适合继续协议研究的环境：
  - 远端真实逻辑继续跑
  - 本地仍能完整抓出站请求

### 快照 126

- 透明代理模式下又补出一个新的动态点：
  - `Data-Policy` 同步会刷新签名材料
- 在：
  - `capture/workdir-proxyseed-20260424-223925/logs/lingma.log`
  已直接出现：
  - `update data policy sign status successfully, status: AGREE`
- 随后同一实例抓到的真实出站请求头也同步变化：
  - `Cosy-Data-Policy`
    - 从常见的 `DISAGREE`
    - 变成了 `AGREE`
  - `Cosy-Key`
    - 也不再沿用之前那组旧值
    - 而是切换成新的运行时材料
- 这说明：
  - `cache/user.key`
    - 仍是当前已知 `Cosy-Key` 的直接来源
  - 但它不是一次抓到就永久稳定
  - 至少在真实远端 `data policy` 状态同步后：
    - `Cosy-Key`
    - `Authorization.info`
    都可能跟着一起刷新
- 因而后续如果要完全脱离 `Lingma` 进程直连远端：
  - 不应长期固化旧的 `info/key`
  - 更稳做法是从最新一次真实运行态里重新提取

### 快照 127

- 这轮把“透明代理模式本身是否稳定”与“`Frida` 是否导致崩溃”拆开单独复现了。
- 新实例：
  - `capture/workdir-proxynofrida-20260424-224555`
  - `ws://127.0.0.1:37026`
  - `http://127.0.0.1:37526`
  - capture：
    - `http://127.0.0.1:18086`
- 全程不挂 `Frida`
  - 仅保留：
    - 克隆旧登录态 workdir
    - 透明代理 capture
    - 本地 `lingma_probe.py`
- 在这个组合下，已经再次稳定拿到：
  - `auth/status.status = 2`
  - `privacyPolicyAgreed = true`
  - `config/queryModels` 完整模型表
  - `chat/ask.success = true`
  - 后续 `chat/process_step_callback` 与 `chat/answer`
- 同时：
  - `capture/lingma-proxynofrida-20260424-224555.err.log`
    - 为空
  - `Lingma.exe`
    - 聊天后仍保持存活
- 因而当前更合理的判断是：
  - 上一轮 `proxyseed` 的 `0xc0000005`
    - 更像是 `Frida` 挂钩窗口或挂钩面引入的不稳定
  - 而不是透明代理模式本身不可用

### 快照 128

- 纯代理模式下，这轮已经再次抓到真实聊天主链：
  - `POST /algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1`
- 这次不是单次样本，而是同一条本地 `chat/ask` 的三次远端重试：
  1. `2026-04-24T22:46:40+08:00`
     - `X-Request-Id = b788e2adc80644dabd0b6c75d2f26160`
     - bearer 内嵌 `requestId = f7c083ce-e25e-4738-9182-69c3531f1c89`
     - `body_len = 11548`
     - `sha256 = 7fa9644251a80466616d45d45277bbd64e7e265f0072fb1bdc0d9c6d9699bcc6`
  2. `2026-04-24T22:46:47+08:00`
     - 同一 `X-Request-Id`
     - bearer 内嵌 `requestId = 867bd8c5-dded-4a5c-89a8-676ea16b7971`
     - `body_len = 6972`
     - `sha256 = 938d8b787f49a3680ac09085982b2b5e946b5e0af588aab1e1c7abcbe129c8d2`
  3. `2026-04-24T22:46:54+08:00`
     - 同一 `X-Request-Id`
     - bearer 内嵌 `requestId = fc4707fc-75b6-48f2-8416-efcdc61d3549`
     - `body_len = 34040`
     - `sha256 = 07f63f06a393473659150d69749a6495e876a3538664b2f6fba9cb69ba6638a1`
- 同一次聊天后，还继续落盘了：
  - `POST /algo/api/v2/service/business/finish?Encode=1`
  - 两次样本：
    - `body_len = 848`
    - `body_len = 852`
- 日志也同步记录：
  - `update data policy sign status successfully, status: AGREE`
  - `|Chat| doAsk params.SessionType: chat, ChatMode: normal`
  - `Async chat, request id: b788e2adc80644dabd0b6c75d2f26160`
- 这把当前聊天主链关系补得更完整：
  - 本地 `chat/ask.params.requestId`
    - 继续进入远端：
      - `X-Request-Id`
  - 同一次本地聊天
    - 会触发多次远端 `agent_chat_generation` 重试
  - 每次重试都会重新生成：
    - bearer 内嵌 `requestId`
    - bearer 尾签名
    - `Cosy-Date`
    - `Encode=1` body
- 但这几次重试共享同一个：
  - `X-Request-Id`

### 快照 129

- `2026-04-24 23:35` 这一轮再次确认：
  - `--copyDataDir`
    - 不能稳定迁移登录态
- 证据是：
  - `capture/workdir-proxynofrida-20260424-235210/cache/user`
    - 缺失
  - `capture/workdir-proxynofrida-20260424-235210/logs/lingma.log`
    - 明确出现：
      - `No cached user info, please login.`
  - `capture/lingma-http-capture-proxynofrida-20260424-235210.jsonl`
    - 只有：
      - `ping`
      - `heartbeat`

- `2026-04-24 23:37` 改成“完整克隆旧 workdir，再直接启动副本”后：
  - `capture/workdir-clone-20260424-235500`
    - 恢复为真实登录态实例
  - `python tools/lingma_probe.py --uri ws://127.0.0.1:37029`
    - `auth/status.status = 2`
    - `privacyPolicyAgreed = true`
    - `config/queryModels`
      - 返回完整模型注册表

- 这轮新的聊天流量采集文件：
  - `capture/lingma-http-capture-proxynofrida-20260424-235500.jsonl`
  再次坐实：
  - `chat/ask.requestId = b75778fc025b4dbebf5cfde250534dd0`
    - 进入远端：
      - `X-Request-Id`
  - 主链仍然是：
    - `POST /algo/api/v2/service/pro/sse/agent_chat_generation?...`
  - 同时再次抓到：
    - `POST /algo/api/v2/service/business/finish?Encode=1`
    - `POST /algo/api/v2/service/codebase/embedding_k2?Encode=1`
    - `POST /algo/api/v2/service/ask/finish?Encode=1`
    - 更晚的 `POST /algo/api/v1/tracking?Encode=1`

- 因而当前更稳的归纳是：
  - 最小稳定链：
    - 预热配置请求
    - `agent_chat_generation`
    - `business/finish`
  - 其它：
    - `ask/finish`
    - `embedding_k2`
    - `tracking`
    在这轮样本里也再次出现
    更像围绕主聊天流派生的阶段性 side-band

- 这一轮还额外把字段边界收紧了：
  - `X-Request-Id`
    - 继续只稳定出现在 `agent_chat_generation`
  - bearer 内 `requestId`
    - 每个 HTTP 请求独立变化
  - bearer 尾 32 位签名
    - 每个 HTTP 请求独立变化
  - `Cosy-Key`
    - 整段聊天窗口保持同一条值
    - 更像运行态签名上下文

### 快照 130

- `tracking` 这一路现在应当从“聊天 side-band”里单独拆出来看。
- 原因不是它和聊天无关，而是它已经稳定落在另一套出站客户端家族上：
  - 聊天主链及其近邻：
    - `model/list`
    - `getDataPolicy`
    - `agent_chat_generation`
    - `business/finish`
    - `embedding_k2`
    - `ask/finish`
    使用：
    - `Authorization`
    - `Cosy-Key`
    - `Cosy-Date`
  - `tracking`：
    - 在当前所有样本里都只使用：
      - `Appcode`
      - `Date`
      - `Signature`
    - 从未出现：
      - `Authorization`
      - `Cosy-Key`
      - `Cosy-Date`

- `2026-04-24 23:37` 这轮时间关系也更支持“后台异步 flush”：
  - `23:37:42`
    - `agent_chat_generation`
  - `23:37:54`
    - `ask/finish`
  - `23:38:02`
    - 第二次 `business/finish`
  - `23:40:07`
    - 才出现 `tracking`
  - 因此它不像主聊天请求生命周期里的同步尾巴，更像后台队列稍后上报。

- 本地与二进制证据又补了一层：
  - `capture/workdir-clone-20260424-235500/logs/lingma.log`
    - 出现：
      - `[tracker] Initialized successfully`
      - `Module tracker started successfully`
  - `capture/goresym-lingma.json`
    - 出现：
      - `cosy/bootstrap/modules.(*TrackerModule).Start`
      - `cosy/tracker.Initialize`
      - `cosy/tracker.getOrCreateQueue`
      - `cosy/tracker.RecordInlineChatModification`
      - `cosy/tracker.RecordAgentModification`
      - `cosy/tracker.reportAICodeCommit`
      - `cosy/core/api/tracker.InitHandlers`

- 所以当前最稳的归纳是：
  - Lingma 至少同时存在两套远端调用家族
  - `tracking` 更可能来自独立 `tracker` 模块
  - 它与聊天行为相关，但并不是主 `remoting` Bearer 发送器里的普通同类请求
  - 它更像事件批量上报器

- `tracking` 的语义层证据也补上了：
  - `C:\Users\Zipper\.lingma\logs\lingma.log`
    - `post report data failed: Post ".../algo/api/v1/tracking?Encode=1"...`
    - `Reported 0/7 events`
  - `C:\Users\Zipper\.lingma\vscode\sharedClientCache\logs\lingma-2026-01-03T10-29-00.938.log`
    - `Failed to report event "back-flow-mtree"...`
    - `Failed to report event "back-flow-edit-seq"...`
    - 大量 `Reported x/y events`

- 因而当前更细的归纳是：
  - `tracking` 不只是“旧签名链路上的一个 endpoint”
  - 它更像：
    - report/event 子系统
    - 批量 flush 队列
    - 周期性或延后上报

### 快照 131

- `capture/lingma-http-capture-proxynofrida-20260424-235500.jsonl` 里的 body 量化结果把“发送器家族”和“body 装甲层”进一步拆开了：
  - `user/status`
    - `len = 240`
    - 去重字符数 `53`
    - 无数字
  - `heartbeat`
    - `len = 1024`
    - 去重字符数 `58`
    - 无数字
  - `business/finish`
    - `len = 848`
    - 去重字符数 `57`
    - 无数字
  - `agent_chat_generation`
    - `len = 11592`
    - 去重字符数 `65`
    - 无数字
  - `tracking`
    - `len = 18232`
    - 去重字符数 `64`
    - 无数字

- 因而现在更稳的判断是：
  - `tracking` 的头家族仍然属于旧签名链路
  - 但它的 `Encode=1` body 外观又和聊天主链高度接近
  - 更像是“不同 sender / 同类可打印装甲层”
  - 也就是上层认证与调用入口分家了，但底层 body codec 很可能仍有共享

- 现有 `frida` 结果也支持“公共底层闸门”而不是“聊天专用编码器”：
  - `encodeRequestBody`
  - `shouldEncryptBody`
  - 都会命中：
    - `GET /api/v2/model/list`
    - `GET /api/v2/config/getDataPolicy`
  - 所以它们更像公共 URL / body 处理层，而不是单独聊天 sender 的专用逻辑

- `tracking` 的内部重复块密度又显著高于聊天首包，更像多事件批量容器：
  - `tracking`
    - `DxK^PSWhBMn*`：`20` 次
    - `JOFYN(Lbu*By`：`27` 次
    - `j@z^VR#kjMz%`：`9` 次
    - `l@VfjMN(l@Tf`：`7` 次
    - `NZKbDZFM`：`4` 次
  - `tracking` 的 16 字符窗口高频片段：
    - `DoByBMaQV^_(j^#Q`：`14` 次
    - `^_(j^#QV@_Il@&fV`：`14` 次
    - `#QV@_Il@&fVMN*Go`：`14` 次
  - 同轮第一个 `agent_chat_generation` 大包的高频 16 字符窗口最高只有 `4` 次

- 这使当前模型进一步收敛为：
  - `tracking` 不是主聊天 remoting sender 的普通尾随请求
  - 它属于 `tracker` / report-event 子系统
  - 它很可能复用了 Lingma 统一的 `Encode=1` 可打印装甲层
  - 但其上层明文结构更像“多事件批量 flush 后再统一编码”

### 快照 132

- `tracking` 的调度模型现在也能进一步收紧了：
  - `capture/workdir-clone-20260424-235500/logs/lingma.log`
    - `20:44:27`
      - `Reported 27/27 events`
    - `20:47:27`
      - `Reported 0/0 events`
    - `20:50:27`
      - `Reported 0/0 events`
    - `22:48:57`
      - `Reported 15/15 events`
    - `22:51:57`
      - `Reported 0/0 events`
    - `22:54:57`
      - `Reported 0/0 events`
    - `23:40:07`
      - `Reported 15/15 events`
  - 连续 flush 间隔：
    - `179.987s`
    - `179.998s`
    - `179.225s`
    - `180.009s`

- 因而现在更稳的判断是：
  - `tracker` 更像固定约 `180s` 的周期任务
  - 聊天行为先写 event queue
  - 定时器再把积累的 event 批量 flush 成一个 `tracking` 请求
  - 所以 `tracking` 并不是“聊天结束立即发”的同步 follow-up

- 本地 queue 的存在也被日志钉住了：
  - `capture/workdir-clone-20260424-235500/logs/lingma.log:1393`
    - `[tracker] Initialized successfully, storagePath=...\\cache\\ai_tracker`
  - `C:\Users\Zipper\.lingma\logs\lingma.log:163416`
    - `[tracker] Initialized successfully, storagePath=C:\\Users\\Zipper\\.lingma\\cache\\ai_tracker`
  - 但当前磁盘检查结果是：
    - `cache/ai_tracker`
      - 目录存在
      - 成功 flush 后通常为空
    - `cache/db/local.db`
      - 没有直接的 `tracker/report/queue` 表

- 这使本地实现模型进一步收敛为：
  - `tracker` 有独立 `storagePath`
  - 更像专用 queue 存储，而不是业务 SQLite 表
  - 成功 flush 后 queue 可能被清空，因此现场经常只剩空目录

- 两次关键 tracking 大包也已经能和日志里的 event 数稳定对账：
  - `capture/lingma-http-capture-proxynofrida-20260424-224555.jsonl`
    - `22:48:57`
    - `body_len = 18152`
    - 同时日志：
      - `Reported 15/15 events`
  - `capture/lingma-http-capture-proxynofrida-20260424-235500.jsonl`
    - `23:40:07`
    - `body_len = 18232`
    - 同时日志：
      - `Reported 15/15 events`

- 因而：
  - `Reported x/y events` 对应的确实是 batched payload
  - `tracking` body 体积会随着 batch 规模明显变化
  - 当前还没法把某个重复片段精确映射成“一条 event”
  - 但“单请求承载多 event”已经不只是推断

### 快照 133

- `tracking` 的“本地入口 -> 聚合对象 -> 出网 report”链路又往前推进了一层。

- `cosy/core/api/tracker` 旁边已经能看到两类明确的本地 handler 形状：
  - `RecordQuestApplyHandler`
    - 邻近 typed handler 入参：
      - `WorkspacePath`
      - `SessionId`
      - `TaskId`
      - `FileChanges []definition.QuestApplyFileChange`
    - 而 `QuestApplyFileChange` 又自带：
      - `FilePath`
      - `OriginalContent`
      - `ModifiedContent`
  - `VerifyCommitHandler`
    - 邻近 typed handler 入参：
      - `WorkspacePath`
      - `CommitId`

- 与此同时，符号表还直接出现：
  - `cosy/tracker.RecordNesModification`
  - `cosy/tracker.RecordInlineChatModification`
  - `cosy/tracker.RecordAgentModification`
  - 以及独立 typed handler：
    - `WorkspacePath`
    - `FilePath`
    - `OriginalContent`
    - `ModifiedContent`

- 这说明 `tracker` 的本地采集层不是只吃“事件名 + 少量标签”：
  - 它在进入出网上报前
  - 已经掌握文件级 before/after 内容
  - 以及 `workspace/session/task/request` 这一类上下文

- `back_flow` 侧的 reporter 字段也开始和日志失败项对上了：
  - `back_flow.AgentStartReporter`
    - `sessionId`
    - `requestId`
    - `workspacePath`
    - `mtreeDiff`
  - `back_flow.EditSeqReporter`
    - `workspacePath`
    - `reportReason`
    - `editSequence`
  - `back_flow.NesReporter`
    - `sessionId`
    - `requestId`
    - `changes`
    - `workspacePath`
  - 这和历史日志里的：
    - `[back-flow][agent-start]...[requestId] get mtree diff failed`
    - `Failed to report event "back-flow-mtree"...`
    - `Failed to report event "back-flow-edit-seq"...`
    - 开始形成字段层闭环

- `tracking` 上报前的中间对象也被 `aicodestats` 这一层钉出来了：
  - `aicodestats.RecordParams`
    - `WorkspacePath`
    - `FilePath`
    - `OriginalContent`
    - `AIModifiedContent`
    - `Brand`
    - `Product`
    - `Scenario`
    - `SessionID`
    - `UserQueryBusinessId`
    - `ExtInfo`
  - `types.LineDetail`
    - `Lines`
    - `Type`
    - `Brand`
    - `Product`
    - `Scenario`
    - `SessionID`
    - `UserQueryBusinessId`
  - 聚合对象：
    - `UserQueryAIStats`
    - `CommitAIStats`
  - 上报前转换函数：
    - `(*UserQueryAIStats).ToAICodeChangeReport`
    - `(*CommitAIStats).ToAICodeCommitReport`

- 对应的最终 report 结构也已经明确出现：
  - `AICodeChangeReport`
    - 更像用户查询维度的改动摘要
  - `AICodeCommitReport`
    - 更像 commit 维度的 AI 代码统计摘要

- 因而现在更稳的模型是：
  - 本地先记录 richer diff-level 数据
    - 包括原文、改后内容、行级归因、session、user-query 等
  - 再按 user query 或 commit 聚合成统计对象
  - 然后转换成 `AICodeChangeReport` / `AICodeCommitReport`
  - 最后才统一装进 `tracking?Encode=1` 的批量包

- 这让 `tracking` 的 pre-encode 上层 payload 判断从“事件名批量”进一步收紧为：
  - 更可能是压缩后的 change/commit report 批量集合
  - 而不是原始全文源码直接出网

### 快照 134

- `tracking` 的上层对象现在更像至少并行存在两条风格不同的来源，而不只是单一 report 容器。

- 第一条是更通用的事件对象入口：
  - `go.shape.struct {`
    - `EventType`
    - `RequestId`
    - `IdeType`
    - `IdeVersion`
    - `PluginPublisher`
    - `PluginName`
    - `EventData map[string]string`
  - 同时存在：
    - `cosy/core/transport/handler/rpc.RegisterTypedHandler[...]`
    - 入参正是这组 `eventType/requestId/eventData` 结构
  - 这说明 Lingma 进程内部至少还有一条“通用事件对象”入口
    - 不等同于前面已经坐实的 `aicodestats` rich diff/report 链

- 第二条仍然是 AI 代码统计 report 分支，但这次又多了显式的 report params 层：
  - `aicodestats.AICodeChangeParams`
    - `ChangeID`
    - `Scenario`
    - `Product`
    - `Action`
    - `ModelLevel`
    - `CreatedAt`
  - `aicodestats.AICodeCommitParams`
    - `RepoName`
    - `BranchName`
    - `Product`
    - `Message`
    - `CommitTs`
    - `CreatedAt`
  - 同时出现函数签名类型：
    - `func(*aicodestats.AICodeChangeParams) *aicodestats.AICodeChangeReport`
    - `func(*aicodestats.AICodeCommitParams) *aicodestats.AICodeCommitReport`

- 这说明 `AICodeChangeReport` / `AICodeCommitReport` 前面
  - 很可能还隔着一层显式 metadata params
  - 而不是只从聚合对象一步直接变成最终 report

- 更关键的新证据是：
  - 二进制里已经明确出现 `[]aicodestats.AICodeCommitReport`
  - 而函数区又紧挨着：
    - `cosy/tracker.reportAICodeCommit`
    - `cosy/tracker.buildCommitItemsJSON`
    - `cosy/tracker.extractRepoName`

- 所以当前最强的静态推断变成：
  - commit 统计分支
    - 很可能已经收敛到：
      - `AICodeCommitReport` 切片
      - `buildCommitItemsJSON`
      - `tracking?Encode=1`
  - 但 change 分支还没露出同等强度的：
    - `[]AICodeChangeReport`
    - 或 `buildChangeItemsJSON`

- 因而现在对 `tracking` 外层对象的判断应更新为：
  - 至少可能并行承载：
    - 通用 `eventType/eventData` 事件对象
    - `aicodestats` 派生的 change/commit report 对象
  - 但这两类对象是否最终在同一个 envelope 中混装
    - 目前还没有明文字段名能完全钉死

- 本地 `ai_tracker` 目录这次也做了更系统的复核：
  - 已定位到多组目录：
    - `capture/workdir-18080/cache/ai_tracker`
    - `capture/workdir-body-20260424-222313/cache/ai_tracker`
    - `capture/workdir-clone-20260424-235500/cache/ai_tracker`
    - `capture/workdir-frida-20260424-214327/cache/ai_tracker`
    - `capture/workdir-frida-20260424-214357/cache/ai_tracker`
    - `capture/workdir-loginbody-20260424-222716/cache/ai_tracker`
    - `capture/workdir-loginseed-20260424-222811/cache/ai_tracker`
    - `capture/workdir-proxynofrida-20260424-224555/cache/ai_tracker`
    - `capture/workdir-proxynofrida-20260424-233125/cache/ai_tracker`
    - `capture/workdir-proxynofrida-20260424-235210/cache/ai_tracker`
    - `capture/workdir-proxyseed-20260424-223925/cache/ai_tracker`
    - `C:\Users\Zipper\.lingma\cache\ai_tracker`
    - `C:\Users\Zipper\AppData\Local\.lingma\ai_tracker`
  - 其中再次抽查的几组关键目录当前都为空

- 这继续支持：
  - `ai_tracker` 更像短生命周期 queue / 中间缓存
  - 成功 flush 后内容会被清空
  - 仅靠事后磁盘残留很难直接拿到 `tracking` 最外层 envelope

### 快照 135

- 这次不再只依赖 `goresym`，而是直接从真实安装的主程序里抽了 JSON tag 字面量。

- 命中的程序路径：
  - `C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe`
  - `Length = 102532096`
  - `LastWriteTime = 2026-04-17 21:24:17`

- 可复用的 tag 快照已落盘：
  - `capture/extracted-json-tags-2.11.1.txt`

- 其中与 `tracking/tracker/aicodestats` 最相关的字段族，已经明显分成两套命名风格。

- 一套偏通用事件对象：
  - `json:"event"`
  - `json:"event_data"`
  - `json:"event_time"`
  - `json:"event_type"`
  - `json:"eventData"`
  - `json:"eventType"`
  - `json:"request_id"`
  - `json:"requestId"`
  - `json:"events"`
  - `json:"report"`

- 另一套则明显贴近前面拼出的 change/commit report 语义：
  - `json:"change_id"`
  - `json:"commit_hash"`
  - `json:"commit_id"`
  - `json:"commit_message"`
  - `json:"commit_ts"`
  - `json:"repo_name"`
  - `json:"branch_name"`
  - `json:"product"`
  - `json:"product_breakdown"`
  - `json:"scenario"`
  - `json:"scenario_breakdown"`
  - `json:"original_commit_ids"`
  - `json:"parent_commit_ids"`
  - `json:"ai_lines_added"`
  - `json:"ai_lines_deleted"`
  - `json:"created_at"`
  - `json:"createdAt"`

- 本地采集入口相关字段也继续能对上：
  - `json:"workspace_path"`
  - `json:"workspacePath"`
  - `json:"session_id"`
  - `json:"sessionId"`
  - `json:"task_id"`
  - `json:"taskId"`
  - `json:"file_path"`
  - `json:"file_changes"`
  - `json:"fileChanges"`

- 这一轮的新约束是：
  - `eventType/eventData/requestId/events/report`
    - 不只是 `goresym` 匿名 struct 里的还原
    - 也是主程序二进制中的真实 JSON tag
  - `change_id/commit_ts/repo_name/product_breakdown/scenario_breakdown/original_commit_ids/...`
    - 同样是主程序二进制中的真实 JSON tag
  - 因此 `tracking` 上层“至少并行存在两套 schema 家族”这件事
    - 已经从符号推断推进成了程序字面量证据

- 当前仍然没有坐实的边界：
  - 是否真的存在一个最外层 `events` 数组
  - 是否还并行存在一个 `reports` 数组
  - 两类对象最终是否混装在同一个 envelope

### 快照 136

- 我又用样本相似度把 `tracking` 和聊天主链分开量化了一次，不再只靠“看起来像重复块”。

- 对两次大 `tracking` 包：
  - `capture/lingma-http-capture-proxynofrida-20260424-224555.jsonl`
    - `body_len = 18152`
  - `capture/lingma-http-capture-proxynofrida-20260424-235500.jsonl`
    - `body_len = 18232`

- 先看最表面的装甲串：
  - 公共前缀长度：`0`
  - 公共后缀长度：`1`

- 这说明：
  - 两次 `tracking` body 的外层字符串前后缀几乎完全不同
  - 所以不能用“前缀不一样”来否定它们属于同一种内部模板
  - `Encode=1` 外层很可能还叠了按请求变化的扰动因子

- 但如果按 16 字符滑动窗口看内部相似度：
  - 第一个 `tracking` 样本唯一窗口数：`9407`
  - 第二个 `tracking` 样本唯一窗口数：`9322`
  - 交集：`3943`
  - Jaccard：`0.2667`

- 共享窗口里直接能看到大量稳定片段：
  - `IIVRVkx,BrBEdYu(`
  - `NZKbDZFMJgWwmxdL`
  - `dLBMn*uHLhD(.iB*`

- 这说明：
  - 尽管外层装甲让前后缀很不稳定
  - 两次大 `tracking` 包内部仍然共享大量稳定子结构
  - 更像同一种 tracker/report 批量模板的两个实例

- 再和同一份流量采集里的聊天主请求对照：
  - 文件：
    - `capture/lingma-http-capture-proxynofrida-20260424-235500.jsonl`
  - 对比对象：
    - `tracking`
    - 首个 `agent_chat_generation`
  - 结果：
    - `tracking` 唯一 16 字符窗口数：`9322`
    - `agent_chat_generation` 唯一 16 字符窗口数：`11275`
    - 交集：`208`
    - Jaccard：`0.0102`

- 这个对照进一步收紧为：
  - `tracking` 与聊天主请求虽然共享 `Encode=1` 这一层
  - 但内部稳定片段族几乎不是一回事
  - 因而 `tracking` 不是聊天主链 body 的简单放大版
  - 更符合独立 `tracker/report` 批量通道模型

### 快照 137

- 这次直接在真实 `Lingma.exe` 里做 ASCII 精确命中，不再只看 `goresym` 函数表。

- 关键命中程序：
  - `C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe`

- `buildCommitItemsJSON` 的精确命中偏移：
  - `63978332`

- 它附近出现了一个更紧的 commit 打包局部簇：
  - `cosy/tracker.reportAICodeCommit`
  - `cosy/tracker.reportAICodeCommit.func1`
  - `cosy/tracker.buildCommitItemsJSON`
  - `code.alibaba-inc.com/cosy/ai-code-commit-tracker.WrapAICodeCommitReport`
  - `cosy/tracker.extractRepoName`

- 这一步的新价值在于：
  - `WrapAICodeCommitReport`
    - 不只是概念推断
    - 现在也在真实二进制中被精确命中
    - 并且直接挨着 `buildCommitItemsJSON/reportAICodeCommit`

- 因而 commit 分支的静态链路可以进一步收紧成：
  - `ToAICodeCommitReport`
  - `AICodeCommitReport`
  - `WrapAICodeCommitReport`
  - `buildCommitItemsJSON`
  - `reportAICodeCommit`
  - `tracking`

- 这里仍保留边界：
  - 还没有拿到 `WrapAICodeCommitReport` 的函数体
  - 不能直接断言它就是“最外层 envelope builder”
  - 但它与 `buildCommitItemsJSON/reportAICodeCommit` 的局部共现
    - 已经明显强于此前的弱推断

- 同时，对称的 change 分支命名仍未出现：
  - `goresym` 中目前只有：
    - `reportAICodeCommit`
    - `buildCommitItemsJSON`
  - 真实二进制精确搜索中：
    - `WrapAICodeCommitReport`
      - `1 hit`
    - `buildCommitItemsJSON`
      - `1 hit`
    - `reportAICodeCommit`
      - `2 hits`
    - 但以下都未命中：
      - `WrapAICodeChangeReport`
      - `buildChangeItemsJSON`
      - `reportAICodeChange`

- 这让先前判断进一步变硬：
  - `commit report` 分支
    - 已经非常接近完整的“report -> wrap -> items JSON -> tracking”静态链
  - `change report` 分支
    - 目前仍只到 `ToAICodeChangeReport` / `AICodeChangeReport`
    - 缺少对称的 wrapper / builder / sender 命名

- 另外也把 `items/events` 精确命中做了居中核对：
  - `json:"items"`
    - 落在一组更泛用的列表/分页字段附近：
      - `title`
      - `scope`
      - `stage`
      - `items`
      - `total`
      - `order`
      - `level`
  - `json:"events"`
    - 落在一组更像 diff/edit 结构的字段附近：
      - `origin`
      - `target`
      - `events`
      - `oldUri`
      - `newUri`
      - `fixEnd`
      - `chunks`
  - `json:"report"`
    - 对真实二进制做完整 ASCII 精确匹配时当前未命中

- 这进一步说明：
  - `items/events/report`
    - 目前仍只能作为 `tracking` 最外层候选字段族
    - 还不是 commit 打包链的直接局部证据
  - 当前更强、也更应优先依赖的静态证据
    - 是 `WrapAICodeCommitReport + buildCommitItemsJSON + reportAICodeCommit` 这个真实二进制局部簇

- 另外又补出一层命名风格证据，但这一点需要收紧：至少有一部分 commit 字段同时存在 `camelCase` 与 `snake_case` 两套 JSON tag，并不是每个同名字段都能直接并入 `tracking` commit 上报链。

- 真实二进制精确命中：
  - `json:"parentCommitIds,omitempty"`
    - `33686538`
  - `json:"parent_commit_ids,omitempty"`
    - `33703824`
  - `json:"originalCommitIds,omitempty"`
    - `33719403`
  - `json:"original_commit_ids,omitempty"`
    - `34132140`
  - `json:"repoName"`
    - `33245930`
  - `json:"repo_name"`
    - `33287640`
  - `json:"commit_ts"`
    - `33287667`
  - `json:"commitTs"`
    - 当前未命中

- 但放回局部邻域以后，强弱要区分开：
  - `parentCommitIds`
    - 邻域里直接出现 `code.alibaba-inc.com/cosy/ai-code-commit-tracker`
  - `parent_commit_ids`
    - 邻域里仍贴着 `*map.bucket[string]*aicodestats.UserQueryFileStats`
  - `originalCommitIds`
    - 邻域里直接贴着 `*func(string) (*aicodestats.UserQueryAIStats, error)`
  - `original_commit_ids`
    - 继续位于前面已经确认过的 commit report 字段区附近

- 相对地：
  - `repoName`
    - 邻域落在一组更像 `longruntask` 的字段旁边：
      - `RepoType`
      - `*longruntask.TaskRuntime`
      - `*longruntask.PullRequest`
      - `*longruntask.TaskVersion`
      - `*longruntask.BuildStatus`
      - `*longruntask.PortForward`
    - 目前不能直接拿它去证明 `tracking` commit 分支里也存在 `repoName -> repo_name` 对应关系

- 因而现在更稳的表述是：
  - 至少对 `ParentCommitIds / OriginalCommitIds` 这组字段来说
    - commit 分支里很像并行存在：
      - 一套偏内部/中间层的 `camelCase` 对象
      - 一套更贴近最终 report/wire 的 `snake_case` 对象
  - 换句话说，更像“内部对象 -> report/wire 对象 -> tracking”
    - 但这个结论当前主要由 `parent/original commit ids` 这组字段支撑

### 快照 138

- 继续把真实二进制里的精确命中点串起来后，commit 分支现在更像一条“三段式静态链”，而不是单个包内一路做完。

- 第一段是 `ai-code-commit-tracker` 自己的聚合/验证区。
- 在 `63969024` 到 `63970454` 这一带，出现了一整段连续 package 局部簇：
  - `code.alibaba-inc.com/cosy/ai-code-commit-tracker.(*CommitAIStats).ToAICodeCommitReport`
  - `code.alibaba-inc.com/cosy/ai-code-commit-tracker.newServiceInternal`
  - `code.alibaba-inc.com/cosy/ai-code-commit-tracker.NewHybridBaselineProvider`
  - `code.alibaba-inc.com/cosy/ai-code-commit-tracker.NewRecorder`
  - `code.alibaba-inc.com/cosy/ai-code-commit-tracker.NewVerifier`
  - `code.alibaba-inc.com/cosy/ai-code-commit-tracker.(*service).RecordAIModification`
  - `code.alibaba-inc.com/cosy/ai-code-commit-tracker.(*service).getOriginalCommitIds`
  - `code.alibaba-inc.com/cosy/ai-code-commit-tracker.(*service).mergeWithOriginalRecords`
  - `code.alibaba-inc.com/cosy/ai-code-commit-tracker.(*service).mergeBreakdown`
  - `code.alibaba-inc.com/cosy/ai-code-commit-tracker.(*service).mergeFileStats`
  - `code.alibaba-inc.com/cosy/ai-code-commit-tracker.(*service).CleanupRecords`

- 这说明：
  - `CommitAIStats`
    - 背后不是空名字
    - 而是真的挂在一套 service 级聚合/merge 逻辑上
  - “内部对象层”现在可以更具体地落到：
    - `ai-code-commit-tracker.(*service)`
    - 及其 `getOriginalCommitIds / mergeWithOriginalRecords / mergeBreakdown / mergeFileStats`

- 第二段是类型/签名元数据区，而不是发送区。
- 当前至少有三组精确点属于这一层：
  - `33142030` 邻域：
    - `ToAICodeCommitReport`
    - `ToAICodeChangeReport`
    - `*aicodestats.Service`
    - `*aicodestats.service`
    - `*aicodestats.Storage`
    - `getOriginalCommitIds`
  - `33435641` / `33435674` 邻域：
    - `*aicodestats.AICodeCommitParams`
    - `*aicodestats.AICodeCommitReport`
    - `*aicodestats.UserQueryFileStats`
    - `*aicodestats.AICodeChangeParams`
    - `*aicodestats.AICodeChangeReport`
  - `34533385` 邻域：
    - `func(*aicodestats.AICodeCommitParams) *aicodestats.AICodeCommitReport`
    - `func(*aicodestats.AICodeChangeParams) *aicodestats.AICodeChangeReport`

- 这意味着：
  - 在聚合层和发送层之间
  - 的确还隔着一层更显式的：
    - `AICodeCommitParams`
    - `AICodeCommitReport`
    - `params -> report` 转换签名

- 第三段才是 `tracker` sender 区，也就是前面已经确认过的 `63978249` 到 `63978425` 局部簇：
  - `cosy/tracker.reportAICodeCommit`
  - `cosy/tracker.reportAICodeCommit.func1`
  - `cosy/tracker.buildCommitItemsJSON`
  - `code.alibaba-inc.com/cosy/ai-code-commit-tracker.WrapAICodeCommitReport`
  - `cosy/tracker.extractRepoName`

- 所以当前最稳的静态模型可以升级成：
  1. `ai-code-commit-tracker.(*service)`
     - 负责 commit 维度聚合、回溯和 merge
     - 形成 `CommitAIStats`
  2. `(*CommitAIStats).ToAICodeCommitReport`
     - 转成 `AICodeCommitReport`
     - 且旁边存在 `AICodeCommitParams -> AICodeCommitReport` 的显式函数签名
  3. `WrapAICodeCommitReport`
     - 很可能把 report 再桥接成更接近 sender 的对象
  4. `buildCommitItemsJSON`
     - 统一装成发送前 JSON
  5. `reportAICodeCommit`
     - 送往 `tracking`

- 这一步里 `WrapAICodeCommitReport` 的定位也更清楚了：
  - 它不该直接写死成“最外层 envelope builder”
  - 但现在很像：
    - `aicodestats` report 形态
    - 进入 `tracker` sender 形态
    - 之间的桥接器

### 快照 139

- 这轮主要做的是纠偏和细化，而不是简单增加新名词。

- 先纠正一个容易误读的点：
  - 之前有一个 `AICodeCommitReport` 命中偏移：
    - `63978406`
  - 这次把它居中展开后可以确认，附近只有：
    - `cosy/tracker.buildCommitItemsJSON`
    - `code.alibaba-inc.com/cosy/ai-code-commit-tracker.WrapAICodeCommitReport`
    - `cosy/tracker.extractRepoName`
  - 因而：
    - `63978406`
      - 本质上只是 `WrapAICodeCommitReport` 这个函数名内部的子串
    - 它不能再被当成“独立的 `AICodeCommitReport` 类型命中点”

- 真正新增的有效证据在 `63976516` 这一带。
- 围绕 `63976574` 的 `AICodeCommitParams` 命中点，邻域里能看到：
  - `code.alibaba-inc.com/cosy/ai-code-commit-tracker.(*Verifier).mergeFileAIStats`
  - `code.alibaba-inc.com/cosy/ai-code-commit-tracker.(*Verifier).supplementDeletedLinesFromModifications`
  - `code.alibaba-inc.com/cosy/ai-code-commit-tracker.(*Verifier).filterValidDeletedLines`
  - `type:.eq.code.alibaba-inc.com/cosy/ai-code-commit-tracker.AICodeCommitParams`
  - `type:.eq.code.alibaba-inc.com/cosy/ai-code-commit-tracker.AICodeChangeParams`
  - `type:.eq.code.alibaba-inc.com/cosy/ai-code-commit-tracker.AICodeChangeFileReport`
  - `type:.eq.code.alibaba-inc.com/cosy/ai-code-commit-tracker.VerifyParams`
  - `type:.eq.code.alibaba-inc.com/cosy/ai-code-commit-tracker.Storage`
  - `type:.eq.code.alibaba-inc.com/cosy/ai-code-commit-tracker.Recorder`
  - `type:.eq.code.alibaba-inc.com/cosy/ai-code-commit-tracker.Verifier`

- 对更严格的精确搜索，目前确认：
  - 命中：
    - `type:.eq.code.alibaba-inc.com/cosy/ai-code-commit-tracker.AICodeCommitParams`
  - 未命中：
    - `type:.eq.code.alibaba-inc.com/cosy/ai-code-commit-tracker.AICodeCommitReport`
    - `type:.eq.code.alibaba-inc.com/cosy/ai-code-commit-tracker.CommitAIStats`
    - `type:.eq.code.alibaba-inc.com/cosy/ai-code-commit-tracker.AICodeChangeReport`

- 这说明：
  - `ai-code-commit-tracker` 包内部至少已经坐实持有：
    - `AICodeCommitParams`
    - `AICodeChangeParams`
    - `AICodeChangeFileReport`
    - `Verifier / Recorder / Storage / VerifyParams`
  - 也就是说，“聚合层和 report 层之间隔着显式 params 对象”这件事
    - 现在已经能落到包内 verifier/type 簇

- 但同时也要保留边界：
  - 还不能因为存在本地 `AICodeCommitParams`
  - 就自动推出本地 `AICodeCommitReport`
    - 也以同样 `type:.eq...` 形式落在同一簇里

- 因而“三段式静态链”要再细化成：
  1. `ai-code-commit-tracker.(*service)` / `(*Verifier)`
     - 聚合、校验、merge
     - 并且持有本地 `AICodeCommitParams` 这类中间层类型
  2. `(*CommitAIStats).ToAICodeCommitReport`
     - 推进到 `AICodeCommitReport`
  3. `WrapAICodeCommitReport`
     - 再桥接进 sender 形态
  4. `buildCommitItemsJSON`
  5. `reportAICodeCommit`

- 这一轮最重要的价值是：
  - 去掉了一个会误导的弱证据：
    - `63978406` 不是独立 report 类型点
  - 同时补上了一个更强的真证据：
    - `ai-code-commit-tracker` 包内部确实已经坐实存在 `AICodeCommitParams` 这一层
