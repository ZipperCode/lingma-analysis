# Lingma2API 项目内认证设计

更新时间：`2026-04-27`

## 1. 背景与结论

`lingma2api` 的运行态认证边界已调整为：

1. 运行态不得读取 `~/.lingma/*`
2. 运行态只允许读取当前项目内自保存的认证文件
3. `~/.lingma/*` 仅允许用于测试、研究或一次性迁移工具

因此，原先围绕 `cache/user`、`cache/id`、`portable_config.json` 的运行态凭据设计全部失效，必须改为：

- 一次性授权引导负责生成项目内认证文件
- 主服务运行时只消费该项目内认证文件

## 2. 目标

本次改造的目标是让 `lingma2api` 在不依赖 Lingma 程序安装目录的前提下完成以下能力：

1. 通过一次性浏览器授权写出项目内认证文件
2. 主服务后续只读项目内认证文件完成签名与远端请求
3. 认证更新逻辑也围绕项目内认证文件进行，不回退到 `~/.lingma/*`

## 3. 非目标

首期明确不做以下事情：

1. 运行态自动扫描 `~/.lingma/*`
2. 运行态在失败时自动回退到本机 Lingma 缓存
3. 将浏览器登录流程耦合进主代理服务入口
4. 在未验证刷新契约前承诺“完全自动 refresh”

## 4. 核心方案

采用方案 A：

1. 新增项目内认证文件 `lingma2api/auth/credentials.json`
2. 新增一次性授权命令 `lingma2api/cmd/lingma-auth-bootstrap`
3. 主服务运行时只读取 `auth/credentials.json`

不采用方案 B（将授权入口并入主代理服务），原因是：

1. 会把授权引导和代理运行态耦合在一起
2. 不利于贯彻“运行态只消费项目认证文件”的边界
3. 对后续单独替换授权实现不友好

## 5. 授权引导流程

### 5.1 Bootstrap 入口

`cmd/lingma-auth-bootstrap` 负责：

1. 生成 `state`
2. 生成 PKCE 参数
3. 生成浏览器 OAuth 链接
4. 启动一次性本地回调监听
5. 接收浏览器回调参数
6. 执行后续交换流程
7. 写入项目内认证文件

### 5.2 用户参与方式

脚本输出浏览器登录链接后：

1. 用户手动在浏览器打开链接
2. 用户完成登录
3. 浏览器跳转到本地回调地址
4. bootstrap 进程接收参数并生成认证文件

### 5.3 失败边界

如果流程中某一步必须人工配合：

1. 脚本明确打印当前步骤
2. 不擅自切换路径
3. 不回退到 `~/.lingma/*`
4. 失败时给出“重新执行 bootstrap”或“等待用户辅助”的明确提示

## 6. 项目内认证文件

### 6.1 文件位置

推荐固定为：

```text
lingma2api/auth/credentials.json
```

并提供：

```text
lingma2api/auth/credentials.example.json
```

### 6.2 文件结构

推荐结构：

```json
{
  "schema_version": 1,
  "source": "project_bootstrap",
  "lingma_version_hint": "2.11.2",
  "obtained_at": "2026-04-27T11:30:00+08:00",
  "updated_at": "2026-04-27T11:30:00+08:00",
  "token_expire_time": "2026-04-27T13:30:00+08:00",
  "auth": {
    "cosy_key": "...",
    "encrypt_user_info": "...",
    "user_id": "...",
    "machine_id": "..."
  },
  "oauth": {
    "access_token": "...",
    "refresh_token": "..."
  }
}
```

### 6.3 字段分层

分两层保存：

1. 运行态必需字段
   - `cosy_key`
   - `encrypt_user_info`
   - `user_id`
   - `machine_id`
2. 授权维护字段
   - `access_token`
   - `refresh_token`
   - `token_expire_time`
   - 时间戳元信息

这样可以把“当前请求签名所需材料”和“未来可能的刷新材料”分开管理。

## 7. 主服务运行态规则

### 7.1 凭据来源

运行态只允许：

1. 读取 `auth/credentials.json`

不再允许：

1. `lingma_dir`
2. `portable_config.json`
3. `cache/user`
4. `cache/id`
5. 日志中的 machine id 回退

### 7.2 认证读取职责

新的凭据层职责是：

1. 读取项目内认证文件
2. 校验 schema 和必填字段
3. 返回 `CredentialSnapshot`
4. 必要时负责将 refresh 结果回写到同一文件

### 7.3 刷新策略

首期采用保守策略：

1. 主服务不自动拉起浏览器授权
2. 如果刷新契约已经验证成功，可由 `/admin/refresh` 触发静默刷新并回写文件
3. 如果刷新契约尚未坐实或刷新失败，直接返回明确错误，要求重新执行 bootstrap

## 8. 代码结构调整

### 8.1 新增

```text
lingma2api/
├── auth/
│   └── credentials.example.json
├── cmd/
│   └── lingma-auth-bootstrap/
│       └── main.go
```

### 8.2 改造

1. `internal/proxy/credentials.go`
   - 改成只读取项目内认证文件
2. `internal/config/config.go`
   - 去掉 `lingma_dir`、`portable_config`
   - 增加 `credential.auth_file`
3. `config.yaml`
   - 同步改成项目文件路径配置
4. `README.md`
   - 改写认证章节

### 8.3 测试边界

1. 普通单测只测项目内认证文件读写
2. 若保留 `~/.lingma/*` 相关代码，只能放到：
   - 独立迁移工具
   - 单独 build tag 的研究/集成测试
3. 主服务运行态包不得再依赖 `~/.lingma/*`

## 9. 与当前实现的冲突点

当前仓库已有实现中，以下内容与新边界冲突：

1. `config.yaml` 中的 `lingma_dir`、`portable_config`
2. `credentials.go` 中对 `~/.lingma/*` 的运行态读取
3. 相关 README 中对 `cache/user` 的运行态说明
4. 旧计划文档里“凭据优先级包含 `.lingma`”的部分

这些都需要在新计划里替换掉。

## 10. 风险与假设

### 10.1 当前假设

当前设计的关键假设是：

1. 浏览器回调参数加后续交换步骤，足以产出主服务运行态所需字段
2. bootstrap 完成后，项目文件能长期保存 `cosy_key`、`encrypt_user_info` 等最小请求材料

### 10.2 如果假设不成立

如果后续发现：

1. `cosy_key`
2. `encrypt_user_info`

不能仅靠 bootstrap 或 refresh 稳定维持，那么处理方式应是：

1. 重新定义 bootstrap 的交换步骤
2. 或要求重新跑 bootstrap

而不是重新把 `.lingma` 回退塞回运行态。

## 11. 结论

新的工程边界已经确定：

1. `lingma2api` 是完全脱离 Lingma 程序的工程
2. 运行态认证唯一来源是项目内认证文件
3. 浏览器授权由一次性 bootstrap 命令负责
4. `.lingma` 只允许出现在测试、研究或迁移工具里

后续实现必须围绕这四点推进，不能再把 `.lingma` 缓存链混回主路径。
