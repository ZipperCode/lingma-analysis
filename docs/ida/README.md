# IDA Pro 反编译参考数据

本目录存放 IDA Pro 对 Lingma 二进制的静态分析原始输出。

## 版本信息

- **Lingma v2.11.1**：部分 `.txt` 反编译文件
- **Lingma v2.11.2**：部分 `.txt` 和 `.json` 文件，函数地址已更新

## 文件分类

### 反编译输出 (.txt)
| 文件 | 内容 |
|------|------|
| `ida_authtoken_decomp.txt` | AuthToken 函数反编译 |
| `ida_completelogin_decomp.txt` | CompleteLogin 流程 |
| `ida_device_login_decomp.txt` | Device Login 逻辑 |
| `ida_devicelogin_decomp.txt` | DeviceLogin 处理 |
| `ida_dorefresh_decomp.txt` | doRefreshToken 主流程 |
| `ida_getquota_decomp.txt` | GetQuota 查询 |
| `ida_gowrap_decomp.txt` | Go 函数包装层 |
| `ida_handleauth_decomp.txt` | HandleAuth 回调处理 |
| `ida_refreshtoken_decomp.txt` | RefreshToken 刷新 |
| `ida_refreshuser_decomp.txt` | RefreshUser 刷新 |

### Payload 结构分析 (.json)
| 文件 | 内容 |
|------|------|
| `ida_buildrequest_decomp.json` | HTTP 请求构造 |
| `ida_payload_bearer.json` | Bearer 认证 payload |
| `ida_payload_cosy.json` | COSY 认证 payload |
| `ida_payload_fmt.json` | Payload 格式结构 |
| `ida_payload_refresh.json` | 刷新令牌 payload |
| `ida_payload_refreshscan.json` | 刷新扫描 |
| `ida_payload_route0.json` | 路由 0 分析 |
| `ida_payload_rt.json` | RT token 结构 |
| `ida_payload_rtscan.json` | RT 扫描 |
| `ida_payload_sep.json` | 分隔符分析 |
| `ida_payload_sign.json` | 签名 payload |
| `ida_payload_sign2.json` | 签名 v2 |
| `ida_payload_strings.json` | 字符串引用 |
| `ida_payload_strings2.json` | 字符串引用 v2 |
| `ida_search_auth_login.json` | 认证登录搜索 |

### IDA 辅助脚本 (.py)
| 文件 | 内容 |
|------|------|
| `ida_payload_callback_keys.py` | 回调 key 搜索 |
| `ida_payload_cosykey.py` | COSY key 提取 |
| `ida_payload_find_login_init.py` | 登录初始化查找 |
| `ida_payload_find_login2.py` | 登录流程 v2 |
| `ida_payload_login_search.py` | 登录搜索 |
| `ida_payload_login_search2.py` | 登录搜索 v2 |
| `ida_payload_login_strings.py` | 登录字符串搜索 |
| `ida_payload_vtable.py` | 虚表分析 |
| `ida_route0.py` | 路由 0 分析脚本 |
| `ida_search_login.py` | 登录搜索脚本 |
| `ida_token_refresh_analysis.py` | Token 刷新分析 |
| `ida_trace_refresh.py` | 刷新追踪 |

## 注意

这些是原始分析数据。从中得出的结论部分已验证、部分未验证。
未验证的结论已移至 `docs/doubt/` 目录。
