# 2026-10-22 原生契约适配验证

这是上一批四项工作的记录。后续五项结果及当前测试数量见 [第二阶段验证记录](native-contract-stage2-validation.md)。

分支 `codex/weixin-4-offline-backends`，推送远端 `git@github.com:szzqa/wxhelper.git`。本阶段继续 REA 留存证据复用和 IDA 定向静态分析，新增可测试的离线读取接口。**4.1.15.13 尚未达到在线兼容：没有注入微信、读取微信进程内存、调用其原生函数或发送真实消息。**

## 分项结果

| 项目 | 提交 | 已实现与关键结论 |
| --- | --- | --- |
| 登录 | `eae54c3` | 内核阶段和按 host 认证读取。host 的 1/2/3 为等待或可重试、认证中、成功已记录；缺 entry 与 raw=0 分开。全局登录仍为 Unknown。 |
| 联系人 | `4ce4685` | 复制存储任务的用户名输入；确认协程 await、结果类型检查、闭包所有权。上层聚合节点为 0x2c0，不能用底层 Contact 的 0x478 节点布局读取。 |
| 接收存储 | `fba3b4e` | 读取批量结果原始标志及成功子集。标志在会话间为 OR，不能代表整批成功；单条 record promise 完成也不能证明落库。 |
| 发送完成 | 随本说明提交 | 读取 56 字节调用者结果，保留旧 8 字节状态接口。登记、展示队列检查、await 分属不同入口；两个状态字为零不代表送达。 |

详细证据：[内核阶段](weixin4-login-auth-contract.md)、[host 认证](weixin4-network-auth-contract.md)、[联系人](weixin4-contact-native-contract.md)、[接收](weixin4-receive-native-contract.md)、[发送](weixin4-send-native-contract.md)。所有原生地址都只是静态观察，本次未加入可调用函数指针或 live adapter。

## 证据核验

原始文件为 `C:\Program Files\Tencent\Weixin\4.1.15.13\Weixin.dll`，SHA-256 `10f8e995453e2da46d4f2b5080cd6da1f13cc5147746adc119ceae38cb039de5`。REA 6.4.0 public CLI 成功读取留存 PE resource Evidence `ev_40633e1feb841402eb3fb30dacdcd3e4f600e046917b9ae8ce9620591d9c0164`，原件哈希一致；返回的 native dossier 仍不可用，没有重复导入 Ghidra 或改变工具配置。

本轮 IDA 7 有界分析共 57 个函数结果、18,339 条指令与原 DLL 字节匹配：登录 28/10,777，联系人 10/793，接收 11/4,139，发送 8/2,630。四份 `weixin4-*-contract-verification.json` 保留结果哈希及边界，`weixin4-analysis-jobs.json` 保留可复跑范围。没有 `.pdata` 的叶函数采用原件反汇编确认的边界，明确记录来源。字节一致仅验证静态证据来源，不验证实际调用 ABI。

原始 DLL、派生分析 PE、IDA 数据库、大型伪代码和日志保留在忽略的 `out/analysis/`，不上传仓库。分析派生 PE 仅用于静态分析，其哈希不能通过运行 profile。

## 验证结果

- MSVC x64 Release 全量构建通过。
- CTest **19/19** 通过，包括新增 host auth、contact task、receive storage、send completion 测试；CLI 内含 **12** 个黑盒用例。
- Python `test_*.py` **15/15**；`weixin_log_review_test.py` **7/7**。
- 新静态接口均使用合成内存，覆盖缺失/错误对象、容器损坏、预算、指针溢出、错误清空和独立字符串所有权。全量回归中的注入器测试只操作本项目自产测试进程/DLL；网络测试只访问自建 loopback 对端。
- 4.x 运行白名单继续拒绝，`kRuntimeSupported`、HTTP `weixin4Runtime` 和 CLI `runtime_supported` 均为 false。
- `git diff --check` 通过。

## 无注入的测试方式

在仓库目录使用已经构建的 CLI：

```powershell
python scripts/make_weixin4_fixture.py --output out/synthetic-weixin4.json
.\out\build\x64\Release\weixin4_snapshot_cli.exe out/synthetic-weixin4.json
```

它会解析 9 项合成请求，包含新增 `auth_host`、`contact_task`、`receive_storage`、`send_completion`。这些是 JSON feature，不是 HTTP 路由，不会查询真实联系人或发送消息。完整输入与地址含义见 [快照接口说明](weixin4-snapshots.md)；原有后台启动、接口与未来移除注入说明见 [后台操作说明](runtime-operation.md)。

## 尚需下一阶段计划的范围

继续接入在线后端前，需要闭合当前主账号的 host 选择与认证失效/重连规则、全量联系人用户名来源和调度环境、原始发送消息对象构造及全部 callback/取消/账号代次，以及普通实时消息的提交后通知链。当前已恢复的任务结果不能替代这些条件。后续若要增加原生调用适配器、放开版本白名单或开展运行时验证，先列具体修改和验证计划，等待用户确认；本阶段没有执行这些变更。
