# 4.1.15.13 第二阶段五项契约验证

日期：2026-10-22。分支：`codex/weixin-4-offline-backends`；推送远端：`git@github.com:szzqa/wxhelper.git`。

本批按已批准顺序完成五项有界静态分析、离线读者及合成测试，每项验证后独立提交。**4.1.15.13 仍未开放在线后端。没有向微信注入、读取其运行内存、调用其原生函数或发送真实消息。** 下表区分已确认的局部契约与尚未证明的业务语义。

## 分项结果

| 项目 | 提交 | 已确认与实现 | 尚未证明 |
| --- | --- | --- | --- |
| 主账号登录判断 | `4927cc5` | 原生 `kernel::IsLogin` 读取 service `+0x38` 低位；离线新增可空 `kernel_is_login`，与退出标记分开保留 | 该位在认证前即可置位。主账号 host 选择、认证失效/重连仍未闭合，全局 `state` 继续为 `unknown` |
| 全量联系人入口 | `7b90819` | 定位 `ContactService::GetContactList` → 无用户名输入的 `LoadFriendContact` 链；按 `local_type` 查询 `{1,2,5,7}`，新增完成输出的 optional 链表读者 | 结果存在不代表各表均成功；服务层另有黑名单等筛选，完整账号覆盖、代次及完成条件仍未证明 |
| 文本消息构造 | `863028f` | 确认工厂对象/控制块、self weak、会话字段、文本参数字节和消息/manager 两组捕获；新增 `text_draft`，原始文本同时输出 hex | 没有实现可调用构造 ABI；manager 生命周期、正文编码及完整类型枚举仍未确认 |
| 取消与等待 | `b12545d` | 确认 SendContext 的作业 cancel/join 路径、无作业时的展示队列查找；新增阶段和取消请求快照 | 取消请求不等于取消完成；join 只等待作业自身，同执行器等待有 Fatal 路径，不能保证全部消息回调已释放 |
| 实时通知候选链 | 随本说明提交 | 确认存储后 signal、同步/排队分发、闭包复制与析构、订阅登记及标记解除；新增 `notification_dispatch` | 来源分类仍为 `unknown`，不能限定为实时新收信；解除原订阅不保证已复制或已排队回调结束 |

详细说明：[登录](weixin4-main-account-contract.md)、[联系人](weixin4-contact-enumeration.md)、[构造](weixin4-message-construction-contract.md)、[取消](weixin4-send-cancel-contract.md)、[通知](weixin4-notification-contract.md)。本批没有加入可调用的原生函数指针、进程内存读者、订阅器或运行时适配器。

## 证据来源

目标原件为 `C:\Program Files\Tencent\Weixin\4.1.15.13\Weixin.dll`，AMD64，SHA-256：

```
10f8e995453e2da46d4f2b5080cd6da1f13cc5147746adc119ceae38cb039de5
```

本批重新核对原件哈希，并使用 REA public CLI 检查留存 PE resource Evidence `ev_40633e1feb841402eb3fb30dacdcd3e4f600e046917b9ae8ce9620591d9c0164`。其 native dossier 不可用；以下原生结果来自独立 IDA 7.0/Hex-Rays 定向分析，没有标成 REA 反编译结果。

15 个有界 IDA 作业覆盖 **60 个不同函数、20,218 条原件字节匹配指令**，报告没有伪代码/反汇编截断或函数错误。无 `.pdata` 的 `0x472a80` 叶函数使用原件指令与 padding 确认边界。各功能 verification 摘要保留报告哈希与选定范围；不同功能复用同一 await 函数，分项数量不能直接相加当成不同函数总数。

可复跑范围见 [分析任务目录](weixin4-analysis-jobs.json)。原始 DLL、派生 PE、IDA 数据库及完整反编译输出留在忽略的 `out/analysis/`，不上传仓库。派生 PE 只调整 Exception Directory 的 8 个头部字节供旧 IDA 静态分析，原节数据保持一致；从未执行该副本。字节一致只支持证据来源，不证明实际调用安全或业务语义完整。

## 最终验证

- MSVC x64 Release 全量构建通过。
- CTest **23/23**，其中 CLI 测试包含 **17** 个黑盒用例。
- `python -B -m unittest discover -s tests -p 'test_*.py'`：**15/15**。
- `python -B tests/weixin_log_review_test.py`：**7/7**。
- 新模块各自通过独立 MSVC `/W4 /WX` 编译与合成快照测试；另完成只读交叉审查，未发现需要修改的问题。
- 全量回归的注入器用例仅操作本项目自产宿主/DLL；网络用例仅操作自建 loopback 对端。没有测试真实微信或真实账号。
- 4.x 版本白名单继续拒绝；`kRuntimeSupported`、HTTP `weixin4Runtime` 与 CLI `runtime_supported` 保持 false。

## 当前可直接运行的无注入测试

在仓库目录使用已构建产物：

```powershell
python scripts/make_weixin4_fixture.py --output out/synthetic-weixin4.json
.\out\build\x64\Release\weixin4_snapshot_cli.exe out/synthetic-weixin4.json
ctest --test-dir out/build/x64 -C Release --output-on-failure
```

生成器构造 **13** 个离线 feature 的测试请求。新功能为 `contact_type_query`、`text_draft`、`send_cancel_context`、`notification_dispatch`；已有 `login` 增加本地谓词。它们都是解析 JSON 快照的入口，不会登录、查询真实联系人、构造原生消息、取消真实作业或接收实时通知。完整格式与地址含义见 [快照接口说明](weixin4-snapshots.md)。

旧版后台启动、HTTP 接口、停止与移除方式见 [后台操作说明](runtime-operation.md)。当前 4.1.15.13 无法通过这些 HTTP 接口收发消息。以后若获准加载 helper，停止监听或服务也不等于卸载 DLL；完整移除仍需正常退出整个宿主进程后重新启动。

## 未执行的后续范围

若继续深入，下一阶段应先列计划，确认后再修改：主账号选择及重登失效链、联系人服务层完整性与账号代次、消息 manager/调度器上下文、实际订阅点及在途回调排空。新增原生调用桥接、放开 4.x 白名单、访问运行中微信或发送消息均不在本批范围内；静态发现不足以批准这些动作。
