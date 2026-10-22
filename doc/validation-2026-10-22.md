# 2026-10-22 修复与离线适配验证

分支：`codex/weixin-4-offline-backends`。远端：`git@github.com:szzqa/wxhelper.git`。

本页记录前一轮修复；后续原生契约适配及 19/19 回归结果见 [本阶段验证记录](native-contract-validation-2026-10-22.md)。

本轮没有向微信注入、读取微信进程内存、调用微信内部函数或发送真实消息。注入器测试仅操作本项目自产的短命测试进程/DLL；HTTP/TCP 测试只访问自建的 loopback 对端。

## 分项提交

| 提交 | 内容 | 针对性验证 |
|---|---|---|
| `c94617a` | 固定配置和 Unicode 日志路径 | 中文路径、CWD 独立、端口边界及实际日志写入 |
| `d0654d1` | HTTP 回调总超时、取消、响应完整性 | 本机成功/错误/断开/截断/并发配置/取消测试 |
| `724b8e9` | 消息/SNS 成对拆装、工作池排空、TCP 取消 | Fake Detours 事务、跨线程原生转发、所有权、全量发送、超时/取消及资源配对 |
| `8b84daa` | API 校验与 health/capabilities/stop | 39 旧路由的离线校验；自产夹具验证实际 HTTP 错误码、完整 202、端口关闭与 DLL PIN |
| `0f2c90a` | 4.x `logout_started` 观察值 | 合成快照/CLI；4 个新函数 1,053 条指令与原 DLL 比对 |
| `cd72872` | 联系人查询契约补充 | 55 条有界日志复核与联系人解码器回归；没有开放全量查询 |
| `d0e5af2` | 4.x 消息正文、账号、会话与元数据解析 | Release 消息/CLI 测试；2 个新函数 1,104 条指令比对；77 条静态复合日志复核 |

## 最终回归

- MSVC x64 Release 全量构建成功。
- CTest：15/15 通过，其中包含 7 个离线 CLI 黑盒用例。
- Python 原有检查：12/12 通过；日志静态证据检查：7/7 通过。
- `git diff --check` 通过。
- 4.1.15.13 的版本拒绝测试仍通过；在线兼容性白名单没有放开。

```powershell
cmake --build out/build/x64 --config Release
ctest --test-dir out/build/x64 -C Release --output-on-failure
python -m unittest discover -s tests -p 'test_*.py' -v
python -m unittest discover -s tests -p 'weixin_log_review_test.py' -v
```

测试过程中发现，本机完成实际 loopback 连接后，系统/provider 可能另外持有 Winsock 引用；因此全进程“socket 必须报未初始化”的断言不可靠。已用独立最小程序复现，并改为检查本项目真实 WSAStartup/WSACleanup 的配对余额；没有额外调用 WSACleanup 掩盖问题。

## 实际可用范围与后续工作

旧版 DLL 后端只支持 `WeChatWin.dll 3.9.5.81 x64`。新增停止接口会撤销监听、取消并排空回调、关闭 HTTP，**不会卸载已 PIN 的 DLL**。完整移除须正常退出宿主进程。真实微信中的拆钩、Detours 线程枚举与宿主锁关系尚未验证。

4.1.15.13 可离线读取登录服务及退出启动标志、联系人查询结果、发送任务及结果、消息记录的原始正文与元数据。认证成功/重连/退出完成状态、完整联系人枚举、消息类型/状态枚举和时间单位，以及对象持有、调用 ABI、线程/队列要求仍需继续确认。当前不具备在线收发能力。

后续顺序：先继续静态确认认证状态及联系人查询上下文，再恢复消息构造/持有/完成回调契约，并用自产对象或快照验证。实际注入和真实发送继续等待用户另行明确授权。操作说明、接口列表和注入/移除计划见 [后台操作说明](runtime-operation.md)。
