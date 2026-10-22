# 4.1.15.13 消息 signal 分发与解除边界

本轮定位到存储结果上层的实际 signal emitter、订阅节点登记/标记解除、排队消息副本及其析构。新增 `ReadNotificationDispatchSnapshot` 只解码该排队闭包的稳定离线快照，**不订阅消息、不安装 hook、不运行回调、不读取微信进程**。

消息来源分类保持 **Unknown**。目前没有证据证明该 signal 只接收新到达、外部发来的消息；历史同步、自己发送、其他触发方尚未完全分类。排队副本也不证明订阅者已经运行，更不证明送达、已读或物理磁盘持久化。

原件固定为 AMD64 Weixin `4.1.15.13`，SHA-256 `10f8e995453e2da46d4f2b5080cd6da1f13cc5147746adc119ceae38cb039de5`。以下均为 RVA。存储结果的部分成功/OR 标志和 `0x2e8` 记录来源见 [接收存储契约](weixin4-receive-native-contract.md)；本轮没有改变这些已知限制。

## 存储成功子集到 signal

| 上层路径 | 已核对的后置调用 |
| --- | --- |
| `0x17b6c00..0x17b7565`，完整日志名 `MessageManager::SaveDbAndNotify` | 存储结果的 true 分支遍历返回类别及其成功记录子集，执行处理器与其他服务通知；尾部按类别调用 `0x17b8970(manager+0xe8, records)` |
| `0x1811ff0..0x1812530`，完整日志名 `MessageManager::AddAndNotifyMessagesToDB` | 存储返回 true 时合并成功子集；合并非空后进入 `0x17ed050` |
| `0x17ed050..0x17ed11e` | 先进入同一 `0x17b8970`，再经当前服务获取另一对象并调用 `0x2a61940` |

`0x17b79a0` 属于另一条处理分支：按记录字段查处理器、复制记录到共享对象，最后创建虚表 `0x90d97f8` 的异步任务。它和统一 signal emitter 不等价。`0x3936d30` 仍只是存储任务 promise 的完成，不是本页通知点。

`0x17b8970..0x17b8dc3` 有明文 `signalslot.h` 以及递归 emit 的诊断 `xsignal: emit signal in signal handler will cause infinite loop!`。函数使用 signal `+8` 指向的内部状态、锁及重入检查，获得订阅者节点副本，再逐个分发。`manager+0xe8` 是这些已观察调用点传入的 signal 对象；manager 的所有获取方式、账号代次和重登失效仍未闭合。

## 同步调用与异步副本

订阅节点为 `0x68` 字节。以下布局来自创建、复制和 emit 三处的数据流，不提供可直接调用的 C++ ABI。

| 节点偏移 | 已观察用途 |
| --- | --- |
| `+0` | 下一节点 |
| `+8`、`+0x10` | 回调上下文观察地址、调用函数观察地址 |
| `+0x18` 起 | 被传给回调的捕获数据区域，完整类型未知 |
| `+0x30` | 解除匹配时比较捕获数据的函数 |
| `+0x38` | 可选 tracker 关联，具体对象类型未知 |
| `+0x40` | flags；bit 1（数值 2）控制是否从订阅列表中移除 |
| `+0x48` | 可选调度对象；为空时走同步分支 |
| `+0x50/+0x58` | 复制和释放时显式增减引用计数的 owner pair，载荷类型未知 |

同步分支在 emitter 内直接调用节点 `+0x10` 的函数，传入 `RCX=[node+8]`、`RDX=node+0x18`、`R8=输入记录 vector`。这是借用原调用的参数范围，不能把记录指针带出回调后继续使用。

异步分支调用记录复制辅助函数，将 `0x2e8` 步长的记录放入独立 vector，再分配 `0x80` 字节闭包，设置虚表 `0x90d86e8`。它复制节点的回调/捕获信息，保留可选 owner pair，并经调度对象虚表 `+8` 投递包装函数。

| 排队闭包偏移 | `NotificationDispatchSnapshot` 字段 |
| --- | --- |
| `+0` | 严格验证虚表为 `module_base + 0x90d86e8` |
| `+8` | `callback_context_address`，可为 0，纯观察值 |
| `+0x10` | `callback_function_address`，纯观察值，不能调用 |
| `+0x48` | `scheduler_address`，纯观察值，不能调度 |
| `+0x50/+0x58` | `lifetime_owner`，不透明 pair 与可选计数观察 |
| `+0x68/+0x70/+0x78` | `records` 的 begin/end/capacity；输出复制为 owned DTO vector |

该虚表的执行项指向 `0x472a80..0x472a93`：它设置 `R8=closure+0x68`、`RDX=closure+0x18`、`RCX=[closure+8]`，然后 tail-jump 到 `[closure+0x10]`。这个 19 字节叶函数没有独立 `.pdata` 项；边界来自原件指令和后续 `CC` padding，已加入专门的 IDA 字节核验。

析构项 `0x1848120..0x18481da` 以 `0x2e8` 步长析构复制出的记录并释放 vector buffer，再释放 `+0x58` 非空控制块，最后按析构 flag 释放闭包。它证明排队副本有独立清理责任；原生共享对象及记录包含动态成员，不能通过 `memcpy` 伪造这一责任。离线读者只复制字符串及标量，从不执行原生析构。

## 解除不是已排队回调的屏障

`0x4945b0..0x494759` 在锁内申请节点，填写上下文、函数、捕获数据、flags、调度对象和可选 owner pair，追加到状态 `+0xa0` 链；`+0xa8` 用于维护尾部链接。

`0x4947c0..0x4948b6` 在锁内按上下文和函数地址匹配，再调用节点 `+0x30` 比较捕获数据。匹配且尚未标记的节点被置 `+0x40` bit 1，并将状态 `+0xb5` 标记为待清理；有 tracker 时还调用关联移除函数。这个函数体没有等待已排队回调结束的步骤。

`0x494ad0..0x494c38` 为当前 emit 建立独立节点副本，跳过已置 bit 1 的原节点，复制可用节点并增加其可选 owner control 的 strong 计数。flags 低两位等于 1 时还会在复制后标记原节点；此行为与单次订阅相容，但本页不据此建立全 flags 枚举。`0x494920..0x494abd` 清理已标记原节点时释放其 owner 引用并删除节点。

已复制的节点和已生成的异步闭包拥有各自的引用。尤其 `0x472a80` 执行时不查询原 signal、原节点或移除 bit，因此**仅解除原订阅不能撤回已复制或已排队的回调**。外层调度器是否另有取消机制未确认，不能把“未看到检查”扩大为“任何层都无法取消”。同样，这个不透明 owner pair 未被证明必然拥有原始 callback context，不能据此宣布完整生命周期安全。

未来运行时适配仍需确定实际订阅者注册点和参数、调度器责任、回调正在执行时的排空策略、账号切换代次和重复/历史事件分类。当前没有实现订阅或解除操作，`kRuntimeSupported` 保持 false。

## 离线读者与测试

```cpp
ReadError ReadNotificationDispatchSnapshot(
    const MemoryReader& stable_snapshot,
    const BinaryIdentity& original_identity,
    std::uint64_t module_base,
    std::uint64_t closure_address,
    NotificationDispatchSnapshot& output,
    const Limits& limits = {});
```

输入是上述排队闭包的稳定快照，不是订阅节点、signal、任务 future 或存储结果 payload。读者要求匹配原件 profile、准确闭包虚表，以及该排队变体必要的非空 callback function 和 scheduler 观察值。它不读取这些地址指向的内容。上下文可为空；owner pair 允许为空和 alias 形式，因为生产者只检查可选 control 并持有它，没有建立 object/control 的固定偏移关系。非空 control 要求正 signed int32 strong/weak 计数。

记录解码复用已有 `ReadReceiveBatchSnapshot`，包含记录数、单串和全批字符串预算，忽略预留容量。全部字符串由输出独立拥有。字段地址计算检查溢出；profile 错误在读取前拒绝。任何错误清空全部观察地址、owner 元数据及记录，避免将先前成功的部分批次误认为完整通知。

`tests/weixin4_notification_tests.cc` 使用自产稀疏快照覆盖：固定及重定位 module base、严格虚表和必要指针、空上下文、空/alias owner pair、非法计数、完整 64 位消息 ID、未知类型/状态值保留、`0x2e8` 步长、未映射的预留容量与回调地址、DTO 字符串独立存活、含 NUL 的 heap 内容、空批次、预算、后项损坏时整批清空、缺页、畸形 vector、profile、空地址与溢出。独立 MSVC x64 C++17 `/W4 /WX` 编译和 fixture 测试通过；测试没有执行目标 DLL或任何回调。

CLI 的 `notification_dispatch` 已接入合成夹具。输出固定保留 `source_classification=unknown`、`callback_executed=false`、`realtime_incoming_verified=false` 和 `disconnect_drains_queue_verified=false`。本批最终 MSVC x64 Release 全量构建、23 项 CTest（含 17 个 CLI 黑盒用例）、15 项 Python 脚本测试和 7 项日志复核测试均通过。

证据位于 `out/analysis/weixin-4.1.15.13/ida7-focused/`：`message-lifecycle-pass1.json` 和 `message-lifecycle-pass3.json` 覆盖通知上层与 emitter；`message-notify-pass4.json` 覆盖节点复制、回收、闭包执行/析构；`message-notify-pass5.json` 覆盖节点登记与标记解除。[核验摘要](weixin4-notification-verification.json) 收录相关 11 个函数、2,220 条与原件字节匹配的指令。日志名称来自有界 XOR 假设与独立代码数据流，不代表目标运行验证。
