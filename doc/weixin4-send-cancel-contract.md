# Weixin 4.1.15.13 发送取消请求与等待契约

本轮确认 `MessageSendContext::Cancel` 的两个作业接口分别为 `cancel` 和 `join`，并新增 `ReadSendCancelContextSnapshot`。它从稳定快照观察发送上下文、作业存在性及取消请求位，不执行取消，不输出“消息已经取消”或“回调已经全部释放”。

适用 profile 是 AMD64、Weixin `4.1.15.13`、原始 DLL SHA-256 `10f8e995453e2da46d4f2b5080cd6da1f13cc5147746adc119ceae38cb039de5`。下文地址均为 RVA；没有注入、访问运行中微信内存、执行原生函数或发送消息。此前发送、等待与结果契约见 [发送任务说明](weixin4-send-native-contract.md)。

## 取消入口实际做了什么

`0x3987000..0x3987542` 的完整日志名为 `kernel::manager::MessageSendContext::Cancel`。它没有直接写整个 SendContext 的“取消完成”字段：

1. 上下文 `+0x58` 的 `send_job` 非空时，先调用作业虚表 `+0x10`，再重新取指针调用 `+0x18`；对应调用点 `0x39871BA/0x39871C4`。
2. 上下文 `+0x68` 的 `send_cgi_job` 非空时做同样操作，对应 `0x39871D3/0x39871DD`。
3. **在上述调用之后**重新检查两指针。都为空时，经当前登录服务取得 manager，调用 `0x17F2FD0` 尝试清理准备展示队列。日志区分 `has no send_job/send_cgi_job (still in prepare_show queue)`。

所以快照中有作业只证明初始会选择作业接口；作业调用可能改变后续条件，不能把这些路径当成互斥且不可变的执行历史。Cancel 的原生返回寄存器值还可能来自日志、释放引用或虚调用，没有统一的成功/完成布尔语义。

`CheckRemoveCancelledPrepare… 0x17F2FD0..0x17F32B2` 先用 `0xA55490` 取得对端字符串，用 `0xA56380` 生成记录身份描述，再经 `0x17F33B0..0x17F3709` 查找准备展示上下文。后者按这两个键匹配并返回 owner pair，**不读取另一个取消状态位**。其中身份描述的已知构造见[消息字段说明](weixin4-messages.md)，不能将其简写为服务端消息 ID。

命中后进入 `0x17F0700`。它按原始阶段是否 `<=3` 走不同队列处理，还会调用 `CheckPrepareShowQueue 0x1793C90` 或 `CheckSerialSendToServerQueue 0x17F0A60`，因此取消某上下文可能推动其他排队上下文。此链不证明整个队列停止，也不保证网络端尚未收到请求。

`0x17F26F0..0x17F2B66` 在阶段 `<=9` 的部分路径处理消息类型 3/43 的附加数据，通过 `0xA352B0/0x38E7D0/0x17EEBA0` 等辅助函数并释放 owner。本轮没有在这里发现发送完成 promise 的发布；不能因为它位于清理链末尾就称作“最终完成回调”。

## 作业身份和请求位

`0x17F0A60` 通过 `0x2FB5B0`（明文日志 `Coroutine::coLaunchInterface`）创建作业，把返回 owner pair 写入 SendContext `+0x68/+0x70`。已闭合的主分支为：

`0x2FB5B0 → 0x2FA790 → 0x3B5370 → 0x3B4DE0 → 0xD80830 → 0xD808F0 → 0xD841E0 → 0xD80A00`。

`0xD808F0` 分配 `0x1A0` 字节，`0xD841E0` 把控制块虚表设为 `0x8F784D8`，strong/weak 计数各初始化为 1；对象为 control `+0x10`。对象构造 `0xD80A00..0xD8112D` 最终设置虚表 `0x8F78568`。该表的 `+0x10` 指向 `0xD816E0`，`+0x18` 指向 `0xD81B60`。其他调度器分支可能产生不同作业类型，离线 decoder 不将未知虚表强行解释成这个布局。

| 作业偏移 | 字段观察值 | 确认证据与限制 |
| --- | --- | --- |
| `+0x178` | `started_raw` / `started` | 明文诊断标签 `is_started_`；Cancel 和 Join 检查其低位。本字段不表示消息已发出。 |
| `+0x179` | `active_raw` / `active` | 明文标签 `is_active_`；Cancel 的首次路径将它清零，不表示消息已撤回或所有回调都结束。 |
| `+0x17B` | `cancel_requested_raw` / `cancel_requested` | 原生标签是 `is_cancelled_`，本项目使用更窄的“请求已记录”语义。`0xD816E0` 入口先写 1，再检查原值、清 active 并安排后续；故它在完成之前就可能为 true。 |

构造函数清零这些字节。`cancel` 对原值低位已经为 1 的路径直接返回；首次路径按 started 选择不同闭包，经对象 `+0x110` 指向的调度器虚接口安排后续。证据支持的是请求记录和后续排程，不支持同步完成、网络撤回或回调全部解除。

decoder 保留原始字节，并按原件消费方式取低位；不把高位非零自行判作损坏，也不根据三个标记的组合补造状态机。例如尚未 started 而 cancel_requested 为 true 是可表达的观察值。

## Join、promise 和回调的边界

`0xD81B60..0xD81E3F` 的明文方法名为 `join`。若作业尚未 started 且尚未请求取消，它可能先调虚表 `+8` 启动作业；然后调用 `0xD83660`，负返回值构造并抛出异常。当前接口没有超时参数，不能承诺有界返回。

`message-cancel-join.json` 的完整反编译与原件指令确认：`0xD83909` 取 **job `+0xD8`** 的 holder pair，`0xD83910` 调 `0x48BD30`；另一分支 `0xD83B42` 取同一 holder，`0xD83B49` 调 `0x39F570`。这与 SendContext `+0x78/+0x80` 的消息完成 holder 是不同成员；不能把等待作业自身的结果直接等同于“消息完成回调全部消失”。

`0xD83660..0xD83F19` 的明文名为 `co_join_`：取得协程上下文时走 `await_noexcept`，负恢复原因传回上层；没有协程上下文时检查当前 executor。如果它等于 job `+0x110` 的 executor，会走明确的 Fatal 诊断 `coroutine to be joined running on the same executor`，不能当作安全阻塞路径。其他 executor 或普通 thread 分支经 `0x39F570` 等待 job holder，并校验结果类型，类型缺失/不符抛 `bad cast`。即使正常返回，函数也没有检查所有消息回调的 owner 是否归零。Join 因此既不能一概描述为只支持协程，也不能一概描述为可在任意线程安全阻塞。

已有 `await_noexcept 0x48BD30` 会检查 TLS 协程上下文，缺失时记录 Fatal；它登记持有对象的回调，恢复原因异常时沿拒绝路径处理。该函数没有超时参数，不能从其名中的 `noexcept` 推断外层调用不会抛异常。

负恢复路径调用 `0x39DD30..0x39DEC6`；在 holder `+0xC4` 仍为 0 且允许的分支，它构造异常载荷，再调用 `0x39DFD0(holder, payload, 2)`。`0x39DFD0..0x39E1EA` 的明文名为 `start_resolve_reject`，在锁内仅从 pending 状态发布新状态/载荷，通知等待者，并在回调列表非空时交给 `0x39E270`。这个发布步骤不能证明所有回调已执行、所有 owner 已释放或后续不再访问消息对象。

本轮没有恢复“取消完成且所有消息回调都解除”的独立不变量，也没有建立用户取消、作业拒绝、发送结果和服务端确认之间的一一对应。生产 DTO 因而不包含 `cancelled`、`completed`、`callbacks_released` 或 `delivered` 字段。

## 离线接口和检查

```cpp
ReadError ReadSendCancelContextSnapshot(
    const MemoryReader&, const BinaryIdentity&,
    std::uint64_t module_base, std::uint64_t send_context_address,
    SendCancelContextSnapshot&);
```

输入是已稳定的 **MessageSendContext 对象地址**，不是 owner pair 地址。实现先验证 profile 和上下文虚表 `0x950A548`，读取原始阶段 `+0xBC`（原件 getter `0xF1DA50` 的完整 leaf 字节为 `8B 81 BC 00 00 00 C3`），再分别检查两个作业 pair。

非空作业要求对象/control 地址按 8 字节对齐、`object=control+0x10`、两虚表与已知类型一致、strong/weak 均为正的 int32 计数。它只读取已证明的三个字节；不会读取未知 `+0x17A`，也不会调用方法或修改计数。对象为空时原生入口按无作业处理，因此 decoder 可以保留一个非空但不解引用的别名控制块地址。

`dispatch` 仅按快照指针给出初始动作：

- `job_cancel_and_join`：至少存在一个可识别作业；不证明 Cancel 曾经执行或 Join 已返回。
- `prepare_show_lookup`：两作业对象均为空；不证明上下文确实在准备队列、已经命中或移除。
- `unknown`：默认值或整个读取失败后的清空状态。

原始阶段不映射到取消成功。任何 profile、对象、地址溢出或不可读错误均清空整份输出，防止一个作业的旧数据与另一作业的读取失败混合。没有字符串或可变长容器分配，不增加运行时读取能力。

## 离线验证与材料

`tests/weixin4_send_cancel_tests.cc` 覆盖两个作业的四种存在组合、0/1/2/255 原始标记、未知阶段保留、取消请求早于 started、两个作业独立状态、别名空对象、不支持的对象身份、控制块关系与引用计数、每个必需字节不可读、profile 在读取前拒绝、地址溢出与错误清空。独立 MSVC x64 C++17 `/W4 /WX` 编译运行通过；只使用自产内存映射。

本地报告位于 `out/analysis/weixin-4.1.15.13/ida7-focused/`。入口来自已核验 `message-lifecycle-pass3.json`，队列与消息构造来自 `message-lifecycle-pass1.json`，await 来自 `message-construction-pass2.json`。新增 `message-cancel-pass4.json` 为 4 函数、789 条原件核验指令，`message-cancel-pass5.json` 为 6 函数、1470 条，`message-cancel-join.json` 为 1 函数、463 条，均完整且无函数错误。明文 `co_job.cpp` 日志直接保留在 pass5 和 join 报告，不依赖 XOR 推导。工厂短包装与 stage leaf 的原件反汇编留存于 `send-cancel-job-factory.dumpbin.txt`。这些是静态证据，不是运行验证；原始 DLL、数据库及大型输出不提交。

本项相关函数的核验摘要见 [cancel verification](weixin4-cancel-verification.json)。Release 全量构建及 cancel/send_contract/messages/construction/memory/CLI 六项 CTest 通过。CLI 新增 `send_cancel_context`，原始标记按低位解释，并固定输出 `cancel_executed=false`、`cancellation_completion_verified=false`、`callbacks_drained_verified=false`，不会把只读观察当作执行成功。
