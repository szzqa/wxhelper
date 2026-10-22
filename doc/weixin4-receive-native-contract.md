# Weixin 4.1.15.13 接收存储结果契约

本轮恢复的是**同步消息存储任务的离线结果 payload**，不是实时接收事件。`receive_contract.h` 新增 `ReadReceiveStorageResultSnapshot`，读取原始结果标志和存储层返回的成功记录子集。它不安装 hook、不取得任务对象、不等待 future、不调用微信、不打开进程，也不发出消息通知。

原始 DLL 为 AMD64 `4.1.15.13`，SHA-256 固定为 `10f8e995453e2da46d4f2b5080cd6da1f13cc5147746adc119ceae38cb039de5`。所有偏移与函数 RVA 只适用于此文件。已有消息字段与 `0x2E8` 记录布局见 `weixin4-messages.md`；此次没有重新推断类型枚举、方向、时间单位或群成员规则。

## 必须区分的结果

| 观察 | 已证实的意义 | 不能由此推出 |
| --- | --- | --- |
| 调用 `AddMessageListToDBForSync` | 输入批次按对端类别分组并创建任务 | 消息已经落库、任务已经完成 |
| 批量结果 `+0x18` 为 1 | 原生存储结果标志；非空会话结果以 OR 归并，空过滤结果默认 1 | 所有会话成功、整批原子提交、收到消息的数量 |
| 返回 vector 中的一条记录 | 生产者从状态字节等于 1 的会话复制来的记录 | 新收到而非历史同步、已通知上层、已持久化到物理磁盘 |
| 单条 `CoAddMessageToDB` 返回记录 | promise 装入并返回记录副本 | 单条数据库写入成功 |

尤其不能将 `storage_result_flag` 命名为 `all_succeeded`，也不能把有返回记录直接转换成实时接收事件。

## 分组、去重和任务链

`AddMessageListToDBForSync 0x38926F0` 从连续 vector 以 744 字节推进。它通过 `0xA55490` 取得对端字符串，再由 `0x156A910` 分类，只接受类别 1/2；不支持类别进入诊断分支。记录包含动态字符串和共享成员，复制使用 `0x1C42E0`，不能把原生对象 `memcpy` 后当作可独立存活的消息。

`TaskInnerAddMessageListToDB 0x39255E0` 的既有完整静态报告明确包含三个阶段：

1. 可选预查询任务 `0x3963740` 通过存储上下文获取已有 ID 集合；随后出现明文计时标记 `query duplicate svrid`。
2. `0x3964130` 遍历 744 字节记录；启用过滤时调用 `0x3961D50`。命中的记录被跳过，其余记录以复制构造器装入新的共享对象，再按会话分组。随后出现 `filter duplicate svrid` 标记。
3. 非空分组进入 `0x3964F30`，调用 `MessageStorage::AddMessageMap 0x153B950`，按返回的会话结果构建最终 vector。空过滤分组直接返回空 vector 和标志 1。

`0x3961D50` 的完整函数显示去重按**会话字符串和完整 64 位 svrid**两级查询。会话为空、svrid 为 0、上层集合为空或任一键未找到时返回 false；日志 `0x90E8F98` 为 `invalid session name:%_ or svrid:%_`。因此不能仅凭全局 server_id 实现等价去重，也不能把零 ID 自动判为重复。`0x3964130` 的重复分支引用完整日志 `0x94FC8E0`：`TaskInnerAddMessageListToDB duplicate svrid:%_ in session:%_ with message:%_`。

单条路径 `CoAddMessageToDB 0x3896FE0` 也在启用过滤且 svrid 非零时启动查询任务 `0x39364A0`，后者调用 `0x15477C0`。该函数构造针对记录字段 `+0x148` 的存储查询并检查结果。此次不执行查询、不访问数据库，也不恢复或开放 SQL 接口。

## 成功子集与 OR 标志

`0x3964F30` 调用 `0x153B950` 后，对每个输入会话查询其结果字节：

- 结果字节等于 1 时，以 `0x1C42E0` 将该会话的记录复制到输出 vector，步长 `0x2E8`；诊断文本 `0x94FCC50` 完整还原为 `TaskInnerAddMessageListToDB succeed for session:%_, msg count:%_`。
- 否则不加入输出，进入 `0x94FF5B0` 的 `failed for session` 诊断分支。
- 随后遍历会话结果映射归并标志。原始指令 `0x39657F0: 80 E3 01` 为 `AND BL,1`，`0x39657F3: 0A 59 30` 为 `OR BL,[RCX+0x30]`；非空映射以 0 起始，空映射使用先前默认的 1。这是 OR，而非全成功的 AND。
- 结果 box 把 vector 放在 box `+8`、标志放在 box `+0x20`。任务结果提取器 `0x3896AD0` 验证结果类型后返回 box `+8`，所以**提取后的 payload**布局是 vector `+0/+8/+0x10`，标志 `+0x18`。

外层 `0x38926F0` 读取该 payload `+0x18`，true 时打印 `AddMessageListToDBForSync succeed, tag, insert count` 并合并成功子集，false 时打印 `failed, tag`。它再对类别结果做 AND，不能抹去每个类别内部的 OR 语义。不同会话部分成功时，外层“succeed”日志仍可能出现。

`0x153B950` 的独立日志给出完整方法名 `kernel::manager::MessageStorage::AddMessageMap`，并区分用户名转换失败、建表全失败与空结果。它将实际存储操作包装给 `0xFC5F80`，生产按会话的结果。当前没有完整验证底层事务提交、磁盘同步、崩溃恢复和每次通知的契约，因此这里仅使用“存储层报告的成功子集”，不承诺持久化或端到端接收成功。

## 单条结果不是数据库成功证明，也不是通知

在 `0x39368C0` 中，原生任务先复制记录，调用 `MessageStorage::AddMessage 0x1538FB0`；该返回布尔值用于诊断统计。随后没有按该值分支，而是调用 `0x3936D30` 完成返回记录。

`0x3936D30` 再复制 744 字节记录到结果 box（payload 在 box `+8`），调用 `0x39E6F0` 完成 promise，然后释放临时记录和共享对象。这个已恢复的后置步骤是**任务结果完成**，没有证据证明它是应用层消息监听器或实时通知投递点。不能根据这一函数中出现记录副本创建一个接收事件。

原生任务构造使用 `0x106F00` 绑定执行回调与析构回调；调度链经过 `0x2F9D610/0x2F9D750`，共享对象有引用计数增减，结果提取还有类型检查。直接拿入口地址同步调用、跨线程保存借用指针、绕过任务完成或析构都没有可用 ABI 保证。本轮不提供可调用的原生函数类型；IDA 对部分函数生成的 `__usercall` 寄存器参数也不能作为真实签名使用。

## 离线 DTO 与调用约束

```cpp
struct ReceiveStorageResultSnapshot {
  bool storage_result_flag;
  std::vector<ReceiveRecordSnapshot> success_subset;
};

ReadError ReadReceiveStorageResultSnapshot(
    const MemoryReader& stable_snapshot,
    const BinaryIdentity& original_identity,
    std::uint64_t result_payload_address,
    ReceiveStorageResultSnapshot& output,
    const Limits& limits = {});
```

调用方必须提供**已提取结果 payload**的稳定快照；地址不是任务对象、闭包、future 或 result box 首地址。读者不会主动寻找这些对象，调用方声明 profile 也不能证明某任意地址就是正确结果。

读取先校验固定 profile，检查非空地址及 `+0x18` 溢出，原生 bool 仅接受 0/1，其余返回 `InvalidObject`。vector 解码复用 `ReadReceiveBatchSnapshot`，不读取预留容量，记录数和所有记录字符串共享预算。字符串复制后由 DTO 独立拥有；不保留或操作原生对象指针、引用计数和虚表。

标志与子集分别保留，不凭数量补出失败会话、输入数量、重复消息数或额外跨字段约束。任何错误清空整个 DTO，包括已经读出的标志和先前成功解码的记录。它仍不能回答“所有输入都成功了吗”“这条消息是否刚收到”“上层是否收到通知”。

## 证据与验证

本地 `out/analysis/weixin-4.1.15.13/ida7-focused/` 保留：

- `message-migration-pass1.json`、`message-migration-receive-pass3.json`：既有批次、单条、同步主函数；本轮复用，没有重新分析大函数 `0x39255E0`。
- `receive-contract-pass1.json`：6 个任务回调/结果提取函数，1429 条指令与原始 PE bytes 一致。
- `receive-contract-pass2.json`：5 个存储、去重、完成包装函数，2710 条指令与原始 PE bytes 一致。
- 对应 `receive-contract-pass1-logs.json`、`receive-contract-pass2-logs.json`：分别 6、14 条编码日志的有界还原；保留原始字节、已知明文推断和未还原后缀，不执行目标解码器。

复现日志和原始指令校验：

```powershell
python -B scripts/review_weixin_message_logs.py `
  --binary 'C:\Program Files\Tencent\Weixin\4.1.15.13\Weixin.dll' `
  --directory out/analysis/weixin-4.1.15.13/ida7-focused `
  --report receive-contract-pass1.json --report receive-contract-pass2.json `
  --output out/analysis/weixin-4.1.15.13/ida7-focused/receive-contract-logs.json
```

`tests/weixin4_receive_contract_tests.cc` 使用合成快照，覆盖非空/空结果、0/1 与非法 2/255 标志、结果数量不等于输入数量的接口边界、完整 64 位 ID、744 字节步长、容量排除、脱离原始内存后的字符串所有权、记录数/跨记录字符串预算、后项损坏时整批清空、残缺向量、profile 提前拒绝、空地址、溢出和不可读字段。MSVC x64 C++17 `/W4` 编译无警告，测试通过。测试没有连接微信或真实收发消息。
