# Weixin 4.1.15.13 消息静态迁移记录

本模块目前是**稳定快照的离线解码器**。它不构成可运行的收发消息适配：没有打开进程、注入、hook、调用微信函数或构造可执行任务的入口。`kRuntimeSupported` 保持 `false`。

## 目标与证据

- 原始文件：`C:\Program Files\Tencent\Weixin\4.1.15.13\Weixin.dll`
- SHA-256：`10f8e995453e2da46d4f2b5080cd6da1f13cc5147746adc119ceae38cb039de5`
- PE 架构：AMD64；preferred image base：`0x180000000`。下表地址均为 RVA。
- 分析报告：`out/analysis/weixin-4.1.15.13/ida7-focused/message-migration-pass1.json`、`message-migration-receive-pass1.json`、`message-migration-receive-pass2.json`、`message-migration-receive-pass3.json`、`message-migration-semantic-pass4.json`、`message-migration-semantic-pass5.json`。
- IDA 仅分析清零 Exception Directory 的副本，所有节内容保持与原件一致，报告保留原件/副本哈希。副本哈希不能用于后端的原件 profile 校验。分析是选定函数范围内的静态反编译，并非全库分析或运行时观测。
- 仓库保存的 `doc/weixin4-message-semantic-verification.json` 记录 pass4/pass5 两个函数的 1,104 条指令与原件一致；本地 `out/analysis/weixin-4.1.15.13/ida7-focused/message-semantic-byte-verification.json` 还覆盖发送任务和存储日志函数，共 2,643 条记录、12,100 字节。此检查证明选定代码字节对应原件，不把反编译推断升级为运行时证据。

## 文本发送任务

`ReadTextSendTaskSnapshot` 读取 `0x54b1e10` 使用的闭包结构。整数地址只描述快照位置，不能作为函数指针执行。字符串读取使用项目统一的 x64 MSVC narrow-string 解码器，并复制为独立 `std::string`。

| 闭包偏移 | 已验证内容 | 证据 |
| --- | --- | --- |
| `+0x08` | 回调上下文地址，具体类型未知 | 成功/失败分支传给 `0x5429c30` |
| `+0x18` | `call_id` 字符串 | `0x54b2022` 等选取字符串，作为 `0x9805f18` 格式串的第一个参数 |
| `+0x38` | 消息对象地址 | `0x54b1e8e`，作为 owner pair 第一项传给 `0x178f040` |
| `+0x40` | 引用计数控制块地址，可为 null | `0x54b1e79` 和 `0x178f040` 中存在显式 null 分支 |
| `+0x48` | manager 上下文地址，具体类型未知 | `0x54b1e6b` 传给 `0x178f040` 的 RCX |

控制块 `+8/+0x0c` 为 strong/weak 计数；复制/释放路径使用 interlocked 增减和虚析构。读者不修改计数。非空控制块的非正/超出有符号范围计数作为无效快照拒绝。

消息对象 `+0xb0` 的字符串现输出为 `chat_id`。`0x9805f18` 是编码片段和普通 `%_` 占位符交错的日志格式；逐片段复核得到完整 `call_id=%_ Send text message success, chat_id=%_`，并与 `0x54b1feb..0x54b201b` 选取 `+0xb0` 作为第二实参对应。因此确认的是日志中的聊天标识，不将其称为正文或消息 ID，也不据此承诺可调用发送接口。

编码日志的 `call_id=` 标签通过静态已知明文验证：编码格式为 `A1 + 长度文本 + B1 + 十六进制内容 + C1`。用同一函数中的明文 `TaskInnerAddMessageListToDB` 与编码 `0x95059e8` 建立前缀 XOR 序列，交叉验证得到 `new_sync.cc`、`message_manager.cc`、`message_storage_impl.cc`、`AddMessageListToDBForSync`、`StartSendMessageSerialStage`；`0x9805f18` 第一片段完整解为 `call_id=`。没有执行目标的解码函数。后续用 `scripts/review_weixin_message_logs.py` 复用登录调查的跨日志 XOR 前缀，保留每片段原始字节、长度、已还原前缀和输入报告哈希；结果位于 `message-composite-log-review.json`。这仍是静态已知明文推断，超过 60 字节的片段保留未解析后缀标记，不把猜测补全当证据。

`0x178f040` 是小包装器：RCX 为上下文，RDX 是返回对象缓冲区，R8 指向两指针 owner pair，内部设置 R9b=1 后调用 `0x178f100`。后者创建任务并走队列/结果等待链。旧版直接传入 `WeChatString` 的发送签名不能套用。

`ReadTextSendResultSnapshot` 仅恢复结果对象的首两个 uint32；`0x54b1eb3..0x54b1ec0` 将它们 OR 后决定成功回调。`call_succeeded=true` 只表示该任务调用返回的成功分支；**不表示服务端确认，更不表示对方收到或阅读**。两个数的独立错误域/错误码语义尚未确认。

## 接收同步调查

`0x2e25b70` 对应 `new_sync.cc` 的 `CoDoSync`；`0x38926f0` 对应 `AddMessageListToDBForSync`。后者从 R8 指向的容器读取 begin/end，以 `0x2e8`（744）字节推进，逐项通过 `0xa55490` 取对端，再由 `0x156a910` 分类，接受结果 1/2 的记录，再用 `0x1c42e0` 复制整条记录。复制构造器证明这是含字符串和引用计数成员的连续记录，不能按旧版结构读取或直接 `memcpy` 后作为独立对象使用。

`0xa55490` 在记录 `+0x18/+0x38` 两个字符串与当前账号比较后返回对端字符串。`0xa56380 → 0x227db80 → 0xa185b0` 生成记录身份描述：复制 `+0x164`、`+0x144`、`+0x150` 以及 `+0x2c8`，随后生成 `peer_num_num` 或使用 `+0x2c8`。这些数值字段的名字不能仅凭这条调用链证明；后续独立日志确认 `+0x150` 为排序序号、`+0x164` 为时间值，`+0x144` 的语义仍未确认。

追踪 `CoAddMessageToDB`（`0x3896fe0`）建立了独立字段证据：`0x3897734` 从同一记录读取 `+0x148` 的 uint64，在非零且启用过滤时进行重复查找，随后将该值作为 `0x94fc828` 格式串 `duplicate svrid:%_ in session:%_ with message:%_` 的第一个参数。函数还用 `0x1c42e0` 复制该记录，确认与批次的 744 字节布局相同。**服务器消息 ID 是 `+0x148`，不能将附近 `+0x150` 的身份描述字段误认成该 ID。**

`ReadReceiveRecordSnapshot` 与 `ReadReceiveBatchSnapshot` 已实现以下选定字段；DTO 拥有字符串存储，不含原生对象指针或 vtable。

| 记录偏移 | 输出 | 语义状态 |
| --- | --- | --- |
| `+0x148` | `server_id`，uint64 | 重复消息查询及 `svrid` 日志确认，保留完整 64 位 |
| `+0x0c` | `message_type`，uint32 | `0xa55e70` 的明文 `,type:` 后取数；枚举对应关系未知 |
| `+0x18` | `from_username`，string | `0x1830c60` 将 XML `fromusername` 写入此处 |
| `+0x38` | `to_username`，string | 同一函数将 XML `tousername` 写入此处 |
| `+0x58` | `sender`，string | `0xa55e70` 的明文 `,sender:` 后读取；群成员和收发方向规则未恢复 |
| `+0x150` | `sort_sequence`，uint64 | 明文 `,sort_seq:` 后读取，不能当作 `server_id` |
| `+0x164` | `time_raw`，uint32 | `CoAddMessageToDB` 日志 `time:` 实参；单位与时间基准未知 |
| `+0x168` | `message_status`，uint32 | 明文 `, msg status:` 后读取；枚举未知 |
| `+0x16c` | `upload_status`，uint32 | 明文 `, upload status` 后读取；枚举未知 |
| `+0x170` | `download_status`，uint32 | 明文 `, download status:` 后读取；枚举未知 |
| `+0x178` | `origin_source`，uint32 | 明文 `, origin_source:` 后读取；枚举未知 |
| `+0x180` | `content`，string | `0x1830c60` 将解析/转换后的 XML `content` 值写入此处；解码器保留记录中的原始字符串字节，不假设为纯文本 |

`message-migration-semantic-pass4.json` 的 `0xa55e70..0xa561b7` 是已有 `CoAddMessageToDB` 调用的记录描述器。其明文标签与随后参数形成独立字段证据：`0xa55f5a` 读取 `+0x150`，`0xa55f7a..0xa55f92` 选取 `+0x58` 字符串，`0xa55fa8` 读取 `+0x0c`；状态字段分别紧跟对应标签。这些标签不依赖 XOR 推断。

`message-migration-semantic-pass5.json` 的 `0x1830c60..0x1831d41` 属于 `MessageManager::HandleReplaceMsgNotice`，处理特殊消息替换通知。`0x183116e..0x1831187` 为栈上记录复制并初始化 **744 字节**模板，随后使用与同步存储记录相同的 `0xa55490` 对端访问器。以汇编中的 `var_5F8` 为记录基址，`fromusername` 在 `0x18311c4` 选取并写入 `var_5E0`（`+0x18`），`tousername` 在 `0x18314a2` 选取并写入 `var_5C0`（`+0x38`）；`content` 在 `0x18310c2` 选取，经转换后在 `0x1831621..0x1831667` 写入 `var_478`（`+0x180`）。这是同一布局的静态字段赋值证据，不是已收到普通消息的运行时观测。

时间字段另有交叉验证：`0x3896fe0` 的记录 `+356` 实参被记录为 `time:`；替换路径在 `0x183166c` 写入相同 `+0x164`，并在 `0x1831672..0x1831679` 将其乘以 1000 写到 `+0x150`。这一特定路径的乘法不证明所有消息的排序序号都遵循同一公式，读者不转换时间、不推断时区。

批次入口要求标准 begin/end/capacity 三地址头，按 `0x2e8` 步长读取 begin/end 内的选定字段；不把预留容量当作已有消息。检查范围、步长、记录数和所有记录共享的字符串总预算，任一记录失败则整批输出清空。它不证明未读取的原生对象成员有效。

内容字段位置已确认，但各种消息的内容格式、类型/状态枚举、时间单位与基准、相对当前账号的收发方向、群成员规则和本地 ID 仍未确认。`micromsg.SendMsgRequestNew` 字符串完整起点是 `0x93d4f28`；它属于协议导航材料，并不是可直接调用的发送入口。`new_sync.pb.cc`、备份导入 `AddMsgTime` 以及 `fmessage_manager.cc` 的好友验证消息日志不能作为普通实时消息字段证据。

## 验证边界

合成快照测试覆盖 inline/heap 字符串、独立存储、null owner 分支、非法计数、空对象、损坏字符串、不可读范围、地址溢出、单字符串/总字符串预算、profile 不匹配及两个状态字的成功判定。接收测试额外覆盖超过 2^63 的 ID/排序序号、相邻字段不同值、超过有符号范围的原始 uint32 状态、UTF-8/内嵌 NUL 内容、发送者和内容独立存储、744 字节步长、容量排除、空批次、倒置/残缺范围、跨记录预算、损坏发送者/内容及后项失败不泄露前项结果。测试在 Release 下仍执行检查；仅链接本项目的离线读者，不加载 Weixin.dll。

每个入口在任何地址读取前校验版本、原件 SHA-256 和 AMD64 架构；失败输出清空。输入必须是稳定且来源可信的快照；调用方声明 profile 不等于验证了实际运行环境。缺少实时消息入口定位、对象获取与生命周期、完整字段语义、线程/队列契约、消息构造和服务端结果处理的运行时证据，因此这里没有开放实时收发功能。
