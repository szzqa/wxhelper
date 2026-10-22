# 4.1.15.13 文本消息来源对象的构造契约

本轮确认文本 function-call 路径如何创建、填写和持有消息来源对象，并提供 `ReadTextMessageDraftSnapshot` 离线解码器。解码器读取已有稳定快照，**不会创建原生对象、提交发送、调用微信或取得运行中内存**。`Draft` 指本页分析的构造路径，不能证明任意输入对象当前处于“尚未发送”阶段。

原件为 AMD64 `4.1.15.13` 的 `Weixin.dll`，SHA-256 `10f8e995453e2da46d4f2b5080cd6da1f13cc5147746adc119ceae38cb039de5`。所有地址均为该原件的 RVA。现有发送上下文与完成结果见 [发送任务契约](weixin4-send-native-contract.md)，同步存储记录见 [接收存储结果契约](weixin4-receive-native-contract.md)。三个对象布局互不等价。

## 从文本调用到原始 owner pair

`0x54b02f0..0x54b103e` 的文件日志为 `message_send_text_message_function_call.cc`，函数名编码日志的已还原前缀为 `chatbot::functioncall::MessageSendTextMessageFunctionCall::D`；独立调用地点标记为 `DoBusiness`。长方法名未还原的后缀不作为证据。

这个函数先以输入聊天标识查询联系人，失败分支打印 `Contact not found, chat_id`，并回调失败结果。成功路径在 `0x54b0420` 调用 `0x6f4c70`，取得新的 `{object, control}`，再执行下列已核对写入。

| 对象偏移 | 构造路径写入 | 离线字段与限制 |
| --- | --- | --- |
| `+0xb0` | 复制输入结构首个 narrow-string；日志将该输入称为 `chat_id` | `chat_id`，不能据此判断当前联系人存在或接收人有效 |
| `+0x758` | 从同一输入结构 `+0x20` 的 narrow-string 复制字节 | `text_argument_bytes`，保留文本调用参数的字节；未验证编码、规范化或最终网络载荷 |
| `+0x118` | `0x54b042d` 写 uint32 值 1 | `word_118_raw`；一般枚举意义尚未确认，不命名为全局消息类型 |

两处字符串赋值都包含 inline/heap 处理、容量检查和复制路径。`+0x758` 是原件 `0x54b043b` 的 `LEA` 结果；不能混用此前导航阶段的 `+0x750` 猜测。该来源对象也不是同步存储使用的 `0x2e8` 记录。

之后通过 `0x47220 → 0x36c740 → 0x6f4d90` 获取 MessageManager owner pair。`0x6f4d90` 使用 registry 的 `0x31b3f0/0x31a250` 与 key 虚表 `0x8e4e168`，是取得服务对象的路径，不是 manager 构造器。缺少 manager 的分支回调错误。

`0x54b0d94` 分配 `0x58` 字节闭包，写虚表 `0x9805968`。其中 `+0x38/+0x40` 持有新消息来源 pair，`+0x48/+0x50` 持有 manager pair。虚表 `+0x10` 指向已分析的 `0x54b1e10` 发送任务。由此闭合了之前只在闭包里观察到的 message pair 来源，也证明 manager 在这里有控制块，不能只保存裸 manager 地址。

这条上层函数还注册 callback holder 并通过调度函数提交闭包。callback 的取消、调度线程与账号代次仍需单独契约；本页不把该入口包装成可从 HTTP 工作线程直接调用的签名。

## 工厂、继承初始化和持有关系

`0x6f4c70..0x6f4d58` 执行：

1. 申请 `0x7a8` 字节块，control 虚表设为 `0x8e534f8`，strong/weak 初始值为 1/1。
2. 对象从 control `+0x10` 开始，先清零 `0x798` 字节，再调用 `0x766680`。
3. 返回 object/control pair，并在对象 `+8/+0x10` 建立指向自身 object/control 的 weak pair。原件中 strong 临时增减抵消、weak 增加一次；工厂正常返回时只有该一个 strong owner 的情况下计数为 1/2。

`0x766680..0x766743` 先调用 `0x766780` 初始化基类，然后将对象虚表改为 `0x8e53588`，把 `+0x758` 与 `+0x778` 初始化为空 narrow-string（capacity 15）。`0x766780..0x766a9d` 明确清空初始 self weak pair、初始化 `+0xb0` 字符串、清空 `+0x118` 起始字，并初始化多个其他成员。本轮没有完整恢复这些成员的业务意义或所有析构/异常展开路径。

离线读者严格限定这一工厂变体：要求 object 为 control `+0x10`，两个虚表等于给定 module base 加上述 RVA，内嵌 self weak pair 与输入 pair 一致。strong 必须为正、weak 至少为 2，且均在正 signed int32 范围内；允许额外 strong/weak 引用，不要求恰好 1/2。缺少任一持有关系或虚表不符返回 `InvalidObject`，不猜测其他分配形式。

这些验证只说明输入与已观察的布局约束相容。调用方仍需提供原件身份和稳定快照来源；给定 profile、虚表地址或计数本身不证明真实对象身份，更不授予 native 调用能力。

## 离线接口与验收

```cpp
ReadError ReadTextMessageDraftSnapshot(
    const MemoryReader& stable_snapshot,
    const BinaryIdentity& original_identity,
    std::uint64_t module_base,
    std::uint64_t owner_pair_address,
    TextMessageDraftSnapshot& output,
    const Limits& limits = {});
```

入口地址指向 `{object, control}` pair，不是对象首地址、闭包或 SendContext。输出的 owner 地址仅为观察值；字符串由 DTO 独立持有。所有地址计算检查溢出，两个字符串共享总字节预算，同时各受单串上限约束。profile 不匹配在读取内存前拒绝。任何错误清空完整输出，避免旧值或部分结果留存。空字符串允许读取；本接口不重复执行原生业务验证。

`tests/weixin4_message_construction_tests.cc` 使用合成且稀疏的地址空间，覆盖：ASLR module base、两个虚表、object/control/self weak 关系、有效的额外引用、非法或溢出的计数、任意原始 `+0x118` 数值、inline/heap 与含 NUL 的字符串、独立所有权、单串/总预算边界、空字符串、损坏或缺页、profile 提前拒绝、空输入、地址溢出及错误清空。未解码的对象成员和 native 虚表内容无需映射，测试不会执行其函数指针。

独立 MSVC x64 C++17 `/W4 /WX` 编译与该测试通过。链接只需 `message_construction.cc`、`memory_reader.cc`、`profile.cc`，不需要微信、Detours 或 Winsock。

集成 Release 全量构建和 construction/messages/send_contract/memory/CLI 五项 CTest 通过。CLI 新增 `text_draft`，请求需提供 pair 的 `address` 和 `module_base`；`text_argument_hex` 无损保留包括 NUL、非法 UTF-8 在内的原始参数字节，文本展示仍采用 JSON 替换规则。输出明确 `native_construction_executed=false` 和 `send_executed=false`。本项选定函数核验见 [construction verification](weixin4-construction-verification.json)。

静态证据位于 `out/analysis/weixin-4.1.15.13/ida7-focused/`：

- `message-lifecycle-pass1.json`：文本上层构造和发送闭包捕获。
- `message-construction-pass2.json`：工厂、derived 构造、manager 获取及共同 await 上下文。
- `message-lifecycle-pass3.json`：基类初始化。
- 对应 `-verification.json` 与 `-logs.json` 保留原件字节核验及有界日志还原。本页使用的日志名称仍属于经独立锚点核对的 XOR 推断，不是导出符号或目标运行结果。

已明确的运行时限制还包括 `0x48bd30` 的原生协程上下文要求：缺少 TLS 当前 coroutine 时进入明文 `must be called from coroutine context` Fatal 路径。这确认不能从任意调用线程直接进入 await。完整构造 ABI、基类其他成员、取消/终止时的 callback 责任、账号切换失效规则以及服务端确认依然未闭合；`kRuntimeSupported` 继续为 false。
