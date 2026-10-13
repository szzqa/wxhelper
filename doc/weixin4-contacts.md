# 微信 4.1.15.13 联系人查询结果静态适配

已实现 `src/weixin4/contact_backend.h/.cc`，将调用方提供的**稳定联系人查询结果快照**转换为持有自身字符串的 `ContactQuerySnapshot`。这是结果布局适配，不是可运行的全联系人枚举接口；未获取微信进程内存、未注入、未调用微信函数。

入口 `ReadContactQuerySnapshot(memory, identity, result_address, output, limits)` 校验原始二进制身份，再读取已完成的查询结果。`query_succeeded=false` 表示结果未就绪/无有效值，不等同于成功查询零条联系人。读取或结构验证失败会清空整个输出，不返回部分成功列表。

## 适用文件及证据来源

- 原始文件：`C:\Program Files\Tencent\Weixin\4.1.15.13\Weixin.dll`。
- 版本：`4.1.15.13`；机器：`0x8664`。
- SHA-256：`10f8e995453e2da46d4f2b5080cd6da1f13cc5147746adc119ceae38cb039de5`。
- 下文地址均为原始文件 RVA，首选映像基址 `0x180000000`；不是运行时绝对地址。
- 静态输出位于 `out/analysis/weixin-4.1.15.13/ida7-focused/contact-migration-pass{1,2,3}.json`。IDA 7 对分析副本作了限定范围分析；输入副本及原始文件来源见各输出中的 provenance。短小 vtable 方法另用 MSVC `dumpbin` 核实原始 DLL 指令，文件名 `contact-disasm-*.txt`。
- 这些是本地 IDA/dumpbin 静态观察，不是 REA Evidence API 返回的证据。REA/Ghidra 全量导入此前超时，没有成功快照；不能把它写成成功分析。

## 已确认的调用与容器结构

| RVA | 静态观察 |
|---|---|
| `0x2fb4520` | 按用户名列表的 SessionManager 聚合流程，包含 `get contact from db` 阶段。 |
| `0x26e8250` | 本地联系人查询、记录处理、复制输出；输出是 0x48 字节的带有效标记 map。 |
| `0x26e8c70` | 查询游标循环；每行构造 0x460 字节记录，调用解码和 map 插入，再销毁临时记录。 |
| `0x27115a0` | 按 WCDB 绑定的列类型执行数值/文本/blob setter。 |
| `0xf1fbf0` | 列名、记录内偏移、setter vtable 的绑定初始化。字段命名的主要依据。 |
| `0xf1f280`、`0x6f9130`、`0x6fad10` | 记录构造、复制、析构；交叉确认文本为 MSVC 32 字节 narrow-string。 |
| `0x2713540`、`0x270c3b0` | 输入/输出 map 插入；分配 0x478 字节节点，DWORD key 位于节点+0x10，记录位于节点+0x18。 |
| `0x2713460` | 构造/重置包装容器，最后写有效标记 1。 |
| `0x83820` | `mov rax,rcx; ret`；查询使用记录起点的 DWORD `id` 作为 key。 |

容器+0x08 是双向链表哨兵，+0x10 是元素数量，+0x40 是有效标记。节点+0 为 next，+0x08 为 previous。插入器哈希四字节数值 key，并非用户名字符串。旧 3.9.5.81 的连续 `0x698` 步长与 UTF-16 字段布局不能用于这个输出。

解码器只遍历链表，不依赖桶数组。它校验标记值、地址溢出、指针对齐、节点数、双向链接、哨兵尾节点、重复节点、重复 id、map key 与记录 id 一致性。它不声称验证整个哈希桶索引。

## 已解码字段

偏移相对于 0x460 字节记录起点，不是节点起点。字段名保留绑定表中的拼写。文本只复制原始窄字符串字节，不把未知编码强制转换为 UTF-16。

| 记录偏移 | 字段 | 已证实存储 |
|---|---|---|
| `0x00` | `id` | DWORD，map 的数值 key |
| `0x04` | `local_type` | DWORD，枚举含义未知 |
| `0x08` | `username` | narrow-string |
| `0x28` | `alias` | narrow-string |
| `0x48` | `encrypt_username` | narrow-string |
| `0x68` | `delete_flag` | DWORD，保留原始位值 |
| `0x6c` | `flag` | DWORD，保留原始位值 |
| `0x70` | `verify_flag` | DWORD，保留原始位值 |
| `0x78` | `remark` | narrow-string |
| `0x98` | `remark_quan_pin` | narrow-string |
| `0xb8` | `remark_pin_yin_initial` | narrow-string |
| `0xd8` | `nick_name` | narrow-string |
| `0xf8` | `pin_yin_initial` | narrow-string |
| `0x118` | `quan_pin` | narrow-string |
| `0x138` | `big_head_url` | narrow-string |
| `0x158` | `small_head_url` | narrow-string |
| `0x178` | `head_img_md5` | narrow-string |
| `0x198` | `chat_room_notify` | DWORD，保留原始位值 |
| `0x19c` | `is_in_chat_room` | DWORD，未假定为 C++ bool |
| `0x1a0` | `description` | narrow-string |
| `0x1c0` | `chat_room_type` | DWORD，枚举含义未知 |

文本 setter vtable `0x8fa1fa8` 的类型方法 `0xa5e6a0` 返回 3；setter `0xa5e6b0` 读取绑定对象+8 的偏移，加到记录基址。整数 vtable `0x8fa1e28`、`0x8fa2128`、`0x8fa2268` 的 setter `0x674660` 明确写 DWORD。结合构造器/复制器可确认宽度和偏移，不能由列名推断标志位业务意义。

## 尚未完成的运行时适配

`0x1015900` 经 `0x2fabb40` 打包 `0x2fb4520` 回调进入调度流程。该链条支持“给定用户名列表后读取并聚合本地数据”的判断；它没有证明全联系人枚举入口、线程要求、对象生命周期或可直接复用的调用 ABI。

`0x1019ce0` 的批量查询包装会调用 `0x101b3f0` 的 CGI 路径，不能当作纯本地读取。`CoGetContactListByCgi` 完整字符串起点是 `0x8fb83d8`，字符串导航命中本身不证明函数等价。

绑定还包含 `extra_buffer`（记录+0x1c8）。`0xf21170` 根据 `local_type` 将其解析到不同派生对象。该 blob、派生对象、记录尾部字段的语义及有效性尚未核定，因此不会读取或序列化。

下一步需在明确许可的受控环境中验证如何获得稳定查询结果、调度线程、对象持有关系、查询参数与完整性。当前代码没有进程读取器、调用器、Hook、路由接入，`kRuntimeSupported` 仍为 false；仅凭测试通过不能声称微信联系人功能已恢复。

## 隔离验证

`tests/weixin4_contact_tests.cc` 使用人工构造的稳定地址空间，覆盖两条记录、内联/堆字符串、多字节文本、原始高位整数、owned 输出、单字符串和整个结果的字节预算、profile 不匹配时零读取、有效空结果与无效值区分、坏链表/循环/数量不符/重复 id/key 不符、缺页、坏字符串及地址溢出。

未知字段保持毒值，测试确保解码过程不解引用它们。所有失败应丢弃已读取的部分结果。测试不接触微信进程或用户联系人数据。
