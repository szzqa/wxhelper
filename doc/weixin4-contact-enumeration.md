# 4.1.15.13 联系人集合与类型查询结果

本轮找到了不依赖调用方提供用户名列表的本地联系人加载链，并增加 `ReadContactTypeQuerySnapshot`，用于解码这条链中已完成、稳定的查询结果。**仍未证明账号全部联系人入口，也没有新增在线调用能力。** 类型查询结果、缓存选择结果和界面通讯录有不同的筛选范围，不能互换。

所有材料来自安装文件和离线 IDA 报告。原件 `C:\Program Files\Tencent\Weixin\4.1.15.13\Weixin.dll` 为 AMD64，SHA-256 为 `10f8e995453e2da46d4f2b5080cd6da1f13cc5147746adc119ceae38cb039de5`。本轮没有读取微信进程内存、注入、执行微信内部函数或访问真实联系人。

## 从按用户名查询转向通讯录消费者

`0x1015900` / `0x1019ce0` 的直接调用链没有产生完整用户名全集：

- `0x3b2e710..0x3b2ed86` 从传入的 R8 向量，经虚接口筛出需要补查的用户名。
- `0x3eebd70..0x3eec734` 遍历调用方提供的 `[RCX,RDX)`、步长 `0x30` 的条目，先查缓存，再把未命中用户名交给 `0x1015900`。
- `0x2a744e0..0x2a75b5f` 的 `SessionManager::SyncSessionList` 从任务携带的字符串向量分批加载，含尾批提交；不是无参数联系人枚举。
- 既有 `SessionManager::OnInitSync` 还把来源记录分成两组，仅一组进入 `0x1015900`。其他直接消费者包括群成员搜索、品牌会话和移动消息同步，均不能据其名称认定为全量联系人。

结果发布路径也存在信息丢失：`0x2fb7510` 把带 `+0x40` 有效标记的聚合 map 放入 `0x60` 字节类型擦除对象，再调用 `0x39e6f0` 发布。`0x1048c70` 是 map 复制，`0x10494c0` 是先构造空 map 再交换内容的移动。`0x1015900` 在聚合结果失效时返回新空 map，故这个上层空容器不能区分有效空结果和失效结果。这些节点为 `0x2c0` 字节，也不是既有低层联系人 map 的 `0x478` 字节节点。

## 新确认的加载链与集合范围

| 函数 RVA | 已确认行为 | 范围限制 |
| --- | --- | --- |
| `0xfff5a0..0x10014a1` | 日志完整名称 `ContactManager::CoLoadFriendContact`；读取 manager `+0x1a8` 存储上下文并调用 `0x2fabee0` | 随后还有缓存补齐和原生异步工作；不是可以直接调用的独立接口 |
| `0x2fabee0..0x2fac068` | 日志 `LoadFriendContact`；构造 `0x50` 字节任务，工作函数 `0x2fba9b0`；没有用户名列表输入 | 仍依赖原生存储对象、调度和引用计数持有 |
| `0x2fba9b0..0x2fbad04` | 向 `0x26ea550` 传 DWORD 向量 `{1,2,5,7}`，常量 RVA `0x93f9a2c`；有效结果送入 `0xf24590`；最后发布 bool | bool 说明这次路径的结果存在/缓存更新路径完成，不能证明整个账号或界面通讯录完整 |
| `0xf24590..0xf25292` | 日志 `ContactCache::AddFriendContactList`；持锁遍历输入，检查用户名、规范化部分显示字符串，再把对象 pair 移入缓存 map | 有跳过异常条目的路径；不是“清空后精确替换全集”的证明 |
| `0xf25860..0xf259b2` | 持锁遍历 cache `+0xd0` 链，选择 `(record.local_type \| 4)==5`，即原值 1 或 5，输出 16 字节对象/owner pair 向量 | 完整遍历的是当时缓存中的选定类型；没有可证的账号代次或缓存完整性标志 |
| `0x715dc0..0x716c36` | `ContactService::GetContactList(ContactListQ…` 读取上述向量，又排除 `flag & 8`，该分支日志为 `IsBlackList`；按查询对象 `+8` 和用户名判别函数继续筛选、转换、排序 | 不是所有本地 Contact 行；本函数中未确认 offset/limit 分页参数 |
| `0x18a4990..0x18a5818` | `ContactListTree::InitializeTreeData` 读取同一个缓存选择向量，再按界面组转换、分组 | 界面树是另一种表示，不能用树行数证明数据库完整性 |

`0xf26850..0xf2743c` 在好友加载之后从缓存及辅助索引生成进一步处理的用户名列表。它仍包含检查和筛选，不能把这个补齐列表反过来当成全量源。方法名称来自已有明文锚点支持的有界 XOR 推导，长于已确认流长度的后缀保留未知；实际调用与布局依据原件指令和数据流，不只依据名称。

## 类型查询及其不完整结果风险

`0x26ea550..0x26eadeb` 接收 R8 指向的 DWORD 类型向量。`0x26eb2a0` 引用既有 Contact WCDB registry `0xf1fbf0`，选择字段偏移 `4`；此前字段绑定已经确认其名称为 `local_type`。`0x270c730` 按 4 字节步长把输入值转换为表达式元素。此处没有恢复具体 SQL 文本，因此不补写假设的 SQL。

类型 4 有特殊处理：函数从输入向量移除一个原值 4，将剩余类型用于 this `+0x88` 的表；若移除了 4，还独立查询 this `+0x90` 的表。它会修改输入向量，不能把其签名包装成接收不可变列表的可调用 ABI。

两份结果通过以下方式合并：

1. 普通分支有有效结果时先取其列表。
2. 特殊分支有有效结果时，将其追加到已有列表，或独立成为最终列表。
3. 只要至少一份结果存在，最终可返回 `engaged=1`。另一份请求分支失败不会强制最终失效。
4. 空输入没有启动这两个分支，最终没有有效结果；空输入不表示“查询所有类型”。

低层 `0x26eb3f0` 也先依据查询准备结果建立 engaged 列表，再调用行处理函数。因此**结果存在不等于每个请求分支或所有行都已被证实成功读取**。最终对象不保留原始类型请求、分支错误、账号标识、完成代次或覆盖率，解码器无法从它恢复这些信息。

逐记录调用的 `0xf21170` 已在旧 `contact-migration-pass2.json` 分析，本轮没有重复运行。它处理 `extra_buffer` 和派生区域，未更改本次复制的 13 个字符串、8 个整数字段；这些字段与原有 `ContactRecord` 共用解码逻辑。

## 新离线接口

`src/weixin4/contact_enumeration.h` 定义：

```cpp
struct ContactTypeQuerySnapshot {
  bool result_present = false;
  std::vector<ContactRecord> contacts;
};
ReadError ReadContactTypeQuerySnapshot(
    const MemoryReader&, const BinaryIdentity&, std::uint64_t result_address,
    ContactTypeQuerySnapshot&, const Limits& = {});
```

`result_address` 必须指向 `0x26ea550` 的稳定完成输出，而不是活动 task、promise、缓存、服务对象或另一个结果 map。

| 位置 | 已确认内容 |
| --- | --- |
| result `+0x00` | 双向链哨兵地址 |
| result `+0x08` | 节点数 |
| result `+0x10` | optional engaged 字节，0 或 1 |
| node `+0x00/+0x08` | next / previous |
| node `+0x10` | Contact 对象地址 |
| node `+0x18` | 原生 owner/control 地址；读者不读取或跟随 |

节点分配大小为 `0x20`。记录字段沿用 [联系人字段证据](weixin4-contacts.md)，由 internal `contact_record_reader.h` 的共享字段解码器复制为 owned 数据。没有复制裸原生对象、调用原生锁或修改引用计数；稳定性和保活由快照提供方负责。

返回语义严格区分：

- `ReadError::None` 且 `result_present=false`：原生 optional 没有结果；不能进一步归因为查询失败或空集合。
- `ReadError::None` 且 `result_present=true`：本快照中有效列表已完整解码；零节点是有效空列表。此标记不是 `query_succeeded`、`is_full` 或账号通讯录完整性。
- 其他 `ReadError`：快照读取、身份或结构验证失败，全部输出清空，不返回先前已解码的部分联系人。

读者保留列表顺序、重复 id/username、原始类型和标志，避免给跨表结果增加未经证实的唯一性约束。不会套用服务层的黑名单、类别或界面分组筛选。没有全量/部分覆盖标记；缺失的请求和分支信息保持未知。

## 验证与材料

新增 `tests/weixin4_contact_enumeration_tests.cc` 使用合成内存，在 `/O2 /DNDEBUG /W4 /WX` 下仍执行全部检查。覆盖 owned 字符串、内嵌 NUL、重复身份与类型顺序、原值标志、有效空/无结果、三项身份校验先于内存读取、数量及总字符串预算、损坏双向链和计数、截断、字符串终止符、空/未对齐指针和地址溢出。测试禁止读取 owner、哨兵 payload 和未知派生区，并验证后项失败时不泄漏前项。原 `weixin4_contact_tests.cc` 也在启用断言的独立构建中回归验证。

本轮原件核验报告均位于 `out/analysis/weixin-4.1.15.13/ida7-focused`，报告 SHA 和逐指令结果由同名 verification 保存：

| 报告 | 函数数 | 与原件一致的指令数 |
| --- | ---: | ---: |
| `full-contact-pass1.json` | 6 | 2484 |
| `full-contact-pass2.json` | 6 | 3955 |
| `full-contact-pass3.json` | 3 | 1961 |
| `full-contact-pass4.json` | 3 | 269 |

对应 `*-logs.json` 保留编码原字节、解码前缀和完整性限制。这些是本地 IDA/原件静态证据，不是 REA 原生引擎成功或微信运行验证。原始安装文件、线上接口和 `kRuntimeSupported=false` 不因这个离线解码器改变。完整账号集合、所有联系人类别、原生调用 ABI、活动对象代次和全部异步完成/取消契约仍未建立。

18 个函数结果、8,669 条指令的可提交摘要见 [核验记录](weixin4-contact-enumeration-verification.json)。集成 MSVC x64 Release 构建通过，联系人三个模块、memory 和 CLI 共五项 CTest 通过。CLI 新增 `contact_type_query`，合成用例覆盖无结果、有效空列表和非空结果，明确输出 `all_contacts_verified=false`。
