# 4.1.15.13 联系人查询契约补充

本轮只读取安装文件的静态字节和既有 IDA JSON，没有读取运行中微信、执行内部函数、注入或访问真实联系人。原始 `Weixin.dll` SHA-256 为 `10f8e995453e2da46d4f2b5080cd6da1f13cc5147746adc119ceae38cb039de5`。

## 方法名与证据等级

新增 `scripts/review_weixin_login_logs.py` 对既有报告引用的编码日志作有界复核，输出 `out/analysis/weixin-4.1.15.13/ida7-focused/login-contact-log-review.json`。文件名明文锚点、35/60 字节函数名假设及独立日志交叉校验过程见 `weixin4-login-static-followup.md`。这里的名称是有交叉支持的已知明文 XOR 推导，不是导出符号；超过 60 字节的后缀没有补猜。

| 函数 RVA | 日志常量 RVA | 完整还原或有界前缀 | 契约含义 |
|---|---|---|---|
| `0x1019CE0` | `0x8FBCCD0` | `kernel::manager::ContactManager::CoLoadContactList` | 给定用户名列表的加载流程，有缓存、本地数据库和 CGI 回退。 |
| `0x2FB4520` | `0x93FA0E0` | `kernel::manager::ContactStorageImpl::GetSessionInfoByUsernam…` | 聚合会话需要的多种本地记录；原始方法名字节数为 121，只有前 60 字节已还原。 |
| `0x2FB4520` | `0x93F9B80` | `contact_storage_impl.cc` | 更准确的所属实现文件；此前笼统称为 SessionManager 聚合流程应按此修正。 |
| `0x26E8C70` | `0x9325B10` | `kernel::BaseTable<class kernel::Contact>::GetObjectsMapWithF…` | 支持已有 WCDB 列选择、游标解码、map 结果链；方法名字节数为 65，后缀尚未还原。 |
| `0x2A3BA50` | `0x935D7B0` | `virtual kernel::manager::SessionManager::OnInitSync` | 属于初始化同步流程，不能当成全联系人枚举。 |

## CoLoadContactList 的缓存、数据库与网络分支

`contact-migration-pass1.json` 中 `0x1019CE0` 的既有反编译同时包含：

- `start load user_list`（`0x8FBBAB0`）标示按输入用户名列表处理。
- `all in cache`（`0x8FBC178`）对应缓存满足查询后返回的路径。
- `all find in db`（`0x8FBCD40`）对应本地数据库满足查询的路径。
- `all not find in db`（`0x8FBB7B0`）和两处 `0x101B3F0` 调用对应本地未满足时的 CGI 回退。

`0x101B3F0` 的 CGI 性质来自已有调用/字符串证据，新增日志仅补强分支名称。不能把 `0x1019CE0` 暴露为保证只读本地、没有网络副作用的联系人查询接口，也不能从名称中的 `List` 推出“枚举当前账号全部联系人”。

## 本地结果的适配范围

`0x2FB4520` 同时处理 chatroom、detail、contact、biz 信息。它调用 `0x26E8250` 时末两个实参为 `0,0`，随后检查联系人结果有效标记，并与其他本地查询结果聚合。输入用户名向量以 32 字节窄字符串为步长处理；它不是从无参数调用中生成全部用户名。

`0x26E8250` 的已观察契约仍是输出一份带有效标记的 map 结果：`+0x40` 有效标记、`+0x08` 链表哨兵、`+0x10` 元素数量；节点 key 为 DWORD id，记录从节点 `+0x18` 开始，长度 `0x460`。这个结果可以由 `ReadContactQuerySnapshot` 从稳定快照解码。失效结果与成功空结果必须区分。

仍未确认：如何从真实运行环境获取稳定且完整的结果、线程和对象持有要求、调用 ABI、`0x26E8250` 两个布尔参数的全部业务含义、全部联系人枚举入口和联系人类别/标志枚举。新增方法名证据不会改变现有解码器的字段偏移，也不满足把旧 `/api/getContactList` 接入 4.x 的条件。

## 可复核材料

- `contact-migration-pass1.json`：`0x1019CE0`、`0x2FB4520`、`0x26E8250`、`0x26E8C70` 与 `0x2A3BA50` 的既有反编译。
- `login-contact-log-review.json`：每条编码 bytes、RVA、解码前缀、完整性、引用函数及输入报告 hashes。
- `scripts/review_weixin_login_logs.py`：仅用标准库和本项目 PE 解析器；固定原始 SHA，错误输入拒绝，未执行目标代码。
- `tests/weixin_log_review_test.py`：编码格式/长度、截断、假设冲突与前缀一致性测试，使用合成数据，不要求安装微信。

本轮没有新启动 IDA。现有 IDA 输出属于本地静态证据，不应记为 REA 引擎成功分析或运行时验证。
