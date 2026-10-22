# Weixin 4.1.15.13 本地登录谓词与主账号认证边界

`ReadLoginObservation` 新增 `kernel_is_login`，还原静态证据明确命名为 `kernel::IsLogin()` 的**本地登录上下文谓词**。它不是按 host 认证状态的汇总，也不是全局账号认证或网络连接是否有效的结论。`LoginObservation::state` 继续为 `Unknown`。

适用对象限定为 AMD64 Weixin `4.1.15.13`，原始 `Weixin.dll` SHA-256 为 `10f8e995453e2da46d4f2b5080cd6da1f13cc5147746adc119ceae38cb039de5`。本轮只检查磁盘文件和稳定的合成快照，没有读取运行中微信内存、注入、调用微信原生函数或发消息。所有地址均为 RVA。

## 本地谓词的闭合证据

已有根对象和服务布局，见[登录阶段契约](weixin4-login-auth-contract.md)。本轮把 getter 与三个独立消费者连接起来：

| 位置 | 原件行为或日志证据 |
| --- | --- |
| 全局 `0xB912690`，getter `0x45D10` | 返回根对象；根虚表为 `0x8D804E8`。 |
| 根虚表 `0x8D804E8 + 0x68` | 磁盘中的绝对函数指针指向 `0x4FFD0`，不是读取退出标记的 `0x4FFF0`。 |
| `0x4FFD0..0x4FFE2` | `MOV RCX,[RCX+0x68]`；服务非空则跳服务虚表第一个槽；为空则 `XOR EAX,EAX; RET`。这是 leaf 的完整字节范围，不冒称 `.pdata` 边界。 |
| 服务虚表 `0x8DFE2F8 + 0` | 指向 `0x373DC0`。该 leaf 完整字节为 `0F B6 41 38 24 01 C3`，即取服务 `+0x38` 字节并与 1。 |
| `0x9137C0..0x913914` | `0x9137DE` 取根，`0x9137E9` 调根虚表 `+0x68`；false 分支使用日志 `!kernel::IsLogin()`，日志地址 `0x8EA77F0`，引用位置 `0x9138A3`。 |
| `0x1D4EB30..0x1D4F4A2` | ScreenShoter 分享入口 `0x1D4EB60` 取根、`0x1D4EB6B` 调同一槽；退出路径日志为 `ScreenShoter::share IsLogin exit.....`，地址 `0x91AA520`，引用位置 `0x1D4EDAC`。 |
| `0x4BDBC0..0x4BDE1E` | Netcore 回调 `0x4BDBE2` 取根、`0x4BDBED` 调同一槽；false 分支记录 `not login`，地址 `0x8E15F78`，引用位置 `0x4BDDAA`。 |

函数名和日志来自已知明文 XOR 推导后的静态解码；调用、表项和字段读取另由原始指令与 PE 数据佐证。没有把日志文本单独当作字段证明。

`+0x38` 的写入仍说明它是本地生命周期状态：服务构造 `0x365BF0` 设置该位，清理路径 `0x36CBC0` 清除该位。构造完成本身不证明服务器认证成功。`+0x39` 的 `logout_started` 则在退出协程启动前置位，因此可能与 `kernel_is_login=true` 同时存在。实现保留这个组合，不自行添加覆盖规则。

## 最小离线接口

新增字段为 `std::optional<bool> LoginObservation::kernel_is_login`：

| 稳定快照条件 | 输出 |
| --- | --- |
| 根指针为空 | `null`；没有将缺失根对象解释成已经完成退出。 |
| 根身份已验证，服务指针为空 | `false`；遵循 `0x4FFD0` 的明确空服务分支。 |
| 服务身份已验证且可读 | `(service_flag38 & 1) != 0`。 |
| profile、对象、读取、字符串或预算检查失败 | 返回相应错误并清空整份输出，字段为 `null`。 |

保留原有 `service_slot0_value` 和原始字节字段兼容调用方。新字段使用现有读取结果，没有增加现场进程访问或调用原生 getter。它不依赖账号查询键、内核阶段、退出标记或任何 host 的认证结果。根和服务虚表校验、字符串预算及错误清空继续适用。

## 主账号认证仍缺少的证据

本轮另检查两条路径，结果不支持把它们合成为主账号认证布尔值：

1. **UI 路由状态。** `0x1E1ECF0..0x1E1EEEB` 在路由不满足条件时记录 `not in login state`。它调用 `0x9911A0..0x991330`（日志名为 `mmui::WeChatApplication::GetCurrentState`），再调用 `0x1E1EAD0..0x1E1EC81`。后者进行 Qt QHash 按类型查找、缺失时创建 16 字节组件，并调用 `0x28C390` 做类型转换；返回的是指针，不能直接当作认证布尔值。其构造虚表 `0x91C4EC8` 的 COL 位于 `0x91C4F30`，指向 TypeDescriptor `0xB30B930`；名称字节不是明文。`GetCurrentState` 使用的 RTTI `0xB16E990` 名称同样不是明文。本轮没有恢复该类型的完整身份及进入/退出生命周期，因此不增加 UI 状态 decoder。
2. **按 host 认证。** `0x50A80..0x50B41` 从根取得服务并调用 `0x370C20`；`0x374620..0x3746AF` 从关联对象的序列化配置恢复输入，再调同一 builder。已分析的 `0x370C20` 按配置组创建 AxAuthLogic，并将组内多个 host 映射到同一 shared_ptr；没有证明其中某一个 host 是当前主账号的唯一认证来源。`0x50A80` 的一个原始直接调用候选在 `0x42F955`，属于大型混淆函数 `0x420850..0x43B005`；仅此调用不能恢复主账号 host 选择规则。详见[按主机认证契约](weixin4-network-auth-contract.md)。

失效路径也不能被简化：`OnSessionTimeOut 0x41B250..0x41B3C0` 在已开始退出的分支清根 `+0x348` 自动认证请求位，否则跳入另一处理函数；`CoClearAxAuth 0x36B620..0x36BAB3` 按参数清理映射或遍历调用 StopAxAuth。`OnAuthEnd 0x345CE0` 的成功回调通过虚表 `+0xE0` 进入已有 `0x345F00` 同步 Netcore 会话配置，没有新增可证明认证有效期的全局位。

因此，主账号认证判定仍需要闭合当前账号/会话归属、认证成功、失效及重新认证、退出与切换账号的完整状态关系。`kernel_is_login=true` 与某 host 的 `success_recorded` 均不补足这些条件；现阶段不将它们映射到 `LoginState::LoggedIn` 或 `LoggedOut`。

## 验证与可复核材料

`tests/weixin4_login_tests.cc` 使用自产快照验证 true/false/null 区分、原始字节 0/1/2/255 的低位语义、根存在但服务缺失、所有已知和未知内核阶段、退出开始仍保留 true、非空账号键但谓词 false、空账号键但谓词 true，以及失败后整份输出清空。独立 MSVC x64 C++17 `/W4 /WX` 编译运行通过，测试不连接微信。

本地分析材料位于 `out/analysis/weixin-4.1.15.13/ida7-focused/`：`main-account-pass1.json`（2 函数、356 条原件指令核验）、`main-account-consumers.json`（3 函数、748 条）、`main-account-pass2.json`（4 函数、315 条）及对应日志/核验文件。getter 来自 `login-migration-pass1.json` 和 `pass3.json`；Netcore 消费者来自 `login-auth-callbacks-pass2.json`。

合计 9 个新函数结果、1,419 条指令的核验摘要见 [main-account verification](weixin4-main-account-verification.json)，作业范围已加入分析目录。REA public CLI 本轮复核留存 Evidence `ev_40633e1feb841402eb3fb30dacdcd3e4f600e046917b9ae8ce9620591d9c0164`，原件身份一致；原生调用结论来自 IDA 静态报告，未将其冒称 REA native dossier。

集成验证：MSVC x64 Release 全量构建通过，login/auth/memory/CLI 四项 CTest 通过；CLI 的 `login` 输出新增 nullable `kernel_is_login`，黑盒用例验证其与认证结论分离。4.x 运行开关继续关闭。

`main-account-navigation.json`、`main-account-host-source-navigation.json` 由可复用 `scripts/find_weixin_direct_refs.py` 对指定 RVA 生成，仅包含原始字节模式导航候选，明确标记 `decoded=false`，不能独立代替指令解码。原始 DLL、IDA 数据库和大型伪代码结果不进入版本库。
