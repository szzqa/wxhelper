# Weixin 4.1.15.13 内核阶段与认证边界

本轮确认了根对象 `+0x330` 的 32 位内核阶段，并加入离线 `ReadLoginObservation`。它和已有服务 `+0x39` 的 `logout_started` 都是本地流程观察值。对外 `LoginState` 仍为 `Unknown`：开始登录、设置回调结束、退出启动均不能证明服务器认证或当前连接有效。

分析只读取磁盘上的原始 DLL 和 IDA 静态报告，没有注入、读取运行中微信内存、调用微信函数或发送消息。支持对象仍严格限定为 AMD64、版本 `4.1.15.13`、原始 SHA-256 `10f8e995453e2da46d4f2b5080cd6da1f13cc5147746adc119ceae38cb039de5`。IDA 派生副本的节字节与原件相同，但自身哈希不能代替原件 profile。

## 阶段字段的读写证据

读取链为模块基址加全局 RVA `0xB912690`，得到根对象；先验证根虚表是模块基址加 `0x8D804E8`，再读取根 `+0x330`。这里只复制 4 字节，不调用 getter、setter、虚函数或原子指令。

setter `0x45510..0x457AA` 的日志常量 `0x8D843D8` 完整还原为 `kernel::KernelPrivate::SetKernelStage`。函数保留传入的 EDX，在 `0x45792` 执行 `87 B7 30 03 00 00`，即 `XCHG ESI,[RDI+0x330]`。其前面的日志还读取旧阶段并打印新旧值。日志语义来自既有已知明文 XOR 交叉校验，指令字节另与原始 PE 逐条验证，不能把推断日志当作导出符号。

本轮限定扫描 setter 的直接 E8/E9、常见 RIP-relative LEA 和非执行节绝对指针，找到 5 个 E8 调用点。以下调用点均已由反汇编确认；该扫描并不证明不存在其他间接调用或直接字段写入。

| 原始值 | DTO 描述 | 写入点和时序 |
| --- | --- | --- |
| `1` | `Initialized` / `initialized` | 初始化函数 `0x43FD0..0x44135` 尾部 `0x44121` 调用 setter 传 1；退出函数 `0x53510..0x54F61` 在 `0x54EEA` 传 1、`0x54EEF` 调 setter，此前将网络层 uin 置 0，随后还有收尾调用。该值表示初始化/退出收尾所使用的内核阶段，不保证远端认证状态。 |
| `2` | `LoginFlow` / `login_flow` | `KernelPrivate::CoLogin` (`0x4C140..0x4CE64`) 在 `0x4C299` 传 2、`0x4C29E` 调 setter。它早于 CurrentUser 更新、网络层 uin 设置、`0x4CB21` 创建登录上下文任务；因此不能视作认证完成。 |
| `3` | `SetupCallbackComplete` / `setup_callback_complete` | 回调 `0x67030..0x67536` 在 `0x674BE` 传 3、`0x674C3` 调 setter，随后清空根 `+0x338/+0x340` 的任务 shared_ptr。这是设置回调尾部的阶段观察，不能据此声明在线。 |
| `4` | `LogoutFlow` / `logout_flow` | `KernelPrivate::CoLogoutFlowInternal` (`0x53510..0x54F61`) 先取消待完成的设置任务，再于 `0x53989` 传 4、`0x5398E` 调 setter，随后执行退出清理，尾部写回 1。 |
| 其他值 | `Unknown` / `unknown` | 保留原始 uint32 值，不猜测 0、5 或其他值的含义。 |

这些英文描述是本项目对已观察路径的命名，并非恢复出的官方枚举标识。阶段 3 的回调关联还有根 `+0x338/+0x340` 的取消链 `0x53160` 支持；该函数的日志为 `CoCancelSetupLoginContextIfNeeded`，但尚未证明阶段 3 与网络认证成功等价。

`CriticalLogin` (`0x3B69F0`) 在原始反汇编 `0x3B7160` 取得根对象，随后读取 `+0x330`；值 2、3、4 均进入 `[Critical] kernel is login` 分支。它包括登录准备和正在退出，说明该日志里的 kernel login 条件宽于“当前已通过网络认证”，不能直接翻译成公开 `LoggedIn`。

## 登录服务发布顺序

`CoLogin 0x4C140` → 任务创建 `0x4D740` → 回调 `0x65980` → 工厂 `0x65F60` 构造登录服务。`0x65980` 将结果 shared_ptr 发布到根 `+0x68/+0x70` 后，才调用初始化 `0x368590`。该顺序与前面的阶段 2 写入相互印证：服务对象存在和内核阶段开始不构成认证结果。

本轮另排除了两个容易误判的下游函数：`0x36FA70` 将字符串复制到服务 `+0x1F8`，`0x66070` 将结构化结果交给任务完成器。它们均没有提供独立的全局认证成功布尔值。账号查询键 `+0x48` 也继续只作为查询键处理。

## 与网络认证状态的关系

另一条只读静态证据链已从同一根对象定位到按 host 索引的认证对象：根虚表 slot `+0x60` → 服务 → `0x3730C0` 按 host 字符串查询容器 → 返回认证对象 → leaf `0x9185E0` 读取对象 `+0x100` 的 32 位值。容器查询原本持有服务 `+0x4B0` 的 SRW 排他锁，涉及 sentinel `+0x510`、buckets `+0x520`、mask `+0x538`；不能将任意节点的值当作全局登录状态。

消费者 `MakeSureAuth 0x345540` 对值 3、1、0 采取不同路径，值 0 的路径还依赖服务 getter 返回的字符串；`OnAuthEnd 0x345CE0` 的自动认证/成功参数属于该回调事件，不能据一次事件推定全局状态或认证新鲜度。认证对象的成功/失败写入与构造、map 发布随后由独立分析闭合，新增的离线 `ReadHostAuthObservation` 只查询调用方指定的 host。完整契约和剩余限制由 [网络认证契约](weixin4-network-auth-contract.md) 单独记录；任何快照读取均不触碰原生锁。

要提升 `LoginState`，仍需证明面向当前主账号的 host 选择、所有成功/失败/失效/重连路径、退出完成的正反条件和状态优先级。当前证据只能增加内核流程观察，不能恢复旧版 `AccountService+0x7F8` 的布尔契约。

## 离线接口与失败语义

`LoginObservation` 新增：

```cpp
std::optional<std::uint32_t> kernel_stage_raw;
KernelPhase kernel_phase = KernelPhase::Unknown;
```

`KernelPhaseName` 提供上表对应名称。根为空时 raw 无值、phase 为 Unknown；根存在但服务为空时仍返回阶段。未识别阶段保留 raw，phase 为 Unknown。根阶段不可读、地址溢出、任一后续读取失败，均返回既有 `ReadError` 并清空整个 DTO，避免混用部分观察和旧值。读取前仍必须匹配 profile，且通过根虚表验证。

已有 `logout_started` 独立于阶段：服务 `+0x39` 的写入位于 `0x3BADBB`，自动认证消费者据此取消请求。true 只表示退出启动，false 不能证明登录；服务不存在时为无值。阶段、两个服务标志以及账号查询键的任意组合都不会改变 `state = Unknown`。

## 可复现检查与验收

源脚本 `scripts/find_weixin_direct_refs.py` 固定原件哈希，最多接收 16 个显式 RVA，输出 raw candidate 与原始 `.pdata` 范围，清楚区分代码字节模式和数据指针。它不把字节模式匹配当作已验证指令，也不执行目标。复现本轮导航：

```powershell
python -B scripts/find_weixin_direct_refs.py `
  --binary 'C:\Program Files\Tencent\Weixin\4.1.15.13\Weixin.dll' `
  --target 0x45510 `
  --output out/analysis/weixin-4.1.15.13/ida7-focused/kernel-state-writer-callers.json

python -B scripts/review_weixin_login_logs.py `
  --binary 'C:\Program Files\Tencent\Weixin\4.1.15.13\Weixin.dll' `
  --directory out/analysis/weixin-4.1.15.13/ida7-focused `
  --report login-auth-pass6.json --report login-kernel-phase.json `
  --output out/analysis/weixin-4.1.15.13/ida7-focused/login-kernel-phase-logs.json
```

本地输出 `login-auth-pass6.json` 的 1230 条和 `login-kernel-phase.json` 的 1839 条指令记录与原件 bytes 匹配，后者包含 setter、退出流程和阶段 3 回调；日志复核产出 22 条有界常量。分析 JSON 位于忽略的 `out/`，不提交原始 DLL、IDB 或伪代码大文件。

`tests/weixin4_login_tests.cc` 用合成稳定快照覆盖阶段 0/1/2/3/4/5/UINT32_MAX、服务存在与缺失、根缺失、阶段缺字节、根地址溢出、错误后输出清空，并断言所有阶段下认证状态始终 Unknown。MSVC x64 C++17 `/W4` 编译和执行通过且无警告。

`tests/test_weixin_direct_refs.py` 的 3 个合成 PE 测试覆盖正负 rel32、E8/E9/LEA、绝对数据指针、`.pdata` 排他结束边界、禁止跨节匹配、目标数量/RVA 范围和原件哈希门禁，全部通过。没有测试打开微信进程或调用其函数。
