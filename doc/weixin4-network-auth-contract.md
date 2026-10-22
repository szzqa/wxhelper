# Weixin 4.1.15.13 按主机认证状态契约

本次增加 `ReadHostAuthObservation`：从调用方提供的稳定快照，经模块全局根对象、登录服务、host 映射读取对应认证对象的状态。该值描述**指定 host 的本地 AxAuthLogic 状态**，不表示全局账号在线、当前连接有效或会话仍未过期。全局 `LoginState` 继续为 `Unknown`；内核流程阶段另见 [登录阶段契约](weixin4-login-auth-contract.md)。

适用 profile 固定为 AMD64、版本 `4.1.15.13`、原始 `Weixin.dll` SHA-256 `10f8e995453e2da46d4f2b5080cd6da1f13cc5147746adc119ceae38cb039de5`。分析和测试没有注入、读取运行中微信的内存、调用微信函数或发消息。匹配 profile 表示离线布局适用，`kRuntimeSupported` 仍为 false。

## 从根对象到 host 状态的证据

调用链 `MakeSureAuth 0x345540` → `0x50F70` → `0x3730C0` → `0x9185E0` 已逐条比对原始 DLL 字节：

1. 全局 RVA `0xB912690` 存根指针，根虚表 RVA 为 `0x8D804E8`。`0x50F70` 调根虚表 `+0x60`（`0x469A0`）取得服务 shared_ptr，对象地址位于根 `+0x68`。服务虚表 RVA 为 `0x8DFE2F8`。
2. `0x3730C0` 原本持有服务 `+0x4B0` 的 SRW 排他锁。它以输入字符串的**全部字节**做 64 位 FNV-1a，初值 `0xCBF29CE484222325`、乘数 `0x100000001B3`，与 bucket mask 按位与后查表。比较使用字节长度和 `memcmp`，没有大小写、URL 或域名规范化。
3. 每个 bucket 有 first/last 两个节点指针。查找从 last 开始沿节点 `+0x08` 的 previous 反向遍历，遇 first 停止。节点 key 是 `+0x10` 的 MSVC 窄字符串；匹配后将节点 `+0x30` 对象传入 leaf `0x9185E0`。
4. leaf 的原件字节 `8B 81 00 01 00 00 C3` 为 `MOV EAX,[RCX+0x100]; RET`。它本身是通用字段 getter，另有其他组件调用者；**仅凭这个偏移不足以认定对象类型**。下面的构造和发布链补齐了身份。

服务中的实际容器字段如下；偏移均以服务对象为基址：

| 偏移 | 已验证布局 |
| --- | --- |
| `+0x508` | map 头开始，包含负载因子；当前 decoder 不输出此字段 |
| `+0x510` / `+0x518` | 双向链表 sentinel / 元素数量 |
| `+0x520` / `+0x528` / `+0x530` | bucket 存储 begin / end / capacity_end |
| `+0x538` / `+0x540` | hash mask / bucket 数量 |
| bucket `+0x00` / `+0x08` | first / last 节点；空桶均指 sentinel |
| node `+0x00` / `+0x08` | next / previous |
| node `+0x10` | 32 字节窄字符串：16 字节 union、size、capacity |
| node `+0x30` / `+0x38` | AxAuthLogic 对象 / shared_ptr 控制块 |

`0x370C20..0x37202F` 构造并发布这些映射：在 `0x371329` 分配 `0x188` 字节；控制块虚表在 `0x37134D` 写为 RVA `0x8DFEAD8`，强/弱计数初始化为 1；对象位于控制块 `+0x10`，占 `0x178` 字节，清零后于 `0x37136F` 调构造函数 `0x379020..0x379191`。对象首字段不是虚表，decoder 因此验证**控制块虚表和 object = control + 0x10**。

该函数把同一对象/控制块 pair 传给 `0x379610..0x379AFA`，并在服务锁下交换 map 到服务 `+0x508` 起的布局，随后调用 `StartAxAuth`。原件反汇编另外确认：`0x379824` 将新节点 `+0x10`、host key、原 pair 传给 `0x1A4CC0`；该 helper 在 `0x1A4D87/0x1A4D8F` 将 pair 写到目的地址 `+0x20/+0x28`，即节点 `+0x30/+0x38`。这将 getter、map 值和 AxAuthLogic 生命周期连成同一证据链。`0x05BA20` 的 map 构造还明确初始化 mask=7、bucket_count=8，分配 `0x80` 字节 bucket 存储。

## 状态读写与命名边界

| raw | 本项目描述 | 写入与消费证据 |
| --- | --- | --- |
| `1` | `idle_or_retryable` | 构造 `0x379020` 初始化对象 `+0x100=1`；`StopAxAuth 0xEDAEB0` 在 `0xEDAFD7` 写 1，随后将重试计数 `+0x118` 置 3；`OnAxAuthFaild 0xEDB920` 在 `0xEDBACF` 也写 1。它可能是初始、停止、失败或等待重试，不能命名为“已登出”或“确定失败”。 |
| `2` | `authenticating` | `StartAxAuth 0xEDA200` 只在当前状态为 1、重试限制允许时继续，在 `0xEDA91F` 原子写 2，再提交异步认证请求。失败后的部分路径会立即再次调用 Start，因此观察到 1 不意味着重试已经结束。 |
| `3` | `success_recorded` | `OnAxAuthSuccess 0xEDB210` 在 `0xEDB384` 原子写 3；响应 lambda `0xEDBC80` 分别派发成功/失败分支，日志也区分两者；`MakeSureAuth 0x345540` 对该 host 状态 3 直接返回 true。这里只证明本地成功结果已记录。 |
| 其他，包括 `0` | `unknown` | 保留原始 uint32，不猜测未闭合的枚举含义。不存在 host entry 与存在 entry 且 raw=0 必须分别表示。 |

这些是本项目的语义描述，非恢复出的官方枚举符号。`StartAxAuth`、`StopAxAuth`、`OnAxAuthSuccess`、拼写为 `OnAxAuthFaild` 的名称，来自已知明文 XOR 推导后交叉校验的编码日志；推导方法和 60 字节边界见 [静态复核](weixin4-login-static-followup.md)。例如 `0x8E00020` 仅恢复到 `LoginContextPrivate::CheckAxAuthStateFor…` 的前缀，没有补写未知后缀。方法名只是语义线索，实际写入与调用关系另由原件指令确认。

`MakeSureAuth` 还有两个关键分支：状态 1 结合时间间隔和正在进行的自动认证请求决定重试；返回值 0 时仍会检查 `0x4F480` → 服务 getter `0x36F9E0` 返回的另一个字符串是否为空。因此，“没有 Ax host entry”也不等于“未登录”。本实现不读取或公开该字符串内容，也没有复刻整套联网决策。

`OnAuthEnd 0x345CE0` 的第二、第三参数由日志和分支确认为 `is_auto_auth`、`is_auth_success`；成功时调用对象虚表 `+0xE0` 的后续路径。该回调是一次事件，本轮没有证明一个覆盖全部账号、host、掉线、过期和重连的全局认证位。`LoginManager::OnUserDidLogin 0x41D4C0` 更新缓存/特性配置，账号查询 `0x5456D70` 返回账号记录，也都不能替代这项证明。

## 离线接口与防护

实现位于 `src/weixin4/auth_backend.h/.cc`：

```cpp
ReadError ReadHostAuthObservation(
    const MemoryReader&, const BinaryIdentity&, std::uint64_t module_base,
    std::string_view host, HostAuthObservation&, const Limits& = {});
```

输出拥有自己的 host 字符串，并包含 context/service/entry 是否存在、原始状态可选值、状态描述、来源地址和选中桶检查的节点数。输入 host 可以引用上一份输出的字符串。读取前先验证 profile；任何错误清空整份输出，避免保留此前的成功状态。

- 根或服务为空：读取成功，对应 presence 为 false，`state_raw` 无值。它表示快照中不存在该对象，不能推定完整登出。
- host 不存在：`host_entry_present=false`，`state_raw=null`，`state=unknown`。
- host 存在且 raw=0：`host_entry_present=true`，`state_raw=0`，`state=unknown`。
- host 存在且 raw=3：`state=success_recorded`，仍不验证全局登录和当前连接。
- entry 存在但对象/控制块为空、关系或虚表不符、引用计数无效：拒绝该结构，不伪装成缺 entry。

decoder 校验根/服务虚表、map 大小、bucket 数量为至少 8 的 2 的幂、mask、bucket 存储边界、指针对齐和加法/乘法溢出。它验证 sentinel 首尾关系，反向检查**选中桶的全部节点**，包括前后指针互指、环、重复 key、hash 所属桶、对象/控制块身份；即使命中目标也继续验证该桶。两侧相邻节点的 key 必须属于其他桶，以拒绝被截短的 bucket 边界。完整链表都在选中桶时，还核对声明的总数量。

`max_elements` 限制 map 声明大小及遍历次数；`max_string_bytes` 限制 query 与每个 key；`max_total_string_bytes` 同时计入 query、遍历 key 和两个边界邻居 key。不会扫描或分配整个 bucket 数组，也不宣称验证了所有未查询桶。

原函数依赖 SRW 锁和 shared_ptr 生存期。这里读取的是调用方已经稳定的快照，不获取锁、不递增引用计数，也无法把持续变化的现场内存变成一致快照。当前项目没有该功能的实时 reader 或注入适配器。

## CLI 和验证

离线 JSON CLI 的请求形式为 `{"feature":"auth_host","address":"0x模块基址","host":"fixture.test"}`；完整输入还须提供 profile 和快照 segments，见 [离线工具说明](weixin4-snapshots.md)。输出显式保留 `global_login_verified=false` 和 `connection_verified=false`，不会把 `success_recorded` 转成旧版登录布尔接口。

`tests/weixin4_auth_tests.cc` 使用自产合成快照，覆盖冲突桶、命中/缺失、大小写差异、SSO/堆字符串、空 host、内嵌 NUL、高位字节、状态 0/1/2/3/4/UINT32_MAX、字符串所有权、输出别名、缺根/服务、每个必要读取地址不可读、边界截断、坏链/环/重复 key、坏共享对象、超预算和地址溢出。独立 MSVC x64 C++17 `/W4 /WX` 编译运行通过。根 CMake Release 集成的 login/auth/memory/CLI 四项 CTest 通过，其中 CLI 包含 9 个测试。

本地证据位于 `out/analysis/weixin-4.1.15.13/ida7-focused/` 的 `login-auth-callbacks-pass1.json` 至 `pass4.json` 及其 `*-verification.json`，补充原件反汇编为 `login-auth-map-insert.dumpbin.txt`、`login-auth-map-value.dumpbin.txt`、`login-auth-map-constructor.dumpbin.txt`。全轮 28 函数、10777 条指令的原件核验摘要为 [auth-contract-verification](weixin4-auth-contract-verification.json)。这批报告来自本地 IDA 7 和 dumpbin 静态工作流，不冒称 REA Evidence API 返回的运行结果；原始 DLL、数据库和大型伪代码输出均不提交。

要恢复全局“是否已登录”，剩余证据仍是当前主账号的 host 选择规则、认证失效/断线/重连的完整写入路径，以及退出与认证状态的优先级。本次新增字段不能替代这些未验证条件。
