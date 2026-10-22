# Weixin 4.1.15.13 登录服务离线读取

实现入口是 `src/weixin4/login_backend.h` 的 `ReadLoginObservation`。它从调用方提供的稳定快照读取根上下文、服务共享指针、两个标志字节及账号查询键，校验两个对象的虚表，并返回独立 DTO。它不打开进程、不注入、不调用微信内部函数，也不修改共享指针引用计数。

已恢复登录服务的**对象布局、静态读取链和登出启动标志**。`LoginObservation::logout_started` 观察退出流程是否已经启动；`state` 始终为 `Unknown`，因为静态证据仍没有完整证明认证成功、离线重连或退出完成。账号查询键非空和服务存在均不能替代登录状态。

## 二进制约束

- 版本：`4.1.15.13`，AMD64 `0x8664`。
- 原始 `Weixin.dll` SHA-256：`10f8e995453e2da46d4f2b5080cd6da1f13cc5147746adc119ceae38cb039de5`。
- `BinaryIdentity` 必须匹配 `profile.h`；不匹配在读取快照前返回 `ProfileMismatch`。
- IDA 分析派生副本仅修改 Exception Directory，哈希不同，不能作为此 profile 的原始文件。
- 模块基址由快照提供；全部地址使用受检加法，不假设固定装载地址。

## 已确认的读取链

| 位置 / RVA | 静态证据 | 后端用途 |
| --- | --- | --- |
| 全局 `0xB912690` | getter `0x45D10` 返回该全局指针；`0x500E0` 分配并发布根对象 | 找到根上下文 |
| 根虚表 `0x8D804E8` | 构造器 `0x42350` 写入 | 拒绝错误对象布局 |
| 根 `+0x68 / +0x70` | `0x469A0` 复制双指针并增加控制块引用计数 | 只读服务指针与控制块地址 |
| 服务虚表 `0x8DFE2F8` | 构造器 `0x365BF0` 写入；工厂 `0x65F60` 创建共享对象 | 拒绝错误服务布局 |
| 服务 `+0x38` | 虚表 slot `+0` 为 `0x373DC0`，读取 `byte & 1`；根 `0x4FFD0` 委托该 slot | 原始字节、getter 对应最低位 |
| 服务 `+0x39` | `0x3BADBB` 以 XCHG 置 1；`0x4FFF0` 读取并 `& 1`；自动认证消费者据此取消请求 | 原始字节、最低位及 `logout_started`；不表示已退出完成 |
| 服务 `+0x48` | 虚表 slot `+0x18` 为 `0x36F930`，返回该地址；根 `0x4F3C0` 委托该 slot | 窄字符串 `account_lookup_key` |

账号查询键的命名来自消费链：`0x5456D70` 的账号信息 handler 通过上述虚函数拿到字符串，检查长度，并传给 `0x100A690` 的账号记录查询。后端不会把它转换为登录判断。

`0x65980` 从其输入对象 `+0x2B8` 取得所有者，在调用 `0x65F60` 后将结果双指针写入所有者 `+0x68 / +0x70`。这补充了工厂与服务持有字段的赋值证据。离线读取仍要求实际快照中的根虚表和服务虚表精确匹配。

## 两个标志的语义边界

`0x365BF0` 先将 `+0x38 / +0x39` 清零，然后在构造流程中把 `+0x38` 置 1。`0x36CBC0` 在一系列异步操作及 `0x36DD30` 清理之后把 `+0x38` 置 0。它确实表示一个服务生命周期状态，但“构造完成”不等于认证成功；目前没有给出完整的认证/重连状态机。

后续静态复核对编码日志作了已知明文交叉验证，详见 `weixin4-login-static-followup.md`。`0x3BBD60` 的方法名还原为 `LoginManager::Quit`，调用 `0x3BAD60`；后者通过 `0x47220` 获取同一服务 shared_ptr，并在 `0x3BADBB` 执行 `XCHG CL,[RAX+0x39]`，前一条将 CL 置 1。消费者 `0x4BC2F0` 在 `0x4FFF0` 为 true 时进入 `cancel autoauth. is start logout` 日志分支。因此可把服务 `+0x39` 的最低位作为 `logout_started` 观察值，而不能把它反转后当作已登录。

DTO 保留原始字节和最低位，另提供 `std::optional<bool> logout_started`。只在实际服务对象存在并解码成功时提供 true/false；根或服务为空、解码失败时没有值，不复制内部 getter 的“服务不存在则返回 true”分支。`state` 不随这两个值或字符串改变，不能将此模块直接替换旧 `AccountService + 0x7F8` 的 `CheckLogin` 实现。

## API 与错误处理

```cpp
ReadError ReadLoginObservation(const MemoryReader& snapshot,
                               const BinaryIdentity& identity,
                               std::uint64_t module_base,
                               LoginObservation& output,
                               const Limits& limits = {});
```

`context_present`、`service_present` 和 `has_service_flags` 区分存在、缺失和未读取。`service_control_address` 只是观察地址；不读取或改变引用计数。`account_lookup_key` 使用 x64 MSVC 32 字节窄字符串布局，包含内联/堆字符串、长度/容量、终止符和地址溢出检查；有效上限为 `min(max_string_bytes, max_total_string_bytes)`。

失败时清空整个输出，避免调用方混用旧值或部分读取结果。错误包括 profile 不匹配、对象虚表不匹配、地址溢出、数据不可读、字符串布局无效或超出读取预算。`MemoryReader` 必须提供稳定地址空间；本模块不宣称并发运行中内存的生命周期安全。

## 验证与证据文件

`tests/weixin4_login_tests.cc` 使用纯内存合成快照，覆盖两个对象虚表、共享指针空值/别名控制块、0/1/2/255 标志、内联和堆字符串、单串/总量预算、profile 提前拒绝、读取失败、溢出及错误后输出清空。已用 MSVC 14.51 x64、C++17、`/W4` 编译并执行通过；测试没有连接或操作微信。

静态分析结果位于 `out/analysis/weixin-4.1.15.13/ida7-focused/`：

- `context-pass1.json`、`context-pass2.json`：根对象与原始 getter。
- `account-pass1.json`、`account-handler-review.json`：账号查询链。
- `login-migration-pass1.json` 至 `login-migration-pass4.json`：四轮有界 IDA 反编译。
- `login-semantic-pass5.json`：退出链和服务 `+0x39` 的写入；`login-contact-log-review.json`：编码日志的有界交叉验证。
- `login-service-vtable-candidates.json`：候选虚表表项；其中使用的关键 leaf 已由第三轮 IDA 验证。
- `login-state-wrapper-call-validation.json`：从原始 `.pdata` 函数起点进行的 dumpbin 调用点验证。

IDA 输入为保留全部节字节的静态派生副本；函数边界和原始哈希来自安装目录中的原始 PE。原始安装文件未修改，未执行目标函数或读取运行中微信内存。
