# Weixin 4.1.15.13 兼容性调查

调查日期：2026-10-13。目标为用户指定安装目录中的客户端文件，未执行该 DLL、注入用户微信或调用真实收发消息接口。

## 结论和当前支持范围

当前源码绑定 `V3_9_5_81`，不是微信 4.x 后端。修复后的代码仍只允许 `WeChatWin.dll 3.9.5.81 / AMD64` 命中旧配置，并在其他版本加载时返回失败。**这次稳定性修复与构建成功不代表 4.1.15.13 的消息、联系人、数据库接口已经可用。**

当前检测基于模块名、PE 架构和固定文件版本；旧版本原始 DLL 的哈希/函数签名字节未提供，因此不能验证同版本的修改版客户端。没有伪造 4.x 偏移，也没有推荐通过降级绕过迁移。

## 二进制证据

| 项目 | 观察值 |
| --- | --- |
| 文件 | `C:\Program Files\Tencent\Weixin\4.1.15.13\Weixin.dll` |
| 文件版本 | `4.1.15.13` |
| 文件大小 | 201,552,944 bytes |
| SHA-256 | `10f8e995453e2da46d4f2b5080cd6da1f13cc5147746adc119ceae38cb039de5` |
| 格式 | PE32+ / AMD64，12 个节、117 个导出 |
| 旧常量 | 79 个函数 RVA、4 个全局 RVA、10 个对象字段偏移，共 93 个 |

- REA 6.4.0 `inspect_pe_resources` Evidence ID：`ev_40633e1feb841402eb3fb30dacdcd3e4f600e046917b9ae8ce9620591d9c0164`。完整资源证据在 `out/analysis/weixin-4.1.15.13/rea-pe-resources.json`，资源树覆盖完整；REA 在此操作中将版本资源内容视为不透明字节，没有反编译函数。
- 标准库脚本 `scripts/inspect_weixin.py` 的独立观察在 `out/analysis/weixin-4.1.15.13/pe-layout.json`；其文件摘要与 REA 一致。节/导出数量已与 MSVC dumpbin 交叉核对，版本由 PE 资源解析和 Windows 文件版本 API 分别确认。
- 4 个旧全局 RVA 在当前文件中全部位于只读可执行 `.text`。把旧全局对象访问直接套到新文件会读取代码字节。这足以否定简单复用；并不证明某个新版函数已被恢复。
- 导航候选：`CoGetContactListByCgi` 字符串 RVA `0x8fb83da`、`micromsg.SendMsgRequestNew` RVA `0x93d4f31`、UTF-16 `MicroMsg.db` RVA `0x8e245a0`。这些是静态字符串位置，不能作为可调用函数地址。
- REA 原生分析首次失败记录在 `rea-native-inspect.json`：缺少配置的 Ghidra/IDA。随后在项目 `out/tools` 获取并校验[官方 Ghidra 12.1.4](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build)，使用现有 JDK 21，环境变量仅对分析进程生效。下载摘要见 `ghidra-download.json`；原生分析结果/边界见 `rea-ghidra-inspect.json` 及相邻日志。
- 本次 Ghidra 完成导入、识别为 `x86:LE:64:default:clangwindows` 并进入自动分析，但 336.209 秒后 REA 返回 `provider_timeout`，`details.operation=list_documents`、`timeout_ms=330000`。缺失 PDB，EH/RTTI 恢复有告警；这些是分析覆盖限制，不能视为微信程序缺陷。**这次 Ghidra 调用没有成功的原生 Evidence ID、函数快照或可续分析数据库。** REA 所属 Java/CLI/反编译进程与临时项目已清理；已有资源证据和独立 PE 布局观察仍然有效。

## 用户提供的 IDA 与定向分析

用户随后提供 `D:\IDA`。本地检查确认 `idat64.exe` 为 IDA 7.0.17.0914，IDAPython 使用随安装提供的 Python 2.7.13，`hexx64` 插件报告 Hex-Rays 7.0.0.170914。当前 [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) 要求更新的 IDA/Python，不能把此安装直接当作已连接的 REA IDA provider。

已用自产空客户端 fixture 验证命令行导入、保存/重新打开 `.i64` 和两个函数的反编译。通过 `scripts/ida7_analyze.py` 直接驱动 IDAPython；输出标记为 `direct_idapython_static_analysis`，与 REA Evidence 分开保存。该脚本校验目标 SHA-256，禁用全局自动分析，只对明确选定的函数范围进行分析，并保留指令字节、引用与伪代码。测试记录位于 `out/analysis/ida7-probe/runner-result.json`。此过程没有修改 IDA 配置或运行被分析 DLL。

登录相关静态导航证据保存在 `login-seeds.json` 和 `login-xref-candidates.json`。`scripts/find_login_xref_candidates.py` 扫描 `.text` 的 x64 RIP 相对 LEA 字节模式，将其关联到 PE 异常处理表中的范围；当前文件含 503,992 条互不重叠的范围记录。**原始字节命中仍需反汇编确认，PE 范围也不等于已确定的 C++ 方法或调用约定。**

原始文件的完整 IDA 导入持续处理元数据，约消耗 814 秒 CPU 时间仍未完成；在取得可用的定向数据库后已停止该自建分析进程并清理其未完成 sidecar，记录在 `ida7/import-status.json`。替代方法是 `scripts/prepare_ida7_view.py` 生成仅供静态分析的派生文件：只清零 PE 头文件偏移 `0x118` 起的 8 字节 Exception Directory 入口，保留 `.pdata` 实体及全部代码/数据节。逐块验证补丁外全部字节一致，12 个节的完整原始字节 SHA-256 一致，安装文件未变。派生哈希为 `b8cc1844a6ef2a092baa06976ffb11195f845e02877a6a0126576112b96fe5fb`，完整来源清单在 `ida7-focused/Weixin.analysis-pe.manifest.json`。**这个派生文件省略了 loader 可见的异常元数据，原签名失效，只用于静态分析，不能运行或注入。**

派生文件约 24 秒完成首次导入并保存，已复用 `ida7-focused/Weixin-focused.i64` 完成定向分析。`login-pass3.json` 中 7 个函数、`account-pass1.json` 中 5 个被调用函数以及 `context-pass1.json` / `context-pass2.json` 中 4 个上下文函数取得指令和伪代码；总计 **16 个函数、5,315 条指令字节**逐条与原始安装文件核对一致，7 个选定字符串引用也由 IDA 指令确认。汇总核对记录为 `verification-final.json`。`FastLoginManager` 候选的伪代码在 50,000 字符处截断；其余 15 个所选函数的伪代码未截断。全局自动分析仍未完成。早期 `login-pass1.json` / `login-pass2.json` 记录了脚本兼容性失败，应使用上述成功输出，不把早期作业保存成功理解为函数恢复成功。

| RVA | 已观察到的行为 | 结论边界 |
| --- | --- | --- |
| `0x881d00`、`0x881dd0` | 将传入名字与 `mmui::LoginState` / `mmui::NonLoginState`、`mmui::WeChatState` 比较，再返回对象或转发 | 与类名转换模式吻合，不是登录标志读取 |
| `0xdc08d0` | `mars::app::AppManager::GetAccountInfo` 经 `this+0x10` 的回调对象及虚表 `+0x18` 返回结果 | 网络库的委托入口，不能等同于旧 AccountService |
| `0x5456990` | `SettingGetUserAccountInfoFunctionCall` 参数对象类型检查及失败响应 | 参数校验，不是登录判断 |
| `0x5456d70` | 取得上下文，经虚表 `+0x20` 取得对象；检查该对象 `+0x10` 非零，再经服务链取得资料对象并组装回调响应 | `+0x10` 尚未定型；响应局部变量的 `1` 不是客户端登录状态 |
| `0x45d10` | 两条指令：读取全局 `base+0xb912690` 并返回 | 找到全局上下文访问点，尚未建立登录状态语义 |
| `0x47220` | 经该全局上下文的虚表 `+0x60` 返回两个指针 | 不能在未确认生命周期、线程约束时直接调用 |
| `0x36c740` | 复制对象 `+0x28/+0x30` 两指针并增加引用计数 | 呈现共享所有权语义，与旧对象布局不同 |
| `0x460a40`、`0x100a690` | 服务取得与按传入标识查询资料的调用链，包含引用计数、多个分支和缓存/回退候选路径 | 可继续导航；未恢复完整类型、异常路径或运行行为 |
| `0x500e0`、`0x42350` | 分配 `0x398` 字节对象、调用构造器，随后写全局 `0xb912690`；构造器最终写入虚表候选 `0x8d804e8` | 由原始字节 store 候选追踪，并已由 IDA 指令确认；未读取运行中的对象 |
| `0x4f3c0`、`0x469a0` | 上述虚表 `+0x20` 继续委托服务对象的虚表 `+0x18`；`+0x60` 方法复制上下文 `+0x68/+0x70` 的共享对象 | 找到静态服务访问链，仍不能把非空指针或账号字符串当作已登录 |

以上观察是直接 IDA 静态证据，不冒充 REA 原生 Evidence，也不证明业务 API 可调用。操作说明与作业格式见 [IDA 7 定向分析](ida7-analysis.md)。

## 已修复的问题

| 缺陷 | 改动 | 验证范围 |
| --- | --- | --- |
| 未找到 WeChatWin.dll 仍将零基址加旧偏移调用 | 增加只读兼容性检测和 DLL 入口拒绝；提供独立 probe | 合成版本资源、实际安装文件元数据、不兼容 fixture 的完整 DLL 加载拒绝 |
| DllMain 中启动服务/线程池，卸载时等待工作线程 | 初始化移到工作线程；成功模块固定到进程生命周期；不在 DllMain join；取消隐藏模块 | 隔离进程测试；停止 helper 需正常退出微信 |
| 后台日志刷新和线程池静态析构可能在加载锁中等待 | 同步日志刷新；上下文与线程池由进程持有，进程结束时交还 Windows | 生命周期策略明确，不宣称支持热卸载 |
| HTTP 先于 Manager/DB 准备好便可收请求 | 依赖先初始化，成功后发布服务；原子状态及统一 FAILED 状态 | 编译和隔离启动/拒绝测试 |
| HTTP 无限循环、未初始化线程句柄、启动失败假成功 | 原子停止标志、正确线程入口、同步监听检测、退出后清理 | 端口冲突、无效端口、线程失败、重启、析构和并发 start/stop |
| 无鉴权服务暴露到全部网卡 | 默认监听 `127.0.0.1` | 隔离真实 HTTP 请求 |
| 注入器将线程结束当成 DLL 加载成功 | 校验实际加载的完整模块路径；失败返回非零；清理资源 | 自产接受/拒绝 DLL、中文路径、仍被引用的卸载等 |
| `-P` 为 x86 shellcode 且截断 x64 指针 | 删除该执行路径，在触碰进程前拒绝参数 | `-P 0` 等负例 |
| WeChatString 构造函数只创建临时对象 | 真正委托构造、成员默认值、空指针处理，保持 ABI | x64 布局及毒化内存构造测试 |
| Python URL 无 scheme、旧数字路由/参数失效 | 对齐源码命名路由，缺失功能明确报错，入口只检查登录 | mock 全部示例，不访问微信 |
| 构建配置混用 x86 文档、缺子模块/包含目录、Unicode 参数错误 | x64/MSVC 检查、明确依赖、工具可独立构建、宽字符配置 API | 完整 Release 构建 |

仓库 `tool/` 中的历史二进制没有重新发布；不能用它们验证新源码。旧互斥体多开功能未测试或现代化，保留为既有代码；注入加载成功仍不保证后台初始化或业务 API 就绪。初始化失败或已固定 DLL 的卸载需要正常退出客户端恢复。

## 复现构建与验证

本机最终验证：MSVC x64 Release 完整构建成功；CTest **5/5** 通过（包含真实 helper DLL 在自产空客户端 fixture 下启动 HTTP、固定模块后正常进程退出）；Python **12/12** 通过（包含静态引用扫描和派生副本校验各 3 项新增回归测试）；HTTP 独立生命周期测试全部通过。实际安装的 4.1.15.13 只读 probe 返回预期退出码 **2**。这些测试没有验证微信 3.9.5.81 或 4.x 的真实业务函数。

Windows + MSVC x64 + CMake 3.21+。推荐先运行 probe，不要对当前 4.x 使用旧 DLL。

```powershell
git submodule update --init spdlog
cmake -S . -B out/build/tools -A x64 -DWXHELPER_BUILD_DLL=OFF
cmake --build out/build/tools --config Release
.\out\build\tools\Release\wxhelper_probe.exe 'C:\Program Files\Tencent\Weixin\4.1.15.13\Weixin.dll'
# 当前文件预期返回 2，显示 unsupported。
```

完整 DLL 可用现有 vcpkg 的 `nlohmann-json`、`detours`。本机验证使用两个固定源码版本，未修改全局 vcpkg：

```powershell
git clone --depth 1 --branch v3.11.3 https://github.com/nlohmann/json.git out/deps/json
git clone --depth 1 --branch v4.0.1 https://github.com/microsoft/Detours.git out/deps/detours
cmake -S . -B out/build/x64 -A x64 `
  -DWXHELPER_JSON_SOURCE_DIR="$PWD/out/deps/json" `
  -DWXHELPER_DETOURS_SOURCE_DIR="$PWD/out/deps/detours" `
  -DWXHELPER_INJECTOR_TESTS=ON
cmake --build out/build/x64 --config Release
ctest --test-dir out/build/x64 -C Release --output-on-failure
python -m unittest discover -s tests -p 'test_*.py' -v
powershell -NoProfile -ExecutionPolicy Bypass -File tests/run_http_lifecycle_test.ps1
```

依赖提交：nlohmann/json `9cca280a4d0ccf0c08f47a99aa71d1b0e52f8d03`，Detours `e4bfd6b03e50de46b47abfbd1e46b384f0c5f833`，spdlog 使用仓库 gitlink `ad0e89cbfb4d0c1ce4d097e134eb7be67baebb36`。产物：`out/build/x64/lib/Release/wxhelper.dll`、`out/build/x64/source/bin/Release/injector.exe`、`out/build/x64/Release/wxhelper_probe.exe`。

只读 PE 分析可重复运行：

```powershell
python scripts/inspect_weixin.py `
  --binary 'C:\Program Files\Tencent\Weixin\4.1.15.13\Weixin.dll' `
  --output out/analysis/weixin-4.1.15.13/pe-layout.json
```

## 4.x 迁移剩余工作

| 调查项 | 状态 |
| --- | --- |
| 当前安装文件的版本、架构与身份 | 已确认 |
| 源码支持版本及旧偏移不适配原因 | 已确认 |
| 本报告所列通用缺陷修复与隔离验证 | 已完成 |
| 新版静态分析 | PE 布局已完成，IDA 定向取得 16 个函数及可复用数据库；全局分析和类型恢复未完成 |
| 新版登录/联系人/消息/数据库后端及运行验证 | 未完成 |

版本身份、旧偏移失效原因和项目通用缺陷已确认。登录状态、账号对象、收消息回调、发消息调用约定、联系人容器与数据库布局仍需通过新版函数交叉引用及受控运行验证；目前没有可用的新后端。

应从一个只读功能（例如登录状态）开始，记录目标 SHA-256、函数边界/签名、字段布局与调用约定，再逐步验证联系人和接收消息。发送、群管理、数据库操作需分别验证；不能将字符串命中、可执行地址命中、导出名称或成功加载等同于业务兼容。

后续可直接复用 IDA 定向数据库，沿上下文虚表和账号对象来源继续分析。如果改用 REA/Ghidra，需要显式提高进程局部 `REA_GHIDRA_STARTUP_TIMEOUT_MS` 或配置合适的数据库/符号；增大时限本身不保证函数恢复成功。不要把分析引擎阶段完成、反编译器猜测的类型或非空账号资料等同于业务兼容或已登录状态。
