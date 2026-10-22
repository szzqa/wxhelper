# 微信 4.1.15.13 离线适配

`weixin4_snapshot` 是实验性静态库，解析调用者提供的稳定地址空间。它不打开进程、不安装钩子、不调用微信函数，也没有加入现有 `wxhelper.dll` 的版本白名单。现有 HTTP 后端仍仅支持 3.9.5.81。

目标原文件：`Weixin.dll`，版本 `4.1.15.13`，AMD64，SHA-256：

```
10f8e995453e2da46d4f2b5080cd6da1f13cc5147746adc119ceae38cb039de5
```

每个业务读取入口都要求 `BinaryIdentity`。这是快照调用方提供的来源标记；相同标记不证明快照内容真实或对象仍存活。用于 IDA 的派生 PE 副本哈希不能通过此配置。所有结果只描述快照时刻，不能用于推断正在运行的客户端状态。

## 内存和容器

`MemoryReader::Read` 必须从不可变快照复制完整范围；不可读返回 `false`。调用方不可在读取期间更改快照。基础读取实现检查地址加法溢出、字符串长短存储、长度/容量关系、终止符、向量起止位置和输出预算。返回字符串与列表拥有自己的内存。

观察到的窄字符串为 32 字节 MSVC 布局，短字符串容量为 15；这不等于旧版 `WeChatString` 的宽字符调用 ABI。向量以第二个指针作为有效元素终点，第三个指针只表示容量。默认单字符串上限 1 MiB、元素上限 10,000、一个字符串列表的累计内容上限 8 MiB；后端可进一步收紧预算。

## 构建与验证

无需加载微信，也无需 JSON/Detours 依赖即可构建基础库和测试：

```powershell
cmake -S . -B out/build/snapshots -A x64 -DWXHELPER_BUILD_DLL=OFF
cmake --build out/build/snapshots --config Release
ctest --test-dir out/build/snapshots -C Release --output-on-failure
```

合成快照测试涵盖短/长字符串、内嵌 NUL、无效指针、边界溢出、损坏长度、容量中未初始化对象、累计预算和版本/架构/哈希不匹配。通过这些测试只证明解析器按契约工作，不证明微信运行时业务兼容。

## 已实现的模块

| 模块 | 可读取内容 | 仍未完成 |
| --- | --- | --- |
| [登录](weixin4-main-account-contract.md) | 本地 `kernel_is_login`、内核阶段、退出启动、账号查询键；指定 host 的认证状态与存在性 | 全局 `state` 保持 `unknown`；本地谓词与 host 成功记录均不保证当前主账号在线 |
| [联系人](weixin4-contact-enumeration.md) | 底层查询结果及按类型查询列表中的 13 个文本字段、8 个数值字段；[存储任务](weixin4-contact-native-contract.md)的用户名输入 | 不发起查询；列表结果存在不证明各表查询成功或完整账号集合；缓存与服务层有不同筛选 |
| [消息](weixin4-messages.md) | 发送任务的会话 ID、调用结果；接收记录的原始正文、from/to/sender、类型、排序号、时间原值及状态字段 | 类型/状态枚举、时间单位和收发方向未验证；无在线收发 |

## 离线命令行

命令行需要 nlohmann/json（本次验证使用 v3.11.3），不需要 Detours 或注入。已有源码依赖可这样构建：

```powershell
cmake -S . -B out/build/snapshot-cli -A x64 `
  -DWXHELPER_BUILD_DLL=OFF -DWXHELPER_BUILD_SNAPSHOT_CLI=ON `
  -DWXHELPER_JSON_SOURCE_DIR="$PWD/out/deps/json"
cmake --build out/build/snapshot-cli --config Release
python scripts/make_weixin4_fixture.py --output out/synthetic-weixin4.json
.\out\build\snapshot-cli\Release\weixin4_snapshot_cli.exe out/synthetic-weixin4.json
ctest --test-dir out/build/snapshot-cli -C Release --output-on-failure
```

示例生成器完全构造合成数据，不读取微信或账号。示例结果应包含 `fixture_user`、`测试昵称` 和十进制字符串服务器 ID `18364758544493064720`；这些都是测试值。登录状态仍为 `unknown`，发送调用成功不代表消息送达。

输入 JSON 格式为 `weixin4_snapshot_v1`，包含 `identity`、`segments` 和 `requests`。`identity` 为版本、原始 SHA-256 和 machine；每个 segment 包含起始 `address` 与完整字节的 `hex`。每个 request 包含 `feature` 与 `address`。地址可用 `0x` 十六进制字符串或非负 JSON 整数。

| feature | address 含义 |
| --- | --- |
| `login` | 快照中的模块基址 |
| `auth_host` | 快照中的模块基址；请求另含精确匹配的 `host` 字符串 |
| `contacts` | 已完成联系人查询结果的起点 |
| `contact_task` | 已存在存储任务闭包的起点，仅读取其用户名输入 |
| `contact_type_query` | 按 local_type 查询的完成输出，optional 链表头；`result_present` 区分无结果与有效空列表，不保证完整通讯录 |
| `send_task` | 已存在发送任务 closure 的起点 |
| `text_draft` | 文本消息工厂产物的 `{object, control}` pair 地址，另需 `module_base`；正文参数字节同时提供 `text_argument_hex`，不执行构造或发送 |
| `send_result` | 已存在任务结果的起点 |
| `send_completion` | 已提取的 56 字节调用方结果；状态、原始字符串和不跟随的 payload 引用；参见[发送契约](weixin4-send-native-contract.md) |
| `send_cancel_context` | SendContext 对象地址，另需 `module_base`；只观察阶段与两个作业的取消请求标记，不执行取消或承诺完成；参见[取消契约](weixin4-send-cancel-contract.md) |
| `receive_batch` | 0x2e8 字节消息记录 vector 头的起点 |
| `receive_storage` | 已提取的批量存储结果 payload；vector +0、标志 +0x18；参见[接收契约](weixin4-receive-native-contract.md) |
| `notification_dispatch` | 已排队通知闭包地址，另需 `module_base`；复制消息记录与不透明回调观察值，不执行回调；来源分类未知，解除订阅不保证队列排空；参见[通知契约](weixin4-notification-contract.md) |

片段不可重叠；每次对象读取范围必须落在单一片段内。JSON 文件最多 80 MiB，解码字节最多 32 MiB、片段最多 10,000、请求最多 32、嵌套最多 64 层。CLI 使用固定的默认对象读取预算。服务器 ID 以十进制字符串输出，避免 JavaScript 对大整数丢失精度；非法 UTF-8 字节在 JSON 展示中替换，库本身仍保留原始字节。

退出码：`0` 所有请求解析成功，`2` 某个请求读取/布局/profile 不匹配，`1` 输入或格式错误。成功仅代表解析成功；`runtime_supported`、`snapshot_provenance_verified` 始终为 `false`。错误请求不附带半成品数据。

语义复核后，实验性消息字段 `unknown_message_string_b0` 更名为 `chat_id`，`unknown_u32_0c` 更名为 `message_type`，`unknown_string_18/38` 更名为 `from_username/to_username`。新增 `sender`、`content`、`sort_sequence`、`time_raw` 及原始状态字段。`content_decoded=true` 只表示已复制原生字符串；正文可能包含 XML 等结构，不承诺是纯文本。服务器 ID 和排序号均输出十进制字符串。`logout_started` 是可空布尔值，不能转换成在线/离线判断。

## 分析来源

REA 提供原始 PE 资源证据；IDA 7.0/Hex-Rays 的定向静态结果是独立证据，未伪装为 REA 返回结果。可复用脚本为 `scripts/prepare_ida7_view.py`、`scripts/ida7_analyze.py`、`scripts/run_ida7_job.ps1`。分析二进制、数据库与完整反编译结果保留在本地 `out/analysis/weixin-4.1.15.13/`，不上传仓库。

只有字段布局、调用约定、对象生命周期和受控运行行为都完成验证后，才可以另行实现在线适配并评估加入 DLL 兼容性白名单。当前用户要求不向正在运行的微信注入，本阶段不做在线验证。
