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

## 分析来源

REA 提供原始 PE 资源证据；IDA 7.0/Hex-Rays 的定向静态结果是独立证据，未伪装为 REA 返回结果。可复用脚本为 `scripts/prepare_ida7_view.py`、`scripts/ida7_analyze.py`、`scripts/run_ida7_job.ps1`。分析二进制、数据库与完整反编译结果保留在本地 `out/analysis/weixin-4.1.15.13/`，不上传仓库。

只有字段布局、调用约定、对象生命周期和受控运行行为都完成验证后，才可以另行实现在线适配并评估加入 DLL 兼容性白名单。当前用户要求不向正在运行的微信注入，本阶段不做在线验证。
