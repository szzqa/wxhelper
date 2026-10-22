# 后台启动、停止与接口测试

当前分支 DLL 只允许 `WeChatWin.dll 3.9.5.81 x64`。`Weixin.dll 4.1.15.13` 继续走静态分析和离线快照适配，尚不能通过这些在线接口收发消息。本轮验证只使用本项目自产夹具和本机测试服务器，没有向运行中的微信注入或发送消息。

## 已修复的运行问题

- HTTP 回调使用同一个请求状态；连接、发送、等响应共用总超时，支持停止时取消。截断响应不判成功。当前 Mongoose 配置不含 TLS，`https://` 回调明确拒绝。
- 消息和 SNS 监听统一事务安装、撤销；失败保留真实安装状态，可以重试。退出时停止捕获，原生调用仍转发；队列拒绝时释放上下文。
- 工作池拒绝新任务后排空已接受任务，再释放资源。TCP 完整发送并使用总超时。
- 参数在进入原生后端前检查；无效请求返回正确 HTTP 状态码，避免整数越界异常逃出事件循环。`/api/test` 返回 501，禁用旧的内存扫描入口。
- `sendTextMsg`、`sendImagesMsg`、`sendFileMsg` 的返回体明确 `status=submitted`、`nativeAcceptance=unverified`、`delivery=unverified`。旧 `code` 不能当成对方收到消息的凭证。

## 配置与启动

当前没有独立的在线后台 EXE。`wxhelper.dll` 在受支持宿主中加载后启动 HTTP 服务，默认 `http://127.0.0.1:19088`。`python/http_server.py` 是回调接收器，不是这个后台。

配置文件固定为 `%LOCALAPPDATA%\wxhelper\config.ini`：

```ini
[config]
Port=19088
```

日志为 `%LOCALAPPDATA%\wxhelper\logs\wxhelper-<PID>.log`，单文件 5 MiB，保留 3 个轮转文件。也可以在启动宿主前设置进程环境变量 `WXHELPER_DATA_DIR` 为绝对路径；宿主需要继承该环境变量。目录与启动时的工作目录无关，不在微信安装目录写配置或日志。

当前可直接执行的无注入测试：

```powershell
# 以下使用已构建产物，不访问微信进程。
ctest --test-dir out/build/x64 -C Release --output-on-failure
python scripts/make_weixin4_fixture.py --output out/synthetic-weixin4.json
.\out\build\x64\Release\weixin4_snapshot_cli.exe out/synthetic-weixin4.json
```

离线 CLI 的输入格式和具体参数以 [快照说明](weixin4-snapshots.md) 为准。它没有发送能力，输入是人工构造的记录。

最新的 [原生契约验证记录](native-contract-validation-2026-10-22.md) 包含按 host 认证、联系人任务输入、接收成功子集和发送完成结果的合成测试。上述命令会同时测试这 9 个离线 feature；它们没有接到以下旧版 HTTP 路由。

## 后续注入计划（尚未执行）

1. 用 `wxhelper_probe.exe <客户端DLL完整路径>` 检查版本与架构。4.1.15.13 当前会报告不支持；此时停止，不绕过检查。
2. 4.x 适配需要分别验证登录状态含义、联系人查询上下文/容器及线程要求、消息对象构造/所有权/异步完成协议，再开放对应能力。每一步先静态证据和离线测试，实际注入与消息发送另等用户明确授权。
3. 未来获准后，只选择明确 PID，使用重新构建的 x64 DLL 和注入器。历史 `tool/` 二进制不代表当前源码；不用 `-P` 或隐藏模块的 `-m`。
4. 受支持版本的手动形式是 `injector.exe -I <PID> -p <DLL绝对路径>`。该命令加载 DLL 后后台自动启动；先查 health/capabilities，再查登录/联系人，最后才对自己控制的测试会话做一次发送验证。

## 对应接口

以下在线接口仅属于旧版后端。除标注外均为 POST，JSON 请求体，`Content-Type: application/json`。

| 接口 | 请求 | 含义 |
|---|---|---|
| `/api/health` | GET 或 POST `{}` | 状态、初始化/停止错误、配置路径、日志路径、DLL 驻留情况 |
| `/api/capabilities` | GET 或 POST `{}` | 当前可用功能；`weixin4Runtime=false`，无送达确认 |
| `/api/checkLogin` | `{}` | 旧版原生登录状态查询 |
| `/api/userInfo` | `{}` | 旧版当前账号信息 |
| `/api/getContactList` | `{}` | 旧版联系人列表 |
| `/api/getContactProfile` | `{"wxid":"测试联系人ID"}` | 旧版联系人资料 |
| `/api/sendTextMsg` | `{"wxid":"测试会话ID","msg":"测试文本"}` | 提交文本发送；提交不等于送达 |
| `/api/sendImagesMsg` | `{"wxid":"测试会话ID","imagePath":"C:\\test\\image.png"}` | 提交图片发送 |
| `/api/sendFileMsg` | `{"wxid":"测试会话ID","filePath":"C:\\test\\file.txt"}` | 提交文件发送 |
| `/api/hookSyncMsg` | `{"ip":"127.0.0.1","port":19099,"enableHttp":1,"url":"http://127.0.0.1:19099/","timeout":5000}` | 消息与 SNS 回调；timeout 单位毫秒 |
| `/api/unhookSyncMsg` | `{}` | 同时撤销消息和 SNS 监听 |
| `/api/hookLog` / `/api/unhookLog` | `{}` | 开启/关闭旧版日志监听 |
| `/api/stop` | `{}` | 接受停止请求返回 202；随后关闭所有监听、排空回调、关闭 HTTP |

健康检查示例（只应连接自己已授权启动的后台）：

```powershell
Invoke-RestMethod 'http://127.0.0.1:19088/api/health'
Invoke-RestMethod 'http://127.0.0.1:19088/api/capabilities'
```

错误状态：400 参数或 JSON 错误，404 未知接口，405 方法错误，500 内部异常，501 禁用诊断功能，503 后端尚未就绪或正在停止。停止初始化中的服务返回 409，应待初始化结束后重试。初始化失败若发生在 HTTP 监听建立之后，可以通过 health 获取原因；配置、日志或端口绑定失败可能没有 HTTP 服务，此时查日志及调试输出。

## 如何停止及移除

只停消息监听：POST `/api/unhookSyncMsg`。停止全部服务：POST `/api/stop`。202 表示已经接受，停止成功后端口关闭；若拆钩失败，服务保留用于查询 health 的 `stop_failed` 和再次调用 stop。停止是单向的，恢复需重启宿主并重新加载 helper。

DLL 已通过 Windows PIN 固定到进程生命周期。停止服务、取消监听、调用 `FreeLibrary` 或注入器 `-u` 都不等于移除 DLL。**完整移除须正常退出整个微信进程，再启动微信**。helper 不修改客户端磁盘文件，也不建立开机启动项；以后不再加载 helper 即不会再次注入。保留日志便于排查，确认无需后可自行删除独立的 wxhelper 数据目录。

`/api/stop` 的回归测试只在自产夹具宿主内验证响应完整送出、端口关闭和 DLL 仍驻留，不能据此宣称已验证真实微信中的热拆钩。
