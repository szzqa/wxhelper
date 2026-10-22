# 4.1.15.13 登录与联系人静态复核

本轮只读取原始 `Weixin.dll` 和既有 IDA JSON，没有注入、打开进程内存、执行微信函数或真实发送消息。原始 SHA-256 固定为 `10f8e995453e2da46d4f2b5080cd6da1f13cc5147746adc119ceae38cb039de5`。

## 编码日志的独立交叉校验

`scripts/review_weixin_login_logs.py` 复核了已有反编译输出引用的编码日志常量，输出为 `out/analysis/weixin-4.1.15.13/ida7-focused/login-contact-log-review.json`。脚本限定输入报告和二进制哈希，保存每条原始 bytes、来源函数、解码前缀及完整性标记。

常量格式是 `A1 + 4 个十六进制长度字符 + B1 + 十六进制负载 + C1 + 00`。长度按小端解释。以下是**已知明文推导与交叉验证**，尚未恢复或执行程序的解密实现：

1. 日志常量 `0x8D83D50` 对应 `kernel.cc`；同样的明文存在于原始 PE 的 `0x8D80598`。
2. `0x3BBD60` 同时引用编码文件名 `0x8E0A658` 和明文 `login_manager.cc`（`0x8E055A8`）。两个文件名锚点推导的 XOR 字节流前缀完全相同。
3. 函数名假设 `kernel::manager::LoginManager::Quit` 和构造函数名假设 `kernel::foundation::LoginContextPrivate::LoginContextPrivate` 分别将推导扩展到 35、60 字节，重叠部分完全一致。构造函数假设另有 `0x365BF0` 写入服务虚表的结构证据。
4. 该字节流同时还原了多条未用来生成字节流的独立日志，包括完整文件名、方法名、退出/自动认证及联系人缓存分支文本。脚本不会输出 60 字节之后的猜测内容。

因此，这些文本是有交叉支持的静态语义线索，不是导出符号，也不能单独证明运行时 ABI。

## 登录的新证据

| 已有反编译函数 RVA | 日志常量 RVA | 完整还原或有界前缀 | 含义与边界 |
|---|---|---|---|
| `0x3BBD60` | `0x8E0B038` | `kernel::manager::LoginManager::Quit` | 该消费者处于退出流程，不能用其调用服务 getter 证明已登录。 |
| `0x3BBD60` | `0x8E0B150` | `[Critical] critical login finish do logout.` | 区分关键登录流程完成和随后退出的动作。 |
| `0x3B9560` | `0x8E0A7B8` | `kernel::manager::LoginManager::WaitForLastLogoutIfNeeded` | 补充等待前一次退出的调用语义。 |
| `0x41B250` | `0x8E0C320` | `kernel::manager::LoginManager::OnSessionTimeOut` | getter `0x4FFF0` 为 true 时进入打印 `logout` 的分支。 |
| `0x4BC2F0` | `0x8E15F00` | `cancel autoauth. is start logout` | getter `0x4FFF0` 为 true 时取消自动认证，强烈支持服务 `+0x39` 属于“已开始登出”的条件。 |
| `0x4BC2F0` | `0x8E15EC8` | `is autoauth requesting` | 根对象 `+0x348` 的提前返回分支与自动认证请求中关联；它不是登录成功标志。 |
| `0x36B460` | `0x8DFF5C0` | `kernel::foundation::LoginContextPrivate::CoBeforeWillLogoutI…` | 60 字节前缀，后缀未恢复。`0x36B2A0` 的后续核对没有发现标志写入。 |

这里的 `+0x39` 指**服务对象**，`+0x348` 指**根上下文对象**。getter `0x4FFF0` 在服务不存在时也返回 true，因此它仍不能直接作为“已登出”或“已登录”的对外状态。服务 `+0x38` 在构造时置 1 的原有证据也仍不足以证明认证完成。

`login-semantic-pass5.json` 已完成四个精确 `.pdata` 范围的分析。真正的写入位于 `0x3BAD60`，调用顺序为：

- `0x3BADA8`：`CALL 0x47220`，取得之前已确认的服务 shared_ptr。
- `0x3BADAD`：取出双指针的对象地址，随后测试非空。
- `0x3BADB9`：`B1 01`，即 `MOV CL,1`。
- `0x3BADBB`：`86 48 39`，即 `XCHG CL,[RAX+0x39]`。
- 随后才创建/等待退出协程任务，故该字段表达**退出已经启动**，不保证退出完成。

此前只在 `0x360000..0x380000` 附近扫描普通 MOV 写入没有命中；实际写入位于另一个范围，并使用 XCHG。这个负结果不能被解释为字段只读。

构造清零、退出链置 1、getter 掩码和自动认证消费分支形成双向证据。离线 DTO 新增 `std::optional<bool> logout_started`；服务缺失/错误时无值，有效对象时复制字段最低位。`state` 继续保持 `Unknown`，既不把 false 解释为已登录，也不把 true 解释为已完全登出。

`0x36B2A0`、`0x36B620` 只补充退出前取消/清理工作，没有找到新的认证成功标志。`0x53160` 处理根对象另一组共享指针（`+0x338/+0x340`），不能与登录服务指针混淆。

同一脚本复核的联系人查询契约单独记录在 `weixin4-contact-query-contract.md`。

## 复现

```powershell
python -B scripts/review_weixin_login_logs.py `
  --binary 'C:\Program Files\Tencent\Weixin\4.1.15.13\Weixin.dll' `
  --directory out/analysis/weixin-4.1.15.13/ida7-focused `
  --output out/analysis/weixin-4.1.15.13/ida7-focused/login-contact-log-review.json
```

输出中的 `confidence` 明确标注 `known_plaintext_xor_inference_not_decoder_execution`。源报告来自本地 IDA 7 静态分析，并非 REA Evidence API 的分析成功记录。
