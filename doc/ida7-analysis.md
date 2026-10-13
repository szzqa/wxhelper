# IDA 7 定向静态分析

本机用户提供的 IDA 7 使用 Python 2.7，不能运行当前版本的 `ida-pro-mcp`。`scripts/ida7_analyze.py` 是直接 IDAPython 批处理入口，其输出不是 REA Evidence；REA 资源分析证据单独保存。

## 作业文件

JSON 必须使用绝对路径。导入作业的 `functions` 可以为空；后续对同一个数据库提供少量已知范围，避免等待全局自动分析。

```json
{
  "expected_sha256": "对应输入文件的完整 SHA-256",
  "output": "C:/analysis/result.json",
  "max_pseudocode_chars": 50000,
  "functions": [
    {
      "start_rva": "0x1000",
      "end_rva": "0x1020",
      "seed": "说明本次选择这个范围的证据"
    }
  ]
}
```

示例地址仅说明格式。目标地址应来自匹配哈希的二进制证据，结束地址不包含在范围中。每个作业最多 30 个函数，每个声明范围不超过 256 KiB。IDA 实际建立的函数边界会另行记录，可能与 PE 异常处理范围不同。

使用派生分析副本时，`expected_sha256` 填派生文件哈希，并增加 `provenance_manifest` 字段指向副本的来源清单绝对路径。脚本会同时校验清单对应的原始文件哈希。

## 启动方式

在单独的 PowerShell 进程中设置环境，避免把老版本 Python 加入全局 PATH。`-a` 关闭全局自动分析；脚本仅等待指定范围的分析。不要用调试器选项启动被分析程序。

```powershell
$idaDir = 'D:\IDA'
$analysisDir = (Resolve-Path 'out/analysis/weixin-4.1.15.13/ida7-focused').Path
$runner = (Resolve-Path 'scripts/ida7_analyze.py').Path
$env:PYTHONHOME = "$idaDir\python27"
$env:PYTHONPATH = "$idaDir\python"
$env:PATH = "$idaDir;$idaDir\python27;" + $env:PATH
$env:WXHELPER_IDA_JOB = "$analysisDir\login-pass3-job.json"

# 已有数据库：不传 -o，且同一个数据库只能由一个 IDA 进程打开。
$idaProcess = Start-Process -FilePath "$idaDir\idat64.exe" `
  -ArgumentList @('-A', '-a', "-L`"$analysisDir\login-rerun.log`"", `
    "-S`"$runner`"", "`"$analysisDir\Weixin-focused.i64`"") `
  -WorkingDirectory $analysisDir -WindowStyle Hidden -PassThru
$idaProcess.Id
```

首次导入使用空函数作业，将最后的数据库参数换为输入 DLL 路径，并增加 `-o"完整输出数据库路径"`。首次导入可能很慢；`-a` 不会跳过 PE loader 对异常处理等元数据的处理。输出中的 `stage=complete`、`database_saved=true` 和正常进程退出才表明作业及保存完成。只有临时 `.id0/.id1` 文件时不能宣称已有完整 `.i64`。

本次为绕过全量异常表导入耗时，使用 Python 3.11+ 的 `scripts/prepare_ida7_view.py --source <原始PE> --target <新的.analysis-pe路径>` 创建分析副本。脚本拒绝覆盖现有文件，仅清零 PE 头 Exception Directory 入口，核实补丁外所有字节和全部节字节一致，并生成 `.manifest.json`。函数范围继续从原始 PE 获取。副本不具备原始签名完整性，不得执行或注入；使用副本的反编译结果也不包含完整异常元数据分析。

最新 runner 对单个函数错误返回 `complete_with_errors` 和非零退出码，并输出 `function_error_count`、`pseudocode_truncated_count`。截断的伪代码不是完整函数结果。输入错误、哈希不符或数据库保存失败也返回非零退出码。

## 证据边界

登录、联系人和消息后续 54 个定向函数结果的作业范围已保存为 [weixin4-analysis-jobs.json](weixin4-analysis-jobs.json)，原始文件逐条指令比对摘要见 [weixin4-instruction-verification.json](weixin4-instruction-verification.json)。共比对 31,754 条指令；这不包含前期 16 个函数的计数，也不等于运行时验证。

对已存在的分析副本数据库，可选择一个作业重新分析。下例复用本地路径，脚本不会执行输入 DLL：

```powershell
$analysisDir = (Resolve-Path 'out/analysis/weixin-4.1.15.13/ida7-focused').Path
$catalog = Get-Content doc/weixin4-analysis-jobs.json -Raw | ConvertFrom-Json
$job = @{
  expected_sha256 = $catalog.analysis_sha256
  provenance_manifest = "$analysisDir/Weixin.analysis-pe.manifest.json"
  output = "$analysisDir/contact-fields-rerun.json"
  max_pseudocode_chars = $catalog.max_pseudocode_chars
  functions = $catalog.jobs.'contact-migration-pass3'.functions
}
$job | ConvertTo-Json -Depth 10 | Set-Content "$analysisDir/contact-fields-rerun-job.json" -Encoding utf8
.\scripts\run_ida7_job.ps1 -JobFile "$analysisDir/contact-fields-rerun-job.json" `
  -Database "$analysisDir/Weixin-focused.i64" -IdaDirectory 'D:\IDA'
python scripts/verify_ida_evidence.py `
  --binary 'C:\Program Files\Tencent\Weixin\4.1.15.13\Weixin.dll' `
  --results "$analysisDir/contact-fields-rerun.json" `
  --output "$analysisDir/contact-fields-verification.json"
```

作业必须串行打开同一个数据库。`verify_ida_evidence.py` 拒绝哈希不匹配、未完成/非静态结果和与原件不符的指令字节；它不验证字段命名或反编译器推断的类型。摘要中的结果文件 SHA-256 用于核对本地保留的原始结果，重新运行时元数据和文件哈希可能变化。

输出包括输入哈希、IDA/反编译器版本、实际函数边界、指令字节、数据引用、调用和伪代码。`auto_analysis_complete=false` 表示仍有未执行的自动分析任务。未恢复的函数类型、间接调用目标、异常处理和 C++ 数据布局仍需继续核实；反编译器推导的参数数量不能直接作为注入调用原型。

候选地址必须先比对指令及引用，再追踪数据来源。源码中的旧 `AccountService + 0x7F8` 不能因为新版出现相似字符串就继续使用。只有完整验证新版本的调用约定、对象生命周期及运行行为后，才能把新配置加入兼容性白名单。
