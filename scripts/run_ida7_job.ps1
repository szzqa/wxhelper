param(
  [Parameter(Mandatory=$true)][string]$JobFile,
  [string]$Database = 'out/analysis/weixin-4.1.15.13/ida7-focused/Weixin-focused.i64',
  [string]$IdaDirectory = 'D:\IDA',
  [ValidateRange(10,1800)][int]$TimeoutSeconds = 180
)
$ErrorActionPreference = 'Stop'
$jobPath = (Resolve-Path -LiteralPath $JobFile).Path
$databasePath = (Resolve-Path -LiteralPath $Database).Path
$runnerPath = Join-Path $PSScriptRoot 'ida7_analyze.py'
$idaPath = Join-Path $IdaDirectory 'idat64.exe'
if (-not (Test-Path -LiteralPath $idaPath)) { throw "Missing IDA: $idaPath" }
$workDirectory = Split-Path -Parent $databasePath
$logPath = [IO.Path]::ChangeExtension($jobPath, '.log')
$recordPath = [IO.Path]::ChangeExtension($jobPath, '.process.json')
$savedEnvironment = @{}
foreach ($name in @('PYTHONHOME','PYTHONPATH','PATH','WXHELPER_IDA_JOB')) {
  $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
try {
  $env:PYTHONHOME = Join-Path $IdaDirectory 'python27'
  $env:PYTHONPATH = Join-Path $IdaDirectory 'python'
  $env:PATH = "$IdaDirectory;$env:PYTHONHOME;" + $env:PATH
  $env:WXHELPER_IDA_JOB = $jobPath
  $idaProcess = Start-Process -FilePath $idaPath -ArgumentList @(
    '-A', '-a', "-L`"$logPath`"", "-S`"$runnerPath`"", "`"$databasePath`"") `
    -WorkingDirectory $workDirectory -WindowStyle Hidden -PassThru
  $record = @{pid=$idaProcess.Id; executable=$idaPath;
    start_utc=$idaProcess.StartTime.ToUniversalTime().ToString('o'); job=$jobPath;
    database=$databasePath; target_executed=$false}
  $record | ConvertTo-Json | Set-Content -LiteralPath $recordPath -Encoding UTF8
  if (-not $idaProcess.WaitForExit($TimeoutSeconds * 1000)) {
    # This handle is the analysis process created above, never the client.
    $idaProcess.Kill()
    $idaProcess.WaitForExit()
    $record.status = 'analysis_timeout'
    throw 'Owned IDA analysis timed out; inspect the saved database and partial result before reuse.'
  }
  $record.exit_code = $idaProcess.ExitCode
  $record.status = if ($idaProcess.ExitCode -eq 0) { 'finished' } else { 'failed' }
  Write-Output ($record | ConvertTo-Json -Compress)
  if ($idaProcess.ExitCode -ne 0) { throw "IDA job failed: $jobPath" }
} finally {
  if ($record) { $record | ConvertTo-Json | Set-Content -LiteralPath $recordPath -Encoding UTF8 }
  foreach ($name in $savedEnvironment.Keys) {
    [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
  }
}
