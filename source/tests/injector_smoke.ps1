param(
    [Parameter(Mandatory = $true)][string] $Injector,
    [Parameter(Mandatory = $true)][string] $Target,
    [Parameter(Mandatory = $true)][string] $AcceptedDll,
    [Parameter(Mandatory = $true)][string] $RejectedDll
)

# VS ships a 32-bit CTest on some hosts. Its PowerShell cannot enumerate x64 modules.
if (-not [Environment]::Is64BitProcess) {
    & "$env:windir\Sysnative\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass `
        -File $PSCommandPath -Injector $Injector -Target $Target -AcceptedDll $AcceptedDll -RejectedDll $RejectedDll
    exit $LASTEXITCODE
}

$ErrorActionPreference = 'Stop'

function Assert-ExitCode([int] $Expected, [string[]] $CliArguments) {
    # Native stderr is expected for negative cases in Windows PowerShell 5.1.
    $ErrorActionPreference = 'Continue'
    $output = & $Injector @CliArguments 2>&1
    $actual = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    Write-Host (($output | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine)
    if ($actual -ne $Expected) {
        throw "Expected injector exit code $Expected, got $actual for $CliArguments"
    }
}

function Assert-Module([int] $TargetId, [string] $ModulePath, [bool] $Present) {
    $currentProcess = [System.Diagnostics.Process]::GetProcessById($TargetId)
    try {
        $currentProcess.Refresh()
        $modules = $currentProcess.Modules | ForEach-Object { $_.FileName }
        $actual = $modules -contains $ModulePath
        if ($actual -ne $Present) {
            Write-Host ('64-bit test driver: ' + [Environment]::Is64BitProcess + '; observed modules: ' + ($modules -join '; '))
            throw "Unexpected module presence ($actual): $ModulePath"
        }
    } finally { $currentProcess.Dispose() }
}

# Include non-ASCII characters without depending on this script's file encoding.
$unicodeDirectory = Join-Path (Split-Path $AcceptedDll) ('fixture_' + [char]0x6D4B + [char]0x8BD5)
New-Item -ItemType Directory -Path $unicodeDirectory -Force | Out-Null
$unicodeDll = Join-Path $unicodeDirectory 'injector_test_accept.dll'
Copy-Item -LiteralPath $AcceptedDll -Destination $unicodeDll -Force

$testHost = Start-Process -FilePath $Target -PassThru -WindowStyle Hidden
try {
    $targetIdText = $testHost.Id.ToString()
    Assert-ExitCode 2 @('-I', $targetIdText, '-p', $unicodeDll, '-P', '0')
    Assert-Module $testHost.Id $unicodeDll $false
    Assert-ExitCode 2 @('-I', '-1', '-p', $unicodeDll)
    Assert-ExitCode 2 @('-I', '4294967296', '-p', $unicodeDll)
    Assert-ExitCode 1 @('-I', $targetIdText, '-p', ($unicodeDll + '.missing'))
    Assert-ExitCode 1 @('-I', $targetIdText, '-p', $RejectedDll)
    Assert-Module $testHost.Id $RejectedDll $false
    Assert-ExitCode 0 @('-I', $targetIdText, '-p', $unicodeDll)
    Assert-Module $testHost.Id $unicodeDll $true
    Assert-ExitCode 0 @('-I', $targetIdText, '-p', $unicodeDll)
    Assert-ExitCode 1 @('-u', (Split-Path $Target -Leaf), '-d', (Split-Path $unicodeDll -Leaf))
    Assert-Module $testHost.Id $unicodeDll $true
    Assert-ExitCode 0 @('-u', (Split-Path $Target -Leaf), '-d', (Split-Path $unicodeDll -Leaf))
    Assert-Module $testHost.Id $unicodeDll $false
    Write-Host 'PASS: CLI rejection, loader rejection, Unicode loading, and verified fixture unload.'
} finally {
    if (-not $testHost.HasExited) { $testHost.Kill(); $testHost.WaitForExit() }
    $testHost.Dispose()
}
