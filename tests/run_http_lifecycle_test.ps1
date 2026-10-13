param(
    [string]$OutputDirectory,
    [string]$VcVars64Path
)

# Standalone Windows regression check. It opens only its own loopback sockets;
# it does not load wxhelper.dll, WeChat, or any private WeChat functions.
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $repoRoot 'out/http_lifecycle_test'
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

if (-not $VcVars64Path) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) {
        throw 'MSVC discovery failed; pass -VcVars64Path with the path to vcvars64.bat.'
    }
    $visualStudio = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $visualStudio) {
        throw 'No Visual Studio C++ toolchain found; pass -VcVars64Path.'
    }
    $VcVars64Path = Join-Path $visualStudio 'VC/Auxiliary/Build/vcvars64.bat'
}
if (-not (Test-Path -LiteralPath $VcVars64Path)) {
    throw "Missing vcvars64.bat: $VcVars64Path"
}

# Remove only the unrelated project PCH dependency. The test supplies logging
# and a minimal HTTP handler while compiling the actual lifecycle implementation.
$serverSource = Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'src/http_server.cc')
if (-not $serverSource.Contains('#include "pch.h"')) {
    throw 'Expected PCH include not found; update the lifecycle test adapter.'
}
$serverSource = $serverSource.Replace('#include "pch.h"', '')
$callbackSource = Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'src/http_server_callback.cc')
$threadStart = $callbackSource.IndexOf('DWORD WINAPI StartHttpServer(')
if ($threadStart -lt 0) {
    throw 'Thread entry not found; update the lifecycle test adapter.'
}
$threadEnd = $callbackSource.IndexOf('void EventHandler(', $threadStart)
if ($threadEnd -le $threadStart) {
    throw 'Thread entry boundary not found; update the lifecycle test adapter.'
}
$threadSource = $callbackSource.Substring($threadStart, $threadEnd - $threadStart)
Set-Content -LiteralPath (Join-Path $OutputDirectory 'http_server_under_test.cc') -Value $serverSource -Encoding UTF8
Set-Content -LiteralPath (Join-Path $OutputDirectory 'http_worker_under_test.inc') -Value $threadSource -Encoding UTF8

$sourceDirectory = Join-Path $repoRoot 'src'
$mongooseSource = Join-Path $sourceDirectory 'mongoose.c'
$testSource = Join-Path $PSScriptRoot 'http_lifecycle_test.cc'
$mongooseObject = Join-Path $OutputDirectory 'mongoose.obj'
$testObject = Join-Path $OutputDirectory 'http_lifecycle_test.obj'
$testExecutable = Join-Path $OutputDirectory 'http_lifecycle_test.exe'
$buildScript = Join-Path $OutputDirectory 'build-lifecycle-test.cmd'
$buildCommands = @"
@echo off
call "$VcVars64Path" >nul
if errorlevel 1 exit /b 1
cl /nologo /W3 /c /TC /I "$sourceDirectory" /Fo"$mongooseObject" "$mongooseSource"
if errorlevel 1 exit /b 1
cl /nologo /W4 /EHsc /std:c++17 /I "$sourceDirectory" /I "$OutputDirectory" /Fo"$testObject" /Fe"$testExecutable" "$testSource" "$mongooseObject"
if errorlevel 1 exit /b 1
"$testExecutable"
"@
Set-Content -LiteralPath $buildScript -Value $buildCommands -Encoding ASCII
& $buildScript
if ($LASTEXITCODE -ne 0) {
    throw "HTTP lifecycle regression failed with exit code $LASTEXITCODE."
}
