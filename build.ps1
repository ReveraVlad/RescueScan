# Builds RescueScan.exe from RescueScan.cs with the in-box .NET Framework 4.x C# compiler (legacy csc, C# 5).
#   .\build.ps1          build RescueScan.exe next to this script
#   .\build.ps1 -Test    build, then run the unit tests (tests\run-tests.ps1)
# -codepage:65001 : RescueScan.cs is UTF-8 without BOM (Russian UI strings); without it csc reads the ANSI code page.
# -platform:anycpu: runs as 64-bit on x64 Windows / x64 WinPE (a 64-bit WinPE cannot run 32-bit programs).
param([switch]$Test)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
if (-not (Test-Path $csc)) { Write-Error 'csc.exe not found - .NET Framework 4.x is required.'; exit 1 }
Push-Location $root
try {
    & $csc -nologo -codepage:65001 -target:winexe -platform:anycpu -win32manifest:app.manifest -out:RescueScan.exe `
        -reference:System.Windows.Forms.dll -reference:System.Drawing.dll -reference:System.Core.dll -reference:System.Management.dll `
        RescueScan.cs
    if ($LASTEXITCODE -ne 0) { Write-Host 'Build FAILED' -ForegroundColor Red; exit $LASTEXITCODE }
    Write-Host ('Built ' + (Join-Path $root 'RescueScan.exe')) -ForegroundColor Green
    if ($Test) {
        & (Join-Path $root 'tests\run-tests.ps1')
        if ($LASTEXITCODE -ne 0) { Write-Host 'Tests FAILED' -ForegroundColor Red; exit $LASTEXITCODE }
        Write-Host 'Tests passed' -ForegroundColor Green
    }
} finally { Pop-Location }
