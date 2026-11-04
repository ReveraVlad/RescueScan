# Builds RescueScan.cs + tests\RescueScan.Tests.cs with the in-box .NET Framework C# compiler (C# 5) and runs the tests.
# Registry tests write only to HKCU\Software\RescueScanTests\<guid> and remove it afterwards. No administrator rights
# needed; run elevated to include the real reg.exe save/load/unload test (a temporary hive file mounted at an unusual
# HKLM\RS_U9<random> name and unloaded again; it never touches the RS_* mounts of a RescueScan that is running).
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
if (-not (Test-Path $csc)) { Write-Error 'csc.exe (.NET Framework 4.x) not found'; exit 2 }
$out = Join-Path ([IO.Path]::GetTempPath()) ('RescueScan.Tests_' + [Guid]::NewGuid().ToString('N') + '.exe')
# -codepage:65001: the sources are UTF-8 without BOM; the legacy csc would otherwise read them as ANSI
& $csc -nologo -codepage:65001 -target:exe -main:RescueScan.Tests.TestMain "-out:$out" `
    -reference:System.Windows.Forms.dll -reference:System.Drawing.dll -reference:System.Core.dll -reference:System.Management.dll `
    (Join-Path $root 'RescueScan.cs') (Join-Path $here 'RescueScan.Tests.cs')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$rc = 1
try { & $out; $rc = $LASTEXITCODE } finally { Remove-Item $out -ErrorAction SilentlyContinue }
exit $rc
