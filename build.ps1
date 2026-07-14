# Build RescueScan.exe from source using the in-box .NET Framework C# compiler.
$csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path $csc)) { Write-Error "csc.exe not found - .NET Framework 4.x required."; exit 1 }
& $csc -nologo -target:winexe -win32manifest:app.manifest -out:RescueScan.exe `
    -reference:System.Windows.Forms.dll -reference:System.Drawing.dll -reference:System.Core.dll -reference:System.Management.dll `
    RescueScan.cs
if ($?) { Write-Host "Built RescueScan.exe" -ForegroundColor Green }
