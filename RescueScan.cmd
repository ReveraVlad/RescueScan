@echo off
rem RescueScan launcher: checks that .NET Framework 4.x is present, then starts RescueScan.exe from this folder.
rem Without .NET (for example stock WinRE: it has no WinPE-NetFx) the exe fails in the Windows loader with
rem 0xc0000135 / "mscoree.dll was not found" and cannot explain anything itself.
setlocal
if not exist "%~dp0RescueScan.exe" (echo RescueScan.exe not found next to %~nx0. & goto fail)
if not exist "%SystemRoot%\System32\mscoree.dll" goto nonet
if exist "%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\clr.dll" goto run
if exist "%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\clr.dll" goto run
:nonet
echo .NET Framework 4.x is not installed in this system (%SystemRoot%).
echo  - Stock WinRE (Advanced startup - Command Prompt) has no .NET: RescueScan cannot run there.
echo  - Use a WinPE built with the ADK plus WinPE-WMI and WinPE-NetFx (x64), or a PE that contains .NET 4.
echo  - On Windows 7 install .NET Framework 4.x first.
echo (RU) Net .NET Framework 4.x: v stokovom WinRE RescueScan ne zapustitsya - nuzhen WinPE s WinPE-NetFx.
goto fail
:run
start "" "%~dp0RescueScan.exe" %*
exit /b 0
:fail
pause
exit /b 1
