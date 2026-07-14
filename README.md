# RescueScan

A small **defensive anti‑malware / rescue tool** for Windows. It finds and removes
malware **autostart (persistence) points** on an *offline* Windows install from the
Windows Recovery Environment (WinRE/WinPE), and also helps on a live but locked‑down
system. Written in C# / WinForms (.NET Framework 4.x), it drives `reg.exe` so it works
identically inside WinPE.

> Built as a personal learning project while analyzing amateur, batch‑based malware
> from "virus review" videos. **Use it only on machines you own or are authorized to
> service.** It is a cleanup tool, not an attack tool.

## Features

**Tab 1 — Autoruns scanner (offline)**
Mounts the offline registry hives (`SOFTWARE`, `SYSTEM`, every `NTUSER.DAT`) and lists
every place malware commonly starts from, flagging suspicious entries in red:

- Run / RunOnce (HKLM, HKCU, WOW64), Policies\Explorer\Run, RunServices
- Winlogon Shell / Userinit / Taskman / Notify / GinaDLL / VmApplet / AppSetup
- AppInit_DLLs (+WOW64), ShellServiceObjectDelayLoad, Browser Helper Objects
- cmd AutoRun, IFEO Debugger hijacks
- BootExecute / Session Manager (SetupExecute, S0InitialCommand, AppCertDlls)
- Services + drivers `ImagePath`, svchost `ServiceDll`, LSA packages, Print Monitors
- Active Setup StubPath, SilentProcessExit (watchdog/"checker")
- Class hijacks (exefile/bat/cmd), Startup folders + redirects
- Scheduled Tasks (with watchdog/self‑heal detection)
- Non‑`.sys` files hiding in `System32\drivers`

Select suspicious → delete → export a CSV report.

**Tab 2 — Task manager**
Process list with full paths and risk highlighting; terminate a process or its whole
**process tree** (so a parent can't respawn the malware).

**Tab 3 — Explorer**
Shows **hidden and system‑hidden** files by default (malware hides with `+h +s`),
highlights suspicious / scan‑flagged files in red, and can clear the hidden/system
attributes or delete files. Files are never launched on double‑click.

**Pre‑boot (ESP/BCD)**
Enumerates the BCD store and the EFI System Partition to catch disk‑based bootkits
(the "virus before BIOS" trick) — flags bootloaders with non‑standard paths and any
foreign files under `\EFI`.

**Watchdog (opt‑in)**
A user‑mode self‑heal: a helper process restarts the tool if malware kills it, and
logs the event. Optional "always on top" so a malware UI can't hide the tool.

## Build

Requires the .NET Framework C# compiler (ships with Windows). From PowerShell:

```powershell
& "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe" `
  -nologo -target:winexe -win32manifest:app.manifest -out:RescueScan.exe `
  -reference:System.Windows.Forms.dll -reference:System.Drawing.dll -reference:System.Core.dll `
  RescueScan.cs
```

Or run `build.ps1`.

## Usage

- **Offline (recommended):** boot into WinRE/WinPE, open a command prompt, run
  `RescueScan.exe`. Click **Найти ОС** → **Сканировать**. The target Windows is not
  running, so the malware can't fight back.
- **Live:** run as Administrator on the infected system to triage processes/files.

## Scope / limitations

RescueScan cleans the **OS level plus the disk bootloader/ESP**. It does **not** touch
a real firmware (SPI flash) implant — that requires reflashing the BIOS. It relies on
`reg.exe` and standard Windows APIs; no kernel driver is included.

## Disclaimer

Provided as‑is, for educational and defensive use on your own or explicitly authorized
systems. You are responsible for how you use it. Deleting autostart entries can affect
system behavior — review findings before removing them.

## License

MIT — see [LICENSE](LICENSE).
