# RescueScan

A small **defensive anti‑malware / rescue tool** for Windows. It finds and removes
malware **autostart (persistence) points** on an *offline* Windows installation from a
WinPE rescue environment, and it also helps on a live but locked‑down system (task
manager, explorer that shows hidden files, repair of hijacked shell/associations/policies,
local accounts). One C# 5 / WinForms source file, .NET Framework 4.x, no installer, no
driver, no network access.

> Built as a personal learning project while analysing amateur, batch‑based malware
> from "virus review" videos. **Use it only on machines you own or are authorised to
> service.** It is a cleanup tool, not an attack tool. The UI is in Russian.

## Requirements

| Where | What is needed |
|---|---|
| Live Windows (7 SP1 – 11) | .NET Framework 4.x (in‑box since Windows 8; on Windows 7 install it first — Win7 ships only .NET 3.5). Run as administrator (the manifest requests it). |
| Offline (rescue) | A **custom WinPE** that contains .NET: Windows ADK + WinPE add‑on, `copype amd64 …`, then `Dism /Add-Package` **WinPE-WMI**, then **WinPE-NetFx** (each with its language cab, e.g. `en-us`), optionally WinPE-Scripting. Use an x64 PE (the build is AnyCPU; a 64‑bit PE cannot run 32‑bit code). |

**Stock WinRE cannot run RescueScan.** *Advanced startup → Troubleshoot → Command Prompt*
boots `winre.wim`, which has WinPE‑WMI but no WinPE‑NetFx; a .NET program fails in the
Windows loader (`0xc0000135` / "mscoree.dll was not found") before it can show anything.
Microsoft also tells WinRE customisers not to depend on NetFx (it is dropped when WinRE is
serviced). Windows 7's WinRE (WinPE 3.x) has no .NET option at all. Third‑party PEs work
only if they include .NET 4 (check for `%SystemRoot%\System32\mscoree.dll`).

`RescueScan.cmd` (next to the exe) checks for .NET 4 and prints a readable message
instead of the loader error, then starts `RescueScan.exe`.

## Modes: offline and live

At start a picker lists the Windows installations found on all drives (the WinPE itself is
hidden only when it really is the PE: `MiniNT` key **and** running from `X:`). Every scan
and every repair action works on the **selected target** — there is no silent fallback to
another registry.

- **Offline** (recommended: the malware is not running and cannot fight back). The
  target's hives are mounted with `reg.exe load` as `HKLM\RS_SOFT`, `HKLM\RS_SYS` and one
  `HKLM\RS_U<n>` per user profile on the target volume, and unloaded on rescan/exit.
  Mounts left over by a crashed/killed earlier run are detected and cleaned up; another
  running RescueScan's mounts are never touched (only one instance holds the mount role).
  The target's own `SystemRoot` (e.g. `C:\Windows` although the PE calls the volume `D:`)
  is used for every default it writes.
  If the target was shut down with **Fast Startup** (the default since Windows 8, i.e. it
  is really hibernated: `<drive>\hiberfil.sys` starts with `hibr`/`HIBR`/`RSTR`), Windows
  would resume from that image and lose — or corrupt — everything changed offline. The scan
  shows a warning and every change on that drive asks for confirmation (once per
  session). Do a full *Restart* (or `shutdown /s /full /t 0`) in that Windows first;
  entering WinRE via Shift+Restart is a full restart and is not affected.
- **Live** (the running OS is the target). `HKLM\SOFTWARE`, `HKLM\SYSTEM` and
  `HKU\<SID>` of logged‑on users are read in place; profiles of other users are mounted.
  Needed for the task manager against the real malware processes, the Winlogon guard and
  the Accounts tab.

Registry access goes through `Microsoft.Win32` / `advapi32` (exact names, all value types,
no parsing of `reg query` text). `reg.exe`, `bcdedit.exe` and `net.exe` are only used for
hive load/unload, BCD listing and enabling/deleting accounts; they are always started by
their full System32 path (`Sysnative` from a 32‑bit process on 64‑bit Windows), with
quoted arguments, a timeout and closed stdin, and they are **not started at all** when
the running system hijacks them through Image File Execution Options. If
`DisableRegistryTools` blocks `reg.exe`, the tool says so and how to proceed.

## The nine tabs

1. **Автозагрузка (полная)** — full autoruns scan of the target. *Найти ОС* →
   *Сканировать*. Covers, among others: Run/RunOnce/RunOnceEx (HKLM, every user, WOW64),
   Policies\Explorer\Run, RunServices; Winlogon Shell/Userinit/Taskman/Notify/GinaDLL/
   VmApplet/AppSetup and per‑user Shell overrides; AppInit_DLLs (+WOW64), AppCertDlls,
   ShellServiceObjectDelayLoad, BHOs; cmd AutoRun (machine + user), logon scripts,
   screensaver/wallpaper; IFEO Debugger (+filters, WOW64 copy) and VerifierDlls,
   SilentProcessExit "checkers", AeDebug; Session Manager BootExecute/SetupExecute/Execute,
   SYSTEM\Setup CmdLine, SafeBoot AlternateShell; services and drivers (ImagePath,
   ServiceDll), LSA packages, Print Monitors; Active Setup; executable class hijacks;
   Startup folders (incl. `.lnk` targets and script contents) and their redirects;
   scheduled tasks (XML actions joined with the TaskCache registry, registry‑only and
   hidden tasks); hidden users (SpecialAccounts\UserList), Defender exclusions, the hosts
   file and its `DataBasePath`; non‑driver files in `System32\drivers`; MiniNT on an
   installed Windows. The control set comes from `Select\Default`.
   *Pre‑boot (ESP/BCD)* lists the system BCD and the `\EFI\Microsoft\Boot\BCD` store of
   every ESP with a letter, plus the files on the ESP — **information only**, never
   deleted by a button (vendor and Linux loaders are legitimate).
   Buttons: *Отметить подозрит.*, *Обезвредить*, *Карантин отм.*, *Удалить отм.*,
   *Экспорт* (CSV).
2. **Автозапуск (кратко)** — only Run/RunOnce/Scheduler/Startup, like the Startup page of
   the Windows Task Manager.
3. **Диспетчер задач** — processes with full path and risk colour. *Завершить* and
   *Завершить дерево* (see safety guards), *Поверх всех окон*, *Watchdog*.
4. **Проводник** — shows hidden and system files; red = suspicious or referenced by a
   SUSPECT finding. *Запустить* (programs only, see below), *Переименовать*, *Карантин*,
   *Удалить*, *Снять скрытие* (clears H/S/R), *Кто ссылается* (which autostart entry
   points at this file).
5. **Карантин** — lists a quarantine folder (*Найти последний* searches all drives) and
   restores checked items.
6. **Ремонт** — Winlogon Shell/Userinit, AppInit_DLLs, cmd AutoRun (+ WOW64 copies) with
   red rows where the value differs from the default; *→ Дефолт* / *→ Своё…*.
   *Снять блокировки (политики + IFEO)* removes the usual lock values (DisableTaskMgr,
   DisableRegistryTools, DisableCMD, NoRun, DisallowRun + list, NoWinKeys, NoLogoff,
   DisableLockWorkstation, NoDrives, NoViewOnDrive …) for the machine and **every** user
   profile (live: every loaded `HKU\S-1-5-21-*`), and the IFEO `Debugger` values — only the
   value, never the whole key; known debuggers (Process Explorer, System Informer,
   Notepad++, windbg/cdb/ntsd, vsjitdebugger) are kept. *Вернуть ассоциации* restores
   the `.exe/.com/.bat/.cmd` classes (`exefile`, `comfile`, `batfile`, `cmdfile`) and the
   `.lnk` icon/arrow (`lnkfile`). *Стеречь Winlogon* (live only) puts
   Shell/Userinit back whenever they are changed.
7. **Аккаунты** — live OS only (WMI): local users with Disabled/Locked/"password
   required". Change password (masked, typed twice, set through `NetUserSetInfo`, never on
   a command line), enable/unlock, delete user, delete profile (only a folder directly in
   the ProfilesDirectory, never the current/system profile, after typing the user name).
   A password reset loses the user's EFS files and DPAPI secrets — the dialog says so.
   Disabled in WinPE and when an offline target is selected (it would change the PE's
   accounts); for offline password resets use chntpw or MS DaRT.
8. **Изи-кнопка** — one button driven by toggles: scan → Winlogon/IFEO/restrictions/
   associations back to defaults → defuse → quarantine SUSPECT → watchdog. Every registry
   change is backed up to the quarantine first; items already fixed by an earlier step are
   not touched again. The two toggles "run instead of Explorer" and "run before Windows"
   are deliberately **disabled**.
9. **Справка** — the full Russian help.

Risk colours: **red = SUSPECT** (strong indicator: Temp/AppData payloads, encoded or
hidden PowerShell, interpreters/LOLBins fetching from the network, double extensions,
programs in `drivers`, …); **yellow = REVIEW** (legitimate but popular with malware —
look at it). A clean Windows 10/11 should show no SUSPECT rows.

## How findings are remediated

- **Delete** — the value/key/file is removed (after a quarantine backup when using
  *Карантин*).
- **Defuse** (*Обезвредить*, do this before deleting a boot‑critical binary) — a service
  gets `Start=4`/`ErrorControl=1`, an IFEO entry loses only its `Debugger` value.
- **Reset to default, never delete** — Winlogon `Shell`/`Userinit`/`VMApplet`,
  `BootExecute` (legitimate `autocheck autochk` lines are kept, the rest becomes
  `autocheck autochk *`), `SafeBoot AlternateShell` (`cmd.exe`). A deleted Userinit means a
  logon/logoff loop, a deleted BootExecute drops autochk, so *every* button (Delete,
  Quarantine, Defuse, Easy) writes the default back instead. `Userinit` is derived from
  the target's own `SystemRoot`. `SetupExecute` holding only Windows servicing entries is
  REVIEW and never auto‑removed.
- **Information only** — BCD/ESP, LSA/class‑hijack style rows that need a manual fix are
  skipped by the buttons.

## Quarantine

- Location: `<target drive>\RescueScan_Quarantine\<yyyyMMdd_HHmmss>`; if that is not
  possible, `RescueScan_Quarantine` next to the exe. **Never** on the WinPE RAM disk `X:`
  or under `%TEMP%` — both vanish at reboot together with the only backup.
- One backup per item with a counter‑based name (never derived from the malware's names):
  files are moved to `<N>_<name>.quarantine` (not executable by double click;
  ReadOnly/Hidden/System cleared first, the move is verified); registry items are written
  by RescueScan's own exact writer to `<N>.reg` (`Windows Registry Editor Version 5.00`,
  UTF‑16LE with BOM, every value type incl. `hex(2)`, `hex(7)`, `hex(b)`, `hex(0)` and
  odd types) — a value item backs up only that value, a key item the whole subtree. The
  `.reg` files can also be imported by hand after Windows boots.
- `manifest.txt` (tab‑separated, escaped, header `RESCUESCAN-QUARANTINE 2`) records for
  each item the **logical** location — installation id, hive kind (SOFTWARE / SYSTEM /
  user profile identity) and the relative key path, or the file's original path and
  volume serial — and the SHA‑256 of the backup.
- Restore (*Карантин* tab → *Восстановить*): select the same installation, press
  *Сканировать* (so its hives are mounted), then restore. Items are restored newest first;
  a backup is written back only into the hive it came from (a clear Russian refusal if
  that installation/hive/profile is not mounted); a backup outside the folder or with a
  changed SHA‑256 is refused; a file that now exists at the original path is renamed
  aside (`*.before-restore-<stamp>`), never overwritten. A file restores to the volume
  with the recorded serial, whatever letter it has now.

## Safety guards

- Explorer *Удалить* refuses drive roots and critical folders (`Windows`, `System32`,
  `SysWOW64`, `WinSxS`, `config`, `drivers`, `Program Files*`, `ProgramData`, `Users`,
  `System Volume Information`, `Boot`, `Recovery`, `EFI`, the target's Windows folder),
  asks a second time for any folder, clears ReadOnly, handles names ending in `.`/space
  via `\\?\`, never follows junctions/symlinks.
- *Запустить* starts `.exe/.com` **directly** (CreateProcess, no file‑association lookup —
  a hijacked `HKCU\Software\Classes\exefile` cannot run with RescueScan's admin token),
  `.bat/.cmd` only through System32 `cmd.exe /k` after a warning, and opens every other
  file type only as text in System32 Notepad. A program hijacked through IFEO is not
  started.
- Task manager: a confirmation lists every process to be killed. The tree is built from a
  Toolhelp snapshot with start‑time checks (a reused parent PID never makes an unrelated
  or critical process a "child"), with a visited set; the root is killed first, then its
  descendants, then a few fresh snapshots catch children spawned meanwhile. PID 0/4,
  RescueScan itself and its watchdog are never killed. System, smss, csrss, wininit,
  winlogon, services, lsass (and winpeshl in WinPE) from System32 need a second explicit
  confirmation. Each kill re‑checks that the PID still belongs to the listed process.
- Offline changes on a hibernated (Fast Startup) target need an explicit confirmation.
- Reset‑only values (above), backups before every change, hives unloaded on exit and on
  a fatal error, last‑chance error handler with a Russian message and a log entry.
- CSV export quotes every cell, doubles quotes and neutralises cells starting with
  `= + - @ TAB CR` (no formula injection from malware‑chosen names).

## Watchdog (opt‑in)

A user‑mode self‑heal: a hidden second `RescueScan.exe --watchdog` relaunches the GUI if
it disappears without the stop signal, and the GUI respawns the watchdog. Each arming
uses a fresh random stop‑event name (Administrators/SYSTEM only). A relaunched GUI adopts
the running watchdog, so closing it normally stops the watchdog, and it restores the
Winlogon guard on a live target. Relaunches back off and stop after repeated failures.
Log: `%TEMP%\rescuescan.log`. **Limit:** both processes have the same image name, so
`taskkill /f /im RescueScan.exe` kills both at once — a user‑mode watchdog cannot prevent
that; prefer offline cleaning against such malware.

## Build

On Windows (no Visual Studio needed — the in‑box .NET Framework 4.x compiler, C# 5):

```powershell
.\build.ps1          # builds RescueScan.exe
.\build.ps1 -Test    # builds, then runs the unit tests
```

`build.ps1` uses `Framework64\v4.0.30319\csc.exe` and falls back to
`Framework\v4.0.30319\csc.exe`. The equivalent command:

```powershell
& "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe" -nologo -codepage:65001 `
  -target:winexe -platform:anycpu -win32manifest:app.manifest -out:RescueScan.exe `
  -reference:System.Windows.Forms.dll -reference:System.Drawing.dll `
  -reference:System.Core.dll -reference:System.Management.dll RescueScan.cs
```

`-codepage:65001` is required: the source is UTF‑8 without BOM (Russian UI strings) and
the legacy compiler would otherwise read it in the ANSI code page. Keep the build AnyCPU
(never `x86` / `anycpu32bitpreferred`) so it runs in an x64 WinPE. The code must stay
C# 5 (no `$""`, `?.`, `nameof`, `=>` members …) and use only in‑box assemblies.

## Tests

`tests/RescueScan.Tests.cs` is a self‑contained test program compiled together with
`RescueScan.cs` (no framework, no NuGet).

- Windows: `tests\run-tests.ps1` (or `.\build.ps1 -Test`). Uses only a throwaway key
  `HKCU\Software\RescueScanTests\<guid>`; run elevated to include the real
  `reg.exe save/load/unload` test.
- Linux/macOS with Mono: `LANG=C.UTF-8 tests/run-tests.sh` (`mcs -langversion:5`, so it
  also checks the C# 5 constraint). Tests marked `[win]` (P/Invoke, real `reg.exe`,
  registry links, Toolhelp) are skipped there.

Covered: registry read/write helpers, argument quoting, process runner, `.reg`
writer/parser round trips, quarantine manifest/location logic, defaults and reset rules,
risk heuristics against clean Windows defaults and known attacks, task XML/TaskCache
parsing, process‑tree logic and `PROCESSENTRY32W` layout, watchdog arguments, CSV
escaping, and more.

## Known limitations

- Cleans the OS level plus the boot loader/ESP (report only). A firmware (SPI flash)
  implant is out of scope — reflash the firmware.
- Offline account changes (SAM editing) are not implemented; use chntpw / MS DaRT.
- Heuristics are heuristics: REVIEW rows need a human; a careful attacker can look clean.
- Path mapping between the target's drive letter (as stored in its registry) and the PE's
  drive letter is limited to the target's own system volume.
- The watchdog does not survive `taskkill /im` (see above); the log lives in `%TEMP%`.
- No kernel driver: rootkits that hide from user‑mode APIs are not found.

### Must be tested on real Windows before relying on it

The code is compiled and unit‑tested with Mono on Linux; Windows‑only paths are covered
by `[win]` tests that must be run with `tests\run-tests.ps1` on Windows. Not yet verified
on real systems:

- Startup and all tabs in an ADK WinPE with WinPE‑WMI + WinPE‑NetFx (x64), including
  System.Management (Accounts tab label in the PE) and the `RescueScan.cmd` launcher in a
  PE without NetFx.
- Offline mount/unload of SOFTWARE/SYSTEM/NTUSER/UsrClass on Windows 10/11, the stale
  mount cleanup after a killed run, and restore of `.reg` backups with odd value types.
- The hibernation check against a real Fast Startup shutdown (Windows 10/11) and after a
  full shutdown (no false warning).
- "Kill tree" against a respawning batch loop; the critical‑process confirmation; the
  start‑time checks with protected processes.
- Watchdog: kill the GUI, close the relaunched GUI normally (the watchdog must exit),
  guard restore on a live target, event creation with the restricted DACL.
- `Запустить` with a hijacked `HKCU\Software\Classes\exefile` (must not trigger it).
- That a clean Windows 10/11 shows no SUSPECT rows; IFEO/association/policy repairs.

## Disclaimer

Provided as‑is, for educational and defensive use on your own or explicitly authorised
systems. You are responsible for how you use it. Changing autostart entries can affect
system behaviour — review findings (and keep the quarantine) before removing things.

## License

MIT — see [LICENSE](LICENSE).
