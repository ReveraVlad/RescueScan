// Self-contained tests for RescueScan's registry / process helpers and scan-side filters (C# 5, no frameworks).
// Compiled TOGETHER with RescueScan.cs using -main:RescueScan.Tests.TestMain:
//   Linux/Mono : tests/run-tests.sh          Windows : tests/run-tests.ps1 (in-box csc)
// Registry tests use a throwaway key HKCU\Software\RescueScanTests\<guid> that is always removed at the end.
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
        static readonly string TopLevel = "RescueScanTests_" + Id;          // directly under HKCU (DeleteKey must refuse it)

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
                Run("SetString/SetDword: create key, exact names, kinds", SetHelpers);
                Run("DeleteValue: exact names, missing => false", DeleteValueExact);
                Run("DeleteKey: whole tree, refusals, missing => false", DeleteKeyTree);
                Run("KeyExists", KeyExistsCases);
                Run("NUL in names/paths: never aliased, never acted on", NulNames);
                Run("Values: a value deleted during the read is not a hidden name", ValuesRace);
                Run("Live mode: ProfileImagePath -> folders on the TARGET drive", ProfileDirs);
                Run("Live mode: SamePath / WinTarget labels", LiveHelpers);
                Run("RunProcess: big stderr does not deadlock", ProcBigStderr);
                Run("RunProcess: exit code + stderr on failure", ProcFailure);
                Run("RunProcess: timeout kills the child", ProcTimeout);
                Run("RunProcess: stdin is closed (no wait for input)", ProcStdinClosed);
                Run("RunProcess: output is capped but drained", ProcOutputCap);
                Run("SysExe: absolute System32 path [win]", SysExeWin);
                Run("Values: raw types .NET cannot read (REG_RESOURCE_LIST, custom) [win]", RawTypesWin);
                Run("Pairs/DeleteKey: registry symbolic links are not followed [win]", LinksWin);
                Run("Export: exit code AND file [win]", ExportWin);
                Run("Values/Pairs: a key with a deny-ACL is noted, not silently skipped [win]", DeniedWin);
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
            catch (Exception e) { failed++; Console.WriteLine("FAIL  " + name + "\n      " + e.Message.Replace("\n", "\n      ")); }
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
            using (RegistryKey b = HKCU())
            {
                try { b.DeleteSubKeyTree(Sub, false); } catch { }
                try { b.DeleteSubKeyTree(TopLevel, false); } catch { }
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
            using (RegistryKey b = HKCU()) b.CreateSubKey(TopLevel).Close();
            True(!Reg.DeleteKey("HKCU\\" + TopLevel), "first-level key refused");
            True(ManagedExists(TopLevel), "...and still there");
            True(!Reg.DeleteKey("HKCU"), "hive root refused");
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
        static string Join(List<string> l) { return string.Join(" | ", l.ToArray()); }

        static void ProfileDirs()
        {
            Eq("D:\\Users\\Ivan", Join(MainForm.ProfileDirCandidates("%SystemDrive%\\Users\\Ivan", "D:\\Windows", false)), "offline %SystemDrive% -> target drive");
            Eq("D:\\Users\\Ivan", Join(MainForm.ProfileDirCandidates("%systemdrive%\\Users\\Ivan\\", "D:\\Windows", false)), "case-insensitive, trailing backslash");
            Eq("D:\\Windows\\ServiceProfiles\\X", Join(MainForm.ProfileDirCandidates("%SystemRoot%\\ServiceProfiles\\X", "D:\\Windows", false)), "%SystemRoot% -> target Windows dir");
            Eq("D:\\Windows\\x", Join(MainForm.ProfileDirCandidates("%windir%\\x", "D:\\Windows", false)), "%windir%");
            Eq("D:\\Users\\Ivan | C:\\Users\\Ivan", Join(MainForm.ProfileDirCandidates("C:\\Users\\Ivan", "D:\\Windows", false)), "offline literal C: -> target drive first");
            Eq("D:\\Users\\Ivan", Join(MainForm.ProfileDirCandidates("D:\\Users\\Ivan", "D:\\Windows", false)), "same drive");
            Eq("C:\\Users\\Ivan", Join(MainForm.ProfileDirCandidates("%SystemDrive%\\Users\\Ivan", "C:\\Windows", true)), "live");
            Eq("E:\\Profiles\\X", Join(MainForm.ProfileDirCandidates("E:\\Profiles\\X", "C:\\Windows", true)), "live: other drive kept as is");
            Eq("D:\\Пользователи\\Иван", Join(MainForm.ProfileDirCandidates("%SystemDrive%\\Пользователи\\Иван", "D:\\Windows", false)), "Cyrillic");
            Eq("", Join(MainForm.ProfileDirCandidates("%USERPROFILE%\\x", "D:\\Windows", false)), "unknown variable rejected");
            Eq("", Join(MainForm.ProfileDirCandidates("\\\\server\\share\\x", "D:\\Windows", false)), "UNC rejected");
            Eq("", Join(MainForm.ProfileDirCandidates("Users\\x", "D:\\Windows", false)), "relative rejected");
            Eq("", Join(MainForm.ProfileDirCandidates("", "D:\\Windows", false)), "empty");
            Eq("", Join(MainForm.ProfileDirCandidates(null, "D:\\Windows", false)), "null");
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

        // ------------------------------------------------------------------ processes
        static List<string> tempFiles = new List<string>();

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

        // A key whose DACL denies reading: Values/Pairs see nothing (like reg.exe did), but the key is noted for the scan.
        static void DeniedWin()
        {
            WindowsOnly();
            using (RegistryKey k = Make("deny\\locked")) k.SetValue("ImagePath", "C:\\Windows\\Temp\\x.exe");
            SecurityIdentifier me = WindowsIdentity.GetCurrent().User;
            RegistryAccessRule rule = new RegistryAccessRule(me, RegistryRights.QueryValues | RegistryRights.EnumerateSubKeys, AccessControlType.Deny);
            using (RegistryKey b = HKCU())
            using (RegistryKey k = b.OpenSubKey(Sub + "\\deny\\locked", RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.ReadPermissions | RegistryRights.ChangePermissions))
            {
                RegistrySecurity s = k.GetAccessControl();
                s.AddAccessRule(rule);
                k.SetAccessControl(s);
            }
            try
            {
                Reg.TakeDenied();
                Eq(0, Reg.Values(Root + "\\deny\\locked").Count, "unreadable key -> no values");
                bool cut;
                Eq(0, Reg.Pairs(Root + "\\deny", "ImagePath", out cut).Count, "Pairs: unreadable child -> nothing");
                List<string> d = Reg.TakeDenied();
                True(d.Contains(Root + "\\deny\\locked"), "noted as denied: " + string.Join(" | ", d.ToArray()));
                Eq(0, Reg.TakeDenied().Count, "TakeDenied starts a new list");
            }
            finally
            {
                using (RegistryKey b = HKCU())   // the owner may always change the DACL: undo, so the cleanup can delete it
                using (RegistryKey k = b.OpenSubKey(Sub + "\\deny\\locked", RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.ReadPermissions | RegistryRights.ChangePermissions))
                {
                    RegistrySecurity s = k.GetAccessControl();
                    s.RemoveAccessRule(rule);
                    k.SetAccessControl(s);
                }
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
    }
}
