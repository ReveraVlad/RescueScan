// RescueScan - defensive persistence scanner/remover for Windows: OFFLINE from a WinPE that contains .NET
// (ADK WinPE + WinPE-WMI + WinPE-NetFx; stock WinRE has no .NET and cannot run it) or LIVE on the infected system.
// GUI: WinForms, .NET Framework 4.x, C# 5, one file. Registry through Microsoft.Win32/advapi32; reg.exe only to
// load/unload offline hives (HKLM\RS_SOFT, RS_SYS, RS_U<n>), bcdedit/net by full System32 path.
// Build: build.ps1 (= csc -codepage:65001 -target:winexe -platform:anycpu -win32manifest:app.manifest
//        -out:RescueScan.exe -r:System.Windows.Forms.dll -r:System.Drawing.dll -r:System.Core.dll
//        -r:System.Management.dll RescueScan.cs).  Tests: tests/run-tests.ps1 (Windows), tests/run-tests.sh (Mono).
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace RescueScan
{
    class Finding
    {
        public string Category;   // where it lives (Run HKLM, IFEO, Service, Task...)
        public string Name;       // value name / task name
        public string Value;      // command / path / data
        public string Location;   // reg key or file path used for deletion display
        public string Risk;       // "", "SUSPECT", "REVIEW"
        public int Kind;          // 0=regvalue 1=regkey 2=file 3=info only (fix by hand) 4=reset value to its default
        public string DelKey;     // reg key for delete
        public string DelName;    // value name (for regvalue)
        public string DelPath;    // file path (for file)
        // Kind 4: values that must never be deleted (Winlogon Shell/Userinit/VMApplet, BootExecute, SetupExecute,
        // SafeBoot AlternateShell): «Удалить», «Карантин», «Обезвредить» and the Easy button write this back instead.
        public object ResetData;  // string or string[]
        public RegistryValueKind ResetType = RegistryValueKind.String;
        // registry keys removed (each backed up first) together with this finding: the TaskCache keys of a task
        public List<string> AlsoKeys;
    }

    static class Reg
    {
        internal const int RegTimeoutMs = 120000;   // reg.exe (load of a big hive from a slow disk still fits)
        internal const int ToolTimeoutMs = 60000;   // bcdedit.exe / net.exe

        public static string Run(string args)
        {
            string outp;
            RunCode(args, out outp);
            return outp;
        }

        // reg.exe <args>. Returns the exit code (-1 = could not start / timed out); outp = stdout (+ stderr on failure).
        // Every variable part of args must be passed through QuoteArg.
        public static int RunCode(string args, out string outp)
        {
            int rc = RunProcess(SysExe("reg.exe"), args, RegTimeoutMs, out outp);
            if (rc != 0 && RegToolsBlocked("HKCU")) outp = (outp ?? "") + "\r\n" + RegToolsHint;
            return rc;
        }

        // reg.exe refuses EVERY operation (load, unload, export, import...: exit code 1) while the HKCU policy value
        // DisableRegistryTools is a non-zero DWORD (research windows-semantics Q6: reg.exe 10.0.26100 disassembly) - a
        // classic winlocker restriction. Our own Microsoft.Win32 reads and writes are not affected by it.
        // userRoot = HKCU (tests pass a throwaway key).
        internal static bool RegToolsBlocked(string userRoot)
        {
            foreach (string[] v in Values(userRoot + "\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"))
                if (v[0].Equals("DisableRegistryTools", StringComparison.OrdinalIgnoreCase) && v[2] == "REG_DWORD" && v[1] != "0x0") return true;
            return false;
        }

        internal const string RegToolsHint = "reg.exe заблокирован политикой DisableRegistryTools (HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System) — " +
            "на живой ОС сначала нажми «Снять блокировки» на вкладке «Ремонт» и повтори.";

        // Image File Execution Options of the RUNNING system apply to every process RescueScan starts, whatever its path
        // (IFEO is keyed by the file name only): a Debugger, VerifierDlls, a filter subkey (UseFilter) with a Debugger, or
        // a SilentProcessExit monitor on reg.exe / bcdedit.exe / net.exe would run the virus's program with our
        // administrator token - and a fake reg.exe could forge results (an "exported" backup that is not one).
        // Returns "" or what was found. softRoot = HKLM\SOFTWARE (tests pass a throwaway key).
        internal static string ToolHijack(string softRoot, string exeName)
        {
            string name = exeName ?? "";
            name = name.Substring(name.LastIndexOfAny(new char[] { '\\', '/' }) + 1);
            foreach (string r in new string[] { softRoot, softRoot + "\\Wow6432Node" })
            {
                string k = r + "\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" + name;
                using (RegistryKey t = OpenKey(k, false))   // an IFEO key for the tool that we may not read cannot be checked
                    if (t == null && KeyExists(k)) return k + " (ключ есть, но не читается — проверить нельзя)";
                string hit = IfeoHit(k);
                if (hit.Length > 0) return hit;
                bool filter = false; long gflag = 0;
                foreach (string[] v in Values(k))
                {
                    if (v[0].Equals("UseFilter", StringComparison.OrdinalIgnoreCase) && Num(v[1]) != 0) filter = true;
                    if (v[0].Equals("GlobalFlag", StringComparison.OrdinalIgnoreCase)) gflag = Num(v[1]);
                }
                if (filter)
                    foreach (string sk in Subkeys(k)) { hit = IfeoHit(sk); if (hit.Length > 0) return hit; }
                if ((gflag & 0x200) != 0)   // FLG_MONITOR_SILENT_PROCESS_EXIT
                {
                    string spe = r + "\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\" + name;
                    foreach (string[] v in Values(spe))
                        if (v[0].Equals("MonitorProcess", StringComparison.OrdinalIgnoreCase) && v[1].Trim().Length > 0) return spe + "\\" + v[0] + " = " + v[1];
                }
            }
            return "";
        }

        static string IfeoHit(string k)
        {
            foreach (string[] v in Values(k))
                if ((v[0].Equals("Debugger", StringComparison.OrdinalIgnoreCase) || v[0].Equals("VerifierDlls", StringComparison.OrdinalIgnoreCase))
                    && v[1].Trim().Length > 0) return k + "\\" + v[0] + " = " + v[1];
            return "";
        }

        // "0x200" (REG_DWORD text) or a decimal / hex string (GlobalFlag is sometimes REG_SZ); 0 if not a number.
        static long Num(string s)
        {
            s = (s ?? "").Trim();
            long n;
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                return long.TryParse(s.Substring(2), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out n) ? n : 0;
            return long.TryParse(s, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out n) ? n : 0;
        }

        // Tool output for a status line / log: one line, at most 'max' characters.
        internal static string OneLine(string s, int max)
        {
            if (string.IsNullOrEmpty(s)) return "";
            StringBuilder sb = new StringBuilder();
            bool gap = false;
            foreach (char c in s)
            {
                if (char.IsWhiteSpace(c) || char.IsControl(c)) { gap = sb.Length > 0; continue; }
                if (gap) { sb.Append(' '); gap = false; }
                sb.Append(c);
            }
            string r = sb.ToString();
            return r.Length > max ? r.Substring(0, max) + "…" : r;
        }

        // Runs a console tool hidden. stdout and stderr are drained concurrently (no pipe-buffer deadlock); on timeout
        // the child is killed and -1 is returned. outp = stdout, plus stderr when the exit code is not 0.
        // A tool hijacked through IFEO on the running system is not started at all (-1, outp says why).
        internal static int RunProcess(string exe, string args, int timeoutMs, out string outp)
        {
            string tool = Path.GetFileName(exe);
            if (IsWindows)
            {
                string hijack = ToolHijack("HKLM\\SOFTWARE", tool);
                if (hijack.Length == 0 && tool.Equals("net.exe", StringComparison.OrdinalIgnoreCase)) hijack = ToolHijack("HKLM\\SOFTWARE", "net1.exe");   // net.exe runs net1.exe
                if (hijack.Length > 0)
                {
                    outp = "Запуск " + tool + " отменён: перехват через Image File Execution Options — " + hijack +
                        ". Вместо " + tool + " запустилась бы чужая программа с правами администратора. Удали этот параметр (Debugger снимает «Снять блокировки» на вкладке «Ремонт») и повтори.";
                    return -1;
                }
            }
            Process p = null;
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo(exe, args);
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                psi.RedirectStandardInput = true;   // closed below: a prompt (reg/net) gets EOF instead of waiting for a console
                Encoding oem = OemEncoding();   // the child's new console writes OEM (866/437...), .NET would decode as ANSI
                if (oem != null) { psi.StandardOutputEncoding = oem; psi.StandardErrorEncoding = oem; }
                p = Process.Start(psi);
                try { p.StandardInput.Close(); } catch { }
                StreamReader so = p.StandardOutput, se = p.StandardError;
                string[] text = new string[2];
                Thread to = new Thread(delegate() { try { text[0] = ReadCapped(so); } catch { } });
                Thread te = new Thread(delegate() { try { text[1] = ReadCapped(se); } catch { } });
                to.IsBackground = true; te.IsBackground = true;
                to.Start(); te.Start();
                if (!p.WaitForExit(timeoutMs))
                {
                    try { p.Kill(); } catch { }
                    try { p.WaitForExit(5000); } catch { }
                    to.Join(2000); te.Join(2000);
                    // only the tool and its sub-command: the arguments may hold a password (net user NAME PASSWORD)
                    string verb = (args ?? "").Trim();
                    int sp = verb.IndexOf(' ');
                    outp = "Превышено время ожидания (" + ((timeoutMs + 999) / 1000) + " с): " + tool + " " + (sp > 0 ? verb.Substring(0, sp) : verb);
                    return -1;
                }
                // exit code is known; a grandchild that inherited the pipes must not hang us forever
                to.Join(10000); te.Join(10000);
                int code = p.ExitCode;
                string o1 = text[0] ?? "", o2 = text[1] ?? "";
                outp = (code != 0 && o2.Trim().Length > 0) ? o1 + (o1.Length > 0 ? "\r\n" : "") + o2 : o1;
                return code;
            }
            catch (Exception ex)
            {
                outp = ex.Message;
                return -1;
            }
            finally
            {
                if (p != null) try { p.Dispose(); } catch { }
            }
        }

        // Drains a stream to the end but keeps at most 1 MB (a looping prompt must not eat all memory until the timeout).
        static string ReadCapped(StreamReader r)
        {
            const int cap = 1 << 20;
            StringBuilder sb = new StringBuilder();
            char[] buf = new char[4096];
            int n;
            while ((n = r.Read(buf, 0, buf.Length)) > 0)
                if (sb.Length < cap) sb.Append(buf, 0, Math.Min(n, cap - sb.Length));
            return sb.ToString();
        }

        [DllImport("kernel32.dll")]
        static extern int GetOEMCP();

        static Encoding OemEncoding()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT) return null;
            try { return Encoding.GetEncoding(GetOEMCP()); } catch { return null; }
        }

        // Full path of a Windows console tool. Never a planted copy next to RescueScan.exe (CreateProcess searches the
        // application directory first); a 32-bit build on 64-bit Windows gets the 64-bit tool via Sysnative.
        internal static string SysExe(string name)
        {
            if (!name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) name += ".exe";
            try
            {
                string sys = Environment.SystemDirectory;   // GetSystemDirectory, not a (spoofable) environment variable
                if (!string.IsNullOrEmpty(sys))
                {
                    if (Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess)
                    {
                        string nat = Path.Combine(Path.Combine(Path.GetDirectoryName(sys), "Sysnative"), name);
                        if (File.Exists(nat)) return nat;
                    }
                    string full = Path.Combine(sys, name);
                    if (File.Exists(full)) return full;
                }
            }
            catch { }
            return name;
        }

        // Quotes ONE argument for the MSVCRT / CommandLineToArgvW parser used by reg.exe, bcdedit.exe, net.exe:
        // always wrapped in quotes; backslashes are doubled only before a quote or the closing quote; quotes -> \".
        internal static string QuoteArg(string s)
        {
            if (s == null) s = "";
            StringBuilder sb = new StringBuilder(s.Length + 8);
            sb.Append('"');
            int bs = 0;
            foreach (char c in s)
            {
                if (c == '\\') { bs++; continue; }
                if (c == '"') { sb.Append('\\', bs * 2 + 1); sb.Append('"'); bs = 0; continue; }
                if (bs > 0) { sb.Append('\\', bs); bs = 0; }
                sb.Append(c);
            }
            sb.Append('\\', bs * 2);
            sb.Append('"');
            return sb.ToString();
        }

        // reg export KEY FILE /y. Success only if reg.exe exited with 0 AND a non-empty file is there.
        public static bool Export(string key, string file)
        {
            string err;
            return Export(key, file, out err);
        }

        // err = why it failed (reg.exe's own message, one line), "" on success.
        public static bool Export(string key, string file, out string err)
        {
            string o;
            int rc = RunCode("export " + QuoteArg(key) + " " + QuoteArg(file) + " /y", out o);
            bool ok = false;
            try { ok = rc == 0 && File.Exists(file) && new FileInfo(file).Length > 0; } catch { }
            err = ok ? "" : OneLine(o, 300);
            if (!ok && err.Length == 0) err = rc == 0 ? "reg export: файл не создан" : "reg export: код " + rc;
            return ok;
        }

        // ================= registry access via Microsoft.Win32 (no "reg query" text parsing) =================
        // Paths are "<ROOT>\sub\key", ROOT = HKLM | HKEY_LOCAL_MACHINE | HKCU | HKEY_CURRENT_USER | HKU | HKEY_USERS |
        // HKCR | HKEY_CLASSES_ROOT; always the 64-bit view on 64-bit Windows (also from a 32-bit build).
        // Missing key / access denied => empty result (or false), never an exception to the UI.
        internal const int PairsMaxDepth = 64;         // Pairs: levels below the start key
        internal static int PairsMaxKeys = 250000;     // Pairs: keys visited per call (not const: tests lower the bounds)
        internal static int PairsMinShare = 50000;     // Pairs: a subtree may always use this much of what is left

        internal static RegistryView View
        {
            get { return Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Default; }
        }

        internal static bool SplitRoot(string path, out RegistryHive hive, out string sub)
        {
            hive = RegistryHive.LocalMachine; sub = "";
            if (path == null || path.IndexOf('\0') >= 0) return false;   // Win32 would silently cut the path at the NUL
            int i = path.IndexOf('\\');
            string root = (i < 0 ? path : path.Substring(0, i)).ToUpperInvariant();
            sub = i < 0 ? "" : path.Substring(i + 1);
            switch (root)
            {
                case "HKLM": case "HKEY_LOCAL_MACHINE": hive = RegistryHive.LocalMachine; return true;
                case "HKCU": case "HKEY_CURRENT_USER": hive = RegistryHive.CurrentUser; return true;
                case "HKU": case "HKEY_USERS": hive = RegistryHive.Users; return true;
                case "HKCR": case "HKEY_CLASSES_ROOT": hive = RegistryHive.ClassesRoot; return true;
            }
            return false;
        }

        // Opens a key by full path; the caller disposes it. null if missing / access denied / unknown root.
        // A key that exists but may not be read is remembered (NoteDenied) so a scan can say so.
        internal static RegistryKey OpenKey(string path, bool writable)
        {
            RegistryHive hive; string sub;
            if (!SplitRoot(path, out hive, out sub)) return null;
            try
            {
                RegistryKey b = RegistryKey.OpenBaseKey(hive, View);
                if (sub.Trim('\\').Length == 0) return b;
                using (b) return b.OpenSubKey(sub, writable);
            }
            catch (System.Security.SecurityException) { if (!writable) NoteDenied(path); return null; }
            catch (UnauthorizedAccessException) { if (!writable) NoteDenied(path); return null; }
            catch { return null; }
        }

        // ---- keys that exist but could not be opened for reading (DACL changed: a known hiding trick) ----
        // Values/Subkeys/Pairs return nothing for them (like reg.exe did); Scan lists them so the user knows the scan is
        // incomplete there. Bounded and de-duplicated (the live guard reads Winlogon every 3 s).
        static readonly object deniedLock = new object();
        static List<string> denied = new List<string>();
        static readonly HashSet<string> deniedSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        static void NoteDenied(string path)
        {
            lock (deniedLock) if (denied.Count < 1000 && deniedSet.Add(path)) denied.Add(path);
        }

        // Returns the keys noted since the last call and starts a new list.
        internal static List<string> TakeDenied()
        {
            lock (deniedLock)
            {
                List<string> r = denied;
                denied = new List<string>(); deniedSet.Clear();
                return r;
            }
        }

        // {name, data, type} for every value of a key. Names are exact (the unnamed default value is ""); data is the
        // text reg.exe printed: REG_SZ/REG_EXPAND_SZ raw (NOT expanded, up to the first NUL), REG_MULTI_SZ items joined
        // with the two characters \0, REG_DWORD/REG_QWORD "0x" + lowercase hex, anything else uppercase hex.
        public static List<string[]> Values(string key)
        {
            List<string[]> res = new List<string[]>();
            using (RegistryKey k = OpenKey(key, false))
            {
                if (k == null) return res;
                // A name that contains NUL (MITRE T1112 "hidden" values; Win32 cannot address it) is enumerated cut at
                // the NUL: "\0x" -> "" aliases the default value, "a\0x" -> "a". Such a name shows up twice or cannot
                // be read back; it is returned as <cut name> + "\0" so it never matches (or deletes) a real name.
                HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                HashSet<string> again = null;   // a second listing, made at the first name that cannot be read
                foreach (string n in Names(k, false))
                {
                    string data, type;
                    if (!seen.Add(n)) { res.Add(new string[] { n + "\0", "", "" }); continue; }   // listed twice: NUL-cut alias
                    if (BeforeValueRead != null) BeforeValueRead(k, n);
                    if (TryGetValue(k, n, out data, out type)) { res.Add(new string[] { n, data, type }); continue; }
                    // Live, a value may simply have been deleted since the listing (RunOnce, an updater): that is not a
                    // hidden name. Only a name that is listed again but still cannot be read is one.
                    if (again == null) again = new HashSet<string>(Names(k, false), StringComparer.OrdinalIgnoreCase);
                    if (!again.Contains(n)) continue;
                    if (TryGetValue(k, n, out data, out type)) res.Add(new string[] { n, data, type });
                    else res.Add(new string[] { n + "\0", "", "" });
                }
            }
            return res;
        }

        internal static Action<RegistryKey, string> BeforeValueRead = null;   // tests only: simulates a change during the read

        // Full paths of the immediate subkeys, with the same root spelling/prefix as 'key' (can be passed on as is).
        public static List<string> Subkeys(string key)
        {
            List<string> res = new List<string>();
            using (RegistryKey k = OpenKey(key, false))
            {
                if (k == null) return res;
                string bas = key.TrimEnd('\\');
                foreach (string s in Names(k, true))
                    if (s.Length > 0) res.Add(bas + "\\" + s);   // "" = NUL-prefixed hidden name: would address the parent
            }
            return res;
        }

        // Like "reg query KEY /s /v NAME", but only for keys BELOW 'key' (a value planted on Services or IFEO itself
        // must not turn into a "delete the whole Services key" finding): {subkeyFullPath, data, type} for every
        // descendant key that has a value named valName. Registry symbolic links are not followed; depth and the
        // number of visited keys are bounded.
        public static List<string[]> Pairs(string key, string valName)
        {
            bool truncated;
            return Pairs(key, valName, out truncated);
        }

        // truncated = a bound was hit (depth, or too many keys): the result may be incomplete and the caller must say so.
        public static List<string[]> Pairs(string key, string valName, out bool truncated)
        {
            List<string[]> res = new List<string[]>();
            truncated = false;
            using (RegistryKey k = OpenKey(key, false))
            {
                if (k == null) return res;
                int budget = PairsMaxKeys;
                PairsRec(k, key.TrimEnd('\\'), valName, 1, ref budget, ref truncated, res);
            }
            return res;
        }

        // Children first, subtrees second: the value of EVERY child is read before any subtree is entered, and each
        // subtree may use only a fair share of the remaining budget (at least PairsMinShare). A padding key with
        // 250,000 descendants that sorts before the real services / IFEO entries can therefore not use up the budget
        // and hide them; if the budget still runs out, 'truncated' tells the user.
        static void PairsRec(RegistryKey k, string path, string valName, int depth, ref int budget, ref bool truncated, List<string[]> res)
        {
            if (depth > PairsMaxDepth || IsLink(k)) return;
            List<string> kids = new List<string>();
            foreach (string s in Names(k, true))
            {
                if (s.Length == 0) continue;   // NUL-prefixed hidden name: opening "" would re-open k itself
                if (budget <= 0) { truncated = true; break; }
                budget--;
                string cp = path + "\\" + s;
                bool deny;
                using (RegistryKey c = OpenChild(k, s, false, out deny))
                {
                    if (c == null) { if (deny) NoteDenied(cp); continue; }
                    string data, type;
                    if (TryGetValue(c, valName, out data, out type)) res.Add(new string[] { cp, data, type });
                    if (IsLink(c) || !HasSubkeys(c)) continue;
                    if (depth < PairsMaxDepth) kids.Add(s); else truncated = true;
                }
            }
            for (int i = 0; i < kids.Count; i++)
            {
                if (budget <= 0) { truncated = true; break; }
                int share = Math.Max(Math.Min(PairsMinShare, budget), budget / (kids.Count - i)), left = share;
                using (RegistryKey c = OpenChild(k, kids[i], false))
                    if (c != null) PairsRec(c, path + "\\" + kids[i], valName, depth + 1, ref left, ref truncated, res);
                budget -= share - left;   // the unused part of the share goes back to the siblings after it
            }
        }

        static bool HasSubkeys(RegistryKey k)
        {
            try { return k.SubKeyCount > 0; } catch { return true; }
        }

        // Immediate subkey names of a key (no paths). Empty if missing / access denied.
        internal static string[] SubkeyNames(string key)
        {
            using (RegistryKey k = OpenKey(key, false)) return k == null ? new string[0] : Names(k, true);
        }

        // true if the key exists (also when it exists but cannot be read).
        public static bool KeyExists(string key)
        {
            RegistryHive hive; string sub;
            if (!SplitRoot(key, out hive, out sub)) return false;
            try
            {
                using (RegistryKey b = RegistryKey.OpenBaseKey(hive, View))
                {
                    if (sub.Trim('\\').Length == 0) return true;
                    using (RegistryKey k = b.OpenSubKey(sub, false)) return k != null;
                }
            }
            catch (System.Security.SecurityException) { return true; }
            catch (UnauthorizedAccessException) { return true; }
            catch { return false; }
        }

        // RegistryKey.GetValue(..., DoNotExpandEnvironmentNames) result -> the text reg.exe printed for it.
        internal static string FormatData(object o)
        {
            if (o == null) return "";
            string s = o as string;
            if (s != null) { int z = s.IndexOf('\0'); return z >= 0 ? s.Substring(0, z) : s; }
            string[] m = o as string[];
            if (m != null) return string.Join("\\0", Array.FindAll(m, delegate(string e) { return !string.IsNullOrEmpty(e); }));   // reg.exe skips empty items
            if (o is int) return "0x" + ((uint)(int)o).ToString("x");
            if (o is long) return "0x" + ((ulong)(long)o).ToString("x");
            byte[] b = o as byte[];
            if (b != null) return Hex(b);
            return Convert.ToString(o, System.Globalization.CultureInfo.InvariantCulture);
        }

        internal static string Hex(byte[] b)
        {
            if (b == null) return "";
            StringBuilder sb = new StringBuilder(b.Length * 2);
            foreach (byte x in b) sb.Append(x.ToString("X2"));
            return sb.ToString();
        }

        internal static string KindName(RegistryValueKind k)
        {
            switch (k)
            {
                case RegistryValueKind.String: return "REG_SZ";
                case RegistryValueKind.ExpandString: return "REG_EXPAND_SZ";
                case RegistryValueKind.MultiString: return "REG_MULTI_SZ";
                case RegistryValueKind.DWord: return "REG_DWORD";
                case RegistryValueKind.QWord: return "REG_QWORD";
                case RegistryValueKind.Binary: return "REG_BINARY";
                case RegistryValueKind.None: return "REG_NONE";
            }
            return "REG_UNKNOWN";
        }

        static string TypeName(int t)
        {
            string[] n = { "REG_NONE", "REG_SZ", "REG_EXPAND_SZ", "REG_BINARY", "REG_DWORD", "REG_DWORD_BIG_ENDIAN", "REG_LINK",
                           "REG_MULTI_SZ", "REG_RESOURCE_LIST", "REG_FULL_RESOURCE_DESCRIPTOR", "REG_RESOURCE_REQUIREMENTS_LIST", "REG_QWORD" };
            return t >= 0 && t < n.Length ? n[t] : "REG_UNKNOWN_0x" + t.ToString("x");
        }

        // One value as reg.exe printed it. false = there is no such value.
        static bool TryGetValue(RegistryKey k, string name, out string data, out string type)
        {
            data = ""; type = "";
            RegistryValueKind kind;
            object o = null;
            try { kind = k.GetValueKind(name); } catch { return false; }   // .NET: IOException for a missing value
            try { o = k.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames); } catch { }
            if (kind == RegistryValueKind.Unknown)
            {
                // REG_LINK, REG_RESOURCE_LIST, REG_DWORD_BIG_ENDIAN, custom types: .NET knows no kind / often returns no data
                int rt; byte[] raw;
                if (RawValue(k, name, out rt, out raw))
                {
                    type = TypeName(rt);
                    data = rt == 5 && raw.Length == 4 ? "0x" + BitConverter.ToUInt32(raw, 0).ToString("x") : Hex(raw);   // like reg.exe
                    return true;
                }
                // .NET on Windows THROWS for a missing value (above), so Unknown means the value exists but its bytes
                // are not available (native read failed): report it as REG_UNKNOWN, not as missing / hidden.
                // Mono reports a missing value as Unknown.
                if (o == null && !IsWindows) return false;
            }
            type = KindName(kind);
            data = FormatData(o);
            return true;
        }

        // Value or subkey names; retried because enumeration throws when the key changes meanwhile.
        static string[] Names(RegistryKey k, bool subkeys)
        {
            for (int i = 0; ; i++)
            {
                try { return subkeys ? k.GetSubKeyNames() : k.GetValueNames(); }
                catch { if (i >= 4) return new string[0]; }
            }
        }

        // ================= registry writes (exact names/data; no command line involved) =================
        // = reg delete KEY /v NAME /f. false if the key or the value does not exist or the delete failed.
        public static bool DeleteValue(string key, string name)
        {
            if (name == null || name.IndexOf('\0') >= 0) return false;   // would address another (cut) name
            try
            {
                using (RegistryKey k = OpenKey(key, true))
                {
                    if (k == null || !ValueExists(k, name)) return false;
                    k.DeleteValue(name, false);
                    return !ValueExists(k, name);   // RegistryKey.DeleteValue ignores most RegDeleteValue errors: verify
                }
            }
            catch { return false; }
        }

        static bool ValueExists(RegistryKey k, string name)
        {
            string d, t;
            return TryGetValue(k, name, out d, out t);
        }

        // = reg delete KEY /f: the key with all its subkeys. Registry symbolic links inside the tree are removed as
        // links; their targets are never touched. Refuses hive roots and first-level keys (ROOT\x) and paths ending
        // with "\" (an empty last component). false if the key is missing or was not (completely) deleted.
        public static bool DeleteKey(string key)
        {
            RegistryHive hive; string parentSub, name;
            if (!DeletablePath(key, out hive, out parentSub, out name)) return false;
            try
            {
                using (RegistryKey b = RegistryKey.OpenBaseKey(hive, View))
                using (RegistryKey parent = b.OpenSubKey(parentSub, !IsWindows))
                {
                    if (parent == null) return false;
                    if (IsWindows) return DeleteTree(parent, name, 0);
                    using (RegistryKey k = parent.OpenSubKey(name)) if (k == null) return false;   // Mono: no links
                    parent.DeleteSubKeyTree(name, false);
                    using (RegistryKey k = parent.OpenSubKey(name)) return k == null;
                }
            }
            catch { return false; }
        }

        // The paths DeleteKey accepts: a known root and at least two levels below it (never a hive root or a first-level
        // key such as HKLM\SOFTWARE or a mounted HKLM\RS_SOFT), no trailing "\" (an empty last component), no NUL.
        internal static bool DeletablePath(string key, out RegistryHive hive, out string parentSub, out string name)
        {
            string sub;
            parentSub = ""; name = "";
            if (key == null || key.EndsWith("\\") || !SplitRoot(key, out hive, out sub)) { hive = RegistryHive.LocalMachine; return false; }
            int cut = sub.LastIndexOf('\\');
            if (cut <= 0) return false;
            parentSub = sub.Substring(0, cut); name = sub.Substring(cut + 1);
            return name.Length > 0 && parentSub.Trim('\\').Length > 0;
        }

        // Windows: depth-first; each key is opened WITHOUT following a link and deleted through its own handle.
        static bool DeleteTree(RegistryKey parent, string name, int depth)
        {
            if (depth > 512) return false;   // deeper than the registry allows
            using (RegistryKey k = OpenChild(parent, name, true))
            {
                if (k == null) return false;
                bool ok = true;
                if (!IsLink(k))
                    foreach (string s in Names(k, true))
                        if (s.Length == 0 || !DeleteTree(k, s, depth + 1)) ok = false;   // "": hidden NUL name, not addressable
                return ok && NtDeleteKey(k.Handle) == 0;
            }
        }

        // = reg add KEY /v NAME /t REG_SZ (expand: REG_EXPAND_SZ) /d DATA /f: creates the key if needed.
        public static bool SetString(string key, string name, string data)
        {
            return SetString(key, name, data, false);
        }

        public static bool SetString(string key, string name, string data, bool expand)
        {
            return SetValue(key, name, data, expand ? RegistryValueKind.ExpandString : RegistryValueKind.String);
        }

        // = reg add KEY /v NAME /t REG_DWORD /d VALUE /f
        public static bool SetDword(string key, string name, int value)
        {
            return SetValue(key, name, value, RegistryValueKind.DWord);
        }

        internal static bool SetValue(string key, string name, object data, RegistryValueKind kind)
        {
            RegistryHive hive; string sub;
            if (name == null || name.IndexOf('\0') >= 0 || data == null || !SplitRoot(key, out hive, out sub) || sub.Trim('\\').Length == 0) return false;
            try
            {
                using (RegistryKey b = RegistryKey.OpenBaseKey(hive, View))
                using (RegistryKey k = b.CreateSubKey(sub))
                {
                    if (k == null) return false;
                    k.SetValue(name, data, kind);
                    return true;
                }
            }
            catch { return false; }
        }

        // REG_MULTI_SZ (or a single REG_SZ / REG_EXPAND_SZ) as its items, empty items kept; null = no such value / not
        // a string type. Unlike Values() this keeps an item that contains the two characters "\0" intact.
        internal static string[] ReadMulti(string key, string name)
        {
            using (RegistryKey k = OpenKey(key, false))
            {
                if (k == null || name == null || name.IndexOf('\0') >= 0) return null;
                object o;
                try { o = k.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames); } catch { return null; }
                string[] m = o as string[];
                if (m != null) return m;
                string s = o as string;
                return s != null ? new string[] { s } : null;
            }
        }

        // ================= exact backups: raw type + bytes (quarantine .reg files, typed restore) =================
        // Raw registry type and bytes of one value. Windows: RegQueryValueEx (any type, exact bytes); elsewhere (Mono,
        // tests) rebuilt from the managed value. false = no such value / unreadable.
        internal static bool ReadRaw(RegistryKey k, string name, out int type, out byte[] data)
        {
            type = 0; data = null;
            if (k == null || name == null || name.IndexOf('\0') >= 0) return false;
            if (UseNative) return RawValue(k, name, out type, out data);
            RegistryValueKind kind;
            object o;
            try { kind = k.GetValueKind(name); o = k.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames); }
            catch { return false; }
            if (o == null) return false;
            switch (kind)
            {
                case RegistryValueKind.String: type = 1; data = Encoding.Unicode.GetBytes((string)o + "\0"); return true;
                case RegistryValueKind.ExpandString: type = 2; data = Encoding.Unicode.GetBytes((string)o + "\0"); return true;
                case RegistryValueKind.Binary: type = 3; data = (byte[])o; return true;
                case RegistryValueKind.DWord: type = 4; data = BitConverter.GetBytes((int)o); return true;
                case RegistryValueKind.MultiString:
                    StringBuilder sb = new StringBuilder();
                    foreach (string e in (string[])o) sb.Append(e).Append('\0');
                    sb.Append('\0');
                    type = 7; data = Encoding.Unicode.GetBytes(sb.ToString()); return true;
                case RegistryValueKind.QWord: type = 11; data = BitConverter.GetBytes((long)o); return true;
                case RegistryValueKind.None: type = 0; data = o as byte[] ?? new byte[0]; return true;
            }
            return false;
        }

        internal const int SnapshotMaxKeys = 100000;

        // Everything needed to put a value or a key back exactly as it was: valueName != null -> that one value (a
        // missing value is recorded as "delete on restore"); valueName == null -> the key with its whole subtree.
        // null + err when the copy would be incomplete (denied subkey, hidden NUL name, unreadable value, too big):
        // then nothing may be deleted. Registry links are recorded as keys but never followed.
        internal static List<RegSection> Snapshot(string key, string valueName, out string err)
        {
            err = "";
            List<RegSection> res = new List<RegSection>();
            if (key == null || key.IndexOf('\0') >= 0 || (valueName != null && valueName.IndexOf('\0') >= 0)) { err = "имя с NUL"; return null; }
            using (RegistryKey k = OpenKey(key, false))
            {
                if (valueName != null)
                {
                    RegSection s = new RegSection(key.TrimEnd('\\'));
                    RegVal v = new RegVal(); v.Name = valueName;
                    if (k == null)
                    {
                        if (KeyExists(key)) { err = "нет доступа к ключу " + key; return null; }
                        v.Delete = true;
                    }
                    else if (!ReadRaw(k, valueName, out v.Type, out v.Data))
                    {
                        // unreadable is not absent: a backup that says "delete on restore" would destroy the real value
                        if (ValueExists(k, valueName)) { err = "значение не читается: " + key + " \\ " + valueName; return null; }
                        v.Delete = true;
                    }
                    s.Values.Add(v);
                    res.Add(s);
                    return res;
                }
                if (k == null) { err = KeyExists(key) ? "нет доступа к ключу " + key : "нет ключа " + key; return null; }
                int budget = SnapshotMaxKeys;
                return SnapRec(k, key.TrimEnd('\\'), 0, ref budget, res, ref err) ? res : null;
            }
        }

        static bool SnapRec(RegistryKey k, string path, int depth, ref int budget, List<RegSection> res, ref string err)
        {
            if (depth > 512 || --budget < 0) { err = "слишком большая ветка: " + path; return false; }
            RegSection s = new RegSection(path);
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string n in Names(k, false))
            {
                RegVal v = new RegVal(); v.Name = n;
                if (!seen.Add(n) || !ReadRaw(k, n, out v.Type, out v.Data)) { err = "значение не читается (скрытое имя с NUL?) в " + path; return false; }
                s.Values.Add(v);
            }
            res.Add(s);
            if (IsLink(k)) return true;   // a link's own values (SymbolicLinkValue) only; never its target
            foreach (string c in Names(k, true))
            {
                if (c.Length == 0) { err = "подключ со скрытым именем (NUL) в " + path; return false; }
                bool deny;
                using (RegistryKey ck = OpenChild(k, c, false, out deny))
                {
                    if (ck == null) { err = (deny ? "нет доступа к " : "не открывается ") + path + "\\" + c; return false; }
                    if (!SnapRec(ck, path + "\\" + c, depth + 1, ref budget, res, ref err)) return false;
                }
            }
            return true;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "RegSetValueExW")]
        static extern int NRegSetValueEx(SafeRegistryHandle key, string name, int reserved, int type, byte[] data, int size);

        // Writes one value with its exact raw type and bytes (creates the key). Windows: RegSetValueEx, so any type and
        // odd strings (no terminator, embedded NUL) come back byte for byte; elsewhere only the standard types.
        internal static bool SetRaw(string key, string name, int type, byte[] data)
        {
            RegistryHive hive; string sub;
            if (name == null || name.IndexOf('\0') >= 0 || data == null || !SplitRoot(key, out hive, out sub) || sub.Trim('\\').Length == 0) return false;
            try
            {
                using (RegistryKey b = RegistryKey.OpenBaseKey(hive, View))
                using (RegistryKey k = b.CreateSubKey(sub))
                {
                    if (k == null) return false;
                    if (UseNative) return NRegSetValueEx(k.Handle, name, 0, type, data, data.Length) == 0;
                    object o; RegistryValueKind kind;
                    if (!RawToManaged(type, data, out o, out kind)) return false;
                    k.SetValue(name, o, kind);
                    return true;
                }
            }
            catch { return false; }
        }

        // raw (type, bytes) -> a value RegistryKey.SetValue accepts; false for types .NET cannot write.
        internal static bool RawToManaged(int type, byte[] data, out object o, out RegistryValueKind kind)
        {
            o = null; kind = RegistryValueKind.Unknown;
            switch (type)
            {
                case 1: case 2:
                    o = TrimNul(Encoding.Unicode.GetString(data, 0, data.Length & ~1));
                    kind = type == 1 ? RegistryValueKind.String : RegistryValueKind.ExpandString; return true;
                case 7:
                    string t = Encoding.Unicode.GetString(data, 0, data.Length & ~1);
                    if (t.EndsWith("\0\0")) t = t.Substring(0, t.Length - 2); else if (t.EndsWith("\0")) t = t.Substring(0, t.Length - 1);
                    o = t.Length == 0 ? new string[0] : t.Split('\0'); kind = RegistryValueKind.MultiString; return true;
                case 4: if (data.Length != 4) return false; o = BitConverter.ToInt32(data, 0); kind = RegistryValueKind.DWord; return true;
                case 11: if (data.Length != 8) return false; o = BitConverter.ToInt64(data, 0); kind = RegistryValueKind.QWord; return true;
                case 3: o = data; kind = RegistryValueKind.Binary; return true;
                case 0: o = data; kind = RegistryValueKind.None; return true;
            }
            return false;
        }

        static string TrimNul(string s) { int z = s.IndexOf('\0'); return z >= 0 ? s.Substring(0, z) : s; }

        // = reg add KEY /f (no value): creates the key and its parents. false for a hive root / first level / failure.
        internal static bool CreateKey(string key)
        {
            RegistryHive hive; string sub;
            if (key == null || key.IndexOf('\0') >= 0 || !SplitRoot(key, out hive, out sub) || sub.Trim('\\').Length == 0) return false;
            try
            {
                using (RegistryKey b = RegistryKey.OpenBaseKey(hive, View))
                using (RegistryKey k = b.CreateSubKey(sub)) return k != null;
            }
            catch { return false; }
        }

        // true if the value exists (any type).
        internal static bool HasValue(string key, string name)
        {
            using (RegistryKey k = OpenKey(key, false))
                return k != null && name != null && name.IndexOf('\0') < 0 && ValueExists(k, name);
        }

        // ---- Windows-only native helpers: recursion and deletion never follow registry symbolic links ----
        // (a link stored in an OFFLINE hive points into the registry of the running WinPE; a link loop would make the
        // recursion endless; RegistryKey.DeleteSubKeyTree follows links and would delete the link TARGET's subtree).
        const int REG_OPTION_OPEN_LINK = 0x8, KEY_READ = 0x20019, KEY_DELETE = 0x10000, KEY_WOW64_64KEY = 0x100;
        const int REG_LINK = 6, ERROR_MORE_DATA = 234, ERROR_ACCESS_DENIED = 5;
        static volatile bool nativeBroken;   // P/Invoke failed unexpectedly: reads fall back to the managed API

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "RegOpenKeyExW")]
        static extern int NRegOpenKeyEx(SafeRegistryHandle key, string subKey, int options, int sam, out IntPtr result);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "RegQueryValueExW")]
        static extern int NRegQueryValueEx(SafeRegistryHandle key, string name, IntPtr reserved, out int type, [Out] byte[] data, ref int size);
        [DllImport("ntdll.dll")]
        static extern int NtDeleteKey(SafeRegistryHandle key);

        internal static bool IsWindows { get { return Environment.OSVersion.Platform == PlatformID.Win32NT; } }
        static bool UseNative { get { return !nativeBroken && IsWindows; } }

        // Opens child 'name' of 'parent' WITHOUT following it when it is a symbolic link (REG_OPTION_OPEN_LINK).
        // forDelete adds DELETE access and never falls back to the link-following managed API on Windows.
        static RegistryKey OpenChild(RegistryKey parent, string name, bool forDelete)
        {
            bool deny;
            return OpenChild(parent, name, forDelete, out deny);
        }

        // deny = the child exists but access was denied (ERROR_ACCESS_DENIED / SecurityException).
        static RegistryKey OpenChild(RegistryKey parent, string name, bool forDelete, out bool deny)
        {
            deny = false;
            if (UseNative)
            {
                try
                {
                    IntPtr h;
                    int sam = KEY_READ | (forDelete ? KEY_DELETE : 0) | (View == RegistryView.Registry64 ? KEY_WOW64_64KEY : 0);
                    int rc = NRegOpenKeyEx(parent.Handle, name, REG_OPTION_OPEN_LINK, sam, out h);
                    if (rc != 0 || h == IntPtr.Zero) { deny = rc == ERROR_ACCESS_DENIED; return null; }
                    SafeRegistryHandle sh = new SafeRegistryHandle(h, true);
                    try { return RegistryKey.FromHandle(sh, View); }
                    catch { sh.Dispose(); throw; }
                }
                catch (Exception) { nativeBroken = true; if (forDelete) return null; }
            }
            else if (forDelete && IsWindows) return null;
            try { return parent.OpenSubKey(name, forDelete); }
            catch (System.Security.SecurityException) { deny = true; return null; }
            catch (UnauthorizedAccessException) { deny = true; return null; }
            catch { return null; }
        }

        static bool IsLink(RegistryKey k)
        {
            int t; byte[] d;
            return UseNative && RawValue(k, "SymbolicLinkValue", out t, out d) && t == REG_LINK;
        }

        // Raw type and bytes of a value (Windows only).
        static bool RawValue(RegistryKey k, string name, out int type, out byte[] data)
        {
            type = 0; data = null;
            if (!UseNative) return false;
            try
            {
                int size = 0;
                int rc = NRegQueryValueEx(k.Handle, name, IntPtr.Zero, out type, null, ref size);
                if (rc != 0 && rc != ERROR_MORE_DATA) return false;
                byte[] buf = new byte[size];
                rc = NRegQueryValueEx(k.Handle, name, IntPtr.Zero, out type, buf, ref size);
                if (rc != 0) return false;
                if (size < buf.Length) Array.Resize(ref buf, size);
                data = buf;
                return true;
            }
            catch { return false; }
        }
    }

    // One Windows installation offered as scan target. Live = it is the running OS (its registry is read in place).
    class WinTarget
    {
        public readonly string WinDir;   // e.g. D:\Windows
        public readonly bool Live;
        public readonly string Note;     // shown in the list, e.g. a MiniNT key on the running OS
        public WinTarget(string winDir, bool live) : this(winDir, live, "") { }
        public WinTarget(string winDir, bool live, string note) { WinDir = winDir; Live = live; Note = note ?? ""; }
        public override string ToString() { return WinDir + (Live ? " (живая — эта ОС" : " (офлайн") + (Note.Length > 0 ? "; " + Note : "") + ")"; }
    }

    // reg.exe-style runner: exit code; outp = stdout (+ stderr on failure). Injectable so tests can simulate reg.exe.
    internal delegate int ToolRunner(string args, out string outp);

    // Bookkeeping of the hives RescueScan mounts under HKLM: RS_SOFT, RS_SYS and RS_U<n>. Only the instance that holds
    // the mount role (MainForm.OtherInstanceAlive() == false) mounts or unloads anything, so every RS_* mount this
    // instance did not make is stale (crashed / killed earlier run) and may be unloaded - and no instance can pull a
    // hive from under another one. reg.exe, the registry / file probes, the HKLM listing and the instance check are
    // injected: tests simulate them without Windows.
    class HiveMounts
    {
        internal const int MaxUserMounts = 1000;   // RS_U0 .. RS_U999
        internal const string OtherInstanceMsg = "запущен другой RescueScan — кусты монтирует только он: закрой его окно и нажми «Сканировать» ещё раз. ";
        internal readonly List<string> Mounted = new List<string>();   // names WE loaded + stale ones that refused to unload (retried)
        readonly ToolRunner reg;
        readonly Predicate<string> keyExists, fileExists;
        readonly Func<string[]> hklmNames;
        readonly Func<bool> otherInstance;

        internal HiveMounts(ToolRunner reg, Predicate<string> keyExists, Predicate<string> fileExists, Func<string[]> hklmNames, Func<bool> otherInstance)
        {
            this.reg = reg; this.keyExists = keyExists; this.fileExists = fileExists; this.hklmNames = hklmNames; this.otherInstance = otherInstance;
        }

        // RS_SOFT, RS_SYS, RS_U<digits> (any case): the names RescueScan mounts at.
        internal static bool IsOurName(string n)
        {
            if (string.IsNullOrEmpty(n)) return false;
            if (n.Equals("RS_SOFT", StringComparison.OrdinalIgnoreCase) || n.Equals("RS_SYS", StringComparison.OrdinalIgnoreCase)) return true;
            if (n.Length < 5 || !n.StartsWith("RS_U", StringComparison.OrdinalIgnoreCase)) return false;
            for (int i = 4; i < n.Length; i++) if (n[i] < '0' || n[i] > '9') return false;
            return true;
        }

        bool Has(string name)
        {
            foreach (string m in Mounted) if (m.Equals(name, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        // " (reg.exe's message)" for a warning; a reason already in the warning is not repeated for every hive.
        static string Why(int rc, string o, StringBuilder warn)
        {
            string m = Reg.OneLine((o ?? "").Replace(Reg.RegToolsHint, ""), 400);
            if ((o ?? "").Contains(Reg.RegToolsHint) && warn.ToString().IndexOf(Reg.RegToolsHint, StringComparison.Ordinal) < 0)
                warn.Append(Reg.RegToolsHint + " ");
            if (m.Length == 0) return rc != 0 ? " (код " + rc + ")" : "";
            return warn.ToString().IndexOf(m, StringComparison.Ordinal) >= 0 ? " (та же причина)" : " (" + m + ")";
        }

        // reg unload HKLM\<name>. null = gone afterwards; else " (reason)".
        string Unload(string name, StringBuilder warn)
        {
            string o;
            int rc = reg("unload " + Reg.QuoteArg("HKLM\\" + name), out o);
            if (!keyExists("HKLM\\" + name)) return null;
            return Why(rc, o, warn);
        }

        // Unloads EVERY RS_* mount left by a crashed or killed earlier run - also names this run will not reuse (RS_U7
        // when only two profiles are mounted now). One that cannot be unloaded is reported by name and kept in Mounted:
        // retried on rescan / exit, and never used as a target. Nothing is touched while another instance holds the
        // mount role (they are its mounts).
        internal void CleanupStale(StringBuilder warn)
        {
            string[] names;
            try { names = hklmNames(); } catch { return; }
            foreach (string n in names)
            {
                if (!IsOurName(n) || Has(n)) continue;
                if (otherInstance()) return;
                string why = Unload(n, warn);
                if (why == null) warn.Append("выгружен старый HKLM\\" + n + " (от прошлого запуска). ");
                else { warn.Append("HKLM\\" + n + " остался от прошлого запуска и не выгружается" + why + ". "); Mounted.Add(n); }
            }
        }

        // Mounts 'file' at HKLM\<name>: 0 = mounted, 1 = failed, 2 = the name is held (another instance has the mount role,
        // or an old mount there cannot be unloaded). A failed mount is never pretended to have worked.
        internal int Mount(string name, string file, StringBuilder warn)
        {
            string p = "HKLM\\" + name, o;
            if (otherInstance())
            {
                if (warn.ToString().IndexOf(OtherInstanceMsg, StringComparison.Ordinal) < 0) warn.Append(OtherInstanceMsg);
                return 2;
            }
            if (!fileExists(file)) { warn.Append("нет файла " + file + ". "); return 1; }   // reg load would CREATE an empty hive
            if (keyExists(p))
            {
                string why = Unload(name, warn);
                if (why != null)
                {
                    warn.Append(p + " занят старым монтированием (прошлый запуск? regedit?) и не выгружается" + why + ". ");
                    if (!Has(name)) Mounted.Add(name);   // retried on rescan / exit
                    return 2;
                }
                Mounted.RemoveAll(delegate(string m) { return m.Equals(name, StringComparison.OrdinalIgnoreCase); });
                warn.Append("выгружен старый " + p + ". ");
            }
            int rc = reg("load " + Reg.QuoteArg(p) + " " + Reg.QuoteArg(file), out o);
            if (rc != 0 || !keyExists(p)) { warn.Append("не смонтирован " + file + Why(rc, o, warn) + ". "); return 1; }
            Mounted.Add(name);
            return 0;
        }

        // Mounts a user hive at the next free HKLM\RS_U<n> (names held by a stale mount are skipped). Returns the root, or
        // "" and counts it in 'failed' (also when all MaxUserMounts names are used up: never silently unscanned).
        internal string MountUser(string file, StringBuilder warn, ref int next, ref int failed)
        {
            while (next < MaxUserMounts)
            {
                string name = "RS_U" + next++;
                if (Has(name) || keyExists("HKLM\\" + name)) continue;
                if (Mount(name, file, warn) == 0) return "HKLM\\" + name;
                failed++;
                return "";
            }
            failed++;
            return "";
        }

        // Unloads everything in Mounted. "" = all gone; else a Russian description of what stays mounted (kept in Mounted:
        // retried on the next rescan and on exit).
        internal string UnloadAll()
        {
            if (Mounted.Count == 0) return "";
            GC.Collect(); GC.WaitForPendingFinalizers();   // a leaked RegistryKey handle into a hive would block the unload
            List<string> still = new List<string>();
            StringBuilder notes = new StringBuilder();   // e.g. the DisableRegistryTools hint, once
            string first = "";
            foreach (string m in Mounted)
            {
                string w = Unload(m, notes);
                if (w == null) continue;
                still.Add(m);
                if (first.Length == 0) first = w;
            }
            Mounted.Clear(); Mounted.AddRange(still);
            if (still.Count == 0) return "";
            return "не выгружено: HKLM\\" + string.Join(", HKLM\\", still.ToArray()) + first + " (закрой regedit и повтори)"
                + (notes.Length > 0 ? ". " + notes.ToString().Trim() : "");
        }
    }

    // One value of a registry backup: raw type + bytes, or Delete = "the value did not exist" (restore deletes it).
    class RegVal
    {
        public string Name = "";
        public int Type;
        public byte[] Data;
        public bool Delete;
    }

    // One key of a registry backup (full path) with its values.
    class RegSection
    {
        public string Path;
        public readonly List<RegVal> Values = new List<RegVal>();
        public RegSection(string path) { Path = path; }
    }

    // Our own exact .reg writer and a parser for what it writes (also regedit's REGEDIT5 output): UTF-16LE + BOM,
    // "Windows Registry Editor Version 5.00", @ = default value, "..." only for REG_SZ that round-trips as text,
    // dword:xxxxxxxx, hex:, hex(N): for everything else (hex(2) expand, hex(7) multi, hex(b) qword, hex(0) none ...),
    // "name"=- for a value that did not exist. Never shells out to reg.exe (whose export depends on reg.exe working
    // and on its own file naming).
    static class RegFile
    {
        internal const string Header = "Windows Registry Editor Version 5.00";

        internal static string Esc(string s) { return s.Replace("\\", "\\\\").Replace("\"", "\\\""); }

        static bool Printable(string s) { return s.IndexOf('\0') < 0 && s.IndexOf('\r') < 0 && s.IndexOf('\n') < 0; }

        // The whole file text, or null + err when something cannot be written faithfully (a name with CR/LF/NUL).
        internal static string Format(List<RegSection> secs, out string err)
        {
            err = "";
            StringBuilder sb = new StringBuilder();
            sb.Append(Header).Append("\r\n");
            foreach (RegSection s in secs)
            {
                if (s.Path == null || !Printable(s.Path) || s.Path.Length == 0) { err = "имя ключа не записать в .reg"; return null; }
                sb.Append("\r\n[").Append(s.Path).Append("]\r\n");
                foreach (RegVal v in s.Values)
                {
                    string line = ValueLine(v);
                    if (line == null) { err = "имя значения не записать в .reg: " + Reg.OneLine(v.Name, 60); return null; }
                    sb.Append(line).Append("\r\n");
                }
            }
            sb.Append("\r\n");
            return sb.ToString();
        }

        internal static string ValueLine(RegVal v)
        {
            if (v.Name == null || !Printable(v.Name)) return null;
            string name = v.Name.Length == 0 ? "@" : "\"" + Esc(v.Name) + "\"";
            if (v.Delete) return name + "=-";
            byte[] d = v.Data ?? new byte[0];
            if (v.Type == 1 && d.Length >= 2 && d.Length % 2 == 0 && d[d.Length - 1] == 0 && d[d.Length - 2] == 0)
            {
                string t = Encoding.Unicode.GetString(d, 0, d.Length - 2);
                if (Printable(t)) return name + "=\"" + Esc(t) + "\"";
            }
            if (v.Type == 4 && d.Length == 4) return name + "=dword:" + BitConverter.ToUInt32(d, 0).ToString("x8");
            string pre = name + "=" + (v.Type == 3 ? "hex:" : "hex(" + ((uint)v.Type).ToString("x") + "):");
            StringBuilder sb = new StringBuilder(pre);
            int col = pre.Length;
            for (int i = 0; i < d.Length; i++)
            {
                if (col > 76) { sb.Append("\\\r\n  "); col = 2; }   // regedit-style continuation lines
                sb.Append(d[i].ToString("x2"));
                col += 2;
                if (i < d.Length - 1) { sb.Append(','); col++; }
            }
            return sb.ToString();
        }

        // Parses a .reg text (REGEDIT5). null + err on anything it does not understand: a backup that cannot be read
        // exactly is not restored half-way.
        internal static List<RegSection> Parse(string text, out string err)
        {
            err = "";
            List<RegSection> res = new List<RegSection>();
            if (text == null) { err = "пустой файл"; return null; }
            if (text.Length > 0 && text[0] == '\uFEFF') text = text.Substring(1);
            List<string> lines = new List<string>();
            StringBuilder cur = null;
            foreach (string raw in text.Replace("\r\n", "\n").Split('\n'))
            {
                string l = cur != null ? raw.TrimStart() : raw;
                if (cur == null) cur = new StringBuilder();
                if (l.EndsWith("\\") && IsHexLine(cur.ToString() + l)) { cur.Append(l.Substring(0, l.Length - 1)); continue; }
                cur.Append(l);
                lines.Add(cur.ToString());
                cur = null;
            }
            if (cur != null) lines.Add(cur.ToString());
            bool header = false;
            RegSection sec = null;
            foreach (string l0 in lines)
            {
                string l = l0.TrimEnd();
                if (l.Trim().Length == 0 || l.TrimStart().StartsWith(";")) continue;
                if (!header) { if (l.Trim() != Header) { err = "нет заголовка «" + Header + "»"; return null; } header = true; continue; }
                if (l.StartsWith("["))
                {
                    int e = l.LastIndexOf(']');
                    if (e < 2 || l.StartsWith("[-")) { err = "строка ключа не понята: " + Reg.OneLine(l, 80); return null; }
                    sec = new RegSection(l.Substring(1, e - 1));
                    res.Add(sec);
                    continue;
                }
                if (sec == null) { err = "значение вне ключа"; return null; }
                RegVal v = ParseValue(l, out err);
                if (v == null) return null;
                sec.Values.Add(v);
            }
            if (!header) { err = "нет заголовка «" + Header + "»"; return null; }
            return res;
        }

        // a line that continues with "\" is a hex list ("=hex"); a quoted string that ends with \ is not continued
        static bool IsHexLine(string l)
        {
            int q = NameEnd(l);
            return q > 0 && q < l.Length && l[q] == '=' && l.Substring(q + 1).StartsWith("hex", StringComparison.OrdinalIgnoreCase);
        }

        // index just after the name part ("..." or @), or -1
        static int NameEnd(string l)
        {
            if (l.StartsWith("@")) return 1;
            if (!l.StartsWith("\"")) return -1;
            for (int i = 1; i < l.Length; i++)
            {
                if (l[i] == '\\') { i++; continue; }
                if (l[i] == '"') return i + 1;
            }
            return -1;
        }

        static string Unesc(string s, out bool ok)
        {
            ok = true;
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < s.Length; i++)
            {
                if (s[i] == '\\')
                {
                    if (i + 1 >= s.Length) { ok = false; break; }
                    char c = s[++i];
                    if (c != '\\' && c != '"') { ok = false; break; }
                    sb.Append(c);
                }
                else if (s[i] == '"') { ok = false; break; }
                else sb.Append(s[i]);
            }
            return sb.ToString();
        }

        static RegVal ParseValue(string l, out string err)
        {
            err = "";
            int ne = NameEnd(l);
            if (ne < 0 || ne >= l.Length || l[ne] != '=') { err = "строка значения не понята: " + Reg.OneLine(l, 80); return null; }
            RegVal v = new RegVal();
            bool ok = true;
            v.Name = l[0] == '@' ? "" : Unesc(l.Substring(1, ne - 2), out ok);
            if (!ok) { err = "имя значения не понято: " + Reg.OneLine(l, 80); return null; }
            string d = l.Substring(ne + 1).Trim();
            if (d == "-") { v.Delete = true; return v; }
            if (d.StartsWith("\"") && d.EndsWith("\"") && d.Length >= 2)
            {
                string t = Unesc(d.Substring(1, d.Length - 2), out ok);
                if (!ok) { err = "строка не понята: " + Reg.OneLine(l, 80); return null; }
                v.Type = 1; v.Data = Encoding.Unicode.GetBytes(t + "\0");
                return v;
            }
            if (d.StartsWith("dword:", StringComparison.OrdinalIgnoreCase))
            {
                uint n;
                if (d.Length != 14 || !uint.TryParse(d.Substring(6), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out n))
                { err = "dword не понят: " + Reg.OneLine(l, 80); return null; }
                v.Type = 4; v.Data = BitConverter.GetBytes(n);
                return v;
            }
            int type; string list;
            if (d.StartsWith("hex:", StringComparison.OrdinalIgnoreCase)) { type = 3; list = d.Substring(4); }
            else if (d.StartsWith("hex(", StringComparison.OrdinalIgnoreCase) && d.IndexOf("):") > 4)
            {
                int c = d.IndexOf("):");
                uint t;
                if (!uint.TryParse(d.Substring(4, c - 4), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out t))
                { err = "тип не понят: " + Reg.OneLine(l, 80); return null; }
                type = (int)t; list = d.Substring(c + 2);
            }
            else { err = "данные не поняты: " + Reg.OneLine(l, 80); return null; }
            List<byte> bytes = new List<byte>();
            foreach (string p in list.Split(','))
            {
                string h = p.Trim();
                if (h.Length == 0 && list.Trim().Length == 0) break;
                byte b;
                if (h.Length != 2 || !byte.TryParse(h, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out b))
                { err = "байты не поняты: " + Reg.OneLine(l, 80); return null; }
                bytes.Add(b);
            }
            v.Type = type; v.Data = bytes.ToArray();
            return v;
        }
    }

    // Windows defaults and "is this the default / a legitimate Microsoft form" predicates for the values that must be
    // RESET, never deleted (Winlogon Shell/Userinit/VMApplet, BootExecute, SetupExecute, SafeBoot AlternateShell).
    // Sources: research windows-semantics Q1/Q2 (defaults observed on Win7 SP1 / Win10 / Server 2016-2022; KB Q160963).
    static class Defaults
    {
        internal const string Shell = "explorer.exe";
        internal const string VmApplet = "SystemPropertiesPerformance.exe /pagefile";
        internal const string AlternateShell = "cmd.exe";
        internal const string BootExecute = "autocheck autochk *";

        // <SystemRoot>\system32\userinit.exe,  (the trailing comma is the Microsoft default form)
        internal static string Userinit(string systemRoot)
        {
            return (string.IsNullOrEmpty(systemRoot) ? "C:\\Windows" : systemRoot.TrimEnd('\\')) + "\\system32\\userinit.exe,";
        }

        // The target's own %SystemRoot% as Windows sees it when it boots: offline the SOFTWARE value
        // ...\Windows NT\CurrentVersion\SystemRoot (the drive letter of the installation, not WinPE's letter for that
        // volume); live the running system's directory. Fallback: C: + the folder of the selected installation.
        internal static string SystemRootFor(string regValue, bool live, string runWinDir, string tgtWinDir)
        {
            if (live && !string.IsNullOrEmpty(runWinDir)) return runWinDir.TrimEnd('\\');
            string v = (regValue ?? "").Trim().TrimEnd('\\');
            if (v.Length >= 4 && char.IsLetter(v[0]) && v[1] == ':' && v[2] == '\\' && v.IndexOf('%') < 0 && v.IndexOf('"') < 0) return v;
            if (!string.IsNullOrEmpty(tgtWinDir) && tgtWinDir.Length >= 3) return "C:" + tgtWinDir.Substring(2).TrimEnd('\\');
            return "C:\\Windows";
        }

        // Clean iff, after splitting on ',' (trimmed, empty parts dropped), there is exactly ONE program and it is
        // <SystemRoot>\system32\userinit.exe or plain userinit.exe / userinit. systemRoot "" = unknown: any
        // <letter>:\Windows\system32\userinit.exe is accepted.
        internal static bool UserinitClean(string data, string systemRoot)
        {
            List<string> parts = new List<string>();
            foreach (string p in (data ?? "").Split(',')) if (p.Trim().Length > 0) parts.Add(p.Trim());
            if (parts.Count != 1) return false;
            string x = parts[0];
            if (x.Equals("userinit.exe", StringComparison.OrdinalIgnoreCase) || x.Equals("userinit", StringComparison.OrdinalIgnoreCase)) return true;
            if (!string.IsNullOrEmpty(systemRoot)) return x.Equals(systemRoot.TrimEnd('\\') + "\\system32\\userinit.exe", StringComparison.OrdinalIgnoreCase);
            return x.Length > 3 && char.IsLetter(x[0]) && x.Substring(1).Equals(":\\Windows\\system32\\userinit.exe", StringComparison.OrdinalIgnoreCase);
        }

        // Clean iff explorer.exe or <SystemRoot>\explorer.exe.
        internal static bool ShellClean(string data, string systemRoot)
        {
            string x = (data ?? "").Trim();
            if (x.Equals(Shell, StringComparison.OrdinalIgnoreCase)) return true;
            return !string.IsNullOrEmpty(systemRoot) && x.Equals(systemRoot.TrimEnd('\\') + "\\explorer.exe", StringComparison.OrdinalIgnoreCase);
        }

        // VMApplet: the Win7-11 default and the W2K/XP one.
        internal static bool VmAppletClean(string data)
        {
            string x = string.Join(" ", (data ?? "").Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries));
            return x.Equals(VmApplet, StringComparison.OrdinalIgnoreCase)
                || x.Equals("rundll32 shell32,Control_RunDLL \"sysdm.cpl\"", StringComparison.OrdinalIgnoreCase);
        }

        internal static bool AlternateShellClean(string data) { return (data ?? "").Trim().Equals(AlternateShell, StringComparison.OrdinalIgnoreCase); }

        // One BootExecute entry written by Windows itself: "autocheck autochk" + only the documented switches
        // (/k:<letters> from chkntfs /x; /r, /m, /p followed by \??\X: or \??\Volume{guid} from a scheduled chkdsk;
        // /q, /v) and an optional "*" (all volumes). Anything else (another native program, extra arguments) is not.
        internal static bool AutochkLine(string entry)
        {
            string[] t = (entry ?? "").Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (t.Length < 2 || !t[0].Equals("autocheck", StringComparison.OrdinalIgnoreCase) || !t[1].Equals("autochk", StringComparison.OrdinalIgnoreCase)) return false;
            for (int i = 2; i < t.Length; i++)
            {
                string a = t[i].ToLowerInvariant();
                if (a == "*" || a == "/q" || a == "/v" || NtVolume(a)) continue;
                if (a.StartsWith("/k:") && a.Length > 3)
                {
                    for (int j = 3; j < a.Length; j++) if (a[j] < 'a' || a[j] > 'z') return false;
                    continue;
                }
                if ((a == "/r" || a == "/m" || a == "/p") && i + 1 < t.Length && NtVolume(t[i + 1].ToLowerInvariant())) { i++; continue; }
                return false;
            }
            return true;
        }

        // \??\C:  or  \??\Volume{8-4-4-4-12 hex}
        static bool NtVolume(string a)
        {
            if (!a.StartsWith("\\??\\")) return false;
            string v = a.Substring(4);
            if (v.Length == 2 && v[0] >= 'a' && v[0] <= 'z' && v[1] == ':') return true;
            if (!v.StartsWith("volume{") || !v.EndsWith("}") || v.Length != 44) return false;
            for (int i = 7; i < 43; i++)
            {
                char c = v[i];
                bool dash = i == 15 || i == 20 || i == 25 || i == 30;
                if (dash ? c != '-' : !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
            }
            return true;
        }

        // What BootExecute is reset to: the legitimate autochk lines that are there, plus the default
        // "autocheck autochk *" when no kept line covers all volumes.
        internal static string[] BootExecuteRepair(string[] entries)
        {
            List<string> keep = new List<string>();
            bool star = false;
            foreach (string e in entries ?? new string[0])
                if (AutochkLine(e))
                {
                    keep.Add(e.Trim());
                    if (Array.IndexOf(e.Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries), "*") >= 0) star = true;
                }
            if (!star) keep.Add(BootExecute);
            return keep.ToArray();
        }

        // A SetupExecute entry of pending Windows servicing: poqexec.exe (bare, \SystemRoot\System32\ or
        // <X>:\Windows\System32\) whose other arguments are switches or ...\WinSxS\pending.xml.
        internal static bool ServicingEntry(string entry)
        {
            string[] t = (entry ?? "").Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (t.Length == 0) return false;
            string exe = t[0].ToLowerInvariant();
            int slash = exe.LastIndexOf('\\');
            string dir = slash < 0 ? "" : exe.Substring(0, slash), name = exe.Substring(slash + 1);
            if (name != "poqexec.exe" && name != "poqexec") return false;
            if (dir.Length > 0 && dir != "\\systemroot\\system32" && !(dir.Length == 19 && dir[1] == ':' && dir.Substring(2) == "\\windows\\system32")) return false;
            for (int i = 1; i < t.Length; i++)
            {
                string a = t[i].ToLowerInvariant();
                if (a.StartsWith("/") && a.IndexOf('\\') < 0 && a.IndexOf(':') < 0) continue;
                if (a.EndsWith("\\winsxs\\pending.xml") && (a.StartsWith("\\systemroot\\") || (a.Length > 3 && a[1] == ':' && a[2] == '\\'))) continue;
                return false;
            }
            return true;
        }

        // IFEO Debugger values set by legitimate tools (research windows-semantics Q7): Process Explorer / System
        // Informer / Process Hacker replacing Task Manager, Notepad++ replacing Notepad, and the Microsoft debuggers.
        // Those are REVIEW (shown, never cleared by the blanket unlock); everything else is SUSPECT.
        internal static bool IfeoKnownDebugger(string exe, string debugger)
        {
            string img = ImageName(debugger);
            string e = (exe ?? "").ToLowerInvariant();
            if (img == "vsjitdebugger.exe" || img == "windbg.exe" || img == "windbgx.exe" || img == "cdb.exe" || img == "ntsd.exe") return true;
            if (e == "taskmgr.exe" && (img == "procexp.exe" || img == "procexp64.exe" || img == "procexp64a.exe" || img == "systeminformer.exe" || img == "processhacker.exe")) return true;
            if (e == "notepad.exe" && img == "notepad++.exe") return true;
            return false;
        }

        // Microsoft's own Active Setup components (Windows 7-11, Edge): GUID -> program -> a marker the StubPath must
        // contain. Themes Setup / Desktop Update use "regsvr32 /i:", the icon-cache one "cmd /D /C start ie4uinit".
        static readonly string[] ActiveSetupMs = {
            "{2c7339cf-2b09-4501-b3f3-f3508c9228ed}", "regsvr32.exe", "themeui.dll",
            "{89820200-ecbd-11cf-8b85-00aa005b4340}", "regsvr32.exe", "shell32.dll",
            "{2d46b6dc-2207-486b-b523-a557e6d54b47}", "cmd.exe", "ie4uinit.exe",
            "{26923b43-4d38-484f-9b9e-de460746276c}", "ie4uinit.exe", "ie4uinit.exe",
            "{89b4c1cd-b018-4511-b0a1-5476dbf70820}", "rundll32.exe", "mscories.dll",
            "{6bf52a52-394a-11d3-b153-00c04f79faa6}", "unregmp2.exe", "unregmp2.exe",
            "{22d6f312-b0f6-11d0-94ab-0080c74c7e95}", "unregmp2.exe", "unregmp2.exe",
            "{a509b1a7-37ef-4b3f-8cfc-4f3a74704073}", "rundll32.exe", "iesetup.dll",
            "{a509b1a8-37ef-4b3f-8cfc-4f3a74704073}", "rundll32.exe", "iesetup.dll",
            "{44bba840-cc51-11cf-aafa-00aa00b6015c}", "winmail.exe", "winmail.exe",
            "{9459c573-b17a-45ae-9f64-1857b5d58cee}", "setup.exe", "\\microsoft\\edge\\application\\",
        };

        // A built-in Active Setup StubPath (not even REVIEW): known GUID (a leading '<' / '>' ordering mark is
        // ignored), the expected program from System32 / SysWOW64 / Program Files (or a bare name), the expected DLL /
        // tool, nothing chained (& |) and nothing Risk() calls SUSPECT.
        internal static bool ActiveSetupClean(string guid, string stub)
        {
            string g = (guid ?? "").Trim().TrimStart('<', '>').ToLowerInvariant();
            string st = stub ?? "";
            if (st.IndexOf('&') >= 0 || st.IndexOf('|') >= 0 || st.IndexOf('>') >= 0) return false;
            if (Heur.Risk(st, true) == "SUSPECT") return false;
            string p = Heur.NormPath(st);
            List<string> t = Heur.Tokens(p);
            if (t.Count == 0) return false;
            string first = t[0];
            string nod = (first.Length >= 2 && first[1] == ':' ? first.Substring(2) : first).TrimStart('\\');
            bool dirOk = first.IndexOf('\\') < 0 || Heur.SysDir(first) || nod.StartsWith("program files\\") || nod.StartsWith("program files (x86)\\");
            for (int i = 0; i < ActiveSetupMs.Length; i += 3)
                if (g == ActiveSetupMs[i])
                    return dirOk && ImageName(st) == ActiveSetupMs[i + 1] && p.Contains(ActiveSetupMs[i + 2]);
            return false;
        }

        // file name (lower case) of the program a command line starts: "C:\x y\a.exe" -b  ->  a.exe
        internal static string ImageName(string cmd)
        {
            string c = (cmd ?? "").Trim();
            string first;
            if (c.StartsWith("\"")) { int q = c.IndexOf('"', 1); first = q > 0 ? c.Substring(1, q - 1) : c.Substring(1); }
            else
            {
                int ex = c.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);   // unquoted path with spaces
                int sp = c.IndexOf(' ');
                first = ex > 0 && (sp < 0 || ex < c.Length) ? c.Substring(0, Math.Min(c.Length, ex + 4)) : (sp > 0 ? c.Substring(0, sp) : c);
            }
            first = first.Trim();
            return first.Substring(first.LastIndexOfAny(new char[] { '\\', '/' }) + 1).ToLowerInvariant();
        }
    }

    // ================= detection heuristics (pure: no registry / file access; unit-tested) =================
    static class Heur
    {
        // Environment-variable spellings and 8.3 short names -> the folder they stand for (applied to the lower-case
        // text after '/' -> '\'), so %TMP%\x.exe, C:/Windows/Temp/x.exe and C:\PROGRA~3\x.exe are judged like the
        // literal long paths. Order matters (%programfiles(x86)% before %programfiles%).
        static readonly string[] EnvMap = {
            "%tmp%", "\\temp", "%temp%", "\\temp", "%localappdata%", "\\appdata\\local", "%appdata%", "\\appdata\\roaming",
            "%userprofile%", "\\users\\~user", "%homepath%", "\\users\\~user", "%public%", "\\users\\public",
            "%programdata%", "\\programdata", "%allusersprofile%", "\\programdata", "%systemroot%", "\\windows",
            "%windir%", "\\windows", "%systemdrive%", "", "%programfiles(x86)%", "\\program files (x86)",
            "%programw6432%", "\\program files", "%programfiles%", "\\program files",
            "%commonprogramfiles%", "\\program files\\common files",
            "\\appdat~1\\", "\\appdata\\", "\\locals~1\\", "\\appdata\\local\\", "\\progra~3\\", "\\programdata\\",
            "\\docume~1\\", "\\users\\", "\\temp~1\\", "\\temp\\" };

        // lower case, cmd carets removed, '/' -> '\', environment variables / short names mapped (see EnvMap);
        // "\SystemRoot\" and "\??\" prefixes of service image paths too.
        internal static string NormPath(string s)
        {
            string p = (s ?? "").ToLowerInvariant().Replace("^", "").Replace('/', '\\');
            for (int i = 0; i < EnvMap.Length; i += 2) p = p.Replace(EnvMap[i], EnvMap[i + 1]);
            p = p.Replace("\\??\\", "");
            if (p.StartsWith("\\systemroot\\")) p = "\\windows\\" + p.Substring(12);
            return p.Replace("\\systemroot\\", "\\windows\\");
        }

        // Command-line tokens: whitespace separated, a "..." run keeps its spaces (quotes removed).
        internal static List<string> Tokens(string s)
        {
            List<string> res = new List<string>();
            if (s == null) return res;
            StringBuilder cur = new StringBuilder();
            bool q = false, any = false;
            foreach (char c in s)
            {
                if (c == '"') { q = !q; any = true; continue; }
                if (!q && char.IsWhiteSpace(c)) { if (any) res.Add(cur.ToString()); cur.Length = 0; any = false; continue; }
                cur.Append(c); any = true;
            }
            if (any) res.Add(cur.ToString());
            return res;
        }

        static bool Sep(char c) { return char.IsWhiteSpace(c) || c == '"' || c == '\'' || c == '\\' || c == ',' || c == ';' || c == '&' || c == '|' || c == '(' || c == ')' || c == '='; }

        // 'name' (or name.exe) as a whole program name in the lower-case text l: "...\powershell.exe -c", "cmd /c".
        internal static bool Word(string l, string name)
        {
            int i = 0;
            while ((i = l.IndexOf(name, i, StringComparison.Ordinal)) >= 0)
            {
                int e = i + name.Length;
                if (e + 4 <= l.Length && string.CompareOrdinal(l, e, ".exe", 0, 4) == 0) e += 4;
                bool before = i == 0 || Sep(l[i - 1]);
                bool after = e == l.Length || (Sep(l[e]) && l[e] != '\\' && l[e] != '=');
                if (before && after) return true;
                i++;
            }
            return false;
        }

        // the text ends a file name with this extension at position i (next char is the end, a quote, space, comma ...)
        internal static bool HasExt(string l, string ext)
        {
            int i = 0;
            while ((i = l.IndexOf(ext, i, StringComparison.Ordinal)) >= 0)
            {
                int e = i + ext.Length;
                if (e == l.Length || char.IsWhiteSpace(l[e]) || l[e] == '"' || l[e] == '\'' || l[e] == ',' || l[e] == ';' || l[e] == ')') return true;
                i++;
            }
            return false;
        }

        // A path (normalised, any drive) inside the Windows system folders: \Windows\System32\..., \Windows\SysWOW64\...
        internal static bool SysDir(string tok)
        {
            string t = (tok ?? "").Trim().Trim('"', '\'');
            if ((t.StartsWith("-") || t.StartsWith("\\")) && t.IndexOf(':') > 0 && t.IndexOf(':') < 24 && !(t.Length > 1 && t[1] == ':'))
            {
                int c = t.IndexOf(':');   // "-file:c:\x.ps1" / "/i:x" -> the part after the switch
                if (c + 1 < t.Length && (char.IsLetter(t[c + 1]) || t[c + 1] == '\\')) t = t.Substring(c + 1);
            }
            if (t.Length >= 2 && t[1] == ':') t = t.Substring(2);
            t = t.TrimStart('\\');
            return t.StartsWith("windows\\system32\\") || t.StartsWith("windows\\syswow64\\") || t.StartsWith("windows\\sysnative\\")
                || t.StartsWith("system32\\");
        }

        static bool ProgDir(string t)
        {
            string x = (t ?? "").Trim().Trim('"');
            if (x.Length >= 2 && x[1] == ':') x = x.Substring(2);
            x = x.TrimStart('\\');
            return x.StartsWith("program files\\") || x.StartsWith("program files (x86)\\");
        }

        // a path with a folder (not a bare "shell32.dll") that is not System32/SysWOW64/Program Files
        static bool OddDll(string t)
        {
            string x = (t ?? "").Trim().Trim('"');
            if (x.IndexOf('\\') < 0) return false;   // bare name: loaded from System32
            return !SysDir(x) && !ProgDir(x);
        }

        static readonly string[] ScriptExt = { ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".ps1", ".psm1" };
        static readonly string[] AlwaysBadScript = { ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta" };   // Windows never autostarts these
        // scripts Windows itself starts (built-in tasks): not even REVIEW
        static readonly string[] CleanScripts = { "\\windows\\system32\\gathernetworkinfo.vbs" };

        // The PowerShell switch name 'n' (without the dash) abbreviates 'full' (PowerShell accepts any unique prefix).
        static bool Abbrev(string n, string full, int min) { return n.Length >= min && full.StartsWith(n, StringComparison.Ordinal); }

        // "SUSPECT" (red) / "REVIEW" (yellow) / "" for an autostart command line (command = true) or a bare file path
        // (command = false: Explorer listing, process image; no command-line rules).
        internal static string Risk(string s, bool command)
        {
            if (string.IsNullOrEmpty(s)) return "";
            string l = s.ToLowerInvariant().Replace("^", "");   // raw (switches, URLs)
            string p = NormPath(s);                            // paths
            bool review = false;
            // ---- strong path / name indicators ----
            string[] strongPath = { "\\temp\\", "\\tmp\\", "\\$recycle.bin\\", "\\recycler\\", "\\system volume information\\" };
            foreach (string b in strongPath) if (p.Contains(b)) return "SUSPECT";
            string[] dbl = { ".txt.exe", ".pdf.exe", ".doc.exe", ".docx.exe", ".xls.exe", ".xlsx.exe", ".jpg.exe", ".jpeg.exe", ".png.exe",
                ".mp3.exe", ".mp4.exe", ".avi.exe", ".zip.exe", ".rar.exe", ".scr.exe", ".pdf.scr", ".doc.scr", ".jpg.scr" };
            foreach (string b in dbl) if (l.Contains(b)) return "SUSPECT";
            if (HasExt(p, ".pif")) return "SUSPECT";
            List<string> toks = Tokens(p);
            if (!command) toks = new List<string>(new string[] { p.Trim().Trim('"') });
            foreach (string t in toks)
            {
                string x = t.TrimEnd(',', ';', ')');
                if (x.EndsWith(".scr") && !SysDir(x)) return "SUSPECT";   // a screensaver outside System32 / SysWOW64
            }
            string[] soft = { "\\appdata\\", "\\programdata\\", "\\downloads\\", "\\users\\", "\\public\\" };
            foreach (string b in soft) if (p.Contains(b)) { review = true; break; }
            if (!command) return review ? "REVIEW" : "";

            // ---- command line ----
            string[] strong = { "frombase64string", "invoke-expression", "downloadstring", "downloadfile", "downloaddata", "net.webclient",
                "javascript:", "vbscript:", "scrobj.dll", "/i:http", "/i:ftp", "-encodedcommand", "-windowstyle hidden", "start-bitstransfer",
                "invoke-webrequest", "invoke-restmethod", "iex(", "iex (" };
            foreach (string b in strong) if (l.Contains(b)) return "SUSPECT";
            if (HasExt(l, ".sct")) return "SUSPECT";
            bool http = l.Contains("http:") || l.Contains("https:") || l.Contains("ftp:") || (l.Contains("\\\\") && !l.Contains("\\\\?\\"));   // URL / UNC share
            bool userPath = p.Contains("\\appdata\\") || p.Contains("\\users\\") || p.Contains("\\programdata\\");
            // PowerShell: any unique prefix of a switch works (-e/-ec/-enc = EncodedCommand, -w/-win = WindowStyle)
            bool ps = Word(l, "powershell") || Word(l, "pwsh") || Word(l, "powershell_ise");
            if (ps)
            {
                review = true;
                List<string> lt = Tokens(l);
                for (int i = 0; i < lt.Count; i++)
                {
                    string t = lt[i];
                    if (Word(t, "iex") || t == "iex" || t.EndsWith("|iex") || t == "iwr" || t == "irm" || t.StartsWith("iwr(") || t == "|iex") return "SUSPECT";
                    if (t.Length < 2 || (t[0] != '-' && t[0] != '/' && t[0] != '\u2013')) continue;
                    string n = t.Substring(1), v = null;
                    int c = n.IndexOf(':');
                    if (c >= 0) { v = n.Substring(c + 1); n = n.Substring(0, c); }
                    if (Abbrev(n, "encodedcommand", 1) || n == "ec" || Abbrev(n, "encodedarguments", 8)) return "SUSPECT";
                    if (Abbrev(n, "windowstyle", 1))
                    {
                        if (v == null && i + 1 < lt.Count) v = lt[i + 1];
                        v = (v ?? "").Trim('"', '\'');
                        if (v == "1" || (v.Length >= 3 && "hidden".StartsWith(v, StringComparison.Ordinal))) return "SUSPECT";
                    }
                }
                if (http || userPath) return "SUSPECT";
            }
            // script hosts / LOLBins that have no business in an autostart
            string[] lol = { "mshta", "cmstp", "installutil", "regasm", "regsvcs", "msbuild", "forfiles", "pcalua", "msxsl", "odbcconf", "syncappvpublishingserver" };
            foreach (string b in lol) if (Word(l, b)) return "SUSPECT";
            if (Word(l, "conhost") && l.Contains("--headless")) return "SUSPECT";
            if (Word(l, "wmic") && (l.Contains("call create") || l.Contains("/format:"))) return "SUSPECT";
            if ((Word(l, "curl") || Word(l, "wget") || Word(l, "msiexec") || Word(l, "bitsadmin") || Word(l, "certutil")) && http) return "SUSPECT";
            if (Word(l, "certutil") && (l.Contains("-urlcache") || l.Contains("-decode") || l.Contains("/urlcache") || l.Contains("/decode"))) return "SUSPECT";
            if (Word(l, "bitsadmin") && (l.Contains("/transfer") || l.Contains("/addfile") || l.Contains("/setnotifycmdline"))) return "SUSPECT";
            bool wsh = Word(l, "wscript") || Word(l, "cscript");
            if (wsh) { review = true; if (http || userPath) return "SUSPECT"; }
            bool cmd = Word(l, "cmd") || l.Contains("%comspec%");
            if (cmd) review = true;
            // rundll32 / regsvr32: the DLL must be a bare name or live in System32 / SysWOW64 / Program Files
            if (Word(l, "rundll32") || Word(l, "regsvr32"))
            {
                if (http) return "SUSPECT";
                bool after = false;
                foreach (string t in Tokens(l))   // raw tokens: "/d", "/s", "/i:/UserInstall" are switches
                {
                    if (!after) { if (Word(t, "rundll32") || Word(t, "regsvr32")) after = true; continue; }
                    if (t.Length == 0 || t.StartsWith("-") || (t.StartsWith("/") && t.IndexOf('\\') < 0)) continue;
                    string dll = NormPath(t); int cm = dll.IndexOf(','); if (cm >= 0) dll = dll.Substring(0, cm);
                    if (OddDll(dll)) return "SUSPECT";
                    break;
                }
            }
            // a script as the program (or as the argument of cmd / wscript / cscript / powershell -file)
            foreach (string t in toks)
            {
                string x = t.TrimEnd(',', ';', ')');
                foreach (string e in ScriptExt)
                {
                    if (!x.EndsWith(e)) continue;
                    bool clean = false;
                    foreach (string c in CleanScripts) if (x.EndsWith(c) && SysDir(x)) clean = true;
                    if (clean) break;
                    if (Array.IndexOf(AlwaysBadScript, e) >= 0) return "SUSPECT";
                    if (SysDir(x) || ProgDir(x)) { review = true; break; }
                    return "SUSPECT";
                }
            }
            if (http && (ps || wsh || cmd)) return "SUSPECT";
            return review ? "REVIEW" : "";
        }

        // ---- scheduled tasks ----
        // "SUSPECT" > "REVIEW" > ""
        internal static string Max(string a, string b)
        {
            if (a == "SUSPECT" || b == "SUSPECT") return "SUSPECT";
            if (a == "REVIEW" || b == "REVIEW") return "REVIEW";
            return "";
        }

        const RegexOptions RxOpt = RegexOptions.Singleline | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;
        static readonly Regex XmlComment = new Regex("<!--.*?-->", RegexOptions.Singleline);
        static readonly Regex ExecRx = new Regex(@"<(?:[\w.-]+:)?Exec(?:\s[^>]*)?>(.*?)</(?:[\w.-]+:)?Exec\s*>", RxOpt);
        static readonly Regex ComRx = new Regex(@"<(?:[\w.-]+:)?ComHandler(?:\s[^>]*)?>(.*?)</(?:[\w.-]+:)?ComHandler\s*>", RxOpt);

        static string Inner(string body, string tag)
        {
            Match m = Regex.Match(body, @"<(?:[\w.-]+:)?" + tag + @"(?:\s[^>]*)?>(.*?)</(?:[\w.-]+:)?" + tag + @"\s*>", RxOpt);
            return m.Success ? XmlText(m.Groups[1].Value).Trim() : "";
        }

        // XML character data -> text: CDATA sections kept verbatim, entities (&lt; &amp; &#101; &#x65; ...) decoded.
        internal static string XmlText(string s)
        {
            StringBuilder sb = new StringBuilder();
            int i = 0;
            while (i < s.Length)
            {
                if (string.CompareOrdinal(s, i, "<![CDATA[", 0, 9) == 0)
                {
                    int e = s.IndexOf("]]>", i + 9, StringComparison.Ordinal);
                    if (e < 0) e = s.Length;
                    sb.Append(s, i + 9, e - i - 9);
                    i = Math.Min(s.Length, e + 3);
                    continue;
                }
                char c = s[i];
                if (c == '&')
                {
                    int semi = s.IndexOf(';', i);
                    if (semi > i && semi - i <= 10)
                    {
                        string ent = s.Substring(i + 1, semi - i - 1);
                        string rep = null;
                        if (ent == "lt") rep = "<"; else if (ent == "gt") rep = ">"; else if (ent == "amp") rep = "&";
                        else if (ent == "quot") rep = "\""; else if (ent == "apos") rep = "'";
                        else if (ent.StartsWith("#"))
                        {
                            int code;
                            bool ok = ent.StartsWith("#x") || ent.StartsWith("#X")
                                ? int.TryParse(ent.Substring(2), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out code)
                                : int.TryParse(ent.Substring(1), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out code);
                            if (ok && code > 0 && code <= 0x10FFFF) { try { rep = char.ConvertFromUtf32(code); } catch { rep = null; } }
                        }
                        if (rep != null) { sb.Append(rep); i = semi + 1; continue; }
                    }
                }
                sb.Append(c); i++;
            }
            return sb.ToString();
        }

        // Every action of a task XML (comments removed, any namespace prefix, entities decoded):
        // {"exec", command, arguments} or {"com", ClassId, Data}. Never the whole XML: its xmlns is an http URL.
        internal static List<string[]> TaskXmlActions(string xml)
        {
            List<string[]> res = new List<string[]>();
            if (string.IsNullOrEmpty(xml)) return res;
            string x = XmlComment.Replace(xml, "");
            foreach (Match m in ExecRx.Matches(x))
                res.Add(new string[] { "exec", Inner(m.Groups[1].Value, "Command"), Inner(m.Groups[1].Value, "Arguments") });
            foreach (Match m in ComRx.Matches(x))
                res.Add(new string[] { "com", Inner(m.Groups[1].Value, "ClassId"), Inner(m.Groups[1].Value, "Data") });
            return res;
        }

        // TaskCache\Tasks\{Id}\Actions (Win8+ REG_BINARY; layout from GhostTask, research coverage-gaps Q2):
        // u16 version, u32 len + UTF-16 author, then per action u16 magic, u32 len + id, and for 0x6666 (exec)
        // u32 len + command, u32 len + arguments, u32 len + working dir (+ u16 flags); 0x7777 (COM) 16-byte CLSID +
        // u32 len + data. Lengths in bytes. null = not this layout (the caller falls back to PrintableStrings).
        internal static List<string[]> TaskCacheActions(byte[] b)
        {
            if (b == null || b.Length < 6) return null;
            List<string[]> res = new List<string[]>();
            int pos = 2;
            string tmp;
            if (!LenStr(b, ref pos, out tmp)) return null;   // author
            while (pos + 2 <= b.Length)
            {
                int magic = BitConverter.ToUInt16(b, pos); pos += 2;
                string id;
                if (!LenStr(b, ref pos, out id)) return null;
                if (magic == 0x6666)
                {
                    string cmd, args, wd;
                    if (!LenStr(b, ref pos, out cmd) || !LenStr(b, ref pos, out args) || !LenStr(b, ref pos, out wd)) return null;
                    res.Add(new string[] { "exec", cmd, args });
                    if (pos + 2 <= b.Length && !KnownMagic(BitConverter.ToUInt16(b, pos))) pos += 2;   // flags
                }
                else if (magic == 0x7777)
                {
                    if (pos + 16 > b.Length) return null;
                    string clsid = new Guid(SubArray(b, pos, 16)).ToString("B"); pos += 16;
                    string data;
                    if (!LenStr(b, ref pos, out data)) return null;
                    res.Add(new string[] { "com", clsid, data });
                }
                else return null;   // e-mail / message box / unknown: layout not verified
            }
            return res;
        }

        static bool KnownMagic(int m) { return m == 0x6666 || m == 0x7777 || m == 0x8888 || m == 0x9999; }

        static byte[] SubArray(byte[] b, int at, int n) { byte[] r = new byte[n]; Array.Copy(b, at, r, 0, n); return r; }

        static bool LenStr(byte[] b, ref int pos, out string s)
        {
            s = null;
            if (pos + 4 > b.Length) return false;
            uint n = BitConverter.ToUInt32(b, pos);
            if (n % 2 != 0 || n > (uint)(b.Length - pos - 4)) return false;
            s = Encoding.Unicode.GetString(b, pos + 4, (int)n);
            pos += 4 + (int)n;
            return true;
        }

        // Runs of at least 'min' printable UTF-16LE characters (fallback display of an unparsed blob).
        internal static List<string> PrintableStrings(byte[] b, int min)
        {
            List<string> res = new List<string>();
            if (b == null) return res;
            for (int start = 0; start < 2; start++)   // both alignments
            {
                StringBuilder cur = new StringBuilder();
                for (int i = start; i + 1 < b.Length; i += 2)
                {
                    char c = (char)(b[i] | (b[i + 1] << 8));
                    bool ok = c >= 0x20 && c != 0x7F && c < 0xD800 && !(c >= 0x80 && c < 0xA0);
                    if (ok) { cur.Append(c); continue; }
                    if (cur.Length >= min) res.Add(cur.ToString());
                    cur.Length = 0;
                }
                if (cur.Length >= min) res.Add(cur.ToString());
                if (res.Count > 0) break;
            }
            return res;
        }

        static readonly Regex GuidRx = new Regex(@"^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$", RegexOptions.CultureInvariant);
        internal static bool IsGuid(string s) { return s != null && GuidRx.IsMatch(s); }

        // the same command, ignoring case, quotes, whitespace runs and env-variable spellings
        internal static string CmdKey(string cmd, string args)
        {
            string s = NormPath(((cmd ?? "") + " " + (args ?? "")).Replace("\"", ""));
            return Regex.Replace(s, @"\s+", " ").Trim();
        }

        // ---- payload of a command line / Startup shortcuts ----
        static readonly string[] Launchers = { "rundll32", "regsvr32", "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta", "conhost",
            "python", "pythonw", "py", "node", "java", "javaw", "svchost", "msiexec", "explorer", "dllhost", "taskhostw", "schtasks", "start" };
        static readonly string[] ThirdPartyLaunchers = { "python", "pythonw", "py", "node", "java", "javaw", "pwsh" };

        // The file a command line is ABOUT: the first absolute path that is not a launcher / interpreter
        // ("rundll32.exe C:\x\evil.dll,Start" -> C:\x\evil.dll; "powershell -File C:\a.ps1" -> C:\a.ps1); an unquoted
        // path with spaces is joined up to its extension. "" = nothing but launchers (never point at powershell.exe).
        internal static string PayloadPath(string s)
        {
            List<string> t = Tokens(s);
            for (int i = 0; i < t.Count; i++)
            {
                string x = t[i];
                int d = -1;
                for (int k = 0; k + 2 < x.Length; k++)
                    if (char.IsLetter(x[k]) && x[k + 1] == ':' && (x[k + 2] == '\\' || x[k + 2] == '/')) { d = k; break; }
                if (d < 0) continue;
                x = x.Substring(d);
                int j = i;
                while (!HasFileExt(x) && j + 1 < t.Count && s.IndexOf('"') < 0) { j++; x += " " + t[j]; }   // C:\Program Files\a b\x.exe
                int c = x.IndexOf(','); if (c > 0) x = x.Substring(0, c);
                x = x.TrimEnd(';', ')', '\'');
                string nm = x.Substring(Math.Max(x.LastIndexOf('\\'), x.LastIndexOf('/')) + 1).ToLowerInvariant();
                if (nm.EndsWith(".exe")) nm = nm.Substring(0, nm.Length - 4);
                // a launcher is skipped only where it really lives: a "svchost.exe"/"rundll32.exe" outside the Windows
                // folder is the payload itself (python/node/java/pwsh are installed elsewhere and always skipped)
                if (Array.IndexOf(Launchers, nm) >= 0 && (Array.IndexOf(ThirdPartyLaunchers, nm) >= 0 || x.ToLowerInvariant().Replace('/', '\\').Contains("\\windows\\")))
                { i = j; continue; }
                return x;
            }
            return "";
        }

        static bool HasFileExt(string p)
        {
            string nm = p.Substring(Math.Max(p.LastIndexOf('\\'), p.LastIndexOf('/')) + 1);
            int c = nm.IndexOf(','); if (c > 0) nm = nm.Substring(0, c);
            int dot = nm.LastIndexOf('.');
            return dot > 0 && nm.Length - dot >= 2 && nm.Length - dot <= 5;
        }

        // A shell link (.lnk, [MS-SHLLINK]): {target path, arguments}; null = not a readable link. Target = LinkInfo
        // LocalBasePath (+ CommonPathSuffix), else the RELATIVE_PATH string; IDList-only links give "".
        internal static string[] LnkTarget(byte[] b)
        {
            try
            {
                if (b == null || b.Length < 0x4C || BitConverter.ToUInt32(b, 0) != 0x4C) return null;
                uint flags = BitConverter.ToUInt32(b, 0x14);
                bool uni = (flags & 0x80) != 0;
                int pos = 0x4C;
                if ((flags & 0x1) != 0) pos += 2 + BitConverter.ToUInt16(b, pos);              // LinkTargetIDList
                string target = "";
                if ((flags & 0x2) != 0)                                                          // LinkInfo
                {
                    int li = pos;
                    int size = (int)BitConverter.ToUInt32(b, li);
                    int hdr = (int)BitConverter.ToUInt32(b, li + 4);
                    uint lflags = BitConverter.ToUInt32(b, li + 8);
                    if ((lflags & 1) != 0)
                    {
                        int lbp = (int)BitConverter.ToUInt32(b, li + 16), suf = (int)BitConverter.ToUInt32(b, li + 24);
                        if (hdr >= 0x24)
                        {
                            int lbpU = (int)BitConverter.ToUInt32(b, li + 28), sufU = (int)BitConverter.ToUInt32(b, li + 32);
                            target = ZStr(b, li + lbpU, true) + (sufU > 0 ? ZStr(b, li + sufU, true) : "");
                        }
                        else target = ZStr(b, li + lbp, false) + (suf > 0 ? ZStr(b, li + suf, false) : "");
                    }
                    if (size < 4 || li + size > b.Length) return null;
                    pos = li + size;
                }
                string[] str = new string[5];   // NAME, RELATIVE_PATH, WORKING_DIR, ARGUMENTS, ICON_LOCATION
                for (int i = 0; i < 5; i++)
                {
                    if ((flags & (0x4u << i)) == 0) continue;
                    int n = BitConverter.ToUInt16(b, pos); pos += 2;
                    int bytes = uni ? n * 2 : n;
                    if (pos + bytes > b.Length) return null;
                    str[i] = uni ? Encoding.Unicode.GetString(b, pos, bytes) : Encoding.Default.GetString(b, pos, bytes);
                    pos += bytes;
                }
                if (target.Length == 0 && str[1] != null) target = str[1];
                return new string[] { target, str[3] ?? "" };
            }
            catch { return null; }
        }

        static string ZStr(byte[] b, int at, bool uni)
        {
            if (at < 0 || at >= b.Length) return "";
            int e = at;
            if (uni) { while (e + 1 < b.Length && (b[e] != 0 || b[e + 1] != 0)) e += 2; return Encoding.Unicode.GetString(b, at, e - at); }
            while (e < b.Length && b[e] != 0) e++;
            return Encoding.Default.GetString(b, at, e - at);
        }

        // ---- hosts ----
        // Active lines of a hosts file as {address, name}: comments (#...) removed, one entry per name; the loopback
        // localhost lines are not returned.
        internal static List<string[]> HostsEntries(string text)
        {
            List<string[]> res = new List<string[]>();
            if (text == null) return res;
            foreach (string raw in text.Replace("\r", "\n").Split('\n'))
            {
                string line = raw;
                int h = line.IndexOf('#'); if (h >= 0) line = line.Substring(0, h);
                string[] p = line.Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (p.Length < 2) continue;
                for (int i = 1; i < p.Length; i++)
                {
                    string n = p[i].ToLowerInvariant();
                    if ((n == "localhost" || n == "localhost.localdomain") && Loopback(p[0])) continue;
                    res.Add(new string[] { p[0], p[i] });
                }
            }
            return res;
        }

        static bool Loopback(string ip)
        {
            string a = ip.Trim().ToLowerInvariant();
            return a.StartsWith("127.") || a == "::1" || a == "0.0.0.0" || a == "::" || a == "0:0:0:0:0:0:0:1";
        }

        static readonly string[] Security = { "microsoft", "windowsupdate", "windows.com", "msftncsi", "live.com", "bing.com", "kaspersky", "drweb",
            "eset", "avast", "avg.com", "avira", "bitdefender", "malwarebytes", "norton", "symantec", "mcafee", "sophos", "virustotal",
            "trendmicro", "f-secure", "comodo", "360totalsecurity", "zillya", "adaware", "emsisoft", "hitmanpro", "safezone", "virusinfo",
            "cureit", "anti-malware", "antivirus", "kaspersky-labs", "esetnod32", "nod32" };
        static readonly string[] Popular = { "google.", "yandex.", "vk.com", "ok.ru", "mail.ru", "facebook.", "instagram.", "sberbank", "paypal.",
            "tinkoff.", "steamcommunity.", "steampowered.", "youtube.", "twitter.", "x.com", "telegram.", "whatsapp.", "gosuslugi.", "rambler." };

        // 'part' starts a DNS label of 'name' ("www.eset.com", "eset.ru"; not "preset.io")
        static bool AtLabel(string name, string part)
        {
            int i = 0;
            while ((i = name.IndexOf(part, i, StringComparison.Ordinal)) >= 0)
            {
                if (i == 0 || name[i - 1] == '.' || name[i - 1] == '-') return true;
                i++;
            }
            return false;
        }

        internal static string HostsRisk(string ip, string name)
        {
            string n = (name ?? "").ToLowerInvariant();
            foreach (string s in Security) if (AtLabel(n, s)) return "SUSPECT";              // AV / Windows Update blocked or redirected
            if (!Loopback(ip)) foreach (string s in Popular) if (n.StartsWith(s) || n.Contains("." + s)) return "SUSPECT";   // pharming
            return "REVIEW";
        }
    }

    // One line of a quarantine manifest (format 2). FILE: a moved file. REG: a registry value (V) or key (K) backed
    // up to <N>.reg; the location is LOGICAL (installation + hive kind + profile + key path below the hive), so a
    // restore in another session maps it onto whatever mount / HKU key that hive has now. Legacy = a line of the
    // old format (shown, never restored automatically).
    class ManEntry
    {
        public string Type = "";            // FILE | REG | LEGACY
        public int N;                       // order of the backups (restore runs newest first)
        public string Orig = "";            // FILE: original full path   LEGACY: original key / path
        public string Vol = "";             // FILE: serial of the original volume ("" = unknown)
        public string Backup = "";          // file name inside the quarantine folder (LEGACY: as written)
        public int Attrs;                   // FILE: original attributes
        public string Sha = "";             // SHA-256 of the backup file
        public bool IsKey;                  // REG: K = whole key, V = one value
        public string Install = "";         // REG: installation identity (InstallId)
        public string RootKind = "";        // REG: SOFTWARE | SYSTEM | USER
        public string UserId = "";          // REG USER: SID, or "dir:" + profile folder without the drive letter
        public string RegRoot = "";         // REG: the hive root as written in the .reg file
        public string Rel = "";             // REG: key path below the hive root
        public string ValueName = "";       // REG V: the value name
        public string Note = "";            // REG: what it was (category / action)
    }

    static class QuarMan
    {
        internal const string Magic = "RESCUESCAN-QUARANTINE";
        internal const string ManifestName = "manifest.txt";

        // TAB / CR / LF / backslash escaped: a field can never split a line or add one.
        internal static string Esc(string s)
        {
            return (s ?? "").Replace("\\", "\\\\").Replace("\t", "\\t").Replace("\r", "\\r").Replace("\n", "\\n").Replace("\0", "\\0");
        }

        internal static string Unesc(string s)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < s.Length; i++)
            {
                if (s[i] != '\\' || i + 1 >= s.Length) { sb.Append(s[i]); continue; }
                char c = s[++i];
                sb.Append(c == 't' ? '\t' : c == 'r' ? '\r' : c == 'n' ? '\n' : c == '0' ? '\0' : c);
            }
            return sb.ToString();
        }

        static string Join(params string[] f)
        {
            string[] e = new string[f.Length];
            for (int i = 0; i < f.Length; i++) e[i] = Esc(f[i]);
            return string.Join("\t", e);
        }

        internal static string HeaderLine(string stamp, string target, string install) { return Join(Magic, "2", stamp, target, install); }

        internal static string FileLine(ManEntry e)
        {
            return Join("FILE", e.N.ToString(), e.Orig, e.Vol, e.Backup, e.Attrs.ToString(), e.Sha);
        }

        internal static string RegLine(ManEntry e)
        {
            return Join("REG", e.N.ToString(), e.IsKey ? "K" : "V", e.Install, e.RootKind, e.UserId, e.RegRoot, e.Rel, e.ValueName, e.Backup, e.Sha, e.Note);
        }

        internal static bool IsHeader(string line) { return line != null && line.StartsWith(Magic + "\t2\t"); }

        // One manifest line -> entry. null with err "" = not an entry (header, blank, *-FAIL lines); null with err = rejected.
        internal static ManEntry Parse(string line, out string err)
        {
            err = "";
            if (string.IsNullOrEmpty(line) || IsHeader(line)) return null;
            string[] raw = line.Split('\t');
            string[] p = new string[raw.Length];
            for (int i = 0; i < raw.Length; i++) p[i] = Unesc(raw[i]);
            if (p[0] != "FILE" && p[0] != "REG") return null;
            ManEntry e = new ManEntry();
            if (p.Length >= 4 && p[2] == "=>")   // format 1: FILE orig => dst   /   REG key => dst [tag]
            {
                e.Type = "LEGACY"; e.Orig = p[1]; e.Backup = p[3]; e.Note = p[0];
                return e;
            }
            int n;
            if (p.Length < 2 || !int.TryParse(p[1], out n) || n <= 0) { err = "нет номера"; return null; }
            e.N = n;
            if (p[0] == "FILE")
            {
                if (p.Length != 7) { err = "FILE: число полей"; return null; }
                e.Type = "FILE"; e.Orig = p[2]; e.Vol = p[3]; e.Backup = p[4]; e.Sha = p[6];
                if (!int.TryParse(p[5], out e.Attrs)) { err = "FILE: атрибуты"; return null; }
                if (!AbsLocalPath(e.Orig)) { err = "FILE: путь не абсолютный локальный: " + e.Orig; return null; }
            }
            else
            {
                if (p.Length != 12) { err = "REG: число полей"; return null; }
                e.Type = "REG"; e.IsKey = p[2] == "K"; e.Install = p[3]; e.RootKind = p[4]; e.UserId = p[5]; e.RegRoot = p[6];
                e.Rel = p[7]; e.ValueName = p[8]; e.Backup = p[9]; e.Sha = p[10]; e.Note = p[11];
                if (p[2] != "K" && p[2] != "V") { err = "REG: вид"; return null; }
                if (e.RootKind != "SOFTWARE" && e.RootKind != "SYSTEM" && e.RootKind != "USER") { err = "REG: куст " + e.RootKind; return null; }
                if (e.RootKind == "USER" && e.UserId.Length == 0) { err = "REG: профиль не указан"; return null; }
                if (!e.RegRoot.StartsWith("HKEY_", StringComparison.OrdinalIgnoreCase)) { err = "REG: корень " + e.RegRoot; return null; }
                if (!RelKeyOk(e.Rel, e.IsKey)) { err = "REG: путь ключа " + e.Rel; return null; }
                if (e.ValueName.IndexOf('\0') >= 0) { err = "REG: имя с NUL"; return null; }
            }
            if (!PlainName(e.Backup)) { err = "имя бэкапа: " + e.Backup; return null; }
            if (e.Sha.Length != 64) { err = "нет SHA-256"; return null; }
            return e;
        }

        // key path below a hive root: components non-empty, no NUL; a whole key needs at least one component
        internal static bool RelKeyOk(string rel, bool isKey)
        {
            if (rel == null || rel.IndexOf('\0') >= 0) return false;
            if (rel.Length == 0) return !isKey;
            foreach (string c in rel.Split('\\')) if (c.Length == 0) return false;
            return true;
        }

        // a bare file name inside the quarantine folder (no path, no "..", not the manifest itself)
        internal static bool PlainName(string n)
        {
            if (string.IsNullOrEmpty(n) || n == "." || n == ".." || n.Length > 200) return false;
            if (n.IndexOfAny(new char[] { '\\', '/', ':', '\0' }) >= 0 || n.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) return false;
            if (n.EndsWith(".") || n.EndsWith(" ")) return false;
            return !n.Equals(ManifestName, StringComparison.OrdinalIgnoreCase);
        }

        // X:\... with no "." / ".." components, no device / UNC forms
        internal static bool AbsLocalPath(string p)
        {
            if (string.IsNullOrEmpty(p) || p.Length < 4 || !char.IsLetter(p[0]) || p[1] != ':' || p[2] != '\\') return false;
            if (p.IndexOf('\0') >= 0 || p.IndexOf('/') >= 0) return false;
            foreach (string c in p.Substring(3).Split('\\')) if (c.Length == 0 || c == "." || c == "..") return false;
            return true;
        }

        // <n>_<name>.quarantine: never executable by double click, never an attacker-chosen extension or path.
        internal static string QuarFileName(int n, string original)
        {
            string name = original ?? "";
            name = name.Substring(name.LastIndexOfAny(new char[] { '\\', '/' }) + 1);
            StringBuilder sb = new StringBuilder();
            char[] bad = Path.GetInvalidFileNameChars();
            foreach (char c in name) sb.Append(c < 32 || Array.IndexOf(bad, c) >= 0 || c == ':' ? '_' : c);
            string s = sb.ToString().TrimEnd('.', ' ');
            if (s.Length > 80) s = s.Substring(0, 80);
            return n + "_" + s + ".quarantine";
        }

        // Where a new quarantine folder may go, best first: <target drive>\RescueScan_Quarantine\<stamp>, then
        // <exe folder>\RescueScan_Quarantine\<stamp>. Never on the WinPE RAM disk (ramDrive, e.g. X:) and never under
        // %TEMP%: both are gone after a reboot, and with them the only copy of what was removed.
        internal static List<string> Candidates(string tgtDrive, string exeDir, string ramDrive, string tempDir, string stamp)
        {
            List<string> res = new List<string>();
            if (!string.IsNullOrEmpty(tgtDrive) && tgtDrive.Length == 2 && tgtDrive[1] == ':' && !OnDrive(tgtDrive, ramDrive))
                res.Add(tgtDrive + "\\RescueScan_Quarantine\\" + stamp);
            if (!string.IsNullOrEmpty(exeDir) && exeDir.Length >= 3 && exeDir[1] == ':' && !OnDrive(exeDir, ramDrive) && !Below(exeDir, tempDir))
            {
                string c = exeDir.TrimEnd('\\') + "\\RescueScan_Quarantine\\" + stamp;
                if (!res.Exists(delegate(string r) { return r.Equals(c, StringComparison.OrdinalIgnoreCase); })) res.Add(c);
            }
            return res;
        }

        static bool OnDrive(string p, string drive)
        {
            return !string.IsNullOrEmpty(drive) && p.StartsWith(drive.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
        }

        internal static bool Below(string p, string dir)
        {
            if (string.IsNullOrEmpty(p) || string.IsNullOrEmpty(dir)) return false;
            string a = p.TrimEnd('\\') + "\\", b = dir.TrimEnd('\\') + "\\";
            return a.StartsWith(b, StringComparison.OrdinalIgnoreCase);
        }

        // the backup file 'name' resolves to a file directly inside 'dir'
        internal static bool Inside(string dir, string name)
        {
            if (!PlainName(name)) return false;
            try
            {
                string d = Path.GetFullPath(dir).TrimEnd('\\', '/');
                string f = Path.GetFullPath(Path.Combine(dir, name));
                return string.Equals(Path.GetDirectoryName(f).TrimEnd('\\', '/'), d, StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        internal static string Sha256(string file)
        {
            using (System.Security.Cryptography.SHA256 h = System.Security.Cryptography.SHA256.Create())
            using (FileStream s = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read))
                return Reg.Hex(h.ComputeHash(s)).ToLowerInvariant();
        }
    }

    // Offline path mapping: the registry of the target stores paths AS THE TARGET SEES THEM (C:\Users\bob\..., %APPDATA%,
    // %SystemRoot%, \SystemRoot\..., system32\drivers\x.sys), while this session sees the same volume under another letter
    // (D: in WinPE on BIOS/MBR systems). Used for the Explorer's red "found by the scan" mark and «Кто ссылается».
    static class PathMap
    {
        // Environment variables of the target (in its own letters, from its SystemRoot) plus the per-user ones for the
        // profile the value came from (curProfile: the profile folder as THIS session sees it, "" = machine value).
        internal static string Expand(string s, string tgtSysRoot, string curProfile)
        {
            if (string.IsNullOrEmpty(s)) return s ?? "";
            string sr = (tgtSysRoot ?? "").TrimEnd('\\');
            string sd = sr.Length >= 2 && sr[1] == ':' ? sr.Substring(0, 2) : "";
            string t = s.Trim();
            if (t.StartsWith("\\??\\")) t = t.Substring(4);                                         // \??\C:\x.sys
            if (sr.Length > 0 && t.StartsWith("\\SystemRoot\\", StringComparison.OrdinalIgnoreCase)) t = sr + t.Substring(11);
            else if (sr.Length > 0 && (t.StartsWith("system32\\", StringComparison.OrdinalIgnoreCase) || t.StartsWith("SysWOW64\\", StringComparison.OrdinalIgnoreCase)))
                t = sr + "\\" + t;                                                                    // driver ImagePath relative to SystemRoot
            if (t.IndexOf('%') < 0) return t;
            Dictionary<string, string> v = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (sr.Length > 0) { v["SystemRoot"] = sr; v["windir"] = sr; }
            if (sd.Length > 0)
            {
                v["SystemDrive"] = sd;
                v["ProgramFiles"] = sd + "\\Program Files"; v["ProgramW6432"] = sd + "\\Program Files";
                v["ProgramFiles(x86)"] = sd + "\\Program Files (x86)";
                v["CommonProgramFiles"] = sd + "\\Program Files\\Common Files"; v["CommonProgramW6432"] = sd + "\\Program Files\\Common Files";
                v["CommonProgramFiles(x86)"] = sd + "\\Program Files (x86)\\Common Files";
                v["ProgramData"] = sd + "\\ProgramData"; v["ALLUSERSPROFILE"] = sd + "\\ProgramData";
                v["PUBLIC"] = sd + "\\Users\\Public";
            }
            if (!string.IsNullOrEmpty(curProfile))
            {
                string pr = curProfile.TrimEnd('\\');
                v["USERPROFILE"] = pr; v["APPDATA"] = pr + "\\AppData\\Roaming"; v["LOCALAPPDATA"] = pr + "\\AppData\\Local";
                v["TEMP"] = pr + "\\AppData\\Local\\Temp"; v["TMP"] = pr + "\\AppData\\Local\\Temp";
            }
            return Regex.Replace(t, "%([^%\\\\]+)%", delegate(Match m) { string r; return v.TryGetValue(m.Groups[1].Value, out r) ? r : m.Value; });
        }

        // A path on the target's system drive (its own letter, e.g. C:) -> the same path under the letter this session
        // sees (curWinDir's drive, e.g. D:). Other letters are left alone (another volume: not mappable here).
        internal static string ToCurrent(string path, string tgtSysRoot, string curWinDir)
        {
            if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(tgtSysRoot) || string.IsNullOrEmpty(curWinDir)) return path ?? "";
            if (tgtSysRoot.Length < 2 || curWinDir.Length < 2 || tgtSysRoot[1] != ':' || curWinDir[1] != ':') return path;
            string from = tgtSysRoot.Substring(0, 2), to = curWinDir.Substring(0, 2);
            if (path.Length >= 3 && path.StartsWith(from, StringComparison.OrdinalIgnoreCase) && (path[2] == '\\' || path[2] == '/'))
                return to + path.Substring(2);
            return path;
        }

        // The payload file of a registry value, as THIS session sees it ("" = none).
        internal static string Payload(string value, string tgtSysRoot, string curWinDir, string curProfile)
        {
            string p = Heur.PayloadPath(Expand(value, tgtSysRoot, curProfile));
            return p.Length == 0 ? "" : ToCurrent(p, tgtSysRoot, curWinDir);
        }
    }

    // Fast Startup / hibernation of an OFFLINE target. A normal «Завершение работы» with Fast Startup (default since
    // Windows 8) hibernates the kernel session into <system drive>\hiberfil.sys, including the loaded SYSTEM/SOFTWARE
    // hives and NTFS caches. Changes made from WinPE are then discarded when Windows resumes (the malware's values come
    // back) or corrupt the volume. Signature of the first 4 bytes: "hibr"/"HIBR" = valid image (ntfs-3g refuses to
    // mount read-write for the same reason), "rstr"/"RSTR" = resume in progress; zeros / "wake" / no file = no image.
    static class Hiber
    {
        internal static bool ActiveSignature(byte[] head)
        {
            if (head == null || head.Length < 4) return false;
            string sig = Encoding.ASCII.GetString(head, 0, 4).ToLowerInvariant();
            return sig == "hibr" || sig == "rstr";
        }

        // "C:" -> true when C:\hiberfil.sys holds an active hibernation image. Unreadable / missing = false.
        internal static bool Active(string drive)
        {
            if (string.IsNullOrEmpty(drive) || drive.Length < 2 || drive[1] != ':') return false;
            return ActiveFile(drive.Substring(0, 2) + "\\hiberfil.sys");
        }

        internal static bool ActiveFile(string f)
        {
            try
            {
                if (!File.Exists(f)) return false;
                byte[] b = new byte[4];
                using (FileStream fs = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    if (fs.Read(b, 0, 4) < 4) return false;
                return ActiveSignature(b);
            }
            catch { return false; }
        }
    }

    // File-system operations that work for every name Win32 can store: on Windows through \\?\ paths (names ending in
    // "." or " ", which the normal path rules silently strip and then hit a DIFFERENT file), without following
    // junctions / symlinks, read-only / hidden / system cleared first. Elsewhere (Mono, tests) the managed API.
    static class FsOps
    {
        static bool Win { get { return Environment.OSVersion.Platform == PlatformID.Win32NT; } }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct FindData
        {
            public uint Attr, C1, C2, A1, A2, W1, W2; public uint SizeHigh, SizeLow, R0, R1;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string Name;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)] public string Alt;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr FindFirstFileW(string p, out FindData d);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool FindNextFileW(IntPtr h, out FindData d);
        [DllImport("kernel32.dll")] static extern bool FindClose(IntPtr h);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool DeleteFileW(string p);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool RemoveDirectoryW(string p);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool SetFileAttributesW(string p, uint a);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern uint GetFileAttributesW(string p);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool MoveFileExW(string a, string b, int flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool GetVolumeInformationW(string root, StringBuilder name, int nameSize, out uint serial, out uint maxComp, out uint flags, StringBuilder fs, int fsSize);

        const uint INVALID = 0xFFFFFFFF, A_RO = 1, A_HIDDEN = 2, A_SYSTEM = 4, A_DIR = 0x10, A_REPARSE = 0x400, A_NORMAL = 0x80;

        internal static string Long(string p)
        {
            if (p.StartsWith("\\\\?\\")) return p;
            if (p.StartsWith("\\\\")) return "\\\\?\\UNC\\" + p.Substring(2);
            return "\\\\?\\" + p;
        }

        static string Why() { return new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message; }

        // attributes, or -1 when nothing is there
        internal static int Attrs(string p)
        {
            if (Win) { uint a = GetFileAttributesW(Long(p)); return a == INVALID ? -1 : (int)a; }
            try { return File.Exists(p) || Directory.Exists(p) ? (int)File.GetAttributes(p) : -1; } catch { return -1; }
        }

        internal static bool Exists(string p) { return Attrs(p) != -1; }

        internal static bool SetAttrs(string p, int a)
        {
            if (Win) return SetFileAttributesW(Long(p), a == 0 ? A_NORMAL : (uint)a);
            try { File.SetAttributes(p, a == 0 ? FileAttributes.Normal : (FileAttributes)a); return true; } catch { return false; }
        }

        // drops ReadOnly / Hidden / System (attrib +r makes DeleteFile fail with "access denied")
        internal static void ClearRhs(string p)
        {
            int a = Attrs(p);
            if (a != -1 && (a & (int)(A_RO | A_HIDDEN | A_SYSTEM)) != 0) SetAttrs(p, a & ~(int)(A_RO | A_HIDDEN | A_SYSTEM));
        }

        internal static bool DeleteFile(string p, out string err)
        {
            err = "";
            ClearRhs(p);
            if (Win) { if (DeleteFileW(Long(p))) return true; err = Why(); return false; }
            try { File.Delete(p); return !File.Exists(p); } catch (Exception ex) { err = ex.Message; return false; }
        }

        // Moves a file (also to another volume). The destination must not exist. The source must be gone afterwards:
        // a cross-volume move that copied but could not delete the original is a failure (err says so).
        internal static bool MoveFile(string src, string dst, out string err)
        {
            err = "";
            try
            {
                if (Win) { if (!MoveFileExW(Long(src), Long(dst), 0x2 | 0x8)) { err = Why(); return false; } }   // COPY_ALLOWED | WRITE_THROUGH
                else File.Move(src, dst);
            }
            catch (Exception ex) { err = ex.Message; return false; }
            if (Exists(src)) { err = "копия сделана, но оригинал не удалился (файл занят?)"; return false; }
            return true;
        }

        // Names in a folder exactly as stored (also "x." and "x "). null = cannot be listed.
        internal static List<string> List(string dir)
        {
            List<string> res = new List<string>();
            if (!Win)
            {
                try { foreach (string e in Directory.GetFileSystemEntries(dir)) res.Add(Path.GetFileName(e)); return res; }
                catch { return null; }
            }
            FindData d;
            IntPtr h = FindFirstFileW(Long(dir.TrimEnd('\\') + "\\*"), out d);
            if (h == new IntPtr(-1)) return Marshal.GetLastWin32Error() == 2 ? res : null;
            try
            {
                do { if (d.Name != "." && d.Name != "..") res.Add(d.Name); } while (FindNextFileW(h, out d));
            }
            finally { FindClose(h); }
            return res;
        }

        // Deletes a folder tree. Junctions / symlinks inside are removed as links; their targets are never entered.
        // Continues after errors; returns false (and counts them in 'failed') if anything stayed.
        internal static bool DeleteTree(string dir, ref int failed, ref string err)
        {
            int a = Attrs(dir);
            if (a == -1) return true;
            if ((a & (int)A_REPARSE) == 0)
            {
                List<string> names = List(dir);
                if (names == null) { failed++; if (err.Length == 0) err = "папка не читается: " + dir; return false; }
                foreach (string n in names)
                {
                    string p = Win ? dir.TrimEnd('\\') + "\\" + n : Path.Combine(dir, n);
                    int pa = Attrs(p);
                    string e;
                    if (pa != -1 && (pa & (int)A_DIR) != 0) DeleteTree(p, ref failed, ref err);
                    else if (!DeleteFile(p, out e)) { failed++; if (err.Length == 0) err = n + ": " + e; }
                }
            }
            ClearRhs(dir);
            bool ok;
            if (Win) ok = RemoveDirectoryW(Long(dir));
            else { try { Directory.Delete(dir, false); ok = true; } catch { ok = false; } }
            if (!ok) { failed++; if (err.Length == 0) err = dir + ": " + (Win ? Why() : "не удалена"); }
            return ok && failed == 0;
        }

        // Volume serial number of the drive of 'path' as 8 hex digits ("" = unknown, e.g. not Windows).
        internal static string VolumeSerial(string path)
        {
            if (!Win || string.IsNullOrEmpty(path) || path.Length < 2 || path[1] != ':') return "";
            try
            {
                uint serial, mc, fl;
                if (GetVolumeInformationW(path.Substring(0, 2) + "\\", null, 0, out serial, out mc, out fl, null, 0)) return serial.ToString("X8");
            }
            catch { }
            return "";
        }
    }

    class MainForm : Form
    {
        ComboBox cboWin;
        Button btnDetect, btnScan, btnMark, btnPreboot, btnDelete, btnExport;
        ListView lv;
        Label lblStatus;
        TabControl tabs;
        ListView lvProc; Label lblProc;
        ListView lvFiles; TextBox txtPath; Label lblFiles;
        // hives WE mounted under HKLM (RS_SOFT, RS_SYS, RS_U<n>): unloaded on rescan / exit
        HiveMounts mounts = new HiveMounts(Reg.RunCode, Reg.KeyExists, File.Exists, delegate { return Reg.SubkeyNames("HKLM"); }, OtherInstanceAlive);
        // ---- scan target: ONE source of truth for the scan AND every repair/unlock/assoc/IFEO/policy action ----
        bool tgtReady = false;       // prepared by Scan (or by the first action before any scan)
        bool tgtLive = false;        // the target is the running OS (live registry)
        string tgtWinDir = "";       // e.g. D:\Windows
        string tgtSoft = "";         // SOFTWARE root: HKLM\RS_SOFT (offline) / HKLM\SOFTWARE (live); "" = not available
        string tgtSys = "";          // SYSTEM root:   HKLM\RS_SYS  (offline) / HKLM\SYSTEM   (live); "" = not available
        List<string[]> tgtUsers = new List<string[]>();   // {name, hive root (HKLM\RS_U<n> / HKU\<SID>) or "", profile dir, SID or ""}
        string tgtSysRoot = "";      // the target's own %SystemRoot% as it boots (e.g. C:\Windows also when WinPE calls it D:)
        string tgtInstall = "";      // identity of the installation for quarantine backups (InstallId)
        // The MOUNT ROLE: only the RescueScan GUI that holds this mutex mounts or unloads hives (HiveMounts). A second
        // instance never does, so the holder may treat every RS_* mount it did not make as stale, and neither instance
        // can unload or replace a hive the other one is using. A second instance takes the role over once the holder
        // has exited (released or abandoned mutex). UI thread only: a mutex belongs to the thread that acquired it.
        static Mutex instanceMutex;
        static bool otherInstance = true;

        static bool OtherInstanceAlive()
        {
            if (!otherInstance) return false;
            try
            {
                if (instanceMutex == null)
                {
                    try { instanceMutex = new Mutex(false, "Global\\RescueScan_GUI"); }
                    catch { instanceMutex = new Mutex(false, "Local\\RescueScan_GUI"); }   // no right to create a global one
                }
                otherInstance = !instanceMutex.WaitOne(0);
            }
            catch (AbandonedMutexException) { otherInstance = false; }   // the previous holder ended without releasing it: ours now
            catch { otherInstance = false; }
            return otherInstance;
        }
        string curDrive = "";
        string curPath = "";
        HashSet<string> flagged = new HashSet<string>();
        List<Finding> lastFindings = new List<Finding>();
        Process watchdogProc; EventWaitHandle stopEvt; bool stopping = false;
        CheckBox chkTop, chkWatch;
        Button btnQuar, btnWho, btnQuarFile;
        string quarDir = "";
        string quarErr = "";   // first failure reason of the last quarantine run (shown in the status line)
        ListView lvRepair; CheckBox chkGuard; bool guarding = false; Thread guardThread;
        ListView lvSimple;
        ListView lvQuar; string quarViewDir = ""; Label lblQuar;
        ListView lvAcc; Label lblAcc;
        Button btnDefuse;
        CheckBox oScan, oWinlogon, oIFEO, oRestrict, oAssoc, oDefuse, oQuar, oWatch, oShell, oBoot;
        Label lblEasy;

        internal static MainForm Current;   // for the last-chance exception handler (unload our hives)

        // Fatal path only: unload the hives this instance mounted. Best effort, never throws.
        internal string EmergencyUnload()
        {
            try { stopping = true; guarding = false; return mounts.UnloadAll(); } catch (Exception ex) { return ex.Message; }
        }

        public MainForm()
        {
            Current = this;
            OtherInstanceAlive();   // take the instance marker (UI thread) as early as possible
            Text = "RescueScan  -  scanner + task manager + explorer (WinPE / live)";
            Width = 1080; Height = 660; StartPosition = FormStartPosition.CenterScreen;
            MinimumSize = new Size(860, 500);

            tabs = new TabControl(); tabs.Dock = DockStyle.Fill;
            TabPage tp1 = new TabPage("Автозагрузка (полная)");
            TabPage tpS = new TabPage("Автозапуск (кратко)");
            TabPage tp2 = new TabPage("Диспетчер задач");
            TabPage tp3 = new TabPage("Проводник");
            TabPage tpQ = new TabPage("Карантин");
            TabPage tp4 = new TabPage("Ремонт");
            TabPage tpA = new TabPage("Аккаунты");
            TabPage tpE = new TabPage("Изи-кнопка");
            TabPage tp5 = new TabPage("Справка");
            tabs.TabPages.Add(tp1); tabs.TabPages.Add(tpS); tabs.TabPages.Add(tp2); tabs.TabPages.Add(tp3); tabs.TabPages.Add(tpQ); tabs.TabPages.Add(tp4); tabs.TabPages.Add(tpA); tabs.TabPages.Add(tpE); tabs.TabPages.Add(tp5);
            Controls.Add(tabs);

            // ---- TAB 1: autoruns scanner ----
            Panel top = new Panel(); top.Dock = DockStyle.Top; top.Height = 40;
            Label l1 = new Label(); l1.Text = "Windows:"; l1.Left = 8; l1.Top = 11; l1.AutoSize = true;
            cboWin = new ComboBox(); cboWin.Left = 72; cboWin.Top = 8; cboWin.Width = 210; cboWin.DropDownStyle = ComboBoxStyle.DropDownList;
            btnDetect = new Button(); btnDetect.Text = "Найти ОС"; btnDetect.Left = 288; btnDetect.Top = 7; btnDetect.Width = 84;
            btnScan = new Button(); btnScan.Text = "Сканировать"; btnScan.Left = 376; btnScan.Top = 7; btnScan.Width = 96;
            btnMark = new Button(); btnMark.Text = "Отметить подозрит."; btnMark.Left = 476; btnMark.Top = 7; btnMark.Width = 140;
            btnPreboot = new Button(); btnPreboot.Text = "Pre-boot (ESP/BCD)"; btnPreboot.Left = 620; btnPreboot.Top = 7; btnPreboot.Width = 130;
            top.Controls.Add(l1); top.Controls.Add(cboWin); top.Controls.Add(btnDetect); top.Controls.Add(btnScan); top.Controls.Add(btnMark); top.Controls.Add(btnPreboot);

            lv = new ListView(); lv.Dock = DockStyle.Fill; lv.View = View.Details;
            lv.CheckBoxes = true; lv.FullRowSelect = true; lv.GridLines = true;
            lv.Columns.Add("Категория", 150); lv.Columns.Add("Имя", 170);
            lv.Columns.Add("Команда / путь", 380); lv.Columns.Add("Расположение", 250); lv.Columns.Add("Риск", 80);

            Panel bot = new Panel(); bot.Dock = DockStyle.Bottom; bot.Height = 40;
            btnDefuse = new Button(); btnDefuse.Text = "Обезвредить"; btnDefuse.Left = 8; btnDefuse.Top = 7; btnDefuse.Width = 104;
            btnQuar = new Button(); btnQuar.Text = "Карантин отм."; btnQuar.Left = 116; btnQuar.Top = 7; btnQuar.Width = 116;
            btnDelete = new Button(); btnDelete.Text = "Удалить отм."; btnDelete.Left = 236; btnDelete.Top = 7; btnDelete.Width = 110;
            btnExport = new Button(); btnExport.Text = "Экспорт"; btnExport.Left = 350; btnExport.Top = 7; btnExport.Width = 90;
            lblStatus = new Label(); lblStatus.Left = 446; lblStatus.Top = 12; lblStatus.Width = 600; lblStatus.Text = "Готово.";
            bot.Controls.Add(btnDefuse); bot.Controls.Add(btnQuar); bot.Controls.Add(btnDelete); bot.Controls.Add(btnExport); bot.Controls.Add(lblStatus);
            tp1.Controls.Add(lv); tp1.Controls.Add(top); tp1.Controls.Add(bot);

            // ---- TAB (simple): user-focused autoruns like Simple Unlocker ----
            Panel sbar = new Panel(); sbar.Dock = DockStyle.Top; sbar.Height = 38;
            Button sscan = new Button(); sscan.Text = "Сканировать"; sscan.Left = 8; sscan.Top = 7; sscan.Width = 110;
            Button smark = new Button(); smark.Text = "Отметить подозрит."; smark.Left = 122; smark.Top = 7; smark.Width = 140;
            Button squar = new Button(); squar.Text = "Карантин"; squar.Left = 266; squar.Top = 7; squar.Width = 100;
            Button sdel = new Button(); sdel.Text = "Удалить"; sdel.Left = 370; sdel.Top = 7; sdel.Width = 100;
            Label slbl = new Label(); slbl.Left = 480; slbl.Top = 12; slbl.Width = 560; slbl.Text = "Только Run / RunOnce / Планировщик / Startup (что видит «Автозагрузка» Диспетчера задач).";
            sbar.Controls.Add(sscan); sbar.Controls.Add(smark); sbar.Controls.Add(squar); sbar.Controls.Add(sdel); sbar.Controls.Add(slbl);
            lvSimple = new ListView(); lvSimple.Dock = DockStyle.Fill; lvSimple.View = View.Details; lvSimple.CheckBoxes = true; lvSimple.FullRowSelect = true; lvSimple.GridLines = true;
            lvSimple.Columns.Add("Тип", 170); lvSimple.Columns.Add("Имя", 190); lvSimple.Columns.Add("Команда / путь", 470); lvSimple.Columns.Add("Риск", 80);
            tpS.Controls.Add(lvSimple); tpS.Controls.Add(sbar);
            sscan.Click += delegate { Scan(); SimpleRefresh(); };
            smark.Click += delegate { MarkSuspect(lvSimple); };
            squar.Click += delegate { QuarantineChecked(lvSimple); };
            sdel.Click += delegate { DeleteChecked(lvSimple); };

            // ---- TAB 2: task manager ----
            Panel tbar = new Panel(); tbar.Dock = DockStyle.Top; tbar.Height = 36;
            Button bpr = new Button(); bpr.Text = "Обновить"; bpr.Left = 8; bpr.Top = 6; bpr.Width = 80;
            Button bpk = new Button(); bpk.Text = "Завершить"; bpk.Left = 92; bpk.Top = 6; bpk.Width = 90;
            Button bpt = new Button(); bpt.Text = "Завершить дерево"; bpt.Left = 186; bpt.Top = 6; bpt.Width = 130;
            chkTop = new CheckBox(); chkTop.Text = "Поверх всех окон"; chkTop.Left = 326; chkTop.Top = 9; chkTop.Width = 130; chkTop.Checked = true;
            chkWatch = new CheckBox(); chkWatch.Text = "Watchdog (самолечение)"; chkWatch.Left = 462; chkWatch.Top = 9; chkWatch.Width = 180; chkWatch.Checked = false;
            lblProc = new Label(); lblProc.Left = 648; lblProc.Top = 11; lblProc.Width = 400; lblProc.Text = "Процессы (в WinRE — WinPE).";
            tbar.Controls.Add(bpr); tbar.Controls.Add(bpk); tbar.Controls.Add(bpt); tbar.Controls.Add(chkTop); tbar.Controls.Add(chkWatch); tbar.Controls.Add(lblProc);
            lvProc = new ListView(); lvProc.Dock = DockStyle.Fill; lvProc.View = View.Details; lvProc.FullRowSelect = true; lvProc.GridLines = true; lvProc.MultiSelect = true;
            lvProc.Columns.Add("PID", 60); lvProc.Columns.Add("Процесс", 200); lvProc.Columns.Add("Путь", 470); lvProc.Columns.Add("Память", 90); lvProc.Columns.Add("Риск", 80);
            tp2.Controls.Add(lvProc); tp2.Controls.Add(tbar);
            bpr.Click += delegate { RefreshProcs(); };
            bpk.Click += delegate { KillProc(false); };
            bpt.Click += delegate { KillProc(true); };
            chkTop.CheckedChanged += delegate { this.TopMost = chkTop.Checked; };
            chkWatch.CheckedChanged += delegate { if (adopting) return; if (chkWatch.Checked) StartWatchdog(); else StopWatchdog(); };

            // ---- TAB 3: explorer (shows hidden + system by default, red = suspicious) ----
            Panel ebar = new Panel(); ebar.Dock = DockStyle.Top; ebar.Height = 36;
            Button bup = new Button(); bup.Text = "Вверх"; bup.Left = 8; bup.Top = 6; bup.Width = 70;
            txtPath = new TextBox(); txtPath.Left = 82; txtPath.Top = 8; txtPath.Width = 520;
            Button bgo = new Button(); bgo.Text = "Перейти"; bgo.Left = 608; bgo.Top = 6; bgo.Width = 78;
            Button bref = new Button(); bref.Text = "Обновить"; bref.Left = 690; bref.Top = 6; bref.Width = 82;
            Button brun = new Button(); brun.Text = "Запустить"; brun.Left = 776; brun.Top = 6; brun.Width = 90;
            ebar.Controls.Add(bup); ebar.Controls.Add(txtPath); ebar.Controls.Add(bgo); ebar.Controls.Add(bref); ebar.Controls.Add(brun);
            lvFiles = new ListView(); lvFiles.Dock = DockStyle.Fill; lvFiles.View = View.Details; lvFiles.FullRowSelect = true; lvFiles.GridLines = true; lvFiles.MultiSelect = true;
            lvFiles.Columns.Add("Имя", 320); lvFiles.Columns.Add("Тип", 70); lvFiles.Columns.Add("Размер", 100); lvFiles.Columns.Add("Атрибуты", 100); lvFiles.Columns.Add("Изменён", 130);
            Panel ebot = new Panel(); ebot.Dock = DockStyle.Bottom; ebot.Height = 36;
            Button bdel = new Button(); bdel.Text = "Удалить"; bdel.Left = 8; bdel.Top = 6; bdel.Width = 76;
            Button bren = new Button(); bren.Text = "Переименовать"; bren.Left = 88; bren.Top = 6; bren.Width = 116;
            btnQuarFile = new Button(); btnQuarFile.Text = "Карантин"; btnQuarFile.Left = 208; btnQuarFile.Top = 6; btnQuarFile.Width = 84;
            Button buh = new Button(); buh.Text = "Снять скрытие"; buh.Left = 296; buh.Top = 6; buh.Width = 104;
            btnWho = new Button(); btnWho.Text = "Кто ссылается"; btnWho.Left = 404; btnWho.Top = 6; btnWho.Width = 114;
            lblFiles = new Label(); lblFiles.Left = 524; lblFiles.Top = 11; lblFiles.Width = 520; lblFiles.Text = "Скрытые (серым) и системные видны. Красный = найден сканом.";
            ebot.Controls.Add(bdel); ebot.Controls.Add(bren); ebot.Controls.Add(btnQuarFile); ebot.Controls.Add(buh); ebot.Controls.Add(btnWho); ebot.Controls.Add(lblFiles);
            tp3.Controls.Add(lvFiles); tp3.Controls.Add(ebar); tp3.Controls.Add(ebot);
            bup.Click += delegate { NavUp(); };
            bgo.Click += delegate { Nav(txtPath.Text); };
            bref.Click += delegate { Nav(curPath); };
            brun.Click += delegate { LaunchSelected(); };
            bdel.Click += delegate { DeleteFile(); };
            bren.Click += delegate { RenameSelected(); };
            btnQuarFile.Click += delegate { QuarantineSelectedFiles(); };
            buh.Click += delegate { Unhide(); };
            btnWho.Click += delegate { WhoReferences(); };
            lvFiles.DoubleClick += delegate { OpenSelected(); };
            txtPath.KeyDown += delegate(object s, KeyEventArgs e) { if (e.KeyCode == Keys.Enter) { Nav(txtPath.Text); e.SuppressKeyPress = true; } };

            // ---- TAB (quarantine): view backed-up items and restore ----
            Panel qbar = new Panel(); qbar.Dock = DockStyle.Top; qbar.Height = 36;
            Button qfind = new Button(); qfind.Text = "Найти последний"; qfind.Left = 8; qfind.Top = 6; qfind.Width = 130;
            Button qbrowse = new Button(); qbrowse.Text = "Открыть папку…"; qbrowse.Left = 142; qbrowse.Top = 6; qbrowse.Width = 120;
            Button qrestore = new Button(); qrestore.Text = "Восстановить"; qrestore.Left = 266; qrestore.Top = 6; qrestore.Width = 120;
            lblQuar = new Label(); lblQuar.Left = 396; lblQuar.Top = 11; lblQuar.Width = 640; lblQuar.Text = "Папка карантина не выбрана.";
            qbar.Controls.Add(qfind); qbar.Controls.Add(qbrowse); qbar.Controls.Add(qrestore); qbar.Controls.Add(lblQuar);
            lvQuar = new ListView(); lvQuar.Dock = DockStyle.Fill; lvQuar.View = View.Details; lvQuar.CheckBoxes = true; lvQuar.FullRowSelect = true; lvQuar.GridLines = true;
            lvQuar.Columns.Add("Тип", 70); lvQuar.Columns.Add("Оригинал / ключ", 470); lvQuar.Columns.Add("Бэкап", 280); lvQuar.Columns.Add("Цель (куст)", 200);
            tpQ.Controls.Add(lvQuar); tpQ.Controls.Add(qbar);
            qfind.Click += delegate { QuarAutoFind(); };
            qbrowse.Click += delegate { QuarBrowse(); };
            qrestore.Click += delegate { QuarRestore(); };

            // ---- TAB 4: repair (restore Shell/Userinit/cmd/AppInit to default or custom) ----
            Panel rbar = new Panel(); rbar.Dock = DockStyle.Top; rbar.Height = 36;
            Button rref = new Button(); rref.Text = "Обновить"; rref.Left = 8; rref.Top = 6; rref.Width = 90;
            Button rdef = new Button(); rdef.Text = "→ Дефолт"; rdef.Left = 102; rdef.Top = 6; rdef.Width = 100;
            Button rcus = new Button(); rcus.Text = "→ Своё…"; rcus.Left = 206; rcus.Top = 6; rcus.Width = 100;
            chkGuard = new CheckBox(); chkGuard.Text = "Стеречь Winlogon (live: вернуть дефолт при подмене)"; chkGuard.Left = 320; chkGuard.Top = 9; chkGuard.Width = 380;
            rbar.Controls.Add(rref); rbar.Controls.Add(rdef); rbar.Controls.Add(rcus); rbar.Controls.Add(chkGuard);
            lvRepair = new ListView(); lvRepair.Dock = DockStyle.Fill; lvRepair.View = View.Details; lvRepair.FullRowSelect = true; lvRepair.GridLines = true; lvRepair.MultiSelect = true;
            lvRepair.Columns.Add("Якорь", 200); lvRepair.Columns.Add("Текущее значение (offline)", 440); lvRepair.Columns.Add("Дефолт", 320);
            Panel rbot = new Panel(); rbot.Dock = DockStyle.Bottom; rbot.Height = 62;
            Button bunlock = new Button(); bunlock.Text = "Снять блокировки (политики + IFEO)"; bunlock.Left = 8; bunlock.Top = 6; bunlock.Width = 250;
            Button bassoc = new Button(); bassoc.Text = "Вернуть ассоциации (.exe/.bat/.lnk)"; bassoc.Left = 262; bassoc.Top = 6; bassoc.Width = 250;
            Label rlbl = new Label(); rlbl.Left = 8; rlbl.Top = 38; rlbl.Width = 1030; rlbl.Text = "Красным — значение ≠ дефолт (подмена). «Снять блокировки» = убрать DisableTaskMgr/DisableRegistryTools/NoRun + IFEO-дебагеры. Работает офлайн и на живой ОС.";
            rbot.Controls.Add(bunlock); rbot.Controls.Add(bassoc); rbot.Controls.Add(rlbl);
            tp4.Controls.Add(lvRepair); tp4.Controls.Add(rbar); tp4.Controls.Add(rbot);
            rref.Click += delegate { RepairRefresh(true); };
            rdef.Click += delegate { RepairSet(false); };
            rcus.Click += delegate { RepairSet(true); };
            chkGuard.CheckedChanged += delegate { GuardToggle(); };
            bunlock.Click += delegate { if (!RequireSoft("Снять блокировки")) return; quarErr = ""; int a = RestoreRestrictions(); int kept; int b = ClearIFEODirect(out kept);
                MessageBox.Show("Снято ограничений политик: " + a + "\r\nСнято IFEO-блокировок: " + b + (kept > 0 ? "\r\nОставлено известных отладчиков (Process Explorer, Notepad++…): " + kept + " — сними вручную в списке скана, если не нужны" : "")
                    + "\r\nЦель: " + TargetName() + (quarDir.Length > 0 ? "\r\nБэкап изменений: " + quarDir : "") + (quarErr.Length > 0 ? "\r\nОшибка: " + quarErr : ""), "Разблокировка"); };
            bassoc.Click += delegate { if (!RequireSoft("Вернуть ассоциации")) return; quarErr = ""; int a = RestoreAssoc(); MessageBox.Show("Восстановлено ассоциаций/иконок: " + a + "\r\nЦель: " + TargetName() + (quarDir.Length > 0 ? "\r\nБэкап изменений: " + quarDir : "") + (quarErr.Length > 0 ? "\r\nОшибка: " + quarErr : ""), "Ассоциации"); };

            // ---- TAB (accounts): live net user ops ----
            Panel abar = new Panel(); abar.Dock = DockStyle.Top; abar.Height = 36;
            Button aref = new Button(); aref.Text = "Обновить"; aref.Left = 8; aref.Top = 6; aref.Width = 90;
            Button apass = new Button(); apass.Text = "Сменить пароль"; apass.Left = 102; apass.Top = 6; apass.Width = 130;
            Button aen = new Button(); aen.Text = "Включить/разблок."; aen.Left = 236; aen.Top = 6; aen.Width = 140;
            Button adel = new Button(); adel.Text = "Удалить юзера"; adel.Left = 380; adel.Top = 6; adel.Width = 120;
            Button aprof = new Button(); aprof.Text = "Удалить профиль"; aprof.Left = 504; aprof.Top = 6; aprof.Width = 130;
            accBtns = new Button[] { apass, aen, adel, aprof };
            abar.Controls.Add(aref); abar.Controls.Add(apass); abar.Controls.Add(aen); abar.Controls.Add(adel); abar.Controls.Add(aprof);
            lvAcc = new ListView(); lvAcc.Dock = DockStyle.Fill; lvAcc.View = View.Details; lvAcc.FullRowSelect = true; lvAcc.GridLines = true;
            lvAcc.Columns.Add("Пользователь", 180); lvAcc.Columns.Add("Отключён", 80); lvAcc.Columns.Add("Заблокирован", 100); lvAcc.Columns.Add("Пароль нужен", 100); lvAcc.Columns.Add("SID", 300);
            Panel abot = new Panel(); abot.Dock = DockStyle.Bottom; abot.Height = 30;
            lblAcc = new Label(); lblAcc.Left = 8; lblAcc.Top = 7; lblAcc.Width = 1030; lblAcc.Text = "Только ЖИВАЯ ОС (нужна работающая система + WMI). В WinPE не работает — там сброс пароля делай через chntpw / MS DaRT.";
            abot.Controls.Add(lblAcc);
            tpA.Controls.Add(lvAcc); tpA.Controls.Add(abar); tpA.Controls.Add(abot);
            aref.Click += delegate { AccRefresh(); };
            apass.Click += delegate { AccSetPass(); };
            aen.Click += delegate { AccEnable(); };
            adel.Click += delegate { AccDelUser(); };
            aprof.Click += delegate { AccDelProfile(); };

            // ---- TAB (easy): one-button cleanup with toggles ----
            Panel eopt = new Panel(); eopt.Dock = DockStyle.Bottom; eopt.Height = 210;
            oScan = EasyChk("Сканировать", 8, 8, true);
            oWinlogon = EasyChk("Вернуть Winlogon Shell/Userinit в дефолт", 8, 32, true);
            oIFEO = EasyChk("Снять IFEO-блокировки (разблокировать Диспетчер/regedit)", 8, 56, true);
            oRestrict = EasyChk("Вернуть дефолт: ограничения политик (DisableTaskMgr и т.п.)", 8, 80, true);
            oAssoc = EasyChk("Вернуть дефолт: ассоциации .exe/.bat/.lnk + иконки", 8, 104, true);
            oDefuse = EasyChk("Обезвредить якоря (службы Start=4, IFEO) перед удалением", 8, 128, true);
            oQuar = EasyChk("Подозрительное -> в Карантин (с бэкапом, не удалять насовсем)", 8, 152, true);
            oWatch = EasyChk("Включить Watchdog (самолечение окна)", 8, 176, false);
            oShell = EasyChk("Запуск вместо Explorer  (после одобрения CVP)", 520, 128, false); oShell.Enabled = false;
            oBoot = EasyChk("Запуск до Windows + пре-бут скан  (после одобрения CVP)", 520, 152, false); oBoot.Enabled = false;
            eopt.Controls.Add(oScan); eopt.Controls.Add(oWinlogon); eopt.Controls.Add(oIFEO); eopt.Controls.Add(oRestrict);
            eopt.Controls.Add(oAssoc); eopt.Controls.Add(oDefuse); eopt.Controls.Add(oQuar); eopt.Controls.Add(oWatch);
            eopt.Controls.Add(oShell); eopt.Controls.Add(oBoot);
            Panel ecent = new Panel(); ecent.Dock = DockStyle.Fill;
            Button big = new Button(); big.Text = "ОЧИСТИТЬ\r\n(EASY)"; big.Font = new Font("Segoe UI", 15f, FontStyle.Bold);
            big.Width = 300; big.Height = 110; big.BackColor = Color.FromArgb(70, 160, 90); big.ForeColor = Color.White;
            lblEasy = new Label(); lblEasy.AutoSize = false; lblEasy.Width = 600; lblEasy.Height = 40; lblEasy.TextAlign = ContentAlignment.MiddleCenter;
            lblEasy.Text = "Одна кнопка: скан -> вернуть дефолты -> обезвредить -> карантин (по тумблерам ниже).";
            ecent.Controls.Add(big); ecent.Controls.Add(lblEasy);
            ecent.Resize += delegate {
                big.Left = (ecent.Width - big.Width) / 2; big.Top = (ecent.Height - big.Height) / 2 - 10;
                lblEasy.Left = (ecent.Width - lblEasy.Width) / 2; lblEasy.Top = big.Top + big.Height + 12;
            };
            tpE.Controls.Add(ecent); tpE.Controls.Add(eopt);
            big.Click += delegate { DoEasy(); };

            // ---- TAB 5: help ----
            TextBox help = new TextBox(); help.Dock = DockStyle.Fill; help.Multiline = true; help.ReadOnly = true;
            help.ScrollBars = ScrollBars.Vertical; help.BackColor = Color.White; help.Font = new Font("Segoe UI", 9f);
            help.Text = HelpText();
            tp5.Controls.Add(help);

            // wiring tab1
            btnDetect.Click += delegate { Detect(); };
            cboWin.SelectedIndexChanged += delegate { UpdateAccState(); };
            btnScan.Click += delegate { Scan(); };
            btnMark.Click += delegate { MarkSuspect(lv); };
            btnPreboot.Click += delegate { PrebootScan(); };
            btnDefuse.Click += delegate { DefuseChecked(lv); };
            btnQuar.Click += delegate { QuarantineChecked(lv); };
            btnDelete.Click += delegate { DeleteChecked(lv); };
            btnExport.Click += delegate { Export(); };
            this.TopMost = true;
            this.FormClosing += delegate(object s, FormClosingEventArgs e)
            {
                stopping = true; guarding = false; StopWatchdog();
                string uf = UnloadAll();
                if (uf.Length == 0) return;
                Watchdog.Log("выход: " + uf);
                if (e.CloseReason == CloseReason.UserClosing)
                    MessageBox.Show("Не все кусты реестра выгружены: " + uf + "\r\nОни останутся смонтированными до перезагрузки (или выгрузи вручную: reg unload).",
                        "RescueScan", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            };
            this.Load += delegate { AdoptWatchdog(); StartupPick(); RestoreGuardAfterRelaunch(); };
            // each start-up step on its own: one failing (unreadable manifest, WMI...) must not skip the others
            this.Shown += delegate
            {
                foreach (Action step in new Action[] { RefreshProcs, ShowDrives, RepairRefresh, QuarAutoFind, AccRefresh })
                    try { step(); } catch (Exception ex) { Watchdog.Log("старт: " + step.Method.Name + ": " + ex.Message); }
            };
        }

        // ================= STARTUP DISK PICKER =================
        void StartupPick()
        {
            Detect(); // fills cboWin with detected installs
            Form f = new Form(); f.Text = "RescueScan — выбор системы"; f.Width = 500; f.Height = 300;
            f.StartPosition = FormStartPosition.CenterScreen; f.FormBorderStyle = FormBorderStyle.FixedDialog;
            f.MinimizeBox = false; f.MaximizeBox = false; f.TopMost = true;
            Label l = new Label(); l.Left = 12; l.Top = 12; l.Width = 460; l.Height = 56;
            l.Text = "На каком диске установлена Windows для проверки?\r\n• в WinPE (с .NET) — выбери офлайн-установку (напр. D:\\Windows)\r\n• на живой ОС — свою (C:\\Windows)";
            ListBox lb = new ListBox(); lb.Left = 12; lb.Top = 72; lb.Width = 460; lb.Height = 130;
            foreach (object it in cboWin.Items) lb.Items.Add(it);
            if (lb.Items.Count == 0) lb.Items.Add("(Windows не найдена — выберешь вручную в приложении)");
            if (lb.Items.Count > 0) lb.SelectedIndex = 0;
            Button ok = new Button(); ok.Text = "Открыть"; ok.Left = 392; ok.Top = 214; ok.Width = 80; ok.DialogResult = DialogResult.OK;
            Button rescan = new Button(); rescan.Text = "Обновить список"; rescan.Left = 12; rescan.Top = 214; rescan.Width = 130;
            rescan.Click += delegate { Detect(); lb.Items.Clear(); foreach (object it in cboWin.Items) lb.Items.Add(it); if (lb.Items.Count > 0) lb.SelectedIndex = 0; };
            f.Controls.Add(l); f.Controls.Add(lb); f.Controls.Add(ok); f.Controls.Add(rescan);
            f.AcceptButton = ok;
            f.ShowDialog(this);
            if (lb.SelectedIndex >= 0 && lb.SelectedIndex < cboWin.Items.Count) cboWin.SelectedIndex = lb.SelectedIndex;
        }

        static string HelpText()
        {
            return
"RescueScan — защитный инструмент для чистки заражённой Windows. Написан на C# (.NET Framework 4.x, WinForms).\r\n" +
"Два режима: ОФЛАЙН (загрузился в WinPE, цель выключена — вирус не сопротивляется) и ЖИВОЙ (запущен в заражённой ОС от админа).\r\n" +
"Требуется .NET Framework 4.x. В WinPE НЕ запустится без компонентов WinPE-WMI + WinPE-NetFx в boot.wim. Стоковый WinRE («Дополнительные\r\n" +
"параметры -> Командная строка») .NET не содержит — там программа не стартует; RescueScan.cmd рядом с exe проверит это и объяснит.\r\n" +
"ГИБЕРНАЦИЯ: если офлайн-Windows выключена с «Быстрым запуском» (в <диск>\\hiberfil.sys живой образ памяти), при включении она продолжит\r\n" +
"   из образа — изменения отсюда потеряются или повредят диск. Скан это покажет, а любое изменение на этом диске спросит подтверждение.\r\n" +
"   Правильно: загрузиться в ту Windows, сделать «Перезагрузку» (или shutdown /s /full /t 0) и только потом чистить.\r\n" +
"\r\n" +
"ЦВЕТА: Красный = SUSPECT (сильный признак: temp, -enc/hidden, интерпретатор+загрузка, двойное расширение, exe в drivers).\r\n" +
"       Жёлтый = REVIEW (легит, но частое у малвари место: AppData/ProgramData/Downloads/автозагрузка) — просто глянь.\r\n" +
"\r\n" +
"1) АВТОЗАГРУЗКА (полная): «Найти ОС» -> «Сканировать» -> ВСЕ точки автозапуска. Кнопки: Обезвредить / Карантин / Удалить / Экспорт / Pre-boot.\r\n" +
"   Экспорт: CSV через «;» (кавычки удваиваются; ячейка, начинающаяся с = + - @, получает апостроф — формула из имени вируса не сработает).\r\n" +
"   Pre-boot (ESP/BCD): хранилища BCD (системное + \\EFI\\Microsoft\\Boot\\BCD каждого ESP с буквой) и файлы ESP — только ИНФОРМАЦИЯ,\r\n" +
"   кнопками не удаляется (загрузчики Linux/производителя легитимны): чинить вручную (bcdedit / bcdboot).\r\n" +
"   ОБЕЗВРЕДИТЬ (defuse): службе -> Start=4/ErrorControl=1, IFEO -> убрать только значение Debugger, Winlogon/BootExecute -> дефолт.\r\n" +
"   Делай ПЕРЕД удалением файла, иначе удаление boot-критичного бинаря даёт BSOD 0x7B (винда не грузится). Всё — с бэкапом в карантин.\r\n" +
"   НЕ УДАЛЯЮТСЯ, а возвращаются к дефолту Windows (любой кнопкой): Winlogon Shell/Userinit/VMApplet, BootExecute (законные строки autochk\r\n" +
"   остаются), SetupExecute (ожидающее обновление Windows не трогается), SafeBoot AlternateShell. Userinit берётся из SystemRoot цели.\r\n" +
"\r\n" +
"2) АВТОЗАПУСК (кратко): только Run/RunOnce/Планировщик/Startup — как «Автозагрузка» в Диспетчере задач Windows.\r\n" +
"\r\n" +
"3) ДИСПЕТЧЕР ЗАДАЧ: процессы с путём и риском. Завершить / Завершить дерево — сначала список и подтверждение. Дерево: сначала\r\n" +
"   родитель (чтобы не успел перезапустить детей), потом потомки, потом ещё пара свежих снимков — добить появившихся. Сам RescueScan,\r\n" +
"   его watchdog, Idle и System не завершаются; критические процессы Windows (smss, csrss, wininit, winlogon, services, lsass, в WinPE\r\n" +
"   winpeshl) — только после второго явного «Да» (иначе синий экран). PID, сменивший владельца после «Обновить», не трогается.\r\n" +
"   «Поверх всех окон». «Watchdog» — если вирус закроет RescueScan, напарник его перезапустит и запишет в лог (%TEMP%\\rescuescan.log);\r\n" +
"   перезапущенное окно снова управляет watchdog'ом (обычное закрытие его останавливает) и возвращает «Стеречь Winlogon».\r\n" +
"   По умолчанию выключен. Ограничение: «taskkill /f /im RescueScan.exe» убивает оба процесса сразу — против такого вируса чисти офлайн.\r\n" +
"\r\n" +
"4) ПРОВОДНИК: видит СКРЫТЫЕ и СИСТЕМНЫЕ файлы (серым/оранжевым). Красный = найден сканом. Кнопки: Запустить (ручной запуск exe,\r\n" +
"   если сломан шелл), Переименовать, Карантин, Удалить, Снять скрытие (убрать H/S/R), Кто ссылается (из какой автозагрузки стартует файл).\r\n" +
"   Запустить: .exe/.com — напрямую, БЕЗ ассоциаций (подменённый exefile не сработает с правами админа); .bat/.cmd — через cmd.exe после\r\n" +
"   предупреждения; всё остальное НЕ выполняется, а открывается как текст в Блокноте. Программа с IFEO-перехватом не запускается.\r\n" +
"   Красный «найден сканом» и «Кто ссылается» понимают пути цели: C:\\... из её реестра = D:\\... в WinPE, %SystemRoot%, %ProgramFiles%,\r\n" +
"   %ProgramData%, %APPDATA%/%TEMP% профиля, \\SystemRoot\\... (другие тома не пересчитываются).\r\n" +
"   Удалить: корни дисков и системные папки (Windows, Program Files, ProgramData, Users…) не удаляются; папка — только после второго\r\n" +
"   подтверждения; «только чтение» снимается; имена с точкой/пробелом в конце удаляются правильно; ссылки (junction) не обходятся.\r\n" +
"\r\n" +
"5) КАРАНТИН: папка <диск цели>\\RescueScan_Quarantine\\<дата_время> (НЕ на RAM-диске X: и не в %TEMP% — там всё пропадёт при перезагрузке).\r\n" +
"   Каждый элемент — свой бэкап: файл -> <N>_<имя>.quarantine (не запускается двойным кликом), реестр -> <N>.reg (точная копия всех типов;\r\n" +
"   значение — только оно, ключ — со всеми подключами; .reg можно импортировать и вручную после загрузки системы).\r\n" +
"   manifest.txt хранит, ЧТО и ОТКУДА (установка + куст + профиль + путь), поэтому «Восстановить» работает и в другом сеансе, и с живой ОС:\r\n" +
"   выбери ту же установку, нажми «Сканировать», затем «Восстановить» (если куст/профиль не смонтирован — будет понятный отказ).\r\n" +
"   Восстановление идёт от новых записей к старым; файл, лежащий сейчас на месте оригинала, не удаляется, а переименовывается.\r\n" +
"   Бэкап с изменённой контрольной суммой (SHA-256) или вне папки карантина не восстанавливается. «Найти последний» ищет на всех дисках.\r\n" +
"\r\n" +
"6) РЕМОНТ: Winlogon Shell/Userinit/AppInit/cmd AutoRun (+ их WOW64-копии). Красная строка = подмена. ВЫДЕЛИ строку -> «→ Дефолт» или «→ Своё…».\r\n" +
"   Кнопки: «Снять блокировки (политики+IFEO)» (DisableTaskMgr/DisableRegistryTools/DisableCMD, NoRun, DisallowRun + список, NoWinKeys, NoLogoff,\r\n" +
"   DisableLockWorkstation, NoDrives/NoViewOnDrive и др. — у машины и у КАЖДОГО профиля; на живой ОС и у всех вошедших HKU\\S-1-5-21-*;\r\n" +
"   IFEO: удаляется только значение Debugger, известные отладчики — Process Explorer, System Informer, Notepad++, windbg — остаются),\r\n" +
"   «Вернуть ассоциации» (.exe/.bat/.lnk+иконки). КАЖДОЕ изменение сначала сохраняется в карантин (можно вернуть).\r\n" +
"   «Стеречь Winlogon» — фоновый страж возвращает дефолт при подмене (живая ОС).\r\n" +
"\r\n" +
"7) АККАУНТЫ (только живая ОС + WMI): локальные юзеры. Колонки Отключён/Заблокирован/Пароль нужен (НЕ «есть ли пароль»!).\r\n" +
"   Сменить пароль (скрытый ввод дважды, через API, не через командную строку) / Включить-разблок / Удалить юзера / Удалить профиль.\r\n" +
"   Сброс пароля и удаление юзера = потеря его EFS-файлов и сохранённых паролей (DPAPI). Профиль удаляется, только если папка лежит прямо\r\n" +
"   в ProfilesDirectory (C:\\Users) и это не твой/чужой/системный профиль; нужно ввести имя юзера.\r\n" +
"   В WinPE и при выбранной офлайн-установке вкладка ОТКЛЮЧЕНА (там видны аккаунты самой WinPE) — офлайн-сброс пароля: chntpw / MS DaRT.\r\n" +
"\r\n" +
"8) ИЗИ-КНОПКА: одна кнопка по тумблерам: скан -> вернуть Winlogon/IFEO/ограничения/ассоциации+иконки -> обезвредить -> подозрительное в карантин -> watchdog.\r\n" +
"   Каждое изменение реестра сохраняется в карантин ДО изменения; уже исправленное предыдущим шагом повторно не трогается.\r\n" +
"   Тумблеры «Запуск вместо Explorer» и «Запуск до Windows/пре-бут» ВЫКЛЮЧЕНЫ (shell-hijack + boot-персистентность) — включим после одобрения CVP.\r\n" +
"\r\n" +
"ГРАНИЦЫ: чистит уровень ОС + загрузчик/ESP. Имплант в прошивку (BIOS/SPI) НЕ трогает — только перепрошивка. Офлайн-сброс пароля (правка SAM) — chntpw/DaRT.\r\n" +
"ОШИБКИ: непредвиденная ошибка показывается по-русски и пишется в лог (%TEMP%\\rescuescan.log); при аварийном выходе смонтированные\r\n" +
"   кусты RS_* выгружаются. Без System.Management (WinPE без WinPE-WMI) не работает только вкладка «Аккаунты».\r\n";
        }

        // ================= WATCHDOG control (user-mode) =================
        // Set by Program.Main for "--relaunched <watchdog pid> <event> <guard>": this GUI was restarted by its watchdog.
        internal static int RelaunchWatchdogPid; internal static string RelaunchEvent; internal static bool RelaunchGuard;
        string stopEvtName = "";
        EventWaitHandle guardEvt;    // "<stop event>_guard": set while the Winlogon guard is on (restored after a relaunch)
        bool adopting = false;       // chkWatch is being ticked by AdoptWatchdog: do not arm a second watchdog

        void StartWatchdog()
        {
            if (adopting) return;
            if (watchdogProc != null && !SafeExited(watchdogProc)) return;
            stopping = false;
            string name = Watchdog.NewEventName();
            EventWaitHandle ev = Watchdog.CreateEvent(name);
            if (ev == null)
            {
                Watchdog.Log("GUI: стоп-событие не создано — watchdog не запущен");
                lblProc.Text = "Watchdog не запущен: не удалось создать стоп-событие.";
                chkWatch.Checked = false;
                return;
            }
            stopEvt = ev; stopEvtName = name;
            guardEvt = Watchdog.CreateEvent(name + "_guard");
            SyncGuardFlag();
            SpawnWatchdog();
            Thread mt = new Thread(WatchdogMonitor); mt.IsBackground = true; mt.Start();
            lblProc.Text = "Watchdog вооружён. Лог: " + Watchdog.LogPath;
        }

        // A GUI relaunched by the watchdog takes it over: same stop event, monitor thread, guard state. Without this the
        // normal close of the relaunched GUI looked like a kill and the watchdog relaunched it again, forever.
        void AdoptWatchdog()
        {
            if (RelaunchEvent == null) return;
            EventWaitHandle ev = Watchdog.OpenEvent(RelaunchEvent);
            Process wd = null;
            try
            {
                wd = Process.GetProcessById(RelaunchWatchdogPid);
                string me = Process.GetCurrentProcess().ProcessName;
                if (!string.Equals(wd.ProcessName, me, StringComparison.OrdinalIgnoreCase)) wd = null;   // not our watchdog
            }
            catch { wd = null; }
            if (ev == null || wd == null)
            {
                Watchdog.Log("GUI: перезапущен watchdog'ом, но его нет (pid " + RelaunchWatchdogPid + ") — работаю без него");
                if (ev != null) try { ev.Set(); ev.Close(); } catch { }   // tell a watchdog we could not identify to stop
                return;
            }
            stopEvt = ev; stopEvtName = RelaunchEvent; watchdogProc = wd; stopping = false;
            guardEvt = Watchdog.OpenEvent(RelaunchEvent + "_guard");
            adopting = true;
            try { chkWatch.Checked = true; } finally { adopting = false; }
            Thread mt = new Thread(WatchdogMonitor); mt.IsBackground = true; mt.Start();
            Watchdog.Log("GUI: перезапущен watchdog'ом (pid " + wd.Id + "), watchdog снова под контролем");
            lblProc.Text = "Перезапущено watchdog'ом после закрытия/убийства. Watchdog вооружён. Лог: " + Watchdog.LogPath;
        }

        // After the startup picker: restore «Стеречь Winlogon» if it was on when the previous GUI died (live target only).
        void RestoreGuardAfterRelaunch()
        {
            if (RelaunchEvent == null || !RelaunchGuard) return;
            WinTarget t = cboWin.SelectedItem as WinTarget;
            if (t != null && t.Live) chkGuard.Checked = true;
            else Watchdog.Log("GUI: страж Winlogon не восстановлен — выбрана не живая ОС");
        }

        void SyncGuardFlag()
        {
            try { if (guardEvt != null) { if (guarding) guardEvt.Set(); else guardEvt.Reset(); } } catch { }
        }

        void SpawnWatchdog()
        {
            try
            {
                string exe = Application.ExecutablePath;
                ProcessStartInfo psi = new ProcessStartInfo(exe, Watchdog.WatchdogArgs(Process.GetCurrentProcess().Id, stopEvtName, exe));
                psi.UseShellExecute = false; psi.CreateNoWindow = true; psi.WindowStyle = ProcessWindowStyle.Hidden;
                try { psi.WorkingDirectory = Path.GetDirectoryName(exe); } catch { }
                watchdogProc = Process.Start(psi);
                Watchdog.Log("GUI: watchdog запущен (pid " + (watchdogProc != null ? watchdogProc.Id : 0) + ")");
            }
            catch (Exception ex) { Watchdog.Log("GUI: не смог запустить watchdog: " + ex.Message); }
        }

        // GUI is watchdog for its watchdog: respawn it if the virus kills it (bounded: no endless 1-second loop when the
        // exe can no longer be started).
        void WatchdogMonitor()
        {
            List<DateTime> spawns = new List<DateTime>();
            int fails = 0;
            while (!stopping)
            {
                try { if (watchdogProc != null) { while (!watchdogProc.WaitForExit(300)) if (stopping) return; } else Thread.Sleep(500); }
                catch { Thread.Sleep(500); }
                if (stopping) return;
                Watchdog.Log("GUI: watchdog УМЕР без команды -> вирус мог убить его. Перезапуск watchdog.");
                if (Watchdog.TooManyRelaunches(spawns, DateTime.Now)) { Watchdog.Log("GUI: watchdog убивают снова и снова — больше не перезапускаю."); return; }
                Process before = watchdogProc;
                SpawnWatchdog();
                if (watchdogProc == null || watchdogProc == before) { watchdogProc = null; fails++; if (fails >= 8) return; Thread.Sleep(Watchdog.BackoffMs(fails)); }
                else { fails = 0; spawns.Add(DateTime.Now); }
            }
        }

        void StopWatchdog()
        {
            bool had = stopEvt != null || (watchdogProc != null && !SafeExited(watchdogProc));
            stopping = true;
            try { if (stopEvt != null) stopEvt.Set(); } catch { }
            try { if (watchdogProc != null && !SafeExited(watchdogProc)) watchdogProc.Kill(); } catch { }
            stopEvt = null; watchdogProc = null;
            try { if (guardEvt != null) guardEvt.Close(); } catch { }
            guardEvt = null;
            if (had) Watchdog.Log("GUI: watchdog остановлен по команде.");
        }

        static bool SafeExited(Process p) { try { return p.HasExited; } catch { return true; } }

        void Detect()
        {
            cboWin.Items.Clear();
            bool miniNT = Reg.KeyExists("HKLM\\SYSTEM\\CurrentControlSet\\Control\\MiniNT");
            foreach (WinTarget t in ListTargets(RunningWinDir(), miniNT, delegate(string f) { return File.Exists(FsPath(f)); }))
                cboWin.Items.Add(t);
            if (cboWin.Items.Count > 0) { cboWin.SelectedIndex = 0; lblStatus.Text = "Найдено установок: " + cboWin.Items.Count; }
            else lblStatus.Text = "Windows не найдена на подключённых дисках.";
        }

        // The running system is the WinPE/WinRE rescue system (never a target) only when ...\Control\MiniNT exists AND it
        // runs from X: (the RAM disk). MiniNT alone proves nothing: malware creates it on an installed Windows to stop the
        // event log (Sigma 919f2ef0-be2d-4a7a-b635-eb2b41fde044 / 1a4bd6af-99ac-4466-b5b2-7b72b4a05462; MITRE ATT&CK
        // mitigation M1024), and one registry key must not hide the infected live OS from the list. The scan reports it.
        internal static bool IsRescueSystem(bool miniNT, string runWinDir)
        {
            return miniNT && !string.IsNullOrEmpty(runWinDir) && runWinDir.StartsWith("X:", StringComparison.OrdinalIgnoreCase);
        }

        // Installations <C..Z>:\Windows that have a SYSTEM hive file, plus the running OS wherever its Windows dir is.
        // The running OS is LIVE (labelled; MiniNT on it is shown); the WinPE/WinRE rescue system itself is left out.
        internal static List<WinTarget> ListTargets(string runWin, bool miniNT, Predicate<string> fileExists)
        {
            List<WinTarget> res = new List<WinTarget>();
            bool rescue = IsRescueSystem(miniNT, runWin), liveListed = false;
            for (char c = 'C'; c <= 'Z'; c++)
            {
                string wd = c + ":\\Windows";
                if (!fileExists(wd + "\\System32\\config\\SYSTEM")) continue;
                bool live = SamePath(wd, runWin);
                if (live && rescue) continue;
                if (live) liveListed = true;
                res.Add(new WinTarget(wd, live, live && miniNT ? "ключ MiniNT!" : ""));
            }
            if (!rescue && !liveListed && !string.IsNullOrEmpty(runWin) && runWin.Length > 3 && fileExists(runWin + "\\System32\\config\\SYSTEM"))
                res.Insert(0, new WinTarget(runWin, true, miniNT ? "ключ MiniNT!" : ""));   // e.g. C:\WINNT, D:\Win10
            return res;
        }

        // A 32-bit build on 64-bit Windows sees <running windir>\System32 redirected to SysWOW64 (only catroot(2),
        // driverstore, drivers\etc, logfiles and spool are exempt), so the live OS's hive files, drivers and Tasks would be
        // the wrong ones or missing: such paths go through Sysnative. Other installations' paths are never redirected.
        internal static string FsPath(string p)
        {
            bool wow = false;
            try { wow = Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess; } catch { }
            return FsPath(p, RunningWinDir(), wow);
        }

        internal static string FsPath(string p, string runWin, bool wow64)
        {
            if (!wow64 || string.IsNullOrEmpty(p) || string.IsNullOrEmpty(runWin)) return p;
            string w = runWin.TrimEnd('\\'), sys = w + "\\System32";
            if (p.StartsWith(sys, StringComparison.OrdinalIgnoreCase) && (p.Length == sys.Length || p[sys.Length] == '\\'))
                return w + "\\Sysnative" + p.Substring(sys.Length);
            return p;
        }

        // Windows dir of the running OS (from GetSystemDirectory, not from environment variables a virus could set).
        internal static string RunningWinDir()
        {
            try
            {
                string s = Environment.SystemDirectory;
                return string.IsNullOrEmpty(s) ? "" : Path.GetDirectoryName(s.TrimEnd('\\'));
            }
            catch { return ""; }
        }

        internal static bool SamePath(string a, string b)
        {
            if (string.IsNullOrEmpty(a) || string.IsNullOrEmpty(b)) return false;
            return string.Equals(NormDir(a), NormDir(b), StringComparison.OrdinalIgnoreCase);
        }

        static string NormDir(string d)
        {
            try { return Path.GetFullPath(d).TrimEnd('\\'); } catch { return d.TrimEnd('\\'); }
        }

        static string ReplaceCI(string s, string old, string rep)
        {
            int i = s.IndexOf(old, StringComparison.OrdinalIgnoreCase);
            while (i >= 0)
            {
                s = s.Substring(0, i) + rep + s.Substring(i + old.Length);
                i = s.IndexOf(old, i + rep.Length, StringComparison.OrdinalIgnoreCase);
            }
            return s;
        }

        // ProfileImagePath from the TARGET's ProfileList -> the profile folder; "" = not usable (UNC, relative, unknown %var%).
        // %SystemDrive%, %SystemRoot% and %windir% are expanded to the target, never to the running WinPE.
        // OFFLINE only the target's own volume is trusted: WinPE assigns drive letters anew, so the installation's C: is
        // e.g. D: now, and WinPE's C: may be a second installation or a USB disk - a profile there must never be mounted,
        // scanned and "cleaned" as a user of this target. So the letter is replaced by the target's. A profile that was on
        // ANOTHER volume of the installation (its letter differs from origSysDrive, the installation's own system drive
        // from its SystemRoot value; "" = unknown) cannot be located safely: "" and otherVolume = true (reported).
        internal static string ProfileDir(string pip, string winDir, bool live, string origSysDrive, out bool otherVolume)
        {
            otherVolume = false;
            if (string.IsNullOrEmpty(pip) || string.IsNullOrEmpty(winDir) || winDir.Length < 3) return "";
            string drive = winDir.Substring(0, 2), raw = pip.Trim();
            string p = ReplaceCI(ReplaceCI(ReplaceCI(raw, "%SystemDrive%", drive), "%SystemRoot%", winDir), "%windir%", winDir).TrimEnd('\\');
            if (p.Length < 3 || p[1] != ':' || p[2] != '\\' || p.IndexOf('%') >= 0) return "";   // UNC, relative, unknown %var%
            if (live) return p;
            if (!raw.StartsWith("%") && !string.IsNullOrEmpty(origSysDrive) && char.ToUpperInvariant(raw[0]) != char.ToUpperInvariant(origSysDrive[0]))
            {
                otherVolume = true;
                return "";
            }
            return drive + p.Substring(2);
        }

        // Profiles of the target: ProfileList (user SIDs -> ProfileImagePath) plus <drive>\Users\*, without duplicates.
        // {name, profile dir, SID or ""}. ProfileList entries whose folder is gone (deleted profiles) are skipped.
        List<string[]> DiscoverProfiles(StringBuilder warn)
        {
            List<string[]> res = new List<string[]>();
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (tgtSoft.Length > 0)
            {
                string orig = "";   // the installation's own system drive, e.g. C:
                if (!tgtLive)
                    foreach (string[] v in Reg.Values(tgtSoft + "\\Microsoft\\Windows NT\\CurrentVersion"))
                        if (v[0].Equals("SystemRoot", StringComparison.OrdinalIgnoreCase) && v[1].Length >= 3 && v[1][1] == ':' && v[1][2] == '\\') orig = v[1].Substring(0, 2);
                int other = 0; string otherEx = "";
                foreach (string sk in Reg.Subkeys(tgtSoft + "\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"))
                {
                    string sid = Last(sk);   // user accounts (local/domain, Azure AD) - not SYSTEM/LocalService/NetworkService
                    if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) && !sid.StartsWith("S-1-12-1-", StringComparison.OrdinalIgnoreCase)) continue;
                    string pip = "";
                    foreach (string[] v in Reg.Values(sk))
                        if (v[0].Equals("ProfileImagePath", StringComparison.OrdinalIgnoreCase)) pip = v[1];
                    bool ov;
                    string dir = ProfileDir(pip, tgtWinDir, tgtLive, orig, out ov);
                    if (ov) { other++; if (otherEx.Length == 0) otherEx = pip; continue; }
                    if (dir.Length == 0 || !Directory.Exists(dir)) continue;
                    if (seen.Add(NormDir(dir))) res.Add(new string[] { Last(dir), dir, sid });
                }
                if (other > 0) warn.Append("профили на других дисках исходной системы не проверены: " + other + " (напр. " + otherEx + "). ");
            }
            string usersDir = curDrive + "\\Users";
            try
            {
                if (Directory.Exists(usersDir))
                    foreach (string ud in Directory.GetDirectories(usersDir))
                    {
                        string name = Path.GetFileName(ud);
                        if (name.Equals("Default", StringComparison.OrdinalIgnoreCase) || name.Equals("Public", StringComparison.OrdinalIgnoreCase)) continue;
                        if (seen.Add(NormDir(ud))) res.Add(new string[] { name, ud, "" });
                    }
            }
            catch { }
            return res;
        }

        // Unloads every hive WE mounted; the target is no longer prepared afterwards. Returns "" or a Russian description
        // of what could NOT be unloaded (those stay mounted and are retried on the next rescan / on exit).
        string UnloadAll()
        {
            tgtReady = false; tgtSoft = ""; tgtSys = ""; tgtUsers.Clear(); tgtSysRoot = ""; tgtInstall = "";
            return mounts.UnloadAll();
        }

        // Prepares the target used by the scan AND by all repair actions: unloads old mounts; OFFLINE mounts SOFTWARE,
        // SYSTEM and the user hives of the selected Windows; LIVE (the running OS, whose hive files are in use) reads
        // HKLM\SOFTWARE, HKLM\SYSTEM and HKU\<SID> of logged-on users in place and mounts only the other users' hives.
        // Returns warnings for the status line ("" = all fine).
        string PrepareTarget(WinTarget t)
        {
            StringBuilder warn = new StringBuilder();
            string uf = UnloadAll();
            if (uf.Length > 0) warn.Append(uf + ". ");
            mounts.CleanupStale(warn);   // ALL RS_* left by a crashed / killed earlier run, not only the names reused below
            tgtWinDir = t.WinDir; tgtLive = t.Live;
            curDrive = t.WinDir.Substring(0, 2);   // D:
            if (!t.Live && Hiber.Active(curDrive))
                warn.Append("Windows на " + curDrive + " ГИБЕРНИРОВАНА (Быстрый запуск) — изменения отсюда могут потеряться: сначала «Перезагрузка» в ней. ");
            if (guarding && !tgtLive)   // the guard writes the RUNNING OS's Winlogon: only while that is the target
            {
                chkGuard.Checked = false; guarding = false;
                warn.Append("«Стеречь Winlogon» выключен: новая цель — не живая ОС. ");
            }
            if (tgtLive) { tgtSoft = "HKLM\\SOFTWARE"; tgtSys = "HKLM\\SYSTEM"; }
            else
            {
                string cfg = t.WinDir + "\\System32\\config";
                if (mounts.Mount("RS_SOFT", cfg + "\\SOFTWARE", warn) == 0) tgtSoft = "HKLM\\RS_SOFT";
                else warn.Append("SOFTWARE не смонтирован. ");
                if (mounts.Mount("RS_SYS", cfg + "\\SYSTEM", warn) == 0) tgtSys = "HKLM\\RS_SYS";
                else warn.Append("SYSTEM не смонтирован. ");
            }
            int next = 0, failed = 0;
            foreach (string[] p in DiscoverProfiles(warn))
            {
                string root = "", nt = p[1] + "\\NTUSER.DAT";
                if (tgtLive && p[2].Length > 0 && Reg.KeyExists("HKU\\" + p[2])) root = "HKU\\" + p[2];   // logged on: already loaded
                else if (File.Exists(nt)) root = mounts.MountUser(nt, warn, ref next, ref failed);
                tgtUsers.Add(new string[] { p[0], root, p[1], p[2] });
            }
            if (failed > 0) warn.Append("не смонтировано профилей: " + failed + ". ");
            string srv = "";
            if (tgtSoft.Length > 0)
                foreach (string[] v in Reg.Values(tgtSoft + "\\Microsoft\\Windows NT\\CurrentVersion"))
                    if (v[0].Equals("SystemRoot", StringComparison.OrdinalIgnoreCase)) srv = v[1];
            tgtSysRoot = Defaults.SystemRootFor(srv, tgtLive, RunningWinDir(), tgtWinDir);
            tgtInstall = InstallId(tgtWinDir, FsOps.VolumeSerial(tgtWinDir));
            tgtReady = true;
            UpdateAccState();
            return warn.ToString().Trim();
        }

        // ================= TASK MANAGER =================
        void RefreshProcs()
        {
            lvProc.Items.Clear();
            Process[] ps;
            try { ps = Process.GetProcesses(); } catch { return; }
            int sus = 0;
            foreach (Process p in ps)
            {
                string name = "", path = "", mem = "";
                try { name = p.ProcessName; } catch { }
                try { path = p.MainModule.FileName; } catch { path = "(нет доступа)"; }
                try { mem = (p.WorkingSet64 / 1048576) + " MB"; } catch { }
                string risk = Heur.Risk(path, false);
                if (risk == "" && ProcNameRisk(name)) risk = "REVIEW";
                ListViewItem it = new ListViewItem(new string[] { p.Id.ToString(), name, path, mem, risk });
                ProcRow row = new ProcRow(); row.Pid = p.Id; row.Name = name; row.Path = path;
                try { row.Start = p.StartTime; } catch { }
                it.Tag = row;
                if (risk == "SUSPECT") { it.BackColor = Color.FromArgb(255, 205, 205); sus++; }
                else if (risk == "REVIEW") it.BackColor = Color.FromArgb(255, 245, 205);
                lvProc.Items.Add(it);
            }
            lblProc.Text = "Процессов: " + lvProc.Items.Count + "   подозрительных путей: " + sus + "   (в WinRE это процессы WinPE)";
        }

        static bool ProcNameRisk(string n)
        {
            if (n == null) return false; string l = n.ToLower();
            string[] bad = { "mshta", "wscript", "cscript", "powershell", "rundll32", "regsvr32", "certutil", "bitsadmin", "ffmpeg" };
            foreach (string b in bad) if (l == b) return true;
            return false;
        }

        // A row of the task list: the PID AND its start time, so a PID reused since the last refresh is never killed.
        class ProcRow { public int Pid; public DateTime? Start; public string Name = "", Path = ""; }

        static DateTime? ProcStart(int pid)
        {
            try { using (Process p = Process.GetProcessById(pid)) return p.StartTime; } catch { return null; }
        }

        static string ProcPath(int pid)
        {
            try { using (Process p = Process.GetProcessById(pid)) return p.MainModule.FileName; } catch { return ""; }
        }

        // Kill pid only if it is still the process we listed (same start time; same image name when the start time was
        // unreadable). "" = killed, else the reason.
        static string KillChecked(int pid, DateTime? start, string name)
        {
            try
            {
                using (Process p = Process.GetProcessById(pid))
                {
                    if (start.HasValue)
                    {
                        DateTime now;
                        try { now = p.StartTime; } catch { now = start.Value; }   // cannot read: trust the name check below
                        if (now != start.Value) return "PID " + pid + " уже другой процесс";
                    }
                    else if (!string.IsNullOrEmpty(name))
                    {
                        string want = name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name.Substring(0, name.Length - 4) : name;
                        string have = ""; try { have = p.ProcessName; } catch { }
                        if (!string.Equals(want, have, StringComparison.OrdinalIgnoreCase)) return "PID " + pid + " уже другой процесс";
                    }
                    p.Kill();
                    return "";
                }
            }
            catch (ArgumentException) { return "PID " + pid + " уже завершён"; }
            catch (Exception ex) { return "PID " + pid + ": " + ex.Message; }
        }

        void KillProc(bool tree)
        {
            if (lvProc.SelectedItems.Count == 0) { MessageBox.Show("Выбери процесс."); return; }
            int self = Process.GetCurrentProcess().Id;
            int wd = 0; try { if (watchdogProc != null && !SafeExited(watchdogProc)) wd = watchdogProc.Id; } catch { }
            HashSet<int> never = ProcTree.Never(self, wd);
            string sysDir = ""; try { sysDir = Environment.SystemDirectory; } catch { }
            // ---- plan: the selected processes (and, for a tree, their descendants from a fresh snapshot) ----
            Dictionary<int, DateTime> members = new Dictionary<int, DateTime>();
            Dictionary<int, string> names = new Dictionary<int, string>();
            List<int> order = new List<int>();
            List<string> refused = new List<string>();
            string treeErr = ""; bool snapOk = false;
            foreach (ListViewItem it in lvProc.SelectedItems)
            {
                ProcRow r = it.Tag as ProcRow;
                if (r == null) continue;
                if (never.Contains(r.Pid)) { refused.Add(r.Pid + " " + r.Name + (r.Pid == self ? " (это RescueScan)" : r.Pid == wd ? " (watchdog RescueScan)" : " (системный)")); continue; }
                if (order.Contains(r.Pid)) continue;
                order.Add(r.Pid); names[r.Pid] = r.Name;
                if (r.Start.HasValue) members[r.Pid] = r.Start.Value;
                else if (tree) treeErr = "время старта " + r.Pid + " " + r.Name + " не читается — его потомки не ищутся";
            }
            Dictionary<int, DateTime?> startCache = new Dictionary<int, DateTime?>();
            Func<int, DateTime?> startOf = delegate(int pid)
            {
                DateTime? v; if (!startCache.TryGetValue(pid, out v)) { v = ProcStart(pid); startCache[pid] = v; }
                return v;
            };
            if (tree)
            {
                Dictionary<int, int> par = new Dictionary<int, int>(); Dictionary<int, string> snapNames = new Dictionary<int, string>();
                int err;
                if (!Native.Snapshot(par, snapNames, out err)) treeErr = "дерево процессов не прочитано (ошибка " + err + ") — завершаются только выбранные";
                else
                {
                    snapOk = true;
                    foreach (int c in ProcTree.Grow(par, startOf, members, never))
                    {
                        if (order.Contains(c)) continue;
                        order.Add(c); string nm; names[c] = snapNames.TryGetValue(c, out nm) ? nm : "";
                    }
                }
            }
            if (order.Count == 0) { MessageBox.Show("Нечего завершать: " + string.Join(", ", refused.ToArray()), "Диспетчер задач"); return; }
            // ---- confirmation: the full list; critical Windows processes need a second, explicit «Да» ----
            List<string> crit = new List<string>();
            StringBuilder list = new StringBuilder();
            for (int i = 0; i < order.Count; i++)
            {
                int pid = order[i];
                string path = ProcPath(pid);
                bool c = ProcTree.IsCritical(names[pid], path, sysDir);
                if (c) crit.Add(pid + " " + names[pid]);
                if (i < 25) list.AppendLine((c ? "!! " : "   ") + pid + "  " + names[pid] + (path.Length > 0 ? "  " + path : ""));
            }
            if (order.Count > 25) list.AppendLine("   … и ещё " + (order.Count - 25));
            if (MessageBox.Show((tree ? "Завершить дерево (сначала родитель, потом потомки):" : "Завершить:") + "\r\n" + list +
                    (refused.Count > 0 ? "\r\nНе трогаю: " + string.Join(", ", refused.ToArray()) + "\r\n" : "") +
                    (treeErr.Length > 0 ? "\r\n" + treeErr + "\r\n" : ""),
                    "Диспетчер задач", MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            HashSet<int> skipCrit = new HashSet<int>();
            if (crit.Count > 0 && MessageBox.Show("КРИТИЧЕСКИЕ процессы Windows:\r\n" + string.Join("\r\n", crit.ToArray()) +
                    "\r\n\r\nИх завершение = синий экран CRITICAL_PROCESS_DIED (в WinPE — перезагрузка, всё несохранённое пропадёт).\r\n" +
                    "Завершить и их тоже? «Нет» — завершить всё остальное, а их пропустить.",
                    "ВНИМАНИЕ", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                foreach (int pid in order) if (ProcTree.IsCritical(names[pid], ProcPath(pid), sysDir)) skipCrit.Add(pid);
            // ---- kill: root first (a respawning parent dies before it can restart its children) ----
            int ok = 0, skipped = 0; List<string> fails = new List<string>();
            foreach (int pid in order)
            {
                if (skipCrit.Contains(pid)) { skipped++; continue; }
                DateTime st; DateTime? s = members.TryGetValue(pid, out st) ? (DateTime?)st : null;
                string e = KillChecked(pid, s, names[pid]);
                if (e.Length == 0) ok++; else fails.Add(e);
            }
            // ---- then descendants started meanwhile: fresh snapshots, a bounded number of rounds ----
            if (tree && snapOk)
            {
                for (int round = 0; round < 5; round++)
                {
                    Dictionary<int, int> par = new Dictionary<int, int>(); Dictionary<int, string> snapNames = new Dictionary<int, string>();
                    int err;
                    if (!Native.Snapshot(par, snapNames, out err)) break;
                    startCache.Clear();
                    List<int> more = ProcTree.Grow(par, startOf, members, never);
                    if (more.Count == 0) break;
                    foreach (int pid in more)
                    {
                        string nm; snapNames.TryGetValue(pid, out nm);
                        if (ProcTree.IsCritical(nm, ProcPath(pid), sysDir)) { skipped++; continue; }   // never without the explicit «Да» above
                        string e = KillChecked(pid, members[pid], nm);
                        if (e.Length == 0) ok++; else fails.Add(e);
                    }
                    Thread.Sleep(150);
                }
            }
            lblProc.Text = (tree ? "Дерево: завершено " : "Завершено: ") + ok + "   ошибок: " + fails.Count +
                (skipped > 0 ? "   пропущено критических: " + skipped : "") +
                (treeErr.Length > 0 ? "   " + treeErr : "") +
                (fails.Count > 0 ? "   (" + string.Join("; ", fails.GetRange(0, Math.Min(3, fails.Count)).ToArray()) + ")" : "");
            RefreshProcs();
        }

        // ================= EXPLORER =================
        void ShowDrives()
        {
            lvFiles.Items.Clear(); curPath = ""; txtPath.Text = "";
            foreach (DriveInfo d in DriveInfo.GetDrives())
            {
                ListViewItem it = new ListViewItem(new string[] { d.Name, "<диск>", "", "", "" });
                it.Tag = "D|" + d.Name;
                lvFiles.Items.Add(it);
            }
            lblFiles.Text = "Диски. Двойной клик — открыть. Красный = подозрительный / найден сканом.";
        }

        void Nav(string path)
        {
            if (string.IsNullOrEmpty(path)) { ShowDrives(); return; }
            if (!Directory.Exists(path)) { lblFiles.Text = "Нет папки: " + path; return; }
            lvFiles.Items.Clear(); curPath = path; txtPath.Text = path;
            int red = 0;
            try
            {
                DirectoryInfo di = new DirectoryInfo(path);
                foreach (DirectoryInfo d in di.GetDirectories())
                {
                    ListViewItem it = new ListViewItem(new string[] { d.Name, "<папка>", "", AttrStr(d.Attributes), Safe(d.LastWriteTime) });
                    it.Tag = "D|" + d.FullName;
                    if (ColorFile(it, d.FullName, d.Attributes)) red++;
                    lvFiles.Items.Add(it);
                }
                foreach (FileInfo fi in di.GetFiles())
                {
                    ListViewItem it = new ListViewItem(new string[] { fi.Name, "файл", fi.Length.ToString("N0"), AttrStr(fi.Attributes), Safe(fi.LastWriteTime) });
                    it.Tag = "F|" + fi.FullName;
                    if (ColorFile(it, fi.FullName, fi.Attributes)) red++;
                    lvFiles.Items.Add(it);
                }
                lblFiles.Text = "Элементов: " + lvFiles.Items.Count + "   подозрительных (красный): " + red + "   (скрытые/системные показаны)";
            }
            catch (Exception ex) { lblFiles.Text = "Ошибка: " + ex.Message; }
        }

        // returns true if flagged red
        bool ColorFile(ListViewItem it, string full, FileAttributes attr)
        {
            bool hidden = (attr & FileAttributes.Hidden) != 0;
            bool system = (attr & FileAttributes.System) != 0;
            bool sus = Heur.Risk(full, false) == "SUSPECT" || flagged.Contains(full.ToLowerInvariant());
            if (sus) { it.BackColor = Color.FromArgb(255, 205, 205); return true; }
            if (hidden && system) { it.BackColor = Color.FromArgb(255, 232, 200); return false; } // скрыто+система = оранжевый
            if (hidden) it.ForeColor = Color.Gray;
            return false;
        }

        static string AttrStr(FileAttributes a)
        {
            string s = "";
            if ((a & FileAttributes.Hidden) != 0) s += "H";
            if ((a & FileAttributes.System) != 0) s += "S";
            if ((a & FileAttributes.ReadOnly) != 0) s += "R";
            if ((a & FileAttributes.Archive) != 0) s += "A";
            return s;
        }

        static string Safe(DateTime d) { try { return d.ToString("yyyy-MM-dd HH:mm"); } catch { return ""; } }

        void NavUp()
        {
            if (string.IsNullOrEmpty(curPath)) return;
            try { DirectoryInfo p = Directory.GetParent(curPath); if (p == null) ShowDrives(); else Nav(p.FullName); }
            catch { ShowDrives(); }
        }

        void OpenSelected()
        {
            if (lvFiles.SelectedItems.Count == 0) return;
            string tag = (string)lvFiles.SelectedItems[0].Tag;
            if (tag.StartsWith("D|")) Nav(tag.Substring(2)); // папки открываем; файлы НЕ запускаем
        }

        // Why a path must not be deleted from the Explorer tab ("" = may be deleted): drive roots and the folders
        // Windows cannot live without (Windows, System32/SysWOW64/WinSxS, Program Files*, ProgramData, Users, System
        // Volume Information, Boot, Recovery) on ANY drive, and the target's own Windows folder wherever it is.
        internal static string ProtectedPath(string p, string targetWinDir)
        {
            string x = (p ?? "").Trim();
            if (x.StartsWith("\\\\?\\")) x = x.Substring(4);
            x = x.TrimEnd('\\', '/');
            if (x.Length <= 2) return "корень диска";
            if (x.Length < 3 || x[1] != ':' || x[2] != '\\') return x.StartsWith("\\\\") && x.Substring(2).Split('\\').Length <= 2 ? "корень сетевой папки" : "";
            if (!string.IsNullOrEmpty(targetWinDir) && x.Equals(targetWinDir.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) return "папка Windows выбранной системы";
            string rest = x.Substring(2);
            string[] crit = { "\\Windows", "\\Windows\\System32", "\\Windows\\SysWOW64", "\\Windows\\WinSxS", "\\Windows\\System32\\config",
                "\\Program Files", "\\Program Files (x86)", "\\ProgramData", "\\Users", "\\System Volume Information", "\\Boot", "\\Recovery", "\\EFI" };
            foreach (string c in crit) if (rest.Equals(c, StringComparison.OrdinalIgnoreCase)) return "системная папка " + x;
            if (!string.IsNullOrEmpty(targetWinDir))
                foreach (string c in new string[] { "\\System32", "\\SysWOW64", "\\WinSxS", "\\System32\\config", "\\System32\\drivers" })
                    if (x.Equals(targetWinDir.TrimEnd('\\') + c, StringComparison.OrdinalIgnoreCase)) return "системная папка " + x;
            return "";
        }

        void DeleteFile()
        {
            if (lvFiles.SelectedItems.Count == 0) { MessageBox.Show("Выбери файл/папку."); return; }
            if (!HiberGuardFiles("Удалить")) return;
            List<string> files = new List<string>(), dirs = new List<string>(), refused = new List<string>();
            foreach (ListViewItem it in lvFiles.SelectedItems)
            {
                string tag = (string)it.Tag, p = tag.Substring(2);
                string why = ProtectedPath(p, tgtWinDir);
                if (why.Length > 0) { refused.Add(p + " — " + why); continue; }
                if (tag.StartsWith("F|")) files.Add(p); else dirs.Add(p);
            }
            if (refused.Count > 0)
                MessageBox.Show("Это не удаляется (иначе Windows не загрузится или пропадут все данные):\r\n" + string.Join("\r\n", refused.ToArray()), "Удаление",
                    MessageBoxButtons.OK, MessageBoxIcon.Stop);
            if (files.Count + dirs.Count == 0) return;
            if (MessageBox.Show("Удалить выбранное (файлов: " + files.Count + ", папок: " + dirs.Count + ")? Необратимо, без бэкапа (для бэкапа файла — «Карантин»).", "Подтверждение",
                MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            if (dirs.Count > 0)
            {
                List<string> show = dirs.GetRange(0, Math.Min(dirs.Count, 10));
                if (MessageBox.Show("ВНИМАНИЕ: папки удаляются ЦЕЛИКОМ, со всем содержимым:\r\n\r\n" + string.Join("\r\n", show.ToArray()) + (dirs.Count > 10 ? "\r\n…" : "") +
                    "\r\n\r\nТочно удалить эти папки?", "Удаление папок", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            }
            int ok = 0, fail = 0; string first = "";
            foreach (string p in files)
            {
                string err;
                if (FsOps.DeleteFile(p, out err)) ok++; else { fail++; if (first.Length == 0) first = Path.GetFileName(p) + ": " + err; }
            }
            foreach (string d in dirs)
            {
                int failed = 0; string err = "";
                if (FsOps.DeleteTree(d, ref failed, ref err)) ok++; else { fail++; if (first.Length == 0) first = err; }
            }
            lblFiles.Text = "Удалено: " + ok + "   ошибок: " + fail + (first.Length > 0 ? "   (" + Reg.OneLine(first, 160) + ")" : ""); Nav(curPath);
        }

        void Unhide()
        {
            if (lvFiles.SelectedItems.Count == 0) { MessageBox.Show("Выбери элемент."); return; }
            if (!HiberGuardFiles("Снять скрытие")) return;
            foreach (ListViewItem it in lvFiles.SelectedItems)
            {
                string p = ((string)it.Tag).Substring(2);
                int a = FsOps.Attrs(p);
                if (a != -1) FsOps.SetAttrs(p, a & ~(int)(FileAttributes.Hidden | FileAttributes.System | FileAttributes.ReadOnly));
            }
            Nav(curPath);
        }

        void RenameSelected()
        {
            if (lvFiles.SelectedItems.Count != 1) { MessageBox.Show("Выбери ровно один элемент."); return; }
            string tag = (string)lvFiles.SelectedItems[0].Tag;
            if (!tag.StartsWith("F|") && !tag.StartsWith("D|")) return;
            if (!HiberGuardFiles("Переименовать")) return;
            string p = tag.Substring(2);
            string parent = null;
            try { parent = Path.GetDirectoryName(p.TrimEnd('\\')); } catch { }
            if (string.IsNullOrEmpty(parent)) { MessageBox.Show("Диск нельзя переименовать здесь."); return; }
            string old = Path.GetFileName(p.TrimEnd('\\'));
            string nn = Prompt("Новое имя для «" + old + "»", old);
            if (nn == null) return; nn = nn.Trim();
            if (nn.Length == 0 || nn == old) return;
            if (nn.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || nn.IndexOfAny(new char[] { '\\', '/', ':' }) >= 0 || nn == "." || nn == "..")
            { MessageBox.Show("Недопустимое имя: только имя, без пути и символов \\ / : * ? \" < > |"); return; }
            string dst = Path.Combine(parent, nn);
            try { if (tag.StartsWith("F|")) File.Move(p, dst); else Directory.Move(p, dst); }
            catch (Exception ex) { MessageBox.Show(ex.Message); }
            Nav(curPath);
        }

        // The payload of a finding's value as THIS session sees the file: the target's env vars (%SystemRoot%, %APPDATA% of
        // the profile the value came from ...), \SystemRoot\, and its system drive letter mapped to the current one.
        string TargetPayload(Finding x)
        {
            string prof = "";
            if (x.Location != null)
                foreach (string[] u in tgtUsers)
                    if (u[1].Length > 0 && (x.Location.Equals(u[1], StringComparison.OrdinalIgnoreCase) || x.Location.StartsWith(u[1] + "\\", StringComparison.OrdinalIgnoreCase)))
                    { prof = u[2]; break; }
            return PathMap.Payload(x.Value, tgtSysRoot, tgtWinDir, prof);
        }

        // ---- Scan ----
        void Scan()
        {
            WinTarget t = cboWin.SelectedItem as WinTarget;
            if (t == null) { MessageBox.Show("Сначала выбери установку Windows."); return; }
            Cursor.Current = Cursors.WaitCursor;
            lv.Items.Clear();
            // the PREVIOUS target's findings must not stay actionable (Easy, «Автозапуск (кратко)», «Кто ссылается»)
            // once PrepareTarget below has switched the target - also not if something fails later in this scan
            lastFindings = new List<Finding>(); flagged.Clear();
            if (lvSimple != null) lvSimple.Items.Clear();
            Reg.TakeDenied();                                     // unreadable keys are collected per scan
            string winDir = t.WinDir;                             // e.g. D:\Windows
            // (re)mount the hives of THIS installation (live: read in place); all repair actions then use this target
            string warn = PrepareTarget(t);

            List<Finding> f = new List<Finding>();
            string SOFT = tgtSoft;                                // "" = hive not mounted: nothing is read from it
            string SYS = tgtSys;

            List<string> cut = new List<string>();   // registry walks that hit a bound: told to the user
            string ccs = "ControlSet001";
            try   // a module that throws (a hostile folder / key) must not discard everything found so far
            {
            // ---- HKLM Run family ----
            AddValues(f, "Run (HKLM)", SOFT + "\\Microsoft\\Windows\\CurrentVersion\\Run");
            AddValues(f, "RunOnce (HKLM)", SOFT + "\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
            AddValues(f, "Run (HKLM WOW64)", SOFT + "\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run");
            AddValues(f, "RunOnce (HKLM WOW64)", SOFT + "\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce");

            // ---- Winlogon ----
            ScanWinlogon(f, SOFT, tgtSysRoot);

            // ---- AppInit_DLLs ----
            string winkey = SOFT + "\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
            foreach (string[] v in Reg.Values(winkey))
            {
                if (v[0].Equals("AppInit_DLLs", StringComparison.OrdinalIgnoreCase) && v[1].Trim().Length > 0)
                    Add(f, "AppInit_DLLs", v[0], v[1], winkey, "SUSPECT", 0, winkey, v[0], null);
            }

            // ---- Command Processor AutoRun (cmd) ----
            foreach (string cp in new string[] { SOFT + "\\Microsoft\\Command Processor", SOFT + "\\Wow6432Node\\Microsoft\\Command Processor" })
                foreach (string[] v in Reg.Values(cp))
                    if (v[0].Equals("AutoRun", StringComparison.OrdinalIgnoreCase))
                        Add(f, "cmd AutoRun", v[0], v[1], cp, "SUSPECT", 0, cp, v[0], null);

            // ---- IFEO debugger hijacks ----
            ScanIfeo(f, SOFT, cut);

            // ---- extra SOFTWARE persistence (Active Setup, Notify, Policies, SilentProcessExit, class hijack) ----
            ScanExtraSoftware(f, SOFT);
            ScanMachineExtras(f, SOFT);   // RunOnceEx, AeDebug, hidden users, Defender exclusions

            // ---- SYSTEM: control set, BootExecute, Services ----
            // the set the NEXT boot uses is Select\Default (Current only records the last boot): a mismatch is shown
            string selWarn;
            ccs = PickControlSet(Reg.Values(SYS + "\\Select"), delegate(string cs) { return Reg.KeyExists(SYS + "\\" + cs); }, out selWarn);
            if (selWarn.Length > 0 && SYS.Length > 0) Add(f, "ControlSet (Select)", ccs, selWarn, SYS + "\\Select", "REVIEW", 3, null, null, null);
            // MiniNT on an installed Windows: after a reboot the event log stops writing (defence evasion; Windows also
            // behaves as WinPE in places). Info only if the target itself looks like a WinPE (InstallationType).
            string mnt = SYS + "\\" + ccs + "\\Control\\MiniNT";
            if (SYS.Length > 0 && Reg.KeyExists(mnt))
            {
                bool pe = false;
                foreach (string[] v in Reg.Values(SOFT + "\\Microsoft\\Windows NT\\CurrentVersion"))
                    if (v[0].Equals("InstallationType", StringComparison.OrdinalIgnoreCase) && v[1].Trim().Equals("WindowsPE", StringComparison.OrdinalIgnoreCase)) pe = true;
                if (pe) Add(f, "MiniNT", "MiniNT", "(цель похожа на WinPE: InstallationType = WindowsPE)", mnt, "REVIEW", 3, null, null, null);
                else Add(f, "MiniNT (журнал событий выкл.)", "MiniNT", "(ключ WinPE на установленной Windows: журнал событий не пишется — трюк вирусов)", mnt, "SUSPECT", 1, mnt, null, null);
            }
            string sm = SYS + "\\" + ccs + "\\Control\\Session Manager";
            if (SYS.Length > 0) ScanBootExecute(f, sm);
            ScanSetupKey(f, SYS);                                 // SYSTEM\Setup CmdLine (hive root, not the control set)
            if (SYS.Length > 0) ScanDataBasePath(f, SYS + "\\" + ccs);
            // Safe Mode with Command Prompt runs AlternateShell instead of Explorer (default cmd.exe): reset, never delete
            string sb = SYS + "\\" + ccs + "\\Control\\SafeBoot";
            if (SYS.Length > 0)
                foreach (string[] v in Reg.Values(sb))
                    if (v[0].Equals("AlternateShell", StringComparison.OrdinalIgnoreCase))
                        AddReset(f, "SafeBoot AlternateShell", sb, v[0], v[1], Defaults.AlternateShellClean(v[1]) ? "" : "SUSPECT", Defaults.AlternateShell, RegistryValueKind.String);
            // services / drivers / svchost ServiceDll: SUSPECT and REVIEW ones are listed
            ScanServices(f, SYS + "\\" + ccs, cut);
            // svchost-hosted ServiceDll, LSA packages, Print Monitors, SessionMgr extras
            ScanExtraSystem(f, SYS + "\\" + ccs, cut);

            // ---- Per-user hives (mounted / located by PrepareTarget) ----
            string usersDir = curDrive + "\\Users";
            foreach (string[] tu in tgtUsers)
            {
                string name = tu[0];
                string U = tu[1];
                if (U.Length == 0) continue;   // hive not available
                ScanUserHive(f, name, U);
            }

            // ---- Filesystem: Startup folders ----
            AddStartup(f, curDrive + "\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp", "Startup (все)");
            string[] uds = new string[0];
            try { if (Directory.Exists(usersDir)) uds = Directory.GetDirectories(usersDir); } catch { }
            foreach (string ud in uds)
                AddStartup(f, ud + "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", "Startup [" + Path.GetFileName(ud) + "]");
            foreach (string[] tu in tgtUsers)   // profiles from ProfileList that live outside <drive>\Users
                if (!SamePath(Path.GetDirectoryName(tu[2]), usersDir))
                    AddStartup(f, tu[2] + "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", "Startup [" + tu[0] + "]");

            // ---- Drivers folder (нестандартные файлы) ----
            ScanDrivers(f, winDir);
            ScanHosts(f, FsPath(winDir + "\\System32\\drivers\\etc\\hosts"), tgtLive);

            // ---- Scheduled tasks: XML files + registry TaskCache (+ anti-checker/watchdog) ----
            ScanTasks(f, FsPath(winDir + "\\System32\\Tasks"), SOFT, tgtLive, cut);
            }
            catch (Exception ex)
            {
                Add(f, "Ошибка скана", ex.GetType().Name, "(скан прерван: " + Reg.OneLine(ex.Message, 200) + " — показано то, что найдено до ошибки)", "", "REVIEW", 3, null, null, null);
            }

            // keys that exist but could not be read: the scan is blind there (a deny-ACL is a known hiding trick; offline
            // the scan runs as SYSTEM, so a denied key is deliberate; live, a few keys may be protected legitimately)
            List<string> dn = Reg.TakeDenied();
            for (int i = 0; i < dn.Count; i++)
            {
                if (i == 50) { Add(f, "Нет доступа к ключу", "…", "(и ещё " + (dn.Count - 50) + ")", "", tgtLive ? "REVIEW" : "SUSPECT", 3, null, null, null); break; }
                Add(f, "Нет доступа к ключу", Last(dn[i]), "(ключ есть, но не читается: права (DACL) изменены? — скан его не видит, проверь вручную)",
                    dn[i], tgtLive ? "REVIEW" : "SUSPECT", 3, null, null, null);
            }
            if (cut.Count > 0)
                warn = (warn.Length > 0 ? warn + " " : "") + "обход " + string.Join("/", cut.ToArray()) + " неполный (слишком много или слишком глубоко вложенных ключей) — часть записей могла не попасть в скан.";

            // populate + build flagged-path set for the Explorer highlight
            lastFindings = f;
            flagged.Clear();
            foreach (Finding x in f)
            {
                if (x.Kind == 2 && x.DelPath != null) flagged.Add(x.DelPath.ToLowerInvariant());
                if (x.Risk == "SUSPECT") { string pp = TargetPayload(x); if (pp.Length > 0) flagged.Add(pp.ToLowerInvariant()); }
                AddRow(x);
            }
            Cursor.Current = Cursors.Default;
            int susp = 0; foreach (Finding x in f) if (x.Risk == "SUSPECT") susp++;
            RepairRefresh();
            SimpleRefresh();   // (sets "Нажми «Сканировать»" when nothing was found: the status below must come after it)
            lblStatus.Text = "Записей: " + f.Count + "   подозрительных: " + susp + "   (ControlSet: " + ccs + ")   цель: " + TargetName()
                + (warn.Length > 0 ? "   ВНИМАНИЕ: " + warn : "");
            if (tgtSoft.Length == 0 || tgtSys.Length == 0)
            {
                string msg = "Кусты реестра системы " + tgtWinDir + " смонтированы не все:\r\n" + warn + "\r\n\r\nСкан реестра НЕПОЛНЫЙ.\r\n";
                if (tgtSoft.Length == 0)
                    msg += "• SOFTWARE не смонтирован: Run, Winlogon, IFEO, политики и т.п. НЕ проверены. «Ремонт», «Снять блокировки», " +
                        "«Вернуть ассоциации» и Изи-кнопка для этой цели будут отменены (на живую ОС программа не переключается).\r\n";
                if (tgtSys.Length == 0)
                    msg += "• SYSTEM не смонтирован: службы, драйверы, BootExecute, LSA и т.п. НЕ проверены." +
                        (tgtSoft.Length > 0 ? " Ремонт куста SOFTWARE (Winlogon, IFEO, политики, ассоциации) при этом работает." : "") + "\r\n";
                MessageBox.Show(msg, "RescueScan", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        // Select values -> the control set to scan: Default (the next boot), else Current, else LastKnownGood, else 001;
        // a set that does not exist is skipped. warn: why the pick is worth a look ("" = Default = Current, present).
        internal static string PickControlSet(List<string[]> select, Predicate<string> exists, out string warn)
        {
            int def = -1, cur = -1, lkg = -1;
            foreach (string[] v in select)
            {
                if (v[2] != "REG_DWORD") continue;
                int n; try { n = Convert.ToInt32(v[1].Substring(2), 16); } catch { continue; }
                if (n < 1 || n > 999) continue;
                if (v[0].Equals("Default", StringComparison.OrdinalIgnoreCase)) def = n;
                else if (v[0].Equals("Current", StringComparison.OrdinalIgnoreCase)) cur = n;
                else if (v[0].Equals("LastKnownGood", StringComparison.OrdinalIgnoreCase)) lkg = n;
            }
            warn = "";
            foreach (int n in new int[] { def, cur, lkg, 1 })
            {
                if (n < 0) continue;
                string cs = "ControlSet" + n.ToString("D3");
                if (!exists(cs)) { if (n == def) warn = "Select\\Default = " + n + ", но " + cs + " нет; "; continue; }
                if (def > 0 && cur > 0 && def != cur) warn += "Select\\Default = " + def + ", Current = " + cur + ": следующая загрузка возьмёт Default — сканируется " + cs;
                else if (n != def) warn += "сканируется " + cs;
                return cs;
            }
            return "ControlSet001";
        }

        // One task as the registry TaskCache knows it (Windows 8+ runs tasks from here, not from the XML: research
        // windows-semantics Q3). Keys = every TaskCache key of this task (removed together with it, backed up).
        internal class TaskReg
        {
            public string Rel = "", TreeKey = "", Id = "";
            public bool HasSD, HasActions, PathOk;
            public int Index = -1;
            public List<string[]> Acts;          // parsed Actions (null = none / not parsed)
            public string Raw = "";              // printable strings of an unparsed Actions blob
            public List<string> Keys = new List<string>();
        }

        // TaskCache\Tree walked recursively (bounded): relative task path (lower case) -> TaskReg.
        internal static Dictionary<string, TaskReg> ReadTaskCache(string SOFT, List<string> cut)
        {
            Dictionary<string, TaskReg> res = new Dictionary<string, TaskReg>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrEmpty(SOFT)) return res;
            string tc = SOFT + "\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache";
            int budget = 20000;
            TreeWalk(tc, tc + "\\Tree", "", 0, ref budget, res);
            if (budget <= 0 && cut != null) cut.Add("TaskCache");
            return res;
        }

        static void TreeWalk(string tc, string key, string rel, int depth, ref int budget, Dictionary<string, TaskReg> res)
        {
            if (--budget < 0) return;
            if (rel.Length > 0)
            {
                string id = null; bool sd = false; int index = -1;
                foreach (string[] v in Reg.Values(key))
                {
                    if (v[0].Equals("Id", StringComparison.OrdinalIgnoreCase)) id = v[1].Trim();
                    else if (v[0].Equals("SD", StringComparison.OrdinalIgnoreCase)) sd = v[1].Length > 0;
                    else if (v[0].Equals("Index", StringComparison.OrdinalIgnoreCase) && v[2] == "REG_DWORD")
                        try { index = Convert.ToInt32(v[1].Substring(2), 16); } catch { }
                }
                if (id != null)
                {
                    TaskReg t = new TaskReg();
                    t.Rel = rel; t.TreeKey = key; t.Id = id; t.HasSD = sd; t.Index = index;
                    t.Keys.Add(key);
                    if (Heur.IsGuid(id))   // a forged Id must never address another key
                    {
                        string tk = tc + "\\Tasks\\" + id;
                        string path = null;
                        foreach (string[] v in Reg.Values(tk))
                            if (v[0].Equals("Path", StringComparison.OrdinalIgnoreCase)) path = v[1];
                        // Tasks\{Id} belongs to THIS task only if its Path says so (another Tree entry may point at the
                        // Id of a Windows task)
                        t.PathOk = path != null && path.Trim().TrimStart('\\').Equals(rel, StringComparison.OrdinalIgnoreCase);
                        if (t.PathOk)
                        {
                            t.Keys.Add(tk);
                            byte[] blob = null;
                            using (RegistryKey k = Reg.OpenKey(tk, false))
                                if (k != null) try { blob = k.GetValue("Actions") as byte[]; } catch { }
                            if (blob != null)
                            {
                                t.HasActions = true;
                                t.Acts = Heur.TaskCacheActions(blob);
                                if (t.Acts == null) t.Raw = string.Join(" | ", Heur.PrintableStrings(blob, 4).ToArray());
                            }
                            foreach (string trig in new string[] { "Boot", "Logon", "Plain", "Maintenance" })
                                if (Reg.KeyExists(tc + "\\" + trig + "\\" + id)) t.Keys.Add(tc + "\\" + trig + "\\" + id);
                        }
                    }
                    res[rel] = t;
                    return;   // a task key has no task below it
                }
            }
            if (depth >= 32) return;
            foreach (string sk in Reg.Subkeys(key))
                TreeWalk(tc, sk, (rel.Length > 0 ? rel + "\\" : "") + sk.Substring(sk.LastIndexOf('\\') + 1), depth + 1, ref budget, res);
        }

        // The command lines of a list of actions ("exec" -> command + arguments, "com" -> "COM-обработчик {clsid}").
        static string ActText(List<string[]> acts)
        {
            List<string> parts = new List<string>();
            foreach (string[] a in acts)
                parts.Add(a[0] == "exec" ? (a[1] + " " + a[2]).Trim() : "COM-обработчик " + a[1] + (a[2].Length > 0 ? " " + a[2] : ""));
            return string.Join("  ||  ", parts.ToArray());
        }

        // Risk of every exec action (command + arguments only: never the whole XML, whose xmlns is an http URL);
        // a "checker" (re-creates autoruns / tasks) is always SUSPECT.
        static string ActRisk(List<string[]> acts, ref bool checker)
        {
            string r = "";
            foreach (string[] a in acts)
            {
                if (a[0] != "exec") continue;
                string text = (a[1] + " " + a[2]).Trim();
                r = Heur.Max(r, Risk(text));
                if (WatchdogRisk(text) == "SUSPECT") { checker = true; r = "SUSPECT"; }
            }
            return r;
        }

        static HashSet<string> ExecKeys(List<string[]> acts)
        {
            HashSet<string> h = new HashSet<string>();
            // exec actions only: the COM-handler layout of the Actions blob is not verified, a misread CLSID must not
            // turn every COM task into a "mismatch"
            foreach (string[] a in acts) if (a[0] == "exec") h.Add(Heur.CmdKey(a[1], a[2]));
            return h;
        }

        // Scheduled tasks: every XML file below <tasksDir> joined with the registry TaskCache of SOFT. Rows are files
        // (Kind 2) whose removal also removes (with backup) the task's TaskCache keys; tasks that exist only in the
        // registry, or are hidden there (no SD), are Kind 1 on their Tree key. live: unreadable is REVIEW, not SUSPECT.
        internal static void ScanTasks(List<Finding> f, string tasksDir, string SOFT, bool live, List<string> cut)
        {
            Dictionary<string, TaskReg> reg = ReadTaskCache(SOFT, cut);
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            List<string> all = new List<string>(), deniedDirs = new List<string>();
            if (Directory.Exists(tasksDir)) FilesBelow(tasksDir, 0, all, deniedDirs);
            foreach (string dd in deniedDirs)
                Add(f, "Scheduled Task (нет доступа)", dd.Length > tasksDir.Length ? dd.Substring(tasksDir.Length).TrimStart('\\') : dd,
                    "(папка задач не читается: права (DACL) изменены? — проверь вручную)", dd, live ? "REVIEW" : "SUSPECT", 3, null, null, null);
            foreach (string tf in all)
            {
                string rel = tf.Substring(tasksDir.Length).Replace(Path.DirectorySeparatorChar, '\\').TrimStart('\\');
                TaskReg tr; reg.TryGetValue(rel, out tr);
                if (tr != null) seen.Add(rel);
                string body = null, why = "";
                try
                {
                    if (new FileInfo(tf).Length > 1024 * 1024) why = "больше 1 МБ — это не задача Windows";
                    else body = File.ReadAllText(tf);
                }
                catch (Exception ex) { why = ex.Message; }
                if (body == null)
                {
                    Add(f, "Scheduled Task (не читается)", rel, "(XML задачи не читается: " + Reg.OneLine(why, 160) + " — проверь вручную)"
                        + (tr != null && tr.Acts != null ? "   реестр: " + ActText(tr.Acts) : ""), tf, live ? "REVIEW" : "SUSPECT", 3, null, null, null);
                    continue;
                }
                List<string[]> acts = Heur.TaskXmlActions(body);
                bool checker = false;
                string risk = ActRisk(acts, ref checker);
                string shown = ActText(acts);
                if (shown.Length == 0) shown = "(нет действий в XML)";
                string note = "";
                if (tr != null)
                {
                    if (tr.Acts != null)
                    {
                        risk = Heur.Max(risk, ActRisk(tr.Acts, ref checker));
                        HashSet<string> a = ExecKeys(acts), b = ExecKeys(tr.Acts);
                        if (!a.SetEquals(b)) { note += "   ВНИМАНИЕ: в реестре (TaskCache — его и выполняет Windows) другое: " + ActText(tr.Acts); risk = Heur.Max(risk, "REVIEW"); }
                    }
                    else if (tr.Raw.Length > 0) note += "   реестр: " + tr.Raw;
                    if (tr.HasActions && !tr.HasSD) { note += "   (скрыта: нет SD в TaskCache\\Tree)"; risk = "SUSPECT"; }
                    if (tr.Index == 0) { note += "   (Index = 0 в TaskCache\\Tree: так задачу прячут)"; risk = Heur.Max(risk, "REVIEW"); }
                }
                Add(f, checker ? "Task *checker?*" : "Scheduled Task", rel, shown + note, tf, risk, 2, null, null, tf);
                if (tr != null) f[f.Count - 1].AlsoKeys = tr.Keys;
            }
            // tasks Windows knows only from the registry (XML deleted or never written: GhostTask-style)
            foreach (KeyValuePair<string, TaskReg> kv in reg)
            {
                if (seen.Contains(kv.Key)) continue;
                TaskReg tr = kv.Value;
                if (!tr.HasActions && !tr.PathOk) continue;   // Win7 orphan / foreign Id: nothing to run
                string xml = Path.Combine(tasksDir, tr.Rel.Replace('\\', Path.DirectorySeparatorChar));
                bool hidden = FsOps.Exists(xml);              // the file is there but its folder could not be listed
                foreach (string dd in deniedDirs) if (QuarMan.Below(xml, dd)) hidden = true;
                bool checker = false;
                string shown = tr.Acts != null ? ActText(tr.Acts) : (tr.Raw.Length > 0 ? tr.Raw : "(действия не прочитаны)");
                string risk = tr.Acts != null ? ActRisk(tr.Acts, ref checker) : "";
                risk = Heur.Max(risk, tr.HasActions && !hidden ? "SUSPECT" : "REVIEW");
                if (tr.HasActions && !tr.HasSD) risk = "SUSPECT";
                shown += hidden ? "   (XML-файл есть, но его папка не читается)"
                    : "   (нет XML-файла — задача только в реестре" + (tr.HasSD ? "" : ", без SD — скрытая") + ")";
                Add(f, "Scheduled Task (только реестр)", tr.Rel, shown, tr.TreeKey, risk, 1, tr.TreeKey, null, null);
                List<string> extra = new List<string>(tr.Keys);
                extra.Remove(tr.TreeKey);
                f[f.Count - 1].AlsoKeys = extra;
            }
        }

        // Every file below 'dir' without throwing (Directory.GetFiles with AllDirectories aborts the whole scan on one
        // folder it may not list). Folders that cannot be listed go to 'denied' (a task folder whose DACL locks out
        // SYSTEM / Administrators hides tasks from tools); junctions and symlinks are not followed (no loops).
        internal static void FilesBelow(string dir, int depth, List<string> res, List<string> denied)
        {
            string[] files, subs;
            try { files = Directory.GetFiles(dir); subs = Directory.GetDirectories(dir); }
            catch (UnauthorizedAccessException) { denied.Add(dir); return; }
            catch (System.Security.SecurityException) { denied.Add(dir); return; }
            catch (PathTooLongException) { denied.Add(dir); return; }   // planted over-long chain: report, never abort
            catch { return; }
            res.AddRange(files);
            if (depth >= 32) return;
            foreach (string sd in subs)
            {
                try { if ((File.GetAttributes(sd) & FileAttributes.ReparsePoint) != 0) continue; } catch { continue; }
                FilesBelow(sd, depth + 1, res, denied);
            }
        }

        // Winlogon Shell / Userinit / Taskman of the SOFTWARE root. Shell and Userinit are Kind 4 (reset to the default,
        // never deleted: a deleted Userinit = logon/logoff loop). systemRoot = the target's %SystemRoot% ("" = unknown).
        internal static void ScanWinlogon(List<Finding> f, string SOFT) { ScanWinlogon(f, SOFT, ""); }

        internal static void ScanWinlogon(List<Finding> f, string SOFT, string systemRoot)
        {
            string wl = SOFT + "\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
            foreach (string[] v in Reg.Values(wl))
            {
                string nm = v[0]; string dt = v[1];
                if (nm.Equals("Shell", StringComparison.OrdinalIgnoreCase))
                    AddReset(f, "Winlogon Shell", wl, nm, dt, Defaults.ShellClean(dt, systemRoot) ? "" : "SUSPECT", Defaults.Shell, RegistryValueKind.String);
                else if (nm.Equals("Userinit", StringComparison.OrdinalIgnoreCase))
                    AddReset(f, "Winlogon Userinit", wl, nm, dt, Defaults.UserinitClean(dt, systemRoot) ? "" : "SUSPECT", Defaults.Userinit(systemRoot), RegistryValueKind.String);
                else if (nm.Equals("Taskman", StringComparison.OrdinalIgnoreCase))
                    Add(f, "Winlogon Taskman", nm, dt, wl, "SUSPECT", 0, wl, nm, null);
            }
        }

        // A Kind 4 finding: remediation writes 'data' back (never deletes the value).
        internal static Finding AddReset(List<Finding> f, string cat, string key, string name, string shown, string risk, object data, RegistryValueKind type)
        {
            Add(f, cat, name, shown, key, risk, 4, key, name, null);
            Finding x = f[f.Count - 1];
            x.ResetData = data; x.ResetType = type;
            return x;
        }

        // BootExecute (REG_MULTI_SZ): every entry must be a Windows autochk line; reset keeps those (+ the default).
        internal static void ScanBootExecute(List<Finding> f, string sm)
        {
            string[] be = Reg.ReadMulti(sm, "BootExecute");
            if (be == null) return;
            bool bad = false;
            foreach (string e in be) if (e.Trim().Length > 0 && !Defaults.AutochkLine(e)) bad = true;
            AddReset(f, "BootExecute", sm, "BootExecute", string.Join(" | ", be), bad ? "SUSPECT" : "", Defaults.BootExecuteRepair(be), RegistryValueKind.MultiString);
        }

        // SetupExecute: pending Windows servicing (poqexec ... pending.xml) is REVIEW and never touched; anything else is
        // SUSPECT and the reset keeps only the servicing entries.
        internal static void ScanSetupExecute(List<Finding> f, string sm)
        {
            string[] se = Reg.ReadMulti(sm, "SetupExecute");
            if (se == null) return;
            List<string> keep = new List<string>();
            bool other = false;
            foreach (string e in se)
            {
                if (e.Trim().Length == 0) continue;
                if (Defaults.ServicingEntry(e)) keep.Add(e); else other = true;
            }
            if (!other && keep.Count == 0) return;
            string shown = string.Join(" | ", se);
            if (!other) Add(f, "SessionMgr SetupExecute", "SetupExecute", shown + "   (ожидает установка обновления Windows — не трогать)", sm, "REVIEW", 3, null, null, null);
            else AddReset(f, "SessionMgr SetupExecute", sm, "SetupExecute", shown, "SUSPECT", keep.ToArray(), RegistryValueKind.MultiString);
        }

        // IFEO Debugger values (also in filter subkeys <exe>\<n>) as "delete only the Debugger value" findings: the
        // IFEO\<exe> key also holds Exploit Protection MitigationOptions, GlobalFlag, Windows 11's notepad redirect.
        // Known legitimate debuggers are REVIEW. The Wow6432Node copy is not consulted on Win7+ (ntdll reads only the
        // native key) but is listed as such; on a live system where it is the same key it is not listed twice.
        internal static void ScanIfeo(List<Finding> f, string SOFT, List<string> cut)
        {
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string root in new string[] { SOFT, SOFT + "\\Wow6432Node" })
            {
                bool wow = root != SOFT, cutWalk;
                string ifeo = root + "\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
                foreach (string[] pr in Reg.Pairs(ifeo, "Debugger", out cutWalk))
                {
                    string rel = pr[0].Substring(ifeo.Length + 1);
                    if (!seen.Add(rel + "\0" + pr[1]) && wow) continue;   // live: the shared key seen again through Wow6432Node
                    if (pr[1].Trim().Length == 0) continue;
                    string exe = rel.Split('\\')[0];
                    string risk = Defaults.IfeoKnownDebugger(exe, pr[1]) && Risk(pr[1]) != "SUSPECT" ? "REVIEW" : "SUSPECT";
                    Add(f, wow ? "IFEO Debugger (WOW64-копия, на Win7+ не действует)" : "IFEO Debugger", rel, pr[1], pr[0], risk, 0, pr[0], "Debugger", null);
                }
                if (cutWalk && cut != null) cut.Add(wow ? "IFEO WOW64" : "IFEO");
            }
            // Application Verifier DLLs (GlobalFlag 0x100): loaded early into the program; never set on a clean Windows.
            // (category not "IFEO ...": «Обезвредить» of an IFEO row removes Debugger)
            string vi = SOFT + "\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
            bool cutV;
            foreach (string[] pr in Reg.Pairs(vi, "VerifierDlls", out cutV))
                if (pr[1].Trim().Length > 0)
                    Add(f, "Verifier DLL (IFEO)", pr[0].Substring(vi.Length + 1), pr[1], pr[0], "SUSPECT", 0, pr[0], "VerifierDlls", null);
        }

        // One user hive (NTUSER.DAT mounted at U). Per-user shell / logon hooks that are absent on a clean profile
        // (research coverage-gaps #7-9, #25): HKCU Winlogon Shell/Userinit/Taskman and Policies\System\Shell override
        // the machine shell (winlocker classic) - deleting the value lets the HKLM default apply; HKCU cmd AutoRun runs
        // in every cmd.exe; Environment\UserInitMprLogonScript runs at logon; the screensaver is REVIEW unless it is
        // a System32 .scr (clean) or suspicious.
        internal static void ScanUserHive(List<Finding> f, string name, string U)
        {
            AddValues(f, "Run [" + name + "]", U + "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
            AddValues(f, "RunOnce [" + name + "]", U + "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
            AddValuesRisk(f, "Policies Run [" + name + "]", U + "\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", "SUSPECT");
            string usf = U + "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders";
            foreach (string[] v in Reg.Values(usf))
                if (v[0].Equals("Startup", StringComparison.OrdinalIgnoreCase) && v[1].IndexOf("Startup", StringComparison.OrdinalIgnoreCase) < 0)
                    Add(f, "Startup redirect [" + name + "]", v[0], v[1], usf, "SUSPECT", 0, usf, v[0], null);
            string uw = U + "\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
            foreach (string[] v in Reg.Values(uw))
                if ((v[0].Equals("Load", StringComparison.OrdinalIgnoreCase) || v[0].Equals("Run", StringComparison.OrdinalIgnoreCase)) && v[1].Trim().Length > 0)
                    Add(f, "Win Load/Run [" + name + "]", v[0], v[1], uw, "SUSPECT", 0, uw, v[0], null);
            // desktop wallpaper (for "effects"/hijacked desktop)
            string dk = U + "\\Control Panel\\Desktop";
            foreach (string[] v in Reg.Values(dk))
                if (v[0].Equals("Wallpaper", StringComparison.OrdinalIgnoreCase) && v[1].Trim().Length > 0)
                    Add(f, "Обои [" + name + "]", v[0], v[1], dk, "REVIEW", 0, dk, v[0], null);
            ScanRunOnceEx(f, U + "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", "RunOnceEx [" + name + "]");
            string uwl = U + "\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
            foreach (string[] v in Reg.Values(uwl))
                if ((v[0].Equals("Shell", StringComparison.OrdinalIgnoreCase) || v[0].Equals("Userinit", StringComparison.OrdinalIgnoreCase)
                    || v[0].Equals("Taskman", StringComparison.OrdinalIgnoreCase)) && v[1].Trim().Length > 0)
                    Add(f, "Winlogon " + v[0] + " [" + name + "]", v[0], v[1], uwl, "SUSPECT", 0, uwl, v[0], null);
            string ups = U + "\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
            foreach (string[] v in Reg.Values(ups))
                if (v[0].Equals("Shell", StringComparison.OrdinalIgnoreCase) && v[1].Trim().Length > 0)
                    Add(f, "Policies Shell [" + name + "]", v[0], v[1], ups, "SUSPECT", 0, ups, v[0], null);
            string ucp = U + "\\Software\\Microsoft\\Command Processor";
            foreach (string[] v in Reg.Values(ucp))
                if (v[0].Equals("AutoRun", StringComparison.OrdinalIgnoreCase) && v[1].Trim().Length > 0)
                    Add(f, "cmd AutoRun [" + name + "]", v[0], v[1], ucp, "SUSPECT", 0, ucp, v[0], null);
            string env = U + "\\Environment";
            foreach (string[] v in Reg.Values(env))
                if (v[0].Equals("UserInitMprLogonScript", StringComparison.OrdinalIgnoreCase) && v[1].Trim().Length > 0)
                    Add(f, "Logon script [" + name + "]", v[0], v[1], env, "SUSPECT", 0, env, v[0], null);
            foreach (string sk in new string[] { U + "\\Control Panel\\Desktop", U + "\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop" })
                foreach (string[] v in Reg.Values(sk))
                    if (v[0].Equals("SCRNSAVE.EXE", StringComparison.OrdinalIgnoreCase) && v[1].Trim().Length > 0)
                    {
                        string r = ScreensaverRisk(v[1]);
                        Add(f, "Заставка [" + name + "]", v[0], v[1], sk, r, 0, sk, v[0], null);
                    }
        }

        // a .scr in System32 / SysWOW64 (or a bare name, loaded from there) = ""; in a user-writable folder (profile,
        // ProgramData: the Gazer trick) or otherwise suspicious = SUSPECT; elsewhere (vendor saver) REVIEW
        internal static string ScreensaverRisk(string data)
        {
            string n = Heur.NormPath(data);
            List<string> t = Heur.Tokens(n);
            string img = t.Count > 0 ? t[0] : "";
            if (img.EndsWith(".scr") && (img.IndexOf('\\') < 0 || Heur.SysDir(img))) return "";
            if (n.Contains("\\users\\") || n.Contains("\\programdata\\") || n.Contains("\\appdata\\")) return "SUSPECT";
            string r = Risk(Regex.Replace(data, @"\.scr\b", ".exe", RegexOptions.IgnoreCase));   // any .scr is SUSPECT for Risk()
            return r == "SUSPECT" ? r : "REVIEW";
        }

        // Value names are exact; only the real unnamed default value ("") is skipped, so names such as "(x)" or
        // "REG_x" are scanned too. internal static: called by tests.
        internal static void AddValues(List<Finding> f, string cat, string key)
        {
            foreach (string[] v in Reg.Values(key))
            {
                if (v[0].Length == 0) continue; // (Default)
                if (HiddenName(f, cat, key, v[0])) continue;
                Add(f, cat, v[0], v[1], key, Risk(v[1]), 0, key, v[0], null);
            }
        }

        // A value name containing NUL (see Reg.Values): Win32 tools cannot read or delete it. Report, never act on it.
        static bool HiddenName(List<Finding> f, string cat, string key, string name)
        {
            if (name.IndexOf('\0') < 0) return false;
            Add(f, cat, "(скрытое имя с NUL: " + name.Replace("\0", "\\0") + ")", "(не читается через Win32; удалить — Sysinternals RegDelNull)",
                key, "SUSPECT", 3, null, null, null);
            return true;
        }

        internal static void AddValuesRisk(List<Finding> f, string cat, string key, string forceRisk)
        {
            foreach (string[] v in Reg.Values(key))
            {
                if (v[0].Length == 0) continue; // (Default)
                if (HiddenName(f, cat, key, v[0])) continue;
                string r = Risk(v[1]); if (r == "") r = forceRisk;
                Add(f, cat, v[0], v[1], key, r, 0, key, v[0], null);
            }
        }

        void AddRow(Finding x)
        {
            ListViewItem it = new ListViewItem(new string[] { x.Category, x.Name, x.Value, x.Location, x.Risk });
            it.Tag = x;
            if (x.Risk == "SUSPECT") it.BackColor = Color.FromArgb(255, 220, 220);
            else if (x.Risk == "REVIEW") it.BackColor = Color.FromArgb(255, 248, 205);
            lv.Items.Add(it);
        }

        static string Last(string path) { int i = path.LastIndexOf('\\'); return i < 0 ? path : path.Substring(i + 1); }

        // ---- MODULE: extra SOFTWARE-hive persistence ----  (internal static: called by tests)
        internal static void ScanExtraSoftware(List<Finding> f, string SOFT)
        {
            // Policies are shared between the 64- and 32-bit views (research windows-semantics Q4): only the native key counts
            AddValuesRisk(f, "Policies Explorer Run", SOFT + "\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", "SUSPECT");
            string pss = SOFT + "\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";   // "Custom User Interface" (absent by default)
            foreach (string[] v in Reg.Values(pss))
                if (v[0].Equals("Shell", StringComparison.OrdinalIgnoreCase) && v[1].Trim().Length > 0)
                    Add(f, "Policies Shell (HKLM)", v[0], v[1], pss, "SUSPECT", 0, pss, v[0], null);
            string[] roots = { SOFT, SOFT + "\\Wow6432Node" };
            foreach (string R in roots)
            {
                AddValuesRisk(f, "RunServices", R + "\\Microsoft\\Windows\\CurrentVersion\\RunServices", "SUSPECT");
                AddValuesRisk(f, "RunServicesOnce", R + "\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce", "SUSPECT");
                // Active Setup StubPath (runs at logon)
                string asroot = R + "\\Microsoft\\Active Setup\\Installed Components";
                foreach (string sk in Reg.Subkeys(asroot))
                    foreach (string[] v in Reg.Values(sk))
                        if (v[0].Equals("StubPath", StringComparison.OrdinalIgnoreCase) && v[1].Trim().Length > 0)
                            Add(f, "Active Setup", Last(sk), v[1], sk, Defaults.ActiveSetupClean(Last(sk), v[1]) ? "" : Risk(v[1]) == "SUSPECT" ? "SUSPECT" : "REVIEW", 0, sk, v[0], null);
            }
            // Winlogon Notify DllName (legacy hook)
            string notify = SOFT + "\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify";
            foreach (string sk in Reg.Subkeys(notify))
                foreach (string[] v in Reg.Values(sk))
                    if (v[0].Equals("DllName", StringComparison.OrdinalIgnoreCase))
                        Add(f, "Winlogon Notify", Last(sk), v[1], sk, "SUSPECT", 1, sk, null, null);
            // SilentProcessExit MonitorProcess = re-launch on target exit ("checker"/watchdog)
            string spe = SOFT + "\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit";
            foreach (string sk in Reg.Subkeys(spe))
                foreach (string[] v in Reg.Values(sk))
                    if (v[0].Equals("MonitorProcess", StringComparison.OrdinalIgnoreCase) && v[1].Trim().Length > 0)
                        Add(f, "SilentProcessExit *checker*", Last(sk), v[1], sk, "SUSPECT", 1, sk, null, null);
            // Executable class hijack (exefile/.bat/.cmd open command should be "%1" %*)
            string[] classes = { "exefile", "comfile", "batfile", "cmdfile", "piffile" };
            foreach (string cl in classes)
            {
                string k = SOFT + "\\Classes\\" + cl + "\\shell\\open\\command";
                foreach (string[] v in Reg.Values(k))
                    if (v[0].Length == 0)   // the unnamed (Default) value
                    {
                        string d = v[1].Trim();
                        bool ok = d.StartsWith("\"%1\"") || d.StartsWith("%1");
                        if (!ok && d.Length > 0) Add(f, "Class hijack [" + cl + "]", "(Default)", v[1], k, "SUSPECT", 3, null, null, null);
                    }
            }
            // ---- прочие стандартные точки (как проверяет Simple Unlocker) ----
            // Winlogon одиночные хуки
            string wl2 = SOFT + "\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
            foreach (string[] v in Reg.Values(wl2))
                if (v[0].Equals("VmApplet", StringComparison.OrdinalIgnoreCase))   // Microsoft default on Win7-11: reset, never delete
                    AddReset(f, "Winlogon VmApplet", wl2, v[0], v[1], Defaults.VmAppletClean(v[1]) ? "" : "SUSPECT", Defaults.VmApplet, RegistryValueKind.String);
                else if ((v[0].Equals("GinaDLL", StringComparison.OrdinalIgnoreCase)
                    || v[0].Equals("AppSetup", StringComparison.OrdinalIgnoreCase) || v[0].Equals("System", StringComparison.OrdinalIgnoreCase)
                    || v[0].Equals("UIHost", StringComparison.OrdinalIgnoreCase)) && v[1].Trim().Length > 0)
                    Add(f, "Winlogon " + v[0], v[0], v[1], wl2, "SUSPECT", 0, wl2, v[0], null);
            // ShellServiceObjectDelayLoad (грузится explorer'ом)
            AddValuesRisk(f, "ShellServiceObjectDelayLoad", SOFT + "\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad", "REVIEW");
            // AppInit_DLLs в WOW6432
            string w64 = SOFT + "\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
            foreach (string[] v in Reg.Values(w64))
                if (v[0].Equals("AppInit_DLLs", StringComparison.OrdinalIgnoreCase) && v[1].Trim().Length > 0)
                    Add(f, "AppInit_DLLs (WOW64)", v[0], v[1], w64, "SUSPECT", 0, w64, v[0], null);
            // Browser Helper Objects (обычно пусто; если есть — проверить)
            foreach (string bhoRoot in new string[] { SOFT + "\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects", SOFT + "\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" })
                foreach (string sk in Reg.Subkeys(bhoRoot))
                    Add(f, "BHO", Last(sk), "(CLSID)", sk, "REVIEW", 1, sk, null, null);
        }

        // ---- MODULE: services, drivers, svchost ServiceDll ----  Every ImagePath / ServiceDll whose risk is not clean is
        // listed (REVIEW ones too: a coin-miner in ProgramData, a driver outside System32); a script host, cmd or a
        // script as the service program is SUSPECT (the batch-malware "sc create ... binPath= cmd /c" pattern).
        internal static void ScanServices(List<Finding> f, string CCS, List<string> cut)
        {
            bool cutWalk;
            foreach (string[] pr in Reg.Pairs(CCS + "\\Services", "ImagePath", out cutWalk))
            {
                string r = ServiceRisk(pr[1]);
                if (r == "") continue;
                Add(f, "Service/Driver", ServiceName(pr[0]), pr[1], pr[0], r, 1, pr[0], null, null);
            }
            if (cutWalk && cut != null) cut.Add("Services");
            // svchost-hosted ServiceDll (classic hiding spot inside a shared svchost group): only the value is deleted
            foreach (string[] pr in Reg.Pairs(CCS + "\\Services", "ServiceDll", out cutWalk))
            {
                string r = Risk(pr[1]);
                if (r == "") continue;
                Add(f, "svchost ServiceDll", ServiceName(pr[0]), pr[1], pr[0], r, 0, pr[0], "ServiceDll", null);
            }
            if (cutWalk && cut != null) cut.Add("ServiceDll");
        }

        static string ServiceName(string p)
        {
            string nm = p;
            int i = p.IndexOf("\\Services\\", StringComparison.OrdinalIgnoreCase);
            if (i >= 0) { nm = p.Substring(i + 10); int j = nm.IndexOf('\\'); if (j > 0) nm = nm.Substring(0, j); }
            return nm;
        }

        // Risk of a service ImagePath: Risk() plus interpreters / scripts as the program and images in the Windows
        // root (no Windows service lives there). Microsoft Defender's platform binaries and its MpKsl driver in
        // ProgramData are not REVIEW (they live there on every updated Windows 10/11).
        internal static string ServiceRisk(string img)
        {
            if (string.IsNullOrEmpty(img) || img.Trim().Length == 0) return "";
            string r = Risk(img);
            string p = Heur.NormPath(img).Trim();
            string image = Defaults.ImageName(img);
            if (image.EndsWith(".exe")) image = image.Substring(0, image.Length - 4);
            List<string> t = Heur.Tokens(p);
            string first = t.Count > 0 ? t[0] : "";
            int sys = p.IndexOf(".sys", StringComparison.Ordinal), exe = p.IndexOf(".exe", StringComparison.Ordinal);
            int cut = sys >= 0 && (exe < 0 || sys < exe) ? sys : exe;   // unquoted path with spaces: up to the extension
            if (cut > 0 && p.IndexOf('"') < 0)
            {
                first = p.Substring(0, cut + 4).Trim();
                image = first.Substring(first.LastIndexOf('\\') + 1);
                if (image.EndsWith(".exe")) image = image.Substring(0, image.Length - 4);
            }
            foreach (string b in new string[] { "cmd", "%comspec%", "powershell", "pwsh", "wscript", "cscript", "mshta", "conhost" })
                if (image == b) return "SUSPECT";
            foreach (string e in new string[] { ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".ps1" })
                if (image.EndsWith(e)) return "SUSPECT";
            if (first.Length >= 2 && first[1] == ':') first = first.Substring(2);
            if (first.StartsWith("\\windows\\") && first.IndexOf('\\', 9) < 0)   // C:\Windows\<x>.exe (directly in the Windows folder)
            {
                // Vendor services really live there (e.g. Realtek Bluetooth C:\Windows\RtkBtManServ.exe), so only a name that
                // masquerades as a System32 binary (C:\Windows\svchost.exe) is SUSPECT; everything else is REVIEW.
                foreach (string m in new string[] { "svchost", "lsass", "csrss", "winlogon", "services", "smss", "wininit", "spoolsv",
                    "taskhost", "taskhostw", "dllhost", "conhost", "rundll32", "regsvr32", "dwm", "sihost", "wuauclt", "msiexec", "lsm",
                    "ctfmon", "searchindexer", "audiodg", "wmiprvse" })
                    if (image == m) return "SUSPECT";
                return Heur.Max(r, "REVIEW");
            }
            if (image == "rundll32") r = Heur.Max(r, "REVIEW");
            if (r == "REVIEW" && first.IndexOf("..") < 0)
            {
                if (first.StartsWith("\\programdata\\microsoft\\windows defender\\platform\\")
                    && (image == "msmpeng" || image == "nissrv" || image == "mpdefendercoreservice")) return "";
                if (first.StartsWith("\\programdata\\microsoft\\windows defender\\definition updates\\") && image.StartsWith("mpksl") && image.EndsWith(".sys")) return "";
            }
            return r;
        }

        // ---- MODULE: extra SYSTEM-hive persistence (services & co.) ----
        void ScanExtraSystem(List<Finding> f, string CCS, List<string> cut)
        {
            // LSA authentication/security/notification packages (DLLs loaded by lsass)
            string lsa = CCS + "\\Control\\Lsa";
            string[] lsaVals = { "Authentication Packages", "Security Packages", "Notification Packages" };
            string[] lsaOK = { "msv1_0", "kerberos", "wdigest", "tspkg", "pku2u", "cloudap", "schannel", "negoexts", "tsssp", "scecli", "rassfm", "kdcsvc", "livessp", "\"\"", "-" };
            foreach (string vn in lsaVals)
                foreach (string[] v in Reg.Values(lsa))
                    if (v[0].Equals(vn, StringComparison.OrdinalIgnoreCase))
                        foreach (string tok in v[1].Replace("\\0", " ").Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries))
                        {
                            string t = tok.Trim().ToLower().Replace("\"", "").Replace(".dll", "");
                            if (t.Length == 0) continue;
                            bool ok = false; foreach (string g in lsaOK) if (t == g) ok = true;
                            if (!ok) Add(f, "LSA " + vn, tok, v[1], lsa, "SUSPECT", 3, null, null, null);
                        }
            // Print Monitors -> Driver DLL (loaded by spoolsv)
            string pm = CCS + "\\Control\\Print\\Monitors";
            string[] okmon = { "local port", "standard tcp/ip port", "usb monitor", "wsd port", "bjnp port", "ws port", "appmon", "microsoft shared fax monitor", "microsoft document imaging writer monitor" };
            foreach (string sk in Reg.Subkeys(pm))
            {
                string mon = Last(sk).ToLower();
                bool known = false; foreach (string ok in okmon) if (mon == ok) known = true;
                foreach (string[] v in Reg.Values(sk))
                    if (v[0].Equals("Driver", StringComparison.OrdinalIgnoreCase) && !known)
                        Add(f, "Print Monitor", Last(sk), v[1], sk, "SUSPECT", 1, sk, null, null);
            }
            // Session Manager execute hooks
            string sm = CCS + "\\Control\\Session Manager";
            ScanSetupExecute(f, sm);
            ScanSessionManagerExtra(f, sm);
        }

        // Session Manager values that are absent / empty on a clean Windows (research windows-semantics Q2): any entry
        // is SUSPECT and the value is deleted. AppCertDlls is a KEY whose values are DLL paths (loaded into every
        // process that calls CreateProcess): each value is a row.
        internal static void ScanSessionManagerExtra(List<Finding> f, string sm)
        {
            foreach (string vn in new string[] { "S0InitialCommand", "PlatformExecute", "Execute", "BootExecuteNoPnpSync", "SetupExecuteNoPnpSync" })
            {
                string[] items = Reg.ReadMulti(sm, vn);
                if (items == null) continue;
                List<string> used = new List<string>();
                foreach (string e in items) if (e != null && e.Trim().Length > 0) used.Add(e);
                if (used.Count > 0) Add(f, "SessionMgr " + vn, vn, string.Join(" | ", used.ToArray()), sm, "SUSPECT", 0, sm, vn, null);
            }
            string ac = sm + "\\AppCertDlls";
            foreach (string[] v in Reg.Values(ac))
            {
                if (HiddenName(f, "AppCertDlls", ac, v[0])) continue;
                if (v[1].Trim().Length == 0) continue;
                Add(f, "AppCertDlls", v[0].Length > 0 ? v[0] : "(по умолчанию)", v[1], ac, "SUSPECT", 0, ac, v[0], null);
            }
        }

        // ---- MODULE: machine locations that are absent / empty on a clean Windows (research coverage-gaps #5, #13,
        // #16, #17; R051) ----
        internal static void ScanMachineExtras(List<Finding> f, string SOFT)
        {
            if (string.IsNullOrEmpty(SOFT)) return;
            foreach (string R in new string[] { SOFT, SOFT + "\\Wow6432Node" })
            {
                bool wow = R != SOFT;
                // RunOnceEx: not created by default on Vista+; every <NNN> subkey runs (its Depend DLLs load)
                ScanRunOnceEx(f, R + "\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", wow ? "RunOnceEx (HKLM WOW64)" : "RunOnceEx (HKLM)");
                // AeDebug: the crash debugger Windows starts by itself when Auto = 1 (default: no Debugger)
                string ae = R + "\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug";
                string dbg = null, auto = "";
                foreach (string[] v in Reg.Values(ae))
                    if (v[0].Equals("Debugger", StringComparison.OrdinalIgnoreCase)) dbg = v[1];
                    else if (v[0].Equals("Auto", StringComparison.OrdinalIgnoreCase)) auto = v[1].Trim();
                if (dbg != null && dbg.Trim().Length > 0)
                    Add(f, wow ? "AeDebug (WOW64)" : "AeDebug", "Debugger", dbg + "   (Auto = " + (auto.Length > 0 ? auto : "нет") + ")", ae,
                        AeDebugRisk(dbg, auto), 0, ae, "Debugger", null);
            }
            // hidden local accounts (DWORD 0 = not shown on the logon screen): REVIEW, deleting the value unhides
            string ul = SOFT + "\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList";
            foreach (string[] v in Reg.Values(ul))
                if (v[0].Length > 0 && v[2] == "REG_DWORD" && v[1] == "0x0" && !HiddenName(f, "Скрытый пользователь", ul, v[0]))
                    Add(f, "Скрытый пользователь", v[0], "(не показывается на экране входа — учётку проверь во вкладке «Учётки»)", ul, "REVIEW", 0, ul, v[0], null);
            // Microsoft Defender exclusions (value name = excluded item) and their policy copy
            foreach (string ex in new string[] { SOFT + "\\Microsoft\\Windows Defender\\Exclusions", SOFT + "\\Policies\\Microsoft\\Windows Defender\\Exclusions" })
                foreach (string kind in new string[] { "Paths", "Extensions", "Processes", "TemporaryPaths", "IpAddresses" })
                {
                    string k = ex + "\\" + kind;
                    foreach (string[] v in Reg.Values(k))
                    {
                        if (v[0].Length == 0 || HiddenName(f, "Defender исключение", k, v[0])) continue;
                        Add(f, "Defender исключение (" + kind + ")", v[0], "(Защитник не проверяет это)", k, DefenderExclusionRisk(kind, v[0]), 0, k, v[0], null);
                    }
                }
        }

        static void ScanRunOnceEx(List<Finding> f, string key, string cat)
        {
            foreach (string sk in Reg.Subkeys(key))
            {
                List<string> parts = new List<string>();
                foreach (string[] v in Reg.Values(sk)) parts.Add((v[0].Length > 0 ? v[0] : "(по умолчанию)") + " = " + v[1]);
                foreach (string dk in Reg.Subkeys(sk)) foreach (string[] v in Reg.Values(dk)) parts.Add(Last(dk) + "\\" + v[0] + " = " + v[1]);
                Add(f, cat, Last(sk), string.Join("  |  ", parts.ToArray()), sk, "SUSPECT", 1, sk, null, null);
            }
        }

        // AeDebug Debugger: known debuggers (Visual Studio, WinDbg, cdb/ntsd, ProcDump) or Auto != 1 (asks first) = REVIEW
        internal static string AeDebugRisk(string dbg, string auto)
        {
            if (Risk(dbg) == "SUSPECT") return "SUSPECT";
            string img = Defaults.ImageName(dbg);
            string[] known = { "vsjitdebugger.exe", "windbg.exe", "windbgx.exe", "cdb.exe", "ntsd.exe", "procdump.exe", "procdump64.exe", "procdump64a.exe", "drwtsn32.exe" };
            if (Array.IndexOf(known, img) >= 0) return "REVIEW";
            string a = (auto ?? "").Trim().ToLowerInvariant();
            return a == "1" || a == "0x1" ? "SUSPECT" : "REVIEW";
        }

        // An exclusion of a whole drive / Windows / the profiles / ProgramData, of a script or program extension, or
        // of a path Risk() calls SUSPECT is SUSPECT (WhisperGate-style "C:\"); anything else REVIEW.
        internal static string DefenderExclusionRisk(string kind, string item)
        {
            string x = Heur.NormPath(item).Trim().TrimEnd('\\');
            if (x.Length == 0 || x == "*") return "SUSPECT";
            if (kind == "Extensions")
            {
                string e = x.TrimStart('*').TrimStart('.');
                string[] bad = { "exe", "dll", "scr", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "hta", "com", "pif", "lnk", "msi", "sys", "cpl" };
                return Array.IndexOf(bad, e) >= 0 ? "SUSPECT" : "REVIEW";
            }
            if (kind == "Paths" || kind == "TemporaryPaths")
            {
                string nod = x.Length >= 2 && x[1] == ':' ? x.Substring(2) : x;
                string[] broad = { "", "\\windows", "\\windows\\system32", "\\windows\\syswow64", "\\users", "\\programdata", "\\program files", "\\program files (x86)", "\\windows\\temp", "\\temp" };
                if (Array.IndexOf(broad, nod) >= 0 || nod.EndsWith("\\appdata") || nod.EndsWith("\\appdata\\roaming") || nod.EndsWith("\\appdata\\local")) return "SUSPECT";
            }
            return Risk(item) == "SUSPECT" ? "SUSPECT" : "REVIEW";
        }

        // SYSTEM\Setup (hive root): with SetupType != 0 winlogon runs CmdLine as SYSTEM before logon (the "utilman /
        // password reset" trick). Windows' own setup / OOBE (windeploy, $WINDOWS.~BT) is REVIEW info; anything else
        // SUSPECT with two resets (CmdLine = "", SetupType = 0), never a delete.
        internal static void ScanSetupKey(List<Finding> f, string SYS)
        {
            if (string.IsNullOrEmpty(SYS)) return;
            string st = SYS + "\\Setup";
            string cmdline = null; int type = 0;
            foreach (string[] v in Reg.Values(st))
                if (v[0].Equals("CmdLine", StringComparison.OrdinalIgnoreCase)) cmdline = v[1];
                else if (v[0].Equals("SetupType", StringComparison.OrdinalIgnoreCase) && v[2] == "REG_DWORD")
                    try { type = Convert.ToInt32(v[1].Substring(2), 16); } catch { }
            if (type == 0 || cmdline == null || cmdline.Trim().Length == 0) return;
            string shown = cmdline + "   (SetupType = " + type + ")";
            string l = Heur.NormPath(cmdline);
            if (l.Contains("\\oobe\\windeploy") || l.StartsWith("oobe\\windeploy") || l.Contains("$windows.~bt") || l.Contains("$windows.~ws") || l.Contains("\\sysprep\\"))
            {
                Add(f, "Setup CmdLine", "CmdLine", shown + "   (идёт установка/обновление Windows — не трогать)", st, "REVIEW", 3, null, null, null);
                return;
            }
            AddReset(f, "Setup CmdLine", st, "CmdLine", shown, "SUSPECT", "", RegistryValueKind.String);
            AddReset(f, "Setup SetupType", st, "SetupType", shown, "SUSPECT", 0, RegistryValueKind.DWord);
        }

        // Tcpip DataBasePath: where Windows reads the hosts file; must stay %SystemRoot%\System32\drivers\etc (reset).
        internal const string HostsDbPath = "%SystemRoot%\\System32\\drivers\\etc";
        internal static void ScanDataBasePath(List<Finding> f, string CCS)
        {
            if (string.IsNullOrEmpty(CCS)) return;
            string k = CCS + "\\Services\\Tcpip\\Parameters";
            foreach (string[] v in Reg.Values(k))
                if (v[0].Equals("DataBasePath", StringComparison.OrdinalIgnoreCase))
                {
                    string d = Heur.NormPath(v[1]).Trim().TrimEnd('\\');
                    if (d.Length >= 2 && d[1] == ':') d = d.Substring(2);
                    bool ok = d == "\\windows\\system32\\drivers\\etc";
                    if (!ok) AddReset(f, "Tcpip DataBasePath (hosts)", k, v[0], v[1], "SUSPECT", HostsDbPath, RegistryValueKind.ExpandString);
                }
        }

        // hosts file: every active (non-comment) line other than localhost is listed as info (fixed by hand: users and
        // ad blockers keep their own lines); security / update sites blocked, or popular sites sent to a public IP,
        // are SUSPECT.
        internal static void ScanHosts(List<Finding> f, string file, bool live)
        {
            string text;
            try
            {
                if (!File.Exists(file)) return;
                if (new FileInfo(file).Length > 8 * 1024 * 1024) { Add(f, "hosts", "(файл)", "(больше 8 МБ — проверь вручную)", file, "REVIEW", 3, null, null, null); return; }
                text = File.ReadAllText(file, Encoding.Default);
            }
            catch (Exception ex) { Add(f, "hosts", "(не читается)", Reg.OneLine(ex.Message, 160), file, live ? "REVIEW" : "SUSPECT", 3, null, null, null); return; }
            List<string[]> act = Heur.HostsEntries(text);
            int shown = 0, rest = 0;
            foreach (string[] e in act)
            {
                string r = Heur.HostsRisk(e[0], e[1]);
                if (r == "REVIEW" && shown >= 30) { rest++; continue; }
                Add(f, "hosts", e[1], e[0] + " " + e[1], file, r, 3, null, null, null);
                shown++;
            }
            if (rest > 0) Add(f, "hosts", "…", "(и ещё строк: " + rest + " — похоже на блок-лист рекламы; проверь вручную)", file, "REVIEW", 3, null, null, null);
        }

        // ---- MODULE: drivers folder (non-.sys files are highly unusual) ----
        void ScanDrivers(List<Finding> f, string winDir)
        {
            string dir = FsPath(winDir + "\\System32\\drivers");
            List<string> files = new List<string>(), denied = new List<string>();
            FilesBelow(dir, 32, files, denied);   // this folder only (depth 32 = no subfolders), never throws
            string[] benign = { ".dat", ".dls", ".wdf", ".txt", ".mui", ".bin", ".din", ".cat", ".inf", ".ini", ".xml", ".json", ".etl" };
            string[] exe = { ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".scr", ".com", ".pif", ".js", ".hta" };
            foreach (string fp in files)
            {
                string ext = Path.GetExtension(fp).ToLower();
                string nm = Path.GetFileName(fp);
                if (ext == ".sys") continue;
                if (nm.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                bool isExe = false; foreach (string e in exe) if (ext == e) isExe = true;
                bool isBenign = false; foreach (string b in benign) if (ext == b) isBenign = true;
                if (isExe) Add(f, "drivers\\ (исполняемый!)", nm, fp, fp, ext == ".dll" ? "REVIEW" : "SUSPECT", 2, null, null, fp);
                else if (!isBenign) Add(f, "drivers\\ (нетипичный)", nm, fp, fp, "REVIEW", 2, null, null, fp);
            }
        }

        static string WatchdogRisk(string body)
        {
            if (body == null) return "";
            string l = body.ToLowerInvariant();
            // сильные индикаторы самовосстановления/перезаписи автозагрузки (без общих слов вроде "check")
            // (-enc / -w hidden: Risk() parses PowerShell switches; a plain "-enc" substring also matched "-Encoding")
            string[] kw = { "reg add ", "reg.exe add ", "reg import", "reg.exe import", "regedit /s", "regedit.exe /s", "schtasks /create",
                "schtasks.exe /create", "bcdedit", "frombase64", "downloadstring", "mshta", "\\temp\\", "\\appdata\\local\\temp\\" };
            foreach (string k in kw) if (l.Contains(k)) return "SUSPECT";
            return "";
        }

        // ---- MODULE: pre-boot (BCD stores + ESP contents) ----  Everything here is information (Kind 3): boot files are
        // fixed by hand (bcdedit / bcdboot), never by «Отметить подозрит.» + «Удалить» (vendor and Linux loaders are legit).
        void PrebootScan()
        {
            if (curDrive == "") { MessageBox.Show("Сначала нажми «Сканировать» (нужен выбранный диск)."); return; }
            Cursor.Current = Cursors.WaitCursor;
            List<Finding> f = new List<Finding>();
            string bo; int brc = RunProc("bcdedit", "/enum all", out bo);
            if (brc != 0) { string w = Reg.OneLine(bo, 220); bo = ""; Add(f, "BCD", "(bcdedit не сработал)", w.Length > 0 ? w : "код " + brc, "BCD store", "REVIEW", 3, null, null, null); }
            ParseBcd(f, bo, "BCD (системное хранилище запущенной ОС)");
            int esps = 0;
            for (char c = 'A'; c <= 'Z'; c++)
            {
                string efi = c + ":\\EFI";
                try
                {
                    if (!Directory.Exists(efi)) continue;
                    if (!Directory.Exists(efi + "\\Microsoft") && !Directory.Exists(efi + "\\Boot")) continue;
                    ScanEsp(f, efi); esps++;
                    string store = efi + "\\Microsoft\\Boot\\BCD";   // the store this ESP boots with (e.g. the target's, not WinPE's)
                    if (File.Exists(store))
                    {
                        string so; int rc = RunProc("bcdedit", "/store " + Reg.QuoteArg(store) + " /enum all", out so);
                        if (rc == 0) ParseBcd(f, so, "BCD " + store);
                        else Add(f, "BCD " + store, "(bcdedit /store не сработал)", Reg.OneLine(so, 220), store, "REVIEW", 3, null, null, null);
                    }
                }
                catch (Exception ex) { Add(f, "ESP " + efi, "(ошибка)", Reg.OneLine(ex.Message, 200), efi, "REVIEW", 3, null, null, null); }
            }
            foreach (Finding x in f) AddRow(x);
            Cursor.Current = Cursors.Default;
            lblStatus.Text = "Pre-boot: +" + f.Count + " записей (BCD + ESP найдено: " + esps + "). Только информация — чинить вручную. ESP без буквы — присвой через diskpart / mountvol.";
        }

        // bcdedit / net: full System32 path, concurrent stdout+stderr, timeout. Variable args -> Reg.QuoteArg.
        static int RunProc(string exe, string args, out string outp)
        {
            return Reg.RunProcess(Reg.SysExe(exe), args, Reg.ToolTimeoutMs, out outp);
        }

        // "bcdedit /enum all" output -> {description, path} per entry. Entries are blocks separated by blank lines; in a
        // block "description" may come before or after "path" (it comes after it in bcdedit's output).
        internal static List<string[]> BcdEntries(string txt)
        {
            List<string[]> res = new List<string[]>();
            if (txt == null) return res;
            string desc = "", path = null;
            foreach (string line in (txt.Replace("\r", "") + "\n\n").Split('\n'))
            {
                string l = line.Trim();
                if (l.Length == 0)
                {
                    if (path != null) res.Add(new string[] { desc, path });
                    desc = ""; path = null;
                    continue;
                }
                int sp = l.IndexOfAny(new char[] { ' ', '\t' });
                string key = sp < 0 ? l : l.Substring(0, sp), val = sp < 0 ? "" : l.Substring(sp).Trim();
                if (key.Equals("description", StringComparison.OrdinalIgnoreCase)) desc = val;
                else if (key.Equals("path", StringComparison.OrdinalIgnoreCase)) path = val;
            }
            return res;
        }

        internal static bool BcdPathOk(string p)
        {
            string lp = (p ?? "").Trim().ToLowerInvariant();
            return lp.EndsWith("winload.efi") || lp.EndsWith("winload.exe") || lp.EndsWith("bootmgfw.efi")
                || lp.EndsWith("bootmgr.efi") || lp.EndsWith("\\bootmgr") || lp.EndsWith("winresume.efi")
                || lp.EndsWith("winresume.exe") || lp.EndsWith("memtest.efi") || lp.EndsWith("memtest.exe") || lp.EndsWith("hvloader.efi");
        }

        static void ParseBcd(List<Finding> f, string txt, string where)
        {
            foreach (string[] e in BcdEntries(txt))
                Add(f, "BCD path", e[0].Length > 0 ? e[0] : "(entry)", e[1], where, BcdPathOk(e[1]) ? "" : "SUSPECT", 3, null, null, null);
        }

        // Every file of the ESP without throwing (one bad entry no longer hides the whole ESP); folders that cannot be
        // read are listed. .efi: Microsoft\ / Boot\ are normal, other loaders (vendor, Linux, tools) are REVIEW.
        void ScanEsp(List<Finding> f, string efi)
        {
            List<string> files = new List<string>(), denied = new List<string>();
            FilesBelow(efi, 0, files, denied);
            foreach (string dd in denied) Add(f, "ESP (нет доступа)", dd, "(папка не читается — проверь вручную)", dd, "REVIEW", 3, null, null, null);
            foreach (string fp in files)
            {
                string ext = Path.GetExtension(fp).ToLowerInvariant();
                string rel = fp.Length > efi.Length ? fp.Substring(efi.Length).TrimStart('\\') : fp;
                string low = rel.ToLowerInvariant();
                if (ext == ".efi")
                {
                    bool std = low.StartsWith("microsoft\\") || low.StartsWith("boot\\");
                    Add(f, "ESP .efi", rel, fp, fp, std ? "" : "REVIEW", 3, null, null, null);
                }
                else if (ext == ".exe" || ext == ".dll" || ext == ".bat" || ext == ".cmd" || ext == ".ps1" || ext == ".vbs" || ext == ".scr")
                    Add(f, "ESP чужой файл!", rel, fp, fp, "SUSPECT", 3, null, null, null);
            }
        }

        // A Startup-folder item: software installs shortcuts, so a program or script placed there directly is SUSPECT;
        // a .lnk is judged by its target + arguments (REVIEW at least); a small script also by its content (checker).
        internal static string StartupRisk(string fp, out string shown)
        {
            shown = fp;
            string ext = Path.GetExtension(fp).ToLowerInvariant();
            string[] direct = { ".exe", ".com", ".scr", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".ps1" };
            string r = Risk(fp);
            if (Array.IndexOf(direct, ext) >= 0) r = "SUSPECT";
            byte[] b = null;
            try { if (new FileInfo(fp).Length <= 1024 * 1024) b = File.ReadAllBytes(fp); } catch { }
            if (ext == ".lnk" && b != null)
            {
                string[] t = Heur.LnkTarget(b);
                if (t != null && (t[0].Length > 0 || t[1].Length > 0))
                {
                    string cmd = (t[0].IndexOf(' ') >= 0 ? "\"" + t[0] + "\"" : t[0]) + (t[1].Length > 0 ? " " + t[1] : "");
                    shown = fp + "  ->  " + cmd;
                    r = Heur.Max(r, Risk(cmd));
                }
            }
            else if (b != null && ext != ".exe" && ext != ".com" && ext != ".scr" && ext != ".pif")
            {
                string text = Encoding.Default.GetString(b);
                if (WatchdogRisk(text) == "SUSPECT") { r = "SUSPECT"; shown = fp + "   (внутри: перезапись автозагрузки / задач — «чекер»)"; }
            }
            return r == "SUSPECT" ? "SUSPECT" : "REVIEW";
        }

        void AddStartup(List<Finding> f, string dir, string cat)
        {
            List<string> files = new List<string>(), denied = new List<string>();
            FilesBelow(dir, 32, files, denied);   // this folder only, never throws
            foreach (string fp in files)
            {
                string nm = Path.GetFileName(fp);
                if (nm.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                string shown, risk = StartupRisk(fp, out shown);
                Add(f, cat, nm, shown, fp, risk, 2, null, null, fp);
            }
        }

        static void Add(List<Finding> f, string cat, string name, string val, string loc, string risk, int kind, string dkey, string dname, string dpath)
        {
            Finding x = new Finding();
            x.Category = cat; x.Name = name; x.Value = val; x.Location = loc; x.Risk = risk;
            x.Kind = kind; x.DelKey = dkey; x.DelName = dname; x.DelPath = dpath;
            f.Add(x);
        }

        static string ExtractTag(string xml, string tag)
        {
            if (xml == null) return "";
            int a = xml.IndexOf("<" + tag + ">");
            if (a < 0) return "";
            a += tag.Length + 2;
            int b = xml.IndexOf("</" + tag + ">", a);
            if (b < 0) return "";
            return xml.Substring(a, b - a).Trim();
        }

        // Risk of an autostart command line (Run, tasks, services, Active Setup, ...): see Heur.Risk.
        internal static string Risk(string s) { return Heur.Risk(s, true); }

        void MarkSuspect(ListView target)
        {
            foreach (ListViewItem it in target.Items)
            {
                Finding x = (Finding)it.Tag;
                it.Checked = (x.Risk == "SUSPECT");
            }
        }

        // ================= QUARANTINE (safe removal with backup) =================
        // Folder: <target drive>\RescueScan_Quarantine\<stamp> (else <exe folder>\RescueScan_Quarantine\<stamp>), never
        // the WinPE RAM disk X: or %TEMP% (gone after a reboot). manifest.txt (format 2) is written BEFORE the first item;
        // every item gets its own numbered backup (never a name chosen by the malware); registry backups are written by
        // our own exact .reg writer and recorded with a LOGICAL location (installation + hive + profile + key path), so
        // «Восстановить» works in a later session, with other drive letters / mount names, or from the live system.
        string quarFor = "";   // target drive the current quarantine folder belongs to
        int quarSeq = 0;       // number of the last backup in quarDir

        static string RamDrive()
        {
            string run = RunningWinDir();
            return IsRescueSystem(Reg.KeyExists("HKLM\\SYSTEM\\CurrentControlSet\\Control\\MiniNT"), run) ? run.Substring(0, 2) : "";
        }

        bool EnsureQuar()
        {
            if (quarDir.Length > 0 && Directory.Exists(quarDir) && (curDrive.Length == 0 || curDrive.Equals(quarFor, StringComparison.OrdinalIgnoreCase))) return true;
            quarDir = ""; quarSeq = 0;
            string stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss"), exeDir = "", tmp = "", why = "";
            try { exeDir = Path.GetDirectoryName(Application.ExecutablePath); } catch { }
            try { tmp = Path.GetTempPath(); } catch { }
            foreach (string c0 in QuarMan.Candidates(curDrive, exeDir, RamDrive(), tmp, stamp))
                for (int i = 0; i < 20; i++)
                {
                    string c = i == 0 ? c0 : c0 + "_" + i;
                    try
                    {
                        if (Directory.Exists(c)) continue;
                        Directory.CreateDirectory(c);
                        File.WriteAllText(Path.Combine(c, QuarMan.ManifestName), QuarMan.HeaderLine(stamp, TargetName(), tgtInstall) + "\r\n", Encoding.UTF8);
                        quarDir = c; quarFor = curDrive;
                        return true;
                    }
                    catch (Exception ex) { if (why.Length == 0) why = ex.Message; break; }
                }
            NoteQuarErr("папку карантина не создать (" + (curDrive.Length > 0 ? curDrive + "\\RescueScan_Quarantine" : "диск цели не выбран") +
                "; RAM-диск X: и %TEMP% не используются — там бэкап пропадёт при перезагрузке)" + (why.Length > 0 ? ": " + why : ""));
            return false;
        }

        bool QAppend(string line)
        {
            try { File.AppendAllText(Path.Combine(quarDir, QuarMan.ManifestName), line + "\r\n", Encoding.UTF8); return true; }
            catch (Exception ex) { NoteQuarErr("manifest.txt не записан: " + ex.Message); return false; }
        }

        void NoteQuarErr(string why)
        {
            if (quarErr.Length == 0 && !string.IsNullOrEmpty(why)) quarErr = Reg.OneLine(why, 220);
        }

        // Moves a file into quarantine as <n>_<name>.quarantine (attributes R/H/S cleared first, restored on restore).
        bool QuarFile(string path)
        {
            if (!EnsureQuar()) return false;
            if (!QuarMan.AbsLocalPath(path)) { NoteQuarErr("путь не поддерживается: " + path); return false; }
            int attrs = FsOps.Attrs(path);
            if (attrs == -1) { NoteQuarErr("нет файла " + path); return false; }
            if ((attrs & 0x10) != 0) { NoteQuarErr("это папка, не файл: " + path); return false; }
            int n = ++quarSeq;
            string dst = Path.Combine(quarDir, QuarMan.QuarFileName(n, path)), err;
            FsOps.ClearRhs(path);
            if (!FsOps.MoveFile(path, dst, out err))
            {
                if (FsOps.Exists(path))
                {
                    if (File.Exists(dst)) { string e2; FsOps.DeleteFile(dst, out e2); }   // the original is still there: no half copy
                    FsOps.SetAttrs(path, attrs);
                }
                QAppend("FILE-FAIL\t" + QuarMan.Esc(path) + "\t" + QuarMan.Esc(err));
                NoteQuarErr(Path.GetFileName(path) + ": " + err);
                return false;
            }
            ManEntry e = new ManEntry();
            e.N = n; e.Orig = path; e.Vol = FsOps.VolumeSerial(path); e.Backup = Path.GetFileName(dst); e.Attrs = attrs;
            try { e.Sha = QuarMan.Sha256(dst); } catch { }
            if (e.Sha.Length == 64 && QAppend(QuarMan.FileLine(e))) return true;
            FsOps.MoveFile(dst, path, out err);   // not recorded = not restorable: put it back
            NoteQuarErr("manifest.txt не записан — файл оставлен на месте: " + path);
            return false;
        }

        // Backs up a registry value (valueName != null; a missing value is recorded as "delete on restore") or a whole
        // key into <n>.reg + a manifest line. false (and nothing may be changed) if any part of it failed.
        bool QuarReg(string key, string valueName, string note)
        {
            if (!EnsureQuar()) return false;
            string kind, uid, rel, regRoot, phys, err;
            if (!Locate(key, tgtSoft, tgtSys, tgtUsers, out kind, out uid, out rel, out regRoot, out phys))
            { NoteQuarErr(key + " — не в кустах цели " + TargetName() + ": бэкап не сделан"); return false; }
            List<RegSection> snap = Reg.Snapshot(key, valueName, out err);
            string text = null;
            if (snap != null)
            {
                foreach (RegSection sec in snap) sec.Path = regRoot + sec.Path.Substring(phys.Length);
                text = RegFile.Format(snap, out err);
            }
            if (text == null)
            {
                QAppend("REG-FAIL\t" + QuarMan.Esc(key) + "\t" + QuarMan.Esc(err));
                NoteQuarErr("бэкап " + key + " не сделан: " + err);
                return false;
            }
            int n = ++quarSeq;
            string dst = Path.Combine(quarDir, n + ".reg");
            ManEntry e = new ManEntry();
            e.N = n; e.IsKey = valueName == null; e.Install = tgtInstall; e.RootKind = kind; e.UserId = uid; e.RegRoot = regRoot;
            e.Rel = rel; e.ValueName = valueName ?? ""; e.Backup = n + ".reg"; e.Note = note ?? "";
            try
            {
                File.WriteAllText(dst, text, Encoding.Unicode);   // UTF-16LE with BOM, like regedit
                e.Sha = QuarMan.Sha256(dst);
            }
            catch (Exception ex) { NoteQuarErr("бэкап не записан: " + ex.Message); return false; }
            if (QAppend(QuarMan.RegLine(e))) return true;
            try { File.Delete(dst); } catch { }
            return false;
        }

        // Which hive of the target a key is in: kind SOFTWARE / SYSTEM / USER, uid (USER: SID or "dir:\Users\x"), rel =
        // path below the hive root, regRoot = the root as written into the .reg file (importable by regedit on the
        // repaired system: HKEY_LOCAL_MACHINE\SOFTWARE, ...\SYSTEM, HKEY_USERS\<SID>), phys = the root in this session.
        internal static bool Locate(string key, string soft, string sys, List<string[]> users, out string kind, out string uid, out string rel, out string regRoot, out string phys)
        {
            kind = ""; uid = ""; rel = ""; regRoot = ""; phys = "";
            if (string.IsNullOrEmpty(key) || key.EndsWith("\\")) return false;
            if (Under(key, soft)) { kind = "SOFTWARE"; phys = soft; regRoot = "HKEY_LOCAL_MACHINE\\SOFTWARE"; }
            else if (Under(key, sys)) { kind = "SYSTEM"; phys = sys; regRoot = "HKEY_LOCAL_MACHINE\\SYSTEM"; }
            else
                foreach (string[] u in users)
                    if (u.Length > 2 && Under(key, u[1]))
                    {
                        string sid = u.Length > 3 ? u[3] : "";
                        kind = "USER"; phys = u[1];
                        uid = sid.Length > 0 ? sid : "dir:" + (u[2].Length > 2 && u[2][1] == ':' ? u[2].Substring(2) : u[2]);
                        regRoot = sid.Length > 0 ? "HKEY_USERS\\" + sid : FullRoot(u[1]);
                        break;
                    }
            if (kind.Length == 0 && soft == "HKLM\\SOFTWARE" && key.StartsWith("HKU\\", StringComparison.OrdinalIgnoreCase))
            {
                // live target: a loaded user hive that is not one of the scanned profiles (e.g. a user whose profile
                // folder is elsewhere): identified by its SID
                string sid = key.Substring(4).Split('\\')[0];
                if (UserSid(sid)) { kind = "USER"; uid = sid; phys = "HKU\\" + sid; regRoot = "HKEY_USERS\\" + sid; }
            }
            if (kind.Length == 0) return false;
            rel = key.Length > phys.Length ? key.Substring(phys.Length + 1) : "";
            return true;
        }

        // S-1-5-21-... (local / domain) or S-1-12-1-... (Azure AD) user SID, not a *_Classes hive
        internal static bool UserSid(string sid)
        {
            if (string.IsNullOrEmpty(sid) || !(sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) || sid.StartsWith("S-1-12-1-", StringComparison.OrdinalIgnoreCase))) return false;
            for (int i = 2; i < sid.Length; i++) if (sid[i] != '-' && (sid[i] < '0' || sid[i] > '9')) return false;
            return true;
        }

        static string FullRoot(string k)
        {
            if (k.StartsWith("HKLM\\", StringComparison.OrdinalIgnoreCase)) return "HKEY_LOCAL_MACHINE" + k.Substring(4);
            if (k.StartsWith("HKU\\", StringComparison.OrdinalIgnoreCase)) return "HKEY_USERS" + k.Substring(3);
            return k;
        }

        // The hive root a manifest entry maps to NOW ("" = that hive is not mounted / not part of the target).
        internal static string Resolve(ManEntry e, string soft, string sys, List<string[]> users)
        {
            if (e.RootKind == "SOFTWARE") return soft ?? "";
            if (e.RootKind == "SYSTEM") return sys ?? "";
            foreach (string[] u in users)
            {
                if (u.Length < 3 || u[1].Length == 0) continue;
                string sid = u.Length > 3 ? u[3] : "";
                string dir = "dir:" + (u[2].Length > 2 && u[2][1] == ':' ? u[2].Substring(2) : u[2]);
                if ((sid.Length > 0 && sid.Equals(e.UserId, StringComparison.OrdinalIgnoreCase)) || dir.Equals(e.UserId, StringComparison.OrdinalIgnoreCase)) return u[1];
            }
            if (soft == "HKLM\\SOFTWARE" && UserSid(e.UserId)) return "HKU\\" + e.UserId;   // live: a loaded user hive
            return "";
        }

        static bool Under(string key, string root)
        {
            return !string.IsNullOrEmpty(root) && (key.Equals(root, StringComparison.OrdinalIgnoreCase) || key.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase));
        }

        // Identity of an installation that survives a reboot into WinPE and back: volume serial + Windows folder.
        internal static string InstallId(string winDir, string serial)
        {
            if (string.IsNullOrEmpty(winDir)) return "";
            return string.IsNullOrEmpty(serial) || winDir.Length < 3 ? winDir.ToUpperInvariant() : serial + winDir.Substring(2).ToUpperInvariant();
        }

        // ---- remediation: one place for «Удалить», «Карантин», «Обезвредить», the Easy button and the repairs ----
        // 1 = done, 2 = nothing to do (already default / already gone), 0 = failed (quarErr says why).
        // backup = the original goes to the quarantine first; no backup -> no change.
        int Remediate(Finding x, bool backup)
        {
            int r = RemediateMain(x, backup);
            if (r == 0 || x.AlsoKeys == null) return r;
            // a task: its XML (or Tree key) is gone - now its TaskCache keys, else Windows 8+ still runs it
            foreach (string k in x.AlsoKeys)
            {
                int e = BackedDeleteKey(k, backup, x.Category + " (TaskCache)");
                if (e == 0) return 0;
                if (e == 1) r = 1;
            }
            return r;
        }

        int RemediateMain(Finding x, bool backup)
        {
            if (x == null || x.Kind == 3) return 0;
            if (x.Kind == 4) return BackedSet(x.DelKey, x.DelName, x.ResetData, x.ResetType, backup, x.Category + " -> дефолт");
            if (x.Kind == 0) return BackedDeleteValue(x.DelKey, x.DelName, backup, x.Category);
            if (x.Kind == 1) return BackedDeleteKey(x.DelKey, backup, x.Category);
            if (x.Kind == 2)
            {
                if (string.IsNullOrEmpty(x.DelPath) || !FsOps.Exists(x.DelPath)) return 2;
                if (backup) return QuarFile(x.DelPath) ? 1 : 0;
                string err;
                if (FsOps.DeleteFile(x.DelPath, out err)) return 1;
                NoteQuarErr(Path.GetFileName(x.DelPath) + ": " + err);
            }
            return 0;
        }

        // value already equal (same type, same data) to what would be written
        static bool SameValue(string key, string name, object data, RegistryValueKind kind)
        {
            foreach (string[] v in Reg.Values(key))
                if (v[0].Equals(name, StringComparison.OrdinalIgnoreCase)) return v[2] == Reg.KindName(kind) && v[1] == Reg.FormatData(data);
            return false;
        }

        int BackedSet(string key, string name, object data, RegistryValueKind kind, bool backup, string note)
        {
            if (string.IsNullOrEmpty(key) || name == null || data == null) return 0;
            if (SameValue(key, name, data, kind)) return 2;
            if (backup && !QuarReg(key, name, note)) return 0;
            if (Reg.SetValue(key, name, data, kind)) return 1;
            NoteQuarErr("не записано: " + key + "\\" + name);
            return 0;
        }

        int BackedDeleteValue(string key, string name, bool backup, string note)
        {
            if (string.IsNullOrEmpty(key) || name == null || !Reg.HasValue(key, name)) return 2;
            if (backup && !QuarReg(key, name, note)) return 0;
            if (Reg.DeleteValue(key, name)) return 1;
            NoteQuarErr("не удалено: " + key + "\\" + name);
            return 0;
        }

        int BackedDeleteKey(string key, bool backup, string note)
        {
            if (string.IsNullOrEmpty(key) || !Reg.KeyExists(key)) return 2;
            if (backup && !QuarReg(key, null, note)) return 0;
            if (Reg.DeleteKey(key)) return 1;
            NoteQuarErr("не удалён ключ: " + key);
            return 0;
        }

        void QuarantineChecked(ListView target)
        {
            int n = 0; foreach (ListViewItem it in target.Items) if (it.Checked) n++;
            if (n == 0) { MessageBox.Show("Ничего не отмечено."); return; }
            if (!HiberGuard("Карантин", null)) return;
            if (MessageBox.Show("Карантин отмеченных (" + n + ")?\r\nФайлы переносятся в папку карантина, значения и ветки реестра сохраняются в .reg и удаляются " +
                "(Winlogon Shell/Userinit, BootExecute и т.п. не удаляются, а возвращаются к дефолту — тоже с бэкапом).\r\n" +
                "Папка: <диск цели>\\RescueScan_Quarantine\\<дата_время> (не на RAM-диске X:).", "Карантин",
                MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            if (!EnsureTarget()) { MessageBox.Show("Сначала выбери установку Windows и нажми «Сканировать»."); return; }
            List<ListViewItem> done = new List<ListViewItem>();
            int ok = 0, fail = 0, skip = 0, already = 0;
            quarErr = "";
            foreach (ListViewItem it in target.Items)
            {
                if (!it.Checked) continue;
                Finding x = (Finding)it.Tag;
                if (x.Kind == 3) { skip++; continue; }
                int r = Remediate(x, true);
                if (r == 1) { ok++; done.Add(it); } else if (r == 2) { already++; done.Add(it); } else fail++;
            }
            foreach (ListViewItem it in done) target.Items.Remove(it);
            lblStatus.Text = "Карантин: " + ok + "   уже чисто: " + already + "   ошибок: " + fail + "   пропущено (info): " + skip + "   -> " + (quarDir.Length > 0 ? quarDir : "(нет папки)")
                + (fail > 0 && quarErr.Length > 0 ? "   причина: " + quarErr : "");
        }

        void QuarantineSelectedFiles()
        {
            if (lvFiles.SelectedItems.Count == 0) { MessageBox.Show("Выбери файл."); return; }
            if (!HiberGuardFiles("Карантин")) return;
            int ok = 0, fail = 0;
            quarErr = "";
            foreach (ListViewItem it in lvFiles.SelectedItems)
            {
                string tag = (string)it.Tag;
                if (!tag.StartsWith("F|")) continue;   // только файлы
                if (QuarFile(tag.Substring(2))) ok++; else fail++;
            }
            lblFiles.Text = "В карантин: " + ok + "   ошибок: " + fail + "   -> " + (quarDir.Length > 0 ? quarDir : "(нет папки)") + (fail > 0 && quarErr.Length > 0 ? "   причина: " + quarErr : "");
            Nav(curPath);
        }

        // ---- Quarantine viewer / restore ----
        // Newest quarantine folder (by its date_time name) in <every drive>\RescueScan_Quarantine, next to the exe, or
        // an old-format <exe folder>\Quarantine_* .
        void QuarAutoFind()
        {
            List<string> roots = new List<string>();
            string exeDir = "";
            try { exeDir = Path.GetDirectoryName(Application.ExecutablePath); } catch { }
            try
            {
                foreach (DriveInfo d in DriveInfo.GetDrives())
                    if (d.DriveType == DriveType.Fixed || d.DriveType == DriveType.Removable) roots.Add(d.Name.TrimEnd('\\') + "\\RescueScan_Quarantine");
            }
            catch { }
            if (exeDir.Length > 0) roots.Add(exeDir.TrimEnd('\\') + "\\RescueScan_Quarantine");
            string best = "", bestKey = "";
            foreach (string r in roots)
                try
                {
                    if (!Directory.Exists(r)) continue;
                    foreach (string d in Directory.GetDirectories(r))
                    {
                        string k = Path.GetFileName(d);
                        if (string.CompareOrdinal(k, bestKey) > 0 && File.Exists(Path.Combine(d, QuarMan.ManifestName))) { bestKey = k; best = d; }
                    }
                }
                catch { }
            try
            {
                if (exeDir.Length > 0)
                    foreach (string d in Directory.GetDirectories(exeDir, "Quarantine_*"))
                    {
                        string k = Path.GetFileName(d).Substring(11);
                        if (string.CompareOrdinal(k, bestKey) > 0 && File.Exists(Path.Combine(d, QuarMan.ManifestName))) { bestKey = k; best = d; }
                    }
            }
            catch { }
            if (best.Length == 0) { lblQuar.Text = "Папок карантина (X:\\RescueScan_Quarantine\\…) не найдено. Нажми «Открыть папку…»."; lvQuar.Items.Clear(); return; }
            QuarLoad(best);
        }

        void QuarBrowse()
        {
            FolderBrowserDialog d = new FolderBrowserDialog();
            d.Description = "Выбери папку карантина (в ней должен быть manifest.txt)";
            if (d.ShowDialog() == DialogResult.OK) QuarLoad(d.SelectedPath);
        }

        void QuarLoad(string dir)
        {
            lvQuar.Items.Clear(); quarViewDir = dir;
            string mf = Path.Combine(dir, QuarMan.ManifestName);
            if (!File.Exists(mf)) { lblQuar.Text = "Нет manifest.txt в " + dir; return; }
            string[] lines;
            try { lines = File.ReadAllLines(mf); } catch (Exception ex) { lblQuar.Text = "manifest.txt не читается: " + ex.Message; return; }
            bool v2 = lines.Length > 0 && QuarMan.IsHeader(lines[0]);
            int cnt = 0, bad = 0;
            foreach (string line in lines)
            {
                string err;
                ManEntry e = QuarMan.Parse(line, out err);
                if (e == null) { if (err.Length > 0) bad++; continue; }
                if (v2 != (e.Type != "LEGACY")) { bad++; continue; }   // both formats in one manifest: not ours
                string what, where;
                if (e.Type == "FILE") { what = "файл"; where = e.Orig; }
                else if (e.Type == "REG")
                {
                    what = e.IsKey ? "ключ" : "значение";
                    where = e.RootKind + (e.RootKind == "USER" ? " " + e.UserId : "") + (e.Rel.Length > 0 ? "\\" + e.Rel : "") + (e.IsKey ? "" : "  : " + (e.ValueName.Length > 0 ? e.ValueName : "(по умолчанию)"))
                        + (e.Note.Length > 0 ? "   [" + e.Note + "]" : "");
                }
                else { what = "старый " + e.Note; where = e.Orig; }
                ListViewItem it = new ListViewItem(new string[] { what, where, e.Backup, e.Type == "REG" ? e.Install : e.Type == "FILE" ? (e.Vol.Length > 0 ? "том " + e.Vol : "") : "только вручную" });
                it.Tag = e;
                if (e.Type == "LEGACY" || !QuarMan.Inside(dir, e.Backup) || !File.Exists(Path.Combine(dir, e.Backup))) it.ForeColor = Color.Gray;
                lvQuar.Items.Add(it); cnt++;
            }
            lblQuar.Text = "Карантин: " + dir + "   (записей: " + cnt + (bad > 0 ? ", отброшено строк: " + bad : "") + ")"
                + (v2 ? "" : "   СТАРЫЙ формат: только просмотр — .reg импортируй вручную, файлы верни вручную");
        }

        void QuarRestore()
        {
            List<ManEntry> sel = new List<ManEntry>();
            List<ListViewItem> items = new List<ListViewItem>();
            foreach (ListViewItem it in lvQuar.Items) if (it.Checked) { sel.Add((ManEntry)it.Tag); items.Add(it); }
            if (sel.Count == 0) { MessageBox.Show("Отметь, что восстановить."); return; }
            if (!HiberGuard("Восстановить", null)) return;
            if (MessageBox.Show("Восстановить отмеченные (" + sel.Count + ") на исходные места?\r\nФайл, который сейчас лежит на месте оригинала, не удаляется, а переименовывается (*.before-restore-…).",
                "Восстановление", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            bool anyReg = sel.Exists(delegate(ManEntry e) { return e.Type == "REG"; });
            if (anyReg) EnsureTarget();
            // newest first: a key backed up after its Start value was changed is restored first, then the original value
            List<int> order = new List<int>();
            for (int i = 0; i < sel.Count; i++) order.Add(i);
            order.Sort(delegate(int a, int b) { return sel[b].N.CompareTo(sel[a].N); });
            int ok = 0, fail = 0;
            string why = "", stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            List<ListViewItem> done = new List<ListViewItem>();
            foreach (int i in order)
            {
                ManEntry e = sel[i];
                string w = "";
                bool r = false;
                try
                {
                    string bk = Path.Combine(quarViewDir, e.Backup);
                    if (e.Type == "LEGACY") w = "старый формат карантина — восстанови вручную (" + e.Backup + ")";
                    else if (!QuarMan.Inside(quarViewDir, e.Backup)) w = "бэкап вне папки карантина: " + e.Backup;
                    else if (!File.Exists(bk)) w = "бэкапа нет (уже восстановлен?): " + e.Backup;
                    else if (!string.Equals(QuarMan.Sha256(bk), e.Sha, StringComparison.OrdinalIgnoreCase)) w = "бэкап " + e.Backup + " изменён после карантина (SHA-256 не совпадает) — не восстанавливаю";
                    else if (e.Type == "FILE") r = RestoreFile(e, bk, stamp, out w);
                    else r = RestoreReg(e, bk, out w);
                }
                catch (Exception ex) { r = false; w = ex.Message; }
                if (r) { ok++; done.Add(items[i]); }
                else { fail++; if (why.Length == 0) why = Reg.OneLine(w, 260); }
            }
            foreach (ListViewItem it in done) lvQuar.Items.Remove(it);
            lblQuar.Text = "Восстановлено: " + ok + "   ошибок: " + fail + (fail > 0 && why.Length > 0 ? "   причина: " + why : "");
            if (fail > 0 && why.Length > 0) MessageBox.Show("Не восстановлено: " + fail + "\r\n" + why, "Восстановление", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }

        // Drive letter that the volume with this serial has now ("" = not attached).
        static string DriveOfSerial(string serial)
        {
            try
            {
                foreach (DriveInfo d in DriveInfo.GetDrives())
                    if (d.Name.Length >= 2 && string.Equals(FsOps.VolumeSerial(d.Name), serial, StringComparison.OrdinalIgnoreCase)) return d.Name.Substring(0, 2);
            }
            catch { }
            return "";
        }

        bool RestoreFile(ManEntry e, string bk, string stamp, out string why)
        {
            why = "";
            string orig = e.Orig;
            if (e.Vol.Length > 0)
            {
                string d = DriveOfSerial(e.Vol);
                if (d.Length == 0) { why = "том " + e.Vol + " (был " + orig.Substring(0, 2) + ") сейчас не подключён"; return false; }
                orig = d + orig.Substring(2);
            }
            string err;
            if (FsOps.Exists(orig))
            {
                string aside = orig + ".before-restore-" + stamp;
                if (!FsOps.MoveFile(orig, aside, out err)) { why = "на месте оригинала есть файл, отодвинуть его не вышло: " + err; return false; }
            }
            string od = orig.Substring(0, orig.LastIndexOf('\\'));
            if (od.Length > 2 && !FsOps.Exists(od)) Directory.CreateDirectory(od);
            if (!FsOps.MoveFile(bk, orig, out err)) { why = orig + ": " + err; return false; }
            if ((e.Attrs & 0x7) != 0) FsOps.SetAttrs(orig, e.Attrs & 0x27);   // ReadOnly / Hidden / System / Archive
            return true;
        }

        // Writes a registry backup back through the Registry API into the hive that is mounted NOW for the same
        // installation / profile; refuses (with the reason) when that hive is not available.
        bool RestoreReg(ManEntry e, string bk, out string why)
        {
            why = "";
            if (!tgtReady) { why = "цель не выбрана: выбери установку Windows и нажми «Сканировать»"; return false; }
            if (!string.Equals(e.Install, tgtInstall, StringComparison.OrdinalIgnoreCase))
            { why = "бэкап другой установки (" + e.Install + "), а цель сейчас " + TargetName() + " (" + tgtInstall + "): выбери ту установку и нажми «Сканировать»"; return false; }
            string root = Resolve(e, tgtSoft, tgtSys, tgtUsers);
            if (root.Length == 0)
            {
                why = (e.RootKind == "USER" ? "профиль " + e.UserId : "куст " + e.RootKind) + " цели " + TargetName() + " сейчас не смонтирован: нажми «Сканировать» и повтори";
                return false;
            }
            string err;
            List<RegSection> secs = RegFile.Parse(File.ReadAllText(bk), out err);
            if (secs == null) { why = e.Backup + ": " + err; return false; }
            List<string> rels = new List<string>();
            foreach (RegSection s in secs)
            {
                if (!Under(s.Path, e.RegRoot)) { why = e.Backup + ": ключ вне " + e.RegRoot; return false; }
                string rel = s.Path.Substring(e.RegRoot.Length).TrimStart('\\');
                bool fits = e.IsKey ? Under(rel, e.Rel) : rel.Equals(e.Rel, StringComparison.OrdinalIgnoreCase) && s.Values.Count == 1 && s.Values[0].Name == e.ValueName;
                if (!fits || (rel.Length == 0 && e.IsKey)) { why = e.Backup + ": не совпадает с записью в manifest.txt"; return false; }
                rels.Add(rel);
            }
            for (int i = 0; i < secs.Count; i++)
            {
                string k = root + (rels[i].Length > 0 ? "\\" + rels[i] : "");
                if (e.IsKey && !Reg.CreateKey(k)) { why = "ключ не создан: " + k; return false; }
                foreach (RegVal v in secs[i].Values)
                {
                    bool r = v.Delete ? (!Reg.HasValue(k, v.Name) || Reg.DeleteValue(k, v.Name)) : Reg.SetRaw(k, v.Name, v.Type, v.Data);
                    if (!r) { why = "не записано: " + k + "\\" + v.Name; return false; }
                }
            }
            return true;
        }

        // ================= WHO REFERENCES A FILE =================
        void WhoReferences()
        {
            if (lvFiles.SelectedItems.Count == 0) { MessageBox.Show("Выбери файл в проводнике."); return; }
            string tag = (string)lvFiles.SelectedItems[0].Tag;
            string full = tag.Substring(2);
            string low = full.ToLowerInvariant();
            string fname = Path.GetFileName(full).ToLowerInvariant();
            List<string> hits = new List<string>();
            foreach (Finding x in lastFindings)
            {
                bool match = false;
                if (x.Kind == 2 && x.DelPath != null && x.DelPath.ToLowerInvariant() == low) match = true;
                else
                {
                    string vp = TargetPayload(x).ToLowerInvariant();
                    if (vp == low) match = true;
                    else if (x.Value != null && x.Value.ToLowerInvariant().Contains(fname) && fname.Length > 3) match = true;
                }
                if (match) hits.Add("[" + x.Risk + "] " + x.Category + "  —  " + x.Name + "\r\n      " + x.Location);
            }
            if (lastFindings.Count == 0) { MessageBox.Show("Сначала выполни «Сканировать» на вкладке Автозагрузка."); return; }
            if (hits.Count == 0) { MessageBox.Show("Ссылок на этот файл в автозагрузке не найдено:\r\n" + full, "Кто ссылается"); return; }
            MessageBox.Show("Файл: " + full + "\r\n\r\nНайден в точках автозапуска (" + hits.Count + "):\r\n\r\n" + string.Join("\r\n\r\n", hits.ToArray()), "Кто ссылается на файл");
        }

        // ================= REPAIR (Shell/Userinit/cmd/AppInit -> default or custom) =================
        // {name, subkey(under hive), valueName, default, "1"=delete-for-default}
        static string[][] Anchors(string systemRoot)
        {
            return new string[][] {
                new string[]{ "Winlogon Shell",    "Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "Shell",    Defaults.Shell, "0" },
                new string[]{ "Winlogon Userinit", "Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "Userinit", Defaults.Userinit(systemRoot), "0" },
                new string[]{ "Winlogon Taskman",  "Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "Taskman",  "", "1" },
                new string[]{ "AppInit_DLLs",      "Microsoft\\Windows NT\\CurrentVersion\\Windows",  "AppInit_DLLs", "", "0" },
                new string[]{ "AppInit_DLLs (WOW64)", "Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows", "AppInit_DLLs", "", "0" },
                new string[]{ "cmd AutoRun",       "Microsoft\\Command Processor",                    "AutoRun",  "", "1" },
                new string[]{ "cmd AutoRun (WOW64)", "Wow6432Node\\Microsoft\\Command Processor",     "AutoRun",  "", "1" },
            };
        }

        // An anchor's current value is fine: Shell / Userinit by the same predicates as the scan, a "delete" anchor when
        // absent, an empty default (AppInit_DLLs) when absent or empty, anything else when equal to the default.
        internal static bool AnchorGood(string[] a, string cur, bool present, string systemRoot)
        {
            if (a[2] == "Shell") return present && Defaults.ShellClean(cur, systemRoot);
            if (a[2] == "Userinit") return present && Defaults.UserinitClean(cur, systemRoot);
            if (a[4] == "1") return !present;
            if (a[3].Length == 0) return !present || cur.Trim().Length == 0;
            return present && string.Equals(cur.Trim(), a[3], StringComparison.OrdinalIgnoreCase);
        }

        // Puts one anchor to its default (or 'custom') with a quarantine backup first. 1 changed / 2 already fine / 0 failed.
        int ApplyAnchor(string[] a, string custom)
        {
            string root = SoftRoot();
            if (root.Length == 0) return 0;
            string key = root + "\\" + a[1];
            if (a[1].StartsWith("Wow6432Node\\") && !Reg.KeyExists(key)) return 2;   // 32-bit Windows: no WOW64 copy
            string cur = ""; bool present = false;
            foreach (string[] v in Reg.Values(key)) if (v[0].Equals(a[2], StringComparison.OrdinalIgnoreCase)) { cur = v[1]; present = true; }
            string note = "Ремонт: " + a[0];
            if (custom != null) return BackedSet(key, a[2], custom, RegistryValueKind.String, true, note);
            if (AnchorGood(a, cur, present, tgtSysRoot)) return 2;
            if (a[4] == "1") return BackedDeleteValue(key, a[2], true, note);
            return BackedSet(key, a[2], a[3], RegistryValueKind.String, true, note);
        }

        // simplified autoruns: Run/RunOnce/Startup/Scheduled Tasks only (like Task Manager Startup / Simple Unlocker)
        void SimpleRefresh()
        {
            if (lvSimple == null) return;
            lvSimple.Items.Clear();
            foreach (Finding x in lastFindings)
            {
                string c = x.Category;
                bool inc = c.StartsWith("Run") || c.StartsWith("Startup") || c.StartsWith("Scheduled Task") || c.StartsWith("Task ");
                if (!inc) continue;
                ListViewItem it = new ListViewItem(new string[] { c, x.Name, x.Value, x.Risk });
                it.Tag = x;
                if (x.Risk == "SUSPECT") it.BackColor = Color.FromArgb(255, 205, 205);
                else if (x.Risk == "REVIEW") it.BackColor = Color.FromArgb(255, 248, 205);
                lvSimple.Items.Add(it);
            }
            if (lastFindings.Count == 0) lblStatus.Text = "Нажми «Сканировать».";
        }


        // SOFTWARE root of the target the scan used. "" = not available: actions refuse (RequireSoft) instead of
        // silently falling back to the live HKLM\SOFTWARE of the machine that runs the tool.
        string SoftRoot() { return tgtSoft; }
        bool IsOffline() { return tgtReady && !tgtLive; }

        string TargetName() { return tgtReady ? tgtWinDir + (tgtLive ? " (живая)" : " (офлайн)") : "не выбрана"; }

        // Target for actions = the one the last scan used; before the first scan, the installation picked in the list.
        bool EnsureTarget()
        {
            if (tgtReady) return true;
            WinTarget t = cboWin.SelectedItem as WinTarget;
            if (t == null) return false;
            string w = PrepareTarget(t);
            lblStatus.Text = "Цель: " + TargetName() + (w.Length > 0 ? "   ВНИМАНИЕ: " + w : "");
            return tgtReady;
        }

        // Guard for every repair / unlock / assoc / IFEO / policy action: the target's SOFTWARE hive must be available.
        // Before any change to an OFFLINE target whose Windows is hibernated (Fast Startup): warn and ask once per target
        // drive (default «Нет»). path != null: an Explorer action - only paths on that target drive are guarded.
        string hiberAck = "";
        bool HiberGuard(string what, string path)
        {
            WinTarget t = cboWin.SelectedItem as WinTarget;
            string drive = tgtReady && tgtWinDir.Length >= 2 ? tgtWinDir.Substring(0, 2) : (t != null && t.WinDir.Length >= 2 ? t.WinDir.Substring(0, 2) : "");
            bool live = tgtReady ? tgtLive : (t != null && t.Live);
            if (live || drive.Length == 0) return true;   // the running OS cannot be hibernated
            if (path != null && !path.StartsWith(drive, StringComparison.OrdinalIgnoreCase)) return true;
            if (hiberAck.Equals(drive, StringComparison.OrdinalIgnoreCase) || !Hiber.Active(drive)) return true;
            if (MessageBox.Show("Windows на " + drive + " не выключена, а ГИБЕРНИРОВАНА («Быстрый запуск»: " + drive + "\\hiberfil.sys содержит образ памяти).\r\n\r\n" +
                    "При следующем включении она продолжит работу из этого образа: изменения, сделанные отсюда, потеряются (вирус вернётся),\r\n" +
                    "а файловая система может повредиться.\r\n\r\nПравильно: загрузись в эту Windows и сделай «Перезагрузку» (или shutdown /s /full /t 0,\r\n" +
                    "или отключи «Быстрый запуск»), затем снова запусти RescueScan. Сканировать можно и так.\r\n\r\n" +
                    "Всё равно выполнить «" + what + "» (и дальнейшие изменения на " + drive + " в этом сеансе)?",
                    "Гибернация / Быстрый запуск", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                return false;
            hiberAck = drive;
            Watchdog.Log("гибернация: пользователь разрешил изменения на " + drive + " несмотря на hiberfil.sys");
            return true;
        }

        bool HiberGuardFiles(string what)
        {
            foreach (ListViewItem it in lvFiles.SelectedItems)
            {
                string tag = it.Tag as string;
                if (tag != null && tag.Length > 2 && !HiberGuard(what, tag.Substring(2))) return false;
            }
            return true;
        }

        bool RequireSoft(string what)
        {
            if (!HiberGuard(what, null)) return false;
            if (!EnsureTarget())
            {
                MessageBox.Show("Сначала выбери установку Windows («Найти ОС») и нажми «Сканировать».", what);
                return false;
            }
            if (tgtSoft.Length > 0) return true;
            MessageBox.Show("Куст SOFTWARE выбранной системы " + tgtWinDir + " не смонтирован — «" + what + "» отменено.\r\n" +
                "Изменения НЕ применяются к системе, на которой запущена программа.\r\n" +
                "Закрой regedit (если открыт) и нажми «Сканировать» ещё раз.", what, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return false;
        }

        void RepairRefresh() { RepairRefresh(false); }

        void RepairRefresh(bool prepare)
        {
            lvRepair.Items.Clear();
            if (prepare) EnsureTarget();
            string root = SoftRoot();
            foreach (string[] a in Anchors(tgtSysRoot))
            {
                string cur = "(нет значения)"; bool present = false;
                if (root.Length == 0) cur = tgtReady ? "(куст SOFTWARE цели не смонтирован)" : "(цель не выбрана: «Сканировать» или «Обновить»)";
                else
                    foreach (string[] v in Reg.Values(root + "\\" + a[1]))
                        if (v[0].Equals(a[2], StringComparison.OrdinalIgnoreCase)) { cur = v[1]; present = true; }
                string def = a[4] == "1" ? "(удалить значение)" : (a[3].Length == 0 ? "(пусто)" : a[3]);
                ListViewItem it = new ListViewItem(new string[] { a[0], cur, def });
                it.Tag = a;
                if (root.Length > 0 && !AnchorGood(a, present ? cur : "", present, tgtSysRoot)) it.BackColor = Color.FromArgb(255, 220, 220);
                lvRepair.Items.Add(it);
            }
        }

        void RepairSet(bool custom)
        {
            if (lvRepair.SelectedItems.Count == 0) { MessageBox.Show("Выбери строку в списке, потом жми «→ Дефолт» или «→ Своё…»."); return; }
            if (!RequireSoft("Ремонт")) return;
            int ok = 0, fail = 0;
            quarErr = "";
            foreach (ListViewItem it in lvRepair.SelectedItems)
            {
                string[] a = (string[])it.Tag;
                string val = null;
                if (custom)
                {
                    val = Prompt("Своё значение для «" + a[0] + "»", a[3]);
                    if (val == null) continue;
                }
                int r = ApplyAnchor(a, val);
                if (r == 1) ok++; else if (r == 0) fail++;
            }
            RepairRefresh();
            lblStatus.Text = (IsOffline() ? "Ремонт офлайн-куста (" + tgtWinDir + ")" : "Ремонт ЖИВОЙ системы (HKLM\\SOFTWARE)") + ": изменено " + ok + ", ошибок " + fail
                + (ok > 0 ? "   бэкап: " + quarDir : "") + (fail > 0 && quarErr.Length > 0 ? "   причина: " + quarErr : "");
        }

        static string Prompt(string title, string def)
        {
            Form f = new Form(); f.Text = title; f.Width = 540; f.Height = 150;
            f.StartPosition = FormStartPosition.CenterScreen; f.FormBorderStyle = FormBorderStyle.FixedDialog;
            f.MinimizeBox = false; f.MaximizeBox = false; f.TopMost = true;
            TextBox tb = new TextBox(); tb.Left = 12; tb.Top = 20; tb.Width = 500; tb.Text = def;
            Button ok = new Button(); ok.Text = "OK"; ok.Left = 336; ok.Top = 60; ok.Width = 80; ok.DialogResult = DialogResult.OK;
            Button cc = new Button(); cc.Text = "Отмена"; cc.Left = 432; cc.Top = 60; cc.Width = 80; cc.DialogResult = DialogResult.Cancel;
            f.Controls.Add(tb); f.Controls.Add(ok); f.Controls.Add(cc); f.AcceptButton = ok; f.CancelButton = cc;
            return f.ShowDialog() == DialogResult.OK ? tb.Text : null;
        }

        // ---- live guard: keep Winlogon Shell/Userinit at default while running on the infected OS ----
        void GuardToggle()
        {
            if (chkGuard.Checked)
            {
                if (guarding) return;
                if (!EnsureTarget() || !tgtLive)   // the guard writes the RUNNING OS's HKLM: only when that is the target
                {
                    MessageBox.Show("«Стеречь Winlogon» работает только когда цель — ЖИВАЯ система (та, где запущена программа).\r\nСейчас цель: " + TargetName(), "Страж");
                    chkGuard.Checked = false;
                    return;
                }
                guarding = true; SyncGuardFlag();
                guardThread = new Thread(GuardLoop); guardThread.IsBackground = true; guardThread.Start();
                Watchdog.Log("guard: слежение за Winlogon (live) включено");
                lblStatus.Text = "Guard включён — Winlogon Shell/Userinit возвращаются к дефолту при подмене. Лог: " + Watchdog.LogPath;
            }
            else if (guarding) { guarding = false; SyncGuardFlag(); Watchdog.Log("guard: слежение выключено"); }
        }

        void GuardLoop()
        {
            string wl = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
            string sr = RunningWinDir();   // the guard only runs while the target is the running OS
            while (guarding)
            {
                foreach (string name in new string[] { "Shell", "Userinit" })
                {
                    string cur = null;
                    foreach (string[] v in Reg.Values(wl))
                        if (v[0].Equals(name, StringComparison.OrdinalIgnoreCase)) cur = v[1];
                    bool shell = name == "Shell";
                    if (cur == null || (shell ? Defaults.ShellClean(cur, sr) : Defaults.UserinitClean(cur, sr))) continue;
                    string def = shell ? Defaults.Shell : Defaults.Userinit(sr);
                    Reg.SetString(wl, name, def);
                    Watchdog.Log("guard: Winlogon " + name + " подменён на '" + cur + "' -> вернул '" + def + "'");
                }
                for (int i = 0; i < 30 && guarding; i++) Thread.Sleep(100);
            }
        }

        static CheckBox EasyChk(string text, int left, int top, bool chk)
        {
            CheckBox c = new CheckBox(); c.Text = text; c.Left = left; c.Top = top; c.Width = 500; c.Checked = chk;
            return c;
        }

        // What «Запустить» does with a file: "exe" = start it directly (CreateProcess, no ShellExecute: a hijacked
        // HKCU\Software\Classes\exefile would otherwise run malware with our admin token), "cmd" = a batch file through
        // System32\cmd.exe /k, "text" = never executed, only opened in System32\notepad.exe.
        internal static string LaunchMode(string path)
        {
            string e = "";
            try { e = (Path.GetExtension(path) ?? "").ToLowerInvariant(); } catch { }
            if (e == ".exe" || e == ".com") return "exe";
            if (e == ".bat" || e == ".cmd") return "cmd";
            return "text";
        }

        void LaunchSelected()
        {
            if (lvFiles.SelectedItems.Count != 1) { MessageBox.Show("Выбери один файл."); return; }
            string tag = (string)lvFiles.SelectedItems[0].Tag;
            if (!tag.StartsWith("F|")) { MessageBox.Show("Это папка — выбери файл (напр. cmd.exe, regedit.exe)."); return; }
            string p = tag.Substring(2);
            string mode = LaunchMode(p);
            string exe = p, args = "";
            if (mode == "cmd") { exe = Reg.SysExe("cmd.exe"); args = "/k " + Reg.QuoteArg(p); }
            else if (mode == "text") { exe = Reg.SysExe("notepad.exe"); args = Reg.QuoteArg(p); }
            if (exe.IndexOf('\\') < 0) { MessageBox.Show("Нет " + exe + " в System32 — открыть нечем.", "Запуск"); return; }   // never a search-path lookup
            string hijack = Reg.IsWindows ? Reg.ToolHijack("HKLM\\SOFTWARE", Path.GetFileName(exe)) : "";
            if (hijack.Length > 0)
            {
                MessageBox.Show("Запуск отменён: " + Path.GetFileName(exe) + " перехвачен через Image File Execution Options — " + hijack +
                    "\r\nВместо него запустилась бы чужая программа с правами администратора. Сними перехват («Снять блокировки» на вкладке «Ремонт»).", "Запуск");
                return;
            }
            string what = mode == "exe" ? "Запустить программу?\r\n" + p + "\r\n\r\nЗапускай только доверенные программы (cmd, regedit, свои тулзы)."
                : mode == "cmd" ? "Это пакетный файл (скрипт). Запустить его в cmd.exe?\r\n" + p + "\r\n\r\nСкрипт выполнится с правами администратора — только если знаешь, что внутри."
                : "Это не программа — файл НЕ будет выполнен, а откроется как текст в Блокноте:\r\n" + p;
            if (MessageBox.Show(what, "Запуск", MessageBoxButtons.YesNo, mode == "text" ? MessageBoxIcon.Information : MessageBoxIcon.Warning) != DialogResult.Yes) return;
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo(exe, args);
                psi.UseShellExecute = false;   // never ShellExecute: no file-association lookup
                try { psi.WorkingDirectory = Path.GetDirectoryName(p); } catch { }
                Process.Start(psi);
                lblFiles.Text = (mode == "text" ? "Открыто в Блокноте: " : "Запущено: ") + Path.GetFileName(p);
            }
            catch (Exception ex) { MessageBox.Show(ex.Message); }
        }

        // ================= DEFUSE (снять критичность/привязки перед удалением) =================
        static string ServiceKeyOf(string k)
        {
            if (k == null) return k;
            int i = k.IndexOf("\\Services\\", StringComparison.OrdinalIgnoreCase);
            if (i < 0) return k;
            int j = k.IndexOf('\\', i + 10);
            return j > 0 ? k.Substring(0, j) : k;
        }

        // Values that must be RESET to the Windows default, never deleted (Kind 4: Winlogon Shell/Userinit/VMApplet,
        // BootExecute, SetupExecute, SafeBoot AlternateShell): a deleted Userinit = logon/logoff loop (research
        // windows-semantics Q1), a deleted BootExecute drops autochk. «Удалить», «Карантин», «Обезвредить» and the Easy
        // button write the default back (with a quarantine backup) through Remediate.
        internal static bool ResetOnly(Finding x)
        {
            return x != null && x.Kind == 4;
        }

        // 1 = defused, 2 = already defused, 0 = failed, -1 = not applicable. Every change is backed up first.
        int DefuseOne(Finding x)
        {
            if (x == null) return -1;
            if (x.Kind == 4) return Remediate(x, true);
            string c = x.Category;
            if (c.StartsWith("Service") || c.StartsWith("svchost"))
            {
                string k = x.DelKey != null ? x.DelKey : x.Location;
                string root = ServiceKeyOf(k);
                // An ImagePath/ServiceDll planted in a NESTED subkey must never disable the real parent service
                // (malware could steer Start=4 onto a boot driver): only the service key itself or its Parameters key.
                if (root == null || !(string.Equals(k, root, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(k, root + "\\Parameters", StringComparison.OrdinalIgnoreCase))) return -1;
                if (!Reg.KeyExists(root)) return 2;   // already removed (e.g. quarantined): never recreate a skeleton service key
                int a = BackedSet(root, "Start", 4, RegistryValueKind.DWord, true, "Обезвредить: Start=4");
                if (a == 0) return 0;
                int b = BackedSet(root, "ErrorControl", 1, RegistryValueKind.DWord, true, "Обезвредить: ErrorControl=1");
                return b == 0 ? 0 : (a == 1 || b == 1 ? 1 : 2);
            }
            if (c.StartsWith("IFEO"))
                return BackedDeleteValue(x.DelKey != null ? x.DelKey : x.Location, "Debugger", true, "Обезвредить: IFEO Debugger");
            return -1;
        }

        void DefuseChecked(ListView target)
        {
            if (!HiberGuard("Обезвредить", null)) return;
            int done = 0, skip = 0, fail = 0, already = 0;
            quarErr = "";
            foreach (ListViewItem it in target.Items)
            {
                if (!it.Checked) continue;
                int r = DefuseOne((Finding)it.Tag);
                if (r == 1) done++; else if (r == 2) already++; else if (r == 0) fail++; else skip++;
            }
            if (done + skip + fail + already == 0) { MessageBox.Show("Отметь службы / IFEO / Winlogon / BootExecute, которые обезвредить."); return; }
            lblStatus.Text = "Обезврежено якорей: " + done + "   уже: " + already + "   ошибок: " + fail + "   (не применимо: " + skip + ")"
                + (done > 0 ? "   бэкап: " + quarDir : "") + (fail > 0 && quarErr.Length > 0 ? "   причина: " + quarErr : "") + ". Теперь можно удалять/карантинить файл.";
        }

        // ================= RESTORE DEFAULTS =================
        // Winlogon Shell/Userinit/Taskman, AppInit_DLLs and cmd AutoRun (also the WOW64 copies): every change backed up.
        int RestoreWinlogonDefaults(out int fail)
        {
            int n = 0; fail = 0;
            if (SoftRoot().Length == 0) return 0;   // never a fallback to the live HKLM (see RequireSoft)
            foreach (string[] a in Anchors(tgtSysRoot))
            {
                int r = ApplyAnchor(a, null);
                if (r == 1) n++; else if (r == 0) fail++;
            }
            return n;
        }

        // Removes IFEO Debugger values (native + Wow6432Node, also in filter subkeys <exe>\<n>), never the IFEO keys
        // (they also hold Exploit Protection settings). Known legitimate debuggers (Process Explorer / System Informer
        // for taskmgr, Notepad++ for notepad, Microsoft debuggers) are kept: kept = how many.
        int ClearIFEODirect(out int kept)
        {
            int n = 0; kept = 0;
            if (SoftRoot().Length == 0) return 0;
            foreach (string r in new string[] { SoftRoot(), SoftRoot() + "\\Wow6432Node" })
            {
                string ifeo = r + "\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
                foreach (string sk in Reg.Subkeys(ifeo))
                {
                    List<string> keys = new List<string>();
                    keys.Add(sk);
                    keys.AddRange(Reg.Subkeys(sk));   // UseFilter subkeys: IFEO\<exe>\<n>\Debugger
                    foreach (string k in keys)
                        foreach (string[] v in Reg.Values(k))
                            if (v[0].Equals("Debugger", StringComparison.OrdinalIgnoreCase) && v[1].Trim().Length > 0)
                            {
                                if (Defaults.IfeoKnownDebugger(Last(sk), v[1]) && Risk(v[1]) != "SUSPECT") { kept++; continue; }
                                if (BackedDeleteValue(k, v[0], true, "IFEO Debugger " + Last(sk)) == 1) n++;
                            }
                }
            }
            return n;
        }

        // Per-user hive roots of the target: the profiles of the scan; live also every loaded HKU\<user SID> (users
        // logged on in another session; over-the-shoulder elevation makes HKCU the ADMIN's hive, also listed there).
        List<string> UserRoots()
        {
            List<string> b = new List<string>();
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string[] u in tgtUsers) if (u[1].Length > 0 && seen.Add(u[1])) b.Add(u[1]);
            if (tgtReady && tgtLive)
            {
                foreach (string sid in Reg.SubkeyNames("HKU"))   // the elevated admin's own HKCU is one of these too
                    if (UserSid(sid) && seen.Add("HKU\\" + sid)) b.Add("HKU\\" + sid);
            }
            return b;
        }

        // Lock values malware sets (research amateur-malware-remediation Q1; default = value absent). Only VALUES are
        // deleted (Policies\System also holds the UAC settings), plus the DisallowRun / RestrictRun / *Cpl list subkeys.
        internal static readonly string[] PolSystem = { "DisableTaskMgr", "DisableRegistryTools", "DisableCMD", "DisableChangePassword", "DisableLockWorkstation",
            "NoDispCPL", "NoDispBackgroundPage", "NoDispAppearancePage", "NoDispScrSavPage", "NoDispSettingsPage", "NoColorChoice", "NoVisualStyleChoice",
            "NoSizeChoice", "Wallpaper", "WallpaperStyle" };
        internal static readonly string[] PolExplorer = { "NoRun", "NoFolderOptions", "NoControlPanel", "NoDesktop", "NoViewContextMenu", "NoFind", "NoClose",
            "RestrictRun", "DisallowRun", "RestrictCpl", "DisallowCpl", "NoWinKeys", "NoLogoff", "StartMenuLogOff", "NoDrives", "NoViewOnDrive",
            "NoTrayContextMenu", "NoSetTaskbar", "NoChangeStartMenu", "NoFileMenu", "NoSecurityTab", "NoManageMyComputerVerb", "HideClock",
            "NoTrayItemsDisplay", "NoSMHelp", "NoThemesTab", "DisableCMD" };
        internal static readonly string[] PolExplorerLists = { "DisallowRun", "RestrictRun", "DisallowCpl", "RestrictCpl" };
        internal static readonly string[] PolNonEnum = { "{20D04FE0-3AEA-1069-A2D8-08002B30309D}", "{645FF040-5081-101B-9F08-00AA002F954E}", "{450D8FBA-AD25-11D0-98A8-0800361B1103}" };

        // {key, value name or null = whole key} below one hive root ("Software\..." relative paths).
        internal static List<string[]> RestrictionItems(string root, bool machine)
        {
            List<string[]> r = new List<string[]>();
            string p = root + (machine ? "\\" : "\\Software\\") + "Microsoft\\Windows\\CurrentVersion\\Policies";
            foreach (string v in PolSystem) r.Add(new string[] { p + "\\System", v });
            foreach (string v in PolExplorer) r.Add(new string[] { p + "\\Explorer", v });
            foreach (string k in PolExplorerLists) r.Add(new string[] { p + "\\Explorer\\" + k, null });
            foreach (string v in PolNonEnum) r.Add(new string[] { p + "\\NonEnum", v });
            r.Add(new string[] { p + "\\ActiveDesktop", "NoChangingWallPaper" });
            r.Add(new string[] { root + (machine ? "\\" : "\\Software\\") + "Policies\\Microsoft\\Windows\\System", "DisableCMD" });   // the real DisableCMD location
            return r;
        }

        int RestoreRestrictions()
        {
            int n = 0;
            if (SoftRoot().Length == 0) return 0;
            List<string[]> items = RestrictionItems(SoftRoot(), true);
            foreach (string u in UserRoots()) items.AddRange(RestrictionItems(u, false));
            foreach (string[] it in items)
            {
                int r = it[1] == null ? BackedDeleteKey(it[0], true, "Снять блокировки") : BackedDeleteValue(it[0], it[1], true, "Снять блокировки: " + it[1]);
                if (r == 1) n++;
            }
            return n;
        }

        int RestoreAssoc()
        {
            int n = 0; string root = SoftRoot() + "\\Classes";
            if (SoftRoot().Length == 0) return 0;
            string cmd = "\"%1\" %*";
            string[][] map = { new string[]{".exe","exefile"}, new string[]{".com","comfile"}, new string[]{".bat","batfile"}, new string[]{".cmd","cmdfile"} };
            foreach (string[] m in map)
            {
                if (BackedSet(root + "\\" + m[0], "", m[1], RegistryValueKind.String, true, "Ассоциации " + m[0]) == 1) n++;
                if (BackedSet(root + "\\" + m[1] + "\\shell\\open\\command", "", cmd, RegistryValueKind.String, true, "Ассоциации " + m[1]) == 1) n++;
            }
            if (BackedSet(root + "\\.lnk", "", "lnkfile", RegistryValueKind.String, true, "Ассоциации .lnk") == 1) n++;
            // иконки: чистим кэш (офлайн — файлы юзеров; живьём — тоже файлы)
            try
            {
                string users = curDrive.Length == 2 ? curDrive + "\\Users" : "C:\\Users";
                if (Directory.Exists(users))
                    foreach (string ud in Directory.GetDirectories(users))
                    {
                        string ic = ud + "\\AppData\\Local\\IconCache.db";
                        try { if (File.Exists(ic)) { File.SetAttributes(ic, FileAttributes.Normal); File.Delete(ic); n++; } } catch { }
                        string exDir = ud + "\\AppData\\Local\\Microsoft\\Windows\\Explorer";
                        if (Directory.Exists(exDir))
                            foreach (string cf in Directory.GetFiles(exDir, "iconcache*"))
                                try { File.SetAttributes(cf, FileAttributes.Normal); File.Delete(cf); n++; } catch { }
                    }
            }
            catch { }
            return n;
        }

        // Easy: every SUSPECT finding with a backup (Kind 4 values are reset, not deleted). already = nothing left to do
        // (e.g. the IFEO / Winlogon step before already fixed it): never deleted afterwards.
        void QuarantineSuspectAll(out int ok, out int fail, out int already)
        {
            ok = 0; fail = 0; already = 0;
            foreach (Finding x in new List<Finding>(lastFindings))
            {
                if (x.Risk != "SUSPECT" || x.Kind == 3) continue;
                int r = Remediate(x, true);
                if (r == 1) ok++; else if (r == 2) already++; else fail++;
            }
        }

        // ================= EASY BUTTON =================
        void DoEasy()
        {
            if (MessageBox.Show("Запустить авто-очистку по выбранным тумблерам?\r\nПодозрительное уйдёт в Карантин, каждое изменение реестра сохраняется туда же (можно вернуть). Дефолты будут восстановлены.",
                "Изи-очистка", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
            if (!HiberGuard("Изи-очистка", null)) return;
            Cursor.Current = Cursors.WaitCursor;
            StringBuilder r = new StringBuilder();
            quarErr = "";
            if (oScan.Checked) { Scan(); r.AppendLine("Скан: записей " + lastFindings.Count); }
            bool soft = EnsureTarget() && SoftRoot().Length > 0;   // repairs act only on the scanned target, never on a fallback
            if (!soft && (oWinlogon.Checked || oIFEO.Checked || oRestrict.Checked || oAssoc.Checked))
                r.AppendLine("ВНИМАНИЕ: куст SOFTWARE цели (" + TargetName() + ") не смонтирован — Winlogon/IFEO/ограничения/ассоциации НЕ тронуты.");
            if (soft && oWinlogon.Checked) { int wf; int w = RestoreWinlogonDefaults(out wf); r.AppendLine("Winlogon Shell/Userinit, AppInit, cmd AutoRun -> дефолт: изменено " + w + (wf > 0 ? ", ошибок " + wf : "")); }
            if (soft && oIFEO.Checked) { int kept; int i = ClearIFEODirect(out kept); r.AppendLine("Снято IFEO-блокировок: " + i + (kept > 0 ? "   (оставлено известных отладчиков — Process Explorer / Notepad++ и т.п.: " + kept + ")" : "")); }
            if (soft && oRestrict.Checked) { int i = RestoreRestrictions(); r.AppendLine("Снято ограничений политик: " + i); }
            if (soft && oAssoc.Checked) { int i = RestoreAssoc(); r.AppendLine("Ассоциации/иконки восстановлены (" + i + ")"); }
            if (oDefuse.Checked) { int d = 0; foreach (Finding x in lastFindings) if (x.Risk == "SUSPECT" && DefuseOne(x) == 1) d++; r.AppendLine("Обезврежено якорей: " + d); }
            if (oQuar.Checked)
            {
                int ok, fail, already; QuarantineSuspectAll(out ok, out fail, out already);
                r.AppendLine("В карантин / к дефолту: " + ok + "  (уже исправлено раньше: " + already + ", ошибок " + fail + ")");
            }
            if (quarDir.Length > 0) r.AppendLine("Бэкапы всех изменений: " + quarDir);
            if (quarErr.Length > 0) r.AppendLine("Первая ошибка: " + quarErr);
            if (oWatch.Checked) { chkWatch.Checked = true; r.AppendLine("Watchdog включён"); }
            if (oScan.Checked) { Scan(); } // пересканировать, чтобы список отражал результат
            QuarAutoFind();
            Cursor.Current = Cursors.Default;
            MessageBox.Show("Готово:\r\n\r\n" + r.ToString(), "Изи-очистка");
        }

        // ================= ACCOUNTS (live only: WMI list, NetUserSetInfo / net user) =================
        Button[] accBtns = new Button[0];

        // The Accounts tab changes the SAM of the RUNNING system. In WinPE that is WinPE's own SAM (not the installation
        // being repaired), and with an offline target selected it is not the target: refused there, with the reason.
        bool AccAllowed(out string why)
        {
            why = "";
            if (IsRescueSystem(Reg.KeyExists("HKLM\\SYSTEM\\CurrentControlSet\\Control\\MiniNT"), RunningWinDir()))
                why = "Это WinPE/WinRE: здесь видны аккаунты самой WinPE, а не выбранной Windows — вкладка отключена. Офлайн-сброс пароля — chntpw / MS DaRT.";
            else
            {
                WinTarget t = cboWin == null ? null : cboWin.SelectedItem as WinTarget;
                bool offline = tgtReady ? !tgtLive : (t != null && !t.Live);
                if (offline) why = "Выбрана офлайн-установка " + (tgtReady ? tgtWinDir : t.WinDir) + ": аккаунты меняются только у ЖИВОЙ ОС, где запущена программа — вкладка отключена. Офлайн-сброс — chntpw / MS DaRT.";
            }
            return why.Length == 0;
        }

        void UpdateAccState()
        {
            if (lvAcc == null) return;
            string why;
            bool ok = AccAllowed(out why);
            foreach (Button b in accBtns) b.Enabled = ok;
            if (!ok) { lvAcc.Items.Clear(); lblAcc.Text = why; }
        }

        void AccRefresh()
        {
            lvAcc.Items.Clear();
            string why;
            if (!AccAllowed(out why)) { UpdateAccState(); return; }
            foreach (Button b in accBtns) b.Enabled = true;
            List<string[]> rows;
            try { rows = WmiLocalUsers(); }   // a missing System.Management.dll fails HERE (when WmiLocalUsers is JIT-compiled)
            catch (Exception ex)
            {
                bool noAsm = ex is FileNotFoundException || ex is FileLoadException || ex is TypeLoadException || ex is BadImageFormatException;
                lblAcc.Text = noAsm ? "WMI недоступен: в этой системе нет System.Management (.NET без WMI; в WinPE нужен WinPE-WMI)."
                                    : "WMI недоступен (служба выключена?): " + ex.Message;
                return;
            }
            foreach (string[] r in rows)
            {
                ListViewItem it = new ListViewItem(r);
                if (r[1] == "да" || r[2] == "да") it.BackColor = Color.FromArgb(255, 245, 205);
                lvAcc.Items.Add(it);
            }
            lblAcc.Text = "Локальных аккаунтов: " + lvAcc.Items.Count + " (живая ОС " + RunningWinDir() + ").";
        }

        // The ONLY method that touches System.Management types. NoInlining keeps them out of the callers' JIT: if the
        // assembly cannot be loaded (trimmed .NET / WinPE without WinPE-WMI) the exception surfaces at the call site in
        // AccRefresh's try instead of before it (where it became an unhandled-exception dialog at every start).
        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
        static List<string[]> WmiLocalUsers()
        {
            List<string[]> rows = new List<string[]>();
            using (System.Management.ManagementObjectSearcher s = new System.Management.ManagementObjectSearcher(
                "SELECT Name,Disabled,Lockout,PasswordRequired,SID FROM Win32_UserAccount WHERE LocalAccount=True"))
                foreach (System.Management.ManagementObject u in s.Get())
                {
                    string name = "" + u["Name"];
                    string dis = (u["Disabled"] != null && (bool)u["Disabled"]) ? "да" : "нет";
                    string lo = (u["Lockout"] != null && (bool)u["Lockout"]) ? "да" : "нет";
                    string pw = (u["PasswordRequired"] != null && (bool)u["PasswordRequired"]) ? "да" : "нет";
                    rows.Add(new string[] { name, dis, lo, pw, "" + u["SID"] });
                }
            return rows;
        }

        string AccName()
        {
            string why;
            if (!AccAllowed(out why)) { MessageBox.Show(why, "Аккаунты"); return null; }
            if (lvAcc.SelectedItems.Count == 0) { MessageBox.Show("Выбери пользователя."); return null; }
            return lvAcc.SelectedItems[0].SubItems[0].Text;
        }

        // Masked password, typed twice. null = cancelled.
        static string PromptPassword(string title)
        {
            Form f = new Form(); f.Text = title; f.Width = 540; f.Height = 190;
            f.StartPosition = FormStartPosition.CenterScreen; f.FormBorderStyle = FormBorderStyle.FixedDialog;
            f.MinimizeBox = false; f.MaximizeBox = false; f.TopMost = true;
            Label l1 = new Label(); l1.Text = "Пароль:"; l1.Left = 12; l1.Top = 18; l1.Width = 90;
            TextBox t1 = new TextBox(); t1.Left = 110; t1.Top = 15; t1.Width = 400; t1.UseSystemPasswordChar = true;
            Label l2 = new Label(); l2.Text = "Ещё раз:"; l2.Left = 12; l2.Top = 52; l2.Width = 90;
            TextBox t2 = new TextBox(); t2.Left = 110; t2.Top = 49; t2.Width = 400; t2.UseSystemPasswordChar = true;
            Button ok = new Button(); ok.Text = "OK"; ok.Left = 336; ok.Top = 100; ok.Width = 80; ok.DialogResult = DialogResult.OK;
            Button cc = new Button(); cc.Text = "Отмена"; cc.Left = 432; cc.Top = 100; cc.Width = 80; cc.DialogResult = DialogResult.Cancel;
            f.Controls.Add(l1); f.Controls.Add(t1); f.Controls.Add(l2); f.Controls.Add(t2); f.Controls.Add(ok); f.Controls.Add(cc);
            f.AcceptButton = ok; f.CancelButton = cc;
            while (f.ShowDialog() == DialogResult.OK)
            {
                if (t1.Text == t2.Text) return t1.Text;
                MessageBox.Show("Пароли не совпадают.", title);
                t1.Text = ""; t2.Text = "";
            }
            return null;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct USER_INFO_1003 { public string usri1003_password; }

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        static extern int NetUserSetInfo(string server, string user, int level, ref USER_INFO_1003 buf, out int parmErr);

        static string NetErr(int rc)
        {
            switch (rc)
            {
                case 5: return "нет прав (запусти от администратора)";
                case 2221: return "пользователь не найден";
                case 2245: return "пароль не подходит под политику (длина / сложность / история)";
            }
            return "код " + rc + ": " + new System.ComponentModel.Win32Exception(rc).Message;
        }

        void AccSetPass()
        {
            string n = AccName(); if (n == null) return;
            if (MessageBox.Show("Сменить пароль «" + n + "» без старого пароля?\r\n\r\nВНИМАНИЕ: при таком сбросе пропадает доступ к EFS-зашифрованным файлам этого пользователя " +
                "и к сохранённым паролям (DPAPI: браузеры, Wi-Fi, учётные данные, сертификаты). Для учётной записи Microsoft пароль меняется на account.microsoft.com, не здесь.",
                "Пароль", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            string p = PromptPassword("Новый пароль для «" + n + "» (пусто = без пароля)");
            if (p == null) return;
            int rc;
            try
            {
                USER_INFO_1003 ui; ui.usri1003_password = p;
                int pe;
                rc = NetUserSetInfo(null, n, 1003, ref ui, out pe);   // no command line: nothing for net.exe to misread, nothing in the process list
            }
            catch (Exception ex) { MessageBox.Show("Ошибка: " + ex.Message, "Пароль"); return; }
            MessageBox.Show(rc == 0 ? "Пароль изменён для " + n : "Ошибка: " + NetErr(rc), "Пароль");
            AccRefresh();
        }

        void AccEnable()
        {
            string n = AccName(); if (n == null) return;
            string o; int rc = RunProc("net", "user " + Reg.QuoteArg(n) + " /active:yes", out o);
            MessageBox.Show(rc == 0 ? "Аккаунт включён/разблокирован: " + n : "Ошибка:\r\n" + o, "Включение");
            AccRefresh();
        }

        void AccDelUser()
        {
            string n = AccName(); if (n == null) return;
            if (MessageBox.Show("Удалить пользователя «" + n + "»? (профиль на диске останется, но его EFS-файлы и сохранённые пароли (DPAPI) станут недоступны)", "Удаление",
                MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            string o; int rc = RunProc("net", "user " + Reg.QuoteArg(n) + " /delete", out o);
            MessageBox.Show(rc == 0 ? "Пользователь удалён: " + n : "Ошибка:\r\n" + o, "Удаление");
            AccRefresh();
        }

        // ProfileImagePath / ProfilesDirectory with only %SystemDrive%, %SystemRoot%, %windir% expanded (to the running
        // system, never the technician's %USERPROFILE% & co.); "" if anything else is in it or it is not X:\...
        internal static string ExpandProfileVar(string raw, string winDir)
        {
            if (string.IsNullOrEmpty(raw) || string.IsNullOrEmpty(winDir) || winDir.Length < 3) return "";
            string p = ReplaceCI(ReplaceCI(ReplaceCI(raw.Trim(), "%SystemDrive%", winDir.Substring(0, 2)), "%SystemRoot%", winDir), "%windir%", winDir).TrimEnd('\\');
            return QuarMan.AbsLocalPath(p) && p.IndexOf('%') < 0 ? p : "";
        }

        // The folder «Удалить профиль» may delete, or "" + why: strictly ONE level below ProfilesDirectory (itself not a
        // root / system folder), not Public/Default, not this process's profile, not the folder of another ProfileList
        // entry, not a protected folder, no "..". pip / profilesDir raw (not expanded) from ProfileList.
        internal static string ProfileDeletePath(string pip, string profilesDir, string winDir, string me, List<string> others, out string why)
        {
            why = "";
            if ((pip ?? "").IndexOf("..") >= 0) { why = "в пути есть «..»"; return ""; }
            string p = ExpandProfileVar(pip, winDir);
            string pd = ExpandProfileVar(string.IsNullOrEmpty(profilesDir) ? "%SystemDrive%\\Users" : profilesDir, winDir);
            if (p.Length == 0) { why = "путь не абсолютный или с неизвестными %переменными%: " + pip; return ""; }
            if (pd.Length <= 3 || QuarMan.Below(pd, winDir) || (ProtectedPath(pd, winDir).Length > 0 && !pd.Substring(2).Equals("\\Users", StringComparison.OrdinalIgnoreCase)))
            { why = "ProfilesDirectory подозрителен: " + profilesDir; return ""; }
            int cut = p.LastIndexOf('\\');
            string parent = p.Substring(0, cut), name = p.Substring(cut + 1);
            if (!parent.Equals(pd, StringComparison.OrdinalIgnoreCase)) { why = "папка не лежит прямо в " + pd + ": " + p; return ""; }
            foreach (string bad in new string[] { "Public", "Default", "Default User", "All Users", "defaultuser0" })
                if (name.Equals(bad, StringComparison.OrdinalIgnoreCase)) { why = "системный профиль " + name; return ""; }
            string prot = QuarMan.Below(p, winDir) ? "папка Windows" : ProtectedPath(p, winDir);
            if (prot.Length > 0) { why = prot; return ""; }
            if (!string.IsNullOrEmpty(me) && p.Equals(me.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) { why = "это профиль, от имени которого запущена программа"; return ""; }
            foreach (string o in others ?? new List<string>())
                if (o.Length > 0 && p.Equals(o.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) { why = "эта папка указана и у другого пользователя в ProfileList"; return ""; }
            return p;
        }

        static bool SidLike(string s)
        {
            if (string.IsNullOrEmpty(s) || !s.StartsWith("S-1-") || s.Length > 200) return false;
            foreach (char c in s) if (!(c == '-' || c == 'S' || (c >= '0' && c <= '9'))) return false;
            return true;
        }

        void AccDelProfile()
        {
            string n = AccName(); if (n == null) return;
            string sid = lvAcc.SelectedItems[0].SubItems[4].Text;
            if (!SidLike(sid)) { MessageBox.Show("Странный SID: " + sid, "Профиль"); return; }
            if (Reg.KeyExists("HKU\\" + sid)) { MessageBox.Show("Пользователь «" + n + "» сейчас вошёл в систему (его куст загружен в HKEY_USERS).\r\nСначала выйди из этой учётной записи или перезагрузи ПК, потом удаляй профиль.", "Профиль", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
            string win = RunningWinDir();
            string pl = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList", pk = pl + "\\" + sid;
            string raw = "", pdir = "";
            foreach (string[] v in Reg.Values(pk)) if (v[0].Equals("ProfileImagePath", StringComparison.OrdinalIgnoreCase)) raw = v[1];
            foreach (string[] v in Reg.Values(pl)) if (v[0].Equals("ProfilesDirectory", StringComparison.OrdinalIgnoreCase)) pdir = v[1];
            List<string> others = new List<string>();
            foreach (string sk in Reg.Subkeys(pl))
                if (!Last(sk).Equals(sid, StringComparison.OrdinalIgnoreCase))
                    foreach (string[] v in Reg.Values(sk)) if (v[0].Equals("ProfileImagePath", StringComparison.OrdinalIgnoreCase)) others.Add(ExpandProfileVar(v[1], win));
            string me = "";
            try { me = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile); } catch { }
            string why = "", path = raw.Length > 0 ? ProfileDeletePath(raw, pdir, win, me, others, out why) : "";
            if (raw.Length > 0 && path.Length == 0) { MessageBox.Show("Папку профиля «" + n + "» удалять нельзя: " + why + "\r\nProfileImagePath = " + raw, "Профиль", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
            if (path.Length > 0 && (FsOps.Attrs(path) & 0x400) != 0 && FsOps.Attrs(path) != -1) { MessageBox.Show("Папка профиля — ссылка (junction / symlink): " + path + "\r\nУдали её вручную.", "Профиль"); return; }
            if (MessageBox.Show("Удалить ПРОФИЛЬ пользователя «" + n + "»?\r\nProfileImagePath: " + (raw.Length > 0 ? raw : "(нет)") + "\r\nПапка: " + (path.Length > 0 ? path : "(не найдена)") +
                "\r\n+ запись ProfileList (её бэкап — в карантин). Папка удаляется НЕОБРАТИМО.", "Удаление профиля", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            string typed = Prompt("Для подтверждения введи имя пользователя: " + n, "");
            if (typed == null || typed != n) { MessageBox.Show("Имя не совпало — ничего не удалено.", "Профиль"); return; }
            quarErr = "";
            if (!(EnsureTarget() && tgtLive)) { MessageBox.Show("Удаление профиля работает только когда целью выбрана ЖИВАЯ ОС (нужен бэкап записи ProfileList в карантин). Ничего не удалено.", "Профиль"); return; }
            // ProfileList first (backed up to quarantine; abort if that fails), the irreversible folder delete only afterwards
            int r = BackedDeleteKey(pk, true, "профиль " + n);
            if (r == 0) { MessageBox.Show("ProfileList не очищен: " + quarErr + "\r\nПапка профиля НЕ удалялась.", "Профиль"); AccRefresh(); return; }
            string msg = r == 1 ? "ProfileList очищен (бэкап в карантине). " : "Записи ProfileList нет. ";
            if (path.Length > 0 && FsOps.Exists(path))
            {
                int failed = 0; string err = "";
                FsOps.DeleteTree(path, ref failed, ref err);
                msg += failed == 0 ? "Папка удалена." : "Папка удалена не полностью (ошибок " + failed + ": " + err + ").";
            }
            MessageBox.Show(msg, "Профиль");
            AccRefresh();
        }

        void DeleteChecked(ListView target)
        {
            int n = 0; foreach (ListViewItem it in target.Items) if (it.Checked) n++;
            if (n == 0) { MessageBox.Show("Ничего не отмечено."); return; }
            if (!HiberGuard("Удалить", null)) return;
            if (MessageBox.Show("Удалить отмеченных записей: " + n + " ?\nОперация необратима (без бэкапа; для бэкапа — «Карантин»).\n" +
                "Winlogon Shell/Userinit, BootExecute и т.п. не удаляются, а возвращаются к дефолту.", "Подтверждение",
                MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
            List<ListViewItem> done = new List<ListViewItem>();
            int ok = 0, fail = 0, skip = 0, already = 0;
            quarErr = "";
            foreach (ListViewItem it in target.Items)
            {
                if (!it.Checked) continue;
                Finding x = (Finding)it.Tag;
                if (x.Kind == 3) { skip++; continue; }   // info-only (BCD/LSA/class hijack/ESP): чинить вручную, не удалять
                int r = Remediate(x, x.Kind == 4);      // a reset keeps the original in the quarantine anyway
                if (r == 1) { ok++; done.Add(it); } else if (r == 2) { already++; done.Add(it); } else fail++;
            }
            foreach (ListViewItem it in done) target.Items.Remove(it);
            lblStatus.Text = "Удалено / к дефолту: " + ok + "   уже нет: " + already + "   ошибок: " + fail + "   пропущено (info): " + skip
                + (fail > 0 && quarErr.Length > 0 ? "   причина: " + quarErr : "");
        }

        void Export()
        {
            SaveFileDialog sd = new SaveFileDialog();
            sd.Filter = "CSV|*.csv|Text|*.txt";
            sd.FileName = "RescueScan_report.csv";
            sd.RestoreDirectory = true;   // keep the current directory: never the (possibly infected) folder of the report
            if (sd.ShowDialog() != DialogResult.OK) return;
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Category;Name;Value;Location;Risk");
            foreach (ListViewItem it in lv.Items)
            {
                Finding x = (Finding)it.Tag;
                sb.AppendLine(CsvCell(x.Category) + ";" + CsvCell(x.Name) + ";" + CsvCell(x.Value) + ";" + CsvCell(x.Location) + ";" + CsvCell(x.Risk));
            }
            try { File.WriteAllText(sd.FileName, sb.ToString(), Encoding.UTF8); lblStatus.Text = "Сохранено: " + sd.FileName; }
            catch (Exception ex) { MessageBox.Show(ex.Message); }
        }

        // One CSV cell (RFC 4180): always quoted, quotes doubled (the evidence is kept as is). Names and commands come from
        // the malware: a cell starting with = + - @ TAB CR would be a live formula in Excel/LibreOffice (DDE, HYPERLINK
        // exfiltration), so it gets a leading apostrophe - the usual CSV-injection neutralisation (OWASP).
        internal static string CsvCell(string s)
        {
            if (s == null) s = "";
            if (s.Length > 0 && "=+-@\t\r".IndexOf(s[0]) >= 0) s = "'" + s;
            return "\"" + s.Replace("\"", "\"\"") + "\"";
        }
    }

    // ================= WATCHDOG (user-mode self-heal) =================
    // GUI and watchdog guard each other. Every arming uses a fresh random stop-event name (passed on the command line,
    // created with an Administrators/SYSTEM-only DACL; a pre-existing object of that name is refused). A GUI relaunched by
    // the watchdog gets "--relaunched <watchdog pid> <event> <guard>" and ADOPTS the watchdog, so a normal close stops it
    // instead of being "relaunched forever". Limit: a user-mode pair dies to `taskkill /f /im RescueScan.exe` (both
    // processes share the image name) - that is documented, not solved.
    static class Watchdog
    {
        public static string LogPath = Path.Combine(Path.GetTempPath(), "rescuescan.log");
        const string EvtPrefix = "RescueScanStop_";
        static readonly object logLock = new object();

        // Serialised in-process (lock) and shared across processes (FileShare.ReadWrite + short retries): the GUI, its
        // monitor/guard threads and the watchdog process all append to the same file.
        public static void Log(string msg)
        {
            byte[] line = Encoding.UTF8.GetBytes(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + msg + "\r\n");
            lock (logLock)
            {
                for (int i = 0; i < 5; i++)
                {
                    try
                    {
                        using (FileStream fs = new FileStream(LogPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
                            fs.Write(line, 0, line.Length);
                        return;
                    }
                    catch (IOException) { Thread.Sleep(20); }
                    catch { return; }
                }
            }
        }

        internal static string NewEventName() { return EvtPrefix + Guid.NewGuid().ToString("N"); }

        internal static bool ValidEventName(string n)
        {
            return n != null && Regex.IsMatch(n, "^" + EvtPrefix + "[0-9a-f]{32}(_guard)?$");
        }

        // The stop event (and its "_guard" companion: set while «Стеречь Winlogon» is on, so a relaunched GUI restores the
        // guard). null when the name is already taken (squatted) or cannot be created.
        internal static EventWaitHandle CreateEvent(string name)
        {
            if (!ValidEventName(name)) return null;
            EventWaitHandle h = null; bool created = false;
            try
            {
                System.Security.AccessControl.EventWaitHandleSecurity sec = new System.Security.AccessControl.EventWaitHandleSecurity();
                foreach (System.Security.Principal.WellKnownSidType t in new System.Security.Principal.WellKnownSidType[] {
                    System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, System.Security.Principal.WellKnownSidType.LocalSystemSid })
                    sec.AddAccessRule(new System.Security.AccessControl.EventWaitHandleAccessRule(
                        new System.Security.Principal.SecurityIdentifier(t, null),
                        System.Security.AccessControl.EventWaitHandleRights.FullControl, System.Security.AccessControl.AccessControlType.Allow));
                h = new EventWaitHandle(false, EventResetMode.ManualReset, name, out created, sec);
            }
            catch { h = null; }
            if (h == null)
                try { h = new EventWaitHandle(false, EventResetMode.ManualReset, name, out created); } catch { h = null; }
            if (h != null && !created) { try { h.Close(); } catch { } return null; }
            return h;
        }

        internal static EventWaitHandle OpenEvent(string name)
        {
            if (!ValidEventName(name)) return null;
            try { return EventWaitHandle.OpenExisting(name); } catch { return null; }
        }

        // --watchdog <gui pid> <event> <exe>
        internal static string WatchdogArgs(int guiPid, string evt, string exe)
        {
            return "--watchdog " + guiPid + " " + evt + " " + Reg.QuoteArg(exe);
        }

        // --relaunched <watchdog pid> <event> <guard 0|1>
        internal static string RelaunchArgs(int watchdogPid, string evt, bool guard)
        {
            return "--relaunched " + watchdogPid + " " + evt + " " + (guard ? "1" : "0");
        }

        // args as Main receives them; null = not this form / invalid (an invalid command line never arms anything)
        internal static bool ParseWatchdog(string[] a, out int guiPid, out string evt, out string exe)
        {
            guiPid = 0; evt = null; exe = null;
            if (a == null || a.Length != 4 || a[0] != "--watchdog") return false;
            if (!int.TryParse(a[1], out guiPid) || guiPid <= 4 || !ValidEventName(a[2]) || a[2].EndsWith("_guard")) return false;
            if (!Regex.IsMatch(a[3], @"^([A-Za-z]:\\|\\\\)[^""]+$")) return false;   // absolute Windows path only
            evt = a[2]; exe = a[3];
            return true;
        }

        internal static bool ParseRelaunched(string[] a, out int watchdogPid, out string evt, out bool guard)
        {
            watchdogPid = 0; evt = null; guard = false;
            if (a == null || a.Length != 4 || a[0] != "--relaunched") return false;
            if (!int.TryParse(a[1], out watchdogPid) || watchdogPid <= 4 || !ValidEventName(a[2]) || a[2].EndsWith("_guard")) return false;
            if (a[3] != "0" && a[3] != "1") return false;
            evt = a[2]; guard = a[3] == "1";
            return true;
        }

        // Back-off after the n-th failed relaunch in a row: 0.5 s, 1 s, 2 s ... capped at 30 s.
        internal static int BackoffMs(int failures)
        {
            if (failures <= 0) return 0;
            return failures >= 7 ? 30000 : Math.Min(30000, 500 << (failures - 1));
        }

        // Too many relaunches in a short time = something kills the GUI as soon as it starts (or it crashes at start):
        // stop instead of spinning forever. launches = start times of the earlier relaunches.
        internal static bool TooManyRelaunches(List<DateTime> launches, DateTime now)
        {
            int n = 0;
            foreach (DateTime t in launches) if ((now - t).TotalSeconds < 120) n++;
            return n >= 6;
        }

        // True when the process ended; false when `stop` was signalled first. Waits on both (polling the process).
        static bool WaitExitOrStop(Process p, WaitHandle stop)
        {
            while (true)
            {
                try { if (p == null || p.WaitForExit(300)) return true; } catch { return true; }
                if (stop.WaitOne(0)) return false;
            }
        }

        // Runs headless: watches the GUI, relaunches it (directly, never through ShellExecute/associations) if it dies
        // without the stop signal.
        public static void Run(string[] args)
        {
            int pid; string evt, exe;
            if (!ParseWatchdog(args, out pid, out evt, out exe)) { Log("watchdog: неверные аргументы — не запускаюсь"); return; }
            EventWaitHandle stop = OpenEvent(evt);
            if (stop == null) { Log("watchdog: нет стоп-события " + evt + " — не запускаюсь"); return; }
            Process gui = null;
            try { gui = Process.GetProcessById(pid); } catch { }
            Log("watchdog: старт, слежу за pid " + pid);
            List<DateTime> launches = new List<DateTime>();
            int fails = 0;
            while (true)
            {
                if (!WaitExitOrStop(gui, stop) || stop.WaitOne(250)) { Log("watchdog: получен стоп-сигнал, выходим."); return; }
                Log("watchdog: ГЛАВНЫЙ процесс (pid " + pid + ") исчез без стоп-сигнала -> ВИРУС мог его убить. Перезапуск.");
                if (TooManyRelaunches(launches, DateTime.Now)) { Log("watchdog: слишком много перезапусков подряд — останавливаюсь."); return; }
                bool guard = false;
                EventWaitHandle g = OpenEvent(evt + "_guard");
                if (g != null) { try { guard = g.WaitOne(0); } catch { } g.Close(); }
                try
                {
                    ProcessStartInfo psi = new ProcessStartInfo(exe, RelaunchArgs(Process.GetCurrentProcess().Id, evt, guard));
                    psi.UseShellExecute = false;
                    try { psi.WorkingDirectory = Path.GetDirectoryName(exe); } catch { }
                    gui = Process.Start(psi);
                    pid = gui.Id; fails = 0; launches.Add(DateTime.Now);
                    Log("watchdog: перезапущено, новый pid " + pid + (guard ? " (страж Winlogon будет восстановлен)" : ""));
                }
                catch (Exception ex)
                {
                    gui = null; fails++;
                    Log("watchdog: не смог перезапустить (" + fails + "): " + ex.Message);
                    if (fails >= 8) { Log("watchdog: сдаюсь после " + fails + " неудач."); return; }
                    if (stop.WaitOne(BackoffMs(fails))) { Log("watchdog: получен стоп-сигнал, выходим."); return; }
                }
            }
        }
    }

    // ================= Native (Toolhelp for the process tree) =================
    // Unicode PROCESSENTRY32W with the W exports. The old struct had no CharSet (= ANSI, 304/296 bytes) while CharSet.Auto
    // bound Process32FirstW, which then failed with ERROR_BAD_LENGTH: «Завершить дерево» silently killed one process.
    static class Native
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct PROCESSENTRY32W
        {
            public uint dwSize; public uint cntUsage; public uint th32ProcessID;
            public IntPtr th32DefaultHeapID; public uint th32ModuleID; public uint cntThreads;
            public uint th32ParentProcessID; public int pcPriClassBase; public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
        }
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        static extern bool Process32FirstW(IntPtr snap, ref PROCESSENTRY32W pe);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        static extern bool Process32NextW(IntPtr snap, ref PROCESSENTRY32W pe);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr h);

        // 568 bytes on x64, 556 on x86 (sizeof(PROCESSENTRY32W)); Process32FirstW refuses anything smaller.
        internal static int EntrySize { get { return Marshal.SizeOf(typeof(PROCESSENTRY32W)); } }

        // One Toolhelp snapshot: pid -> parent pid, pid -> image name. error = Win32 error (or -1 when the API is
        // missing) - the caller must SHOW it and never report a tree as killed when the walk failed.
        public static bool Snapshot(Dictionary<int, int> parentOf, Dictionary<int, string> names, out int error)
        {
            error = 0;
            IntPtr snap;
            try { snap = CreateToolhelp32Snapshot(0x2 /*TH32CS_SNAPPROCESS*/, 0); }
            catch (Exception) { error = -1; return false; }   // DllNotFound / EntryPointNotFound (not Windows)
            if (snap == (IntPtr)(-1)) { error = Marshal.GetLastWin32Error(); return false; }
            try
            {
                PROCESSENTRY32W pe = new PROCESSENTRY32W();
                pe.dwSize = (uint)EntrySize;
                if (!Process32FirstW(snap, ref pe)) { error = Marshal.GetLastWin32Error(); return false; }
                do
                {
                    int c = (int)pe.th32ProcessID;
                    parentOf[c] = (int)pe.th32ParentProcessID;
                    names[c] = pe.szExeFile ?? "";
                    pe.dwSize = (uint)EntrySize;
                } while (Process32NextW(snap, ref pe));
                return true;
            }
            finally { CloseHandle(snap); }
        }
    }

    // Pure process-tree logic (unit-tested): which PIDs belong to a tree, which processes are critical.
    static class ProcTree
    {
        // Killing one of these = CRITICAL_PROCESS_DIED bugcheck (or, in WinPE, winpeshl = reboot of the rescue system).
        internal static readonly string[] CriticalNames = { "system", "smss", "csrss", "wininit", "winlogon", "services", "lsass", "winpeshl" };

        // name: image name with or without .exe; path: full image path ("" / "(нет доступа)" = unknown);
        // sysDir: the RUNNING system's System32. A look-alike csrss.exe outside System32 is NOT critical (it is malware);
        // an unknown path counts as critical (the real ones are exactly the processes whose path we cannot read).
        internal static bool IsCritical(string name, string path, string sysDir)
        {
            if (string.IsNullOrEmpty(name)) return false;
            string n = name.Trim().ToLowerInvariant();
            if (n.EndsWith(".exe")) n = n.Substring(0, n.Length - 4);
            if (Array.IndexOf(CriticalNames, n) < 0) return false;
            if (n == "system") return string.IsNullOrEmpty(path) || !path.Contains("\\");   // the kernel process has no image path
            if (string.IsNullOrEmpty(path) || path.IndexOf('\\') < 0) return true;
            string dir = path.Substring(0, path.LastIndexOf('\\'));   // Windows path: no Path.* (tests run on Mono/Linux too)
            if (string.IsNullOrEmpty(sysDir)) return true;
            return string.Equals(dir.TrimEnd('\\'), sysDir.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
        }

        // PIDs that are never killed and never walked into: Idle (0), System (4), RescueScan itself, its watchdog.
        internal static HashSet<int> Never(int self, int watchdog)
        {
            HashSet<int> n = new HashSet<int>(); n.Add(0); n.Add(4); n.Add(self);
            if (watchdog > 0) n.Add(watchdog);
            return n;
        }

        // Grows the tree `members` (pid -> start time recorded when the process joined) from one snapshot and returns
        // the PIDs added, parents before children. parentOf: pid -> parent pid of the snapshot; startOf: current start
        // time of a pid (null = gone / unknown). A process joins only when
        //  - its parent pid is a member and it started no earlier than that member (a parent pid is never updated and
        //    PIDs are reused: an older process "below" a member is a stale edge - e.g. winlogon under a reused smss pid),
        //  - and, if the member's pid now belongs to a NEWER process (the member died and the pid was reused), it was
        //    started before that newer process;
        //  - it is not in `never` and its start time is known (we cannot prove it is a child otherwise).
        // Iterative with a visited set: cycles (pid reuse, 0 -> 0) cannot loop or overflow the stack.
        internal static List<int> Grow(Dictionary<int, int> parentOf, Func<int, DateTime?> startOf,
            Dictionary<int, DateTime> members, ICollection<int> never)
        {
            Dictionary<int, List<int>> kids = new Dictionary<int, List<int>>();
            foreach (KeyValuePair<int, int> kv in parentOf)
            {
                int c = kv.Key, p = kv.Value;
                if (c == p || c == 0 || c == 4 || p == 0) continue;
                List<int> l; if (!kids.TryGetValue(p, out l)) { l = new List<int>(); kids[p] = l; }
                l.Add(c);
            }
            List<int> added = new List<int>();
            Queue<int> q = new Queue<int>(members.Keys);
            HashSet<int> visited = new HashSet<int>(members.Keys);
            while (q.Count > 0)
            {
                int p = q.Dequeue();
                List<int> l; if (!kids.TryGetValue(p, out l)) continue;
                DateTime pStart = members[p];
                DateTime? cur = startOf(p);
                bool reused = cur.HasValue && cur.Value != pStart;
                foreach (int c in l)
                {
                    if (visited.Contains(c) || never.Contains(c)) continue;
                    DateTime? cs = startOf(c);
                    if (!cs.HasValue || cs.Value < pStart) continue;
                    if (reused && cs.Value >= cur.Value) continue;
                    visited.Add(c); members[c] = cs.Value; added.Add(c); q.Enqueue(c);
                }
            }
            return added;
        }
    }

    static class Program
    {
        static int shown = 0;

        // Message text for an unexpected exception (pure: unit-tested).
        internal static string ErrorText(Exception ex, bool fatal, string unload)
        {
            string what = ex == null ? "неизвестная ошибка" : ex.GetType().Name + ": " + Reg.OneLine(ex.Message, 300);
            return (fatal ? "Критическая ошибка — RescueScan будет закрыт.\r\n" : "Внутренняя ошибка RescueScan (работа продолжается).\r\n") +
                what + "\r\n" +
                (fatal ? (unload.Length > 0 ? "Не все кусты выгружены: " + unload + " (reg unload вручную или перезагрузка).\r\n" : "Смонтированные кусты реестра выгружены.\r\n") : "") +
                "Подробности в логе: " + Watchdog.LogPath;
        }

        static void OnError(Exception ex, bool fatal)
        {
            try { Watchdog.Log((fatal ? "FATAL: " : "ошибка: ") + (ex == null ? "?" : ex.ToString())); } catch { }
            string unload = "";
            if (fatal && MainForm.Current != null) unload = MainForm.Current.EmergencyUnload();
            if (Interlocked.Increment(ref shown) > 3 && !fatal) return;   // a handler failing in a loop: log only
            try { MessageBox.Show(ErrorText(ex, fatal, unload), "RescueScan", MessageBoxButtons.OK, fatal ? MessageBoxIcon.Error : MessageBoxIcon.Warning); } catch { }
        }

        [STAThread]
        static void Main(string[] args)
        {
            if (args.Length >= 1 && args[0] == "--watchdog") { Watchdog.Run(args); return; }
            int wdPid; string evt; bool guard;
            if (Watchdog.ParseRelaunched(args, out wdPid, out evt, out guard))
            { MainForm.RelaunchWatchdogPid = wdPid; MainForm.RelaunchEvent = evt; MainForm.RelaunchGuard = guard; }
            // Last-chance handlers: a Russian message + log instead of the English .NET dialog; on a fatal error the
            // mounted RS_* hives are unloaded first (they would otherwise stay loaded until reboot).
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            Application.ThreadException += delegate(object s, ThreadExceptionEventArgs e) { OnError(e.Exception, false); };
            AppDomain.CurrentDomain.UnhandledException += delegate(object s, UnhandledExceptionEventArgs e) { OnError(e.ExceptionObject as Exception, true); };
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            try { Application.Run(new MainForm()); }
            catch (Exception ex) { OnError(ex, true); }
        }
    }
}
