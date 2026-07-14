// RescueScan - offline persistence scanner/remover for Windows Recovery (WinRE/WinPE)
// GUI (WinForms, .NET Framework 4.x). Orchestrates reg.exe so it works identically in WinPE.
// Build: csc /target:winexe /win32manifest:app.manifest /out:RescueScan.exe RescueScan.cs
//        (references System.Windows.Forms, System.Drawing, System.Core)
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace RescueScan
{
    class Finding
    {
        public string Category;   // where it lives (Run HKLM, IFEO, Service, Task...)
        public string Name;       // value name / task name
        public string Value;      // command / path / data
        public string Location;   // reg key or file path used for deletion display
        public string Risk;       // "", "SUSPECT", "REVIEW"
        public int Kind;          // 0=regvalue 1=regkey 2=file
        public string DelKey;     // reg key for delete
        public string DelName;    // value name (for regvalue)
        public string DelPath;    // file path (for file)
    }

    static class Reg
    {
        public static string Run(string args)
        {
            string outp;
            RunCode(args, out outp);
            return outp;
        }

        public static int RunCode(string args, out string outp)
        {
            ProcessStartInfo psi = new ProcessStartInfo("reg.exe", args);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            try
            {
                Process p = Process.Start(psi);
                string so = p.StandardOutput.ReadToEnd();
                p.StandardError.ReadToEnd();
                p.WaitForExit();
                outp = so;
                return p.ExitCode;
            }
            catch (Exception ex)
            {
                outp = ex.Message;
                return -1;
            }
        }

        // Returns list of {name,type,data} for a key's values.
        public static List<string[]> Values(string key)
        {
            List<string[]> res = new List<string[]>();
            string outp = Run("query \"" + key + "\"");
            string[] lines = outp.Replace("\r", "").Split('\n');
            foreach (string line in lines)
            {
                if (line.Length < 6) continue;
                if (!line.StartsWith("    ")) continue;      // values are indented
                string t = line.Substring(4);
                int rt = t.IndexOf("REG_");
                if (rt < 1) continue;
                string name = t.Substring(0, rt).Trim();
                string rest = t.Substring(rt);
                string data = "";
                int sp = rest.IndexOf("    ");
                if (sp >= 0) data = rest.Substring(sp).Trim();
                res.Add(new string[] { name, data });
            }
            return res;
        }

        // Full paths of immediate subkeys.
        public static List<string> Subkeys(string key)
        {
            List<string> res = new List<string>();
            string outp = Run("query \"" + key + "\"");
            string[] lines = outp.Replace("\r", "").Split('\n');
            foreach (string line in lines)
            {
                string l = line.Trim();
                if (l.StartsWith("HKEY_")) res.Add(l);
            }
            return res;
        }

        // Recursive /v: returns {subkeyFullPath, data} pairs for a single value name.
        public static List<string[]> Pairs(string key, string valName)
        {
            List<string[]> res = new List<string[]>();
            string outp = Run("query \"" + key + "\" /s /v " + valName);
            string[] lines = outp.Replace("\r", "").Split('\n');
            string last = null;
            foreach (string line in lines)
            {
                string l = line.Trim();
                if (l.StartsWith("HKEY_")) { last = l; continue; }
                if (line.StartsWith("    "))
                {
                    string t = line.Substring(4);
                    int rt = t.IndexOf("REG_");
                    if (rt < 0) continue;
                    string rest = t.Substring(rt);
                    string data = "";
                    int sp = rest.IndexOf("    ");
                    if (sp >= 0) data = rest.Substring(sp).Trim();
                    if (last != null) res.Add(new string[] { last, data });
                }
            }
            return res;
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
        List<string> mounted = new List<string>();
        string curDrive = "";
        string curPath = "";
        HashSet<string> flagged = new HashSet<string>();
        Process watchdogProc; EventWaitHandle stopEvt; bool stopping = false;
        CheckBox chkTop, chkWatch;

        public MainForm()
        {
            Text = "RescueScan  -  scanner + task manager + explorer (WinRE)";
            Width = 1080; Height = 660; StartPosition = FormStartPosition.CenterScreen;
            MinimumSize = new Size(860, 500);

            tabs = new TabControl(); tabs.Dock = DockStyle.Fill;
            TabPage tp1 = new TabPage("Автозагрузка");
            TabPage tp2 = new TabPage("Диспетчер задач");
            TabPage tp3 = new TabPage("Проводник");
            tabs.TabPages.Add(tp1); tabs.TabPages.Add(tp2); tabs.TabPages.Add(tp3);
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
            btnDelete = new Button(); btnDelete.Text = "Удалить отмеченное"; btnDelete.Left = 8; btnDelete.Top = 7; btnDelete.Width = 150;
            btnExport = new Button(); btnExport.Text = "Экспорт отчёта"; btnExport.Left = 164; btnExport.Top = 7; btnExport.Width = 120;
            lblStatus = new Label(); lblStatus.Left = 296; lblStatus.Top = 12; lblStatus.Width = 740; lblStatus.Text = "Готово.";
            bot.Controls.Add(btnDelete); bot.Controls.Add(btnExport); bot.Controls.Add(lblStatus);
            tp1.Controls.Add(lv); tp1.Controls.Add(top); tp1.Controls.Add(bot);

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
            chkWatch.CheckedChanged += delegate { if (chkWatch.Checked) StartWatchdog(); else StopWatchdog(); };

            // ---- TAB 3: explorer (shows hidden + system by default, red = suspicious) ----
            Panel ebar = new Panel(); ebar.Dock = DockStyle.Top; ebar.Height = 36;
            Button bup = new Button(); bup.Text = "Вверх"; bup.Left = 8; bup.Top = 6; bup.Width = 70;
            txtPath = new TextBox(); txtPath.Left = 82; txtPath.Top = 8; txtPath.Width = 610;
            Button bgo = new Button(); bgo.Text = "Перейти"; bgo.Left = 698; bgo.Top = 6; bgo.Width = 80;
            Button bref = new Button(); bref.Text = "Обновить"; bref.Left = 782; bref.Top = 6; bref.Width = 90;
            ebar.Controls.Add(bup); ebar.Controls.Add(txtPath); ebar.Controls.Add(bgo); ebar.Controls.Add(bref);
            lvFiles = new ListView(); lvFiles.Dock = DockStyle.Fill; lvFiles.View = View.Details; lvFiles.FullRowSelect = true; lvFiles.GridLines = true; lvFiles.MultiSelect = true;
            lvFiles.Columns.Add("Имя", 320); lvFiles.Columns.Add("Тип", 70); lvFiles.Columns.Add("Размер", 100); lvFiles.Columns.Add("Атрибуты", 100); lvFiles.Columns.Add("Изменён", 130);
            Panel ebot = new Panel(); ebot.Dock = DockStyle.Bottom; ebot.Height = 36;
            Button bdel = new Button(); bdel.Text = "Удалить"; bdel.Left = 8; bdel.Top = 6; bdel.Width = 90;
            Button buh = new Button(); buh.Text = "Снять скрытие"; buh.Left = 104; buh.Top = 6; buh.Width = 120;
            lblFiles = new Label(); lblFiles.Left = 234; lblFiles.Top = 11; lblFiles.Width = 800; lblFiles.Text = "Показаны скрытые (серым) и системные. Красный = подозрительный / найден сканом.";
            ebot.Controls.Add(bdel); ebot.Controls.Add(buh); ebot.Controls.Add(lblFiles);
            tp3.Controls.Add(lvFiles); tp3.Controls.Add(ebar); tp3.Controls.Add(ebot);
            bup.Click += delegate { NavUp(); };
            bgo.Click += delegate { Nav(txtPath.Text); };
            bref.Click += delegate { Nav(curPath); };
            bdel.Click += delegate { DeleteFile(); };
            buh.Click += delegate { Unhide(); };
            lvFiles.DoubleClick += delegate { OpenSelected(); };
            txtPath.KeyDown += delegate(object s, KeyEventArgs e) { if (e.KeyCode == Keys.Enter) { Nav(txtPath.Text); e.SuppressKeyPress = true; } };

            // wiring tab1
            btnDetect.Click += delegate { Detect(); };
            btnScan.Click += delegate { Scan(); };
            btnMark.Click += delegate { MarkSuspect(); };
            btnPreboot.Click += delegate { PrebootScan(); };
            btnDelete.Click += delegate { DeleteChecked(); };
            btnExport.Click += delegate { Export(); };
            this.TopMost = true;
            this.FormClosing += delegate { stopping = true; StopWatchdog(); UnloadAll(); };
            this.Shown += delegate { Detect(); RefreshProcs(); ShowDrives(); };
        }

        // ================= WATCHDOG control (user-mode) =================
        void StartWatchdog()
        {
            if (watchdogProc != null && !SafeExited(watchdogProc)) return;
            stopping = false;
            try
            {
                stopEvt = new EventWaitHandle(false, EventResetMode.ManualReset, Watchdog.StopEvtName);
                stopEvt.Reset();
            }
            catch { }
            SpawnWatchdog();
            Thread mt = new Thread(WatchdogMonitor); mt.IsBackground = true; mt.Start();
            lblProc.Text = "Watchdog вооружён. Лог: " + Watchdog.LogPath;
        }

        void SpawnWatchdog()
        {
            try
            {
                string args = "--watchdog " + Process.GetCurrentProcess().Id + " \"" + Application.ExecutablePath + "\"";
                ProcessStartInfo psi = new ProcessStartInfo(Application.ExecutablePath, args);
                psi.UseShellExecute = false; psi.CreateNoWindow = true; psi.WindowStyle = ProcessWindowStyle.Hidden;
                watchdogProc = Process.Start(psi);
                Watchdog.Log("GUI: watchdog запущен (pid " + (watchdogProc != null ? watchdogProc.Id : 0) + ")");
            }
            catch (Exception ex) { Watchdog.Log("GUI: не смог запустить watchdog: " + ex.Message); }
        }

        // GUI is watchdog for its watchdog: respawn it if the virus kills it.
        void WatchdogMonitor()
        {
            while (!stopping)
            {
                try { if (watchdogProc != null) watchdogProc.WaitForExit(); else Thread.Sleep(500); }
                catch { Thread.Sleep(500); }
                if (stopping) return;
                Watchdog.Log("GUI: watchdog УМЕР без команды -> вирус мог убить его. Перезапуск watchdog.");
                SpawnWatchdog();
                Thread.Sleep(400);
            }
        }

        void StopWatchdog()
        {
            stopping = true;
            try { if (stopEvt != null) stopEvt.Set(); } catch { }
            try { if (watchdogProc != null && !SafeExited(watchdogProc)) watchdogProc.Kill(); } catch { }
            Watchdog.Log("GUI: watchdog остановлен по команде.");
        }

        static bool SafeExited(Process p) { try { return p.HasExited; } catch { return true; } }

        void Detect()
        {
            cboWin.Items.Clear();
            for (char c = 'C'; c <= 'Z'; c++)
            {
                string sys = c + ":\\Windows\\System32\\config\\SYSTEM";
                if (File.Exists(sys)) cboWin.Items.Add(c + ":\\Windows");
            }
            if (cboWin.Items.Count > 0) { cboWin.SelectedIndex = 0; lblStatus.Text = "Найдено установок: " + cboWin.Items.Count; }
            else lblStatus.Text = "Windows не найдена на подключённых дисках.";
        }

        void UnloadAll()
        {
            foreach (string m in mounted) Reg.Run("unload \"HKLM\\" + m + "\"");
            mounted.Clear();
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
                string risk = Risk(path);
                if (risk == "" && ProcNameRisk(name)) risk = "REVIEW";
                ListViewItem it = new ListViewItem(new string[] { p.Id.ToString(), name, path, mem, risk });
                it.Tag = p.Id;
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

        void KillProc(bool tree)
        {
            if (lvProc.SelectedItems.Count == 0) { MessageBox.Show("Выбери процесс."); return; }
            int ok = 0, fail = 0;
            Dictionary<int, List<int>> map = tree ? Native.ChildMap() : null;
            foreach (ListViewItem it in lvProc.SelectedItems)
            {
                int pid = (int)it.Tag;
                if (tree) { int k = KillRec(pid, map); ok += k; }
                else { try { Process.GetProcessById(pid).Kill(); ok++; } catch { fail++; } }
            }
            lblProc.Text = (tree ? "Дерево завершено: " : "Завершено: ") + ok + "   ошибок: " + fail;
            RefreshProcs();
        }

        static int KillRec(int pid, Dictionary<int, List<int>> map)
        {
            int n = 0;
            if (map != null && map.ContainsKey(pid))
                foreach (int c in map[pid]) n += KillRec(c, map);   // детей — первыми
            try { Process.GetProcessById(pid).Kill(); n++; } catch { }
            return n;
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
            bool sus = Risk(full) == "SUSPECT" || flagged.Contains(full.ToLowerInvariant());
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

        void DeleteFile()
        {
            if (lvFiles.SelectedItems.Count == 0) { MessageBox.Show("Выбери файл/папку."); return; }
            if (MessageBox.Show("Удалить выбранное (" + lvFiles.SelectedItems.Count + ")? Необратимо.", "Подтверждение",
                MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
            int ok = 0, fail = 0;
            foreach (ListViewItem it in lvFiles.SelectedItems)
            {
                string tag = (string)it.Tag; string p = tag.Substring(2);
                try { if (tag.StartsWith("F|")) File.Delete(p); else Directory.Delete(p, true); ok++; } catch { fail++; }
            }
            lblFiles.Text = "Удалено: " + ok + "   ошибок: " + fail; Nav(curPath);
        }

        void Unhide()
        {
            if (lvFiles.SelectedItems.Count == 0) { MessageBox.Show("Выбери элемент."); return; }
            foreach (ListViewItem it in lvFiles.SelectedItems)
            {
                string p = ((string)it.Tag).Substring(2);
                try { FileAttributes a = File.GetAttributes(p); a &= ~FileAttributes.Hidden; a &= ~FileAttributes.System; File.SetAttributes(p, a); } catch { }
            }
            Nav(curPath);
        }

        static string ExtractPath(string s)
        {
            if (s == null) return "";
            int i = -1;
            for (int k = 0; k < s.Length - 2; k++)
                if (char.IsLetter(s[k]) && s[k + 1] == ':' && (s[k + 2] == '\\' || s[k + 2] == '/')) { i = k; break; }
            if (i < 0) return "";
            bool q = (i > 0 && s[i - 1] == '"');
            int j = i;
            while (j < s.Length && (q ? s[j] != '"' : s[j] != ' ')) j++;
            return s.Substring(i, j - i).Trim();
        }

        // ---- Scan ----
        void Scan()
        {
            if (cboWin.SelectedItem == null) { MessageBox.Show("Сначала выбери установку Windows."); return; }
            Cursor.Current = Cursors.WaitCursor;
            lv.Items.Clear();
            string winDir = cboWin.SelectedItem.ToString();       // e.g. D:\Windows
            curDrive = winDir.Substring(0, 2);                    // D:
            string cfg = winDir + "\\System32\\config";

            UnloadAll();
            int rc; string o;
            rc = Reg.RunCode("load \"HKLM\\RS_SOFT\" \"" + cfg + "\\SOFTWARE\"", out o); if (rc == 0) mounted.Add("RS_SOFT");
            rc = Reg.RunCode("load \"HKLM\\RS_SYS\" \"" + cfg + "\\SYSTEM\"", out o); if (rc == 0) mounted.Add("RS_SYS");

            List<Finding> f = new List<Finding>();
            string SOFT = "HKLM\\RS_SOFT";
            string SYS = "HKLM\\RS_SYS";

            // ---- HKLM Run family ----
            AddValues(f, "Run (HKLM)", SOFT + "\\Microsoft\\Windows\\CurrentVersion\\Run");
            AddValues(f, "RunOnce (HKLM)", SOFT + "\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
            AddValues(f, "Run (HKLM WOW64)", SOFT + "\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run");
            AddValues(f, "RunOnce (HKLM WOW64)", SOFT + "\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce");

            // ---- Winlogon ----
            string wl = SOFT + "\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
            foreach (string[] v in Reg.Values(wl))
            {
                string nm = v[0]; string dt = v[1];
                if (nm.Equals("Shell", StringComparison.OrdinalIgnoreCase))
                    Add(f, "Winlogon Shell", nm, dt, wl, dt.Trim().ToLower() == "explorer.exe" ? "" : "SUSPECT", 0, wl, nm, null);
                else if (nm.Equals("Userinit", StringComparison.OrdinalIgnoreCase))
                    Add(f, "Winlogon Userinit", nm, dt, wl, dt.ToLower().Contains("userinit.exe,") && dt.Split(',').Length <= 2 ? "" : "SUSPECT", 0, wl, nm, null);
                else if (nm.Equals("Taskman", StringComparison.OrdinalIgnoreCase))
                    Add(f, "Winlogon Taskman", nm, dt, wl, "SUSPECT", 0, wl, nm, null);
            }

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
            string ifeo = SOFT + "\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
            foreach (string[] pr in Reg.Pairs(ifeo, "Debugger"))
            {
                string sub = pr[0]; string dbg = pr[1];
                string target = sub.Substring(sub.LastIndexOf('\\') + 1);
                Add(f, "IFEO Debugger", target, dbg, sub, "SUSPECT", 1, sub, null, null);
            }

            // ---- extra SOFTWARE persistence (Active Setup, Notify, Policies, SilentProcessExit, class hijack) ----
            ScanExtraSoftware(f, SOFT);

            // ---- SYSTEM: control set, BootExecute, Services ----
            string ccs = "ControlSet001";
            foreach (string[] v in Reg.Values(SYS + "\\Select"))
                if (v[0].Equals("Current", StringComparison.OrdinalIgnoreCase))
                {
                    int n = 1; try { n = Convert.ToInt32(v[1].Replace("0x", ""), 16); } catch { }
                    ccs = "ControlSet" + n.ToString("D3");
                }
            string sm = SYS + "\\" + ccs + "\\Control\\Session Manager";
            foreach (string[] v in Reg.Values(sm))
                if (v[0].Equals("BootExecute", StringComparison.OrdinalIgnoreCase))
                {
                    string dt = v[1].Replace("\\0", " ").Trim();
                    Add(f, "BootExecute", v[0], dt, sm, dt.ToLower().StartsWith("autocheck autochk") && dt.Length < 40 ? "" : "SUSPECT", 0, sm, v[0], null);
                }
            // suspicious services/drivers only
            foreach (string[] pr in Reg.Pairs(SYS + "\\" + ccs + "\\Services", "ImagePath"))
            {
                string img = pr[1];
                if (Risk(img) == "SUSPECT")
                {
                    string svc = pr[0].Substring(pr[0].LastIndexOf('\\') + 1);
                    Add(f, "Service/Driver", svc, img, pr[0], "SUSPECT", 1, pr[0], null, null);
                }
            }
            // svchost-hosted ServiceDll, LSA packages, Print Monitors, SessionMgr extras
            ScanExtraSystem(f, SYS + "\\" + ccs);

            // ---- Per-user hives ----
            int ui = 0;
            string usersDir = curDrive + "\\Users";
            if (Directory.Exists(usersDir))
            {
                foreach (string ud in Directory.GetDirectories(usersDir))
                {
                    string nt = ud + "\\NTUSER.DAT";
                    string name = Path.GetFileName(ud);
                    if (!File.Exists(nt)) continue;
                    if (name.Equals("Default", StringComparison.OrdinalIgnoreCase) || name.Equals("Public", StringComparison.OrdinalIgnoreCase)) continue;
                    string mp = "RS_U" + ui;
                    rc = Reg.RunCode("load \"HKLM\\" + mp + "\" \"" + nt + "\"", out o);
                    if (rc != 0) continue;
                    mounted.Add(mp);
                    string U = "HKLM\\" + mp;
                    AddValues(f, "Run [" + name + "]", U + "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
                    AddValues(f, "RunOnce [" + name + "]", U + "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
                    AddValuesRisk(f, "Policies Run [" + name + "]", U + "\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", "SUSPECT");
                    string usf = U + "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders";
                    foreach (string[] v in Reg.Values(usf))
                        if (v[0].Equals("Startup", StringComparison.OrdinalIgnoreCase) && v[1].IndexOf("Startup", StringComparison.OrdinalIgnoreCase) < 0)
                            Add(f, "Startup redirect [" + name + "]", v[0], v[1], usf, "SUSPECT", 0, usf, v[0], null);
                    string uw = U + "\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
                    foreach (string[] v in Reg.Values(uw))
                        if (v[0].Equals("Load", StringComparison.OrdinalIgnoreCase) || v[0].Equals("Run", StringComparison.OrdinalIgnoreCase))
                            Add(f, "Win Load/Run [" + name + "]", v[0], v[1], uw, "SUSPECT", 0, uw, v[0], null);
                    // desktop wallpaper (for "effects"/hijacked desktop)
                    string dk = U + "\\Control Panel\\Desktop";
                    foreach (string[] v in Reg.Values(dk))
                        if (v[0].Equals("Wallpaper", StringComparison.OrdinalIgnoreCase) && v[1].Trim().Length > 0)
                            Add(f, "Обои [" + name + "]", v[0], v[1], dk, "REVIEW", 0, dk, v[0], null);
                    ui++;
                }
            }

            // ---- Filesystem: Startup folders ----
            AddStartup(f, curDrive + "\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp", "Startup (все)");
            if (Directory.Exists(usersDir))
                foreach (string ud in Directory.GetDirectories(usersDir))
                    AddStartup(f, ud + "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", "Startup [" + Path.GetFileName(ud) + "]");

            // ---- Drivers folder (нестандартные файлы) ----
            ScanDrivers(f, winDir);

            // ---- Scheduled tasks (+ anti-checker/watchdog) ----
            string tasksDir = winDir + "\\System32\\Tasks";
            if (Directory.Exists(tasksDir))
            {
                string[] all = Directory.GetFiles(tasksDir, "*", SearchOption.AllDirectories);
                foreach (string tf in all)
                {
                    string body = "";
                    try { body = File.ReadAllText(tf); } catch { }
                    string risk = Risk(body);
                    string wd = WatchdogRisk(body);
                    if (risk == "" && wd == "SUSPECT") risk = "SUSPECT";
                    string rel = tf.Substring(tasksDir.Length).TrimStart('\\');
                    string cmd = ExtractTag(body, "Command");
                    string args = ExtractTag(body, "Arguments");
                    string shown = (cmd + " " + args).Trim();
                    string cat = wd == "SUSPECT" ? "Task *checker?*" : "Scheduled Task";
                    Add(f, cat, rel, shown.Length > 0 ? shown : "(task)", tf, risk, 2, null, null, tf);
                }
            }

            // populate + build flagged-path set for the Explorer highlight
            flagged.Clear();
            foreach (Finding x in f)
            {
                if (x.Kind == 2 && x.DelPath != null) flagged.Add(x.DelPath.ToLowerInvariant());
                if (x.Risk == "SUSPECT") { string pp = ExtractPath(x.Value); if (pp.Length > 0) flagged.Add(pp.ToLowerInvariant()); }
                AddRow(x);
            }
            Cursor.Current = Cursors.Default;
            int susp = 0; foreach (Finding x in f) if (x.Risk == "SUSPECT") susp++;
            lblStatus.Text = "Записей: " + f.Count + "   подозрительных: " + susp + "   (ControlSet: " + ccs + ")";
        }

        void AddValues(List<Finding> f, string cat, string key)
        {
            foreach (string[] v in Reg.Values(key))
            {
                if (v[0].StartsWith("(") ) continue; // (Default)
                Add(f, cat, v[0], v[1], key, Risk(v[1]), 0, key, v[0], null);
            }
        }

        void AddValuesRisk(List<Finding> f, string cat, string key, string forceRisk)
        {
            foreach (string[] v in Reg.Values(key))
            {
                if (v[0].StartsWith("(")) continue;
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

        // ---- MODULE: extra SOFTWARE-hive persistence ----
        void ScanExtraSoftware(List<Finding> f, string SOFT)
        {
            string[] roots = { SOFT, SOFT + "\\Wow6432Node" };
            foreach (string R in roots)
            {
                AddValuesRisk(f, "Policies Explorer Run", R + "\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", "SUSPECT");
                AddValuesRisk(f, "RunServices", R + "\\Microsoft\\Windows\\CurrentVersion\\RunServices", "SUSPECT");
                AddValuesRisk(f, "RunServicesOnce", R + "\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce", "SUSPECT");
                // Active Setup StubPath (runs at logon)
                string asroot = R + "\\Microsoft\\Active Setup\\Installed Components";
                foreach (string sk in Reg.Subkeys(asroot))
                    foreach (string[] v in Reg.Values(sk))
                        if (v[0].Equals("StubPath", StringComparison.OrdinalIgnoreCase) && v[1].Trim().Length > 0)
                            Add(f, "Active Setup", Last(sk), v[1], sk, Risk(v[1]) == "SUSPECT" ? "SUSPECT" : "REVIEW", 0, sk, v[0], null);
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
                    if (v[0].StartsWith("("))
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
                if ((v[0].Equals("GinaDLL", StringComparison.OrdinalIgnoreCase) || v[0].Equals("VmApplet", StringComparison.OrdinalIgnoreCase)
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
            // Explorer\Run (политика, HKLM)
            AddValuesRisk(f, "Explorer\\Run (HKLM)", SOFT + "\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", "SUSPECT");
        }

        // ---- MODULE: extra SYSTEM-hive persistence (services & co.) ----
        void ScanExtraSystem(List<Finding> f, string CCS)
        {
            // svchost-hosted ServiceDll (classic hiding spot inside a shared svchost group)
            foreach (string[] pr in Reg.Pairs(CCS + "\\Services", "ServiceDll"))
                if (Risk(pr[1]) == "SUSPECT")
                {
                    string p = pr[0]; string nm = p;
                    int i = p.IndexOf("\\Services\\");
                    if (i >= 0) { nm = p.Substring(i + 10); int j = nm.IndexOf('\\'); if (j > 0) nm = nm.Substring(0, j); }
                    Add(f, "svchost ServiceDll", nm, pr[1], pr[0], "SUSPECT", 0, pr[0], "ServiceDll", null);
                }
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
            foreach (string vn in new string[] { "SetupExecute", "S0InitialCommand", "PlatformExecute", "AppCertDlls" })
                foreach (string[] v in Reg.Values(sm))
                    if (v[0].Equals(vn, StringComparison.OrdinalIgnoreCase) && v[1].Trim().Length > 0)
                        Add(f, "SessionMgr " + vn, v[0], v[1].Replace("\\0", " "), sm, "SUSPECT", 0, sm, v[0], null);
        }

        // ---- MODULE: drivers folder (non-.sys files are highly unusual) ----
        void ScanDrivers(List<Finding> f, string winDir)
        {
            string dir = winDir + "\\System32\\drivers";
            if (!Directory.Exists(dir)) return;
            foreach (string fp in Directory.GetFiles(dir))
            {
                string ext = Path.GetExtension(fp).ToLower();
                string nm = Path.GetFileName(fp);
                if (ext == ".sys") continue;
                if (nm.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                Add(f, "drivers\\ (не .sys!)", nm, fp, fp, "SUSPECT", 2, null, null, fp);
            }
        }

        static string WatchdogRisk(string body)
        {
            if (body == null) return "";
            string l = body.ToLowerInvariant();
            string[] kw = { "check", "chk", "watch", "guard", "restore", "reg add", "reg import", "schtasks", "bcdedit", ".ps1", ".bat", ".vbs", "-enc", "-w hidden", "-windowstyle hidden", "mshta" };
            foreach (string k in kw) if (l.Contains(k)) return "SUSPECT";
            return "";
        }

        // ---- MODULE: pre-boot (BCD store + ESP contents) ----
        void PrebootScan()
        {
            if (curDrive == "") { MessageBox.Show("Сначала нажми «Сканировать» (нужен выбранный диск)."); return; }
            Cursor.Current = Cursors.WaitCursor;
            List<Finding> f = new List<Finding>();
            string bo; RunProc("bcdedit", "/enum all", out bo);
            ParseBcd(f, bo);
            int esps = 0;
            for (char c = 'A'; c <= 'Z'; c++)
            {
                string efi = c + ":\\EFI";
                if (!Directory.Exists(efi)) continue;
                if (!Directory.Exists(efi + "\\Microsoft") && !Directory.Exists(efi + "\\Boot")) continue;
                ScanEsp(f, efi); esps++;
            }
            foreach (Finding x in f) AddRow(x);
            Cursor.Current = Cursors.Default;
            lblStatus.Text = "Pre-boot: +" + f.Count + " записей (BCD + ESP найдено: " + esps + "). ESP без буквы — присвой через diskpart.";
        }

        static int RunProc(string exe, string args, out string outp)
        {
            ProcessStartInfo psi = new ProcessStartInfo(exe, args);
            psi.UseShellExecute = false; psi.CreateNoWindow = true; psi.RedirectStandardOutput = true; psi.RedirectStandardError = true;
            try { Process p = Process.Start(psi); string so = p.StandardOutput.ReadToEnd(); p.StandardError.ReadToEnd(); p.WaitForExit(); outp = so; return p.ExitCode; }
            catch (Exception ex) { outp = ex.Message; return -1; }
        }

        void ParseBcd(List<Finding> f, string txt)
        {
            if (txt == null) return;
            string[] lines = txt.Replace("\r", "").Split('\n');
            string desc = "";
            foreach (string line in lines)
            {
                string l = line.Trim();
                if (l.StartsWith("description")) { desc = l.Substring(11).Trim(); }
                else if (l.StartsWith("path"))
                {
                    string p = l.Substring(4).Trim(); string lp = p.ToLower();
                    bool ok = lp.EndsWith("winload.efi") || lp.EndsWith("winload.exe") || lp.EndsWith("bootmgfw.efi")
                        || lp.EndsWith("bootmgr.efi") || lp.EndsWith("\\bootmgr") || lp.EndsWith("winresume.efi")
                        || lp.EndsWith("winresume.exe") || lp.EndsWith("memtest.efi") || lp.EndsWith("hvloader.efi");
                    Add(f, "BCD path", desc.Length > 0 ? desc : "(entry)", p, "BCD store", ok ? "" : "SUSPECT", 3, null, null, null);
                }
            }
        }

        void ScanEsp(List<Finding> f, string efi)
        {
            try
            {
                foreach (string fp in Directory.GetFiles(efi, "*", SearchOption.AllDirectories))
                {
                    string ext = Path.GetExtension(fp).ToLower();
                    string rel = fp.Substring(efi.Length).TrimStart('\\');
                    string low = rel.ToLower();
                    if (ext == ".efi")
                    {
                        bool std = low.StartsWith("microsoft\\") || low.StartsWith("boot\\") || low.Contains("\\boot\\") || low.StartsWith("linux\\") || low.StartsWith("ubuntu\\");
                        Add(f, "ESP .efi", rel, fp, fp, std ? "REVIEW" : "SUSPECT", 2, null, null, fp);
                    }
                    else if (ext == ".exe" || ext == ".dll" || ext == ".bat" || ext == ".cmd" || ext == ".ps1" || ext == ".vbs" || ext == ".scr")
                        Add(f, "ESP чужой файл!", rel, fp, fp, "SUSPECT", 2, null, null, fp);
                }
            }
            catch { }
        }

        void AddStartup(List<Finding> f, string dir, string cat)
        {
            if (!Directory.Exists(dir)) return;
            foreach (string fp in Directory.GetFiles(dir))
            {
                string nm = Path.GetFileName(fp);
                if (nm.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                Add(f, cat, nm, fp, fp, Risk(nm) == "SUSPECT" ? "SUSPECT" : "REVIEW", 2, null, null, fp);
            }
        }

        void Add(List<Finding> f, string cat, string name, string val, string loc, string risk, int kind, string dkey, string dname, string dpath)
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

        static string Risk(string s)
        {
            if (s == null) return "";
            string l = s.ToLowerInvariant();
            string[] bad = { "\\temp\\", "\\appdata\\", "\\programdata\\", "\\users\\public", "\\downloads\\",
                "%temp%", "%appdata%", ".scr", ".pif", ".tmp\"", "powershell", "-enc", "-w hidden", "-windowstyle hidden",
                "mshta", "wscript", "cscript", "rundll32", "regsvr32", "certutil", "bitsadmin", "\\public\\" };
            foreach (string b in bad) if (l.Contains(b)) return "SUSPECT";
            return "";
        }

        void MarkSuspect()
        {
            foreach (ListViewItem it in lv.Items)
            {
                Finding x = (Finding)it.Tag;
                it.Checked = (x.Risk == "SUSPECT");
            }
        }

        void DeleteChecked()
        {
            int n = 0; foreach (ListViewItem it in lv.Items) if (it.Checked) n++;
            if (n == 0) { MessageBox.Show("Ничего не отмечено."); return; }
            if (MessageBox.Show("Удалить отмеченных записей: " + n + " ?\nОперация необратима.", "Подтверждение",
                MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;

            List<ListViewItem> done = new List<ListViewItem>();
            int ok = 0, fail = 0, skip = 0;
            foreach (ListViewItem it in lv.Items)
            {
                if (!it.Checked) continue;
                Finding x = (Finding)it.Tag;
                if (x.Kind == 3) { skip++; continue; }   // info-only (BCD/LSA/class hijack): чинить вручную, не удалять
                bool r = false;
                try
                {
                    if (x.Kind == 0) { string o; r = Reg.RunCode("delete \"" + x.DelKey + "\" /v \"" + x.DelName + "\" /f", out o) == 0; }
                    else if (x.Kind == 1) { string o; r = Reg.RunCode("delete \"" + x.DelKey + "\" /f", out o) == 0; }
                    else if (x.Kind == 2) { File.Delete(x.DelPath); r = true; }
                }
                catch { r = false; }
                if (r) { ok++; done.Add(it); } else fail++;
            }
            foreach (ListViewItem it in done) lv.Items.Remove(it);
            lblStatus.Text = "Удалено: " + ok + "   ошибок: " + fail + "   пропущено (info): " + skip;
        }

        void Export()
        {
            SaveFileDialog sd = new SaveFileDialog();
            sd.Filter = "CSV|*.csv|Text|*.txt";
            sd.FileName = "RescueScan_report.csv";
            if (sd.ShowDialog() != DialogResult.OK) return;
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Category;Name;Value;Location;Risk");
            foreach (ListViewItem it in lv.Items)
            {
                Finding x = (Finding)it.Tag;
                sb.AppendLine(Q(x.Category) + ";" + Q(x.Name) + ";" + Q(x.Value) + ";" + Q(x.Location) + ";" + x.Risk);
            }
            try { File.WriteAllText(sd.FileName, sb.ToString(), Encoding.UTF8); lblStatus.Text = "Сохранено: " + sd.FileName; }
            catch (Exception ex) { MessageBox.Show(ex.Message); }
        }

        static string Q(string s) { if (s == null) return "\"\""; return "\"" + s.Replace("\"", "'") + "\""; }
    }

    // ================= WATCHDOG (user-mode self-heal) =================
    static class Watchdog
    {
        public static string LogPath = Path.Combine(Path.GetTempPath(), "rescuescan.log");
        public const string StopEvtName = "RescueScanStopEvt";

        public static void Log(string msg)
        {
            try { File.AppendAllText(LogPath, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + msg + "\r\n"); }
            catch { }
        }

        // Runs headless: watches the GUI pid, relaunches it if it dies unexpectedly.
        public static void Run(string[] args)
        {
            int pid = 0; try { pid = int.Parse(args[1]); } catch { }
            string exe = args.Length > 2 ? args[2].Trim('"') : Application.ExecutablePath;
            EventWaitHandle stop = null;
            try { stop = EventWaitHandle.OpenExisting(StopEvtName); }
            catch { try { stop = new EventWaitHandle(false, EventResetMode.ManualReset, StopEvtName); } catch { } }
            Log("watchdog: старт, слежу за pid " + pid);
            while (true)
            {
                try { Process.GetProcessById(pid).WaitForExit(); }
                catch { Thread.Sleep(400); }
                if (stop != null && stop.WaitOne(0)) { Log("watchdog: получен стоп-сигнал, выходим."); return; }
                Log("watchdog: ГЛАВНЫЙ процесс (pid " + pid + ") исчез без стоп-сигнала -> ВИРУС мог его убить. Перезапуск.");
                try { Process np = Process.Start(exe); pid = np.Id; Log("watchdog: перезапущено, новый pid " + pid); }
                catch (Exception ex) { Log("watchdog: не смог перезапустить: " + ex.Message); Thread.Sleep(1000); }
            }
        }
    }

    // ================= Native (Toolhelp for process tree) =================
    static class Native
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESSENTRY32
        {
            public uint dwSize; public uint cntUsage; public uint th32ProcessID;
            public IntPtr th32DefaultHeapID; public uint th32ModuleID; public uint cntThreads;
            public uint th32ParentProcessID; public int pcPriClassBase; public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
        }
        [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)] public static extern bool Process32First(IntPtr snap, ref PROCESSENTRY32 pe);
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)] public static extern bool Process32Next(IntPtr snap, ref PROCESSENTRY32 pe);
        [DllImport("kernel32.dll", SetLastError = true)] public static extern bool CloseHandle(IntPtr h);

        public static Dictionary<int, List<int>> ChildMap()
        {
            Dictionary<int, List<int>> map = new Dictionary<int, List<int>>();
            IntPtr snap = CreateToolhelp32Snapshot(0x2 /*TH32CS_SNAPPROCESS*/, 0);
            if (snap == (IntPtr)(-1)) return map;
            try
            {
                PROCESSENTRY32 pe = new PROCESSENTRY32(); pe.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32));
                if (Process32First(snap, ref pe))
                    do
                    {
                        int p = (int)pe.th32ParentProcessID, c = (int)pe.th32ProcessID;
                        if (!map.ContainsKey(p)) map[p] = new List<int>();
                        map[p].Add(c);
                    } while (Process32Next(snap, ref pe));
            }
            finally { CloseHandle(snap); }
            return map;
        }
    }

    static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            if (args.Length >= 1 && args[0] == "--watchdog") { Watchdog.Run(args); return; }
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }
}
