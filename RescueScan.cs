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
        List<Finding> lastFindings = new List<Finding>();
        Process watchdogProc; EventWaitHandle stopEvt; bool stopping = false;
        CheckBox chkTop, chkWatch;
        Button btnQuar, btnWho, btnQuarFile;
        string quarDir = "";
        ListView lvRepair; CheckBox chkGuard; bool guarding = false; Thread guardThread;
        ListView lvSimple;
        ListView lvQuar; string quarViewDir = ""; Label lblQuar;

        public MainForm()
        {
            Text = "RescueScan  -  scanner + task manager + explorer (WinRE)";
            Width = 1080; Height = 660; StartPosition = FormStartPosition.CenterScreen;
            MinimumSize = new Size(860, 500);

            tabs = new TabControl(); tabs.Dock = DockStyle.Fill;
            TabPage tp1 = new TabPage("Автозагрузка (полная)");
            TabPage tpS = new TabPage("Автозапуск (кратко)");
            TabPage tp2 = new TabPage("Диспетчер задач");
            TabPage tp3 = new TabPage("Проводник");
            TabPage tpQ = new TabPage("Карантин");
            TabPage tp4 = new TabPage("Ремонт");
            TabPage tp5 = new TabPage("Справка");
            tabs.TabPages.Add(tp1); tabs.TabPages.Add(tpS); tabs.TabPages.Add(tp2); tabs.TabPages.Add(tp3); tabs.TabPages.Add(tpQ); tabs.TabPages.Add(tp4); tabs.TabPages.Add(tp5);
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
            btnQuar = new Button(); btnQuar.Text = "Карантин отмеч."; btnQuar.Left = 8; btnQuar.Top = 7; btnQuar.Width = 130;
            btnDelete = new Button(); btnDelete.Text = "Удалить отмеч."; btnDelete.Left = 144; btnDelete.Top = 7; btnDelete.Width = 130;
            btnExport = new Button(); btnExport.Text = "Экспорт отчёта"; btnExport.Left = 280; btnExport.Top = 7; btnExport.Width = 120;
            lblStatus = new Label(); lblStatus.Left = 408; lblStatus.Top = 12; lblStatus.Width = 640; lblStatus.Text = "Готово.";
            bot.Controls.Add(btnQuar); bot.Controls.Add(btnDelete); bot.Controls.Add(btnExport); bot.Controls.Add(lblStatus);
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
            lvQuar.Columns.Add("Тип", 70); lvQuar.Columns.Add("Оригинал / ключ", 560); lvQuar.Columns.Add("Бэкап", 340);
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
            Panel rbot = new Panel(); rbot.Dock = DockStyle.Bottom; rbot.Height = 30;
            Label rlbl = new Label(); rlbl.Left = 8; rlbl.Top = 7; rlbl.Width = 1000; rlbl.Text = "Красным — значение отличается от дефолта (возможная подмена). Правит офлайн-куст (нужен «Сканировать»). Guard работает на ЖИВОЙ ОС.";
            rbot.Controls.Add(rlbl);
            tp4.Controls.Add(lvRepair); tp4.Controls.Add(rbar); tp4.Controls.Add(rbot);
            rref.Click += delegate { RepairRefresh(); };
            rdef.Click += delegate { RepairSet(false); };
            rcus.Click += delegate { RepairSet(true); };
            chkGuard.CheckedChanged += delegate { GuardToggle(); };

            // ---- TAB 5: help ----
            TextBox help = new TextBox(); help.Dock = DockStyle.Fill; help.Multiline = true; help.ReadOnly = true;
            help.ScrollBars = ScrollBars.Vertical; help.BackColor = Color.White; help.Font = new Font("Segoe UI", 9f);
            help.Text = HelpText();
            tp5.Controls.Add(help);

            // wiring tab1
            btnDetect.Click += delegate { Detect(); };
            btnScan.Click += delegate { Scan(); };
            btnMark.Click += delegate { MarkSuspect(lv); };
            btnPreboot.Click += delegate { PrebootScan(); };
            btnQuar.Click += delegate { QuarantineChecked(lv); };
            btnDelete.Click += delegate { DeleteChecked(lv); };
            btnExport.Click += delegate { Export(); };
            this.TopMost = true;
            this.FormClosing += delegate { stopping = true; guarding = false; StopWatchdog(); UnloadAll(); };
            this.Load += delegate { StartupPick(); };
            this.Shown += delegate { RefreshProcs(); ShowDrives(); RepairRefresh(); QuarAutoFind(); };
        }

        // ================= STARTUP DISK PICKER =================
        void StartupPick()
        {
            Detect(); // fills cboWin with detected installs
            Form f = new Form(); f.Text = "RescueScan — выбор системы"; f.Width = 500; f.Height = 300;
            f.StartPosition = FormStartPosition.CenterScreen; f.FormBorderStyle = FormBorderStyle.FixedDialog;
            f.MinimizeBox = false; f.MaximizeBox = false; f.TopMost = true;
            Label l = new Label(); l.Left = 12; l.Top = 12; l.Width = 460; l.Height = 56;
            l.Text = "На каком диске установлена Windows для проверки?\r\n• в WinRE — выбери офлайн-установку (напр. D:\\Windows)\r\n• на живой ОС — свою (C:\\Windows)";
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
"RescueScan — защитный инструмент для чистки заражённой Windows.\r\n" +
"Работает в двух режимах: ОФЛАЙН (загрузился в WinRE/WinPE — цель выключена, вирус не сопротивляется) и ЖИВОЙ (запущен прямо в заражённой ОС от админа).\r\n" +
"\r\n" +
"ЦВЕТА:\r\n" +
"  Красный  = SUSPECT, сильный признак вредоноса (temp, -enc/hidden, интерпретатор+загрузка, двойное расширение, exe в drivers).\r\n" +
"  Жёлтый   = REVIEW, ЛЕГИТИМНОЕ но частое у малвари место (AppData, ProgramData, Downloads, автозагрузка) — просто глянь, не паникуй.\r\n" +
"  Красный часто = ложные срабатывания на своих программах в AppData. Это норма, смотри путь.\r\n" +
"\r\n" +
"ВКЛАДКА «Автозагрузка»:\r\n" +
"  1) «Найти ОС» -> «Сканировать». Показывает ВСЕ точки автозапуска (Run/Службы/Задачи/IFEO/Winlogon/ESP...).\r\n" +
"  2) «Отметить подозрительные» -> проверь галочки глазами.\r\n" +
"  3) «Карантин отмеч.» (перенос+бэкап, безопасно) ИЛИ «Удалить отмеч.».\r\n" +
"  ВАЖНО: если файл висит на boot-критичном якоре (служба/Userinit), удаление может убить загрузку.\r\n" +
"         Сначала почини якорь на вкладке «Ремонт», потом убирай файл.\r\n" +
"\r\n" +
"ВКЛАДКА «Диспетчер задач»: процессы с путём и риском; «Завершить» и «Завершить дерево».\r\n" +
"  «Поверх всех окон» — чтобы вирусный интерфейс не перекрывал. «Watchdog» — самовосстановление окна, если вирус его убьёт (лог в temp).\r\n" +
"\r\n" +
"ВКЛАДКА «Проводник»: видит СКРЫТЫЕ и СИСТЕМНЫЕ файлы. Красный = найден сканом.\r\n" +
"  «Кто ссылается» — из какой точки автозапуска стартует выбранный файл. «Снять скрытие» — убрать атрибуты H/S. «Карантин»/«Удалить».\r\n" +
"\r\n" +
"ВКЛАДКА «Ремонт» (как пользоваться):\r\n" +
"  Список Winlogon Shell/Userinit/AppInit/cmd AutoRun. Красная строка = значение отличается от дефолта (подмена).\r\n" +
"  ВЫДЕЛИ строку -> «→ Дефолт» (вернуть штатное) или «→ Своё…» (ввести своё значение).\r\n" +
"  Работает и офлайн (правит смонтированный куст), и на живой ОС (правит HKLM напрямую).\r\n" +
"  «Стеречь Winlogon» — фоновый страж: если вирус подменит Shell/Userinit, вернёт дефолт (только живая ОС).\r\n" +
"\r\n" +
"ГРАНИЦЫ: RescueScan чистит уровень ОС + загрузчик/ESP. Имплант в прошивку (BIOS/SPI) НЕ трогает — только перепрошивка.\r\n" +
"Сброс пароля офлайн (правка SAM) НЕ входит — используй chntpw / MS DaRT. Аккаунт-операции живьём — через net user (пока не встроено).\r\n";
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

        void RenameSelected()
        {
            if (lvFiles.SelectedItems.Count != 1) { MessageBox.Show("Выбери ровно один элемент."); return; }
            string tag = (string)lvFiles.SelectedItems[0].Tag;
            if (!tag.StartsWith("F|") && !tag.StartsWith("D|")) return;
            string p = tag.Substring(2);
            string old = Path.GetFileName(p.TrimEnd('\\'));
            string nn = Prompt("Новое имя для «" + old + "»", old);
            if (nn == null) return; nn = nn.Trim();
            if (nn.Length == 0 || nn == old) return;
            string dst = Path.Combine(Path.GetDirectoryName(p.TrimEnd('\\')), nn);
            try { if (tag.StartsWith("F|")) File.Move(p, dst); else Directory.Move(p, dst); }
            catch (Exception ex) { MessageBox.Show(ex.Message); }
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
                    if (shown.Length == 0)
                    {
                        string cls = ExtractTag(body, "ClassId");
                        if (cls.Length > 0) shown = "COM-обработчик " + cls;
                        else if (body.IndexOf("<ComHandler", StringComparison.OrdinalIgnoreCase) >= 0) shown = "(COM-обработчик)";
                        else shown = "(нет exec-команды)";
                    }
                    string cat = wd == "SUSPECT" ? "Task *checker?*" : "Scheduled Task";
                    Add(f, cat, rel, shown, tf, risk, 2, null, null, tf);
                }
            }

            // populate + build flagged-path set for the Explorer highlight
            lastFindings = f;
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
            RepairRefresh();
            SimpleRefresh();
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
            string[] benign = { ".dat", ".dls", ".wdf", ".txt", ".mui", ".bin", ".din", ".cat", ".inf", ".ini", ".xml", ".json", ".etl" };
            string[] exe = { ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".scr", ".com", ".pif", ".js", ".hta" };
            foreach (string fp in Directory.GetFiles(dir))
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
            string[] kw = { "reg add ", "reg import", "schtasks /create", "bcdedit", "-enc", "-encodedcommand",
                "-w hidden", "-windowstyle hidden", "frombase64", "downloadstring", "mshta", "\\temp\\", "\\appdata\\local\\temp\\" };
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
            // STRONG -> SUSPECT (red): почти всегда вредонос
            string[] strong = { "\\temp\\", "\\appdata\\local\\temp\\", "%temp%", ".scr", ".pif",
                "-enc", "-encodedcommand", "-w hidden", "-windowstyle hidden", "frombase64string",
                "invoke-expression", "iex(", "iex ", "downloadstring", "downloadfile",
                ".txt.exe", ".pdf.exe", ".doc.exe", ".jpg.exe", ".png.exe", ".scr.exe" };
            foreach (string b in strong) if (l.Contains(b)) return "SUSPECT";
            // интерпретатор + подозрительное использование (а не просто путь к нему)
            bool interp = l.Contains("powershell") || l.Contains("mshta") || l.Contains("wscript")
                || l.Contains("cscript") || l.Contains("rundll32") || l.Contains("regsvr32")
                || l.Contains("certutil") || l.Contains("bitsadmin");
            if (interp && (l.Contains("http") || l.Contains("\\temp\\") || l.Contains("%temp%")
                || l.Contains("\\appdata\\") || l.Contains("javascript:") || l.Contains("/i:") || l.Contains(".hta")))
                return "SUSPECT";
            // SOFT -> REVIEW (yellow): легитимные места, где ТОЖЕ часто прячется малварь — просто «глянь»
            string[] soft = { "\\appdata\\", "%appdata%", "\\programdata\\", "\\downloads\\", "\\users\\public", "\\public\\" };
            foreach (string b in soft) if (l.Contains(b)) return "REVIEW";
            return "";
        }

        void MarkSuspect(ListView target)
        {
            foreach (ListViewItem it in target.Items)
            {
                Finding x = (Finding)it.Tag;
                it.Checked = (x.Risk == "SUSPECT");
            }
        }

        // ================= QUARANTINE (safe removal with backup) =================
        bool EnsureQuar()
        {
            if (quarDir.Length > 0 && Directory.Exists(quarDir)) return true;
            string bas = Path.GetDirectoryName(Application.ExecutablePath);
            string stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string[] cands = { Path.Combine(bas, "Quarantine_" + stamp),
                               Path.Combine(curDrive.Length == 2 ? curDrive + "\\" : "C:\\", "RescueScan_Quarantine\\" + stamp),
                               Path.Combine(Path.GetTempPath(), "RescueScan_Quarantine_" + stamp) };
            foreach (string c in cands)
                try { Directory.CreateDirectory(c); quarDir = c; return true; } catch { }
            MessageBox.Show("Не удалось создать папку карантина."); return false;
        }

        void QLog(string line)
        {
            try { File.AppendAllText(Path.Combine(quarDir, "manifest.txt"), line + "\r\n", Encoding.UTF8); } catch { }
        }

        // move a file into quarantine; returns true on success
        bool QuarFile(string path)
        {
            if (!EnsureQuar()) return false;
            try
            {
                string name = Path.GetFileName(path);
                string dst = Path.Combine(quarDir, name);
                int n = 1; while (File.Exists(dst)) { dst = Path.Combine(quarDir, "(" + (n++) + ")" + name); }
                try { File.SetAttributes(path, FileAttributes.Normal); } catch { }
                File.Move(path, dst);
                QLog("FILE\t" + path + "\t=>\t" + dst);
                return true;
            }
            catch (Exception ex) { QLog("FILE-FAIL\t" + path + "\t" + ex.Message); return false; }
        }

        // export a reg key to .reg (backup) then return true; caller deletes afterwards
        bool QuarReg(string key)
        {
            if (!EnsureQuar()) return false;
            try
            {
                string safe = key.Replace("\\", "_").Replace("\"", "");
                if (safe.Length > 80) safe = safe.Substring(safe.Length - 80);
                string dst = Path.Combine(quarDir, "reg_" + safe + ".reg");
                string o; Reg.RunCode("export \"" + key + "\" \"" + dst + "\" /y", out o);
                QLog("REG\t" + key + "\t=>\t" + dst);
                return true;
            }
            catch (Exception ex) { QLog("REG-FAIL\t" + key + "\t" + ex.Message); return false; }
        }

        void QuarantineChecked(ListView target)
        {
            int n = 0; foreach (ListViewItem it in target.Items) if (it.Checked) n++;
            if (n == 0) { MessageBox.Show("Ничего не отмечено."); return; }
            if (MessageBox.Show("Карантин отмеченных (" + n + ")? Файлы будут перенесены, ветки реестра — забэкаплены в .reg и удалены.\nПапка карантина создастся рядом с программой.", "Карантин",
                MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            List<ListViewItem> done = new List<ListViewItem>();
            int ok = 0, fail = 0, skip = 0;
            foreach (ListViewItem it in target.Items)
            {
                if (!it.Checked) continue;
                Finding x = (Finding)it.Tag;
                bool r = false;
                if (x.Kind == 2) r = QuarFile(x.DelPath);
                else if (x.Kind == 0) { if (QuarReg(x.DelKey)) { string o; r = Reg.RunCode("delete \"" + x.DelKey + "\" /v \"" + x.DelName + "\" /f", out o) == 0; } }
                else if (x.Kind == 1) { if (QuarReg(x.DelKey)) { string o; r = Reg.RunCode("delete \"" + x.DelKey + "\" /f", out o) == 0; } }
                else { skip++; continue; }
                if (r) { ok++; done.Add(it); } else fail++;
            }
            foreach (ListViewItem it in done) target.Items.Remove(it);
            lblStatus.Text = "Карантин: " + ok + "   ошибок: " + fail + "   пропущено: " + skip + "   -> " + quarDir;
        }

        void QuarantineSelectedFiles()
        {
            if (lvFiles.SelectedItems.Count == 0) { MessageBox.Show("Выбери файл."); return; }
            int ok = 0, fail = 0;
            List<ListViewItem> done = new List<ListViewItem>();
            foreach (ListViewItem it in lvFiles.SelectedItems)
            {
                string tag = (string)it.Tag;
                if (!tag.StartsWith("F|")) continue;   // только файлы
                if (QuarFile(tag.Substring(2))) { ok++; done.Add(it); } else fail++;
            }
            lblFiles.Text = "В карантин: " + ok + "   ошибок: " + fail + "   -> " + quarDir;
            Nav(curPath);
        }

        // ---- Quarantine viewer / restore ----
        void QuarAutoFind()
        {
            string bas = Path.GetDirectoryName(Application.ExecutablePath);
            string best = ""; DateTime bestT = DateTime.MinValue;
            try
            {
                foreach (string d in Directory.GetDirectories(bas, "Quarantine_*"))
                {
                    DateTime t = Directory.GetLastWriteTime(d);
                    if (t > bestT && File.Exists(Path.Combine(d, "manifest.txt"))) { bestT = t; best = d; }
                }
            }
            catch { }
            if (best.Length == 0) { lblQuar.Text = "Рядом с программой нет папок Quarantine_* с manifest.txt. Нажми «Открыть папку…»."; lvQuar.Items.Clear(); return; }
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
            string mf = Path.Combine(dir, "manifest.txt");
            if (!File.Exists(mf)) { lblQuar.Text = "Нет manifest.txt в " + dir; return; }
            int cnt = 0;
            foreach (string line in File.ReadAllLines(mf))
            {
                string[] p = line.Split('\t');
                if (p.Length < 4) continue;
                if (p[0] != "FILE" && p[0] != "REG") continue;   // пропускаем *-FAIL
                string type = p[0]; string orig = p[1]; string backup = p[3];
                ListViewItem it = new ListViewItem(new string[] { type, orig, backup });
                it.Tag = new string[] { type, orig, backup };
                if (!File.Exists(backup)) it.ForeColor = Color.Gray;   // бэкап уже убран
                lvQuar.Items.Add(it); cnt++;
            }
            lblQuar.Text = "Карантин: " + dir + "   (записей: " + cnt + ")";
        }

        void QuarRestore()
        {
            int n = 0; foreach (ListViewItem it in lvQuar.Items) if (it.Checked) n++;
            if (n == 0) { MessageBox.Show("Отметь, что восстановить."); return; }
            if (MessageBox.Show("Восстановить отмеченные (" + n + ") на исходные места?", "Восстановление",
                MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            int ok = 0, fail = 0;
            List<ListViewItem> done = new List<ListViewItem>();
            foreach (ListViewItem it in lvQuar.Items)
            {
                if (!it.Checked) continue;
                string[] e = (string[])it.Tag; bool r = false;
                try
                {
                    if (e[0] == "FILE")
                    {
                        string orig = e[1], backup = e[2];
                        if (File.Exists(backup))
                        {
                            string od = Path.GetDirectoryName(orig);
                            if (od.Length > 0 && !Directory.Exists(od)) Directory.CreateDirectory(od);
                            if (File.Exists(orig)) File.Delete(orig);
                            File.Move(backup, orig); r = true;
                        }
                    }
                    else if (e[0] == "REG")
                    {
                        string o; r = Reg.RunCode("import \"" + e[2] + "\"", out o) == 0;
                    }
                }
                catch { r = false; }
                if (r) { ok++; done.Add(it); } else fail++;
            }
            foreach (ListViewItem it in done) lvQuar.Items.Remove(it);
            lblQuar.Text = "Восстановлено: " + ok + "   ошибок: " + fail;
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
                    string vp = ExtractPath(x.Value).ToLowerInvariant();
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
        static string[][] Anchors()
        {
            return new string[][] {
                new string[]{ "Winlogon Shell",    "Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "Shell",    "explorer.exe", "0" },
                new string[]{ "Winlogon Userinit", "Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "Userinit", "C:\\Windows\\system32\\userinit.exe,", "0" },
                new string[]{ "Winlogon Taskman",  "Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "Taskman",  "", "1" },
                new string[]{ "AppInit_DLLs",      "Microsoft\\Windows NT\\CurrentVersion\\Windows",  "AppInit_DLLs", "", "0" },
                new string[]{ "cmd AutoRun",       "Microsoft\\Command Processor",                    "AutoRun",  "", "1" },
            };
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

        // офлайн-куст если смонтирован, иначе живой HKLM\SOFTWARE
        string SoftRoot() { return mounted.Contains("RS_SOFT") ? "HKLM\\RS_SOFT" : "HKLM\\SOFTWARE"; }
        bool IsOffline() { return mounted.Contains("RS_SOFT"); }

        void RepairRefresh()
        {
            lvRepair.Items.Clear();
            string root = SoftRoot();
            foreach (string[] a in Anchors())
            {
                string cur = "(нет значения)";
                foreach (string[] v in Reg.Values(root + "\\" + a[1]))
                    if (v[0].Equals(a[2], StringComparison.OrdinalIgnoreCase)) cur = v[1];
                string def = a[4] == "1" ? "(удалить значение)" : (a[3].Length == 0 ? "(пусто)" : a[3]);
                ListViewItem it = new ListViewItem(new string[] { a[0], cur, def });
                it.Tag = a;
                bool good = a[4] == "1" ? (cur == "(нет значения)") : string.Equals(cur.Trim(), a[3], StringComparison.OrdinalIgnoreCase);
                if (!good) it.BackColor = Color.FromArgb(255, 220, 220);
                lvRepair.Items.Add(it);
            }
        }

        void RepairSet(bool custom)
        {
            if (lvRepair.SelectedItems.Count == 0) { MessageBox.Show("Выбери строку в списке, потом жми «→ Дефолт» или «→ Своё…»."); return; }
            string root = SoftRoot();
            foreach (ListViewItem it in lvRepair.SelectedItems)
            {
                string[] a = (string[])it.Tag;
                string key = root + "\\" + a[1]; string o;
                if (custom)
                {
                    string val = Prompt("Своё значение для «" + a[0] + "»", a[3]);
                    if (val == null) continue;
                    Reg.RunCode("add \"" + key + "\" /v \"" + a[2] + "\" /t REG_SZ /d \"" + val + "\" /f", out o);
                }
                else
                {
                    if (a[4] == "1") Reg.RunCode("delete \"" + key + "\" /v \"" + a[2] + "\" /f", out o);
                    else Reg.RunCode("add \"" + key + "\" /v \"" + a[2] + "\" /t REG_SZ /d \"" + a[3] + "\" /f", out o);
                }
            }
            RepairRefresh();
            lblStatus.Text = IsOffline() ? "Ремонт применён к офлайн-кусту." : "Ремонт применён к ЖИВОЙ системе (HKLM\\SOFTWARE).";
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
                guarding = true;
                guardThread = new Thread(GuardLoop); guardThread.IsBackground = true; guardThread.Start();
                Watchdog.Log("guard: слежение за Winlogon (live) включено");
                lblStatus.Text = "Guard включён — Winlogon Shell/Userinit возвращаются к дефолту при подмене. Лог: " + Watchdog.LogPath;
            }
            else { guarding = false; Watchdog.Log("guard: слежение выключено"); }
        }

        void GuardLoop()
        {
            string wl = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
            string[][] want = { new string[] { "Shell", "explorer.exe" },
                                new string[] { "Userinit", "C:\\Windows\\system32\\userinit.exe," } };
            while (guarding)
            {
                foreach (string[] w in want)
                {
                    string cur = null;
                    foreach (string[] v in Reg.Values(wl))
                        if (v[0].Equals(w[0], StringComparison.OrdinalIgnoreCase)) cur = v[1];
                    if (cur != null && !string.Equals(cur.Trim(), w[1], StringComparison.OrdinalIgnoreCase))
                    {
                        string o; Reg.RunCode("add \"" + wl + "\" /v " + w[0] + " /t REG_SZ /d \"" + w[1] + "\" /f", out o);
                        Watchdog.Log("guard: Winlogon " + w[0] + " подменён на '" + cur + "' -> вернул '" + w[1] + "'");
                    }
                }
                for (int i = 0; i < 30 && guarding; i++) Thread.Sleep(100);
            }
        }

        void DeleteChecked(ListView target)
        {
            int n = 0; foreach (ListViewItem it in target.Items) if (it.Checked) n++;
            if (n == 0) { MessageBox.Show("Ничего не отмечено."); return; }
            if (MessageBox.Show("Удалить отмеченных записей: " + n + " ?\nОперация необратима.", "Подтверждение",
                MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;

            List<ListViewItem> done = new List<ListViewItem>();
            int ok = 0, fail = 0, skip = 0;
            foreach (ListViewItem it in target.Items)
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
            foreach (ListViewItem it in done) target.Items.Remove(it);
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
