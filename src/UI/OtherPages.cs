using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using static NSFShield.Theme;

namespace NSFShield
{
    sealed class LogPage : PageBase
    {
        public override string Key => "log";
        readonly RichTextBox box;
        readonly CheckX verbose, errorsOnly;

        public LogPage()
        {
            Header(Loc.T("logPage.title"), Loc.T("logPage.subtitle"));

            verbose = new CheckX { Text = Loc.T("logPage.verbose"), Bounds = R(28, 82, 170, 24), BackColor = Bg };
            errorsOnly = new CheckX { Text = Loc.T("logPage.errorsOnly"), Bounds = R(204, 82, 170, 24), BackColor = Bg };
            Controls.Add(verbose);
            Controls.Add(errorsOnly);
            verbose.CheckedChanged += (s, e) => Rebuild();
            errorsOnly.CheckedChanged += (s, e) => Rebuild();

            int x = 792;
            FlatBtn B(string t, string g, int w)
            {
                x -= w;
                var b = Btn(t, g, FlatBtn.Kinds.Secondary, x, 76, w, 36);
                x -= 8;
                return b;
            }
            var bFolder = B(Loc.T("logPage.folder"), GFolder, 96);
            var bSave = B(Loc.T("common.save"), GSave, 96);
            var bCopy = B(Loc.T("logPage.copy"), GCopy, 102);
            var bClear = B(Loc.T("logPage.clear"), GDelete, 102);

            box = new RichTextBox
            {
                Bounds = R(28, 124, 764, 500), ReadOnly = true, BorderStyle = BorderStyle.None,
                BackColor = LogBg, ForeColor = LogText, Font = Mono, DetectUrls = false, WordWrap = true,
            };
            Theme.StyleScroll(box);
            if (Lum(LogBg) < 0.4) box.HandleCreated += (s, e) => Native.ThemeWindow(box.Handle, "DarkMode_Explorer");
            Controls.Add(box);

            bClear.Click += (s, e) => { App.ClearLog(); box.Clear(); };
            // copied or saved log text goes through the shared privacy mask (the user's folder becomes %USERPROFILE%)
            bCopy.Click += (s, e) => { if (box.TextLength > 0) Clipboard.SetText(Privacy.MaskUser(box.Text)); };
            bSave.Click += (s, e) =>
            {
                using (var d = new SaveFileDialog { FileName = "nsfshield-log-" + DateTime.Now.ToString("yyyyMMdd-HHmm") + ".txt", Filter = Loc.T("logPage.txtFilter") })
                    if (d.ShowDialog(FindForm()) == DialogResult.OK) File.WriteAllText(d.FileName, Privacy.MaskUser(box.Text), Encoding.UTF8);
            };
            bFolder.Click += (s, e) => Sys.OpenFolder(App.DataDir);

            OnLog(Append);
            Rebuild();
        }

        static Color ColorOf(LogLevel l)
        {
            switch (l)
            {
                case LogLevel.Success: return LogGreen;
                case LogLevel.Warn: return LogAmber;
                case LogLevel.Error: return LogRed;
                case LogLevel.Debug: return LogMuted;
                case LogLevel.Output: return LogBlue;
                default: return LogText;
            }
        }

        void Rebuild()
        {
            box.Clear();
            var items = App.LogSnapshot();
            foreach (var e in items.Skip(Math.Max(0, items.Length - 1500))) Append(e);
        }

        void Append(LogEntry e)
        {
            if (e.Level == LogLevel.Debug && !verbose.Checked) return;
            if (errorsOnly.Checked && e.Level != LogLevel.Warn && e.Level != LogLevel.Error) return;
            if (box.TextLength > 300000)
            {
                box.Select(0, box.TextLength / 2);
                box.SelectedText = "";
            }
            box.SelectionStart = box.TextLength;
            box.SelectionLength = 0;
            box.SelectionColor = LogMuted;
            box.AppendText(e.Time.ToString("HH:mm:ss") + "  ");
            box.SelectionColor = ColorOf(e.Level);
            string prefix = e.Level == LogLevel.Output ? App.Engine.Current.ProcessName + " │ " : "";
            box.AppendText(prefix + e.Text + "\n");
            if (Visible) box.ScrollToCaret();
        }

        public override void OnActivated()
        {
            box.SelectionStart = box.TextLength;
            box.ScrollToCaret();
        }
    }

    sealed class SettingsPage : PageBase
    {
        public override string Key => "settings";
        readonly ScrollArea scroll;
        int y;
        Card cur;
        int curRows;
        readonly List<(ToggleRow Row, Func<bool> Get)> rows = new List<(ToggleRow, Func<bool>)>();
        ToggleRow rStartWin, rService;

        /// <summary>The page has its own scrolled area: it takes the page's height (the window may be shorter than the design).</summary>
        internal override void FitHost() => FillPage(scroll);

        public SettingsPage()
        {
            Header(Loc.T("settingsPage.title"), null);
            scroll = new ScrollArea { Bounds = R(0, 48, 820, 592) };
            Controls.Add(scroll);
            y = 4;

            // ------------------------------------------------ interface
            Caption(Loc.T("settingsPage.interface"));
            var lc = new Card { Bounds = R(28, y, 764, 180) };
            scroll.Controls.Add(lc);
            lc.Add(UIx.L(Loc.T("settingsPage.uiLevel"), Bold, Theme.Text, 20, 14, 300, 22));
            lc.Add(UIx.L(Loc.T("settingsPage.uiLevelInfo"),
                Small, Muted, 20, 36, 420, 40));
            var seg = lc.Add(new Segmented(Loc.T("uiLevel.Simple"), Loc.T("uiLevel.Standard"), Loc.T("uiLevel.Advanced")) { Bounds = R(456, 18, 288, 36) });
            seg.SetSilently((int)App.Settings.UiLevel);
            seg.SelectedChanged += (s, e) => UiLevelSwitch.Set((UiLevel)seg.SelectedIndex, this);
            var bLook = lc.Add(new FlatBtn { Text = Loc.T("settingsPage.colors"), Glyph = GColor, Kind = FlatBtn.Kinds.Ghost, Bounds = R(12, 78, 190, 32) });
            bLook.Click += (s, e) => MainForm.Instance.Navigate("appearance");
            lc.Add(UIx.L(Loc.T("settingsPage.themeLabel", Theme.Current?.Name ?? ""), Small, Muted, 210, 84, 530, 22));
            // the title stays bilingual on purpose, so the setting can be found in any language
            lc.Add(UIx.L("Language / Dil", Bold, Theme.Text, 20, 124, 300, 22));
            lc.Add(UIx.L(Loc.T("settingsPage.languageHint"), Small, Muted, 20, 146, 420, 22));
            var langs = Loc.Languages;
            var cLang = lc.Add(new ThemedCombo { Bounds = R(456, 128, 288, 26) });
            cLang.Items.Add(Loc.T("settingsPage.languageAuto"));
            foreach (var l in langs) cLang.Items.Add(l.Label);
            int li = -1;
            for (int k = 0; k < langs.Count; k++) if (langs[k].Code == App.Settings.Language) li = k;
            cLang.SelectedIndex = li + 1;
            cLang.SelectedIndexChanged += (s, e) =>
            {
                string code = cLang.SelectedIndex <= 0 ? Loc.Auto : langs[cLang.SelectedIndex - 1].Code;
                if (code == App.Settings.Language) return;
                App.Settings.Language = code;
                App.Save();
                App.Log("Language setting: " + code, LogLevel.Info);
                BeginInvoke(new Action(() => Loc.SetLanguage(code)));
            };
            y += 180 + 22;

            // ------------------------------------------------ startup
            bool offerSwitch = InstallerSwitch.Offered;
            Section(Loc.T("settingsPage.startup"), (Level(UiLevel.Standard) ? 3 : 2) + (offerSwitch ? 1 : 0));
            bool portable = InstallGuard.IsPortable;
            string onlyInstalled = Loc.T("settingsPage.onlyInstalled");
            rStartWin = Row(Loc.T("settingsPage.startWin"),
                portable ? onlyInstalled : Loc.T("settingsPage.startWinInfo"), () => App.Settings.StartWithWindows);
            Row(Loc.T("settingsPage.autoStart"), Loc.T("settingsPage.autoStartInfo"),
                () => App.Settings.AutoStartProtection, v => App.Settings.AutoStartProtection = v);
            if (Level(UiLevel.Standard))
                rService = Row(Loc.T("settingsPage.service"),
                    portable ? onlyInstalled : Loc.T("settingsPage.serviceInfo"), () => App.Settings.ServiceMode);
            if (offerSwitch)
                ActionRow(Loc.T("settingsPage.switchTitle"), Loc.T("settingsPage.switchInfo"), Loc.T("settingsPage.switchButton"),
                          () => SwitchDialog.Run(FindForm()));
            End();

            // ------------------------------------------------ window
            Section(Loc.T("settingsPage.windowSection"), 4);
            Row(Loc.T("settingsPage.closeToTray"), Loc.T("settingsPage.closeToTrayInfo"),
                () => App.Settings.CloseToTray, v => App.Settings.CloseToTray = v);
            Row(Loc.T("settingsPage.hideTaskbar"), Loc.T("settingsPage.hideTaskbarInfo"),
                () => App.Settings.HideFromTaskbar, v => { App.Settings.HideFromTaskbar = v; MainForm.Instance.ApplyTaskbarSetting(); });
            Row(Loc.T("settingsPage.notifications"), Loc.T("settingsPage.notificationsInfo"),
                () => App.Settings.Notifications, v => App.Settings.Notifications = v);
            Row(Loc.T("settingsPage.hotkey", MainForm.HotkeyText), Loc.T("settingsPage.hotkeyInfo", MainForm.HotkeyText),
                () => App.Settings.Hotkey, v => { App.Settings.Hotkey = v; MainForm.Instance.ApplyHotkey(); });
            End();

            // ------------------------------------------------ protection
            bool det = Level(UiLevel.Advanced);
            Section(Loc.T("settingsPage.protection"), Level(UiLevel.Standard) ? (det ? 7 : 6) : 3);
            Row(Loc.T("settingsPage.autoHeal"),
                Loc.T("settingsPage.autoHealInfo"),
                () => App.Settings.AutoHeal, v => App.Settings.AutoHeal = v);
            if (Level(UiLevel.Standard))
                SegRow(Loc.T("settingsPage.watchdog"), Loc.T("settingsPage.watchdogInfo"),
                    new[] { Loc.T("settingsPage.off"), Loc.T("settingsPage.minutes", 5), Loc.T("settingsPage.minutes", 15), Loc.T("settingsPage.minutes", 30) }, new[] { 0, 5, 15, 30 },
                    () => App.Settings.WatchMinutes, v => { App.Settings.WatchMinutes = v; MainForm.Instance.ApplyWatchSetting(); });
            Row(Loc.T("settingsPage.autoRestart"), Loc.T("settingsPage.autoRestartInfo"),
                () => App.Settings.AutoRestart, v => App.Settings.AutoRestart = v);
            Row(Loc.T("settingsPage.suggestDiscord"), Loc.T("settingsPage.suggestDiscordInfo"),
                () => App.Settings.SuggestDiscordRestart, v => App.Settings.SuggestDiscordRestart = v);
            if (Level(UiLevel.Standard))
            {
                Row(Loc.T("settingsPage.testAfterStart"), Loc.T("settingsPage.testAfterStartInfo"),
                    () => App.Settings.TestAfterStart, v => App.Settings.TestAfterStart = v);
                Row(Loc.T("settingsPage.flushDns"), Loc.T("settingsPage.flushDnsInfo"),
                    () => App.Settings.FlushDns, v => App.Settings.FlushDns = v);
            }
            if (det)
                Row(Loc.T("settingsPage.verifyDns"), Loc.T("settingsPage.verifyDnsInfo"),
                    () => App.Settings.CheckDnsOnStart, v => App.Settings.CheckDnsOnStart = v);
            End();

            // ------------------------------------------------ ByeDPI (driverless proxy engine)
            if (Level(UiLevel.Standard))
            {
                Section(Loc.T("settingsPage.byedpiSection"), 2);
                Row(Loc.T("settingsPage.byedpiSystemProxy"), Loc.T("settingsPage.byedpiSystemProxyInfo"),
                    () => App.Settings.ByeDpiSystemProxy, v =>
                    {
                        App.Settings.ByeDpiSystemProxy = v;
                        if (App.Engine.IsActive && App.Engine.Current.Kind == EngineKind.ByeDpi) _ = Actions.StartAsync();
                    });
                NumRow(Loc.T("settingsPage.byedpiPort"), Loc.T("settingsPage.byedpiPortInfo"), 1024, 65000,
                    () => App.Settings.ByeDpiPort, v => App.Settings.ByeDpiPort = v);
                End();
            }

            // ------------------------------------------------ repair
            Caption(Loc.T("settingsPage.repairSection"));
            var c4 = new Card { Bounds = R(28, y, 764, 206) };
            scroll.Controls.Add(c4);
            y += 206 + 22;
            c4.Add(UIx.L(Loc.T("settingsPage.repairInfo"),
                Small, Muted, 20, 14, 724, 40));
            var bFlush = c4.Add(new FlatBtn { Text = Loc.T("settingsPage.flushBtn"), Glyph = GRefresh, Kind = FlatBtn.Kinds.Secondary, Bounds = R(20, 62, 228, 38) });
            var bKill = c4.Add(new FlatBtn { Text = Loc.T("settingsPage.conflicts"), Glyph = GWrench, Kind = FlatBtn.Kinds.Secondary, Bounds = R(258, 62, 228, 38) });
            var bReset = c4.Add(new FlatBtn { Text = Loc.T("settingsPage.resetAll"), Glyph = GDelete, Kind = FlatBtn.Kinds.Danger, Bounds = R(496, 62, 228, 38) });
            var bClean = c4.Add(new FlatBtn { Text = Loc.T("settingsPage.cleanUninstall"), Glyph = GDelete, Kind = FlatBtn.Kinds.Danger, Bounds = R(20, 110, 228, 38) });
            c4.Add(UIx.L(Loc.T("settingsPage.cleanInfo"),
                Small, Muted, 258, 110, 486, 40));
            var info = c4.Add(UIx.L("", Small, Muted, 20, 158, 724, 40));
            bClean.Click += async (s, e) =>
            {
                if (MessageBox.Show(FindForm(),
                        Loc.T("settingsPage.cleanConfirm"),
                        App.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
                bClean.Enabled = false;
                string rep = await Task.Run(() => Uninstaller.Run());
                if (IsDisposed) return;
                LoadValues();
                bClean.Enabled = true;
                info.Text = Loc.T("settingsPage.cleanDone");
                if (MessageBox.Show(FindForm(), Loc.T("settingsPage.cleanReverted", rep),
                        App.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Information) == DialogResult.Yes)
                    MainForm.Instance.ExitApp(false);
            };
            bFlush.Click += async (s, e) => info.Text = await Fixes.Run(FixKind.FlushDns, FindForm());
            bKill.Click += async (s, e) => { bKill.Enabled = false; info.Text = await Fixes.Run(FixKind.ResolveConflicts, FindForm()); bKill.Enabled = true; };
            bReset.Click += async (s, e) =>
            {
                bReset.Enabled = false;
                string m = await Fixes.Run(FixKind.ResetAll, FindForm());
                if (IsDisposed) return;
                if (m != null) info.Text = m;
                LoadValues();
                bReset.Enabled = true;
            };

            // ------------------------------------------------ updates
            Caption(Loc.T("settingsPage.updates"));
            var cu = new Card { Bounds = R(28, y, 764, 124) };
            scroll.Controls.Add(cu);
            y += 124 + 22;
            var rUpd = new ToggleRow(Loc.T("settingsPage.autoUpdate"),
                Loc.T("settingsPage.autoUpdateInfo"),
                D(744)) { Location = new Point(D(10), D(6)), Divider = false };
            cu.Add(rUpd);
            rUpd.Switch.SetSilently(App.Settings.AutoUpdate);
            rUpd.Switch.CheckedChanged += (s, e) => { App.Settings.AutoUpdate = rUpd.Switch.Checked; App.Save(); };
            var bCheck = cu.Add(new FlatBtn { Text = Loc.T("settingsPage.checkNow"), Glyph = GRefresh, Kind = FlatBtn.Kinds.Secondary, Bounds = R(30, 74, 170, 36) });
            var updInfo = cu.Add(UIx.L("", Small, Muted, 212, 74, 530, 36, ContentAlignment.MiddleLeft));
            Action showUpd = () =>
            {
                var last = App.Settings.LastUpdateCheck;
                updInfo.Text = Loc.T("settingsPage.updInfo", App.Version, last.HasValue ? last.Value.ToString("dd.MM.yyyy HH:mm") : Loc.T("settingsPage.never")) + (Updater.Available != null ? " · " + Loc.T("settingsPage.updReady", Updater.Available.Version) : "");
                updInfo.ForeColor = Updater.Available != null ? AccentInk : Muted;
            };
            showUpd();
            bCheck.Click += async (s, e) =>
            {
                bCheck.Enabled = false;
                await UpdateDialog.CheckAndShow(FindForm(), manual: true);
                if (IsDisposed) return;
                bCheck.Enabled = true;
                showUpd();
            };

            // ------------------------------------------------ backup
            if (Level(UiLevel.Standard))
            {
                Caption(Loc.T("settingsPage.backup"));
                var cb = new Card { Bounds = R(28, y, 764, 110) };
                scroll.Controls.Add(cb);
                y += 110 + 22;
                cb.Add(UIx.L(Loc.T("settingsPage.backupInfo"), Small, Muted, 20, 12, 724, 34));
                var bExp = cb.Add(new FlatBtn { Text = Loc.T("settingsPage.export"), Glyph = GSave, Kind = FlatBtn.Kinds.Secondary, Bounds = R(20, 54, 228, 38) });
                var bImp = cb.Add(new FlatBtn { Text = Loc.T("settingsPage.import"), Glyph = GFolder, Kind = FlatBtn.Kinds.Secondary, Bounds = R(258, 54, 228, 38) });
                bExp.Click += (s, e) =>
                {
                    using (var d = new SaveFileDialog { FileName = "NSF-Shield-settings-" + DateTime.Now.ToString("yyyyMMdd") + ".xml", Filter = Loc.T("settingsPage.xmlFilter") })
                    {
                        if (d.ShowDialog(FindForm()) != DialogResult.OK) return;
                        try { SettingsStore.Export(App.Settings, d.FileName); App.Log("Settings exported: " + d.FileName, LogLevel.Success); }
                        catch (Exception ex) { MessageBox.Show(FindForm(), Loc.T("common.saveFailed") + " " + ex.Message, App.Name); }
                    }
                };
                bImp.Click += async (s, e) =>
                {
                    using (var d = new OpenFileDialog { Filter = Loc.T("settingsPage.xmlFilter") })
                    {
                        if (d.ShowDialog(FindForm()) != DialogResult.OK) return;
                        AppSettings imported;
                        try { imported = SettingsStore.Import(d.FileName); }
                        catch (Exception ex) { MessageBox.Show(FindForm(), Loc.T("settingsPage.readFailed", ex.Message), App.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
                        if (MessageBox.Show(FindForm(), Loc.T("settingsPage.importConfirm"), App.Name,
                                MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
                        bool wasActive = App.Engine.IsActive;
                        // states specific to this computer are kept
                        imported.DnsBackups = App.Settings.DnsBackups;
                        imported.DohBackups = App.Settings.DohBackups;
                        imported.GlobalDohBackup = App.Settings.GlobalDohBackup;
                        imported.SystemProxyId = App.Settings.SystemProxyId;
                        imported.ServiceMode = App.Settings.ServiceMode;
                        imported.StartWithWindows = App.Settings.StartWithWindows;
                        App.Settings = imported;
                        App.Save();
                        App.Log("Settings imported: " + d.FileName, LogLevel.Success);
                        ProxyBridge.StopAll();
                        ProxyBridge.Sync();
                        MainForm.Instance.ApplyHotkey();
                        MainForm.Instance.ApplyWatchSetting();
                        MainForm.Instance.ApplyTheme();
                        if (wasActive) await Actions.StartAsync();
                    }
                };
            }

            // ------------------------------------------------ advanced
            if (det)
            {
                Caption(Loc.T("settingsPage.advanced"));
                var c5 = new Card { Bounds = R(28, y, 764, 110) };
                scroll.Controls.Add(c5);
                y += 110 + 22;
                c5.Add(UIx.L(Loc.T("settingsPage.exportInfo"), Small, Muted, 20, 14, 724, 22));
                var bExport = c5.Add(new FlatBtn { Text = Loc.T("settingsPage.exportScripts"), Glyph = GSave, Kind = FlatBtn.Kinds.Secondary, Bounds = R(20, 46, 228, 38) });
                var bData = c5.Add(new FlatBtn { Text = Loc.T("settingsPage.openData"), Glyph = GFolder, Kind = FlatBtn.Kinds.Secondary, Bounds = R(258, 46, 228, 38) });
                bData.Click += (s, e) => Sys.OpenFolder(App.DataDir);
                bExport.Click += (s, e) =>
                {
                    using (var d = new FolderBrowserDialog { Description = Loc.T("settingsPage.chooseFolder") })
                    {
                        if (d.ShowDialog(FindForm()) != DialogResult.OK) return;
                        try
                        {
                            string dir = Path.Combine(d.SelectedPath, "NSF Shield scripts");
                            Directory.CreateDirectory(dir);
                            string binRoot = Path.GetDirectoryName(Engine.BinDir);
                            int i = 0, skipped = 0;
                            foreach (var p in App.AllProfiles.Where(x => x.IsGoodbyeDpi).OrderBy(x => x.Priority))
                            {
                                try { Scripts.Write(p, Path.Combine(dir, (i + 1).ToString("00") + "_" + Scripts.Slug(p.Name) + ".cmd"), binRoot); i++; }
                                catch (InvalidDataException ex) { skipped++; App.Log(ex.Message, LogLevel.Warn); }
                            }
                            Sys.OpenFolder(dir);
                            App.Log(i + " scripts exported: " + dir + (skipped > 0 ? " (" + skipped + " profiles skipped because they are not safe)" : ""), LogLevel.Success);
                        }
                        catch (Exception ex) { MessageBox.Show(FindForm(), Loc.T("settingsPage.exportFailed", ex.Message), App.Name); }
                    }
                };
            }

            scroll.Controls.Add(new Panel { Bounds = R(0, y, 10, 10), BackColor = Bg });
            WireSpecial();
            LoadValues();
        }

        void Caption(string t)
        {
            scroll.Controls.Add(UIx.L(t, Theme.Caption, Muted, 30, y, 300, 20));
            y += 24;
        }

        void Section(string title, int count)
        {
            Caption(title);
            cur = new Card { Bounds = R(28, y, 764, 64 * count + 12) };
            scroll.Controls.Add(cur);
            curRows = 0;
            y += 64 * count + 12 + 22;
        }

        void End() { }

        /// <summary>Title + description + option group row.</summary>
        void SegRow(string title, string desc, string[] items, int[] values, Func<int> get, Action<int> set)
        {
            var row = new Panel { Bounds = new Rectangle(D(10), D(6 + 64 * curRows), D(744), D(64)), BackColor = Theme.Card };
            row.Controls.Add(new Label { Text = title, Font = Bold, ForeColor = Theme.Text, BackColor = Theme.Card, AutoSize = false, UseMnemonic = false,
                Bounds = new Rectangle(D(20), D(10), D(440), D(22)) });
            row.Controls.Add(new Label { Text = desc, Font = Small, ForeColor = Muted, BackColor = Theme.Card, AutoSize = false, UseMnemonic = false,
                Bounds = new Rectangle(D(20), D(31), D(440), D(32)) });
            var seg = new Segmented(items) { Bounds = new Rectangle(D(470), D(14), D(258), D(34)), BackColor = Theme.Card, Font = Small };
            int idx = Array.IndexOf(values, get());
            seg.SetSilently(idx < 0 ? 0 : idx);
            seg.SelectedChanged += (s, e) => { set(values[seg.SelectedIndex]); App.Save(); };
            row.Controls.Add(seg);
            row.Paint += (s, e) => { using (var pen = new Pen(Theme.Divider)) e.Graphics.DrawLine(pen, D(20), row.Height - 1, row.Width - D(20), row.Height - 1); };
            cur.Controls.Add(row);
            curRows++;
        }

        /// <summary>Title + description + button row.</summary>
        void ActionRow(string title, string desc, string button, Action click)
        {
            var row = new Panel { Bounds = new Rectangle(D(10), D(6 + 64 * curRows), D(744), D(64)), BackColor = Theme.Card };
            row.Controls.Add(new Label { Text = title, Font = Bold, ForeColor = Theme.Text, BackColor = Theme.Card, AutoSize = false, UseMnemonic = false,
                Bounds = new Rectangle(D(20), D(10), D(480), D(22)) });
            int bw = Math.Min(218, Math.Max(120, (int)(TextRenderer.MeasureText(button, Bold).Width / Theme.Scale) + 64));
            row.Controls.Add(new Label { Text = desc, Font = Small, ForeColor = Muted, BackColor = Theme.Card, AutoSize = false, UseMnemonic = false,
                Bounds = new Rectangle(D(20), D(31), D(728 - bw - 36), D(32)) });
            var b = new FlatBtn { Text = button, Glyph = GShield, Kind = FlatBtn.Kinds.Primary, BackColor = Theme.Card, Bounds = new Rectangle(D(728 - bw), D(13), D(bw), D(38)) };
            b.Click += (s, e) => click();
            row.Controls.Add(b);
            cur.Controls.Add(row);
            curRows++;
        }

        /// <summary>Title + description + number box (saved when it changes; used at the next start).</summary>
        void NumRow(string title, string desc, int min, int max, Func<int> get, Action<int> set)
        {
            var row = new Panel { Bounds = new Rectangle(D(10), D(6 + 64 * curRows), D(744), D(64)), BackColor = Theme.Card };
            row.Controls.Add(new Label { Text = title, Font = Bold, ForeColor = Theme.Text, BackColor = Theme.Card, AutoSize = false, UseMnemonic = false,
                Bounds = new Rectangle(D(20), D(10), D(560), D(22)) });
            row.Controls.Add(new Label { Text = desc, Font = Small, ForeColor = Muted, BackColor = Theme.Card, AutoSize = false, UseMnemonic = false,
                Bounds = new Rectangle(D(20), D(31), D(560), D(32)) });
            var num = Theme.Style(new NumericUpDown { Minimum = min, Maximum = max, Value = Math.Max(min, Math.Min(max, get())), Bounds = new Rectangle(D(608), D(18), D(120), D(28)), Font = Body });
            num.ValueChanged += (s, e) => { set((int)num.Value); App.Save(); };
            row.Controls.Add(num);
            row.Paint += (s, e) => { using (var pen = new Pen(Theme.Divider)) e.Graphics.DrawLine(pen, D(20), row.Height - 1, row.Width - D(20), row.Height - 1); };
            cur.Controls.Add(row);
            curRows++;
        }

        ToggleRow Row(string title, string desc, Func<bool> get, Action<bool> set = null)
        {
            var r = new ToggleRow(title, desc, D(744)) { Location = new Point(D(10), D(6 + 64 * curRows)) };
            cur.Add(r);
            curRows++;
            r.Divider = true;
            rows.Add((r, get));
            if (set != null)
                r.Switch.CheckedChanged += (s, e) => { set(r.Switch.Checked); App.Save(); App.RaiseStatus(); };
            return r;
        }

        void LoadValues()
        {
            foreach (var (r, get) in rows) r.Switch.SetSilently(get());
        }

        public override void OnActivated() => LoadValues();

        void WireSpecial()
        {
            rStartWin.Switch.CheckedChanged += async (s, e) =>
            {
                bool want = rStartWin.Switch.Checked;
                if (want && InstallGuard.IsPortable)
                {
                    MessageBox.Show(FindForm(), InstallGuard.NeedInstall + "\n\n" + Loc.T("settingsPage.detail") + " " + InstallGuard.Reason, App.Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
                    rStartWin.Switch.SetSilently(false);
                    return;
                }
                if (want && App.RunningFromTemp)
                {
                    MessageBox.Show(FindForm(), Loc.T("settingsPage.tempFolder"),
                        App.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    rStartWin.Switch.SetSilently(false);
                    return;
                }
                rStartWin.Switch.Enabled = false;
                string err = null;
                bool ok = await Task.Run(() =>
                {
                    if (want) return Startup.Enable(out err);
                    Startup.Disable();
                    return true;
                });
                if (IsDisposed) return;
                rStartWin.Switch.Enabled = true;
                if (!ok)
                {
                    rStartWin.Switch.SetSilently(false);
                    App.Problems.Report("NSF-703", err);
                    MessageBox.Show(FindForm(), Loc.T("settingsPage.taskFailed") + "\n" + err, App.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
                App.Problems.Clear("NSF-703");
                App.Settings.StartWithWindows = want;
                App.Save();
            };

            if (rService == null) return;
            rService.Switch.CheckedChanged += async (s, e) =>
            {
                bool want = rService.Switch.Checked;
                if (want && InstallGuard.IsPortable)
                {
                    MessageBox.Show(FindForm(), InstallGuard.NeedInstall + "\n\n" + Loc.T("settingsPage.detail") + " " + InstallGuard.Reason, App.Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
                    rService.Switch.SetSilently(false);
                    return;
                }
                if (want && MessageBox.Show(FindForm(),
                        Loc.T("settingsPage.serviceConfirm"),
                        App.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                {
                    rService.Switch.SetSilently(false);
                    return;
                }
                rService.Switch.Enabled = false;
                bool wasActive = App.Engine.IsActive;
                App.Settings.ServiceMode = want;
                App.Save();
                if (want)
                {
                    await Actions.StartAsync();
                    if (App.Engine.State != EngineState.Running)
                    {
                        App.Settings.ServiceMode = false;
                        App.Save();
                        await Task.Run(() => App.Engine.UninstallService());
                        rService.Switch.SetSilently(false);
                        MessageBox.Show(FindForm(), Loc.T("settingsPage.serviceFailed") + "\n\n" + App.Engine.LastErrorCode + " " + App.Engine.LastError,
                            App.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        if (wasActive) await Actions.StartAsync();
                    }
                }
                else
                {
                    await Task.Run(() => App.Engine.UninstallService());
                    if (wasActive) await Actions.StartAsync();
                }
                if (IsDisposed) return;
                rService.Switch.Enabled = true;
                App.RaiseStatus();
            };
        }
    }

    sealed class AboutPage : PageBase
    {
        public override string Key => "about";

        public AboutPage()
        {
            Header(Loc.T("aboutPage.title"), null);
            var c = AddCard(28, 52, 764, 226);
            var logo = new PictureBox { Bounds = R(28, 28, 96, 96), Image = IconArt.AppBitmap(D(96)), SizeMode = PictureBoxSizeMode.Zoom };
            c.Add(logo);
            c.Add(UIx.L(App.Title, Hero, Theme.Text, 146, 24, 594, 44));
            c.Add(UIx.L(Loc.T("aboutPage.version", App.Version) + "  ·  GoodbyeDPI 0.2.3rc3  ·  WinDivert 2.2", Body, Muted, 149, 70, 560, 22));
            c.Add(UIx.L(Loc.T("aboutPage.intro"),
                Body, Theme.Text, 149, 96, 590, 64));
            int bx = 146;
            FlatBtn B(string t, string g, int w, Action a)
            {
                var b = c.Add(new FlatBtn { Text = t, Glyph = g, Kind = FlatBtn.Kinds.Secondary, Bounds = R(bx, 170, w, 36) });
                b.Click += (s, e) => a();
                bx += w + 8;
                return b;
            }
            B(Loc.T("aboutPage.guide"), GHelp, 156, () =>
            {
                // a fixed entry page for the UI language (Explorer gets a plain file path, opened as the normal user)
                string guide = Guide.EntryFor(App.BaseDir, Loc.Current);
                if (guide != null) Sys.OpenAsUser(guide); else MainForm.Instance.Navigate("trouble");
            });
            B(Loc.T("aboutPage.project"), GLink, 140, () => Sys.OpenAsUser(App.RepoUrl));
            B(Loc.T("aboutPage.scripts"), GFolder, 140, () =>
            {
                string dir = Path.Combine(App.BaseDir, "scripts");
                Sys.OpenFolder(Directory.Exists(dir) ? dir : App.BaseDir);
            });
            B(Loc.T("aboutPage.licenses"), GInfo, 118, () =>
            {
                string dir = Path.Combine(App.BaseDir, "licenses");
                Sys.OpenFolder(Directory.Exists(dir) ? dir : App.BaseDir);
            });

            var c2 = AddCard(28, 292, 764, 336);
            var r = c2.Add(new ReportBox { Bounds = R(20, 14, 724, 310) });
            r.BackColor = Theme.Card;
            foreach (var (ver, n) in new[] { ("1.0.1", 1), ("1.0", 6) })
            {
                r.Out(Loc.T("aboutPage.whatsNew", ver), Muted, Theme.Caption);
                for (int k = 1; k <= n; k++)
                    r.Out("•  " + Loc.T("aboutPage.new." + ver.Replace(".", "") + "." + k, MainForm.HotkeyText, Profiles.BuiltIns.Count,
                        DnsProviders.All.Count, ErrorCatalog.Categories.Length, ErrorCatalog.All.Count, Palettes.Presets.Count + 1), Theme.Text, Small);
            }
            r.Blank();
            r.Out(Loc.T("aboutPage.howTitle"), Muted, Theme.Caption);
            r.Out(Loc.T("aboutPage.how"),
                Theme.Text, Small);
            r.Blank();
            r.Out(Loc.T("aboutPage.antivirus"), Theme.Text, Small);
            r.Blank();
            r.Out(Loc.T("aboutPage.license"), Muted, Theme.Caption);
            r.Out("NSF Shield · " + App.Copyright + " · " + Loc.T("aboutPage.mit"), Theme.Text, Small);
            r.Out(Loc.T("aboutPage.thirdParty"), Theme.Text, Small);
            r.Out(Loc.T("aboutPage.thirdPartyEngines"), Theme.Text, Small);
            r.Blank();
            r.Out(Loc.T("aboutPage.thanks"), Muted, Small);
            r.Out(Loc.T("aboutPage.thanksEngines"), Muted, Small);
            r.SelectionStart = 0;
        }
    }
}
