using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;
using static NSFShield.Theme;

namespace NSFShield
{
    sealed class MainForm : Form
    {
        public static MainForm Instance;

        Panel sidebar, topbar, host, navArea;
        readonly List<NavItem> navs = new List<NavItem>();
        readonly Dictionary<string, PageBase> pages = new Dictionary<string, PageBase>();
        SideStatus sideStatus;
        PageBase current;
        readonly ToolTip tips = new ToolTip();

        readonly NotifyIcon tray;
        ContextMenuStrip trayMenu;
        ToolStripMenuItem miStatus, miToggle, miProfiles, miTest, miScan, miDiscord, miUpdate, miOpen, miExit;
        readonly Dictionary<TrayStatus, Icon> trayIcons = new Dictionary<TrayStatus, Icon>();
        readonly Timer pollTimer = new Timer { Interval = 3000 };
        readonly Timer themeTimer = new Timer { Interval = 600 };
        readonly Timer watchTimer = new Timer();
        readonly Timer netChangeTimer = new Timer { Interval = NetChangeFlow.QuietMs };
        NetWatchHost netWatch;
        /// <summary>The network events the window subscribes to (null: the system's; PREVIEW never uses the real ones).</summary>
        internal static INetEvents NetEventsOverride = null;
        internal NetWatchHost NetWatch => netWatch;
        readonly Timer updateTimer = new Timer { Interval = 45000 };   // first check 45 s after start
        bool exiting;

        [System.Runtime.InteropServices.DllImport("user32.dll")] static extern bool RegisterHotKey(IntPtr h, int id, uint mods, uint vk);
        [System.Runtime.InteropServices.DllImport("user32.dll")] static extern bool UnregisterHotKey(IntPtr h, int id);
        const int WM_HOTKEY = 0x0312, HotkeyId = 0x4B44;
        public const string HotkeyText = "Ctrl+Alt+K";

        /// <summary>Pages in the sidebar (Title is a locale key) and the UI level they appear at.</summary>
        static readonly (string Key, string Title, string Glyph, UiLevel Min)[] NavDefs =
        {
            ("home", "nav.home", GHome, UiLevel.Simple),
            ("profiles", "nav.profiles", GProfiles, UiLevel.Simple),   // Simple: a plain list of the recommended profiles
            ("net", "nav.net", GNetwork, UiLevel.Standard),
            ("dns", "nav.dns", GGlobe, UiLevel.Standard),
            ("sites", "nav.sites", GList, UiLevel.Standard),
            ("proxy", "nav.proxy", GLink, UiLevel.Standard),
            ("trouble", "nav.trouble", GHelp, UiLevel.Simple),
            ("log", "nav.log", GLog, UiLevel.Advanced),
            ("appearance", "nav.appearance", GColor, UiLevel.Simple),
            ("settings", "nav.settings", GSettings, UiLevel.Simple),
            ("about", "nav.about", GInfo, UiLevel.Simple),
        };

        /// <summary>Test hook: the work area the window must fit into (null: the work area of the screen the window is on).</summary>
        internal static Func<Rectangle> WorkAreaOverride = null;

        internal static Rectangle WorkAreaFor(Form f) =>
            WorkAreaOverride?.Invoke() ?? (f != null && f.IsHandleCreated ? Screen.FromHandle(f.Handle) : Screen.FromPoint(Cursor.Position)).WorkingArea;

        /// <summary>The design size (1040 x 680 at 100 %), never larger than the usable work area (without the taskbar) at this DPI.</summary>
        internal static Size FitSize(Rectangle work) => new Size(Math.Min(D(1040), work.Width), Math.Min(D(680), work.Height));

        public MainForm()
        {
            Instance = this;
            Text = App.Name;
            FormBorderStyle = FormBorderStyle.None;
            StartPosition = FormStartPosition.CenterScreen;
            AutoScaleMode = AutoScaleMode.None;
            ClientSize = FitSize(WorkAreaFor(null));
            Font = Body;
            ShowInTaskbar = !App.Settings.HideFromTaskbar;
            Icon = IconArt.AppIcon(32);
            DoubleBuffered = true;
            KeyPreview = true;

            BuildChrome();

            // --- tray
            trayMenu = BuildTrayMenu();
            tray = new NotifyIcon { ContextMenuStrip = trayMenu, Visible = !App.Preview, Text = App.Name };
            tray.MouseClick += (s, e) => { if (e.Button == MouseButtons.Left) ShowFromTray(); };
            tray.BalloonTipClicked += (s, e) => ShowFromTray();

            App.Engine.StateChanged += OnEngineStateChanged;
            App.StatusChanged += RefreshChrome;
            pollTimer.Tick += (s, e) => Task.Run(() => App.Engine.Poll());
            pollTimer.Start();

            // With the system theme or "follow Windows", follow Windows light/dark and accent color changes
            themeTimer.Tick += (s, e) => { themeTimer.Stop(); if (FollowsWindows) ApplyThemeIfChanged(); };
            SystemEvents.UserPreferenceChanged += OnUserPreferenceChanged;
            // a smaller screen, a moved taskbar or another resolution: the window fits the work area again
            SystemEvents.DisplaySettingsChanged += OnDisplaySettingsChanged;

            // Connection watchdog: the periodic test the user turned on (a network event no longer starts a test or a repair)
            watchTimer.Tick += async (s, e) => await Actions.WatchCheckAsync("periodic check");
            ApplyWatchSetting();
            // Network changes: one watcher for both events, joined for 2.5 s, read in the background, shown read-only
            var events = NetEventsOverride ?? (App.Preview ? new RecordingNetEvents() : (INetEvents)new SystemNetEvents());
            netWatch = new NetWatchHost(events, new FormsDebounce(netChangeTimer), () => NetStateReader.Read(true), PostUi, () => ScanGate.Busy, OnNetStateChanged);
            if (!App.Preview) netWatch.Flow.Prime();

            Loc.Changed += OnLanguageChanged;

            Navigate("home");
            RefreshChrome();
        }

        /// <summary>Live language switch: rebuilds every page, the window chrome and the tray menu in the new language.</summary>
        void OnLanguageChanged()
        {
            if (IsDisposed) return;
            if (InvokeRequired) { BeginInvoke(new Action(OnLanguageChanged)); return; }
            var old = trayMenu;
            trayMenu = BuildTrayMenu();
            tray.ContextMenuStrip = trayMenu;
            old.Dispose();
            Rebuild();
        }

        /// <summary>Runs on the UI thread; nothing once the window is closing or gone (a late network read is dropped).</summary>
        void PostUi(Action a)
        {
            if (exiting || IsDisposed || Disposing || !IsHandleCreated) return;
            try { BeginInvoke(new Action(() => { if (!IsDisposed) a(); })); } catch (InvalidOperationException) { }
        }

        /// <summary>A new network state (not the first picture, not a repeat): status refresh and, if notifications are on, a note.</summary>
        void OnNetStateChanged(NetState old, NetState now)
        {
            if (IsDisposed) return;
            App.Log("Network changed: " + (now.AdapterName ?? (now.Online ? "several adapters" : "offline")) + ", DNS " + (now.DnsChoice ?? "?"), LogLevel.Debug);
            App.RaiseStatus();
            var (title, text) = NetNotice(now);
            ShowBalloon(title, text, ToolTipIcon.Info);
        }

        /// <summary>Text of the network change note (also shown in the preview).</summary>
        internal static (string Title, string Text) NetNotice(NetState now) =>
            (Loc.T("main.netChanged.title"),
             !now.Online ? Loc.T("main.netChanged.offline") : Loc.T("main.netChanged.text", now.AdapterName ?? Loc.T("main.netChanged.severalAdapters"), SystemDns.StatusLabel(now)));

        /// <summary>The watchdog interval in milliseconds, clamped to 0 (off) … 24 h before the conversion (never an overflow).</summary>
        internal static int WatchIntervalMs(int minutes) => Math.Max(0, Math.Min(minutes, AppSettings.MaxWatchMinutes)) * 60 * 1000;

        public void ApplyWatchSetting()
        {
            watchTimer.Stop();
            int m = WatchIntervalMs(App.Settings.WatchMinutes);
            if (m > 0 && !App.Preview)
            {
                watchTimer.Interval = m;
                watchTimer.Start();
            }
        }

        public void ApplyHotkey()
        {
            if (!IsHandleCreated || App.Preview) return;
            UnregisterHotKey(Handle, HotkeyId);
            if (!App.Settings.Hotkey) return;
            // MOD_ALT | MOD_CONTROL | MOD_NOREPEAT
            if (!RegisterHotKey(Handle, HotkeyId, 0x0001 | 0x0002 | 0x4000, (uint)Keys.K))
                App.Log(HotkeyText + " hotkey is used by another program; it could not be registered.", LogLevel.Warn);
        }

        protected override void WndProc(ref Message m)
        {
            if (m.Msg == WM_HOTKEY && m.WParam.ToInt32() == HotkeyId)
            {
                bool wasActive = App.Engine.IsActive;
                _ = Actions.ToggleAsync();
                ShowBalloon(App.Name, wasActive ? Loc.T("main.hotkeyStopping", HotkeyText) : Loc.T("main.hotkeyStarting", HotkeyText), ToolTipIcon.Info, force: true);
                return;
            }
            base.WndProc(ref m);
        }

        void OnDisplaySettingsChanged(object sender, EventArgs e)
        {
            try { if (IsHandleCreated && !IsDisposed) BeginInvoke(new Action(FitToWorkArea)); } catch (InvalidOperationException) { }
        }

        /// <summary>Fits the window into the work area of its screen (the chrome and the pages follow the client size).</summary>
        internal void FitToWorkArea()
        {
            if (IsDisposed) return;
            var wa = WorkAreaFor(this);
            var size = FitSize(wa);
            if (ClientSize != size) ClientSize = size;
            if (Visible)
                Location = new Point(Math.Max(wa.Left, Math.Min(Left, wa.Right - Width)), Math.Max(wa.Top, Math.Min(Top, wa.Bottom - Height)));
        }

        void OnUserPreferenceChanged(object sender, UserPreferenceChangedEventArgs e)
        {
            if (!FollowsWindows) return;
            if (e.Category != UserPreferenceCategory.General && e.Category != UserPreferenceCategory.Color && e.Category != UserPreferenceCategory.VisualStyle) return;
            try { BeginInvoke(new Action(() => { themeTimer.Stop(); themeTimer.Start(); })); } catch { }
        }

        // ---------------------------------------------------------------- UI skeleton

        void BuildChrome()
        {
            SuspendLayout();
            BackColor = Bg;

            // the chrome follows the client size (anchors): the window may be smaller than the design size on a small work area
            sidebar = new Panel { Bounds = new Rectangle(0, 0, D(220), ClientSize.Height), BackColor = Sidebar, Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left };
            var logo = new LogoPanel { Bounds = new Rectangle(0, 0, D(220), D(84)) };
            logo.MouseDown += DragMouseDown;
            sidebar.Controls.Add(logo);

            // the menu scrolls when the window is too short for it (the status box below it is left out first)
            navArea = new Panel { Bounds = new Rectangle(0, D(84), D(220), Math.Max(D(40), ClientSize.Height - D(84))), BackColor = Sidebar, AutoScroll = true };
            if (SidebarIsDark) Theme.StyleScroll(navArea);
            sidebar.Controls.Add(navArea);
            navs.Clear();
            int y = D(8);
            foreach (var (key, title, glyph, min) in NavDefs)
            {
                if (App.Settings.UiLevel < min) continue;
                var n = new NavItem { Key = key, Text = Loc.T(title), Glyph = glyph, Bounds = new Rectangle(0, y, D(220), D(40)),
                                      Dot = key == "appearance" && AppearancePage.HasUnappliedColors };
                n.Click += (s, e) => Navigate(((NavItem)s).Key);
                navs.Add(n);
                navArea.Controls.Add(n);
                y += D(42);
            }
            sideStatus = new SideStatus { Bounds = new Rectangle(D(12), ClientSize.Height - D(84), D(196), D(70)) };
            sideStatus.Click += (s, e) => Navigate("home");
            sidebar.Controls.Add(sideStatus);
            sidebar.Resize += (s, e) => LayoutSidebar();
            LayoutSidebar();

            topbar = new Panel { Bounds = new Rectangle(D(220), 0, ClientSize.Width - D(220), D(40)), BackColor = Bg, Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right };
            topbar.MouseDown += DragMouseDown;
            var bClose = new ChromeBtn(GClose, true) { Bounds = new Rectangle(topbar.Width - D(46), 0, D(46), D(34)), Anchor = AnchorStyles.Top | AnchorStyles.Right };
            var bMin = new ChromeBtn(GMin, false) { Bounds = new Rectangle(topbar.Width - D(92), 0, D(46), D(34)), Anchor = AnchorStyles.Top | AnchorStyles.Right };
            bClose.Click += (s, e) => Close();
            bMin.Click += (s, e) => HideToTray();
            tips.SetToolTip(bMin, Loc.T("main.minimize"));
            tips.SetToolTip(bClose, App.Settings.CloseToTray ? Loc.T("main.closeToTray") : Loc.T("main.close"));
            topbar.Controls.Add(bClose);
            topbar.Controls.Add(bMin);
            var level = new Label
            {
                Text = Loc.T("main.uiLevel", LevelName(App.Settings.UiLevel)), Font = Small, ForeColor = Muted, BackColor = Bg, AutoSize = false,
                TextAlign = ContentAlignment.MiddleRight, Bounds = new Rectangle(topbar.Width - D(300), 0, D(200), D(34)), Cursor = Cursors.Hand,
                Anchor = AnchorStyles.Top | AnchorStyles.Right,
            };
            level.Click += (s, e) => Navigate("settings");
            tips.SetToolTip(level, Loc.T("main.uiLevelTip"));
            topbar.Controls.Add(level);

            host = new Panel { Bounds = new Rectangle(D(220), D(40), ClientSize.Width - D(220), ClientSize.Height - D(40)), BackColor = Bg,
                               Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right };

            Controls.Add(host);
            Controls.Add(topbar);
            Controls.Add(sidebar);
            ResumeLayout();
        }

        /// <summary>The status box only when the whole menu fits above it; otherwise the menu gets the height and scrolls if needed.</summary>
        void LayoutSidebar()
        {
            if (sidebar == null || navArea == null || sideStatus == null) return;
            int h = sidebar.ClientSize.Height;
            int need = D(8) + navs.Count * D(42);
            bool status = h >= D(84) + need + D(92);
            sideStatus.Visible = status;
            if (status) sideStatus.Top = h - D(84);
            var b = new Rectangle(0, D(84), D(220), Math.Max(D(40), h - D(84) - (status ? D(92) : 0)));
            if (navArea.Bounds != b) navArea.Bounds = b;
            int w = navArea.ClientSize.Width;   // narrower while the menu scrolls
            foreach (var n in navs) if (n.Width != w) n.Width = w;
        }

        // self-check access
        internal Panel Host => host;
        internal Panel NavArea => navArea;
        internal IReadOnlyList<NavItem> NavItems => navs;
        internal Control SideStatusBox => sideStatus;
        internal PageBase CurrentPage => current;

        public static string LevelName(UiLevel l) => Loc.T("uiLevel." + l);

        /// <summary>Rebuilds the whole UI when the theme, the UI level or the language changes.</summary>
        public void Rebuild()
        {
            string key = current?.Key ?? "home";
            // keep the page and its scroll position; painting is stopped until the new controls are ready (no flicker)
            var scrollPos = current?.Controls.OfType<ScrollArea>().FirstOrDefault()?.Offset;
            bool freeze = IsHandleCreated && Visible;
            if (freeze) Native.SetRedraw(Handle, false);
            try
            {
                SuspendLayout();
                current = null;
                foreach (var p in pages.Values) { p.Visible = false; p.Dispose(); }
                pages.Clear();
                var old = Controls.Cast<Control>().ToList();
                Controls.Clear();
                foreach (var c in old) c.Dispose();
                BuildChrome();
                trayMenu.Renderer = new MenuRenderer();
                ResumeLayout();
                Navigate(key);
                // the scroll position comes back as far as the new page allows (another language may change the content height)
                var area = current?.Controls.OfType<ScrollArea>().FirstOrDefault();
                if (area != null && scrollPos.HasValue) { area.PerformLayout(); area.Offset = scrollPos.Value; }
                RefreshChrome();
            }
            finally
            {
                if (freeze) Native.SetRedraw(Handle, true);
            }
        }

        public void ApplyTheme()
        {
            Theme.Apply(Palettes.Resolve(App.Settings));
            Rebuild();
        }

        /// <summary>The theme depends on Windows: the system theme, or "follow Windows" light/dark.</summary>
        static bool FollowsWindows => App.Settings.FollowSystem || App.Settings.ThemeId == "system";

        /// <summary>Applies the theme only if Windows changes produced other colors (avoids needless rebuilds).</summary>
        void ApplyThemeIfChanged()
        {
            var p = Palettes.Resolve(App.Settings);
            if (Theme.Current != null && p.ToCode() == Theme.Current.ToCode() && p.Id == Theme.Current.Id && p.NameKey == Theme.Current.NameKey) return;
            App.Log("Windows theme changed; theme: " + p.Id, LogLevel.Info);
            ApplyTheme();
        }

        /// <summary>A small mark next to a menu entry (e.g. unapplied custom colors on the Appearance page).</summary>
        public void SetNavDot(string key, bool on)
        {
            foreach (var n in navs.Where(n => n.Key == key)) if (n.Dot != on) { n.Dot = on; n.Invalidate(); }
        }

        protected override CreateParams CreateParams
        {
            get
            {
                var cp = base.CreateParams;
                cp.ClassStyle |= 0x20000;   // CS_DROPSHADOW
                return cp;
            }
        }

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            Native.RoundCorners(Handle);
            ApplyHotkey();   // the window handle is recreated when the taskbar setting changes
        }

        protected override void OnKeyDown(KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Escape && !(ActiveControl is ComboBox cb && cb.DroppedDown)) { HideToTray(); e.Handled = true; }
            base.OnKeyDown(e);
        }

        void DragMouseDown(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Left) Native.DragWindow(Handle);
        }

        PageBase Create(string key)
        {
            switch (key)
            {
                case "home": return new HomePage();
                case "profiles": return new ProfilesPage();
                case "net": return new NetPage();
                case "dns": return new DnsPage();
                case "sites": return new SitesPage();
                case "proxy": return new ProxyPage();
                case "trouble": return new TroublePage();
                case "log": return new LogPage();
                case "appearance": return new AppearancePage();
                case "settings": return new SettingsPage();
                case "about": return new AboutPage();
            }
            return null;
        }

        /// <summary>Goes to a page. A page can be opened even if it is not in the menu at the selected UI level.</summary>
        public PageBase Navigate(string key)
        {
            if (!pages.TryGetValue(key, out var page))
            {
                page = Create(key);
                if (page == null) return null;
                page.Visible = false;
                page.FitHost();
                pages[key] = page;
                host.Controls.Add(page);
            }
            foreach (var n in navs) n.Selected = n.Key == key;
            if (current != null && current != page) current.Visible = false;
            current = page;
            page.Visible = true;
            page.BringToFront();
            page.OnActivated();
            return page;
        }

        public T Page<T>() where T : PageBase => pages.Values.OfType<T>().FirstOrDefault();

        public T Go<T>(string key) where T : PageBase => Navigate(key) as T;

        // ---------------------------------------------------------------- tray

        sealed class MenuColors : ProfessionalColorTable
        {
            public override Color ToolStripDropDownBackground => Theme.Card;
            public override Color ImageMarginGradientBegin => Theme.Card;
            public override Color ImageMarginGradientMiddle => Theme.Card;
            public override Color ImageMarginGradientEnd => Theme.Card;
            public override Color MenuBorder => Theme.Border;
            public override Color MenuItemBorder => Theme.AccentBorder;
            public override Color MenuItemSelected => Theme.AccentSoft;
            public override Color MenuItemSelectedGradientBegin => Theme.AccentSoft;
            public override Color MenuItemSelectedGradientEnd => Theme.AccentSoft;
            public override Color SeparatorDark => Theme.Divider;
            public override Color SeparatorLight => Theme.Divider;
            public override Color CheckBackground => Theme.AccentSoft;
            public override Color CheckSelectedBackground => Theme.AccentSoft;
            public override Color CheckPressedBackground => Theme.AccentSoft;
        }

        sealed class MenuRenderer : ToolStripProfessionalRenderer
        {
            public MenuRenderer() : base(new MenuColors()) { RoundedEdges = false; }
            protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
            {
                e.TextColor = e.Item.Enabled ? Theme.Text : Theme.Muted;
                base.OnRenderItemText(e);
            }
            protected override void OnRenderArrow(ToolStripArrowRenderEventArgs e)
            {
                e.ArrowColor = Theme.Muted;
                base.OnRenderArrow(e);
            }
            protected override void OnRenderItemCheck(ToolStripItemImageRenderEventArgs e)
            {
                var r = e.ImageRectangle;
                TextRenderer.DrawText(e.Graphics, GCheck, IconS, r, Theme.AccentInk, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
            }
        }

        ContextMenuStrip BuildTrayMenu()
        {
            var m = new ContextMenuStrip { Font = Body, ShowImageMargin = true, Renderer = new MenuRenderer() };
            miStatus = new ToolStripMenuItem(Loc.T("tray.status")) { Enabled = false, Font = Bold };
            miToggle = new ToolStripMenuItem(Loc.T("tray.start"), null, async (s, e) => await Actions.ToggleAsync());
            miTest = new ToolStripMenuItem(Loc.T("tray.test"), null, async (s, e) =>
            {
                var r = await Actions.QuickTestAsync();
                int ok = r?.Count(x => x.Ok) ?? 0, total = r?.Count ?? 0;
                ShowBalloon(Loc.T("tray.testTitle"), Loc.T("tray.testResult", ok, total) + (App.LastDnsOk == false ? " " + Loc.T("tray.dnsWrong") : ""),
                    ok == total ? ToolTipIcon.Info : ToolTipIcon.Warning, force: true);
            });
            miScan = new ToolStripMenuItem(Loc.T("tray.scan"), null, (s, e) => { ShowFromTray(); ScanDialog.Run(this); });
            miUpdate = new ToolStripMenuItem(Loc.T("tray.update"), null, (s, e) => { ShowFromTray(); if (Updater.Available != null) UpdateDialog.ShowFor(this, Updater.Available); }) { Font = Bold, Visible = false };
            miDiscord = new ToolStripMenuItem(Loc.T("tray.restartDiscord"), null, async (s, e) =>
            {
                string msg = await Actions.RestartDiscordAsync();
                ShowBalloon("Discord", msg, ToolTipIcon.Info, force: true);
            });
            miOpen = new ToolStripMenuItem(Loc.T("tray.open"), null, (s, e) => ShowFromTray()) { Font = Bold };
            miExit = new ToolStripMenuItem(Loc.T("tray.exit"), null, (s, e) => ExitApp());
            // quick-switch submenus: engine, then the profiles of that engine (TrayMenus.Choices)
            var switches = TrayMenus.Choices.Select(c => (Menu: new ToolStripMenuItem(Loc.T(c.TitleKey)), Source: c)).ToList();
            miProfiles = switches.First(x => x.Source is ProfileTrayChoices).Menu;
            var items = new List<ToolStripItem> { miStatus, new ToolStripSeparator(), miToggle };
            items.AddRange(switches.Select(x => x.Menu));
            items.AddRange(new ToolStripItem[] { new ToolStripSeparator(), miTest, miScan, miDiscord, miUpdate, new ToolStripSeparator(), miOpen, miExit });
            m.Items.AddRange(items.ToArray());
            m.Opening += (s, e) =>
            {
                foreach (var (menu, source) in switches) TrayMenus.Fill(menu, source, new MenuRenderer());
                miTest.Enabled = !Actions.Testing && !Actions.Scanning;
                miScan.Enabled = !Actions.Scanning;
                miDiscord.Visible = DiscordHelper.IsRunning;
                miUpdate.Visible = Updater.Available != null;
                if (Updater.Available != null) miUpdate.Text = Loc.T("tray.updateTo", Updater.Available.Version);
            };
            return m;
        }

        Icon TrayIcon(TrayStatus s)
        {
            if (!trayIcons.TryGetValue(s, out var ic))
            {
                ic = TrayLook.MakeIcon(s, SystemInformation.SmallIconSize.Width);
                trayIcons[s] = ic;
            }
            return ic;
        }

        public static string TrayStatusText(TrayStatus t, EngineState s) =>
            t == TrayStatus.Warning ? Loc.T("tray.activeWithWarning") : StateText(s);

        public static string StateText(EngineState s)
        {
            switch (s)
            {
                case EngineState.Running: return Loc.T("state.running");
                case EngineState.Starting: return Loc.T("state.starting");
                case EngineState.Stopping: return Loc.T("state.stopping");
                case EngineState.Error: return Loc.T("state.error");
                default: return Loc.T("state.stopped");
            }
        }

        void RefreshChrome()
        {
            if (IsDisposed) return;
            var st = App.Engine.State;
            var prof = App.Engine.ActiveProfile ?? App.SelectedProfile;
            var look = TrayLook.Current();
            string t = App.Name + " – " + TrayStatusText(look, st);
            if (st == EngineState.Running) t += "\n" + Engines.Of(prof).DisplayName.Split(' ')[0] + " · " + prof.Name;
            tray.Text = t.Length > 63 ? t.Substring(0, 63) : t;
            tray.Icon = TrayIcon(look);
            miStatus.Text = TrayStatusText(look, st) +(st == EngineState.Error && App.Engine.LastErrorCode.Length > 0 ? " (" + App.Engine.LastErrorCode + ")" : "");
            bool active = st == EngineState.Running || st == EngineState.Starting;
            miToggle.Text = active ? Loc.T("tray.stop") : Loc.T("tray.start");
            miToggle.Enabled = st != EngineState.Stopping && !Actions.Scanning;
            sideStatus?.Invalidate();
            int issues = App.Problems.Snapshot().Count(p => p.Info != null && p.Info.Severity != Severity.Info);
            foreach (var n in navs.Where(n => n.Key == "trouble")) { if (n.Badge != issues) { n.Badge = issues; n.Invalidate(); } }
        }

        void OnEngineStateChanged(EngineState old, EngineState now)
        {
            RefreshChrome();
            if (App.Engine.Quiet || !App.Settings.Notifications) return;
            if (now == EngineState.Running && old == EngineState.Starting && !Visible)
                ShowBalloon(Loc.T("state.running"), Loc.T("main.methodLabel") + " " + (App.Engine.ActiveProfile?.Name ?? ""), ToolTipIcon.Info);
            else if (now == EngineState.Error && !Visible)
            {
                string err = App.Engine.LastError ?? "";
                if (err.Length > 200) err = err.Substring(0, 197) + "…";
                string code = App.Engine.LastErrorCode;
                ShowBalloon(Loc.T("main.protectionStopped") + (code.Length > 0 ? " – " + code : ""), err, ToolTipIcon.Error);
            }
        }

        public void ShowBalloon(string title, string text, ToolTipIcon icon, bool force = false)
        {
            if (App.Preview) return;
            if (!force && !App.Settings.Notifications) return;
            if (string.IsNullOrEmpty(text)) text = " ";
            tray.ShowBalloonTip(4000, title, text, icon);
        }

        // ---------------------------------------------------------------- window

        public void ShowFromTray()
        {
            if (!Visible) Show();
            if (WindowState == FormWindowState.Minimized) WindowState = FormWindowState.Normal;
            Activate();
            Native.SetForegroundWindow(Handle);
            current?.OnActivated();
        }

        public void HideToTray()
        {
            Hide();
            if (!App.Settings.TrayHintShown)
            {
                App.Settings.TrayHintShown = true;
                App.Save();
                ShowBalloon(App.Name + " " + Loc.T("main.runningInBackground"),
                    Loc.T("main.trayHint"),
                    ToolTipIcon.Info, force: true);
            }
        }

        public void ApplyTaskbarSetting()
        {
            ShowInTaskbar = !App.Settings.HideFromTaskbar;
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (!exiting && e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;
                if (App.Settings.CloseToTray) HideToTray();
                else ExitApp();
                return;
            }
            if (!exiting)
            {
                // Windows is shutting down / the session is ending
                exiting = true;
                tray.Visible = false;
                Actions.CancelScans();   // candidate processes are in the kill-on-close job; the service starts again at boot
                if (!App.Engine.RunningAsService) App.Engine.Stop(true);
                CrashMarker.End();   // the process may be killed while Windows shuts down; counts as a clean exit
            }
            base.OnFormClosing(e);
        }

        public void ExitApp(bool ask = true)
        {
            if (Actions.Scanning)
            {
                // a running scan is cancelled first; the app closes once its candidate is stopped and the original state is back
                Actions.CancelScans();
                foreach (var d in Application.OpenForms.OfType<ScanDialog>().ToList()) d.Close();
                ExitWhenScanDone(ask);
                return;
            }
            if (ask && App.Engine.IsActive && !App.Engine.RunningAsService)
            {
                var r = MessageBox.Show(Visible ? this : null,
                    Loc.T("main.exitConfirm"),
                    App.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2);
                if (r != DialogResult.Yes) return;
            }
            exiting = true;
            pollTimer.Stop();
            tray.Visible = false;
            if (!App.Engine.RunningAsService) App.Engine.Stop();
            ProxyBridge.StopAll();
            App.Log("App closed.", LogLevel.Info);
            CrashMarker.End();
            Application.Exit();
        }

        async void ExitWhenScanDone(bool ask)
        {
            for (int i = 0; i < 600 && Actions.Scanning; i++) await Task.Delay(100);
            ExitApp(ask);
        }

        public async void AfterStartup(bool fromTray, bool scan, bool scanAll = false, string updatedFrom = null, bool updateFailed = false, bool resume = false, bool switched = false)
        {
            App.Log(App.Name + " " + App.Version + " started (" + App.Settings.UiLevel + " UI, language: " + Loc.Current + ", theme: " + Theme.Current?.Id + ").", LogLevel.Info);
            if (App.Preview) return;
            if (updatedFrom != null)
            {
                App.Log("Update finished: " + updatedFrom + " → " + App.Version, LogLevel.Success);
                ShowBalloon(Loc.T("main.updatedTitle"), Loc.T("main.updatedText", updatedFrom, App.Version), ToolTipIcon.Info, force: true);
                History.Add(new HistoryEntry { Time = DateTime.Now, Kind = "update", Profile = App.Version, Ok = 1, Total = 1, Running = true, Note = updatedFrom + " → " + App.Version });
                _ = Task.Delay(15000).ContinueWith(_ => Updater.Cleanup());
            }
            if (CrashMarker.PreviousUnexpected != null && updatedFrom == null)
            {
                App.Problems.Report("NSF-106", CrashMarker.PreviousUnexpected);
                ShowBalloon(Loc.T("main.crashTitle"),
                    Loc.T("main.crashText"),
                    ToolTipIcon.Warning, force: true);
            }
            if (updateFailed)
            {
                App.Log("The update failed; rolled back to the previous version. Details: data\\update.log", LogLevel.Error);
                ShowBalloon(Loc.T("main.updateFailedTitle"), Loc.T("main.updateFailedText"), ToolTipIcon.Warning, force: true);
            }
            updateTimer.Tick += async (s, e) =>
            {
                updateTimer.Interval = 6 * 60 * 60 * 1000;
                if (Updater.DueForCheck && !Actions.Scanning) await UpdateDialog.CheckAndShow(this, manual: false);
            };
            updateTimer.Start();
            var curEngine = App.Engine.Current;
            string missing = Engine.MissingFile(curEngine);
            if (missing != null) App.Log("[NSF-102] " + missing + " not found: " + curEngine.BinDir, LogLevel.Error);
            if (App.RunningFromTemp)
            {
                App.Problems.Report("NSF-103", App.BaseDir);
                App.Log("[NSF-103] The app is running from a temporary folder: " + App.BaseDir, LogLevel.Warn);
            }

            // The service and the startup task can only run from a protected (installed) folder
            bool protectedInstall = await Task.Run(() => InstallGuard.Evaluate(true));
            string removed = "";
            bool serviceWasRunning = await Task.Run(() => Uninstaller.EnforceLocationRules(protectedInstall, out removed));
            if (removed.Length > 0)
            {
                App.Problems.Report("NSF-705", removed);
                ShowBalloon(Loc.T("main.securityClosed", removed),
                    Loc.T("main.securityClosedText"),
                    ToolTipIcon.Warning, force: true);
            }
            if (protectedInstall && App.Settings.StartWithWindows)
                _ = Task.Run(() =>
                {
                    if (!Startup.Enable(out string err))
                    {
                        App.Log("[NSF-703] The startup task could not be updated: " + err, LogLevel.Warn);
                        App.Problems.Report("NSF-703", err);
                    }
                });

            try { ProxyBridge.Sync(); } catch (Exception ex) { App.Log("Local proxy bridge could not be started: " + ex.Message, LogLevel.Warn); }
            // ByeDPI: a Windows proxy left pointed at its bridge by a crash or power loss is restored before anything starts
            try { ByeDpiNet.StartupCheck(); ByeDpiNet.RecoverStale("app start"); } catch (Exception ex) { App.Log("Windows proxy could not be checked: " + ex.Message, LogLevel.Warn); }
            try { if (!App.Preview) Uninstaller.ReportSetupResult(); } catch (Exception ex) { App.Ignored("Setup result could not be read", ex); }
            await Task.Run(() => App.Engine.Poll());
            bool repointed = false, repointOk = false;
            var target = App.Engine.ServiceInstalled && App.Settings.ServiceMode ? await Task.Run(() => Engine.CheckServiceTarget()) : Engine.ServiceTarget.NoService;
            if (target == Engine.ServiceTarget.NeedsRepoint)
            {
                // the service runs another engine of this folder: it gets the verified command of the selected engine and is read
                // back from the SCM. Never a general takeover: a running service of this installation is restarted with the new
                // command (no other program is closed); a stopped one is set up again and stays stopped.
                App.Log("The service runs another engine of this folder; updating it.", LogLevel.Warn);
                repointed = true;
                repointOk = await Actions.RepointServiceAsync();
            }
            else if (target == Engine.ServiceTarget.Unknown)
                App.Log("The service could not be read; it is not changed.", LogLevel.Warn);
            if (repointed && !repointOk) App.Log("The service could not be updated; it was left as it was.", LogLevel.Warn);
            if (scan)
            {
                // scan requested from the command line (e.g. NSFShield.exe --scan)
                ShowFromTray();
                ScanDialog.Run(this, ScanDialog.CommandLineRequest(scanAll), autoStart: true);
            }
            else if (repointed) { }
            else if ((App.Settings.AutoStartProtection || resume || serviceWasRunning) && App.Engine.State != EngineState.Running)
            {
                if (App.Engine.ExternalCount > 0)
                    App.Log("A DPI tool (GoodbyeDPI/winws) running outside the app was found; taking over.", LogLevel.Warn);
                await Actions.StartAsync();
            }
            else if (App.Engine.State == EngineState.Running && App.Settings.TestAfterStart)
                await Actions.QuickTestAsync();

            if (switched)
            {
                // first start after a portable copy switched to this installed copy
                App.Log("Started after the switch from the portable version (settings carried over).", LogLevel.Success);
                ShowFromTray();
                SwitchDialog.ShowDone(this);
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Loc.Changed -= OnLanguageChanged;
                SystemEvents.UserPreferenceChanged -= OnUserPreferenceChanged;
                SystemEvents.DisplaySettingsChanged -= OnDisplaySettingsChanged;
                // the app-wide events must not keep a closed window alive (or call into it)
                App.StatusChanged -= RefreshChrome;
                if (App.Engine != null) App.Engine.StateChanged -= OnEngineStateChanged;
                if (ReferenceEquals(Instance, this)) Instance = null;
                netWatch?.Dispose();
                watchTimer.Dispose();
                updateTimer.Dispose();
                netChangeTimer.Dispose();
                tray.Visible = false;
                tray.Dispose();
                // the cached tray icons (GDI handles) go after the tray that showed them
                foreach (var ic in trayIcons.Values) try { ic.Dispose(); } catch { }
                trayIcons.Clear();
                pollTimer.Dispose();
                themeTimer.Dispose();
            }
            base.Dispose(disposing);
        }

        // ---------------------------------------------------------------- inner controls

        sealed class LogoPanel : Control
        {
            readonly Bitmap logo = IconArt.AppBitmap(D(36));
            public LogoPanel()
            {
                SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer, true);
            }
            protected override void Dispose(bool disposing) { if (disposing) logo.Dispose(); base.Dispose(disposing); }
            protected override void OnPaint(PaintEventArgs e)
            {
                var g = e.Graphics;
                g.Clear(Sidebar);
                g.DrawImage(logo, D(20), D(24));
                using (var f = new Font("Segoe UI Semibold", 13f))
                    TextRenderer.DrawText(g, App.Name, f, new Point(D(64), D(21)), SidebarText, Sidebar);
                TextRenderer.DrawText(g, Loc.T("main.tagline"), Small, new Point(D(65), D(45)), SidebarMuted, Sidebar);
            }
        }

        sealed class SideStatus : Control
        {
            public SideStatus()
            {
                SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
                Cursor = Cursors.Hand;
            }
            protected override void OnPaint(PaintEventArgs e)
            {
                var g = e.Graphics;
                g.Clear(Sidebar);
                HQ(g);
                var bg = SidebarBox;
                using (var p = Round(new RectangleF(0, 0, Width - 1, Height - 1), D(10)))
                using (var b = new SolidBrush(bg)) g.FillPath(b, p);
                var st = App.Engine.State;
                Color c = st == EngineState.Running ? Color.FromArgb(52, 211, 153)
                        : st == EngineState.Error ? Color.FromArgb(248, 113, 113)
                        : st == EngineState.Stopped ? Mix(SidebarText, Sidebar, 0.5f) : Color.FromArgb(251, 191, 36);
                float d = D(10);
                using (var halo = new SolidBrush(Color.FromArgb(60, c))) g.FillEllipse(halo, D(14) - D(3), D(17) - D(3), d + D(6), d + D(6));
                using (var b = new SolidBrush(c)) g.FillEllipse(b, D(14), D(17), d, d);
                TextRenderer.DrawText(g, StateText(st), Bold, new Point(D(32), D(12)), SidebarText, bg);
                var prof = App.Engine.ActiveProfile ?? App.SelectedProfile;
                string sub = st == EngineState.Running
                    ? prof.Name + (App.Engine.RunningAsService ? " · " + Loc.T("main.service") : "")
                    : st == EngineState.Error && App.Engine.LastErrorCode.Length > 0 ? Loc.T("main.errorCode") + " " + App.Engine.LastErrorCode
                    : Loc.T("main.methodLabel") + " " + prof.Name;
                TextRenderer.DrawText(g, sub, Small, new Rectangle(D(14), D(38), Width - D(20), D(20)), SidebarMuted, bg,
                    TextFormatFlags.EndEllipsis | TextFormatFlags.NoPadding);
            }
        }

        sealed class ChromeBtn : Control
        {
            readonly string glyph;
            readonly bool isClose;
            bool hover;
            public ChromeBtn(string glyph, bool isClose)
            {
                this.glyph = glyph;
                this.isClose = isClose;
                SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer, true);
            }
            protected override void OnMouseEnter(EventArgs e) { hover = true; Invalidate(); base.OnMouseEnter(e); }
            protected override void OnMouseLeave(EventArgs e) { hover = false; Invalidate(); base.OnMouseLeave(e); }
            protected override void OnPaint(PaintEventArgs e)
            {
                Color bg = hover ? (isClose ? Color.FromArgb(232, 17, 35) : Mix(Bg, Theme.Text, 0.08f)) : Bg;
                Color fg = hover && isClose ? Color.White : Muted;
                e.Graphics.Clear(bg);
                using (var f = new Font(IconFontName, 8f))
                    TextRenderer.DrawText(e.Graphics, glyph, f, ClientRectangle, fg, bg,
                        TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
            }
        }
    }
}
