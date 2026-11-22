using System;
using System.Drawing;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using static NSFShield.Theme;

namespace NSFShield
{
    sealed class HomePage : PageBase
    {
        public override string Key => "home";

        readonly bool simple;
        readonly Card hero, banner, cProfile, cConn, cSession, tip;
        readonly ShieldView shield;
        readonly Label lblState, lblSub, lblHint, bannerIcon, bannerTitle, bannerText;
        readonly FlatBtn btnToggle, btnTest, bannerFix, bannerMore, bDiscord, bAuto, bChange;
        readonly Label pName, pDesc, pCmd, connIcon, connTitle, connDetail, connDns, connTime, upVal;
        Label modeVal, dnsVal, targetVal, scanVal;
        readonly ThemedCombo pCombo;
        readonly StatusChip chipEngine, chipMode, chipDns, chipUp;
        readonly ToolTip chipTips = new ToolTip();
        readonly Timer tick = new Timer { Interval = 1000 };
        DetectedProblem shownProblem;
        bool showingUpdate, showingSwitch;
        ConflictNotice shownNotice;
        /// <summary>Information cards closed in this session (kind + title; they come back after a restart).</summary>
        static readonly System.Collections.Generic.HashSet<string> noticesClosed = new System.Collections.Generic.HashSet<string>();
        static bool? switchOffered;
        static bool updateDismissed;
        string hintOverride;
        bool filling;
        /// <summary>The cards scroll vertically in one area when the window is short (their positions stay logical).</summary>
        readonly ScrollArea area;
        readonly ScrollContent content;

        public HomePage()
        {
            simple = App.Settings.UiLevel == UiLevel.Simple;
            area = new ScrollArea { Dock = DockStyle.Fill };
            content = new ScrollContent(area);
            Controls.Add(area);
            Surface = content;

            // ------------------------------------------------ status card
            hero = AddCard(28, 6, 764, 252);
            shield = hero.Add(new ShieldView { Bounds = R(22, 22, 208, 208) });
            lblState = hero.Add(UIx.L(Loc.T("home.stateOff"), Hero, Theme.Text, 250, 34, 490, 46));
            lblSub = hero.Add(UIx.L("", Body, Muted, 252, 84, 490, 44));
            btnToggle = hero.Add(new FlatBtn { Text = Loc.T("home.start"), Kind = FlatBtn.Kinds.Success, Glyph = GPlay, Bounds = R(252, 142, 232, 52), Font = Big });
            btnTest = hero.Add(new FlatBtn { Text = Loc.T("home.testDiscord"), Kind = FlatBtn.Kinds.Secondary, Glyph = GSpeed, Bounds = R(498, 142, 206, 52), Font = Big });
            // status chips: engine, mode, DNS and uptime at a glance
            chipEngine = hero.Add(new StatusChip { Glyph = GShield, Label = Loc.T("home.chip.engine"), Value = App.Engine.Current.DisplayName, BackColor = Theme.Card, Cursor = Cursors.Hand });
            chipEngine.Click += (s, e) => ShowEngineMenu(chipEngine);
            chipMode = hero.Add(new StatusChip { Glyph = GServer, Label = Loc.T("home.chip.mode"), BackColor = Theme.Card });
            chipDns = hero.Add(new StatusChip { Glyph = GGlobe, Label = Loc.T("home.chip.dns"), BackColor = Theme.Card });
            chipUp = hero.Add(new StatusChip { Glyph = GClock, Label = Loc.T("home.chip.uptime"), Value = "—", BackColor = Theme.Card });
            lblHint = hero.Add(UIx.L("", Small, Muted, 252, 230, 496, 18));
            lblHint.AutoEllipsis = true;
            btnToggle.Click += async (s, e) => { hintOverride = null; await Actions.ToggleAsync(); };
            btnTest.Click += async (s, e) => { hintOverride = null; await Actions.QuickTestAsync(); };

            // ------------------------------------------------ problem banner
            banner = AddCard(28, 272, 764, 56);
            bannerIcon = banner.Add(UIx.Glyph(GWarn, IconM, Amber, 12, 0, 34, 56));
            bannerTitle = banner.Add(UIx.L("", Bold, Theme.Text, 48, 8, 440, 20));
            bannerText = banner.Add(UIx.L("", Small, Muted, 48, 28, 440, 22));
            bannerText.AutoEllipsis = true;
            bannerFix = banner.Add(new FlatBtn { Text = Loc.T("home.fix"), Kind = FlatBtn.Kinds.Warning, Bounds = R(498, 11, 150, 34) });
            bannerMore = banner.Add(new FlatBtn { Text = Loc.T("home.details"), Glyph = GHelp, Kind = FlatBtn.Kinds.Ghost, Bounds = R(654, 11, 100, 34) });
            bannerFix.Click += async (s, e) =>
            {
                if (shownNotice != null)
                {
                    // information only: the profile page opens on the ByeDPI tab; no profile is selected and nothing starts
                    MainForm.Instance.Go<ProfilesPage>("profiles")?.ShowEngineTab(EngineKind.ByeDpi);
                    return;
                }
                if (showingUpdate) { if (Updater.Available != null) UpdateDialog.ShowFor(FindForm(), Updater.Available); return; }
                if (showingSwitch) { SwitchDialog.Run(FindForm()); return; }
                var p = shownProblem;
                if (p?.Info == null) return;
                bannerFix.Enabled = false;
                string msg = await Fixes.Run(p.Info.Fix, FindForm());
                if (IsDisposed) return;
                bannerFix.Enabled = true;
                if (!string.IsNullOrEmpty(msg)) hintOverride = msg;
                if (p.Code == "NSF-901" || p.Code == "NSF-103") App.Problems.Clear(p.Code);
                UpdateAll();
            };
            bannerMore.Click += (s, e) =>
            {
                if (shownNotice != null) { noticesClosed.Add(NoticeKey(shownNotice)); UpdateAll(); return; }
                if (showingUpdate) { updateDismissed = true; UpdateAll(); return; }
                if (showingSwitch)
                {
                    App.Settings.InstallerHintDismissed = true;
                    App.Save();
                    UpdateAll();
                    return;
                }
                var p = shownProblem;
                MainForm.Instance.Go<TroublePage>("trouble")?.ShowCode(p?.Code);
            };
            banner.Visible = false;

            if (simple)
            {
                // ------------------------------------------------ SIMPLE: two big cards
                cConn = AddCard(28, 272, 374, 210);
                cConn.Add(UIx.L(Loc.T("home.discordAccess"), Caption, Muted, 20, 18, 300, 18));
                connIcon = cConn.Add(UIx.Glyph(GInfo, IconL, Gray, 16, 42, 40, 40));
                connTitle = cConn.Add(UIx.L(Loc.T("home.notTested"), H2, Theme.Text, 60, 44, 300, 36, ContentAlignment.MiddleLeft));
                connDetail = cConn.Add(UIx.L("", Small, Muted, 20, 90, 340, 40));
                connDns = cConn.Add(UIx.L("", Small, Muted, 20, 130, 200, 20));
                connTime = cConn.Add(UIx.L("", Small, Muted, 220, 130, 140, 20, ContentAlignment.TopRight));
                bDiscord = cConn.Add(new FlatBtn { Text = Loc.T("home.restartDiscord"), Glyph = GRefresh, Kind = FlatBtn.Kinds.Secondary, Bounds = R(20, 158, 230, 36) });

                cProfile = AddCard(418, 272, 374, 210);
                cProfile.Add(UIx.L(Loc.T("home.methodInUse"), Caption, Muted, 20, 18, 210, 18));
                pName = cProfile.Add(UIx.L("", H2, Theme.Text, 19, 38, 340, 28));
                pDesc = cProfile.Add(UIx.L("", Small, Muted, 20, 68, 336, 72));
                // one click: the recommended candidates of every engine, stop at the first full success and connect with it
                bAuto = cProfile.Add(new FlatBtn { Text = Loc.T("home.findAndConnect"), Glyph = GSearch, Kind = FlatBtn.Kinds.Primary, Bounds = R(20, 152, 334, 40) });
                bChange = cProfile.Add(new FlatBtn { Text = Loc.T("home.change"), Glyph = GChevron, Kind = FlatBtn.Kinds.Ghost, Bounds = R(236, 10, 124, 28), Font = Small });
                bAuto.Click += (s, e) => ScanDialog.Run(FindForm(), ScanRequest.SimpleConnect("home"), autoStart: true);
                bChange.Click += (s, e) => ShowProfileMenu(bChange);

                tip = AddCard(28, 496, 764, 74);
                tip.Fill = AccentSoft;
                tip.Stroke = AccentBorder;
                tip.Add(UIx.Glyph(GHelp, IconL, AccentInk, 16, 0, 48, 74));
                tip.Add(UIx.L(Loc.T("home.stillNotOpening"), Bold, Theme.Text, 70, 15, 460, 22));
                tip.Add(UIx.L(Loc.T("home.findProblemHint"), Small, Muted, 70, 37, 460, 34));
                var bTrouble = tip.Add(new FlatBtn { Text = Loc.T("home.findProblem"), Glyph = GSearch, Kind = FlatBtn.Kinds.Primary, Bounds = R(566, 18, 180, 38) });
                bTrouble.Click += async (s, e) => { var tp = MainForm.Instance.Go<TroublePage>("trouble"); if (tp != null) await tp.RunCheck(); };
            }
            else
            {
                // ------------------------------------------------ STANDARD / ADVANCED: three cards
                cProfile = AddCard(28, 272, 244, 220);
                cProfile.Add(UIx.L(Loc.T("home.activeMethod"), Caption, Muted, 20, 18, 200, 18));
                pName = cProfile.Add(UIx.L("", H2, Theme.Text, 19, 38, 212, 28));
                bool det = Level(UiLevel.Advanced);
                pDesc = cProfile.Add(UIx.L("", Small, Muted, 20, 68, 210, det ? 58 : 92));
                if (det) pCmd = cProfile.Add(UIx.L("", MonoSmall, Muted, 20, 128, 210, 36));
                pCombo = new ThemedCombo { Bounds = R(20, 172, 204, 28) };
                cProfile.Add(pCombo);
                pCombo.SelectedIndexChanged += async (s, e) =>
                {
                    if (filling || !(pCombo.SelectedItem is Profile it)) return;
                    await Actions.SelectProfileAsync(it);
                };

                cConn = AddCard(288, 272, 244, 220);
                cConn.Add(UIx.L(Loc.T("home.discordAccess"), Caption, Muted, 20, 18, 200, 18));
                connIcon = cConn.Add(UIx.Glyph(GInfo, IconL, Gray, 16, 42, 40, 40));
                connTitle = cConn.Add(UIx.L(Loc.T("home.notTested"), H2, Theme.Text, 60, 44, 176, 36, ContentAlignment.MiddleLeft));
                connDetail = cConn.Add(UIx.L("", Small, Muted, 20, 88, 210, 48));
                connDns = cConn.Add(UIx.L("", Small, Muted, 20, 136, 210, 18));
                connTime = cConn.Add(UIx.L("", Small, Muted, 20, 154, 210, 18));
                var lnk = cConn.Add(new FlatBtn { Text = Loc.T("home.internetCheck"), Glyph = GArrow, Kind = FlatBtn.Kinds.Ghost, Bounds = R(12, 178, 170, 32) });
                lnk.Click += (s, e) => MainForm.Instance.Navigate("net");

                cSession = AddCard(548, 272, 244, 220);
                cSession.Add(UIx.L(Loc.T("home.session"), Caption, Muted, 20, 18, 200, 18));
                upVal = cSession.Add(UIx.L("—", new Font("Segoe UI Semibold", 20f), Theme.Text, 18, 36, 210, 40));
                cSession.Add(UIx.L(Loc.T("home.uptime"), Small, Muted, 20, 76, 210, 18));
                int y = 104;
                var rows = new (string, Action<Label>)[] { ("home.row.mode", l => modeVal = l), ("home.row.dns", l => dnsVal = l), ("home.row.targeted", l => targetVal = l), ("home.row.lastScan", l => scanVal = l) };
                foreach (var (k, setter) in rows)
                {
                    cSession.Add(UIx.L(Loc.T(k), Small, Muted, 20, y, 84, 22, ContentAlignment.MiddleLeft));
                    var v = cSession.Add(UIx.L("", Bold, Theme.Text, 100, y, 134, 22, ContentAlignment.MiddleLeft));
                    setter(v);
                    y += 27;
                }

                tip = AddCard(28, 506, 764, 74);
                tip.Fill = AccentSoft;
                tip.Stroke = AccentBorder;
                tip.Add(UIx.Glyph(GShield, IconL, AccentInk, 16, 0, 48, 74));
                tip.Add(UIx.L(Loc.T("home.stillNotOpening"), Bold, Theme.Text, 70, 15, 300, 22));
                tip.Add(UIx.L(Loc.T("home.scanHint"), Small, Muted, 70, 37, 300, 34));
                bDiscord = tip.Add(new FlatBtn { Text = Loc.T("home.restartDiscord"), Glyph = GRefresh, Kind = FlatBtn.Kinds.Secondary, Bounds = R(378, 18, 190, 38) });
                bAuto = tip.Add(new FlatBtn { Text = Loc.T("home.findBest"), Glyph = GSearch, Kind = FlatBtn.Kinds.Primary, Bounds = R(576, 18, 172, 38) });
                bAuto.Click += (s, e) => ScanDialog.Run(FindForm());
            }
            bDiscord.Click += async (s, e) =>
            {
                bDiscord.Enabled = false;
                hintOverride = await Actions.RestartDiscordAsync();
                if (IsDisposed) return;
                bDiscord.Enabled = true;
                UpdateAll();
            };

            tick.Tick += (s, e) => UpdateUptime();
            tick.Start();
            Track(tick);
            Track(chipTips);
            OnStatus(UpdateAll);
            // the shared read-only conflict diagnosis (Find Problems runs the same one): only refreshed when it is old
            Action onConflicts = () => { if (!IsDisposed) UpdateAll(); };
            Conflicts.Updated += onConflicts;
            Disposed += (s, e) => Conflicts.Updated -= onConflicts;
            Conflicts.RefreshIfStale(TimeSpan.FromMinutes(2));
            UpdateAll();
        }

        /// <summary>The cards are in their own scrolled area already.</summary>
        internal override void FitHost() { }

        public override void OnActivated()
        {
            Conflicts.RefreshIfStale(TimeSpan.FromMinutes(2));
            UpdateAll();
        }

        static string NoticeKey(ConflictNotice n) => n.Kind + "|" + n.Title?.English;

        /// <summary>The banner's height and the number of text lines; the buttons and the icon stay vertically centered.</summary>
        void BannerHeight(int h, int lines)
        {
            if (banner.Height == D(h)) return;
            banner.Height = D(h);
            bannerIcon.Height = D(h);
            bannerText.Height = D(lines == 1 ? 22 : 16 * lines + 2);
            bannerFix.Top = bannerMore.Top = D((h - 34) / 2);
        }
        /// <summary>The information card shown now (self-test).</summary>
        internal ConflictNotice ShownNotice => shownNotice;
        internal string BannerTitle => banner.Visible ? bannerTitle.Text : null;
        internal bool BannerButtonVisible => banner.Visible && bannerFix.Visible;
        // self-check access: the scrolled area, the profile box, the card and the box's refills
        internal ScrollArea Area => area;
        internal ScrollContent Content => content;
        internal ThemedCombo ProfileBox => pCombo;
        internal string CardProfileName => pName.Text;
        internal Profile ShownProfile { get; private set; }
        internal int ComboRefills { get; private set; }
        internal Control LastCard => UIx.OwnVisible(tip) ? (Control)tip : cSession ?? cProfile;
        internal Card BannerCard => banner;
        internal Card TipCard => tip;
        internal Card ProfileCard => cProfile;

        /// <summary>Quick engine switch from the engine chip.</summary>
        void ShowEngineMenu(Control anchor)
        {
            var m = new ContextMenuStrip { Font = Body, ShowImageMargin = true, ShowItemToolTips = true };
            AddEngineItems(m);
            m.Closed += (s, e) => BeginInvoke(new Action(m.Dispose));
            m.Show(anchor, new Point(0, anchor.Height));
        }

        static void AddEngineItems(ContextMenuStrip m)
        {
            bool busy = Actions.Scanning || App.Engine.State == EngineState.Starting || App.Engine.State == EngineState.Stopping;
            var cur = App.Engine.Current.Kind;
            m.Items.Add(new ToolStripMenuItem(Loc.T("home.engineMenu")) { Enabled = false, Font = Caption });
            foreach (var en in Engines.All)
            {
                var k = en.Kind;
                var it = new ToolStripMenuItem(en.DisplayName) { Checked = k == cur, Enabled = !busy && en.Available(out _), ToolTipText = Loc.T("engines." + en.Id + ".tip") };
                it.Click += async (s, e) => await Actions.SelectEngineAsync(k);
                m.Items.Add(it);
            }
        }

        /// <summary>Simple: the recommended profiles of every engine (and the selected / running other profile once), grouped by engine.</summary>
        void ShowProfileMenu(Control anchor)
        {
            var m = new ContextMenuStrip { Font = Body, ShowImageMargin = true, ShowItemToolTips = true };
            EngineKind? lastEngine = null;
            foreach (var p in ProfileCatalog.VisibleNow(null).OrderBy(x => (int)x.Engine))
            {
                if (lastEngine != p.Engine)
                {
                    if (lastEngine != null) m.Items.Add(new ToolStripSeparator());
                    m.Items.Add(new ToolStripMenuItem(Engines.Of(p).DisplayName) { Enabled = false, Font = Caption });
                    lastEngine = p.Engine;
                }
                var prof = p;
                var it = new ToolStripMenuItem(p.Name) { Checked = p.Id == (ShownProfile?.Id ?? App.Settings.SelectedProfileId), ToolTipText = p.Description, Enabled = Engines.Of(p).Available(out _) };
                it.Click += async (s, e) => await Actions.SelectProfileAsync(prof);
                m.Items.Add(it);
            }
            m.Closed += (s, e) => BeginInvoke(new Action(m.Dispose));
            m.Show(anchor, new Point(0, anchor.Height));
        }

        string[] filledNames = new string[0];

        /// <summary>
        /// The box lists the visible profiles of the effective profile's engine and selects that same profile object (the card shows
        /// it too). The list is only rebuilt when it changed; the selection is set without a user selection event.
        /// </summary>
        void FillCombo(Profile prof)
        {
            if (pCombo == null || pCombo.DroppedDown) return;
            var items = ProfileCatalog.HomeItems(prof, ProfileCatalog.VisibleNow(prof.Engine));
            var names = items.Select(i => i.Name ?? "").ToArray();
            var now = pCombo.Items.Cast<object>().ToList();
            bool same = now.Count == items.Count && now.Zip(items, (a, b) => ReferenceEquals(a, b)).All(x => x) && names.SequenceEqual(filledNames);
            int want = items.FindIndex(i => ReferenceEquals(i, prof));
            filling = true;
            try
            {
                if (!same)
                {
                    pCombo.BeginUpdate();
                    pCombo.Items.Clear();
                    pCombo.Items.AddRange(items.Cast<object>().ToArray());
                    pCombo.EndUpdate();
                    filledNames = names;
                    ComboRefills++;
                }
                if (pCombo.SelectedIndex != want) pCombo.SelectedIndex = want;
            }
            finally { filling = false; }
        }

        int arrangedDy = -1;

        void Arrange(bool showBanner)
        {
            int dy = showBanner ? (int)Math.Round(banner.Height / Theme.Scale) + 14 : 0;
            if (UIx.OwnVisible(banner) == showBanner && dy == arrangedDy) { content.UpdateExtent(); return; }
            arrangedDy = dy;
            banner.Visible = showBanner;
            if (simple)
            {
                cConn.Top = cProfile.Top = D(272 + dy);
                tip.Top = D(496 + dy);
            }
            else
            {
                cProfile.Top = cConn.Top = cSession.Top = D(272 + dy);
                tip.Top = D(506 + dy);
            }
            // the tip card keeps its rule: hidden while a banner is shown
            tip.Visible = !showBanner;
            content.UpdateExtent();
        }

        void UpdateAll()
        {
            var e = App.Engine;
            // one snapshot for the whole page: the card, the box and the chips show the same profile (see ProfileCatalog.Effective)
            var (st, activeProfile, _) = e.ScanState();
            var prof = ProfileCatalog.Effective(st, activeProfile, App.Settings.SelectedProfileId, App.AllProfiles);
            ShownProfile = prof;
            shield.State = st;

            switch (st)
            {
                case EngineState.Running:
                    lblState.Text = Loc.T("home.stateOn");
                    lblState.ForeColor = GreenText;
                    lblSub.Text = Loc.T("home.subOn");
                    break;
                case EngineState.Starting:
                    lblState.Text = Loc.T("home.stateStarting");
                    lblState.ForeColor = AmberText;
                    lblSub.Text = Loc.T("home.subStarting");
                    break;
                case EngineState.Stopping:
                    lblState.Text = Loc.T("home.stateStopping");
                    lblState.ForeColor = AmberText;
                    lblSub.Text = "";
                    break;
                case EngineState.Error:
                    lblState.Text = Loc.T("home.stateError");
                    lblState.ForeColor = RedText;
                    lblSub.Text = (e.LastErrorCode.Length > 0 ? Loc.T("home.errorCode", e.LastErrorCode) + " " : "") + Trim(e.LastError, 210);
                    break;
                default:
                    lblState.Text = Loc.T("home.stateOff");
                    lblState.ForeColor = Theme.Text;
                    lblSub.Text = Loc.T("home.subOff");
                    break;
            }
            lblSub.Font = st == EngineState.Error ? Small : Body;
            lblSub.Height = D(st == EngineState.Error ? 52 : 44);
            bool active = st == EngineState.Running || st == EngineState.Starting;
            btnToggle.Text = active ? Loc.T("home.stop") : st == EngineState.Error ? Loc.T("home.retry") : Loc.T("home.start");
            btnToggle.Glyph = active ? GStop : st == EngineState.Error ? GRefresh : GPlay;
            btnToggle.Kind = active ? FlatBtn.Kinds.Danger : FlatBtn.Kinds.Success;
            btnToggle.Enabled = st != EngineState.Stopping && !Actions.Scanning;
            btnTest.Enabled = !Actions.Testing && !Actions.Scanning;
            btnTest.Text = Actions.Testing ? Loc.T("home.testing") : Loc.T("home.testDiscord");
            if (bAuto != null) bAuto.Enabled = !Actions.Scanning;

            lblHint.Text = hintOverride ?? (st == EngineState.Error
                    ? Loc.T("home.hintError")
                    : Actions.Scanning ? Loc.T("home.hintScanning")
                    : Loc.T("home.hintTray"));
            chipTips.SetToolTip(lblHint, lblHint.Text);

            // ------------------------------------------------ status chips
            var peng = Engines.Of(prof);
            chipEngine.Value = peng.DisplayName;
            bool serviceShown = e.RunningAsService || (App.Settings.ServiceMode && st != EngineState.Running && peng.SupportsService);
            chipMode.Value = serviceShown ? Loc.T("home.mode.service") : Loc.T("home.mode.app");
            SystemDns.RefreshStatus();
            bool redirect = st == EngineState.Running && prof.UsesDnsRedirect;
            var net = SystemDns.Status;
            chipDns.Value = redirect ? prof.DnsLabel : SystemDns.StatusLabel(net);
            // automatic (DHCP) DNS is a valid choice: no warning colour for it
            chipDns.Tone = Color.Empty;
            LayoutChips();
            chipTips.SetToolTip(chipDns, (redirect ? Loc.T("home.dnsTip.redirect", prof.DnsLabel) + "\n" : "") + SystemDns.StatusTip(net));

            // ------------------------------------------------ problem banner (one line; the information card below uses three)
            BannerHeight(56, 1);
            var problem = App.Problems.Snapshot().FirstOrDefault(p => p.Info != null && (p.Info.Severity != Severity.Info || p.Code == "NSF-901"));
            if (Actions.Scanning) problem = null;
            shownProblem = problem;
            if (problem != null)
            {
                var info = problem.Info;
                banner.Fill = info.Severity == Severity.Error ? RedSoft : info.Severity == Severity.Warning ? AmberSoft : AccentSoft;
                banner.Stroke = info.Severity == Severity.Error ? RedBorder : info.Severity == Severity.Warning ? AmberBorder : AccentBorder;
                bannerIcon.Text = info.Severity == Severity.Info ? GInfo : GWarn;
                bannerIcon.ForeColor = info.Severity == Severity.Error ? RedText : info.Severity == Severity.Warning ? AmberText : AccentInk;
                bannerTitle.Text = problem.Code + " · " + info.Title;
                bannerText.Text = Trim(info.Summary, 120);
                bannerFix.Visible = info.Fix != FixKind.None;
                bannerFix.Text = info.Code == "NSF-301" || info.Code == "NSF-302" ? Loc.T("home.takeOverFix") : ErrorInfo.FixLabel(info.Fix);
                bannerFix.Kind = info.Severity == Severity.Error ? FlatBtn.Kinds.Danger : info.Severity == Severity.Warning ? FlatBtn.Kinds.Warning : FlatBtn.Kinds.Primary;
                int fw = Math.Min(220, Math.Max(130, (int)(TextRenderer.MeasureText(bannerFix.Text, Bold).Width / Theme.Scale) + 40));
                bannerFix.Bounds = R(648 - fw, 11, fw, 34);
                bannerTitle.Width = bannerText.Width = D(648 - fw - 58);
            }
            // if there is no problem and a new version exists: update banner
            var upd = Updater.Available;
            showingUpdate = problem == null && upd != null && !updateDismissed && !Updater.Skipped(upd) && !Actions.Scanning;
            if (showingUpdate)
            {
                banner.Fill = AccentSoft;
                banner.Stroke = AccentBorder;
                bannerIcon.Text = GRefresh;
                bannerIcon.ForeColor = AccentInk;
                bannerTitle.Text = Loc.T("home.updateReady", upd.Version);
                bannerText.Text = Loc.T("home.updateText");
                bannerFix.Visible = true;
                bannerFix.Text = Loc.T("home.update");
                bannerFix.Kind = FlatBtn.Kinds.Primary;
                bannerFix.Bounds = R(518, 11, 130, 34);
                bannerMore.Text = Loc.T("home.later");
                bannerMore.Glyph = null;
                bannerTitle.Width = bannerText.Width = D(460);
            }
            // portable copy: a one-time notice that can be closed for good
            if (switchOffered == null) switchOffered = InstallerSwitch.Offered;
            showingSwitch = problem == null && !showingUpdate && !Actions.Scanning && switchOffered == true && !App.Settings.InstallerHintDismissed;
            if (showingSwitch)
            {
                banner.Fill = AccentSoft;
                banner.Stroke = AccentBorder;
                bannerIcon.Text = GShield;
                bannerIcon.ForeColor = AccentInk;
                bannerTitle.Text = Loc.T("home.switchTitle");
                bannerText.Text = Loc.T("home.switchText");
                bannerFix.Visible = true;
                bannerFix.Text = Loc.T("home.switchButton");
                bannerFix.Kind = FlatBtn.Kinds.Primary;
                int fw = Math.Min(220, Math.Max(130, (int)(TextRenderer.MeasureText(bannerFix.Text, Bold).Width / Theme.Scale) + 40));
                bannerFix.Bounds = R(648 - fw, 11, fw, 34);
                bannerMore.Text = Loc.T("common.close");
                bannerMore.Glyph = null;
                bannerTitle.Width = bannerText.Width = D(648 - fw - 58);
            }
            else if (!showingUpdate)
            {
                bannerMore.Text = Loc.T("home.details");
                bannerMore.Glyph = GHelp;
            }
            // lowest priority: an information card of the conflict diagnosis (e.g. an active anti-cheat driver next to WinDivert)
            var notice = Conflicts.Latest?.Notice;
            shownNotice = problem == null && !showingUpdate && !showingSwitch && !Actions.Scanning && notice != null && !noticesClosed.Contains(NoticeKey(notice)) ? notice : null;
            if (shownNotice != null)
            {
                banner.Fill = AccentSoft;
                banner.Stroke = AccentBorder;
                bannerIcon.Text = GInfo;
                bannerIcon.ForeColor = AccentInk;
                BannerHeight(88, 3);
                bannerTitle.Text = shownNotice.Title.Text;
                bannerText.Text = (shownNotice.Short ?? shownNotice.Text).Text;
                chipTips.SetToolTip(bannerText, shownNotice.Text.Text);
                bannerFix.Visible = shownNotice.OpenProfiles;
                bannerFix.Text = Loc.T("home.notice.openProfiles");
                bannerFix.Kind = FlatBtn.Kinds.Primary;
                int fw = Math.Min(220, Math.Max(130, (int)(TextRenderer.MeasureText(bannerFix.Text, Bold).Width / Theme.Scale) + 40));
                bannerFix.Bounds = R(648 - fw, (88 - 34) / 2, fw, 34);
                bannerMore.Text = Loc.T("common.close");
                bannerMore.Glyph = null;
                bannerTitle.Width = bannerText.Width = D((shownNotice.OpenProfiles ? 648 - fw : 648) - 58);
            }
            Arrange(problem != null || showingUpdate || showingSwitch || shownNotice != null);

            // ------------------------------------------------ method card
            FillCombo(prof);
            pName.Text = prof.Name;
            // long names (e.g. "Discord + General (TLS + QUIC)") get a smaller font, then an ellipsis; the tooltip has the full text
            pName.AutoEllipsis = pDesc.AutoEllipsis = true;
            pName.Font = TextRenderer.MeasureText(prof.Name, H2).Width > pName.Width ? Big : H2;
            chipTips.SetToolTip(pName, prof.Name);
            pDesc.Text = prof.Description;
            if (pCmd != null) pCmd.Text = Trim(CommandPreview.Display(prof, App.Settings), 96);
            if (pCombo != null) pCombo.Enabled = st != EngineState.Starting && st != EngineState.Stopping && !Actions.Scanning;
            if (bChange != null) bChange.Enabled = !Actions.Scanning;

            // ------------------------------------------------ connection card
            var t = App.LastTest;
            if (Actions.Testing)
            {
                connIcon.Text = GRefresh; connIcon.ForeColor = AccentInk;
                connTitle.Text = Loc.T("home.testing"); connTitle.ForeColor = Theme.Text;
            }
            else if (t == null || t.Count == 0)
            {
                connIcon.Text = GInfo; connIcon.ForeColor = Gray;
                connTitle.Text = Loc.T("home.notTested"); connTitle.ForeColor = Theme.Text;
                connDetail.Text = Loc.T("home.testPrompt");
            }
            else
            {
                int ok = t.Count(r => r.Ok);
                int ms = ok > 0 ? (int)t.Where(r => r.Ok).Average(r => r.Ms) : 0;
                bool dnsBad = App.LastDnsOk == false;
                if (ok == t.Count && !dnsBad) { connIcon.Text = GCheck; connIcon.ForeColor = GreenText; connTitle.Text = Loc.T("home.reachable"); connTitle.ForeColor = GreenText; }
                else if (ok == 0) { connIcon.Text = GCancel; connIcon.ForeColor = RedText; connTitle.Text = Loc.T("home.noAccess"); connTitle.ForeColor = RedText; }
                else { connIcon.Text = GWarn; connIcon.ForeColor = AmberText; connTitle.Text = dnsBad && ok == t.Count ? Loc.T("home.dnsProblem") : Loc.T("home.partialAccess"); connTitle.ForeColor = AmberText; }
                connDetail.Text = Loc.T(ok > 0 ? "home.answeredAvg" : "home.answered", ok, t.Count, ms) + (ok < t.Count ? "\n" + Loc.T("home.failing", string.Join(", ", t.Where(r => !r.Ok).Select(r => r.Host))) : "");
                connTime.Text = Loc.T("home.lastTest") + " " + App.LastTestTime?.ToString("HH:mm:ss");
            }
            connDns.Text = App.LastDnsOk == true ? Loc.T("home.dnsCorrect") : App.LastDnsOk == false ? Loc.T("home.dnsWrong") : "";
            connDns.ForeColor = App.LastDnsOk == false ? RedText : App.LastDnsOk == true ? GreenText : Muted;
            bool discord = DiscordHelper.IsRunning;
            bDiscord.Visible = discord || simple;
            bDiscord.Text = discord ? Loc.T("home.restartDiscord") : Loc.T("home.openDiscord");

            // ------------------------------------------------ session card
            if (cSession != null)
            {
                modeVal.Text = serviceShown ? Loc.T("home.mode.service") : Loc.T("home.mode.app");
                dnsVal.Text = prof.DnsLabel;
                // Zapret and ByeDPI always use the Windows DNS (a valid choice, not a missing setting): no warning colour for them
                dnsVal.ForeColor = prof.UsesDnsRedirect || !prof.IsGoodbyeDpi ? Theme.Text : AmberText;
                targetVal.Text = (App.Settings.TargetedMode ? Loc.T("home.targetedOn", App.Settings.TargetDomains.Count) : Loc.T("home.targetedOff")) +
                                 (Hostlists.ExcludeOn(App.Settings) ? " · " + Loc.T("home.excludedCount", App.Settings.ExcludeDomains.Count) : "");
                scanVal.Text = App.Settings.LastScanTime.HasValue ? App.Settings.LastScanTime.Value.ToString("dd.MM HH:mm") : Loc.T("home.never");
            }
            UpdateUptime();
        }

        /// <summary>Places the chips in one row under the buttons; if they do not fit, only the values are shown.</summary>
        void LayoutChips()
        {
            var chips = new[] { chipEngine, chipMode, chipDns, chipUp };
            int gap = D(8), avail = D(496);
            int ChipW(StatusChip c, bool compact) => c.PreferredWidth(compact, c == chipUp ? "000:00:00" : null);
            bool compact = chips.Sum(c => ChipW(c, false)) + gap * (chips.Length - 1) > avail;
            int x = D(252);
            foreach (var c in chips)
            {
                c.Compact = compact;
                int w = Math.Min(ChipW(c, compact), avail - (x - D(252)));
                c.Bounds = new Rectangle(x, D(200), Math.Max(D(40), w), D(28));
                chipTips.SetToolTip(c, c.Label + ": " + c.Value);
                x += c.Width + gap;
            }
        }

        void UpdateUptime()
        {
            if (!Visible) return;
            var s = App.Engine.StartedAt;
            string text = "—";
            bool on = App.Engine.State == EngineState.Running && s.HasValue;
            if (on)
            {
                var d = DateTime.Now - s.Value;
                text = ((int)d.TotalHours).ToString("00") + ":" + d.Minutes.ToString("00") + ":" + d.Seconds.ToString("00");
            }
            chipUp.Value = text;
            chipUp.Tone = on ? Green : Gray;
            if (upVal == null) return;
            upVal.Text = text;
            upVal.ForeColor = on ? Theme.Text : Muted;
        }

        static string Trim(string s, int n)
        {
            s = s ?? "";
            return s.Length <= n ? s : s.Substring(0, n - 1) + "…";
        }
    }
}
