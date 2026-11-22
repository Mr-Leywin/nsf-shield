using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using static NSFShield.Theme;

namespace NSFShield
{
    /// <summary>
    /// The smart scanner window. Simple: one button ("Find a working method and connect": the recommended candidates of every
    /// engine, stop at the first full success, apply it). Standard: scope, mode, auto apply and, on request, the candidate
    /// list. Advanced: the candidate matrix, the scan targets, technical columns and the layer results of a row.
    /// </summary>
    sealed class ScanDialog : Form
    {
        readonly UiLevel level;
        readonly bool simple, advanced;
        readonly ScanRequest preset;
        readonly ReportBox report, detail;
        readonly ProgressLine bar;
        readonly Label lblStep, lblPanelInfo, lblCount, lblTargetNote;
        readonly Segmented segScope, segMode, segPanel;
        readonly CheckX chkApply, chkCustom, chkWiden;
        readonly ListView lvCands, lvRes;
        readonly ListBox lbTargets;
        readonly TextBox tTarget;
        readonly FlatBtn bStart, bApply, bClose, bDiscord, bHelp, bAll, bRec, bNone, bAddT, bDelT, bResetT;
        readonly List<Control> candidateControls = new List<Control>(), targetControls = new List<Control>();
        readonly HashSet<string> chosen = new HashSet<string>();
        CancellationTokenSource cts;
        Scanner scanner;
        ScanOutcome outcome;
        bool running, closeWhenDone, filling;
        /// <summary>Screenshots only: the preview folder has no engine files.</summary>
        static bool debugFiles = false;

        /// <summary>Opens the window (nothing happens while a scan already runs). <paramref name="preset"/>: a fixed request (Simple, command line).</summary>
        public static void Run(IWin32Window owner, ScanRequest preset = null, bool autoStart = false)
        {
            if (Actions.Scanning) return;
            using (var d = new ScanDialog(App.Settings.UiLevel, preset))
            {
                if (autoStart) d.Shown += async (s, e) => await d.StartScan();
                d.ShowDialog(owner);
            }
        }

        /// <summary>The scan of the command line: --scan finds and applies, --scan-all compares the active engine's profiles.</summary>
        public static ScanRequest CommandLineRequest(bool all) =>
            all ? ScanRequest.ForScope(ScanScope.ActiveEngine, ScanMode.FullBenchmark, false, "cli")
                : App.Settings.UiLevel == UiLevel.Simple ? ScanRequest.SimpleConnect("cli")
                : ScanRequest.ForScope(App.Settings.ScanScope, ScanMode.StopOnFirstMatch, true, "cli");

        ScanDialog(UiLevel lvl, ScanRequest fixedRequest)
        {
            level = lvl;
            simple = lvl == UiLevel.Simple;
            advanced = lvl == UiLevel.Advanced;
            preset = fixedRequest ?? (simple ? ScanRequest.SimpleConnect() : null);
            Text = Loc.T("scanDialog.title") + " – " + App.Name;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterParent;
            MaximizeBox = MinimizeBox = false;
            ShowInTaskbar = false;
            AutoScaleMode = AutoScaleMode.None;
            BackColor = Bg;
            Font = Body;
            Icon = IconArt.AppIcon(32);
            int W = simple ? 760 : 900;
            ClientSize = new Size(D(W), D(simple ? 620 : 704));
            UIx.FitDialog(this);
            int inner = W - 48;

            Controls.Add(UIx.L(Loc.T("scanDialog.title"), H2, Theme.Text, 24, 14, inner, 30));
            Controls.Add(UIx.L(Loc.T(simple ? "scanDialog.introSimple" : "scanDialog.intro"), Small, Muted, 25, 46, inner, 40));

            int yStep;
            if (simple)
            {
                lblPanelInfo = UIx.L(Loc.T("scanDialog.simpleInfo", preset.Candidates.Count, Engines.All.Count(e => e.Available(out _))), Small, Theme.Text, 24, 90, inner, 40);
                Controls.Add(lblPanelInfo);
                yStep = 136;
            }
            else
            {
                Controls.Add(UIx.L(Loc.T("scanDialog.scopeTitle"), Caption, Muted, 24, 88, 400, 18));
                segScope = new Segmented(Loc.T("scanDialog.scope.Recommended"), Loc.T("scanDialog.scope.ActiveEngine"), Loc.T("scanDialog.scope.AllEngines"), Loc.T("scanDialog.scope.DriverlessOnly"))
                { Bounds = R(24, 108, 520, 32), BackColor = Bg };
                Controls.Add(segScope);
                Controls.Add(UIx.L(Loc.T("scanDialog.modeTitle"), Caption, Muted, 560, 88, 316, 18));
                segMode = new Segmented(Loc.T("scanDialog.mode.StopOnFirstMatch"), Loc.T("scanDialog.mode.FullBenchmark")) { Bounds = R(560, 108, 316, 32), BackColor = Bg };
                Controls.Add(segMode);
                chkApply = new CheckX { Text = Loc.T("scanDialog.autoApply"), Bounds = R(24, 150, 280, 24), BackColor = Bg, Checked = true };
                Controls.Add(chkApply);
                if (advanced)
                {
                    segPanel = new Segmented(Loc.T("scanDialog.panel.candidates"), Loc.T("scanDialog.panel.targets")) { Bounds = R(310, 146, 270, 30), BackColor = Bg };
                    Controls.Add(segPanel);
                    chkWiden = new CheckX { Text = Loc.T("scanDialog.widen"), Bounds = R(592, 150, 284, 24), BackColor = Bg };
                    Controls.Add(chkWiden);
                }
                else
                {
                    chkCustom = new CheckX { Text = Loc.T("scanDialog.customize"), Bounds = R(310, 150, 566, 24), BackColor = Bg };
                    Controls.Add(chkCustom);
                }

                // ------------------------------------------------ candidates (grouped by engine)
                lvCands = UIx.StyleList(new ListView
                {
                    Bounds = R(24, 182, 640, 150), View = View.Details, FullRowSelect = true, HeaderStyle = ColumnHeaderStyle.Nonclickable,
                    BorderStyle = BorderStyle.FixedSingle, Font = Small, MultiSelect = false, CheckBoxes = true, ShowGroups = true,
                });
                lvCands.Columns.Add(Loc.T("scanDialog.col.profile"), D(250));
                lvCands.Columns.Add(Loc.T("scanDialog.col.tier"), D(110));
                lvCands.Columns.Add(Loc.T("scanDialog.col.engine"), D(120));
                lvCands.Columns.Add(Loc.T("scanDialog.col.state"), D(140));
                lvCands.BackColor = Input;
                lvCands.ItemChecked += (s, e) =>
                {
                    if (filling || !(e.Item.Tag is Profile p)) return;
                    if (e.Item.Checked) chosen.Add(p.Id); else chosen.Remove(p.Id);
                    UpdateCount();
                };
                Controls.Add(lvCands);
                bAll = Btn(Loc.T("scanDialog.selectAll"), 676, 182, 200, 30);
                bRec = Btn(Loc.T("scanDialog.selectRecommended"), 676, 218, 200, 30);
                bNone = Btn(Loc.T("scanDialog.selectNone"), 676, 254, 200, 30);
                lblCount = UIx.L("", Small, Muted, 676, 290, 200, 42);
                Controls.Add(lblCount);
                bAll.Click += (s, e) => SetChecks(p => true);
                bRec.Click += (s, e) => SetChecks(p => p.Tier == ProfileTier.Recommended);
                bNone.Click += (s, e) => SetChecks(p => false);
                candidateControls.AddRange(new Control[] { lvCands, bAll, bRec, bNone, lblCount });
                lblPanelInfo = UIx.L("", Small, Theme.Text, 24, 182, 852, 150);
                Controls.Add(lblPanelInfo);

                if (advanced)
                {
                    // ------------------------------------------------ scan targets (strict host names)
                    lbTargets = Theme.Style(new ListBox { Bounds = R(24, 182, 400, 150), Font = Body, IntegralHeight = false, BorderStyle = BorderStyle.FixedSingle });
                    tTarget = Theme.Style(new TextBox { Bounds = R(436, 184, 280, 26), Font = Body });
                    tTarget.KeyDown += (s, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; AddTarget(); } };
                    bAddT = Btn(Loc.T("scanDialog.addTarget"), 726, 182, 150, 30);
                    bDelT = Btn(Loc.T("scanDialog.removeTarget"), 436, 220, 200, 30);
                    bResetT = Btn(Loc.T("scanDialog.resetTargets"), 646, 220, 230, 30);
                    lblTargetNote = UIx.L(Loc.T("scanDialog.targetNote", ScanTargets.MaxTargets), Small, Muted, 436, 258, 440, 74);
                    Controls.Add(lbTargets); Controls.Add(tTarget); Controls.Add(lblTargetNote);
                    bAddT.Click += (s, e) => AddTarget();
                    bDelT.Click += (s, e) => RemoveTarget();
                    bResetT.Click += (s, e) => { App.Settings.TestTargets = AppSettings.DefaultTestHosts.ToList(); App.Save(); FillTargets(); };
                    targetControls.AddRange(new Control[] { lbTargets, tTarget, bAddT, bDelT, bResetT, lblTargetNote });
                    segPanel.SelectedChanged += (s, e) => ShowPanel();
                    FillTargets();
                }
                yStep = 342;
            }

            lblStep = UIx.L(Loc.T("scanDialog.ready"), Bold, Theme.Text, 24, yStep, inner, 22);
            Controls.Add(lblStep);
            bar = new ProgressLine { Bounds = R(24, yStep + 24, inner, 6), BackColor = Bg };
            Controls.Add(bar);

            // ------------------------------------------------ results
            int yRes = yStep + 38, hRes = simple ? 170 : advanced ? 140 : 150;
            lvRes = UIx.StyleList(new ListView
            {
                Bounds = R(24, yRes, inner, hRes), View = View.Details, FullRowSelect = true, HeaderStyle = ColumnHeaderStyle.Nonclickable,
                BorderStyle = BorderStyle.FixedSingle, Font = Small, MultiSelect = false,
            });
            if (simple)
            {
                Col(Loc.T("scanDialog.col.profile"), 220); Col(Loc.T("scanDialog.col.engine"), 120); Col(Loc.T("scanDialog.col.result"), 190);
                Col(Loc.T("scanDialog.col.score"), 70); Col(Loc.T("scanDialog.col.latency"), 80);
            }
            else
            {
                Col(Loc.T("scanDialog.col.engine"), 110); Col(Loc.T("scanDialog.col.profile"), advanced ? 210 : 250); Col(Loc.T("scanDialog.col.result"), 120);
                Col(Loc.T("scanDialog.col.score"), 62); Col(Loc.T("scanDialog.col.latency"), 80); Col(Loc.T("scanDialog.col.udp"), advanced ? 130 : 200);
                if (advanced) Col(Loc.T("scanDialog.col.layers"), 120);
            }
            lvRes.BackColor = Input;
            lvRes.SelectedIndexChanged += (s, e) => { UpdateButtons(); ShowRowDetail(); };
            Controls.Add(lvRes);
            FitLast(lvRes);

            int yLog = yRes + hRes + 8, hLog = simple ? 194 : (704 - 56) - yLog - 10;
            var card = new Card { Bounds = R(24, yLog, advanced ? 420 : inner, hLog) };
            Controls.Add(card);
            report = new ReportBox { Bounds = R(12, 8, (advanced ? 420 : inner) - 24, hLog - 16) };
            card.Add(report);
            report.BackColor = Theme.Card;
            report.Muted(Loc.T(simple ? "scanDialog.pressStartSimple" : "scanDialog.pressStart"));
            if (advanced)
            {
                var dc = new Card { Bounds = R(456, yLog, 420, hLog) };
                Controls.Add(dc);
                detail = new ReportBox { Bounds = R(12, 8, 396, hLog - 16) };
                dc.Add(detail);
                detail.BackColor = Theme.Card;
                detail.Muted(Loc.T("scanDialog.detailHint"));
            }

            // ------------------------------------------------ buttons
            int yb = simple ? 568 : 652;
            bStart = new FlatBtn { Text = Loc.T(simple ? "scanDialog.findAndConnect" : "scanDialog.start"), Glyph = GSearch, Kind = FlatBtn.Kinds.Primary, Bounds = R(24, yb, simple ? 260 : 200, 40), BackColor = Bg };
            bApply = new FlatBtn { Text = Loc.T("scanDialog.apply"), Glyph = GCheck, Kind = FlatBtn.Kinds.Secondary, Bounds = R(234, yb, 180, 40), BackColor = Bg, Visible = !simple, Enabled = false };
            bDiscord = new FlatBtn { Text = Loc.T("scanDialog.restartDiscord"), Glyph = GRefresh, Kind = FlatBtn.Kinds.Secondary, Bounds = R(simple ? 294 : 424, yb, 210, 40), BackColor = Bg, Visible = false };
            bHelp = new FlatBtn { Text = Loc.T("scanDialog.viewCode"), Glyph = GHelp, Kind = FlatBtn.Kinds.Secondary, Bounds = R(simple ? 294 : 424, yb, 210, 40), BackColor = Bg, Visible = false };
            bClose = new FlatBtn { Text = Loc.T("common.close"), Kind = FlatBtn.Kinds.Secondary, Bounds = R(W - 144, yb, 120, 40), BackColor = Bg };
            Controls.AddRange(new Control[] { bStart, bApply, bDiscord, bHelp, bClose });
            bStart.Click += async (s, e) => await StartScan();
            bClose.Click += (s, e) => Close();
            bApply.Click += async (s, e) => await ApplySelected();
            bDiscord.Click += async (s, e) =>
            {
                bDiscord.Enabled = false;
                string msg = await Actions.RestartDiscordAsync();
                if (IsDisposed) return;
                report.Out(msg, GreenText, Bold);
                bDiscord.Enabled = true;
            };
            bHelp.Click += (s, e) =>
            {
                string code = outcome?.FailCode;
                Close();
                MainForm.Instance.ShowFromTray();
                MainForm.Instance.Go<TroublePage>("trouble")?.ShowCode(code);
            };

            if (!simple)
            {
                // the window opens with the request it was given, or with the saved choices (the "try all" choice = comparison)
                var scope = preset?.Scope ?? App.Settings.ScanScope;
                var mode = preset?.Mode ?? (App.Settings.ScanAll ? ScanMode.FullBenchmark : ScanMode.StopOnFirstMatch);
                segScope.SetSilently((int)scope);
                segMode.SetSilently((int)mode);
                chkApply.Checked = preset?.AutoApply ?? true;
                if (preset != null) foreach (var id in preset.CandidateIds) chosen.Add(id);
                segScope.SelectedChanged += (s, e) =>
                {
                    App.Settings.ScanScope = (ScanScope)segScope.SelectedIndex;
                    App.Save();
                    chosen.Clear();
                    FillCandidates();
                };
                segMode.SelectedChanged += (s, e) =>
                {
                    App.Settings.ScanAll = segMode.SelectedIndex == 1;
                    App.Save();
                    UpdateButtons();
                };
                if (chkCustom != null) chkCustom.CheckedChanged += (s, e) => ShowPanel();
                FillCandidates();
                ShowPanel();
            }
            UpdateButtons();
        }

        FlatBtn Btn(string text, int x, int y, int w, int h)
        {
            var b = new FlatBtn { Text = text, Kind = FlatBtn.Kinds.Secondary, Bounds = R(x, y, w, h), BackColor = Bg, Font = Small };
            Controls.Add(b);
            return b;
        }

        void Col(string text, int w) => lvRes.Columns.Add(text, D(w));

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        static extern int GetWindowLong(IntPtr hWnd, int index);

        /// <summary>
        /// The last column takes the rest of the row (no unpainted header area, no horizontal scroll bar); room is kept for a
        /// vertical scroll bar that the rows will need.
        /// </summary>
        static void FitLast(ListView lv)
        {
            if (lv == null || lv.Columns.Count == 0) return;
            int w = lv.ClientSize.Width;
            bool vscroll = (GetWindowLong(lv.Handle, -16) & 0x00200000) != 0;
            if (!vscroll && lv.Items.Count > 0)
            {
                var r = lv.GetItemRect(0);
                int rows = lv.Items.Count + (lv.ShowGroups ? lv.Groups.Count * 2 : 0);
                if (r.Top + r.Height * rows > lv.ClientSize.Height) w -= SystemInformation.VerticalScrollBarWidth;
            }
            int rest = w - lv.Columns.Cast<ColumnHeader>().Take(lv.Columns.Count - 1).Sum(c => c.Width) - 2;
            if (rest > D(40)) lv.Columns[lv.Columns.Count - 1].Width = rest;
        }

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            Native.DarkTitle(Handle, IsDark);
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (running)
            {
                // the window closes once the candidate is stopped and the restore result is known
                e.Cancel = true;
                cts?.Cancel();
                lblStep.Text = Loc.T("scanDialog.cancelling");
                bClose.Enabled = false;
                closeWhenDone = true;
                return;
            }
            base.OnFormClosing(e);
        }

        ScanScope Scope => segScope == null ? ScanScope.Recommended : (ScanScope)segScope.SelectedIndex;
        ScanMode Mode => segMode == null ? ScanMode.StopOnFirstMatch : (ScanMode)segMode.SelectedIndex;
        bool Customizing => advanced || (chkCustom?.Checked ?? false);

        /// <summary>The candidates of the scope, grouped by engine; unavailable engines are shown with their reason (NSF-107).</summary>
        void FillCandidates()
        {
            if (lvCands == null) return;
            var pool = ScanCatalog.Candidates(Scope, App.Engine.Current.Kind);
            if (chosen.Count == 0 || !chosen.Any(id => pool.Any(p => p.Id == id))) { chosen.Clear(); foreach (var p in pool) chosen.Add(p.Id); }
            filling = true;
            lvCands.BeginUpdate();
            lvCands.Items.Clear();
            lvCands.Groups.Clear();
            foreach (var eng in Engines.All)
            {
                var ps = pool.Where(p => p.Engine == eng.Kind).ToList();
                if (ps.Count == 0) continue;
                var g = new ListViewGroup(eng.DisplayName);
                lvCands.Groups.Add(g);
                bool ok = eng.Available(out var why);
                foreach (var p in ps)
                {
                    string state = ok ? (Engine.MissingFile(eng) == null || debugFiles ? Loc.T("scanDialog.state.ready") : Loc.T("scanDialog.state.missing")) : "NSF-107 · " + why.Text;
                    var it = new ListViewItem(new[] { p.Name, TierText(p), eng.DisplayName, state }, g)
                    { Tag = p, Checked = chosen.Contains(p.Id), ForeColor = ok ? Theme.Text : Muted, ToolTipText = p.Description };
                    lvCands.Items.Add(it);
                }
            }
            lvCands.EndUpdate();
            filling = false;
            // ids that are not in the scope any more are dropped
            chosen.IntersectWith(pool.Select(p => p.Id));
            UpdateCount();
        }

        static string TierText(Profile p) => Loc.T(p.BuiltIn ? "profiles.tier." + p.Tier : "profiles.tier.custom");

        void SetChecks(Func<Profile, bool> pick)
        {
            filling = true;
            foreach (ListViewItem it in lvCands.Items)
                if (it.Tag is Profile p) { it.Checked = pick(p); if (it.Checked) chosen.Add(p.Id); else chosen.Remove(p.Id); }
            filling = false;
            UpdateCount();
        }

        void UpdateCount()
        {
            if (lblCount == null) return;
            var pool = ScanCatalog.Candidates(Scope, App.Engine.Current.Kind);
            int n = pool.Count(p => chosen.Contains(p.Id));
            lblCount.Text = Loc.T("scanDialog.count", n, pool.Count);
            lblCount.ForeColor = n == 0 ? AmberText : Muted;
            if (lblPanelInfo != null && !Customizing)
            {
                var by = Engines.All.Select(e => (e, c: pool.Count(p => p.Engine == e.Kind))).Where(x => x.c > 0).Select(x => x.e.DisplayName + " " + x.c);
                lblPanelInfo.Text = Loc.T("scanDialog.scopeInfo", pool.Count, string.Join(" · ", by)) + "\n" + Loc.T("scanDialog.scopeHint." + Scope);
            }
            UpdateButtons();
        }

        void ShowPanel()
        {
            bool targets = advanced && segPanel.SelectedIndex == 1;
            foreach (var c in candidateControls) c.Visible = Customizing && !targets;
            foreach (var c in targetControls) c.Visible = targets;
            if (lblPanelInfo != null) lblPanelInfo.Visible = !Customizing;
            UpdateCount();
        }

        // ------------------------------------------------------------------ targets (Advanced)

        void FillTargets()
        {
            lbTargets.BeginUpdate();
            lbTargets.Items.Clear();
            foreach (var t in App.Settings.TestTargets) lbTargets.Items.Add(t);
            lbTargets.EndUpdate();
        }

        void AddTarget()
        {
            string raw = tTarget.Text;
            // checked as typed: nothing is trimmed or cut off; only the letter case does not matter in DNS
            if (!ScanTargets.IsValid(raw.ToLowerInvariant(), out string why))
            {
                lblTargetNote.Text = "✗ " + Loc.T(why);
                lblTargetNote.ForeColor = RedText;
                return;
            }
            string d = raw.ToLowerInvariant();
            if (App.Settings.TestTargets.Count >= ScanTargets.MaxTargets)
            {
                lblTargetNote.Text = "✗ " + Loc.T("scanDialog.tooManyTargets", ScanTargets.MaxTargets);
                lblTargetNote.ForeColor = RedText;
                return;
            }
            if (!App.Settings.TestTargets.Contains(d)) App.Settings.TestTargets.Add(d);
            App.Save();
            tTarget.Text = "";
            lblTargetNote.Text = Loc.T("scanDialog.targetNote", ScanTargets.MaxTargets);
            lblTargetNote.ForeColor = Muted;
            FillTargets();
        }

        void RemoveTarget()
        {
            if (!(lbTargets.SelectedItem is string t) || App.Settings.TestTargets.Count <= 1) return;
            App.Settings.TestTargets.Remove(t);
            App.Save();
            FillTargets();
        }

        // ------------------------------------------------------------------ run

        /// <summary>The request of the current choices (fixed from here on).</summary>
        ScanRequest BuildRequest()
        {
            if (simple) return ScanRequest.SimpleConnect(preset?.Source ?? "simple");
            var pool = ScanCatalog.Candidates(Scope, App.Engine.Current.Kind);
            var ids = Customizing ? pool.Where(p => chosen.Contains(p.Id)).Select(p => p.Id) : pool.Select(p => p.Id);
            return ScanRequest.Create(Scope, Mode, chkApply.Checked && Mode == ScanMode.StopOnFirstMatch, ids, App.Settings.TestTargets,
                                      chkWiden?.Checked ?? false, true, preset?.Source ?? "dialog");
        }

        void SetOptionsEnabled(bool on)
        {
            foreach (var c in new Control[] { segScope, segMode, chkApply, chkCustom, chkWiden, segPanel, bAll, bRec, bNone, bAddT, bDelT, bResetT, tTarget })
                if (c != null) c.Enabled = on;
            if (lvCands != null) lvCands.Enabled = on;
        }

        internal async Task StartScan()
        {
            if (running || Actions.Scanning) return;
            var req = BuildRequest();
            running = true;
            bStart.Enabled = false;
            bApply.Enabled = false;
            SetOptionsEnabled(false);
            bDiscord.Visible = bHelp.Visible = false;
            bClose.Text = Loc.T("common.cancel");
            report.Clear();
            lvRes.Items.Clear();
            detail?.Clear();
            outcome = null;
            cts = new CancellationTokenSource();
            scanner = new Scanner(req);
            scanner.Line += (text, kind) =>
            {
                if (IsDisposed) return;
                switch (kind)
                {
                    case ScanLineKind.Step: report.Out(text, Theme.Text, Bold); break;
                    case ScanLineKind.Good: report.Out(text, GreenText); break;
                    case ScanLineKind.Warn: report.Out(text, AmberText); break;
                    case ScanLineKind.Bad: report.Out(text, RedText); break;
                    case ScanLineKind.Muted: report.Out(text, Muted, Small); break;
                    default: report.Out(text); break;
                }
            };
            scanner.Progress += (done, total, label) =>
            {
                if (IsDisposed) return;
                bar.Value = total == 0 ? 0 : done / (float)total;
                lblStep.Text = done >= total && total > 0 ? Loc.T("scanDialog.finished") : Loc.T("scanDialog.trying", label, done + 1, total);
            };
            scanner.RowChanged += r => { if (!IsDisposed) ShowRow(r); };
            var sw = Stopwatch.StartNew();
            try { outcome = await scanner.RunAsync(cts.Token); }
            catch (Exception ex) { report.Bad(Loc.T("common.error", ex.Message)); }
            running = false;
            if (IsDisposed) return;
            Done(outcome, (int)sw.Elapsed.TotalSeconds);
            if (closeWhenDone) Close();
        }

        void Done(ScanOutcome o, int seconds)
        {
            bar.Value = 1;
            string head = o == null ? Loc.T("scanDialog.done")
                        : o.Busy ? Loc.T("scan.busy")
                        : o.Applied != null ? Loc.T("scanDialog.doneApplied", o.Applied.Name)
                        : o.Suggested != null ? Loc.T("scanDialog.doneWith", o.Suggested.P.Name)
                        : Loc.T("scanDialog.done");
            lblStep.Text = head + "  ·  " + seconds + " " + Loc.T("common.secondsShort");
            bClose.Text = Loc.T("common.close");
            bClose.Enabled = true;
            bStart.Enabled = true;
            bStart.Text = Loc.T(simple ? "scanDialog.findAndConnect" : "scanDialog.again");
            SetOptionsEnabled(true);
            if (o == null) return;
            if (o.Applied != null)
            {
                report.Blank();
                if (DiscordHelper.IsRunning) { report.Out(Loc.T("scanDialog.discordOpen"), AccentInk, Bold); bDiscord.Visible = true; }
                else report.Muted(Loc.T("scanDialog.openDiscordNow"));
            }
            else if (o.Suggested != null && !simple)
            {
                report.Blank();
                report.Out(Loc.T(o.Request.Mode == ScanMode.FullBenchmark ? "scanDialog.pickAndApply" : "scanDialog.notApplied"), AccentInk, Bold);
                SelectRow(o.Suggested);
            }
            else if (!string.IsNullOrEmpty(o.FailCode))
            {
                var info = ErrorCatalog.Get(o.FailCode);
                report.Blank();
                report.Out(Loc.T("scanDialog.whatToDo", o.FailCode, info?.Title), Theme.Text, Bold);
                if (info != null) foreach (var st in info.Steps) report.Out("  • " + st, Theme.Text, Small);
                bHelp.Visible = true;
            }
            UpdateButtons();
        }

        // ------------------------------------------------------------------ results table

        void ShowRow(ScanRow r)
        {
            ListViewItem it = lvRes.Items.Cast<ListViewItem>().FirstOrDefault(x => ReferenceEquals(x.Tag, r));
            var cells = RowCells(r);
            if (it == null)
            {
                it = new ListViewItem(cells) { Tag = r };
                lvRes.Items.Add(it);
                FitLast(lvRes);
                it.EnsureVisible();
            }
            else for (int i = 0; i < cells.Length; i++) it.SubItems[i].Text = cells[i];
            it.ForeColor = r.IsFull ? GreenText : r.Status == ScanRow.Partial ? AmberText : r.Status == ScanRow.Testing ? Theme.Text : r.Measured ? RedText : Muted;
            if (lvRes.SelectedItems.Count > 0 && ReferenceEquals(lvRes.SelectedItems[0].Tag, r)) ShowRowDetail();
        }

        string[] RowCells(ScanRow r)
        {
            string score = r.Score.HasValue ? r.Score + "%" : "—";
            string ms = r.AvgMs.HasValue ? r.AvgMs + " ms" : "—";
            string result = r.StatusText + (outcome?.Applied != null && outcome.Applied.Id == r.P.Id ? " · " + Loc.T("scanDialog.appliedMark") : "");
            if (simple) return new[] { r.P.Name, r.Engine.DisplayName, result, score, ms };
            string udp = r.Udp != null ? Scanner.StunText(r.Udp) : r.Measured ? "—" : (r.Note?.Text ?? "");
            var cells = new List<string> { r.Engine.DisplayName, r.P.Name, result, score, ms, udp };
            if (advanced)
            {
                var first = r.Targets.FirstOrDefault(t => t.InScope && t.R1 != null);
                cells.Add(r.Measured ? r.PassedBoth + "/" + r.Required + (first != null ? " · " + first.R1.Layers.Replace(" · ", " ") : "") : r.Code);
            }
            return cells.ToArray();
        }

        void SelectRow(ScanRow r)
        {
            foreach (ListViewItem it in lvRes.Items)
                if (ReferenceEquals(it.Tag, r)) { it.Selected = true; it.EnsureVisible(); break; }
        }

        ScanRow SelectedRow => lvRes.SelectedItems.Count > 0 ? lvRes.SelectedItems[0].Tag as ScanRow : null;

        /// <summary>Advanced: the layers of every target in both rounds, the capture/UDP meaning, the reason of a skip.</summary>
        void ShowRowDetail()
        {
            if (detail == null) return;
            var r = SelectedRow;
            detail.Clear();
            if (r == null) { detail.Muted(Loc.T("scanDialog.detailHint")); return; }
            detail.Out(r.P.Name + " · " + r.Engine.DisplayName, Theme.Text, Bold);
            detail.Muted(string.Join(" · ", ProfileCatalog.TechnicalTags(r.P)));
            if (r.Note != null) detail.Out(r.Note.Text, AmberText, Small);
            foreach (var t in r.Targets)
            {
                if (!t.InScope) { detail.Out(t.Host + " — " + Loc.T("scanDialog.outOfScope"), Muted, Small); continue; }
                string base0 = outcome?.Baseline.FirstOrDefault(b => b.Host == t.Host)?.R1?.Verdict == TargetVerdict.Pass ? " · " + Loc.T("scanDialog.openWithout") : "";
                detail.Out(t.Host + (ScanTargets.IsGateway(t.Host) ? " · " + Loc.T("scan.gateway.name") : "") + base0, Theme.Text, Small);
                foreach (var (n, x) in new[] { ("1", t.R1), ("2", t.R2) })
                    if (x != null)
                        detail.Out("  " + n + ") " + x.Layers + (x.TotalMs.HasValue ? " · " + x.TotalMs + " ms" : "") + (x.Ip.Length > 0 ? " · " + x.Ip : "") +
                                   (x.Detail != null ? " · " + x.Detail.Text : ""), x.Verdict == TargetVerdict.Pass ? GreenText : x.Verdict == TargetVerdict.Partial ? AmberText : RedText, MonoSmall);
            }
            if (r.Udp != null) detail.Out("UDP/STUN: " + Scanner.StunText(r.Udp), Muted, Small);
            detail.SelectionStart = 0;
            detail.ScrollToCaret();
        }

        void UpdateButtons()
        {
            if (bApply == null) return;
            var r = SelectedRow;
            bool valid = r != null && (r.IsFull || r.Status == ScanRow.Partial) && ArgPolicy.ValidateProfile(r.P, out _) && r.Engine.Available(out _);
            bApply.Enabled = !running && !simple && outcome != null && !outcome.Busy && valid && outcome.Applied?.Id != r.P.Id;
            bApply.Kind = r != null && r.IsFull ? FlatBtn.Kinds.Primary : FlatBtn.Kinds.Secondary;
        }

        /// <summary>The user applies a compared result: after the restore, through the normal start (rolls back if it fails).</summary>
        async Task ApplySelected()
        {
            var r = SelectedRow;
            if (r == null || running || Actions.Scanning) return;
            var p = App.FindProfile(r.P.Id);
            if (p == null) { report.Bad(Loc.T("scanDialog.profileGone")); return; }
            bApply.Enabled = false;
            bool ok = await Actions.ApplyProfileAsync(p);
            if (IsDisposed) return;
            if (ok)
            {
                report.Out(Loc.T("scanDialog.appliedNow", p.Name), GreenText, Bold);
                if (outcome != null) outcome.Applied = p;
                foreach (ListViewItem it in lvRes.Items) if (it.Tag is ScanRow sr) ShowRow(sr);
                if (DiscordHelper.IsRunning) bDiscord.Visible = true;
            }
            else report.Bad(Loc.T("scanDialog.applyFailed", p.Name, App.Engine.LastErrorCode, App.Engine.LastError));
            UpdateButtons();
        }

#if PREVIEW
        /// <summary>A window with a fixed example result (screenshots; nothing is scanned or changed).</summary>
        internal static ScanDialog DebugCreate(UiLevel lvl, ScanOutcome sample)
        {
            debugFiles = true;
            var d = new ScanDialog(lvl, null);
            debugFiles = false;
            d.outcome = sample;
            foreach (var r in sample.Rows) d.ShowRow(r);
            d.report.Clear();
            foreach (var line in new[] { ("1/4  " + Loc.T("scan.step.internet"), ScanLineKind.Step), ("   ✓ " + Loc.T("scan.pretestOk"), ScanLineKind.Good),
                                         ("2/4  " + Loc.T("scan.step.dns"), ScanLineKind.Step), ("   ✓ " + new LocText("scan.dnsVerdict.DifferentPublic", "discord.com").Text, ScanLineKind.Good),
                                         ("3/4  " + Loc.T("scan.step.baseline"), ScanLineKind.Step), ("   " + Loc.T("scan.baseline", 0, 6), ScanLineKind.Muted),
                                         ("4/4  " + Loc.T(sample.Request?.Mode == ScanMode.FullBenchmark ? "scan.step.benchmark" : "scan.step.firstMatch", sample.Request?.Candidates.Count ?? sample.Rows.Count), ScanLineKind.Step) })
                d.report.Out(line.Item1, line.Item2 == ScanLineKind.Step ? Theme.Text : line.Item2 == ScanLineKind.Good ? GreenText : Muted, line.Item2 == ScanLineKind.Step ? Bold : Small);
            if (sample.Summary != null) d.report.Out("✓ " + sample.Summary.Text, GreenText);
            d.lblStep.Text = (sample.Suggested != null ? Loc.T("scanDialog.doneWith", sample.Suggested.P.Name) : Loc.T("scanDialog.done")) + "  ·  94 " + Loc.T("common.secondsShort");
            d.bar.Value = 1;
            if (sample.Suggested != null) d.SelectRow(sample.Suggested);
            d.UpdateButtons();
            return d;
        }
#endif
    }

    /// <summary>Actions of the "Fix" buttons in the error codes.</summary>
    static class Fixes
    {
        public static async Task<string> Run(FixKind f, IWin32Window owner)
        {
            var mf = MainForm.Instance;
            switch (f)
            {
                case FixKind.RestartAsAdmin:
                    try
                    {
                        Process.Start(new ProcessStartInfo(Application.ExecutablePath) { Verb = "runas", UseShellExecute = true });
                        mf.ExitApp(false);
                    }
                    catch { return Loc.T("fix.denied"); }
                    return null;
                case FixKind.OpenAppFolder: Sys.OpenFolder(App.BaseDir); return Loc.T("fix.folderOpened", App.BaseDir);
                case FixKind.ReportFalsePositive:
                    Sys.OpenAsUser(App.WdsiUrl);
                    return Loc.T("fix.falsePositive");
                case FixKind.ResetAll:
                    if (MessageBox.Show(owner, Loc.T("fix.resetConfirm"),
                            App.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return null;
                    await Task.Run(() => App.Engine.ResetAll());
                    App.Settings.ServiceMode = false;
                    App.Save();
                    {
                        bool proxySet = ProxyTools.HasRecord, dnsSet = App.Settings.DnsBackups.Count > 0 || App.Settings.DohBackups.Count > 0;
                        if ((proxySet || dnsSet) && MessageBox.Show(owner,
                                Loc.T(proxySet && dnsSet ? "fix.restoreBoth" : proxySet ? "fix.restoreProxy" : "fix.restoreDns"), App.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                        {
                            await Task.Run(() =>
                            {
                                if (proxySet) ProxyTools.RestoreSystem();
                                if (dnsSet) SystemDns.Restore(out _, onlyBackups: true);
                            });
                            return Loc.T("fix.resetDoneRestored");
                        }
                    }
                    return Loc.T("fix.resetDone");
                case FixKind.ResolveConflicts:
                    await Task.Run(() => App.Engine.ResolveConflicts());
                    if (!App.Engine.IsActive) await Actions.StartAsync();
                    return Loc.T("fix.conflictsResolved");
                case FixKind.FlushDns:
                    Native.FlushDns();
                    App.Log("DNS cache flushed.", LogLevel.Info);
                    return Loc.T("fix.dnsFlushed");
                case FixKind.FindBest: ScanDialog.Run(owner); return null;
                case FixKind.OpenProfiles: mf.Navigate("profiles"); return null;
                case FixKind.OpenDnsPage: mf.Navigate("dns"); return null;
                case FixKind.TestDnsServers: mf.Go<NetPage>("net")?.ShowTab(2, true); return null;
                case FixKind.SiteAnalysis: mf.Go<NetPage>("net")?.ShowTab(1, false); return null;
                case FixKind.StartBfe:
                    {
                        var r = await Task.Run(() =>
                        {
                            Engine.Sc("config BFE start= auto");
                            return Engine.Sc("start BFE");
                        });
                        return r.Code == 0 || r.Output.Contains("1056") ? Loc.T("fix.bfeStarted") : Loc.T("fix.bfeFailed", r.Output);
                    }
                case FixKind.OpenWindowsSecurity: Sys.OpenUri("windowsdefender://threat/"); return null;
                case FixKind.RestartDiscord: return await Actions.RestartDiscordAsync();
                case FixKind.StartProtection: await Actions.StartAsync(); return App.Engine.State == EngineState.Running ? Loc.T("fix.protectionRestarted") : App.Engine.LastError;
                case FixKind.OpenLog: mf.Navigate("log"); return null;
                case FixKind.OpenSites: mf.Navigate("sites"); return null;
                case FixKind.OpenProxySettings: Sys.OpenUri("ms-settings:network-proxy"); return null;
                case FixKind.OpenDateTime: Sys.OpenUri("ms-settings:dateandtime"); return null;
                case FixKind.OpenSettings: mf.Navigate("settings"); return null;
                case FixKind.OpenProxyPage: mf.Navigate("proxy"); return null;
                case FixKind.OpenHosts: Sys.SelectFile(NetTest.HostsPath); return Loc.T("fix.hostsSelected");
                case FixKind.DisableServiceMode:
                    App.Settings.ServiceMode = false;
                    App.Save();
                    await Task.Run(() => App.Engine.UninstallService());
                    await Actions.StartAsync();
                    return Loc.T("fix.appMode");
            }
            return null;
        }
    }
}
