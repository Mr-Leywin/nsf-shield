using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using static NSFShield.Theme;

namespace NSFShield
{
    /// <summary>Troubleshooting: full check (Find the Problem) and the error code guide.</summary>
    sealed class TroublePage : PageBase
    {
        public override string Key => "trouble";

        readonly Segmented tabs;
        readonly Panel pCheck, pCodes;
        // find the problem
        readonly FlatBtn bRun;
        readonly Label runStatus;
        readonly ScrollArea rowsArea;
        int rowY;
        bool checking;
        // error codes
        readonly ThemedCombo cat;
        readonly TextBox search;
        readonly ListBox codes;
        readonly ReportBox info;
        readonly FlatBtn bFix1, bFix2, bCopy;

        public TroublePage()
        {
            Header(Loc.T("troublePage.title"), Loc.T("troublePage.subtitle"));
            tabs = new Segmented(Loc.T("troublePage.tab.find"), Loc.T("troublePage.tab.codes")) { Bounds = R(28, 76, 420, 36), BackColor = Bg };
            Controls.Add(tabs);
            pCheck = new Panel { Bounds = R(0, 124, 820, 516), BackColor = Bg };
            pCodes = new Panel { Bounds = R(0, 124, 820, 516), BackColor = Bg, Visible = false };
            Controls.Add(pCheck);
            Controls.Add(pCodes);
            tabs.SelectedChanged += (s, e) => { pCheck.Visible = tabs.SelectedIndex == 0; pCodes.Visible = tabs.SelectedIndex == 1; };

            // ================================================ find the problem
            bRun = new FlatBtn { Text = Loc.T("troublePage.runFull"), Glyph = GSearch, Kind = FlatBtn.Kinds.Primary, Bounds = R(28, 0, 220, 40), BackColor = Bg };
            pCheck.Controls.Add(bRun);
            bRun.Click += async (s, e) => await RunCheck();
            runStatus = UIx.L(Loc.T("troublePage.runInfo"),
                Small, Muted, 258, 0, 270, 40, ContentAlignment.MiddleLeft);
            runStatus.AutoEllipsis = true;   // a long result text ends with "…" instead of being cut; the tooltip has all of it
            var statusTip = new ToolTip();
            runStatus.TextChanged += (s, e) => statusTip.SetToolTip(runStatus, runStatus.Text);
            pCheck.Controls.Add(runStatus);
            var bPack = new FlatBtn { Text = Loc.T("troublePage.supportPack"), Glyph = GSave, Kind = FlatBtn.Kinds.Secondary, Bounds = R(534, 2, 128, 36), BackColor = Bg, Font = Small };
            var bIssue = new FlatBtn { Text = Loc.T("troublePage.report"), Glyph = GLink, Kind = FlatBtn.Kinds.Secondary, Bounds = R(668, 2, 124, 36), BackColor = Bg, Font = Small };
            pCheck.Controls.Add(bPack);
            pCheck.Controls.Add(bIssue);
            new ToolTip().SetToolTip(bPack, Loc.T("troublePage.supportTip"));
            new ToolTip().SetToolTip(bIssue, Loc.T("troublePage.issueTip"));
            bPack.Click += async (s, e) =>
            {
                using (var d = new SaveFileDialog { FileName = "NSF-Shield-support-" + DateTime.Now.ToString("yyyyMMdd-HHmm") + ".zip", Filter = Loc.T("troublePage.zipFilter") })
                {
                    if (d.ShowDialog(FindForm()) != DialogResult.OK) return;
                    bPack.Enabled = false;
                    try
                    {
                        string path = d.FileName;
                        await Task.Run(() => Support.CreatePackage(path));
                        Sys.SelectFile(path);
                        MessageBox.Show(FindForm(), Loc.T("troublePage.packSaved"), App.Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                    catch (Exception ex) { MessageBox.Show(FindForm(), Loc.T("troublePage.packFailed", ex.Message), App.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
                    finally { if (!IsDisposed) bPack.Enabled = true; }
                }
            };
            bIssue.Click += (s, e) =>
            {
                if (MessageBox.Show(FindForm(), Loc.T("troublePage.issueConfirm"), App.Name,
                        MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                    Sys.OpenAsUser(Support.IssueUrl());
            };
            rowsArea = new ScrollArea { Bounds = R(18, 52, 790, 462) };
            pCheck.Controls.Add(rowsArea);

            // ================================================ error codes
            var left = new Card { Bounds = R(28, 0, 330, 512) };
            pCodes.Controls.Add(left);
            cat = left.Add(new ThemedCombo { Bounds = R(12, 12, 306, 26) });
            cat.Items.Add(Loc.T("troublePage.allCategories", ErrorCatalog.All.Count));
            foreach (var c in ErrorCatalog.Categories) cat.Items.Add(ErrorCatalog.CategoryName(c) + " (" + ErrorCatalog.All.Count(e => e.Category == c) + ")");
            cat.SelectedIndex = 0;
            cat.SelectedIndexChanged += (s, e) => FillCodes();
            search = left.Add(Theme.Style(new TextBox { Bounds = R(12, 46, 306, 26), Font = Body }));
            SetCue(search, Loc.T("troublePage.searchCue"));
            search.TextChanged += (s, e) => FillCodes();
            codes = new ListBox
            {
                Bounds = R(6, 82, 318, 422), DrawMode = DrawMode.OwnerDrawFixed, ItemHeight = D(46),
                BorderStyle = BorderStyle.None, IntegralHeight = false, Font = Body,
            };
            left.Add(codes);
            codes.BackColor = Theme.Card;
            Theme.StyleScroll(codes);
            codes.DrawItem += DrawCode;
            codes.SelectedIndexChanged += (s, e) => ShowInfo(codes.SelectedItem as ErrorInfo);

            var right = new Card { Bounds = R(370, 0, 422, 512) };
            pCodes.Controls.Add(right);
            info = right.Add(new ReportBox { Bounds = R(16, 12, 390, 432) });
            info.BackColor = Theme.Card;
            bFix1 = right.Add(new FlatBtn { Kind = FlatBtn.Kinds.Primary, Bounds = R(16, 456, 180, 40), Font = Small });
            bFix2 = right.Add(new FlatBtn { Kind = FlatBtn.Kinds.Secondary, Bounds = R(202, 456, 172, 40), Font = Small });
            bCopy = right.Add(new FlatBtn { Glyph = GCopy, Kind = FlatBtn.Kinds.Ghost, Bounds = R(378, 456, 30, 40) });
            new ToolTip().SetToolTip(bCopy, Loc.T("troublePage.copyTip"));
            bFix1.Click += async (s, e) => await RunFix(bFix1, (codes.SelectedItem as ErrorInfo)?.Fix ?? FixKind.None);
            bFix2.Click += async (s, e) => await RunFix(bFix2, (codes.SelectedItem as ErrorInfo)?.Fix2 ?? FixKind.None);
            bCopy.Click += (s, e) => { if (info.TextLength > 0) Clipboard.SetText(info.Text); };

            FillCodes();
            ShowProblems();
            OnStatus(() => { if (Visible && !checking && rowY == 0) ShowProblems(); codes.Invalidate(); });
        }

        [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        static extern IntPtr SendMessage(IntPtr h, int msg, IntPtr w, string l);
        static void SetCue(TextBox tb, string text)
        {
            tb.HandleCreated += (s, e) => SendMessage(tb.Handle, 0x1501, (IntPtr)1, text);
            if (tb.IsHandleCreated) SendMessage(tb.Handle, 0x1501, (IntPtr)1, text);
        }

        public override void OnActivated()
        {
            if (!checking && rowY == 0) ShowProblems();
        }

        /// <summary>Opens the error codes tab and selects the given code.</summary>
        public void ShowCode(string code)
        {
            tabs.SelectedIndex = 1;
            cat.SelectedIndex = 0;
            search.Text = "";
            FillCodes();
            if (string.IsNullOrEmpty(code)) return;
            for (int i = 0; i < codes.Items.Count; i++)
                if (((ErrorInfo)codes.Items[i]).Code == code) { codes.SelectedIndex = i; codes.TopIndex = Math.Max(0, i - 2); break; }
        }

        // ------------------------------------------------ find the problem

        void ClearRows()
        {
            var old = rowsArea.Controls.Cast<Control>().ToList();
            rowsArea.Controls.Clear();
            foreach (var c in old) c.Dispose();
            rowsArea.AutoScrollPosition = Point.Empty;
            rowY = 0;
        }

        void ShowProblems()
        {
            ClearRows();
            var list = App.Problems.Snapshot();
            if (list.Count == 0)
            {
                var c = AddRowCard(70);
                c.Add(UIx.Glyph(GCheck, IconL, GreenText, 14, 0, 44, 70));
                c.Add(UIx.L(Loc.T("troublePage.noProblem"), Bold, Theme.Text, 64, 14, 640, 22));
                c.Add(UIx.L(Loc.T("troublePage.noProblemHint"), Small, Muted, 64, 36, 660, 30));
                rowY = 0;   // placeholder
                return;
            }
            var h = UIx.L(Loc.T("troublePage.detected", list.Count), Caption, Muted, 12, 0, 400, 20);
            rowsArea.Controls.Add(h);
            rowY = 24;
            foreach (var p in list)
            {
                var e = p.Info;
                var st = e.Severity == Severity.Error ? CheckStatus.Fail : e.Severity == Severity.Warning ? CheckStatus.Warn : CheckStatus.Info;
                AddCheckRow(new CheckItem { Title = e.Title, Status = st, Code = p.Code, Detail = (p.Detail.Length > 0 ? p.Detail + " · " : "") + p.Time.ToString("HH:mm") });
            }
            rowY = 0;   // cleared when the full check starts
        }

        Card AddRowCard(int h)
        {
            var c = new Card { Bounds = new Rectangle(D(10), D(rowY) + rowsArea.AutoScrollPosition.Y, D(744), D(h)), BackColor = Bg };
            rowsArea.Controls.Add(c);
            rowY += h + 8;
            return c;
        }

        void AddCheckRow(CheckItem it)
        {
            var info0 = string.IsNullOrEmpty(it.Code) ? null : ErrorCatalog.Get(it.Code);
            bool problem0 = it.Status == CheckStatus.Fail || it.Status == CheckStatus.Warn || (it.Status == CheckStatus.Info && info0 != null && it.Code == "NSF-901");
            // a long detail (process lists, driver entries, the anti-cheat card) gets the height it needs instead of being cut
            int w0 = problem0 && info0 != null ? 420 : 680;
            int need = TextRenderer.MeasureText(it.Detail ?? "", Small, new Size(D(w0), 0), TextFormatFlags.WordBreak | TextFormatFlags.NoPrefix).Height;
            int extra = Math.Max(0, (int)Math.Ceiling(need / Theme.Scale) - 24);
            var c = AddRowCard(58 + extra);
            string g; Color col;
            switch (it.Status)
            {
                case CheckStatus.Ok: g = GCheck; col = GreenText; break;
                case CheckStatus.Warn: g = GWarn; col = AmberText; break;
                case CheckStatus.Fail: g = GCancel; col = RedText; break;
                case CheckStatus.Skip: g = GInfo; col = Muted; break;
                default: g = GInfo; col = AccentInk; break;
            }
            if (it.Status == CheckStatus.Fail) { c.Fill = RedSoft; c.Stroke = RedBorder; }
            else if (it.Status == CheckStatus.Warn) { c.Fill = AmberSoft; c.Stroke = AmberBorder; }
            c.Add(UIx.Glyph(g, IconM, col, 10, 0, 40, 58));
            var info = info0;
            bool problem = it.Status == CheckStatus.Fail || it.Status == CheckStatus.Warn || (it.Status == CheckStatus.Info && info != null && it.Code == "NSF-901");
            int textW = problem && info != null ? 420 : 680;
            c.Add(UIx.L(it.Title + (problem && info != null ? "  ·  " + it.Code : ""), Bold, Theme.Text, 52, 8, textW, 22));
            c.Add(UIx.L(it.Detail, Small, Muted, 52, 29, textW, 24 + extra));
            if (problem && info != null)
            {
                var more = c.Add(new FlatBtn { Text = Loc.T("troublePage.solution"), Glyph = GHelp, Kind = FlatBtn.Kinds.Ghost, Bounds = R(480, 12, 96, 34) });
                more.Click += (s, e) => ShowCode(it.Code);
                if (info.Fix != FixKind.None)
                {
                    var fix = c.Add(new FlatBtn { Text = ErrorInfo.FixLabel(info.Fix), Kind = it.Status == CheckStatus.Fail ? FlatBtn.Kinds.Danger : FlatBtn.Kinds.Secondary, Bounds = R(582, 12, 152, 34), Font = Small });
                    fix.Click += async (s, e) => await RunFix(fix, info.Fix);
                }
            }
        }

#if PREVIEW
        /// <summary>Screenshots and the self-test: shows given check results (no check runs).</summary>
        internal void DebugShow(List<CheckItem> items)
        {
            tabs.SelectedIndex = 0;
            ClearRows();
            rowY = 0;
            foreach (var it in items) AddCheckRow(it);
            int fail = items.Count(i => i.Status == CheckStatus.Fail), warn = items.Count(i => i.Status == CheckStatus.Warn);
            runStatus.Text = fail + warn == 0 ? Loc.T("troublePage.allGood") : Loc.T("troublePage.found", fail, warn);
            runStatus.ForeColor = fail > 0 ? RedText : warn > 0 ? AmberText : GreenText;
        }
#endif

        public async Task RunCheck()
        {
            tabs.SelectedIndex = 0;
            if (checking) return;
            checking = true;
            bRun.Enabled = false;
            runStatus.Text = Loc.T("troublePage.checking");
            runStatus.ForeColor = Muted;
            ClearRows();
            rowY = 0;
            List<CheckItem> items = null;
            try
            {
                items = await Diagnostics.RunAsync(it => { if (!IsDisposed) AddCheckRow(it); });
            }
            catch (Exception ex) { runStatus.Text = Loc.T("common.error", ex.Message); }
            checking = false;
            if (IsDisposed) return;
            bRun.Enabled = true;
            bRun.Text = Loc.T("troublePage.checkAgain");
            if (items != null)
            {
                int fail = items.Count(i => i.Status == CheckStatus.Fail), warn = items.Count(i => i.Status == CheckStatus.Warn);
                runStatus.Text = fail + warn == 0 ? Loc.T("troublePage.allGood") :
                    Loc.T("troublePage.found", fail, warn);
                runStatus.ForeColor = fail > 0 ? RedText : warn > 0 ? AmberText : GreenText;
            }
        }

        async Task RunFix(FlatBtn b, FixKind f)
        {
            if (f == FixKind.None) return;
            b.Enabled = false;
            string msg = await Fixes.Run(f, FindForm());
            if (IsDisposed) return;
            b.Enabled = true;
            if (!string.IsNullOrEmpty(msg)) MessageBox.Show(FindForm(), msg, App.Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        // ------------------------------------------------ error codes

        void FillCodes()
        {
            string q = (search.Text ?? "").Trim().ToLower(Loc.Culture);
            string category = cat.SelectedIndex > 0 ? ErrorCatalog.Categories[cat.SelectedIndex - 1] : null;
            var keep = codes.SelectedItem as ErrorInfo;
            codes.BeginUpdate();
            codes.Items.Clear();
            var tr = Loc.Culture;
            foreach (var e in ErrorCatalog.All)
            {
                if (category != null && e.Category != category) continue;
                if (q.Length > 0)
                {
                    string hay = (e.Code + " " + e.Title + " " + e.Summary + " " + e.CategoryName + " " + string.Join(" ", e.Causes)).ToLower(tr);
                    if (!q.Split(' ').All(w => hay.Contains(w))) continue;
                }
                codes.Items.Add(e);
            }
            codes.EndUpdate();
            int idx = keep != null ? codes.Items.IndexOf(keep) : -1;
            if (idx < 0 && codes.Items.Count > 0) idx = 0;
            codes.SelectedIndex = idx;
            if (idx < 0) ShowInfo(null);
        }

        void DrawCode(object sender, DrawItemEventArgs e)
        {
            if (e.Index < 0) return;
            var it = (ErrorInfo)codes.Items[e.Index];
            var g = e.Graphics;
            HQ(g);
            bool sel = (e.State & DrawItemState.Selected) != 0;
            var r = e.Bounds;
            using (var b = new SolidBrush(Theme.Card)) g.FillRectangle(b, r);
            Color bg = sel ? AccentSoft : Theme.Card;
            using (var p = Round(new RectangleF(r.X + 2, r.Y + 2, r.Width - 5, r.Height - 4), D(8)))
            {
                using (var b = new SolidBrush(bg)) g.FillPath(b, p);
                if (sel) using (var pen = new Pen(AccentBorder)) g.DrawPath(pen, p);
            }
            Color sc = SevColor(it.Severity);
            Color soft = Mix(bg, sc, IsDark ? 0.28f : 0.16f);
            Color ink = Readable(sc, soft, 4.0);
            var badge = new RectangleF(r.X + D(10), r.Y + D(12), D(62), D(22));
            using (var p = Round(badge, D(6))) using (var b = new SolidBrush(soft)) g.FillPath(b, p);
            TextRenderer.DrawText(g, it.Code, Caption, Rectangle.Round(badge), ink, soft, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
            bool active = App.Problems.Snapshot().Any(p => p.Code == it.Code);
            TextRenderer.DrawText(g, it.Title, Bold, new Rectangle(r.X + D(82), r.Y + D(5), r.Width - D(92), D(20)), Theme.Text, bg, TextFormatFlags.NoPadding | TextFormatFlags.EndEllipsis);
            TextRenderer.DrawText(g, it.CategoryName + (active ? "  ·  " + Loc.T("troublePage.detectedNow") : ""), Small, new Rectangle(r.X + D(82), r.Y + D(25), r.Width - D(92), D(18)),
                active ? AmberText : Muted, bg, TextFormatFlags.NoPadding | TextFormatFlags.EndEllipsis);
        }

        void ShowInfo(ErrorInfo e)
        {
            info.Clear();
            bFix1.Visible = bFix2.Visible = false;
            if (e == null) { info.Muted(Loc.T("troublePage.noMatch")); return; }
            string sev = e.Severity == Severity.Error ? Loc.T("troublePage.sev.error") : e.Severity == Severity.Warning ? Loc.T("troublePage.sev.warning") : Loc.T("troublePage.sev.info");
            info.Out(e.Code + " · " + sev, Readable(SevColor(e.Severity), Theme.Card, 3.5), Bold);
            info.Out(e.Title, Theme.Text, H2);
            info.Muted(Loc.T("troublePage.category", e.CategoryName));
            var det = App.Problems.Snapshot().FirstOrDefault(p => p.Code == e.Code);
            if (det != null) info.Out(Loc.T("troublePage.detectedAt", det.Time.ToString("HH:mm")) + (det.Detail.Length > 0 ? ": " + det.Detail : "."), AmberText, Small);
            info.Blank();
            info.Out(e.Summary, Theme.Text, Body);
            if (e.Causes.Length > 0)
            {
                info.Blank();
                info.Out(Loc.T("troublePage.causes"), Muted, Caption);
                foreach (var c in e.Causes) info.Out("•  " + c, Theme.Text, Small);
            }
            if (e.Steps.Length > 0)
            {
                info.Blank();
                info.Out(Loc.T("troublePage.steps"), Muted, Caption);
                int i = 0;
                foreach (var s in e.Steps) info.Out((++i) + ".  " + s, Theme.Text, Body);
            }
            if (!string.IsNullOrEmpty(e.Detect))
            {
                info.Blank();
                info.Out(Loc.T("troublePage.howDetected", e.Detect), Muted, Small);
            }
            info.SelectionStart = 0;
            info.ScrollToCaret();
            if (e.Fix != FixKind.None) { bFix1.Text = ErrorInfo.FixLabel(e.Fix); bFix1.Visible = true; }
            if (e.Fix2 != FixKind.None) { bFix2.Text = ErrorInfo.FixLabel(e.Fix2); bFix2.Visible = true; }
        }
    }
}
