using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;
using static NSFShield.Theme;

namespace NSFShield
{
    /// <summary>
    /// Appearance: UI level, following the Windows light/dark mode, ready-made themes and custom colors. Custom colors are
    /// edited in a draft with a live preview; the app's theme only changes when the draft is applied.
    /// </summary>
    sealed class AppearancePage : PageBase
    {
        public override string Key => "appearance";

        /// <summary>The draft outlives the page (rebuilds after a language change or navigation keep it).</summary>
        static ThemeDraft pending;

        /// <summary>True when there are custom colors that were not applied yet.</summary>
        public static bool HasUnappliedColors => pending != null && pending.Dirty && pending.Current;

        readonly ScrollArea scroll;
        readonly ThemeDraft draft;
        readonly Dictionary<string, (Swatch Sw, TextBox Tb)> editors = new Dictionary<string, (Swatch, TextBox)>();
        readonly ThemePreview preview;
        readonly Label contrast, draftState;
        readonly FlatBtn bApply, bCancel, bReset;
        bool loading;

        /// <summary>The page has its own scrolled area: it takes the page's height (the window may be shorter than the design).</summary>
        internal override void FitHost() => FillPage(scroll);

        public AppearancePage()
        {
            Header(Loc.T("appearancePage.title"), Loc.T("appearancePage.subtitle"));
            scroll = new ScrollArea { Bounds = R(0, 68, 820, 572) };
            Controls.Add(scroll);
            int y = 4;

            bool systemDark = Palettes.SystemDark();
            draft = pending != null && pending.Dirty && pending.Current ? pending : new ThemeDraft(App.Settings, systemDark);
            pending = draft;

            // ------------------------------------------------ UI level
            scroll.Controls.Add(UIx.L(Loc.T("appearancePage.uiLevel"), Theme.Caption, Muted, 30, y, 300, 20));
            y += 24;
            var lc = new Card { Bounds = R(28, y, 764, 96) };
            scroll.Controls.Add(lc);
            var seg = lc.Add(new Segmented(Loc.T("uiLevel.Simple"), Loc.T("uiLevel.Standard"), Loc.T("uiLevel.Advanced")) { Bounds = R(20, 16, 360, 36) });
            seg.SetSilently((int)App.Settings.UiLevel);
            lc.Add(UIx.L(LevelText(App.Settings.UiLevel), Small, Muted, 396, 12, 350, 76));
            seg.SelectedChanged += (s, e) => UiLevelSwitch.Set((UiLevel)seg.SelectedIndex, this);
            lc.Add(UIx.L(Loc.T("appearancePage.appliedNow"), Small, Muted, 20, 62, 360, 22));
            y += 96 + 22;

            // ------------------------------------------------ follow Windows
            scroll.Controls.Add(UIx.L(Loc.T("appearancePage.followSection"), Theme.Caption, Muted, 30, y, 300, 20));
            y += 24;
            var fc = new Card { Bounds = R(28, y, 764, 124) };
            scroll.Controls.Add(fc);
            var follow = new ToggleRow(Loc.T("appearancePage.follow"), Loc.T("appearancePage.followInfo", Loc.T(systemDark ? "appearancePage.modeDark" : "appearancePage.modeLight")), D(744))
            { Location = new Point(D(10), D(4)) };
            fc.Add(follow);
            follow.Switch.SetSilently(App.Settings.FollowSystem);
            var lightCombo = ThemeCombo(fc, Loc.T("appearancePage.lightTheme"), 20, "light", App.Settings.LightThemeId);
            var darkCombo = ThemeCombo(fc, Loc.T("appearancePage.darkTheme"), 392, "dark", App.Settings.DarkThemeId);
            lightCombo.Enabled = darkCombo.Enabled = App.Settings.FollowSystem;
            follow.Switch.CheckedChanged += (s, e) =>
            {
                if (!ConfirmDiscard()) { follow.Switch.SetSilently(App.Settings.FollowSystem); return; }
                App.Settings.FollowSystem = follow.Switch.Checked;
                App.Save();
                App.Log("Follow the Windows light/dark mode: " + (App.Settings.FollowSystem ? "on" : "off"), LogLevel.Info);
                Retheme();
            };
            lightCombo.SelectedIndexChanged += (s, e) => SetModeTheme(lightCombo, false);
            darkCombo.SelectedIndexChanged += (s, e) => SetModeTheme(darkCombo, true);
            y += 124 + 22;

            // ------------------------------------------------ featured and other ready-made themes
            string effective = Palettes.EffectiveBaseId(App.Settings, systemDark);
            var featured = Palettes.FeaturedIds.Select(id => Palettes.Presets.First(p => p.Id == id)).ToList();
            var others = new List<Palette> { Palettes.System() };
            others.AddRange(Palettes.Presets.Where(p => !Palettes.FeaturedIds.Contains(p.Id)));
            y = Tiles(Loc.T("appearancePage.featured"), featured, effective, y);
            y = Tiles(Loc.T("appearancePage.presets"), others, effective, y);

            // ------------------------------------------------ custom colors (draft + preview)
            scroll.Controls.Add(UIx.L(Loc.T("appearancePage.custom"), Theme.Caption, Muted, 30, y, 165, 20));
            scroll.Controls.Add(UIx.L(Loc.T("appearancePage.colorHint"), Small, Muted, 200, y, 590, 20));
            y += 24;
            int gridY = 16 + 168 + 44;
            int barY = gridY + 6 * 44 + 10;
            int cardH = barY + 38 + 12 + 38 + 16;
            var cc = new Card { Bounds = R(28, y, 764, cardH) };
            scroll.Controls.Add(cc);

            preview = cc.Add(new ThemePreview { Bounds = R(20, 16, 724, 168), BackColor = Theme.Card });
            contrast = cc.Add(UIx.L("", Small, Muted, 20, 16 + 172, 724, 40));

            for (int i = 0; i < Palette.Keys.Length; i++)
            {
                string key = Palette.Keys[i];
                int col = i % 2, row = i / 2;
                int x0 = 20 + col * 372, y0 = gridY + row * 44;
                var sw = cc.Add(new Swatch { Bounds = R(x0, y0, 34, 30) });
                cc.Add(UIx.L(Loc.T(Palette.Labels[i]), Body, Theme.Text, x0 + 44, y0 + 4, 200, 22, ContentAlignment.MiddleLeft));
                var tb = cc.Add(Theme.Style(new TextBox { Bounds = R(x0 + 248, y0 + 3, 96, 24), Font = Mono, MaxLength = 20 }));
                editors[key] = (sw, tb);
                sw.Click += (s, e) =>
                {
                    using (var d = new ColorDialog { Color = sw.Color, FullOpen = true, AnyColor = true })
                        if (d.ShowDialog(FindForm()) == DialogResult.OK) SetDraft(key, d.Color);
                };
                tb.KeyDown += (s, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; Commit(key, tb); } };
                tb.Leave += (s, e) => Commit(key, tb);
                tb.TextChanged += (s, e) =>
                {
                    if (loading) return;
                    bool valid = Palettes.TryParseColor(tb.Text, out var c);
                    tb.BackColor = valid ? Input : Mix(Input, Red, 0.25f);
                    if (valid) SetDraft(key, c, fromText: true);
                };
            }

            bApply = cc.Add(new FlatBtn { Text = Loc.T("appearancePage.apply"), Glyph = GCheck, Kind = FlatBtn.Kinds.Primary, Bounds = R(20, barY, 150, 38) });
            bCancel = cc.Add(new FlatBtn { Text = Loc.T("common.cancel"), Glyph = GCancel, Kind = FlatBtn.Kinds.Secondary, Bounds = R(180, barY, 130, 38) });
            bReset = cc.Add(new FlatBtn { Text = Loc.T("appearancePage.resetCustom"), Glyph = GUndo, Kind = FlatBtn.Kinds.Secondary, Bounds = R(320, barY, 210, 38) });
            draftState = cc.Add(UIx.L("", Small, Muted, 540, barY, 204, 38, ContentAlignment.MiddleRight));
            bApply.Click += (s, e) => ApplyDraft();
            bCancel.Click += (s, e) => { draft.Cancel(); LoadDraft(); };
            bReset.Click += (s, e) => { draft.ResetToBase(); LoadDraft(); };

            int codeY = barY + 38 + 12;
            var bCopy = cc.Add(new FlatBtn { Text = Loc.T("appearancePage.copyCode"), Glyph = GCopy, Kind = FlatBtn.Kinds.Ghost, Bounds = R(12, codeY, 220, 38) });
            bCopy.Click += (s, e) =>
            {
                Clipboard.SetText(draft.Colors.ToCode());
                MessageBox.Show(FindForm(), Loc.T("appearancePage.codeCopied"), App.Name);
            };
            var bPaste = cc.Add(new FlatBtn { Text = Loc.T("appearancePage.pasteCode"), Glyph = GPaste, Kind = FlatBtn.Kinds.Ghost, Bounds = R(240, codeY, 240, 38) });
            bPaste.Click += (s, e) => PasteCode();
            y += cardH + 20;

            scroll.Controls.Add(UIx.L(Loc.T("appearancePage.tip"), Small, Muted, 30, y, 760, 40));
            scroll.Controls.Add(new Panel { Bounds = R(0, y + 40, 10, 16), BackColor = Bg });

            LoadDraft();
        }

        static string LevelText(UiLevel l)
        {
            switch (l)
            {
                case UiLevel.Simple: return Loc.T("appearancePage.level.simple");
                case UiLevel.Standard: return Loc.T("appearancePage.level.standard");
                default: return Loc.T("appearancePage.level.advanced");
            }
        }

        ThemedCombo ThemeCombo(Card card, string label, int x, string group, string selected)
        {
            card.Add(UIx.L(label, Small, Muted, x, 74, 110, 26, ContentAlignment.MiddleLeft));
            var c = card.Add(new ThemedCombo { Bounds = R(x + 112, 74, 240, 26) });
            var items = Palettes.Presets.Where(p => p.Group == group).ToList();
            foreach (var p in items) c.Items.Add(new ThemeItem(p));
            c.SelectedIndex = Math.Max(0, items.FindIndex(p => p.Id == selected));
            return c;
        }

        /// <summary>Combo box entry (the name is read when it is drawn, so it follows the language).</summary>
        sealed class ThemeItem
        {
            public readonly Palette P;
            public ThemeItem(Palette p) { P = p; }
            public override string ToString() => P.Name;
        }

        void SetModeTheme(ThemedCombo c, bool dark)
        {
            if (!(c.SelectedItem is ThemeItem it)) return;
            string old = dark ? App.Settings.DarkThemeId : App.Settings.LightThemeId;
            if (old == it.P.Id) return;
            if (!ConfirmDiscard())
            {
                c.SelectedIndex = c.Items.Cast<ThemeItem>().ToList().FindIndex(x => x.P.Id == old);
                return;
            }
            if (dark) App.Settings.DarkThemeId = it.P.Id; else App.Settings.LightThemeId = it.P.Id;
            App.Save();
            App.Log((dark ? "Dark" : "Light") + " mode theme: " + it.P.Id, LogLevel.Info);
            Retheme();
        }

        int Tiles(string caption, List<Palette> list, string effective, int y)
        {
            scroll.Controls.Add(UIx.L(caption, Theme.Caption, Muted, 30, y, 300, 20));
            y += 24;
            int cols = 4, tw = 182, th = 92, gap = 12;
            bool custom = App.Settings.ThemeOverrides.Count > 0;
            for (int i = 0; i < list.Count; i++)
            {
                var pal = list[i];
                bool slot = App.Settings.FollowSystem && (pal.Id == App.Settings.LightThemeId || pal.Id == App.Settings.DarkThemeId);
                var tile = new ThemeTile(pal, pal.Id == effective && !custom, pal.Id == effective && custom, slot && pal.Id != effective)
                {
                    Bounds = R(28 + (i % cols) * (tw + gap), y + (i / cols) * (th + gap), tw, th), BackColor = Bg,
                };
                tile.Click += (s, e) => SelectTheme(pal);
                scroll.Controls.Add(tile);
            }
            return y + (list.Count + cols - 1) / cols * (th + gap) + 14;
        }

        /// <summary>Asks before unapplied custom colors are dropped; false = keep them (do nothing).</summary>
        bool ConfirmDiscard()
        {
            if (!draft.Dirty) return true;
            if (MessageBox.Show(FindForm(), Loc.T("appearancePage.discardDraft"), App.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                return false;
            draft.Cancel();
            return true;
        }

        void SelectTheme(Palette pal)
        {
            if (!ConfirmDiscard()) return;
            var s = App.Settings;
            if (s.ThemeOverrides.Count > 0 && pal.Id != Palettes.EffectiveBaseId(s, Palettes.SystemDark()) &&
                MessageBox.Show(FindForm(), Loc.T("appearancePage.keepCustom"), App.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.No)
                s.ThemeOverrides.Clear();
            if (s.FollowSystem && pal.Group.Length > 0)
            {
                // following Windows: a light theme becomes the light-mode theme, a dark one the dark-mode theme
                if (pal.Group == "dark") s.DarkThemeId = pal.Id; else s.LightThemeId = pal.Id;
            }
            else
            {
                s.FollowSystem = false;
                s.ThemeId = pal.Id;
            }
            App.Save();
            App.Log("Theme: " + pal.Id, LogLevel.Info);
            Retheme();
        }

        void Retheme()
        {
            pending = null;
            MainForm.Instance.ApplyTheme();
        }

        // ------------------------------------------------------------ draft

        void LoadDraft()
        {
            loading = true;
            foreach (var key in Palette.Keys)
            {
                var (sw, tb) = editors[key];
                sw.Color = draft.Colors.Get(key);
                tb.Text = Palettes.Hex(draft.Colors.Get(key));
                tb.BackColor = Input;
            }
            loading = false;
            Refresh2();
        }

        void SetDraft(string key, Color c, bool fromText = false)
        {
            draft.Set(key, c);
            var (sw, tb) = editors[key];
            sw.Color = c;
            if (!fromText) { loading = true; tb.Text = Palettes.Hex(c); loading = false; }
            Refresh2();
        }

#if PREVIEW
        /// <summary>Screenshots: changes a draft color and scrolls to the custom colors (or drops the draft).</summary>
        internal void DebugEdit(string key, Color c)
        {
            if (key == null) { draft.Cancel(); LoadDraft(); return; }
            SetDraft(key, c);
            scroll.AutoScrollPosition = new Point(0, preview.Parent.Top - scroll.AutoScrollPosition.Y - D(34));
        }
#endif

        void Commit(string key, TextBox tb)
        {
            if (!Palettes.TryParseColor(tb.Text, out var c)) c = draft.Colors.Get(key);
            loading = true;
            tb.Text = Palettes.Hex(c);
            tb.BackColor = Input;
            loading = false;
            SetDraft(key, c, fromText: true);
        }

        /// <summary>Updates the preview, the contrast warning and the action bar; nothing else is redrawn.</summary>
        void Refresh2()
        {
            preview.Palette = draft.Colors;
            foreach (var key in Palette.Keys)
                editors[key].Tb.ForeColor = draft.Colors.Get(key).ToArgb() != draft.Base.Get(key).ToArgb() ? AccentInk : Theme.Text;

            var low = draft.LowContrast();
            if (low.Count == 0)
            {
                contrast.Text = GCheckText + Loc.T("appearancePage.contrastOk", Wcag.AA.ToString("0.0", Loc.Culture));
                contrast.ForeColor = GreenText;
            }
            else
            {
                contrast.Text = GWarnText + Loc.T("appearancePage.contrastLow",
                    string.Join(", ", low.Select(l => Loc.T(l.Pair) + " " + l.Ratio.ToString("0.0", Loc.Culture) + ":1")), Wcag.AA.ToString("0.0", Loc.Culture));
                contrast.ForeColor = AmberText;
            }

            bool dirty = draft.Dirty;
            bApply.Enabled = bCancel.Enabled = dirty;
            bReset.Enabled = draft.Overrides().Count > 0;
            draftState.Text = dirty ? Loc.T("appearancePage.unapplied") : App.Settings.ThemeOverrides.Count > 0 ? Loc.T("appearancePage.customInUse") : "";
            draftState.ForeColor = dirty ? AmberText : Muted;
            MainForm.Instance?.SetNavDot("appearance", dirty);
        }

        const string GCheckText = "✓ ", GWarnText = "⚠ ";

        void ApplyDraft()
        {
            draft.Apply();
            App.Save();
            App.Log("Custom colors applied (" + App.Settings.ThemeOverrides.Count + " changed).", LogLevel.Info);
            pending = null;
            MainForm.Instance.ApplyTheme();
        }

        void PasteCode()
        {
            string code = Clipboard.ContainsText() ? Clipboard.GetText() : "";
            if (!Palette.TryParseCode(code, draft.Base, out var p))
            {
                MessageBox.Show(FindForm(), Loc.T("appearancePage.badCode"), App.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            foreach (var k in Palette.Keys) draft.Set(k, p.Get(k));
            LoadDraft();
        }

        /// <summary>Clickable color box.</summary>
        sealed class Swatch : Control
        {
            Color color;
            public Color Color { get => color; set { color = value; Invalidate(); } }
            public Swatch()
            {
                SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer, true);
                Cursor = Cursors.Hand;
            }
            protected override void OnPaint(PaintEventArgs e)
            {
                var g = e.Graphics;
                g.Clear(BackColor);
                HQ(g);
                using (var p = Round(new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f), D(6)))
                using (var b = new SolidBrush(color))
                using (var pen = new Pen(Mix(Border, Theme.Text, 0.25f)))
                {
                    g.FillPath(b, p);
                    g.DrawPath(pen, p);
                }
            }
        }

        /// <summary>
        /// Live preview of the draft colors with the app's real building blocks: window background, sidebar, card, primary
        /// button, status badge, main and secondary text.
        /// </summary>
        sealed class ThemePreview : Control
        {
            Palette p;
            public Palette Palette { get => p; set { p = value; Invalidate(); } }

            public ThemePreview()
            {
                SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            }

            protected override void OnPaint(PaintEventArgs e)
            {
                var g = e.Graphics;
                g.Clear(BackColor);
                if (p == null) return;
                HQ(g);
                var outer = new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f);
                using (var path = Round(outer, D(10)))
                {
                    using (var b = new SolidBrush(p.Bg)) g.FillPath(b, path);
                    var st = g.Save();
                    g.SetClip(path);

                    // sidebar with the app name and three menu entries (the second one selected)
                    float sw = D(168);
                    using (var b = new SolidBrush(p.Sidebar)) g.FillRectangle(b, outer.X, outer.Y, sw, outer.Height);
                    var flags = TextFormatFlags.NoPadding | TextFormatFlags.SingleLine | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis;
                    TextRenderer.DrawText(g, App.Name, Bold, new Rectangle(D(16), D(10), (int)sw - D(24), D(24)), p.SidebarText, p.Sidebar, flags);
                    string[] nav = { Loc.T("nav.home"), Loc.T("nav.appearance"), Loc.T("nav.settings") };
                    for (int i = 0; i < nav.Length; i++)
                    {
                        var r = new RectangleF(D(8), D(42) + i * D(32), sw - D(16), D(28));
                        Color back = p.Sidebar;
                        if (i == 1)
                        {
                            back = Mix(p.Sidebar, p.SidebarText, 0.13f);
                            using (var rp = Round(r, D(6))) using (var b = new SolidBrush(back)) g.FillPath(b, rp);
                            using (var b = new SolidBrush(Readable(p.Accent, p.Sidebar, 2.5))) g.FillRectangle(b, r.X, r.Y + D(7), D(3), r.Height - D(14));
                        }
                        TextRenderer.DrawText(g, nav[i], i == 1 ? Bold : Small, Rectangle.Round(new RectangleF(r.X + D(12), r.Y, r.Width - D(14), r.Height)),
                            i == 1 ? p.SidebarText : Mix(p.SidebarText, p.Sidebar, 0.12f), back, flags);
                    }

                    // card
                    var card = new RectangleF(sw + D(16), D(14), outer.Width - sw - D(32), outer.Height - D(28));
                    using (var cp = Round(card, D(8)))
                    using (var b = new SolidBrush(p.Card))
                    using (var pen = new Pen(p.Border)) { g.FillPath(b, cp); g.DrawPath(pen, cp); }
                    int cx = (int)card.X + D(18), cw = (int)card.Width - D(36);
                    TextRenderer.DrawText(g, Loc.T("appearancePage.preview.title"), H2, new Rectangle(cx, (int)card.Y + D(12), cw - D(120), D(28)), p.Text, p.Card, flags);
                    TextRenderer.DrawText(g, Loc.T("appearancePage.preview.text"), Small, new Rectangle(cx, (int)card.Y + D(42), cw, D(20)), p.Muted, p.Card, flags);

                    // status badge
                    string badge = Loc.T("appearancePage.preview.badge");
                    int bw = TextRenderer.MeasureText(badge, Theme.Caption).Width + D(26);
                    var br = new RectangleF(card.Right - D(18) - bw, card.Y + D(16), bw, D(22));
                    var soft = Mix(p.Card, p.Green, IsDarkCard ? 0.2f : 0.14f);
                    using (var bp = Round(br, D(11))) using (var b = new SolidBrush(soft)) g.FillPath(b, bp);
                    using (var b = new SolidBrush(p.Green)) g.FillEllipse(b, br.X + D(9), br.Y + D(8), D(6), D(6));
                    TextRenderer.DrawText(g, badge, Theme.Caption, Rectangle.Round(new RectangleF(br.X + D(18), br.Y, br.Width - D(20), br.Height)),
                        Readable(p.Green, soft, 4.0), soft, flags);

                    // primary and secondary buttons
                    var b1 = new RectangleF(cx, card.Y + D(76), D(170), D(36));
                    using (var bp = Round(b1, D(8))) using (var b = new SolidBrush(p.Accent)) g.FillPath(b, bp);
                    TextRenderer.DrawText(g, Loc.T("appearancePage.preview.button"), Bold, Rectangle.Round(b1), On(p.Accent), p.Accent,
                        flags | TextFormatFlags.HorizontalCenter);
                    var b2 = new RectangleF(b1.Right + D(10), b1.Y, D(150), D(36));
                    var sec = Mix(p.Card, p.Text, IsDarkCard ? 0.10f : 0.06f);
                    using (var bp = Round(b2, D(8))) using (var b = new SolidBrush(sec)) using (var pen = new Pen(p.Border)) { g.FillPath(b, bp); g.DrawPath(pen, bp); }
                    TextRenderer.DrawText(g, Loc.T("appearancePage.preview.secondary"), Bold, Rectangle.Round(b2), p.Text, sec, flags | TextFormatFlags.HorizontalCenter);

                    // warning and error colors
                    float dx = b2.Right + D(18);
                    foreach (var c in new[] { p.Green, p.Amber, p.Red })
                    {
                        using (var b = new SolidBrush(c)) g.FillEllipse(b, dx, b1.Y + D(12), D(12), D(12));
                        dx += D(18);
                    }
                    g.Restore(st);
                    using (var pen = new Pen(Mix(Border, Theme.Text, 0.2f))) g.DrawPath(pen, path);
                }
            }

            bool IsDarkCard => Lum(p.Card) < 0.35;
        }

        /// <summary>Theme preview box: shows the sidebar, card and accent color at a small scale.</summary>
        sealed class ThemeTile : Control
        {
            readonly Palette p;
            readonly bool selected, modified, slot;
            bool hover;
            public ThemeTile(Palette p, bool selected, bool modified, bool slot)
            {
                this.p = p;
                this.selected = selected;
                this.modified = modified;
                this.slot = slot;
                SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
                Cursor = Cursors.Hand;
            }
            protected override void OnMouseEnter(EventArgs e) { hover = true; Invalidate(); base.OnMouseEnter(e); }
            protected override void OnMouseLeave(EventArgs e) { hover = false; Invalidate(); base.OnMouseLeave(e); }
            protected override void OnPaint(PaintEventArgs e)
            {
                var g = e.Graphics;
                g.Clear(BackColor);
                HQ(g);
                var outer = new RectangleF(1, 1, Width - 3, Height - 3);
                bool mark = selected || modified;
                using (var path = Round(outer, D(10)))
                {
                    using (var b = new SolidBrush(p.Bg)) g.FillPath(b, path);
                    var st = g.Save();
                    g.SetClip(path);
                    float sideW = Width * 0.26f;
                    using (var b = new SolidBrush(p.Sidebar)) g.FillRectangle(b, outer.X, outer.Y, sideW, outer.Height);
                    using (var b = new SolidBrush(Mix(p.Sidebar, p.SidebarText, 0.5f)))
                        for (int i = 0; i < 3; i++) g.FillRectangle(b, outer.X + D(8), outer.Y + D(12) + i * D(10), sideW - D(16), D(4));
                    var card = new RectangleF(outer.X + sideW + D(8), outer.Y + D(8), outer.Width - sideW - D(16), D(38));
                    using (var cp = Round(card, D(5)))
                    using (var b = new SolidBrush(p.Card))
                    using (var pen = new Pen(p.Border)) { g.FillPath(b, cp); g.DrawPath(pen, cp); }
                    using (var b = new SolidBrush(p.Text)) g.FillRectangle(b, card.X + D(7), card.Y + D(8), card.Width * 0.55f, D(5));
                    using (var b = new SolidBrush(p.Muted)) g.FillRectangle(b, card.X + D(7), card.Y + D(18), card.Width * 0.75f, D(4));
                    using (var cp = Round(new RectangleF(card.X + D(7), card.Y + D(27), D(28), D(7)), D(3)))
                    using (var b = new SolidBrush(p.Accent)) g.FillPath(b, cp);
                    float dx = card.X + D(40);
                    foreach (var c in new[] { p.Green, p.Amber, p.Red })
                    {
                        using (var b = new SolidBrush(c)) g.FillEllipse(b, dx, card.Y + D(27), D(7), D(7));
                        dx += D(10);
                    }
                    g.Restore(st);
                    Color edge = mark ? Accent : slot ? Mix(Border, Accent, 0.6f) : hover ? Mix(Border, Theme.Text, 0.35f) : Border;
                    using (var pen = new Pen(edge, mark ? 2.5f : slot ? 1.6f : 1f)) g.DrawPath(pen, path);
                }
                string name = p.Name + (modified ? " ✎" : "");
                var nameRect = new Rectangle((int)(Width * 0.26f) + D(8), Height - D(36), Width - (int)(Width * 0.26f) - D(12), D(30));
                TextRenderer.DrawText(g, name, mark ? Bold : Small, nameRect, p.Text, p.Bg,
                    TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPadding);
                if (mark)
                {
                    var badge = new RectangleF(Width - D(26), D(6), D(18), D(18));
                    using (var b = new SolidBrush(Accent)) g.FillEllipse(b, badge);
                    TextRenderer.DrawText(g, GCheck, new Font(IconFontName, 7f), Rectangle.Round(badge), On(Accent),
                        TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
                }
            }
        }
    }

    /// <summary>
    /// The one way to change the UI level (Appearance and Settings pages behave the same): the same level does nothing; a new
    /// level is saved and logged once, then the window is rebuilt. Rebuilding only creates controls (their values are set
    /// silently): no engine is selected, protection is not stopped and no setting is written again.
    /// </summary>
    static class UiLevelSwitch
    {
        /// <summary>Changes of the level (tests).</summary>
        internal static int Changes;

        public static bool Set(UiLevel level, Control invoker)
        {
            if (App.Settings.UiLevel == level) return false;
            App.Settings.UiLevel = level;
            App.Save();
            Changes++;
            App.Log("UI level: " + level, LogLevel.Info);
            if (invoker != null && invoker.IsHandleCreated && MainForm.Instance != null) invoker.BeginInvoke(new Action(() => MainForm.Instance.Rebuild()));
            return true;
        }
    }
}
