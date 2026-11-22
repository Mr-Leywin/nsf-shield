using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Windows.Forms;
using static NSFShield.Theme;

namespace NSFShield
{
    sealed class ProfilesPage : PageBase
    {
        public override string Key => "profiles";

        /// <summary>A heading in the list: an engine (Simple) or a catalog layer (Standard / Advanced).</summary>
        sealed class GroupHeader { public string Text; public override string ToString() => Text; }

        readonly ListBox list;
        readonly ReportBox detail;
        readonly FlatBtn bActivate, bNew, bCopy, bEdit, bDelete, bScript, bCmd;
        readonly Segmented engineTabs;
        readonly CheckX chkExperts;
        readonly Label engineInfo;
        readonly UiLevel level;
        readonly bool simple, detailed;
        EngineKind tab;

        public ProfilesPage()
        {
            level = App.Settings.UiLevel;
            simple = level == UiLevel.Simple;
            detailed = level == UiLevel.Advanced;
            Header(Loc.T("profilesPage.title"), Loc.T(simple ? "profilesPage.subtitleSimple" : "profilesPage.subtitle"));

            // engine tabs (Standard / Advanced): every engine has its own profiles; "Use" switches to the profile's engine
            tab = App.Engine.Current.Kind;
            if (!simple)
            {
                engineTabs = new Segmented(Engines.All.Select(e => e.DisplayName).ToArray()) { Bounds = R(28, 70, 430, 36), BackColor = Bg };
                engineTabs.SetSilently((int)tab);
                Controls.Add(engineTabs);
                engineTabs.SelectedChanged += (s, e) => { tab = (EngineKind)engineTabs.SelectedIndex; Reload(); };
            }
            if (level == UiLevel.Standard)
            {
                // the value is set before the event is attached: rebuilding the page never writes the setting again
                chkExperts = new CheckX { Text = Loc.T("profilesPage.showExperts"), Checked = App.Settings.ShowExpertProfiles, Bounds = R(470, 64, 322, 24), BackColor = Bg };
                chkExperts.CheckedChanged += (s, e) =>
                {
                    App.Settings.ShowExpertProfiles = chkExperts.Checked;
                    App.Save();
                    Reload();
                };
                Controls.Add(chkExperts);
            }
            engineInfo = simple ? UIx.L(Loc.T("profilesPage.simpleInfo"), Small, Muted, 28, 66, 764, 40, ContentAlignment.MiddleLeft)
                       : level == UiLevel.Standard ? UIx.L("", Small, Muted, 470, 88, 322, 22, ContentAlignment.MiddleLeft)
                       : UIx.L("", Small, Muted, 470, 68, 322, 40, ContentAlignment.MiddleLeft);
            engineInfo.AutoEllipsis = true;
            Controls.Add(engineInfo);

            var card = AddCard(28, 114, 430, 436);
            list = new ListBox
            {
                Bounds = R(8, 8, 414, 420),
                DrawMode = DrawMode.OwnerDrawVariable,
                BorderStyle = BorderStyle.None,
                IntegralHeight = false,
                Font = Body,
            };
            card.Add(list);
            list.BackColor = Theme.Card;
            Theme.StyleScroll(list);
            list.MeasureItem += (s, e) => e.ItemHeight = list.Items[e.Index] is GroupHeader ? D(30) : D(detailed ? 70 : 56);
            list.DrawItem += DrawItem;
            list.SelectedIndexChanged += (s, e) =>
            {
                if (list.SelectedItem is GroupHeader && list.SelectedIndex + 1 < list.Items.Count) { list.SelectedIndex++; return; }
                UpdateButtons();
                ShowDetail();
            };
            list.DoubleClick += async (s, e) => { if (Selected != null) await Actions.SelectProfileAsync(Selected); };
            list.MouseMove += (s, e) =>
            {
                int i = list.IndexFromPoint(e.Location);
                list.Cursor = i >= 0 && list.Items[i] is Profile ? Cursors.Hand : Cursors.Default;
            };

            var dcard = AddCard(470, 114, 322, 436);
            detail = new ReportBox { Bounds = R(16, 12, 296, detailed ? 366 : 412) };
            dcard.Add(detail);
            detail.BackColor = Theme.Card;
            if (detailed)
            {
                // the full local command (not the short preview) is copied only on this explicit click
                bCmd = dcard.Add(new FlatBtn { Text = Loc.T("profilesPage.copyCommand"), Glyph = GCopy, Kind = FlatBtn.Kinds.Secondary, Bounds = R(16, 388, 296, 36) });
                bCmd.Click += (s, e) => CopyCommand(Selected, FindForm());
            }

            int x = 28;
            FlatBtn B(string text, string glyph, FlatBtn.Kinds kind, int w, bool show = true)
            {
                var b = Btn(text, glyph, kind, x, 562, w, 40);
                b.Visible = show;
                if (show) x += w + 8;
                return b;
            }
            bActivate = B(Loc.T("profilesPage.use"), GCheck, FlatBtn.Kinds.Primary, 166);
            bNew = B(Loc.T("profilesPage.new"), GAdd, FlatBtn.Kinds.Secondary, 84, detailed);
            bCopy = B(Loc.T("profilesPage.copy"), GCopy, FlatBtn.Kinds.Secondary, 104, detailed);
            bEdit = B(Loc.T("profilesPage.edit"), GEdit, FlatBtn.Kinds.Secondary, 106, detailed);
            bDelete = B(Loc.T("profilesPage.delete"), GDelete, FlatBtn.Kinds.Secondary, 72, !simple);
            bScript = B(Loc.T("profilesPage.shareButton"), GChevron, FlatBtn.Kinds.Secondary, 112, !simple);

            bActivate.Click += async (s, e) => { if (Selected != null) await Actions.SelectProfileAsync(Selected); };
            bNew.Click += (s, e) => Edit(NewProfile(tab), true);
            bCopy.Click += (s, e) => { if (Selected != null) Edit(Selected.CloneAsCustom(), true); };
            bEdit.Click += (s, e) => { if (Selected != null) Edit(Selected, false); };
            bDelete.Click += (s, e) => DeleteSelected();
            bScript.Click += (s, e) => ShowShareMenu();

            OnStatus(() => { if (Visible) { list.Invalidate(); UpdateButtons(); } });
        }

        /// <summary>A new custom profile of an engine, filled with its recommended parameters as a starting point.</summary>
        static Profile NewProfile(EngineKind k)
        {
            var p = new Profile { Name = Loc.T("profilesPage.newName"), Engine = k };
            if (k == EngineKind.Zapret) p.EngineArgs = Profiles.ZapretDiscord;
            else if (k == EngineKind.ByeDpi) p.EngineArgs = Profiles.ByeDpiRecommended;
            if (k != EngineKind.GoodbyeDpi) { p.Mode = ""; p.Dns = DnsChoice.None; }
            return p;
        }

        Profile Selected => list.SelectedItem as Profile;

        public override void OnActivated()
        {
            tab = App.Engine.Current.Kind;
            engineTabs?.SetSilently((int)tab);
            Reload();
        }

        /// <summary>Shows one engine's tab (an information card's link): nothing is selected, saved or started.</summary>
        public void ShowEngineTab(EngineKind k)
        {
            if (engineTabs == null) return;
            tab = k;
            engineTabs.SetSilently((int)tab);
            Reload();
        }

        /// <summary>Command preview of a profile with the current lists and port (short names: shown, never run).</summary>
        internal static string Preview(Profile p) => CommandPreview.Display(p, App.Settings);

        /// <summary>
        /// "Copy command": the full local command (real paths, port, Windows quoting) – only for a valid profile and only on this
        /// explicit request; it is never written to the log.
        /// </summary>
        internal static void CopyCommand(Profile p, IWin32Window owner)
        {
            if (p == null) return;
            if (!CommandPreview.TryBuild(p, App.Settings, true, out string cmd, out string err))
            {
                MessageBox.Show(owner, Loc.T("profilesPage.commandInvalid", err), App.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            try { Clipboard.SetText(cmd); }
            catch (Exception ex) { MessageBox.Show(owner, Loc.T("common.error", ex.Message), App.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
            App.Log("Command of \"" + p.Name + "\" copied to the clipboard.", LogLevel.Info);
            MessageBox.Show(owner, Loc.T("profilesPage.commandCopied"), App.Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        /// <summary>The list of the level: Simple = recommended of every engine; Standard = recommended (+ others on request); Advanced = all.</summary>
        internal List<Profile> ListedProfiles() =>
            simple ? ProfileCatalog.VisibleNow(null).OrderBy(p => (int)p.Engine).ToList() : ProfileCatalog.VisibleNow(tab);

        void Reload(string selectId = null)
        {
            string keep = selectId ?? Selected?.Id ?? App.Settings.SelectedProfileId;
            if (!simple)
            {
                var eng = Engines.Get(tab);
                bool ok = eng.Available(out var why);
                engineInfo.Text = Loc.T("profilesPage.engineInfo." + eng.Id) + (ok ? "" : " " + why.Text);
                engineInfo.ForeColor = ok ? Muted : AmberText;
            }
            list.BeginUpdate();
            list.Items.Clear();
            string group = null;
            foreach (var p in ListedProfiles())
            {
                string g = simple ? Engines.Of(p).DisplayName
                         : Loc.T(p.BuiltIn ? "profiles.tier." + p.Tier : "profiles.tier.custom");
                if (g != group) { group = g; list.Items.Add(new GroupHeader { Text = g }); }
                list.Items.Add(p);
            }
            list.EndUpdate();
            bool found = false;
            for (int i = 0; i < list.Items.Count; i++)
                if (list.Items[i] is Profile pp && pp.Id == keep) { list.SelectedIndex = i; found = true; break; }
            if (!found)
                for (int i = 0; i < list.Items.Count; i++)
                    if (list.Items[i] is Profile) { list.SelectedIndex = i; break; }
            UpdateButtons();
            ShowDetail();
        }

        void UpdateButtons()
        {
            var p = Selected;
            bool busy = Actions.Scanning || App.Engine.State == EngineState.Starting || App.Engine.State == EngineState.Stopping;
            bActivate.Enabled = p != null && !busy && Engines.Of(p).Available(out _);
            bCopy.Enabled = p != null;
            bEdit.Enabled = p != null;
            bEdit.Text = p != null && p.BuiltIn ? Loc.T("profilesPage.inspect") : Loc.T("profilesPage.edit");
            bDelete.Enabled = p != null && !p.BuiltIn;
            bScript.Enabled = true;
            if (bCmd != null) bCmd.Enabled = p != null && ArgPolicy.ValidateProfile(p, out _);
        }

        void ShowDetail()
        {
            var p = Selected;
            detail.Clear();
            if (p == null) { detail.Muted(Loc.T("profilesPage.selectHint")); return; }
            detail.Out(p.Name, Theme.Text, H2);
            var tags = new List<string> { Engines.Of(p).DisplayName, Loc.T(p.BuiltIn ? "profiles.tier." + p.Tier : "profiles.tier.custom") };
            if (p.Id == App.Settings.SelectedProfileId) tags.Add(App.Engine.State == EngineState.Running ? Loc.T("profilesPage.inUse") : Loc.T("profilesPage.selected"));
            detail.Muted(string.Join(" · ", tags));
            var scen = ProfileCatalog.ScenarioTags(p).ToList();
            if (scen.Count > 0) detail.Out(Loc.T("profilesPage.scenarios", string.Join(" · ", scen)), AccentInk, Small);
            if (ProfileCatalog.IsException(p, level, App.Settings.ShowExpertProfiles))
                detail.Out(Loc.T("profilesPage.exceptionNote"), AmberText, Small);
            detail.Blank();
            detail.Out(p.Description, Theme.Text, Body);
            detail.Blank();
            detail.Out(Loc.T("profilesPage.whatItDoes"), Muted, Caption);
            foreach (var (title, text, warn) in ProfileHelp.Explain(p))
            {
                detail.Out("• " + title, warn ? AmberText : Theme.Text, Bold);
                detail.Out(text, Muted, Small);
            }
            string when = ProfileHelp.WhenToUse(p);
            if (when.Length > 0)
            {
                detail.Blank();
                detail.Out(Loc.T("profilesPage.whenToTry"), Muted, Caption);
                detail.Out(when, Theme.Text, Small);
            }
            if (detailed)
            {
                detail.Blank();
                detail.Out(Loc.T("profilesPage.technical"), Muted, Caption);
                detail.Out(string.Join(" · ", ProfileCatalog.TechnicalTags(p)), Theme.Text, Small);
            }
            if (!simple)
            {
                detail.Blank();
                detail.Out(Loc.T(detailed ? "profilesPage.commandPreview" : "profilesPage.command"), Muted, Caption);
                bool valid = CommandPreview.TryBuild(p, App.Settings, false, out string cmd, out string err);
                detail.Out(valid ? cmd : "✗ " + err, valid ? Muted : RedText, MonoSmall);
            }
            detail.SelectionStart = 0;
            detail.ScrollToCaret();
        }

        void Edit(Profile p, bool isNew)
        {
            DialogResult r;
            if (p.IsGoodbyeDpi)
                using (var dlg = new ProfileEditor(p)) r = dlg.ShowDialog(FindForm());
            else
                using (var dlg = new EngineProfileEditor(p)) r = dlg.ShowDialog(FindForm());
            if (r == DialogResult.Retry) { Edit(p.CloneAsCustom(), true); return; }
            if (r != DialogResult.OK) return;
            if (isNew) App.Settings.CustomProfiles.Add(p);
            App.Save();
            App.Log("Profile saved: " + p.Name + " [" + Engines.Of(p).DisplayName + "]", LogLevel.Info);
            Reload(p.Id);
            App.RaiseStatus();
            if (!isNew && p.Id == App.Settings.SelectedProfileId && App.Engine.IsActive)
            {
                if (MessageBox.Show(FindForm(), Loc.T("profilesPage.applyChanges"),
                        App.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                    _ = Actions.StartAsync();
            }
        }

        void DeleteSelected()
        {
            var p = Selected;
            if (p == null || p.BuiltIn) return;
            if (MessageBox.Show(FindForm(), Loc.T("profilesPage.deleteConfirm", p.Name), App.Name,
                    MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            App.Settings.CustomProfiles.RemoveAll(x => x.Id == p.Id);
            if (App.Settings.SelectedProfileId == p.Id)
            {
                // stay on the same engine: its first recommended profile
                App.Settings.SelectedProfileId = ProfileCatalog.Recommended(p.Engine).FirstOrDefault()?.Id ?? Profiles.ForEngine(Profiles.BuiltIns, p.Engine).First().Id;
                if (App.Engine.IsActive) _ = Actions.StartAsync();
            }
            App.Save();
            Reload();
            App.RaiseStatus();
        }

        void ShowShareMenu()
        {
            var p = Selected;
            var m = new ContextMenuStrip { Font = Body, ShowImageMargin = false };
            var copy = new ToolStripMenuItem(Loc.T("profilesPage.share.copyCode")) { Enabled = p != null };
            copy.Click += (s, e) =>
            {
                // NSF1; a profile its own reader would refuse is never written
                if (!ProfileCode.TryToCode(p, out string code, out string err))
                {
                    MessageBox.Show(FindForm(), Loc.T("profilesPage.share.failed", err), App.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                try { Clipboard.SetText(code); }
                catch (Exception ex) { MessageBox.Show(FindForm(), Loc.T("common.error", ex.Message), App.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
                MessageBox.Show(FindForm(), CopiedText(p, code), App.Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
            };
            var paste = new ToolStripMenuItem(Loc.T("profilesPage.share.paste"));
            paste.Click += (s, e) => ImportCode();
            m.Items.Add(copy);
            m.Items.Add(paste);
            if (detailed)
            {
                m.Items.Add(new ToolStripSeparator());
                // .cmd scripts run goodbyedpi.exe directly; the other engines are started by the app only
                var cmd = new ToolStripMenuItem(Loc.T("profilesPage.share.saveCmd")) { Enabled = p != null && p.IsGoodbyeDpi };
                cmd.Click += (s, e) => SaveScript();
                m.Items.Add(cmd);
            }
            m.Closed += (s, e) => BeginInvoke(new Action(m.Dispose));
            m.Show(bScript, new Point(0, bScript.Height));
        }

        /// <summary>The message after copying a code (format and length, never the code itself in the log).</summary>
        internal static string CopiedText(Profile p, string code) => Loc.T("profilesPage.share.copiedCode", p.Name, code.Substring(0, 4), code.Length);

        /// <summary>The confirmation text of an import (name, engine, description, command preview with short names).</summary>
        internal static string ImportConfirmText(Profile p) =>
            Loc.T("profilesPage.import.confirmEngine", p.Name, Engines.Of(p).DisplayName, p.Description) + Preview(p);

        void ImportCode()
        {
            string text;
            try { text = Clipboard.ContainsText() ? Clipboard.GetText() : ""; } catch (Exception) { text = ""; }
            if (!ProfileCode.TryFromCode(text, out var p, out var err))
            {
                MessageBox.Show(FindForm(), err + "\n\n" + Loc.T("profilesPage.import.hint"), App.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            if (App.AllProfiles.Any(x => x.Name == p.Name)) p.Name += " " + Loc.T("profilesPage.import.suffix");
            // the existing confirmation: "No" changes nothing (no profile, no file, no engine start)
            if (MessageBox.Show(FindForm(), ImportConfirmText(p),
                    App.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            App.Settings.CustomProfiles.Add(p);
            App.Save();
            App.Log("Profile added from code: " + p.Name + " [" + Engines.Of(p).DisplayName + "]", LogLevel.Success);
            tab = p.Engine;
            engineTabs?.SetSilently((int)tab);
            // an imported (custom) profile is an expert profile: Standard shows it when "show expert profiles" is on
            Reload(p.Id);
            App.RaiseStatus();
        }

        void SaveScript()
        {
            var p = Selected;
            if (p == null || !p.IsGoodbyeDpi) return;
            using (var d = new SaveFileDialog { FileName = Scripts.Slug(p.Name) + ".cmd", Filter = Loc.T("profilesPage.cmdFilter") })
            {
                if (d.ShowDialog(FindForm()) != DialogResult.OK) return;
                try
                {
                    Scripts.Write(p, d.FileName, Engine.BinDir.Substring(0, Engine.BinDir.Length - Engine.Arch.Length - 1));
                    App.Log("Script saved: " + d.FileName, LogLevel.Success);
                    MessageBox.Show(FindForm(), Loc.T("profilesPage.scriptSaved") + "\n\n" + d.FileName, App.Name,
                        MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                catch (Exception ex) { MessageBox.Show(FindForm(), Loc.T("common.saveFailed") + " " + ex.Message, App.Name, MessageBoxButtons.OK, MessageBoxIcon.Error); }
            }
        }

        void DrawItem(object sender, DrawItemEventArgs e)
        {
            if (e.Index < 0) return;
            var g = e.Graphics;
            HQ(g);
            var r = e.Bounds;
            using (var b = new SolidBrush(Theme.Card)) g.FillRectangle(b, r);
            if (list.Items[e.Index] is GroupHeader gh)
            {
                TextRenderer.DrawText(g, gh.Text.ToUpper(Loc.Culture), Caption,
                    new Rectangle(r.X + D(10), r.Y + D(8), r.Width - D(20), D(20)), Muted, Theme.Card, TextFormatFlags.NoPadding);
                return;
            }
            var p = (Profile)list.Items[e.Index];
            bool sel = (e.State & DrawItemState.Selected) != 0;
            bool active = p.Id == App.Settings.SelectedProfileId;
            Color bg = sel ? AccentSoft : Theme.Card;
            var inner = new RectangleF(r.X + D(2), r.Y + D(2), r.Width - D(5), r.Height - D(4));
            using (var path = Round(inner, D(8)))
            {
                using (var b = new SolidBrush(bg)) g.FillPath(b, path);
                if (sel) using (var pen = new Pen(AccentBorder)) g.DrawPath(pen, path);
            }

            bool running = App.Engine.State == EngineState.Running && (App.Engine.ActiveProfile?.Id ?? App.Settings.SelectedProfileId) == p.Id;
            Color dot = running ? Green : active ? Accent : Mix(Theme.Card, Theme.Text, 0.2f);
            using (var b = new SolidBrush(dot)) g.FillEllipse(b, r.X + D(14), r.Y + D(15), D(10), D(10));

            int x = r.X + D(34);
            var flags = TextFormatFlags.NoPadding | TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis;
            var nameSize = TextRenderer.MeasureText(g, p.Name, Bold, Size.Empty, TextFormatFlags.NoPadding | TextFormatFlags.SingleLine);
            int nameW = Math.Min(nameSize.Width, r.Width - D(170));
            TextRenderer.DrawText(g, p.Name, Bold, new Rectangle(x, r.Y + D(8), nameW + D(2), D(22)), Theme.Text, bg, flags);

            int bx = x + nameW + D(8);
            if (running || active) bx = Badge(g, running ? Loc.T("profilesPage.badge.running") : Loc.T("profilesPage.badge.selected"), running ? GreenText : AccentInk, running ? GreenSoft : AccentSoft, bx, r.Y + D(9));
            if (ProfileCatalog.IsException(p, level, App.Settings.ShowExpertProfiles)) bx = Badge(g, Loc.T("profilesPage.badge.expert"), AmberText, AmberSoft, bx, r.Y + D(9));
            else if (!p.BuiltIn) bx = Badge(g, Loc.T("profilesPage.badge.custom"), AccentInk, Mix(Theme.Card, Accent, 0.15f), bx, r.Y + D(9));
            if (bx < r.Right - D(70))
            {
                if (p.IsGoodbyeDpi && !p.UsesDnsRedirect) Badge(g, Loc.T("profilesPage.badge.noDns"), AmberText, AmberSoft, bx, r.Y + D(9));
                else if (p.Engine == EngineKind.ByeDpi) Badge(g, Loc.T("profilesPage.badge.noDriver"), GreenText, GreenSoft, bx, r.Y + D(9));
            }

            TextRenderer.DrawText(g, p.Description, Small, new Rectangle(x, r.Y + D(30), r.Width - D(44), D(18)), Muted, bg, flags);
            if (detailed)
                TextRenderer.DrawText(g, string.Join(" · ", ProfileCatalog.TechnicalTags(p)), MonoSmall, new Rectangle(x, r.Y + D(48), r.Width - D(44), D(16)), Mix(Muted, bg, 0.2f), bg, flags);
        }

        static int Badge(Graphics g, string text, Color fg, Color bg, int x, int y)
        {
            var flags = TextFormatFlags.NoPadding | TextFormatFlags.SingleLine;
            var sz = TextRenderer.MeasureText(g, text, Caption, Size.Empty, flags);
            var rect = new RectangleF(x, y, sz.Width + D(12), D(18));
            using (var p = Round(rect, D(9)))
            using (var b = new SolidBrush(bg)) g.FillPath(b, p);
            TextRenderer.DrawText(g, text, Caption, new Rectangle(x + D(6), y, sz.Width + D(2), D(18)), fg, bg,
                flags | TextFormatFlags.VerticalCenter);
            return (int)rect.Right + D(5);
        }
    }

    /// <summary>
    /// Editor of a Zapret or ByeDPI profile: name, description and the parameters (one winws rule or one ByeDPI group per
    /// line), checked live against the engine's allow list, with the command it will run.
    /// </summary>
    sealed class EngineProfileEditor : Form
    {
        readonly Profile p;
        readonly IDpiEngine eng;
        readonly TextBox tName, tDesc, tArgs, tPreview;
        readonly Label lCheck;
        readonly FlatBtn ok, bCopyCmd;

        public EngineProfileEditor(Profile profile)
        {
            p = profile;
            eng = Engines.Of(profile);
            Text = (profile.BuiltIn ? Loc.T("profileEdit.builtInTitle", profile.Name) : Loc.T("profileEdit.title")) + " – " + eng.DisplayName;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterParent;
            MaximizeBox = MinimizeBox = false;
            ShowInTaskbar = false;
            AutoScaleMode = AutoScaleMode.None;
            BackColor = Bg;
            Font = Body;
            ClientSize = new Size(D(960), D(640));
            UIx.FitDialog(this);
            Icon = IconArt.AppIcon(32);

            Label Lbl(string t, int x, int y, int w = 150, Font f = null, Color? c = null)
            {
                var l = UIx.L(t, f ?? Body, c ?? Theme.Text, x, y, w, 24, ContentAlignment.MiddleLeft);
                Controls.Add(l);
                return l;
            }
            Lbl(Loc.T("profileEdit.name"), 20, 16);
            tName = Theme.Style(new TextBox { Bounds = R(170, 16, 430, 24), Text = p.Name, Font = Body });
            Controls.Add(tName);
            Lbl(Loc.T("profileEdit.description"), 20, 48);
            tDesc = Theme.Style(new TextBox { Bounds = R(170, 48, 430, 24), Text = p.Description, Font = Body });
            Controls.Add(tDesc);

            Lbl(Loc.T("engineEdit.params", eng.DisplayName), 20, 86, 580, Caption, Muted);
            tArgs = Theme.Style(new TextBox
            {
                Bounds = R(20, 112, 580, 330), Multiline = true, Font = Mono, ScrollBars = ScrollBars.Vertical, WordWrap = true,
                Text = FormatArgs(eng, p.EngineArgs), AcceptsReturn = true,
            });
            Controls.Add(tArgs);
            lCheck = UIx.L("", Small, Muted, 20, 448, 580, 40);
            Controls.Add(lCheck);

            Lbl(Loc.T("profileEdit.preview"), 20, 494, 300, Bold);
            bCopyCmd = new FlatBtn { Text = Loc.T("profilesPage.copyCommand"), Glyph = GCopy, Kind = FlatBtn.Kinds.Secondary, Bounds = R(400, 488, 200, 30), BackColor = Bg, Font = Small };
            Controls.Add(bCopyCmd);
            bCopyCmd.Click += (s, e) => ProfilesPage.CopyCommand(Draft(), this);
            tPreview = Theme.Style(new TextBox { Bounds = R(20, 520, 580, 104), Multiline = true, ReadOnly = true, Font = Mono, ScrollBars = ScrollBars.Vertical });
            Controls.Add(tPreview);

            // right: help (allowed options, payload names, what the app adds itself)
            var hc = new Card { Bounds = R(620, 16, 320, 560) };
            Controls.Add(hc);
            var help = new ReportBox { Bounds = R(14, 12, 292, 536) };
            hc.Add(help);
            help.BackColor = Theme.Card;
            help.Out(eng.DisplayName, Theme.Text, Big);
            help.Blank();
            help.Out(Loc.T("engineEdit.help." + eng.Id), Theme.Text, Small);
            help.Blank();
            help.Out(Loc.T("engineEdit.helpSafety"), AmberText, Small);
            if (eng.Kind == EngineKind.Zapret)
            {
                help.Blank();
                help.Out(Loc.T("engineEdit.payloads"), Muted, Caption);
                foreach (var n in WinwsPolicy.Payloads) help.Out(n, Theme.Text, MonoSmall);
            }
            help.Blank();
            help.Out(Loc.T("engineEdit.options"), Muted, Caption);
            help.Out(string.Join("  ", (eng.Kind == EngineKind.Zapret ? WinwsPolicy.KnownOptions : CiadpiPolicy.KnownOptions).OrderBy(o => o)), Muted, MonoSmall);
            help.SelectionStart = 0;
            help.ScrollToCaret();

            ok = new FlatBtn { Text = Loc.T("common.save"), Glyph = GSave, Kind = FlatBtn.Kinds.Primary, Bounds = R(620, 588, 150, 38), BackColor = Bg };
            var cancel = new FlatBtn { Text = Loc.T("common.cancel"), Kind = FlatBtn.Kinds.Secondary, Bounds = R(780, 588, 160, 38), BackColor = Bg };
            Controls.Add(ok); Controls.Add(cancel);
            ok.Click += (s, e) => Save();
            cancel.Click += (s, e) => { DialogResult = DialogResult.Cancel; Close(); };

            if (p.BuiltIn)
            {
                tName.ReadOnly = tDesc.ReadOnly = tArgs.ReadOnly = true;
                ok.Text = Loc.T("profileEdit.editCopy");
                ok.Glyph = GCopy;
                cancel.Text = Loc.T("common.close");
            }
            tArgs.TextChanged += (s, e) => Sync();
            Sync();
        }

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            Native.DarkTitle(Handle, IsDark);
        }

        /// <summary>One winws rule (--new) or one ByeDPI group (--auto) per line, so long parameters stay readable.</summary>
        internal static string FormatArgs(IDpiEngine eng, string args)
        {
            var t = Engines.Tokens(args);
            var lines = new List<List<string>> { new List<string>() };
            for (int i = 0; i < t.Count; i++)
            {
                bool split = eng.Kind == EngineKind.Zapret ? t[i] == "--new" : t[i] == "--auto" || t[i].StartsWith("--auto=");
                if (split && lines[lines.Count - 1].Count > 0) lines.Add(new List<string>());
                lines[lines.Count - 1].Add(t[i]);
            }
            return string.Join("\r\n", lines.Select(l => string.Join(" ", l)));
        }

        /// <summary>The stored form: line breaks and repeated spaces become single spaces.</summary>
        internal static string Collapse(string text) => string.Join(" ", Engines.Tokens(text));

        Profile Draft() => new Profile { Name = tName.Text.Trim(), Engine = eng.Kind, EngineArgs = Collapse(tArgs.Text), Mode = "", Dns = DnsChoice.None };

        void Sync()
        {
            var tmp = Draft();
            bool valid = eng.Validate(tmp, out string err);
            lCheck.Text = valid ? "✓ " + Loc.T("engineEdit.valid") : "✗ " + err;
            lCheck.ForeColor = valid ? GreenText : RedText;
            // the same validation, lists, port and quoting as a real start; an invalid draft shows its error and cannot be copied
            tPreview.Text = valid ? ProfilesPage.Preview(tmp) + "\r\n\r\n" + Loc.T("profileEdit.previewNote") : "✗ " + err;
            if (bCopyCmd != null) bCopyCmd.Enabled = valid;
            if (!p.BuiltIn) ok.Enabled = valid;
        }

        void Save()
        {
            if (p.BuiltIn) { DialogResult = DialogResult.Retry; Close(); return; }
            string name = tName.Text.Trim();
            if (name.Length == 0) { MessageBox.Show(this, Loc.T("profileEdit.nameEmpty"), App.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
            var tmp = new Profile { Engine = eng.Kind, EngineArgs = Collapse(tArgs.Text), Mode = "", Dns = DnsChoice.None };
            if (!eng.Validate(tmp, out string err))
            {
                MessageBox.Show(this, Loc.T("profileEdit.argsRejected") + " " + err, App.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            p.Name = ArgPolicy.CleanText(name, 80);
            p.Description = ArgPolicy.CleanText(tDesc.Text, 600);
            p.EngineArgs = tmp.EngineArgs;
            p.Mode = "";
            p.Dns = DnsChoice.None;
            DialogResult = DialogResult.OK;
            Close();
        }
    }

    /// <summary>Profile editor window: the explanation of every option is shown in the right panel.</summary>
    sealed class ProfileEditor : Form
    {
        readonly Profile p;
        readonly TextBox tName, tDesc, tExtra, tRaw, tPreview, tDns4, tDns6;
        readonly NumericUpDown nDns4Port, nDns6Port, nFake, nResend, nHttps, nHttp;
        readonly ThemedCombo cMode, cTtl, cDns;
        readonly CheckX chkChk, chkSeq, chkNative, chkReverse, chkQuic, chkSni, chkPayload, chkNoSni, chkPassive, chkHostR, chkHostS, chkHostM, chkRaw;
        readonly Label lDns4, lDns6;
        readonly ReportBox help;
        FlatBtn bCopyCmd;
        readonly List<(DnsChoice Id, string Label)> dnsItems = new List<(DnsChoice, string)>();
        string lastTopic;

        static readonly (string Value, string Label)[] Modes =
        {
            ("", "profileEdit.mode.none"),
            ("-1", "profileEdit.mode.m1"), ("-2", "profileEdit.mode.m2"),
            ("-3", "profileEdit.mode.m3"), ("-4", "profileEdit.mode.m4"),
            ("-5", "profileEdit.mode.m5"), ("-6", "profileEdit.mode.m6"),
            ("-7", "profileEdit.mode.m7"), ("-8", "profileEdit.mode.m8"),
            ("-9", "profileEdit.mode.m9"),
        };

        public ProfileEditor(Profile profile)
        {
            p = profile;
            Text = profile.BuiltIn ? Loc.T("profileEdit.builtInTitle", profile.Name) : Loc.T("profileEdit.title");
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterParent;
            MaximizeBox = MinimizeBox = false;
            ShowInTaskbar = false;
            AutoScaleMode = AutoScaleMode.None;
            BackColor = Bg;
            Font = Body;
            ClientSize = new Size(D(960), D(690));
            UIx.FitDialog(this);
            Icon = IconArt.AppIcon(32);

            Label Lbl(string t, int x, int y, int w = 150, Font f = null, Color? c = null)
            {
                var l = UIx.L(t, f ?? Body, c ?? Theme.Text, x, y, w, 24, ContentAlignment.MiddleLeft);
                Controls.Add(l);
                return l;
            }
            T Add<T>(T c, string topic) where T : Control
            {
                Controls.Add(c);
                if (topic != null)
                {
                    c.Enter += (s, e) => ShowHelp(topic);
                    c.MouseEnter += (s, e) => ShowHelp(topic);
                }
                return c;
            }
            TextBox Tb(int x, int y, int w, string text, string topic, Font f = null) =>
                Add(Theme.Style(new TextBox { Bounds = R(x, y, w, 24), Text = text, Font = f ?? Body }), topic);
            NumericUpDown Num(int x, int y, int w, int min, int max, int val, string topic) =>
                Add(Theme.Style(new NumericUpDown { Bounds = R(x, y, w, 24), Minimum = min, Maximum = max, Value = Math.Max(min, Math.Min(max, val)) }), topic);
            CheckX Chk(string t, bool v, int x, int y, string topic) =>
                Add(new CheckX { Text = t, Checked = v, Bounds = R(x, y, 280, 24), BackColor = Bg }, topic);

            Lbl(Loc.T("profileEdit.name"), 20, 16);
            tName = Tb(170, 16, 430, p.Name, "name");
            Lbl(Loc.T("profileEdit.description"), 20, 48);
            tDesc = Tb(170, 48, 430, p.Description, "name");

            Lbl(Loc.T("profileEdit.method"), 20, 86, 300, Caption, Muted);
            Lbl(Loc.T("profileEdit.baseMode"), 20, 108);
            cMode = Add(new ThemedCombo { Bounds = R(170, 108, 430, 24) }, "mode");
            foreach (var m in Modes) cMode.Items.Add(Loc.T(m.Label));
            cMode.SelectedIndex = Math.Max(0, Array.FindIndex(Modes, m => m.Value == (p.Mode ?? "")));
            cMode.SelectedIndexChanged += (s, e) => ShowHelp("mode:" + Modes[Math.Max(0, cMode.SelectedIndex)].Value);

            Lbl(Loc.T("profileEdit.fakeTtl"), 20, 140);
            cTtl = Add(new ThemedCombo { Bounds = R(170, 140, 160, 24) }, "ttl");
            cTtl.Items.Add(Loc.T("profileEdit.ttlOff"));
            cTtl.Items.Add(Loc.T("profileEdit.ttlAuto"));
            for (int i = 1; i <= 12; i++) cTtl.Items.Add("TTL " + i);
            cTtl.SelectedIndex = p.Ttl == "auto" ? 1 : int.TryParse(p.Ttl, out int ttl) && ttl >= 1 && ttl <= 12 ? ttl + 1 : 0;
            Lbl(Loc.T("profileEdit.httpsFrag"), 350, 140, 120);
            nHttps = Num(480, 140, 120, 0, 1000, p.HttpsFrag, "httpsfrag");

            Lbl(Loc.T("profileEdit.fakeCount"), 20, 172);
            nFake = Num(170, 172, 160, 0, 30, p.FakeGen, "fakegen");
            Lbl(Loc.T("profileEdit.fakeRepeat"), 350, 172, 120);
            nResend = Num(480, 172, 120, 1, 20, Math.Max(1, p.FakeResend), "fakeresend");

            Lbl(Loc.T("profileEdit.httpFrag"), 20, 204);
            nHttp = Num(170, 204, 160, 0, 1000, p.HttpFrag, "httpfrag");

            Lbl(Loc.T("profileEdit.dnsRedirect"), 20, 244, 300, Caption, Muted);
            Lbl(Loc.T("profileEdit.dnsServer"), 20, 266);
            cDns = Add(new ThemedCombo { Bounds = R(170, 266, 430, 24) }, "dns");
            foreach (var d in DnsProviders.All) dnsItems.Add((d.Id, d.Name + " – " + d.V4 + ":" + d.V4Port + (d.Id == DnsChoice.Yandex ? " " + Loc.T("profileEdit.recommended") : "")));
            dnsItems.Add((DnsChoice.Custom, Loc.T("profileEdit.customServer")));
            dnsItems.Add((DnsChoice.None, Loc.T("profileEdit.dnsOff")));
            foreach (var d in dnsItems) cDns.Items.Add(d.Label);
            cDns.SelectedIndex = Math.Max(0, dnsItems.FindIndex(d => d.Id == p.Dns));

            lDns4 = Lbl(Loc.T("profileEdit.ipv4"), 20, 298);
            tDns4 = Tb(170, 298, 300, p.CustomDns4, "dns:custom");
            nDns4Port = Num(480, 298, 120, 1, 65535, p.CustomDns4Port <= 0 ? 53 : p.CustomDns4Port, "dns:custom");
            lDns6 = Lbl(Loc.T("profileEdit.ipv6"), 20, 328);
            tDns6 = Tb(170, 328, 300, p.CustomDns6, "dns:custom");
            nDns6Port = Num(480, 328, 120, 1, 65535, p.CustomDns6Port <= 0 ? 53 : p.CustomDns6Port, "dns:custom");

            Lbl(Loc.T("profileEdit.extraOptions"), 20, 366, 300, Caption, Muted);
            chkSeq = Chk(Loc.T("profileEdit.wrongSeq"), p.WrongSeq, 20, 388, "wrongseq");
            chkChk = Chk(Loc.T("profileEdit.wrongChk"), p.WrongChksum, 20, 414, "wrongchk");
            chkNative = Chk(Loc.T("profileEdit.native"), p.NativeFrag, 20, 440, "native");
            chkReverse = Chk(Loc.T("profileEdit.reverse"), p.ReverseFrag, 20, 466, "reverse");
            chkSni = Chk(Loc.T("profileEdit.sni"), p.FragBySni, 20, 492, "sni");
            chkPayload = Chk(Loc.T("profileEdit.payload"), p.MaxPayload, 20, 518, "payload");
            chkQuic = Chk(Loc.T("profileEdit.quic"), p.BlockQuic, 320, 388, "quic");
            chkNoSni = Chk(Loc.T("profileEdit.noSni"), p.AllowNoSni, 320, 414, "nosni");
            chkPassive = Chk(Loc.T("profileEdit.passive"), p.PassiveDpi, 320, 440, "passive");
            chkHostR = Chk("Host → hoSt (-r)", p.HostReplace, 320, 466, "hostr");
            chkHostS = Chk(Loc.T("profileEdit.hostSpace"), p.HostRemoveSpace, 320, 492, "hosts");
            chkHostM = Chk(Loc.T("profileEdit.hostCase"), p.HostMixCase, 320, 518, "hostm");

            Lbl(Loc.T("profileEdit.extraParams"), 20, 552);
            tExtra = Tb(170, 552, 430, p.ExtraArgs, "extra", Mono);
            chkRaw = Add(new CheckX { Text = Loc.T("profileEdit.raw"), Checked = p.UseRaw, Bounds = R(20, 584, 580, 24), BackColor = Bg }, "raw");
            tRaw = Add(Theme.Style(new TextBox { Bounds = R(20, 612, 580, 60), Multiline = true, Font = Mono, Text = p.RawArgs, ScrollBars = ScrollBars.Vertical }), "raw");

            // --- right: help panel
            var hc = new Card { Bounds = R(620, 16, 320, 440) };
            Controls.Add(hc);
            help = new ReportBox { Bounds = R(14, 12, 292, 416) };
            hc.Add(help);
            help.BackColor = Theme.Card;

            Lbl(Loc.T("profileEdit.preview"), 620, 466, 170, Bold);
            bCopyCmd = new FlatBtn { Text = Loc.T("profilesPage.copyCommand"), Glyph = GCopy, Kind = FlatBtn.Kinds.Secondary, Bounds = R(790, 461, 150, 28), BackColor = Bg, Font = Small };
            Controls.Add(bCopyCmd);
            bCopyCmd.Click += (s, e) => ProfilesPage.CopyCommand(Collect(new Profile()), this);
            tPreview = Add(Theme.Style(new TextBox { Bounds = R(620, 492, 320, 132), Multiline = true, ReadOnly = true, Font = Mono, ScrollBars = ScrollBars.Vertical }), "preview");

            var ok = new FlatBtn { Text = Loc.T("common.save"), Glyph = GSave, Kind = FlatBtn.Kinds.Primary, Bounds = R(620, 636, 150, 38), BackColor = Bg };
            var cancel = new FlatBtn { Text = Loc.T("common.cancel"), Kind = FlatBtn.Kinds.Secondary, Bounds = R(780, 636, 160, 38), BackColor = Bg };
            Controls.Add(ok); Controls.Add(cancel);
            ok.Click += (s, e) => Save();
            cancel.Click += (s, e) => { DialogResult = DialogResult.Cancel; Close(); };

            if (p.BuiltIn)
            {
                foreach (Control c in Controls)
                    if (!(c is Label) && !(c is Card) && c != cancel && c != tPreview && c != ok) c.Enabled = false;
                ok.Text = Loc.T("profileEdit.editCopy");
                ok.Glyph = GCopy;
                cancel.Text = Loc.T("common.close");
            }

            foreach (Control c in Controls)
            {
                if (c is CheckX cb) cb.CheckedChanged += (s, e) => Sync();
                else if (c is ComboBox co) co.SelectedIndexChanged += (s, e) => Sync();
                else if (c is NumericUpDown nu) nu.ValueChanged += (s, e) => Sync();
                else if (c is TextBox tb && tb != tPreview) tb.TextChanged += (s, e) => Sync();
            }
            chkRaw.CheckedChanged += (s, e) =>
            {
                if (chkRaw.Checked && string.IsNullOrWhiteSpace(tRaw.Text)) tRaw.Text = Collect(new Profile()).BuildArgs(null);
            };
            Sync();
            ShowHelp("intro");
        }

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            Native.DarkTitle(Handle, IsDark);
        }

        void ShowHelp(string key)
        {
            if (key == lastTopic) return;
            lastTopic = key;
            var t = ProfileHelp.Get(key);
            help.Clear();
            help.Out(t.Title, Theme.Text, Big);
            if (!string.IsNullOrEmpty(t.Flag)) help.Out(t.Flag, AccentInk, Mono);
            help.Blank();
            help.Out(t.Text, Theme.Text, Body);
            if (key == "dns" && cDns != null && cDns.SelectedIndex >= 0)
            {
                var prov = DnsProviders.Get(dnsItems[cDns.SelectedIndex].Id);
                if (prov != null) { help.Blank(); help.Out(Loc.T("profileEdit.selectedDns") + " " + prov.Name, Theme.Text, Bold); help.Out(prov.Note, Muted, Small); }
            }
            if (key == "intro" || key == "name")
            {
                help.Blank();
                help.Out(Loc.T("profileEdit.summary"), Muted, Caption);
                foreach (var (title, _, warn) in ProfileHelp.Explain(Collect(new Profile())))
                    help.Out("• " + title, warn ? AmberText : Theme.Text, Small);
            }
            help.SelectionStart = 0;
            help.ScrollToCaret();
        }

        Profile Collect(Profile t)
        {
            t.Name = tName.Text.Trim();
            t.Description = tDesc.Text.Trim();
            t.Mode = Modes[Math.Max(0, cMode.SelectedIndex)].Value;
            t.Ttl = cTtl.SelectedIndex <= 0 ? "" : cTtl.SelectedIndex == 1 ? "auto" : (cTtl.SelectedIndex - 1).ToString();
            t.FakeGen = (int)nFake.Value;
            t.FakeResend = (int)nResend.Value;
            t.HttpsFrag = (int)nHttps.Value;
            t.HttpFrag = (int)nHttp.Value;
            t.Dns = dnsItems[Math.Max(0, cDns.SelectedIndex)].Id;
            t.CustomDns4 = tDns4.Text.Trim();
            t.CustomDns4Port = (int)nDns4Port.Value;
            t.CustomDns6 = tDns6.Text.Trim();
            t.CustomDns6Port = (int)nDns6Port.Value;
            t.WrongChksum = chkChk.Checked;
            t.WrongSeq = chkSeq.Checked;
            t.NativeFrag = chkNative.Checked;
            t.ReverseFrag = chkReverse.Checked;
            t.BlockQuic = chkQuic.Checked;
            t.FragBySni = chkSni.Checked;
            t.MaxPayload = chkPayload.Checked;
            t.AllowNoSni = chkNoSni.Checked;
            t.PassiveDpi = chkPassive.Checked;
            t.HostReplace = chkHostR.Checked;
            t.HostRemoveSpace = chkHostS.Checked;
            t.HostMixCase = chkHostM.Checked;
            t.ExtraArgs = tExtra.Text.Trim();
            t.UseRaw = chkRaw.Checked;
            t.RawArgs = tRaw.Text.Trim();
            return t;
        }

        void Sync()
        {
            if (tPreview == null) return;
            var tmp = Collect(new Profile());
            bool valid = CommandPreview.TryBuild(tmp, App.Settings, false, out string cmd, out string err);
            tPreview.Text = valid ? cmd + "\r\n\r\n" + Loc.T("profileEdit.previewNote") : "✗ " + err;
            if (bCopyCmd != null) bCopyCmd.Enabled = valid;
            if (p.BuiltIn) return;
            bool raw = chkRaw.Checked;
            bool custom = dnsItems[Math.Max(0, cDns.SelectedIndex)].Id == DnsChoice.Custom;
            foreach (Control c in new Control[] { cMode, cTtl, nFake, nResend, nHttps, nHttp, cDns, chkChk, chkSeq, chkNative, chkReverse, chkQuic, chkSni, chkPayload, chkPassive, chkHostR, chkHostS, chkHostM, tExtra })
                c.Enabled = !raw;
            foreach (Control c in new Control[] { tDns4, tDns6, nDns4Port, nDns6Port, lDns4, lDns6 })
                c.Enabled = !raw && custom;
            tRaw.Enabled = raw;
        }

        void Save()
        {
            if (p.BuiltIn) { DialogResult = DialogResult.Retry; Close(); return; }
            var tmp = Collect(new Profile());
            if (tmp.Name.Length == 0) { Warn(Loc.T("profileEdit.nameEmpty")); return; }
            if (!tmp.UseRaw && tmp.Dns == DnsChoice.Custom)
            {
                if (tmp.CustomDns4.Length > 0 && !(IPAddress.TryParse(tmp.CustomDns4, out var a4) && a4.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork))
                { Warn(Loc.T("profileEdit.badIpv4")); return; }
                if (tmp.CustomDns6.Length > 0 && !(IPAddress.TryParse(tmp.CustomDns6, out var a6) && a6.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6))
                { Warn(Loc.T("profileEdit.badIpv6")); return; }
                if (tmp.CustomDns4.Length == 0 && tmp.CustomDns6.Length == 0) { Warn(Loc.T("profileEdit.customDnsEmpty")); return; }
            }
            if (tmp.BuildArgs(null).Trim().Length == 0) { Warn(Loc.T("profileEdit.noMethod")); return; }
            if (!ArgPolicy.ValidateProfile(tmp, out string argErr))
            { Warn(Loc.T("profileEdit.argsRejected") + " " + argErr); return; }
            if (!tmp.UsesDnsRedirect &&
                MessageBox.Show(this, Loc.T("profileEdit.noDnsConfirm"),
                    App.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
            Collect(p);
            DialogResult = DialogResult.OK;
            Close();
        }

        void Warn(string m) => MessageBox.Show(this, m, App.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
    }
}
