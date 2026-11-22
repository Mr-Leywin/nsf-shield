using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;
using static NSFShield.Theme;

namespace NSFShield
{
    /// <summary>
    /// Domain lists: Include (apply the bypass only to these sites) and Exclude (never touch these sites). The lists are
    /// validated host names; while protection starts they are written to data\lists\include.txt / exclude.txt.
    /// </summary>
    sealed class SitesPage : PageBase
    {
        public override string Key => "sites";

        readonly Segmented tabs;
        readonly Label support, count, fileInfo, pending;
        readonly ToggleRow modeRow;
        readonly ListBox list;
        readonly TextBox input;
        readonly FlatBtn apply, bTemplates;
        bool exclude;

        List<string> Items => exclude ? App.Settings.ExcludeDomains : App.Settings.TargetDomains;

        public SitesPage()
        {
            Header(Loc.T("sitesPage.title"), Loc.T("sitesPage.subtitle"));

            tabs = new Segmented(Loc.T("sitesPage.tabInclude"), Loc.T("sitesPage.tabExclude")) { Bounds = R(28, 70, 430, 36), BackColor = Bg };
            Controls.Add(tabs);
            tabs.SelectedChanged += (s, e) => { exclude = tabs.SelectedIndex == 1; Rebuild(); };
            support = UIx.L("", Small, Muted, 470, 68, 322, 40, ContentAlignment.MiddleLeft);
            Controls.Add(support);

            var top = AddCard(28, 114, 764, 84);
            modeRow = new ToggleRow("", "", D(744)) { Location = new Point(D(10), D(10)), Divider = false };
            top.Add(modeRow);
            modeRow.Switch.CheckedChanged += (s, e) =>
            {
                bool on = modeRow.Switch.Checked;
                if (exclude) App.Settings.ExcludeEnabled = on; else App.Settings.TargetedMode = on;
                App.Save();
                App.Log((exclude ? "Exclude list " : "Targeted mode (include list) ") + (on ? "turned on." : "turned off."), LogLevel.Info);
                UpdateSupport();
                App.RaiseStatus();
                _ = Actions.RestartIfActiveAsync();
            };

            var card = AddCard(28, 210, 764, 410);
            card.Add(UIx.L(Loc.T("sitesPage.list"), Caption, Muted, 20, 16, 200, 18));
            count = card.Add(UIx.L("", Small, Muted, 300, 16, 180, 18, ContentAlignment.TopRight));
            list = Theme.Style(new ListBox
            {
                Bounds = R(20, 40, 460, 352), Font = Body, IntegralHeight = false,
                BorderStyle = BorderStyle.FixedSingle, SelectionMode = SelectionMode.MultiExtended,
            });
            card.Add(list);
            list.KeyDown += (s, e) => { if (e.KeyCode == Keys.Delete) RemoveSelected(); };

            card.Add(UIx.L(Loc.T("sitesPage.addSites"), Bold, Theme.Text, 500, 36, 244, 22));
            input = Theme.Style(new TextBox { Bounds = R(500, 60, 244, 64), Font = Body, Multiline = true, ScrollBars = ScrollBars.Vertical, AcceptsReturn = true });
            card.Add(input);
            input.KeyDown += (s, e) => { if (e.KeyCode == Keys.Enter && e.Control) { e.SuppressKeyPress = true; AddSites(); } };
            var bAdd = card.Add(new FlatBtn { Text = Loc.T("sitesPage.add"), Glyph = GAdd, Kind = FlatBtn.Kinds.Primary, Bounds = R(500, 132, 244, 36) });
            bAdd.Click += (s, e) => AddSites();
            var bDel = card.Add(new FlatBtn { Text = Loc.T("sitesPage.deleteSelected"), Glyph = GDelete, Kind = FlatBtn.Kinds.Secondary, Bounds = R(500, 174, 244, 36) });
            bDel.Click += (s, e) => RemoveSelected();
            bTemplates = card.Add(new FlatBtn { Text = Loc.T("sitesPage.addPreset"), Glyph = GChevron, Kind = FlatBtn.Kinds.Secondary, Bounds = R(500, 216, 244, 36) });
            bTemplates.Click += (s, e) => ShowTemplates();
            fileInfo = card.Add(UIx.L("", Small, Muted, 500, 258, 244, 56));
            fileInfo.Visible = App.Settings.UiLevel == UiLevel.Advanced;   // the file path is an advanced detail

            pending = card.Add(UIx.L(Loc.T("sitesPage.restartNeeded"), Small, AmberText, 500, 314, 244, 36));
            apply = card.Add(new FlatBtn { Text = Loc.T("sitesPage.applyNow"), Glyph = GRefresh, Kind = FlatBtn.Kinds.Warning, Bounds = R(500, 356, 244, 36) });
            apply.Click += async (s, e) => { pending.Visible = apply.Visible = false; await Actions.StartAsync(); };
            pending.Visible = apply.Visible = false;

            OnStatus(() => { if (Visible) UpdateSupport(); });
            Rebuild();
        }

        public override void OnActivated() => Rebuild();

        /// <summary>Shows the include or the exclude list (for tests and screenshots too).</summary>
        internal void ShowList(bool excludeList)
        {
            exclude = excludeList;
            tabs.SetSilently(excludeList ? 1 : 0);
            Rebuild();
        }

        void Rebuild()
        {
            var row = (Label[])modeRow.Controls.OfType<Label>().ToArray();
            if (row.Length >= 2)
            {
                row[0].Text = Loc.T(exclude ? "sitesPage.excludeMode" : "sitesPage.targeted");
                row[1].Text = Loc.T(exclude ? "sitesPage.excludeInfo" : "sitesPage.targetedInfo");
            }
            modeRow.Switch.SetSilently(exclude ? App.Settings.ExcludeEnabled : App.Settings.TargetedMode);
            fileInfo.Text = Loc.T("sitesPage.fileInfo", @"data\lists\" + (exclude ? Hostlists.ExcludeName : Hostlists.IncludeName));
            Reload();
            UpdateSupport();
        }

        void Reload()
        {
            list.BeginUpdate();
            list.Items.Clear();
            foreach (var d in Items) list.Items.Add(d);
            list.EndUpdate();
            count.Text = Loc.T("sitesPage.countText", Items.Count);
        }

        /// <summary>Which list the active engine can use; an unsupported combination is shown in amber.</summary>
        void UpdateSupport()
        {
            var eng = App.Engine.Current;
            bool ok = exclude ? eng.SupportsExclude : eng.SupportsInclude;
            bool on = exclude ? App.Settings.ExcludeEnabled : App.Settings.TargetedMode;
            support.Text = ok ? Loc.T(exclude ? "sitesPage.supportExclude" : "sitesPage.supportInclude", eng.DisplayName)
                              : Loc.T("sitesPage.unsupported", eng.DisplayName);
            support.ForeColor = !ok && on ? AmberText : Muted;
        }

        void Changed()
        {
            App.Settings.Normalize();
            App.Save();
            Reload();
            App.RaiseStatus();
            bool on = exclude ? App.Settings.ExcludeEnabled : App.Settings.TargetedMode;
            if (on && App.Engine.IsActive) pending.Visible = apply.Visible = true;
        }

        void AddSites()
        {
            var (ok, bad) = Hostlists.ParseMany(input.Text);
            int added = 0;
            foreach (var d in ok)
            {
                if (Items.Count >= Hostlists.MaxEntries) { bad.Add(Loc.T("lists.tooMany", Hostlists.MaxEntries)); break; }
                if (!Items.Contains(d)) { Items.Add(d); added++; }
            }
            if (bad.Count > 0)
                MessageBox.Show(FindForm(), Loc.T("sitesPage.badDomains", string.Join("\n", bad.Take(10)) + (bad.Count > 10 ? "\n…" : "")),
                    App.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            input.Text = bad.Count > 0 ? string.Join(Environment.NewLine, bad.Take(10)) : "";
            if (added > 0) Changed();
        }

        void RemoveSelected()
        {
            var sel = list.SelectedItems.Cast<string>().ToList();
            if (sel.Count == 0) return;
            if (!exclude && sel.Count >= App.Settings.TargetDomains.Count)
            {
                MessageBox.Show(FindForm(), Loc.T("sitesPage.keepOne"), App.Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            Items.RemoveAll(sel.Contains);
            Changed();
        }

        void ShowTemplates()
        {
            var m = new ContextMenuStrip { Font = Body, ShowImageMargin = false };
            foreach (var t in exclude ? Hostlists.ExcludeTemplates : Hostlists.IncludeTemplates)
            {
                var tpl = t;
                m.Items.Add(tpl.Name + " " + Loc.T("sitesPage.presetCount", tpl.Domains.Length), null, (s2, e2) =>
                {
                    foreach (var d in tpl.Domains)
                        if (!Items.Contains(d) && Items.Count < Hostlists.MaxEntries) Items.Add(d);
                    Changed();
                });
            }
            m.Closed += (s2, e2) => BeginInvoke(new Action(m.Dispose));
            m.Show(bTemplates, new Point(0, bTemplates.Height));
        }
    }
}
