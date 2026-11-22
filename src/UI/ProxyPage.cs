using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using static NSFShield.Theme;

namespace NSFShield
{
    /// <summary>Proxy: saved proxies, test, Windows proxy and per-program proxy.</summary>
    sealed class ProxyPage : PageBase
    {
        public override string Key => "proxy";

        readonly Segmented tabs;
        readonly Panel pList, pApps;

        // --- proxies
        readonly ListBox list;
        readonly TextBox tQuick, tName, tHost, tUser, tPass;
        readonly NumericUpDown nPort;
        readonly Segmented kind;
        readonly FlatBtn bSave, bTest, bNew, bBulk, bDel, bSys, bSysOff, bDiscord, bShortcut, bDiscordNormal;
        readonly ReportBox result;
        readonly Label sysState;
        ProxyEntry editing;

        // --- per program
        readonly ListBox appList;
        readonly TextBox aPath, aName, aArgs;
        readonly ThemedCombo aProxy;
        readonly Label aMode, aModeInfo, bridgeState;
        readonly CheckX aSeparate, aClose;
        readonly FlatBtn aAdd, aDel, aSave, aLaunch, aShortcut, aBrowse;
        ProxyApp editingApp;

        public ProxyPage()
        {
            Controls.Add(UIx.L("Proxy", H1, Theme.Text, 28, 2, 300, 36));
            Controls.Add(UIx.L(Loc.T("proxyPage.subtitle"),
                Body, Muted, 29, 40, 764, 22));
            tabs = new Segmented(Loc.T("proxyPage.tab.proxies"), Loc.T("proxyPage.tab.apps")) { Bounds = R(452, 4, 340, 34), BackColor = Bg };
            Controls.Add(tabs);
            pList = new Panel { Bounds = R(0, 72, 820, 568), BackColor = Bg };
            pApps = new Panel { Bounds = R(0, 72, 820, 568), BackColor = Bg, Visible = false };
            Controls.Add(pList);
            Controls.Add(pApps);
            tabs.SelectedChanged += (s, e) => { pList.Visible = tabs.SelectedIndex == 0; pApps.Visible = tabs.SelectedIndex == 1; if (pApps.Visible) ReloadApps(); };

            Card C(Panel host, int x, int y, int w, int h) { var c = new Card { Bounds = R(x, y, w, h) }; host.Controls.Add(c); return c; }

            // ============================================================ PROXIES
            var left = C(pList, 28, 4, 330, 412);
            left.Add(UIx.L(Loc.T("proxyPage.saved"), Caption, Muted, 18, 14, 290, 18));
            list = new ListBox
            {
                Bounds = R(8, 38, 314, 318), DrawMode = DrawMode.OwnerDrawFixed, ItemHeight = D(54),
                BorderStyle = BorderStyle.None, IntegralHeight = false, Font = Body,
            };
            left.Add(list);
            list.BackColor = Theme.Card;
            Theme.StyleScroll(list);
            list.DrawItem += DrawItem;
            list.SelectedIndexChanged += (s, e) => { if (list.SelectedItem is ProxyEntry p) Load(p); };
            bNew = left.Add(new FlatBtn { Text = Loc.T("proxyPage.new"), Glyph = GAdd, Kind = FlatBtn.Kinds.Secondary, Bounds = R(14, 362, 92, 36), Font = Small });
            bBulk = left.Add(new FlatBtn { Text = Loc.T("proxyPage.bulkAdd"), Glyph = GList, Kind = FlatBtn.Kinds.Secondary, Bounds = R(112, 362, 120, 36), Font = Small });
            bDel = left.Add(new FlatBtn { Text = Loc.T("proxyPage.delete"), Glyph = GDelete, Kind = FlatBtn.Kinds.Secondary, Bounds = R(238, 362, 78, 36), Font = Small });
            bNew.Click += (s, e) => { list.ClearSelected(); Load(null); tQuick.Focus(); };
            bBulk.Click += (s, e) => { using (var d = new BulkProxyDialog()) if (d.ShowDialog(FindForm()) == DialogResult.OK) Reload(d.FirstAddedId); };
            bDel.Click += (s, e) => Delete();

            var right = C(pList, 370, 4, 422, 412);
            right.Add(UIx.L(Loc.T("proxyPage.details"), Caption, Muted, 20, 14, 300, 18));
            Label Lbl(Card c, string t, int y) => c.Add(UIx.L(t, Body, Theme.Text, 20, y, 100, 26, ContentAlignment.MiddleLeft));
            Lbl(right, Loc.T("proxyPage.quickEntry"), 38);
            tQuick = right.Add(Theme.Style(new TextBox { Bounds = R(120, 38, 196, 26), Font = Body }));
            var bFill = right.Add(new FlatBtn { Text = Loc.T("proxyPage.fill"), Kind = FlatBtn.Kinds.Secondary, Bounds = R(322, 36, 84, 30), Font = Small });
            bFill.Click += (s, e) => QuickFill();
            tQuick.KeyDown += (s, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; QuickFill(); } };
            right.Add(UIx.L(Loc.T("proxyPage.quickExample"), Small, Muted, 120, 66, 290, 32));
            Lbl(right, Loc.T("proxyPage.name"), 100);
            tName = right.Add(Theme.Style(new TextBox { Bounds = R(120, 100, 286, 26), Font = Body }));
            Lbl(right, Loc.T("proxyPage.kind"), 134);
            kind = right.Add(new Segmented("HTTP", "SOCKS5") { Bounds = R(120, 132, 200, 32) });
            right.Add(UIx.L(Loc.T("proxyPage.kindAutoFix"), Small, Muted, 326, 132, 84, 32));
            Lbl(right, Loc.T("proxyPage.address"), 172);
            tHost = right.Add(Theme.Style(new TextBox { Bounds = R(120, 172, 190, 26), Font = Body }));
            right.Add(UIx.L(":", Bold, Muted, 312, 172, 10, 26, ContentAlignment.MiddleCenter));
            nPort = right.Add(Theme.Style(new NumericUpDown { Bounds = R(324, 172, 82, 26), Minimum = 1, Maximum = 65535, Value = 8080 }));
            Lbl(right, Loc.T("proxyPage.user"), 206);
            tUser = right.Add(Theme.Style(new TextBox { Bounds = R(120, 206, 286, 26), Font = Body }));
            Lbl(right, Loc.T("proxyPage.password"), 240);
            tPass = right.Add(Theme.Style(new TextBox { Bounds = R(120, 240, 286, 26), Font = Body, UseSystemPasswordChar = true }));
            right.Add(UIx.L(Loc.T("proxyPage.passwordInfo"), Small, Muted, 120, 268, 290, 20));
            bSave = right.Add(new FlatBtn { Text = Loc.T("common.save"), Glyph = GSave, Kind = FlatBtn.Kinds.Primary, Bounds = R(20, 294, 186, 36) });
            bTest = right.Add(new FlatBtn { Text = Loc.T("proxyPage.test"), Glyph = GSpeed, Kind = FlatBtn.Kinds.Secondary, Bounds = R(216, 294, 190, 36) });
            bSave.Click += (s, e) => Save();
            bTest.Click += async (s, e) => await RunTest();
            result = right.Add(new ReportBox { Bounds = R(20, 338, 386, 66) });
            result.BackColor = Theme.Card;
            result.Muted(Loc.T("proxyPage.testIntro"));

            var bottom = C(pList, 28, 428, 764, 132);
            bottom.Add(UIx.L(Loc.T("proxyPage.useSelected"), Caption, Muted, 20, 14, 300, 18));
            sysState = bottom.Add(UIx.L("", Small, Muted, 300, 12, 444, 22, ContentAlignment.TopRight));
            bDiscord = bottom.Add(new FlatBtn { Text = Loc.T("proxyPage.openDiscord"), Glyph = GChat, Kind = FlatBtn.Kinds.Primary, Bounds = R(20, 40, 214, 38), Font = Small });
            bShortcut = bottom.Add(new FlatBtn { Text = Loc.T("proxyPage.desktopShortcut"), Glyph = GLink, Kind = FlatBtn.Kinds.Secondary, Bounds = R(242, 40, 162, 38), Font = Small });
            bDiscordNormal = bottom.Add(new FlatBtn { Text = Loc.T("proxyPage.openDiscordNormal"), Glyph = GRefresh, Kind = FlatBtn.Kinds.Secondary, Bounds = R(412, 40, 170, 38), Font = Small });
            bSys = bottom.Add(new FlatBtn { Text = Loc.T("proxyPage.makeSystem"), Glyph = GGlobe, Kind = FlatBtn.Kinds.Secondary, Bounds = R(590, 40, 154, 38), Font = Small });
            bSysOff = bottom.Add(new FlatBtn { Text = Loc.T("proxyPage.systemOff"), Glyph = GUndo, Kind = FlatBtn.Kinds.Warning, Bounds = R(590, 40, 154, 38), Font = Small, Visible = false });
            bottom.Add(UIx.L(Loc.T("proxyPage.useInfo"), Small, Muted, 20, 86, 724, 40));
            bDiscord.Click += async (s, e) => await LaunchDiscord();
            bDiscordNormal.Click += async (s, e) => { bDiscordNormal.Enabled = false; string m = await Actions.RestartDiscordAsync(); if (!IsDisposed) { bDiscordNormal.Enabled = true; Info(m); } };
            bShortcut.Click += (s, e) => MakeShortcut();
            bSys.Click += (s, e) => ApplySystem();
            bSysOff.Click += (s, e) =>
            {
                bool ok = ProxyTools.RestoreSystem();
                UpdateState();
                if (ok) Info(Loc.T("proxyPage.systemRestored")); else Warn(Loc.T("proxyPage.systemNotRestored"));
            };

            // ============================================================ PER PROGRAM
            var aleft = C(pApps, 28, 4, 330, 412);
            aleft.Add(UIx.L(Loc.T("proxyPage.apps.list"), Caption, Muted, 18, 14, 290, 18));
            appList = new ListBox
            {
                Bounds = R(8, 38, 314, 318), DrawMode = DrawMode.OwnerDrawFixed, ItemHeight = D(54),
                BorderStyle = BorderStyle.None, IntegralHeight = false, Font = Body,
            };
            aleft.Add(appList);
            appList.BackColor = Theme.Card;
            Theme.StyleScroll(appList);
            appList.DrawItem += DrawApp;
            appList.SelectedIndexChanged += (s, e) => { if (appList.SelectedItem is ProxyApp a) LoadApp(a); };
            aAdd = aleft.Add(new FlatBtn { Text = Loc.T("proxyPage.apps.add"), Glyph = GAdd, Kind = FlatBtn.Kinds.Primary, Bounds = R(14, 362, 196, 36), Font = Small });
            aDel = aleft.Add(new FlatBtn { Text = Loc.T("proxyPage.delete"), Glyph = GDelete, Kind = FlatBtn.Kinds.Secondary, Bounds = R(216, 362, 100, 36), Font = Small });
            aAdd.Click += (s, e) => ShowAddMenu();
            aDel.Click += (s, e) => DeleteApp();

            var aright = C(pApps, 370, 4, 422, 412);
            aright.Add(UIx.L(Loc.T("proxyPage.apps.setting"), Caption, Muted, 20, 14, 300, 18));
            Lbl(aright, Loc.T("proxyPage.apps.program"), 38);
            aPath = aright.Add(Theme.Style(new TextBox { Bounds = R(120, 38, 206, 26), Font = Small, ReadOnly = true }));
            aBrowse = aright.Add(new FlatBtn { Text = Loc.T("proxyPage.apps.browse"), Kind = FlatBtn.Kinds.Secondary, Bounds = R(332, 36, 74, 30), Font = Small });
            aBrowse.Click += (s, e) => Browse(editingApp);
            Lbl(aright, Loc.T("proxyPage.name"), 72);
            aName = aright.Add(Theme.Style(new TextBox { Bounds = R(120, 72, 286, 26), Font = Body }));
            Lbl(aright, "Proxy", 106);
            aProxy = aright.Add(new ThemedCombo { Bounds = R(120, 106, 286, 26) });
            aProxy.SelectedIndexChanged += (s, e) => UpdateAppInfo();
            Lbl(aright, Loc.T("proxyPage.apps.method"), 140);
            aMode = aright.Add(UIx.L("", Bold, Theme.Text, 120, 140, 286, 26, ContentAlignment.MiddleLeft));
            aModeInfo = aright.Add(UIx.L("", Small, Muted, 120, 166, 286, 46));
            aSeparate = aright.Add(new CheckX { Text = Loc.T("proxyPage.apps.separate"), Bounds = R(20, 214, 386, 24), Font = Small });
            aClose = aright.Add(new CheckX { Text = Loc.T("proxyPage.apps.closeFirst"), Bounds = R(20, 240, 386, 24), Font = Small });
            Lbl(aright, Loc.T("proxyPage.apps.extra"), 270);
            aArgs = aright.Add(Theme.Style(new TextBox { Bounds = R(120, 270, 286, 26), Font = Mono }));
            aSave = aright.Add(new FlatBtn { Text = Loc.T("common.save"), Glyph = GSave, Kind = FlatBtn.Kinds.Secondary, Bounds = R(20, 308, 120, 36) });
            aLaunch = aright.Add(new FlatBtn { Text = Loc.T("proxyPage.apps.launch"), Glyph = GPlay, Kind = FlatBtn.Kinds.Primary, Bounds = R(146, 308, 136, 36) });
            aShortcut = aright.Add(new FlatBtn { Text = Loc.T("proxyPage.apps.shortcut"), Glyph = GLink, Kind = FlatBtn.Kinds.Secondary, Bounds = R(288, 308, 118, 36) });
            aSave.Click += (s, e) => SaveApp(true);
            aLaunch.Click += async (s, e) => await LaunchApp();
            aShortcut.Click += (s, e) => AppShortcut();
            bridgeState = aright.Add(UIx.L("", Small, Muted, 20, 352, 386, 50));

            var abottom = C(pApps, 28, 428, 764, 132);
            abottom.Add(UIx.L(Loc.T("proxyPage.apps.howTitle"), Caption, Muted, 20, 14, 300, 18));
            abottom.Add(UIx.L(
                Loc.T("proxyPage.apps.how"),
                Small, Muted, 20, 36, 724, 90));

            OnStatus(() => { if (Visible) { UpdateState(); UpdateBridgeState(); } });
            Reload();
        }

        public override void OnActivated() { Reload(); UpdateState(); if (pApps.Visible) ReloadApps(); }

        /// <summary>Opens the per-program proxy tab.</summary>
        public void ShowApps() => tabs.SelectedIndex = 1;

        // ============================================================ proxy list

        ProxyEntry Selected => list.SelectedItem as ProxyEntry;

        void Reload(string selectId = null)
        {
            string keep = selectId ?? Selected?.Id;
            list.BeginUpdate();
            list.Items.Clear();
            foreach (var p in App.Settings.Proxies) list.Items.Add(p);
            list.EndUpdate();
            int idx = App.Settings.Proxies.FindIndex(p => p.Id == keep);
            if (idx < 0 && list.Items.Count > 0) idx = 0;
            if (idx >= 0) list.SelectedIndex = idx; else Load(null);
            UpdateState();
        }

        void Load(ProxyEntry p)
        {
            editing = p;
            tQuick.Text = "";
            tName.Text = p?.Name ?? "";
            kind.SetSilently(p != null && p.Kind == ProxyKind.Socks5 ? 1 : 0);
            tHost.Text = p?.Host ?? "";
            nPort.Value = Math.Max(1, Math.Min(65535, p?.Port ?? 8080));
            tUser.Text = p?.User ?? "";
            tPass.Text = p?.Password ?? "";
            bSave.Text = p == null ? Loc.T("proxyPage.add") : Loc.T("common.save");
            UpdateState();
        }

        void UpdateState()
        {
            var sel = Selected;
            bool has = sel != null;
            bDel.Enabled = bDiscord.Enabled = bShortcut.Enabled = bSys.Enabled = has;
            var cur = ProxyTools.CurrentSystem();
            var mine = ProxyTools.ActiveSystemEntry();
            bool ours = mine != null;
            bSys.Visible = !ours;
            bSysOff.Visible = ours || ProxyTools.HasRecord;
            sysState.Text = ours ? Loc.T("proxyPage.sys.ours", mine.Title)
                          : cur.Enabled ? Loc.T("proxyPage.sys.other", cur.Server)
                          : Loc.T("proxyPage.sys.off");
            sysState.ForeColor = ours ? AccentInk : cur.Enabled ? AmberText : Muted;
            list.Invalidate();
        }

        void QuickFill()
        {
            if (!ProxyTools.TryParse(tQuick.Text, kind.SelectedIndex == 1 ? ProxyKind.Socks5 : ProxyKind.Http, out var p, out var err)) { Warn(err); return; }
            kind.SetSilently(p.Kind == ProxyKind.Socks5 ? 1 : 0);
            tHost.Text = p.Host;
            nPort.Value = p.Port;
            tUser.Text = p.User;
            tPass.Text = p.Password;
            if (tName.Text.Trim().Length == 0) tName.Text = p.KindLabel + " " + p.Host;
            tQuick.Text = "";
        }

        ProxyEntry Collect(out string error)
        {
            error = "";
            string host = tHost.Text.Trim();
            if (host.Length == 0 && tQuick.Text.Trim().Length > 0) { QuickFill(); host = tHost.Text.Trim(); }
            if (host.Length == 0) { error = Loc.T("proxyPage.enterAddress"); return null; }
            // an https:// proxy is refused with its own message (it would otherwise be saved as plain HTTP)
            if (host.StartsWith("https:", StringComparison.OrdinalIgnoreCase)) { error = Loc.T("proxy.parse.httpsUnsupported"); return null; }
            if (Uri.CheckHostName(host.Trim('[', ']')) == UriHostNameType.Unknown) { error = Loc.T("proxyPage.badAddress", host); return null; }
            var p = new ProxyEntry
            {
                Name = tName.Text.Trim(), Kind = kind.SelectedIndex == 1 ? ProxyKind.Socks5 : ProxyKind.Http,
                Host = host.Trim('[', ']'), Port = (int)nPort.Value, User = tUser.Text.Trim(),
            };
            p.Password = p.User.Length > 0 ? tPass.Text : "";
            if (!ProxyTools.ValidEntry(p, out error)) return null;
            return p;
        }

        void Save()
        {
            var p = Collect(out var err);
            if (p == null) { Warn(err); return; }
            if (editing != null)
            {
                editing.Name = p.Name; editing.Kind = p.Kind; editing.Host = p.Host; editing.Port = p.Port;
                editing.User = p.User; editing.PassData = p.PassData;
                p = editing;
            }
            else App.Settings.Proxies.Add(p);
            ProxyBridge.AssignPorts(App.Settings.Proxies);
            App.Save();
            App.Log("Proxy saved: " + p.KindLabel + " " + p.Address, LogLevel.Info);
            Reload(p.Id);
            if (ProxyTools.ActiveSystemEntry()?.Id == p.Id)
            {
                try { ProxyTools.ApplySystem(p); }
                catch (Exception ex) { Warn(Loc.T("proxyPage.sys.failed", ex.Message)); }
            }
            if (ProxyBridge.IsRunning(p)) { ProxyBridge.Stop(p.Id); ProxyBridge.Sync(); }
        }

        void Delete()
        {
            var p = Selected;
            if (p == null) return;
            int used = App.Settings.ProxyApps.Count(a => a.ProxyId == p.Id);
            if (MessageBox.Show(FindForm(), Loc.T("proxyPage.deleteConfirm", p.Title) + (used > 0 ? "\n\n" + Loc.T("proxyPage.deleteRules", used) : ""),
                    App.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            if (ProxyTools.ActiveSystemEntry()?.Id == p.Id) ProxyTools.RestoreSystem();
            ProxyBridge.Stop(p.Id);
            App.Settings.Proxies.RemoveAll(x => x.Id == p.Id);
            App.Settings.ProxyApps.RemoveAll(a => a.ProxyId == p.Id);
            App.Save();
            Reload();
        }

        async Task RunTest()
        {
            var p = Collect(out var err);
            if (p == null) { Warn(err); return; }
            bTest.Enabled = false;
            result.Clear();
            result.Muted(Loc.T("proxyPage.testing", p.KindLabel, p.Address));
            var r = await Task.Run(() => ProxyTools.Test(p));
            if (IsDisposed) return;
            bTest.Enabled = true;
            result.Clear();
            if (r.Ok)
            {
                result.Out(Loc.T("proxyPage.working", r.TotalMs), GreenText, Bold);
                result.Out(Loc.T("proxyPage.exitIp") + " " + (r.ExitIp.Length > 0 ? r.ExitIp : "?") + (r.Country.Length > 0 ? "  ·  " + Loc.T("proxyPage.country") + " " + r.Country : "") +
                           (r.KindFixed ? "  ·  " + Loc.T("proxyPage.kindFixed", p.KindLabel) : ""), Theme.Text, Small);
            }
            else
            {
                var info = ErrorCatalog.Get(r.Code);
                result.Out("✗ " + r.Code + " · " + (info?.Title ?? Loc.T("proxyPage.notWorking")), RedText, Bold);
                result.Out(r.Message, Theme.Text, Small);
            }
            result.SelectionStart = 0;
            if (r.KindFixed) kind.SetSilently(p.Kind == ProxyKind.Socks5 ? 1 : 0);
            if (editing != null && editing.Host == p.Host && editing.Port == p.Port)
            {
                editing.Kind = p.Kind;
                editing.LastOk = p.LastOk; editing.LastResult = p.LastResult; editing.LastTest = p.LastTest; editing.LastMs = p.LastMs;
                App.Save();
                list.Invalidate();
            }
        }

        async Task LaunchDiscord()
        {
            var p = Selected;
            if (p == null) return;
            bDiscord.Enabled = false;
            string msg = null;
            bool ok;
            var discordPath = AppProxy.Installed().FirstOrDefault(x => x.Name == "Discord").Path;
            if (discordPath != null)
            {
                // proxies with a password use the local bridge
                var rule = new ProxyApp { Name = "Discord", ExePath = discordPath, Mode = AppProxyMode.Discord, ProxyId = p.Id };
                ok = await Task.Run(() => AppProxy.Launch(rule, p, out msg));
            }
            else ok = await Task.Run(() => ProxyTools.LaunchDiscord(p, out msg));
            if (IsDisposed) return;
            bDiscord.Enabled = true;
            Info(msg + (ok ? "\n\n" + Loc.T("proxyPage.backToNormal") : ""));
        }

        void MakeShortcut()
        {
            var p = Selected;
            if (p == null) return;
            try
            {
                string desk = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
                string name = "Discord (Proxy " + Scripts.Slug(p.Title) + ").lnk";
                string path;
                var discordPath = AppProxy.Installed().FirstOrDefault(x => x.Name == "Discord").Path;
                if (discordPath != null)
                {
                    var rule = new ProxyApp { Name = "Discord", ExePath = discordPath, Mode = AppProxyMode.Discord, ProxyId = p.Id };
                    if (AppProxy.NeedsBridge(rule, p)) { App.Settings.ProxyApps.Add(rule); App.Save(); ProxyBridge.Sync(); }
                    path = AppProxy.CreateShortcut(rule, p, Path.Combine(desk, name));
                }
                else path = ProxyTools.CreateShortcut(p, Path.Combine(desk, name));
                App.Log("Discord shortcut with proxy created: " + path, LogLevel.Success);
                Info(Loc.T("proxyPage.discordShortcutDone", name));
            }
            catch (Exception ex) { Warn(Loc.T("proxyPage.shortcutFailed", ex.Message)); }
        }

        void ApplySystem()
        {
            var p = Selected;
            if (p == null) return;
            string note = p.Kind == ProxyKind.Socks5
                ? "\n\n" + Loc.T("proxyPage.sys.socksWarning")
                : "";
            if (p.HasAuth) note += "\n\n" + Loc.T("proxyPage.sys.authNote");
            if (MessageBox.Show(FindForm(),
                    Loc.T("proxyPage.sys.confirm", p.KindLabel, p.Address) +
                    note + "\n\n" + Loc.T("proxyPage.sys.confirmEnd"),
                    App.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            try { ProxyTools.ApplySystem(p); }
            catch (Exception ex) { Warn(Loc.T("proxyPage.sys.failed", ex.Message)); }
            UpdateState();
        }

        void DrawItem(object sender, DrawItemEventArgs e)
        {
            if (e.Index < 0) return;
            var p = (ProxyEntry)list.Items[e.Index];
            var (g, bg, r) = Row(e);
            bool active = ProxyTools.ActiveSystemEntry()?.Id == p.Id;
            Color dot = p.LastTest == null ? Mix(Theme.Card, Theme.Text, 0.2f) : p.LastOk ? Green : Red;
            using (var b = new SolidBrush(dot)) g.FillEllipse(b, r.X + D(12), r.Y + D(12), D(9), D(9));
            var flags = TextFormatFlags.NoPadding | TextFormatFlags.EndEllipsis | TextFormatFlags.SingleLine;
            string tag = active ? "  · " + Loc.T("proxyPage.tag.system") : ProxyBridge.IsRunning(p) ? "  · " + Loc.T("proxyPage.tag.bridge") : "";
            TextRenderer.DrawText(g, p.Title + tag, Bold, new Rectangle(r.X + D(28), r.Y + D(6), r.Width - D(36), D(20)), active ? AccentInk : Theme.Text, bg, flags);
            TextRenderer.DrawText(g, p.KindLabel + " · " + p.Address + (p.HasAuth ? " · " + Loc.T("proxyPage.tag.auth") : ""), Small, new Rectangle(r.X + D(28), r.Y + D(25), r.Width - D(36), D(16)), Muted, bg, flags);
            if (!string.IsNullOrEmpty(p.LastResult))
                TextRenderer.DrawText(g, p.LastResult, Small, new Rectangle(r.X + D(28), r.Y + D(39), r.Width - D(36), D(14)), p.LastOk ? GreenText : RedText, bg, flags);
        }

        (Graphics, Color, Rectangle) Row(DrawItemEventArgs e)
        {
            var g = e.Graphics;
            HQ(g);
            bool sel = (e.State & DrawItemState.Selected) != 0;
            var r = e.Bounds;
            using (var b = new SolidBrush(Theme.Card)) g.FillRectangle(b, r);
            Color bg = sel ? AccentSoft : Theme.Card;
            using (var path = Round(new RectangleF(r.X + 2, r.Y + 2, r.Width - 5, r.Height - 4), D(8)))
            {
                using (var b = new SolidBrush(bg)) g.FillPath(b, path);
                if (sel) using (var pen = new Pen(AccentBorder)) g.DrawPath(pen, path);
            }
            return (g, bg, r);
        }

        // ============================================================ per-program proxy

        ProxyApp SelectedApp => appList.SelectedItem as ProxyApp;

        void ReloadApps(string selectId = null)
        {
            string keep = selectId ?? SelectedApp?.Id;
            appList.BeginUpdate();
            appList.Items.Clear();
            foreach (var a in App.Settings.ProxyApps) appList.Items.Add(a);
            appList.EndUpdate();
            aProxy.BeginUpdate();
            aProxy.Items.Clear();
            foreach (var p in ProxyTools.RuleChoices())
                aProxy.Items.Add(p.Id == ByeDpiNet.ProxyMarker ? Loc.T("proxyPage.apps.byedpiChoice", p.Address) : p.Title + "  (" + p.KindLabel + " " + p.Address + ")");
            aProxy.EndUpdate();
            int idx = App.Settings.ProxyApps.FindIndex(a => a.Id == keep);
            if (idx < 0 && appList.Items.Count > 0) idx = 0;
            if (idx >= 0) appList.SelectedIndex = idx; else LoadApp(null);
            UpdateBridgeState();
        }

        void LoadApp(ProxyApp a)
        {
            editingApp = a;
            bool has = a != null;
            foreach (Control c in new Control[] { aName, aProxy, aSeparate, aClose, aArgs, aSave, aLaunch, aShortcut, aBrowse }) c.Enabled = has;
            aDel.Enabled = has;
            aPath.Text = a?.ExePath ?? "";
            aName.Text = a?.Name ?? "";
            aArgs.Text = a?.ExtraArgs ?? "";
            aSeparate.Checked = a?.SeparateProfile ?? true;
            aClose.Checked = a?.CloseRunning ?? true;
            int pi = a == null ? -1 : ProxyTools.RuleChoices().FindIndex(p => p.Id == a.ProxyId);
            aProxy.SelectedIndex = pi >= 0 ? pi : (aProxy.Items.Count > 0 && has ? 0 : -1);
            UpdateAppInfo();
        }

        void UpdateAppInfo()
        {
            var a = editingApp;
            if (a == null)
            {
                aMode.Text = "";
                aModeInfo.Text = App.Settings.Proxies.Count == 0
                    ? Loc.T("proxyPage.apps.emptyNoProxy")
                    : Loc.T("proxyPage.apps.empty");
                return;
            }
            aMode.Text = a.ModeLabel;
            var choices = ProxyTools.RuleChoices();
            var p = aProxy.SelectedIndex >= 0 && aProxy.SelectedIndex < choices.Count ? choices[aProxy.SelectedIndex] : null;
            bool bridge = p != null && AppProxy.NeedsBridge(a, p);
            switch (a.Mode)
            {
                case AppProxyMode.Discord: aModeInfo.Text = Loc.T("proxyPage.apps.mode.discord"); break;
                case AppProxyMode.Chromium: aModeInfo.Text = Loc.T("proxyPage.apps.mode.chromium"); break;
                case AppProxyMode.Firefox: aModeInfo.Text = Loc.T("proxyPage.apps.mode.firefox"); break;
                default: aModeInfo.Text = Loc.T("proxyPage.apps.mode.env"); break;
            }
            if (bridge) aModeInfo.Text += " " + Loc.T("proxyPage.apps.usesBridge", p.LocalPort);
            bool browser = a.Mode == AppProxyMode.Firefox || (a.Mode == AppProxyMode.Chromium && new[] { "chrome.exe", "msedge.exe", "brave.exe", "opera.exe", "vivaldi.exe", "browser.exe", "chromium.exe" }.Contains(Path.GetFileName(a.ExePath).ToLowerInvariant()));
            aSeparate.Visible = browser && a.Mode == AppProxyMode.Chromium;
            aClose.Visible = !browser || !aSeparate.Checked;
        }

        void UpdateBridgeState()
        {
            int n = ProxyBridge.RunningCount, act = ProxyBridge.ActiveConnections;
            bridgeState.Text = n == 0 ? Loc.T("proxyPage.bridge.off")
                                      : Loc.T("proxyPage.bridge.on", n, act);
            bridgeState.ForeColor = n > 0 ? AccentInk : Muted;
            appList.Invalidate();
        }

        void ShowAddMenu()
        {
            if (App.Settings.Proxies.Count == 0)
            {
                Warn(Loc.T("proxyPage.apps.addProxyFirst"));
                tabs.SelectedIndex = 0;
                return;
            }
            var m = new ContextMenuStrip { Font = Body, ShowImageMargin = false };
            var found = AppProxy.Installed();
            foreach (var (name, path) in found)
            {
                var pth = path; var nm = name;
                m.Items.Add(nm, null, (s, e) => AddApp(nm, pth));
            }
            if (found.Count > 0) m.Items.Add(new ToolStripSeparator());
            m.Items.Add(Loc.T("proxyPage.apps.other"), null, (s, e) => Browse(null));
            m.Closed += (s, e) => BeginInvoke(new Action(m.Dispose));
            m.Show(aAdd, new Point(0, aAdd.Height));
        }

        void Browse(ProxyApp target)
        {
            using (var d = new OpenFileDialog { Filter = Loc.T("proxyPage.apps.filter"), Title = Loc.T("proxyPage.apps.chooseTitle") })
            {
                if (d.ShowDialog(FindForm()) != DialogResult.OK) return;
                if (target == null) AddApp(System.Diagnostics.FileVersionInfo.GetVersionInfo(d.FileName).FileDescription is string desc && desc.Trim().Length > 0
                                           ? desc.Trim() : Path.GetFileNameWithoutExtension(d.FileName), d.FileName);
                else
                {
                    target.ExePath = d.FileName;
                    target.Mode = AppProxy.Detect(d.FileName);
                    App.Save();
                    ReloadApps(target.Id);
                }
            }
        }

        void AddApp(string name, string path)
        {
            var a = new ProxyApp
            {
                Name = name, ExePath = path, Mode = AppProxy.Detect(path),
                ProxyId = (Selected ?? App.Settings.Proxies.FirstOrDefault())?.Id ?? "",
            };
            App.Settings.ProxyApps.Add(a);
            App.Save();
            ProxyBridge.Sync();
            App.Log("Per-program proxy rule added: " + a.Name + " (" + a.ModeLabel + ")", LogLevel.Info);
            ReloadApps(a.Id);
        }

        bool SaveApp(bool notify)
        {
            var a = editingApp;
            if (a == null) return false;
            var choices = ProxyTools.RuleChoices();
            if (aProxy.SelectedIndex < 0 || aProxy.SelectedIndex >= choices.Count) { Warn(Loc.T("proxyPage.apps.chooseProxy")); return false; }
            a.Name = aName.Text.Trim().Length > 0 ? aName.Text.Trim() : Path.GetFileNameWithoutExtension(a.ExePath);
            a.ProxyId = choices[aProxy.SelectedIndex].Id;
            string extraArgs = aArgs.Text.Trim();
            if (CmdLine.HasControlChars(extraArgs) || (a.Mode == AppProxyMode.Env && !CmdLine.BareSafe(extraArgs)))
            { Warn(Loc.T("proxyPage.apps.badExtra")); return false; }
            a.ExtraArgs = extraArgs;
            a.SeparateProfile = aSeparate.Checked;
            a.CloseRunning = aClose.Checked;
            App.Save();
            ProxyBridge.Sync();
            ReloadApps(a.Id);
            if (notify) App.Log("Per-program proxy rule saved: " + a.Name, LogLevel.Info);
            return true;
        }

        void DeleteApp()
        {
            var a = SelectedApp;
            if (a == null) return;
            if (MessageBox.Show(FindForm(), Loc.T("proxyPage.apps.deleteConfirm", a.Name),
                    App.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            App.Settings.ProxyApps.RemoveAll(x => x.Id == a.Id);
            App.Save();
            ProxyBridge.Sync();
            ReloadApps();
        }

        async Task LaunchApp()
        {
            if (!SaveApp(false)) return;
            var a = editingApp;
            var p = ProxyTools.Find(a.ProxyId);
            if (p == null) return;
            if (p.Id == ByeDpiNet.ProxyMarker && !(App.Engine.State == EngineState.Running && App.Engine.Current.Kind == EngineKind.ByeDpi))
            { Warn(Loc.T("proxyPage.apps.byedpiNotRunning")); return; }
            if (a.CloseRunning && aClose.Visible && Path.GetFileName(a.ExePath).Length > 0 &&
                System.Diagnostics.Process.GetProcessesByName(a.Mode == AppProxyMode.Discord ? "Discord" : Path.GetFileNameWithoutExtension(a.ExePath)).Length > 0 &&
                MessageBox.Show(FindForm(), Loc.T("proxyPage.apps.running", a.Name),
                    App.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            aLaunch.Enabled = false;
            string msg = null;
            bool ok = await Task.Run(() => AppProxy.Launch(a, p, out msg));
            if (IsDisposed) return;
            aLaunch.Enabled = true;
            UpdateBridgeState();
            if (!ok) Warn(msg);
        }

        void AppShortcut()
        {
            if (!SaveApp(false)) return;
            var a = editingApp;
            var p = ProxyTools.Find(a.ProxyId);
            if (p == null) return;
            try
            {
                string desk = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
                string name = a.Name + " (Proxy).lnk";
                foreach (var ch in Path.GetInvalidFileNameChars()) name = name.Replace(ch, '_');
                string path = AppProxy.CreateShortcut(a, p, Path.Combine(desk, name));
                App.Log("Shortcut with proxy created: " + path, LogLevel.Success);
                Info(Loc.T("proxyPage.apps.shortcutDone", name) +
                     (AppProxy.NeedsBridge(a, p) ? "\n\n" + Loc.T("proxyPage.apps.shortcutBridge") : ""));
            }
            catch (Exception ex) { Warn(Loc.T("proxyPage.shortcutFailed", ex.Message)); }
        }

        void DrawApp(object sender, DrawItemEventArgs e)
        {
            if (e.Index < 0) return;
            var a = (ProxyApp)appList.Items[e.Index];
            var (g, bg, r) = Row(e);
            Icon ic = null;
            try
            {
                string icoFile = a.Mode == AppProxyMode.Discord ? Path.Combine(Path.GetDirectoryName(a.ExePath) ?? "", "app.ico") : null;
                if (icoFile != null && File.Exists(icoFile)) ic = new Icon(icoFile, D(24), D(24));
                else if (File.Exists(a.ExePath)) ic = Icon.ExtractAssociatedIcon(a.ExePath);
            }
            catch (Exception ign) { App.Ignored("Program icon could not be read", ign); }
            if (ic != null) using (ic) g.DrawIcon(ic, new Rectangle(r.X + D(10), r.Y + D(11), D(24), D(24)));
            var p = ProxyTools.Find(a.ProxyId);
            var flags = TextFormatFlags.NoPadding | TextFormatFlags.EndEllipsis | TextFormatFlags.SingleLine;
            TextRenderer.DrawText(g, a.Name, Bold, new Rectangle(r.X + D(42), r.Y + D(6), r.Width - D(50), D(20)), Theme.Text, bg, flags);
            TextRenderer.DrawText(g, p != null ? "→ " + p.Title + " (" + p.KindLabel + ")" : Loc.T("proxyPage.apps.noProxy"), Small,
                new Rectangle(r.X + D(42), r.Y + D(25), r.Width - D(50), D(16)), p != null ? AccentInk : RedText, bg, flags);
            TextRenderer.DrawText(g, a.ModeLabel + (p != null && AppProxy.NeedsBridge(a, p) ? " · " + Loc.T("proxyPage.apps.bridge") : ""), Small,
                new Rectangle(r.X + D(42), r.Y + D(39), r.Width - D(50), D(14)), Muted, bg, flags);
        }

        void Info(string m) => MessageBox.Show(FindForm(), m, App.Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
        void Warn(string m) => MessageBox.Show(FindForm(), m, App.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
    }

    /// <summary>Window for pasting a proxy list and testing all of them at the same time.</summary>
    sealed class BulkProxyDialog : Form
    {
        readonly TextBox input;
        readonly ListView lv;
        readonly FlatBtn bTest, bAdd, bClose;
        readonly ProgressLine bar;
        readonly Label status;
        readonly Segmented kind;
        List<(ProxyEntry P, ProxyTestResult R)> results;
        CancellationTokenSource cts;
        public string FirstAddedId;

        public BulkProxyDialog()
        {
            Text = Loc.T("proxyBulk.windowTitle") + " – " + App.Name;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterParent;
            MaximizeBox = MinimizeBox = false;
            ShowInTaskbar = false;
            AutoScaleMode = AutoScaleMode.None;
            BackColor = Bg;
            Font = Body;
            ClientSize = new Size(D(720), D(600));
            UIx.FitDialog(this);
            Icon = IconArt.AppIcon(32);

            Controls.Add(UIx.L(Loc.T("proxyBulk.title"), H2, Theme.Text, 24, 14, 600, 30));
            Controls.Add(UIx.L(Loc.T("proxyBulk.intro"),
                Small, Muted, 25, 44, 670, 36));
            input = Theme.Style(new TextBox { Bounds = R(24, 84, 672, 150), Multiline = true, ScrollBars = ScrollBars.Vertical, Font = Mono, AcceptsReturn = true });
            Controls.Add(input);
            Controls.Add(UIx.L(Loc.T("proxyBulk.defaultKind"), Body, Theme.Text, 24, 244, 150, 30, ContentAlignment.MiddleLeft));
            kind = new Segmented("HTTP", "SOCKS5") { Bounds = R(170, 242, 200, 32), BackColor = Bg };
            Controls.Add(kind);
            Controls.Add(UIx.L(Loc.T("proxyBulk.kindHint"), Small, Muted, 378, 244, 300, 30, ContentAlignment.MiddleLeft));
            bTest = new FlatBtn { Text = Loc.T("proxyBulk.testAll"), Glyph = GSpeed, Kind = FlatBtn.Kinds.Primary, Bounds = R(24, 284, 180, 38) };
            Controls.Add(bTest);
            status = UIx.L("", Small, Muted, 214, 284, 482, 38, ContentAlignment.MiddleLeft);
            Controls.Add(status);
            bar = new ProgressLine { Bounds = R(24, 330, 672, 6), BackColor = Bg };
            Controls.Add(bar);
            lv = UIx.StyleList(new ListView
            {
                Bounds = R(24, 344, 672, 196), View = View.Details, FullRowSelect = true, HeaderStyle = ColumnHeaderStyle.Nonclickable,
                BorderStyle = BorderStyle.FixedSingle, Font = Body, MultiSelect = false,
            });
            lv.Columns.Add("Proxy", D(210));
            lv.Columns.Add(Loc.T("proxyPage.kind"), D(70));
            lv.Columns.Add(Loc.T("netPage.col.duration"), D(70));
            lv.Columns.Add(Loc.T("proxyBulk.country"), D(60));
            lv.Columns.Add(Loc.T("netPage.col.result"), D(240));
            Controls.Add(lv);
            bAdd = new FlatBtn { Text = Loc.T("proxyBulk.addWorking"), Glyph = GAdd, Kind = FlatBtn.Kinds.Success, Bounds = R(24, 550, 220, 38), Enabled = false };
            bClose = new FlatBtn { Text = Loc.T("common.close"), Kind = FlatBtn.Kinds.Secondary, Bounds = R(576, 550, 120, 38) };
            Controls.Add(bAdd);
            Controls.Add(bClose);
            bTest.Click += async (s, e) => await RunAll();
            bAdd.Click += (s, e) => AddWorking();
            bClose.Click += (s, e) => { cts?.Cancel(); DialogResult = FirstAddedId != null ? DialogResult.OK : DialogResult.Cancel; Close(); };
        }

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            Native.DarkTitle(Handle, IsDark);
        }

        async Task RunAll()
        {
            var items = ProxyTools.ParseList(input.Text, kind.SelectedIndex == 1 ? ProxyKind.Socks5 : ProxyKind.Http, out int invalid);
            if (items.Count == 0) { status.Text = Loc.T("proxyBulk.noneValid") + (invalid > 0 ? " " + Loc.T("proxyBulk.unreadable", invalid) : "."); return; }
            if (items.Count > 500) items = items.Take(500).ToList();
            bTest.Enabled = bAdd.Enabled = false;
            lv.Items.Clear();
            cts = new CancellationTokenSource();
            status.Text = Loc.T("proxyBulk.testing", items.Count) + (invalid > 0 ? " " + Loc.T("proxyBulk.unreadableLines", invalid) : "");
            status.ForeColor = Muted;
            var token = cts.Token;
            results = await Task.Run(() => ProxyTools.BulkTest(items, (done, total) =>
            {
                try { BeginInvoke(new Action(() => { bar.Value = done / (float)total; status.Text = Loc.T("proxyBulk.progress", done, total); })); } catch { }
            }, token));
            if (IsDisposed) return;
            lv.BeginUpdate();
            foreach (var (p, r) in results.OrderByDescending(x => x.R.Ok).ThenBy(x => x.R.Ok ? x.R.TotalMs : int.MaxValue))
                lv.Items.Add(new ListViewItem(new[]
                {
                    p.Address + (p.HasAuth ? " " + Loc.T("proxyBulk.auth") : ""), p.KindLabel, r.Ok ? r.TotalMs + " ms" : "", r.Country,
                    r.Ok ? Loc.T("proxyBulk.working") + (r.KindFixed ? " " + Loc.T("proxyBulk.kindFixed") : "") : r.Code + " " + r.Message,
                }) { ForeColor = r.Ok ? GreenText : Muted });
            lv.EndUpdate();
            int ok = results.Count(x => x.R.Ok);
            bar.Value = 1;
            status.Text = Loc.T("proxyBulk.result", ok, results.Count) + (ok == 0 ? " " + Loc.T("proxyBulk.freeHint") : "");
            status.ForeColor = ok > 0 ? GreenText : AmberText;
            bAdd.Text = Loc.T("proxyBulk.addWorkingN", ok);
            bAdd.Enabled = ok > 0;
            bTest.Enabled = true;
        }

        void AddWorking()
        {
            int n = 0;
            foreach (var (p, r) in results.Where(x => x.R.Ok).OrderBy(x => x.R.TotalMs))
            {
                if (App.Settings.Proxies.Any(x => x.Host == p.Host && x.Port == p.Port)) continue;
                p.Name = p.KindLabel + " " + p.Host + (r.Country.Length > 0 ? " · " + r.Country : "");
                App.Settings.Proxies.Add(p);
                if (FirstAddedId == null) FirstAddedId = p.Id;
                n++;
            }
            ProxyBridge.AssignPorts(App.Settings.Proxies);
            App.Save();
            App.Log(n + " working proxies added (bulk test).", LogLevel.Success);
            bAdd.Enabled = false;
            bAdd.Text = Loc.T("proxyBulk.added", n);
        }
    }
}
