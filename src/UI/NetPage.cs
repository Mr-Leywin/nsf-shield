using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using static NSFShield.Theme;

namespace NSFShield
{
    /// <summary>Internet Check: connection test, site analysis, DNS servers, network info.</summary>
    sealed class NetPage : PageBase
    {
        public override string Key => "net";

        readonly Segmented tabs;
        readonly Panel[] panels;
        FlatBtn bScan, bSpeed;
        Label[] speedVals, speedSubs;
        Label speedStatus, histStats;
        ProgressLine speedBar;
        ReportBox speedInfo;
        HistoryChart chart;
        ListView lvHist;
        bool speedRunning;

        sealed class Unsub : IDisposable { readonly Action a; public Unsub(Action a) { this.a = a; } public void Dispose() => a(); }

        // connection test
        readonly ListView lvHosts;
        readonly TextBox hostInput;
        readonly FlatBtn bTest;
        readonly Label testSummary;
        // site analysis
        readonly TextBox siteInput;
        readonly FlatBtn bAnalyze;
        readonly ReportBox siteOut;
        // dns
        readonly ListView lvDns;
        readonly FlatBtn bDns, bUseDns;
        readonly Label dnsSummary;
        DnsChoice bestDns = DnsChoice.None;
        // network
        readonly ReportBox netOut;
        readonly FlatBtn bNet;

        public NetPage()
        {
            Header(Loc.T("netPage.title"), Loc.T("netPage.subtitle"));

            var items = new List<string> { Loc.T("netPage.tab.connection"), Loc.T("netPage.tab.site"), "DNS", Loc.T("netPage.tab.speed"), Loc.T("netPage.tab.history") };
            if (Level(UiLevel.Advanced)) items.Add(Loc.T("netPage.tab.network"));
            tabs = new Segmented(items.ToArray()) { Bounds = R(28, 76, 764, 36), BackColor = Bg };
            Controls.Add(tabs);

            panels = new Panel[items.Count];
            for (int i = 0; i < panels.Length; i++)
            {
                panels[i] = new Panel { Bounds = R(0, 124, 820, 516), BackColor = Bg, Visible = i == 0 };
                Controls.Add(panels[i]);
            }
            tabs.SelectedChanged += (s, e) => { for (int i = 0; i < panels.Length; i++) panels[i].Visible = i == tabs.SelectedIndex; };

            // ================================================ 1) connection test
            {
                var p = panels[0];
                var card = new Card { Bounds = R(28, 0, 764, 380) };
                p.Controls.Add(card);
                lvHosts = UIx.StyleList(new ListView
                {
                    Bounds = R(12, 12, 740, 300), View = View.Details, FullRowSelect = true, HeaderStyle = ColumnHeaderStyle.Nonclickable,
                    BorderStyle = BorderStyle.None, Font = Body, MultiSelect = false,
                });
                lvHosts.Columns.Add(Loc.T("netPage.col.server"), D(176));
                lvHosts.Columns.Add(Loc.T("netPage.col.status"), D(74));
                lvHosts.Columns.Add(Loc.T("netPage.col.duration"), D(60));
                lvHosts.Columns.Add(Loc.T("netPage.col.ip"), D(114));
                lvHosts.Columns.Add(Loc.T("netPage.col.detail"), D(234));
                lvHosts.Columns.Add(Loc.T("netPage.col.code"), D(58));
                card.Add(lvHosts);
                lvHosts.BackColor = Input;

                hostInput = card.Add(Theme.Style(new TextBox { Bounds = R(12, 330, 290, 26), Font = Body }));
                hostInput.KeyDown += (s, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; AddHost(); } };
                var bAdd = card.Add(new FlatBtn { Text = Loc.T("netPage.addServer"), Glyph = GAdd, Kind = FlatBtn.Kinds.Secondary, Bounds = R(310, 326, 140, 34) });
                bAdd.Click += (s, e) => AddHost();
                var bDel = card.Add(new FlatBtn { Text = Loc.T("netPage.removeSelected"), Glyph = GDelete, Kind = FlatBtn.Kinds.Secondary, Bounds = R(458, 326, 150, 34) });
                bDel.Click += (s, e) => RemoveHost();
                var bReset = card.Add(new FlatBtn { Text = Loc.T("netPage.defaults"), Kind = FlatBtn.Kinds.Ghost, Bounds = R(616, 326, 136, 34) });
                bReset.Click += (s, e) => { App.Settings.TestHosts = AppSettings.DefaultTestHosts.ToList(); App.Save(); FillHosts(); };

                bTest = new FlatBtn { Text = Loc.T("netPage.startTest"), Glyph = GSpeed, Kind = FlatBtn.Kinds.Primary, Bounds = R(28, 394, 160, 40), BackColor = Bg };
                bScan = new FlatBtn { Text = Loc.T("netPage.findBest"), Glyph = GShield, Kind = FlatBtn.Kinds.Secondary, Bounds = R(196, 394, 180, 40), BackColor = Bg };
                p.Controls.Add(bScan);
                bScan.Click += (s, e) => ScanDialog.Run(FindForm());
                p.Controls.Add(bTest);
                bTest.Click += async (s, e) => await RunTest();
                testSummary = UIx.L(Loc.T("netPage.testInfo"), Small, Muted, 388, 394, 404, 44);
                p.Controls.Add(testSummary);
            }

            // ================================================ 2) site analysis
            {
                var p = panels[1];
                p.Controls.Add(UIx.L(Loc.T("netPage.site.intro"),
                    Small, Muted, 29, 0, 760, 36));
                siteInput = Theme.Style(new TextBox { Bounds = R(28, 42, 380, 28), Font = Body, Text = "discord.com" });
                p.Controls.Add(siteInput);
                siteInput.KeyDown += async (s, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; await Analyze(); } };
                bAnalyze = new FlatBtn { Text = Loc.T("netPage.site.analyze"), Glyph = GSearch, Kind = FlatBtn.Kinds.Primary, Bounds = R(418, 38, 140, 36), BackColor = Bg };
                p.Controls.Add(bAnalyze);
                bAnalyze.Click += async (s, e) => await Analyze();
                int qx = 568;
                foreach (var q in new[] { "gateway.discord.gg", "cdn.discordapp.com" })
                {
                    var qb = new FlatBtn { Text = q.Split('.')[0], Kind = FlatBtn.Kinds.Ghost, Bounds = R(qx, 38, 110, 36), BackColor = Bg, Font = Small };
                    qb.Click += async (s, e) => { siteInput.Text = q; await Analyze(); };
                    p.Controls.Add(qb);
                    qx += 112;
                }
                var card = new Card { Bounds = R(28, 86, 764, 420) };
                p.Controls.Add(card);
                siteOut = card.Add(new ReportBox { Bounds = R(16, 12, 732, 396) });
                siteOut.BackColor = Theme.Card;
                siteOut.Muted(Loc.T("netPage.site.resultHere"));
            }

            // ================================================ 3) DNS servers
            {
                var p = panels[2];
                p.Controls.Add(UIx.L(Loc.T("netPage.dns.intro"),
                    Small, Muted, 29, 0, 760, 36));
                var card = new Card { Bounds = R(28, 42, 764, 330) };
                p.Controls.Add(card);
                lvDns = UIx.StyleList(new ListView
                {
                    Bounds = R(12, 12, 740, 306), View = View.Details, FullRowSelect = true, HeaderStyle = ColumnHeaderStyle.Nonclickable,
                    BorderStyle = BorderStyle.None, Font = Body, MultiSelect = false,
                });
                lvDns.Columns.Add(Loc.T("netPage.col.server"), D(170));
                lvDns.Columns.Add(Loc.T("netPage.col.address"), D(150));
                lvDns.Columns.Add(Loc.T("netPage.col.duration"), D(70));
                lvDns.Columns.Add(Loc.T("netPage.col.answer"), D(150));
                lvDns.Columns.Add(Loc.T("netPage.col.result"), D(176));
                card.Add(lvDns);
                lvDns.BackColor = Input;

                bDns = new FlatBtn { Text = Loc.T("netPage.dns.test"), Glyph = GSearch, Kind = FlatBtn.Kinds.Primary, Bounds = R(28, 386, 220, 40), BackColor = Bg };
                p.Controls.Add(bDns);
                bDns.Click += async (s, e) => await RunDns();
                bUseDns = new FlatBtn { Text = "", Glyph = GCheck, Kind = FlatBtn.Kinds.Success, Bounds = R(258, 386, 300, 40), BackColor = Bg, Visible = false };
                p.Controls.Add(bUseDns);
                bUseDns.Click += async (s, e) =>
                {
                    var prof = Profiles.BuiltIns.FirstOrDefault(x => x.Group == Profiles.GroupRecommended && x.Dns == bestDns);
                    if (prof != null) await Actions.SelectProfileAsync(prof);
                };
                dnsSummary = UIx.L("", Small, Muted, 28, 436, 764, 60);
                p.Controls.Add(dnsSummary);
            }

            // ================================================ 4) speed test
            {
                var p = panels[3];
                p.Controls.Add(UIx.L(Loc.T("netPage.speed.intro"),
                    Small, Muted, 29, 0, 760, 36));
                string[] titles = { Loc.T("netPage.speed.latency"), Loc.T("netPage.speed.download"), Loc.T("netPage.speed.upload") };
                speedVals = new Label[3];
                speedSubs = new Label[3];
                for (int i = 0; i < 3; i++)
                {
                    var c = new Card { Bounds = R(28 + i * 260, 44, 244, 160) };
                    p.Controls.Add(c);
                    c.Add(UIx.L(titles[i], Caption, Muted, 20, 16, 200, 18));
                    speedVals[i] = c.Add(UIx.L("—", new Font("Segoe UI Semibold", 30f), Theme.Text, 16, 40, 220, 64, ContentAlignment.MiddleLeft));
                    speedSubs[i] = c.Add(UIx.L(i == 0 ? "ms" : "Mbit/s", Body, Muted, 20, 108, 210, 40));
                }
                bSpeed = new FlatBtn { Text = Loc.T("netPage.speed.start"), Glyph = GSpeed, Kind = FlatBtn.Kinds.Primary, Bounds = R(28, 220, 200, 40), BackColor = Bg };
                p.Controls.Add(bSpeed);
                bSpeed.Click += async (s, e) => await RunSpeed();
                speedStatus = UIx.L("", Small, Muted, 240, 220, 552, 40, ContentAlignment.MiddleLeft);
                p.Controls.Add(speedStatus);
                speedBar = new ProgressLine { Bounds = R(28, 268, 764, 6), BackColor = Bg };
                p.Controls.Add(speedBar);
                var info = new Card { Bounds = R(28, 290, 764, 120) };
                p.Controls.Add(info);
                speedInfo = info.Add(new ReportBox { Bounds = R(16, 12, 732, 96) });
                speedInfo.BackColor = Theme.Card;
                speedInfo.Muted(Loc.T("netPage.speed.note"));
            }

            // ================================================ 5) history
            {
                var p = panels[4];
                histStats = UIx.L("", Body, Theme.Text, 29, 0, 620, 40, ContentAlignment.MiddleLeft);
                p.Controls.Add(histStats);
                var bClear = new FlatBtn { Text = Loc.T("netPage.history.clear"), Glyph = GDelete, Kind = FlatBtn.Kinds.Secondary, Bounds = R(672, 2, 120, 36), BackColor = Bg };
                p.Controls.Add(bClear);
                bClear.Click += (s, e) =>
                {
                    if (MessageBox.Show(FindForm(), Loc.T("netPage.history.clearConfirm"), App.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes) History.Clear();
                };
                var cc = new Card { Bounds = R(28, 46, 764, 150) };
                p.Controls.Add(cc);
                chart = cc.Add(new HistoryChart { Bounds = R(14, 10, 736, 130) });
                var lc = new Card { Bounds = R(28, 206, 764, 306) };
                p.Controls.Add(lc);
                lvHist = UIx.StyleList(new ListView
                {
                    Bounds = R(12, 12, 740, 282), View = View.Details, FullRowSelect = true, HeaderStyle = ColumnHeaderStyle.Nonclickable,
                    BorderStyle = BorderStyle.None, Font = Body, MultiSelect = false,
                });
                lvHist.Columns.Add(Loc.T("netPage.col.when"), D(110));
                lvHist.Columns.Add(Loc.T("netPage.col.kind"), D(70));
                lvHist.Columns.Add(Loc.T("netPage.col.method"), D(170));
                lvHist.Columns.Add(Loc.T("netPage.col.result"), D(90));
                lvHist.Columns.Add(Loc.T("netPage.col.detail"), D(268));
                lc.Add(lvHist);
                lvHist.BackColor = Input;
                Action h = () => { if (Visible && panels[4].Visible) FillHistory(); };
                History.Changed += h;
                Track(new Unsub(() => History.Changed -= h));
                tabs.SelectedChanged += (s, e) => { if (tabs.SelectedIndex == 4) FillHistory(); };
            }

            // ================================================ 6) network info
            if (panels.Length > 5)
            {
                var p = panels[5];
                bNet = new FlatBtn { Text = Loc.T("netPage.net.refresh"), Glyph = GRefresh, Kind = FlatBtn.Kinds.Secondary, Bounds = R(28, 0, 140, 36), BackColor = Bg };
                p.Controls.Add(bNet);
                bNet.Click += async (s, e) => await RunNet();
                var card = new Card { Bounds = R(28, 46, 764, 460) };
                p.Controls.Add(card);
                netOut = card.Add(new ReportBox { Bounds = R(16, 12, 732, 436) });
                netOut.BackColor = Theme.Card;
            }

            OnStatus(() => { if (Visible) { SyncButtons(); if (!Actions.Testing && App.LastTest != null) ShowResults(App.LastTest); } });
        }

        public override void OnActivated()
        {
            if (App.LastTest != null) ShowResults(App.LastTest); else FillHosts();
            SyncButtons();
            if (panels.Length > 5 && netOut.TextLength == 0) _ = RunNet();
            if (panels[4].Visible) FillHistory();
        }

        /// <summary>Opens the given tab; starts the test right away if asked.</summary>
        public void ShowTab(int index, bool run)
        {
            if (index >= panels.Length) return;
            tabs.SelectedIndex = index;
            if (!run) { if (index == 1) siteInput.Focus(); return; }
            if (index == 0) _ = RunTest();
            else if (index == 1) _ = Analyze();
            else if (index == 2) _ = RunDns();
        }

        void SyncButtons()
        {
            bool busy = Actions.Scanning || Actions.Testing;
            bTest.Enabled = !busy;
            bScan.Enabled = !Actions.Scanning;
        }

        // ------------------------------------------------ connection test

        void FillHosts()
        {
            lvHosts.BeginUpdate();
            lvHosts.Items.Clear();
            foreach (var h in App.Settings.TestHosts)
                lvHosts.Items.Add(new ListViewItem(new[] { h, "—", "", "", "", "" }) { Tag = h, ForeColor = Theme.Text });
            lvHosts.EndUpdate();
        }

        void ShowResults(List<HostResult> res)
        {
            lvHosts.BeginUpdate();
            lvHosts.Items.Clear();
            foreach (var h in App.Settings.TestHosts)
            {
                var r = res.FirstOrDefault(x => x.Host == h);
                ListViewItem it = r == null
                    ? new ListViewItem(new[] { h, "—", "", "", "", "" }) { ForeColor = Theme.Text }
                    : new ListViewItem(new[] { h, r.Ok ? Loc.T("netPage.status.open") : Loc.T("netPage.status.closed"), r.Ms + " ms", r.Ip, r.Detail, r.Ok ? "" : r.Code })
                      { ForeColor = r.Ok ? GreenText : RedText };
                it.Tag = h;
                lvHosts.Items.Add(it);
            }
            lvHosts.EndUpdate();
            int ok = res.Count(r => r.Ok);
            string dns = App.LastDnsOk == true ? " " + Loc.T("netPage.dnsCorrect") : App.LastDnsOk == false ? " " + Loc.T("netPage.dnsWrong") : "";
            testSummary.Text = (ok == res.Count ? Loc.T("netPage.allReachable") : Loc.T("netPage.someUnreachable", res.Count - ok)) + dns;
            testSummary.ForeColor = ok == res.Count && App.LastDnsOk != false ? GreenText : AmberText;
        }

        void AddHost()
        {
            string h = hostInput.Text.Trim();
            if (h.Length == 0) return;
            string clean = h.Contains("://") ? h : Domains.Clean(h);
            if (clean == null) { MessageBox.Show(FindForm(), Loc.T("netPage.badServer"), App.Name); return; }
            if (!App.Settings.TestHosts.Contains(clean, StringComparer.OrdinalIgnoreCase)) App.Settings.TestHosts.Add(clean);
            App.Save();
            hostInput.Clear();
            FillHosts();
        }

        void RemoveHost()
        {
            if (lvHosts.SelectedItems.Count == 0 || App.Settings.TestHosts.Count <= 1) return;
            App.Settings.TestHosts.Remove((string)lvHosts.SelectedItems[0].Tag);
            App.Save();
            FillHosts();
        }

        async Task RunTest()
        {
            testSummary.Text = Loc.T("netPage.testing");
            testSummary.ForeColor = Muted;
            var res = await Actions.QuickTestAsync();
            if (res != null && !IsDisposed) ShowResults(res);
        }

        // ------------------------------------------------ site analysis

        async Task Analyze()
        {
            string host = Domains.Clean(siteInput.Text);
            if (host == null) { siteOut.Clear(); siteOut.Bad(Loc.T("netPage.site.badDomain")); return; }
            bAnalyze.Enabled = false;
            siteOut.Clear();
            siteOut.Head(Loc.T("netPage.site.analysis", host));
            siteOut.Muted(Loc.T(App.Engine.State == EngineState.Running ? "netPage.site.stateOn" : "netPage.site.stateOff", App.Engine.ActiveProfile?.Name));
            siteOut.Blank();
            try
            {
                var rep = await Task.Run(() => NetTest.AnalyzeSite(host));
                if (IsDisposed) return;
                siteOut.Out("1) DNS", Theme.Text, Bold);
                siteOut.Kv("   " + Loc.T("netPage.site.systemDns"), rep.Sys.Count > 0 ? string.Join(", ", rep.Sys.Take(3)) : Loc.T("netPage.site.noAnswer"));
                siteOut.Kv("   " + Loc.T("netPage.site.independentDns", rep.RefServer.Length > 0 ? rep.RefServer : "—"), rep.Ref.Count > 0 ? string.Join(", ", rep.Ref.Take(3)) : Loc.T("netPage.site.noAnswer"));
                siteOut.Kv("   " + Loc.T("netPage.col.result"), rep.Ref.Count == 0 ? Loc.T("netPage.site.noCompare") : rep.DnsPoisoned ? Loc.T("netPage.site.fake") : Loc.T("netPage.site.correct"), rep.DnsPoisoned ? RedText : GreenText);
                siteOut.Blank();
                siteOut.Out(Loc.T("netPage.site.step2") + (rep.ProbeRef != null ? " (" + rep.ProbeRef.Ip + ")" : ""), Theme.Text, Bold);
                if (rep.ProbeRef != null)
                {
                    siteOut.Kv("   TCP (443)", rep.ProbeRef.TcpOk ? Loc.T("netPage.site.connected", rep.ProbeRef.TcpMs) : Loc.T("netPage.site.connectFailed"), rep.ProbeRef.TcpOk ? GreenText : RedText);
                    if (rep.ProbeRef.TcpOk)
                        siteOut.Kv("   " + Loc.T("netPage.site.tls"), rep.ProbeRef.Describe(), rep.ProbeRef.TlsOk ? GreenText : RedText);
                }
                if (rep.ProbeSys != null)
                    siteOut.Kv("   " + Loc.T("netPage.site.fakeAddress", rep.ProbeSys.Ip), rep.ProbeSys.Describe(), Muted);
                siteOut.Blank();
                siteOut.Out(Loc.T("netPage.site.step3"), Theme.Text, Bold);
                siteOut.Kv("   " + Loc.T("netPage.col.result"), rep.Http.Detail + " · " + rep.Http.Ms + " ms", rep.Http.Ok ? GreenText : RedText);
                siteOut.Blank();
                siteOut.Out(Loc.T("netPage.site.diagnosis", rep.Verdict), rep.Ok ? GreenText : RedText, Big);
                siteOut.Out(rep.Advice, Theme.Text, Body);
                if (!string.IsNullOrEmpty(rep.Code))
                {
                    var info = ErrorCatalog.Get(rep.Code);
                    if (info != null)
                    {
                        siteOut.Blank();
                        siteOut.Out(Loc.T("netPage.site.relatedCode", info.Code, info.Title), AccentInk, Bold);
                        foreach (var st in info.Steps.Take(3)) siteOut.Out("  • " + st, Theme.Text, Small);
                    }
                }
            }
            catch (Exception ex) { siteOut.Bad(Loc.T("common.error", ex.Message)); }
            finally { if (!IsDisposed) bAnalyze.Enabled = true; }
        }

        // ------------------------------------------------ DNS servers

        async Task RunDns()
        {
            bDns.Enabled = false;
            bUseDns.Visible = false;
            dnsSummary.Text = Loc.T("netPage.testing");
            lvDns.Items.Clear();
            try
            {
                var rows = await Task.Run(() => NetTest.TestDnsServers("discord.com"));
                if (IsDisposed) return;
                lvDns.BeginUpdate();
                foreach (var r in rows)
                {
                    var it = new ListViewItem(new[]
                    {
                        r.Name, r.IsSystem ? Loc.T("netPage.dns.windowsSetting") : r.Server + ":" + r.Port, r.Answered ? r.Ms + " ms" : "—",
                        r.Ips.Count > 0 ? string.Join(", ", r.Ips.Take(2)) : "—", r.Note,
                    })
                    { ForeColor = r.Correct == true ? Theme.Text : r.Answered ? AmberText : RedText };
                    if (r.Correct == true) it.SubItems[4].Text = "✓ " + r.Note;
                    lvDns.Items.Add(it);
                }
                lvDns.EndUpdate();
                var best = rows.Where(r => !r.IsSystem && r.Correct == true && r.Port != 53).OrderBy(r => r.Ms).FirstOrDefault();
                var sys = rows.FirstOrDefault(r => r.IsSystem);
                string s = "";
                if (sys != null)
                    s += sys.Correct == false ? Loc.T("netPage.dns.sysBlocked") + " "
                       : sys.Correct == true ? Loc.T("netPage.dns.sysOk") + " " : "";
                if (best != null)
                {
                    bestDns = best.Id;
                    s += Loc.T("netPage.dns.fastest", best.Name, best.Ms);
                    var prof = Profiles.BuiltIns.FirstOrDefault(x => x.Group == Profiles.GroupRecommended && x.Dns == best.Id);
                    if (prof != null && prof.Id != App.Settings.SelectedProfileId)
                    {
                        bUseDns.Text = Loc.T("netPage.dns.useProfile", prof.Name);
                        bUseDns.Visible = true;
                    }
                }
                else s += Loc.T("netPage.dns.noneAnswered");
                dnsSummary.Text = s;
            }
            catch (Exception ex) { dnsSummary.Text = Loc.T("common.error", ex.Message); }
            finally { if (!IsDisposed) bDns.Enabled = true; }
        }

        // ------------------------------------------------ network info

        async Task RunNet()
        {
            if (netOut == null) return;
            bNet.Enabled = false;
            netOut.Clear();
            netOut.Muted(Loc.T("netPage.net.collecting"));
            try
            {
                var adapters = await Task.Run(() => NetTest.Adapters());
                var proxy = NetTest.SystemProxy();
                var hosts = NetTest.HostsDiscordLines();
                var av = await Task.Run(() => Diagnostics.Antivirus());
                var other = await Task.Run(() => Diagnostics.RunningOtherDpi());
                if (IsDisposed) return;
                netOut.Clear();
                netOut.Head(Loc.T("netPage.net.adapters"));
                foreach (var a in adapters)
                {
                    netOut.Out(a.Name + "  ·  " + a.Type + (a.Speed.Length > 0 ? "  ·  " + a.Speed : "") + (a.IsVpn ? "  ·  VPN" : ""), a.IsVpn ? AmberText : Theme.Text, Bold);
                    netOut.Muted("   " + a.Description);
                    if (a.V4.Count > 0) netOut.Kv("   IPv4", string.Join(", ", a.V4) + (a.Dhcp ? " " + Loc.T("netPage.net.dhcp") : " " + Loc.T("netPage.net.static")));
                    if (a.V6.Count > 0) netOut.Kv("   IPv6", string.Join(", ", a.V6.Take(2)) + (a.HasGlobalV6 ? "" : " " + Loc.T("netPage.net.local")));
                    if (a.Gateways.Count > 0) netOut.Kv("   " + Loc.T("netPage.net.gateway"), string.Join(", ", a.Gateways));
                    if (a.Dns.Count > 0) netOut.Kv("   " + Loc.T("netPage.net.dnsServers"), string.Join(", ", a.Dns));
                }
                netOut.Blank();
                netOut.Head(Loc.T("netPage.net.system"));
                netOut.Kv("Proxy", proxy.Enabled ? Loc.T("netPage.net.proxyOn") + " " + proxy.Server : Loc.T("netPage.net.off"), proxy.Enabled ? AmberText : (Color?)null);
                netOut.Kv(Loc.T("netPage.net.ipv6Internet"), adapters.Any(a => a.HasGlobalV6) ? Loc.T("netPage.net.yes") : Loc.T("netPage.net.no"));
                netOut.Kv(Loc.T("netPage.net.hostsDiscord"), hosts.Count > 0 ? string.Join(" | ", hosts.Take(3)) : Loc.T("netPage.net.noEntries"), hosts.Count > 0 ? AmberText : (Color?)null);
                netOut.Kv(Loc.T("netPage.net.antivirus"), av.Count > 0 ? string.Join(", ", av) : Loc.T("netPage.net.unknown"));
                netOut.Kv(Loc.T("netPage.net.otherDpi"), other.Count > 0 ? string.Join(", ", other) : Loc.T("netPage.net.none"), other.Count > 0 ? AmberText : (Color?)null);
                netOut.Kv(Loc.T("netPage.net.gdpiFolder"), Engine.BinDir);
                netOut.Kv("Windows", Environment.OSVersion.VersionString + (Environment.Is64BitOperatingSystem ? " (64-bit)" : " (32-bit)"));
                netOut.Kv(Loc.T("netPage.net.doh"), SystemDns.DohSupported ? Loc.T("netPage.net.dohYes") : Loc.T("netPage.net.no"));
                netOut.SelectionStart = 0;
                netOut.ScrollToCaret();
            }
            catch (Exception ex) { netOut.Bad(Loc.T("common.error", ex.Message)); }
            finally { if (!IsDisposed) bNet.Enabled = true; }
        }
            // ------------------------------------------------ speed test

        async Task RunSpeed()
        {
            if (speedRunning) return;
            speedRunning = true;
            bSpeed.Enabled = false;
            foreach (var l in speedVals) { l.Text = "…"; l.ForeColor = Muted; }
            var cts = new System.Threading.CancellationTokenSource();
            var r = await Task.Run(() => SpeedTest.Run((msg, frac) =>
            {
                try { BeginInvoke(new Action(() => { if (!IsDisposed) { speedStatus.Text = msg; speedBar.Value = (float)frac; } })); } catch { }
            }, cts.Token));
            speedRunning = false;
            if (IsDisposed) return;
            bSpeed.Enabled = true;
            speedBar.Value = 1;
            if (r.Error.Length > 0 && r.PingMs == 0) { speedStatus.Text = Loc.T("netPage.speed.failed", r.Error); speedStatus.ForeColor = RedText; return; }
            speedVals[0].Text = r.PingMs.ToString();
            speedSubs[0].Text = Loc.T("netPage.speed.jitter", r.JitterMs);
            speedVals[1].Text = r.DownMbps.ToString(r.DownMbps < 10 ? "0.0" : "0");
            speedSubs[1].Text = "Mbit/s · " + (r.DownBytes / 1048576.0).ToString("0") + " MB";
            speedVals[2].Text = r.UpMbps.ToString(r.UpMbps < 10 ? "0.0" : "0");
            speedSubs[2].Text = "Mbit/s · " + (r.UpBytes / 1048576.0).ToString("0") + " MB";
            foreach (var l in speedVals) l.ForeColor = Theme.Text;
            speedStatus.Text = Loc.T(App.Engine.State == EngineState.Running ? "netPage.speed.doneOn" : "netPage.speed.doneOff", DateTime.Now.ToString("HH:mm")) +
                               (r.Error.Length > 0 ? " " + Loc.T("netPage.speed.warning") + " " + r.Error : "");
            speedStatus.ForeColor = r.Error.Length > 0 ? AmberText : GreenText;
        }

        // ------------------------------------------------ history

        void FillHistory()
        {
            var all = History.Snapshot();
            chart.Items = all.Where(x => x.Kind == "test" || x.Kind == "repair").ToList();
            chart.Invalidate();
            var day = all.Where(x => x.Kind == "test" && x.Running && x.Time > DateTime.Now.AddHours(-24)).ToList();
            int heals = all.Count(x => x.Kind == "repair" && x.Time > DateTime.Now.AddDays(-7));
            if (day.Count == 0) histStats.Text = Loc.T("netPage.history.none");
            else
            {
                double pct = 100.0 * day.Count(x => x.Success) / day.Count;
                var good = day.Where(x => x.Ms > 0).ToList();
                histStats.Text = Loc.T("netPage.history.stats", day.Count, pct.ToString("0")) +
                                 (good.Count > 0 ? " · " + Loc.T("netPage.history.avg", (int)good.Average(x => x.Ms)) : "") + " · " + Loc.T("netPage.history.repairs", heals);
            }
            lvHist.BeginUpdate();
            lvHist.Items.Clear();
            foreach (var e in all.AsEnumerable().Reverse().Take(300))
            {
                string res = e.Kind == "speed" ? e.Ms + " ms" : e.Kind == "test" ? e.Ok + "/" + e.Total + (e.DnsOk == false ? " DNS✗" : "") : e.Ok > 0 ? Loc.T("netPage.history.ok") : Loc.T("netPage.history.failed");
                var it = new ListViewItem(new[]
                {
                    e.Time.ToString("dd.MM HH:mm:ss"), History.KindName(e.Kind), e.Profile, res,
                    (e.Kind == "test" && !e.Running ? Loc.T("netPage.history.protectionOff") + " · " : "") + (e.Kind == "test" && e.Ms > 0 ? Loc.T("netPage.history.avg", e.Ms) + (e.Note.Length > 0 ? " · " : "") : "") + e.Note,
                });
                it.ForeColor = e.Kind == "speed" ? Theme.Text : (e.Kind == "test" ? e.Success : e.Ok > 0) ? GreenText : e.Kind == "test" && e.Ok > 0 ? AmberText : RedText;
                if (e.Kind == "test" && !e.Running) it.ForeColor = Muted;
                lvHist.Items.Add(it);
            }
            lvHist.EndUpdate();
        }
    }

    /// <summary>Bar chart of the recent tests: the height is the latency, the color is the result.</summary>
    sealed class HistoryChart : Control
    {
        public List<HistoryEntry> Items = new List<HistoryEntry>();

        public HistoryChart()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.Clear(BackColor);
            HQ(g);
            var data = Items.Skip(Math.Max(0, Items.Count - 60)).ToList();
            int left = D(36), bottom = Height - D(20), top = D(8);
            using (var pen = new Pen(Divider)) { g.DrawLine(pen, left, bottom, Width, bottom); g.DrawLine(pen, left, top, Width, top); }
            if (data.Count == 0)
            {
                TextRenderer.DrawText(g, Loc.T("netPage.chart.empty"), Small,
                    new Rectangle(left, top, Width - left, bottom - top), Muted, BackColor, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.WordBreak);
                return;
            }
            int max = Math.Max(200, data.Where(x => x.Kind == "test").Select(x => x.Ms).DefaultIfEmpty(0).Max());
            max = (int)(Math.Ceiling(max / 100.0) * 100);
            TextRenderer.DrawText(g, max + " ms", Caption, new Point(0, top - D(2)), Muted, BackColor);
            TextRenderer.DrawText(g, "0", Caption, new Point(D(20), bottom - D(12)), Muted, BackColor);
            float slot = (Width - left) / 60f;
            float bw = Math.Max(D(3), slot * 0.7f);
            for (int i = 0; i < data.Count; i++)
            {
                var d = data[i];
                float x = left + (60 - data.Count + i) * slot + (slot - bw) / 2;
                if (d.Kind == "repair")
                {
                    using (var b = new SolidBrush(Accent))
                        g.FillPolygon(b, new[] { new PointF(x + bw / 2, top), new PointF(x, top + D(8)), new PointF(x + bw, top + D(8)) });
                    using (var pen = new Pen(Color.FromArgb(120, Accent)) { DashStyle = System.Drawing.Drawing2D.DashStyle.Dot })
                        g.DrawLine(pen, x + bw / 2, top + D(8), x + bw / 2, bottom);
                    continue;
                }
                Color c = !d.Running ? Mix(Muted, BackColor, 0.4f) : d.Success ? Green : d.Ok > 0 ? Amber : Red;
                float h = d.Ok == 0 ? (bottom - top) * 0.15f : Math.Max(D(3), (bottom - top) * Math.Min(1f, d.Ms / (float)max));
                using (var p = Round(new RectangleF(x, bottom - h, bw, h), Math.Min(D(2), bw / 2)))
                using (var b = new SolidBrush(c)) g.FillPath(b, p);
            }
            var first = data.First().Time;
            TextRenderer.DrawText(g, first.ToString("dd.MM HH:mm"), Caption, new Point(left, bottom + D(4)), Muted, BackColor);
            string last = data.Last().Time.ToString("dd.MM HH:mm");
            var sz = TextRenderer.MeasureText(last, Caption);
            TextRenderer.DrawText(g, last, Caption, new Point(Width - sz.Width, bottom + D(4)), Muted, BackColor);
        }
    }
}
