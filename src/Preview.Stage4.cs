#if PREVIEW
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace NSFShield
{
    /// <summary>stage 4 screenshots: EN/TR × Simple/Standard/Advanced × home, profiles, smart scanner (fixed example results).</summary>
    static partial class Preview
    {
        static Profile BI(string id) => Profiles.BuiltIns.First(p => p.Id == id);

        static TargetProbe Pr(string host, TargetVerdict v, int ms, string via = "direct")
        {
            bool ok = v != TargetVerdict.Fail;
            int status = host.StartsWith("cdn.") || host.StartsWith("media.") ? 404 : host == "discordapp.com" ? 301 : 200;
            return new TargetProbe
            {
                Host = host, Ip = "162.159.13" + (host.Length % 8) + "." + (200 + host.Length), Verdict = v, Via = via,
                Stage = ok ? ProbeStage.Done : ProbeStage.Tls, DnsMs = 14, ConnectMs = ms / 4, TlsMs = ok ? ms / 2 : (int?)null,
                HttpMs = ok ? ms - ms / 4 - ms / 2 : (int?)null, Status = ok ? (v == TargetVerdict.Partial ? 429 : status) : 0,
                Detail = ok ? (v == TargetVerdict.Partial ? new LocText("scan.http.unclear", 429) : new LocText("scan.http.expected", status)) : new LocText("scan.probe.tlsFailed", "ConnectionReset"),
                Code = v == TargetVerdict.Pass ? "" : v == TargetVerdict.Partial ? "NSF-505" : "NSF-501",
            };
        }

        /// <summary>A measured row: <paramref name="pass"/> targets pass both rounds, <paramref name="partial"/> answer unclearly, the rest fail.</summary>
        static ScanRow Row(string id, int order, int pass, int partial, int ms, StunResult udp, bool socks = false)
        {
            var hosts = AppSettings.DefaultTestHosts;
            var r = new ScanRow { P = BI(id), Order = order, Tested = true, Udp = udp };
            for (int i = 0; i < hosts.Length; i++)
            {
                var v = i < pass ? TargetVerdict.Pass : i < pass + partial ? TargetVerdict.Partial : TargetVerdict.Fail;
                var t = new TargetRow { Host = hosts[i], R1 = Pr(hosts[i], v, ms + i * 9, socks ? "socks" : "direct") };
                if (v == TargetVerdict.Pass) t.R2 = Pr(hosts[i], v, ms + i * 7, socks ? "socks" : "direct");
                r.Targets.Add(t);
            }
            Scanner.Evaluate(r);
            return r;
        }

        static StunResult Udp(StunStatus st, string scope, int? ms = null) => new StunResult { Status = st, Scope = scope, Ms = ms };

        /// <summary>Fixed example result of a scan (nothing is measured).</summary>
        static ScanOutcome Sample(UiLevel lvl)
        {
            var o = new ScanOutcome();
            var baseline = AppSettings.DefaultTestHosts.Select(h => new TargetRow { Host = h, Baseline = true, R1 = Pr(h, TargetVerdict.Fail, 0) }).ToList();
            o.Baseline = baseline;
            if (lvl == UiLevel.Simple)
            {
                o.Request = ScanRequest.Create(ScanScope.Recommended, ScanMode.StopOnFirstMatch, true, ProfileCatalog.RecommendedOrder, AppSettings.DefaultTestHosts, all: Profiles.BuiltIns);
                o.Rows.Add(Row("tr-recommended", 0, 0, 0, 0, Udp(StunStatus.Timeout, "general")));
                o.Rows.Add(Row("zapret-discord", 1, 6, 0, 168, Udp(StunStatus.Ok, "general", 38)));
                o.Suggested = o.Rows[1];
                o.Applied = o.Rows[1].P;
                o.Summary = new LocText("scan.applied", o.Applied.Name, o.Rows[1].AvgMs + " ms");
                return o;
            }
            o.Request = ScanRequest.Create(ScanScope.Recommended, ScanMode.FullBenchmark, false, ProfileCatalog.RecommendedOrder, AppSettings.DefaultTestHosts, all: Profiles.BuiltIns);
            o.Rows.Add(Row("tr-recommended", 0, 0, 0, 0, Udp(StunStatus.Timeout, "general")));
            o.Rows.Add(Row("zapret-discord", 1, 6, 0, 168, Udp(StunStatus.Ok, "general", 38)));
            o.Rows.Add(Row("byedpi-recommended", 2, 4, 1, 231, Udp(StunStatus.NotMeasured, "na"), socks: true));
            o.Rows.Add(Row("zapret-general", 3, 6, 0, 187, Udp(StunStatus.Ok, "general", 41)));
            o.Rows.Add(Row("tr-adguard", 4, 0, 0, 0, Udp(StunStatus.Timeout, "general")));
            o.Rows.Add(Row("tr-quad9", 5, 0, 0, 0, Udp(StunStatus.Timeout, "general")));
            o.Rows.Add(Row("tr-opendns", 6, 2, 0, 264, Udp(StunStatus.Timeout, "general")));
            o.Suggested = Scanner.Rank(o.Rows).First(r => r.IsFull);
            o.Summary = new LocText("scan.suggestedBenchmark", o.Suggested.P.Name);
            return o;
        }

        static void ShotDialog(Form d, string path)
        {
            d.StartPosition = FormStartPosition.Manual;
            d.Location = new Point(-5000, 0);
            d.Show();
            Shot(d, path);
            d.Close();
        }

        public static void Stage4Shots(MainForm form, string dir)
        {
            string sel = App.Settings.SelectedProfileId;
            foreach (var lang in new[] { "en", "tr" })
            {
                Loc.SetLanguage(lang);
                foreach (var lvl in new[] { UiLevel.Simple, UiLevel.Standard, UiLevel.Advanced })
                {
                    string tag = "s4_" + lang + "_" + lvl.ToString().ToLowerInvariant();
                    App.Settings.SelectedProfileId = "zapret-discord";
                    App.Settings.ShowExpertProfiles = false;
                    App.Engine.DebugSet(EngineState.Running, BI("zapret-discord"));
                    Theme(form, "system", lvl);
                    App.RaiseStatus();
                    form.Navigate("home");
                    Shot(form, Path.Combine(dir, tag + "_home.png"));
                    form.Navigate("profiles");
                    Shot(form, Path.Combine(dir, tag + "_profiles.png"));
                    using (var d = ScanDialog.DebugCreate(lvl, Sample(lvl))) ShotDialog(d, Path.Combine(dir, tag + "_scanner.png"));
                }
                // the selected/running expert profile is shown once in the filtered lists (Simple, Standard without experts)
                App.Settings.SelectedProfileId = "zapret-lastresort";
                App.Engine.DebugSet(EngineState.Running, BI("zapret-lastresort"));
                Theme(form, "system", UiLevel.Simple);
                App.RaiseStatus();
                form.Navigate("home");
                Shot(form, Path.Combine(dir, "s4x_" + lang + "_simple_home_expert.png"));
                form.Navigate("profiles");
                Shot(form, Path.Combine(dir, "s4x_" + lang + "_simple_profiles_expert.png"));
                Theme(form, "system", UiLevel.Standard);
                form.Navigate("profiles");
                Shot(form, Path.Combine(dir, "s4x_" + lang + "_standard_profiles_expert.png"));
                App.Settings.ShowExpertProfiles = true;
                Theme(form, "system", UiLevel.Standard);
                form.Navigate("profiles");
                Shot(form, Path.Combine(dir, "s4x_" + lang + "_standard_profiles_showexperts.png"));
                App.Settings.ShowExpertProfiles = false;
                // Advanced in a dark theme: command preview and the scanner's layer view
                App.Settings.SelectedProfileId = "byedpi-hybrid-oob";
                App.Engine.DebugSet(EngineState.Running, BI("byedpi-hybrid-oob"));
                Theme(form, "slate-dark", UiLevel.Advanced);
                form.Navigate("profiles");
                Shot(form, Path.Combine(dir, "s4x_" + lang + "_advanced_profiles_dark.png"));
                using (var d = ScanDialog.DebugCreate(UiLevel.Advanced, Sample(UiLevel.Advanced))) ShotDialog(d, Path.Combine(dir, "s4x_" + lang + "_advanced_scanner_dark.png"));
                using (var ed = new EngineProfileEditor(new Profile { Name = "Test", Engine = EngineKind.Zapret, EngineArgs = "--wf-tcp=443 --debug=@log.txt" }))
                    ShotDialog(ed, Path.Combine(dir, "s4x_" + lang + "_editor_invalid.png"));
            }
            App.Settings.SelectedProfileId = sel;
            App.Engine.DebugSet(EngineState.Running, App.SelectedProfile);
            Loc.SetLanguage(App.Settings.Language);
        }
    }
}
#endif
