using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace NSFShield
{
    /// <summary>Shared operations called from different places of the UI (home page, tray, profiles).</summary>
    static class Actions
    {
        public static bool Testing { get; private set; }
        /// <summary>A scan owns the engine (<see cref="ScanGate"/>): nothing else may start, switch or stop protection meanwhile.</summary>
        public static bool Scanning => ScanGate.Busy;

        /// <summary>True (and logged) when an action must wait because a scan owns the engine.</summary>
        static bool RefusedByScan(string what)
        {
            if (!ScanGate.Busy) return false;
            App.Log(what + " ignored: a scan is running.", LogLevel.Debug);
            return true;
        }
        static DateTime? discordHintFor;

        public static DateTime LastHeal = DateTime.MinValue;
        static System.Threading.CancellationTokenSource healCts;

        /// <summary>Cancels an automatic repair scan (app exit, Windows shutdown); scan windows cancel their own scan when closed.</summary>
        public static void CancelScans()
        {
            try { healCts?.Cancel(); } catch (ObjectDisposedException) { }
        }
        public static bool Healing { get; private set; }

        /// <summary>
        /// Runs a user's start/stop on the engine. Accepting it and a scan taking the engine are ordered under the scan gate's
        /// lock: refused while a scan owns the engine, and until it has finished no scan can record the state.
        /// </summary>
        static async Task<bool> UserEngineOp(string what, Func<bool> op)
        {
            if (!ScanGate.TryBeginUser())
            {
                App.Log(what + " ignored: a scan is running.", LogLevel.Debug);
                return false;
            }
            try { return await Task.Run(op); }
            finally { ScanGate.EndUser(); }
        }

        public static async Task StartAsync()
        {
            var p = App.SelectedProfile;
            bool ok = await UserEngineOp("Start", () => App.Engine.Start(p));
            if (ok && App.Settings.TestAfterStart)
            {
                await Task.Delay(1500);
                var res = await QuickTestAsync(!App.Settings.AutoHeal);
                await MaybeHealAsync(res);
            }
        }

        static bool Broken(List<HostResult> res) =>
            res != null && res.Count > 0 && (res.Count(r => r.Ok) < res.Count || App.LastDnsOk == false);

        /// <summary>
        /// If Discord cannot be reached while protection is on, finds a working method by itself (auto-repair).
        /// Does not kick in again for 10 minutes after a scan or a repair.
        /// </summary>
        public static async Task<bool> MaybeHealAsync(List<HostResult> res)
        {
            if (!App.Settings.AutoHeal || Scanning || Healing || App.Engine.Quiet) return false;
            if (App.Engine.State != EngineState.Running || !Broken(res)) return false;
            if ((DateTime.Now - LastHeal).TotalMinutes < 10) return false;
            Healing = true;
            LastHeal = DateTime.Now;
            try
            {
                int ok = res.Count(r => r.Ok);
                App.Log("Auto-repair: protection is on but " + (res.Count - ok) + "/" + res.Count + " server(s) cannot be reached" +
                        (App.LastDnsOk == false ? " (wrong DNS)" : "") + "; searching for a working method…", LogLevel.Warn);
                App.Notify(Loc.T("actions.heal.title"), Loc.T("actions.heal.searching"), ToolTipIcon.Info);
                string before = App.SelectedProfile.Name;
                var sc = new Scanner(ScanRequest.Heal());
                healCts = new System.Threading.CancellationTokenSource();
                ScanOutcome o;
                try { o = await sc.RunAsync(healCts.Token); }
                finally { healCts.Dispose(); healCts = null; }
                var best = o.Applied;
                if (best != null)
                {
                    var msg = best.Name == before ? new LocText("actions.heal.sameMethod", best.Name) : new LocText("actions.heal.newMethod", best.Name, before);
                    App.Log("Auto-repair finished. " + msg.English, LogLevel.Success);
                    History.Add(new HistoryEntry { Time = DateTime.Now, Kind = "repair", Profile = best.Name, Ok = 1, Total = 1, Running = true, Note = msg.Text });
                    App.Notify(Loc.T("actions.heal.fixedTitle"), msg.Text + (DiscordHelper.IsRunning ? Loc.T("actions.heal.restartDiscordHint") : ""), ToolTipIcon.Info);
                    return true;
                }
                App.Log("Auto-repair could not find a working method" + (o.FailCode.Length > 0 ? " [" + o.FailCode + "]" : "") + ".", LogLevel.Warn);
                History.Add(new HistoryEntry { Time = DateTime.Now, Kind = "repair", Profile = before, Ok = 0, Total = 1, Running = App.Engine.State == EngineState.Running, Note = Loc.T("actions.heal.noMethod") + " " + o.FailCode });
                App.Notify(Loc.T("actions.heal.failedTitle"),
                    Loc.T("actions.heal.failedText", o.FailCode.Length > 0 ? " (" + o.FailCode + " – " + ErrorCatalog.Get(o.FailCode)?.Title + ")" : ""), ToolTipIcon.Warning);
                return false;
            }
            finally
            {
                Healing = false;
                LastHeal = DateTime.Now;
                App.RaiseStatus();
            }
        }

        /// <summary>Connection watchdog: silently tests while protection is on and repairs problems.</summary>
        public static async Task WatchCheckAsync(string reason)
        {
            if (App.Engine.State != EngineState.Running || Scanning || Testing || Healing || App.Engine.Quiet) return;
            App.Log("Connection watchdog: checking (" + reason + ").", LogLevel.Debug);
            var res = await QuickTestAsync(!App.Settings.AutoHeal);
            await MaybeHealAsync(res);
        }

        public static Task StopAsync() => UserEngineOp("Stop", () => { App.Engine.Stop(); return true; });

        public static async Task ToggleAsync()
        {
            if (Scanning) return;
            var s = App.Engine.State;
            if (s == EngineState.Running || s == EngineState.Starting) await StopAsync();
            else if (s != EngineState.Stopping) await StartAsync();
        }

        /// <summary>Profile selections requested (the self-test checks that rebuilding a page selects nothing).</summary>
        internal static int SelectRequests;

        /// <summary>
        /// Selects a profile: the settings write and the restart happen inside one reservation of the scan gate (accepted only
        /// while no scan owns the engine; until it has finished no scan can record the state). The test after the start runs
        /// after the reservation (its repair may start a scan).
        /// </summary>
        public static async Task SelectProfileAsync(Profile p)
        {
            SelectRequests++;
            if (p == null) return;
            if (!ScanGate.TryBeginUser()) { App.Log("Profile change ignored: a scan is running.", LogLevel.Debug); return; }
            bool started = false;
            try
            {
                bool changed = p.Id != App.Settings.SelectedProfileId;
                var before = App.SelectedProfile;
                App.Settings.SelectedProfileId = p.Id;
                App.Settings.RememberProfile(p);
                App.Save();
                if (changed) App.Log("Profile selected: " + p.Name + (before.Engine != p.Engine ? " (engine: " + Engines.Of(before).DisplayName + " → " + Engines.Of(p).DisplayName + ")" : ""), LogLevel.Info);
                App.RaiseStatus();
                var s = App.Engine.State;
                if (s == EngineState.Running || s == EngineState.Starting || s == EngineState.Error)
                    started = await Task.Run(() => App.Engine.Start(p));
            }
            finally { ScanGate.EndUser(); }
            if (started && App.Settings.TestAfterStart)
            {
                await Task.Delay(1500);
                var res = await QuickTestAsync(!App.Settings.AutoHeal);
                await MaybeHealAsync(res);
            }
        }

        /// <summary>
        /// Sets this installation's service up again for this folder (2.x data, another engine of this folder): a running service
        /// is restarted with the new command without a general takeover (no other program is closed); a stopped one is
        /// reconfigured and stays stopped. Inside one reservation of the scan gate.
        /// </summary>
        public static async Task<bool> RepointServiceAsync()
        {
            if (!ScanGate.TryBeginUser()) { App.Log("Service update postponed: a scan is running.", LogLevel.Debug); return false; }
            try
            {
                return await Task.Run(() =>
                {
                    var svc = Engine.Scm.Query(Engine.ServiceName);
                    if (!svc.Exists || svc.Unknown || svc.Owned == null) return false;
                    var p = Engine.RepointProfile(svc.Owned.Value);
                    if (svc.Running) return App.Engine.Start(p, takeOver: false) && Engine.CheckServiceTarget() == Engine.ServiceTarget.ThisFolder;
                    bool ok = App.Engine.RepointStoppedService(p, out var err);
                    if (!ok) App.Log("[NSF-701] " + err?.English, LogLevel.Warn);
                    return ok && Engine.CheckServiceTarget() == Engine.ServiceTarget.ThisFolder;
                });
            }
            finally { ScanGate.EndUser(); }
        }

        /// <summary>
        /// Quick engine switch (profiles page, tray, home page): selects the profile last used with that engine (or its first
        /// recommended one). If protection is on, the running engine is stopped cleanly and the new one started.
        /// </summary>
        public static async Task SelectEngineAsync(EngineKind k)
        {
            if (Scanning) return;
            var eng = Engines.Get(k);
            if (!eng.Available(out var why))
            {
                App.Log("[NSF-107] " + why.English, LogLevel.Warn);
                App.Notify(eng.DisplayName, why.Text, ToolTipIcon.Warning);
                return;
            }
            var all = Profiles.ForEngine(App.AllProfiles, k).ToList();
            var p = all.FirstOrDefault(x => x.Id == App.Settings.LastProfileId(k)) ?? all.FirstOrDefault();
            if (p == null) return;
            await SelectProfileAsync(p);
        }

        /// <summary>Restarts protection with the new settings if it is running.</summary>
        public static async Task RestartIfActiveAsync()
        {
            if (App.Engine.IsActive) await StartAsync();
        }

        /// <summary>
        /// "Apply" of a compared scan result (FullBenchmark never applies by itself): selects the profile and starts protection the
        /// normal way. If it does not run, the previous profile and state come back.
        /// </summary>
        public static async Task<bool> ApplyProfileAsync(Profile p)
        {
            if (p == null) return false;
            // the settings write, the start and the undo of a failure are one reservation of the scan gate (a scan can never
            // record the state in between); the scan result is applied by the same owner rule as a scan (no general takeover)
            if (!ScanGate.TryBeginUser()) { App.Log("Apply ignored: a scan is running.", LogLevel.Debug); return false; }
            try
            {
                var s = App.Settings;
                string sel = s.SelectedProfileId;
                var (g, z, b) = (s.LastGoodbyeDpiProfileId, s.LastZapretProfileId, s.LastByeDpiProfileId);
                bool wasActive = App.Engine.IsActive;
                s.SelectedProfileId = p.Id;
                s.RememberProfile(p);
                App.Save();
                App.Log("Profile applied from the scan result: " + p.Name + " [" + Engines.Of(p).DisplayName + "]", LogLevel.Info);
                bool ok = await Task.Run(() => App.Engine.Start(p, takeOver: false)) && App.Engine.State == EngineState.Running;
                if (ok) { App.RaiseStatus(); return true; }
                App.Log("The scan result could not be applied; going back to the previous profile.", LogLevel.Warn);
                s.SelectedProfileId = sel;
                s.LastGoodbyeDpiProfileId = g; s.LastZapretProfileId = z; s.LastByeDpiProfileId = b;
                App.Save();
                var prev = App.SelectedProfile;
                if (wasActive) await Task.Run(() => App.Engine.Start(prev, takeOver: false));
                App.RaiseStatus();
                return false;
            }
            finally { ScanGate.EndUser(); }
        }

        public static async Task<List<HostResult>> QuickTestAsync(bool notifyOnFail = false)
        {
            if (Testing) return App.LastTest;
            Testing = true;
            App.RaiseStatus();
            try
            {
                var hosts = App.Settings.TestHosts.ToList();
                var eng = App.Engine;
                bool running = eng.State == EngineState.Running;
                var prof = running ? eng.ActiveProfile : null;
                string main = Domains.HostOf(hosts.FirstOrDefault() ?? "discord.com");

                // DNS check and HTTPS test in parallel
                // the same verdict as the scanner: system DNS against DNS over HTTPS (different public CDN answers are normal)
                var dnsTask = Task.Run(async () =>
                {
                    try { return (await DnsComparison.CheckAsync(main, new ProbeEnv(), System.Threading.CancellationToken.None)).Ok; }
                    catch (Exception ign) { App.Ignored("DNS check", ign); return (bool?)null; }
                });
                var res = await NetTest.TestManyAsync(hosts);
                bool? dnsOk = await dnsTask;

                App.LastTest = res;
                App.LastTestTime = DateTime.Now;
                App.LastDnsOk = dnsOk;
                History.Add(new HistoryEntry
                {
                    Time = DateTime.Now, Kind = "test", Profile = (prof ?? App.SelectedProfile)?.Name ?? "", Running = running,
                    Ok = res.Count(r => r.Ok), Total = res.Count, DnsOk = dnsOk,
                    Ms = res.Any(r => r.Ok) ? (int)res.Where(r => r.Ok).Average(r => r.Ms) : 0,
                    Note = string.Join(", ", res.Where(r => !r.Ok).Select(r => r.Host + " " + r.Code)),
                });
                int ok = res.Count(r => r.Ok);
                App.Log("Connection test: " + ok + "/" + res.Count + " site(s) reachable" +
                        (dnsOk == true ? ", DNS correct." : dnsOk == false ? ", DNS WRONG." : "."),
                    ok == res.Count ? LogLevel.Success : ok == 0 ? LogLevel.Error : LogLevel.Warn);
                foreach (var r in res.Where(r => !r.Ok)) App.Log("   " + r.Host + ": " + r.DetailEnglish + " [" + r.Code + "]", LogLevel.Warn);

                // DNS problems
                if (dnsOk == false)
                {
                    if (running && prof != null && prof.UsesDnsRedirect) App.Problems.Report("NSF-403", main);
                    else if (running) App.Problems.Report("NSF-401", new LocText("actions.dnsNotRedirected"));
                }
                else if (dnsOk == true) { App.Problems.Clear("NSF-403"); App.Problems.Clear("NSF-401"); }

                // Access problems (only meaningful while protection is on)
                var accessCodes = new[] { "NSF-501", "NSF-502", "NSF-503", "NSF-504", "NSF-505", "NSF-506" };
                foreach (var c in accessCodes) App.Problems.Clear(c);
                if (running && ok < res.Count)
                {
                    var fails = res.Where(r => !r.Ok).ToList();
                    string code;
                    if (App.Settings.TargetedMode && fails.Any(f => !Domains.Covered(f.Host, App.Settings.TargetDomains))) code = "NSF-506";
                    else if (ok > 0) code = "NSF-505";
                    else code = fails.GroupBy(f => f.Code).OrderByDescending(g => g.Count()).First().Key;
                    if (code != "NSF-401") App.Problems.Report(code, string.Join(", ", fails.Select(f => f.Host)));
                }

                if (notifyOnFail && ok < res.Count && running && !eng.Quiet)
                    App.Notify(Loc.T("actions.accessProblem.title"),
                        Loc.T("actions.accessProblem.text", res.Count - ok),
                        ToolTipIcon.Warning);

                // If Discord was opened before protection, suggest restarting it
                if (running && ok == res.Count && App.Settings.SuggestDiscordRestart && eng.StartedAt.HasValue && !eng.Quiet)
                {
                    if (DiscordHelper.StartedBefore(eng.StartedAt.Value))
                    {
                        App.Problems.Report("NSF-901");
                        if (discordHintFor != eng.StartedAt)
                        {
                            discordHintFor = eng.StartedAt;
                            App.Notify(Loc.T("actions.restartDiscord.title"),
                                Loc.T("actions.restartDiscord.text"), ToolTipIcon.Info);
                        }
                    }
                    else App.Problems.Clear("NSF-901");
                }
                return res;
            }
            finally
            {
                Testing = false;
                App.RaiseStatus();
            }
        }

        public static async Task<string> RestartDiscordAsync()
        {
            string msg = null;
            await Task.Run(() => DiscordHelper.Restart(out msg));
            return msg;
        }
    }
}
