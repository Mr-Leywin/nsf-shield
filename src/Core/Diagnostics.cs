using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;

namespace NSFShield
{
    public enum CheckStatus { Ok, Info, Warn, Fail, Skip }

    public sealed class CheckItem
    {
        /// <summary>string or <see cref="LocText"/> (rendered in the current UI language).</summary>
        public object TitleValue, DetailValue;
        public string Code = "";
        public CheckStatus Status;
        public string Title { get => TitleValue?.ToString() ?? ""; set => TitleValue = value; }
        public string Detail { get => DetailValue?.ToString() ?? ""; set => DetailValue = value; }
    }

    /// <summary>"Find problems" check: checks everything in order, from the installation to Discord.</summary>
    public static class Diagnostics
    {
        static LocText L(string key, params object[] args) => new LocText(key, args);

        /// <summary>A list of texts that renders in the current language ("a; b; c").</summary>
        public static LocText JoinL(IList<LocText> items)
        {
            if (items.Count == 0) return L("diag.none");
            var acc = items[items.Count - 1];
            for (int i = items.Count - 2; i >= 0; i--) acc = L("diag.listJoin", items[i], acc);
            return acc;
        }

        /// <summary>"kernel driver · running · …\folder\file.sys (this installation)" – or why the entry could not be read.</summary>
        public static LocText EntryText(ServiceFinding f)
        {
            var e = f.E;
            if (e.Read != ScmRead.Ok) return L("diag.scm.entryUnreadable", e.Name, L(e.StateKey));
            string file = DriverControl.DriverFile(e.ImagePath);
            object where = file == null ? (object)L("diag.scm.pathUnknown")
                         : f.Product == "WinDivert" ? L(f.InOurFolder ? "diag.scm.ours" : "diag.scm.otherFolder", Conflicts.ShortPath(file)) : (object)Conflicts.ShortPath(file);
            return L("diag.scm.entry", f.Product, e.Name, L(e.TypeKey), L(e.StateKey), where);
        }

        /// <summary>One line of an anti-cheat entry: an active kernel driver, an installed driver, a user-mode service, or "not checked".</summary>
        public static LocText AntiCheatText(ServiceFinding f)
        {
            if (f.Unreadable) return L("diag.anticheat.unreadable", f.Product, f.E.Name, L(f.E.StateKey));
            if (f.ActiveDriver) return L("diag.anticheat.activeDriver", f.Product, f.E.Name);
            if (f.E.IsDriver) return L("diag.anticheat.driverInstalled", f.Product, f.E.Name, L(f.E.StateKey));
            return L("diag.anticheat.userService", f.Product, f.E.Name, L(f.E.StateKey));
        }

        /// <summary>The VPN finding: an Up virtual adapter, a running product service and the route are separate facts.</summary>
        public static (CheckStatus Status, LocText Text) VpnText(ConflictReport r)
        {
            var parts = new List<LocText>();
            var names = string.Join(", ", r.VpnAdapters.Select(a => a.Description ?? a.Name));
            CheckStatus st = CheckStatus.Ok;
            if (r.VpnAdapters.Count > 0)
            {
                if (r.VpnRoute == true) { parts.Add(L("diag.vpn.route", r.VpnRouteAdapter)); st = CheckStatus.Warn; }
                else if (r.VpnRoute == false) { parts.Add(L("diag.vpn.upNoRoute", names)); st = CheckStatus.Info; }
                else { parts.Add(L("diag.vpn.upRouteUnknown", names)); st = CheckStatus.Info; }
            }
            foreach (var s in r.VpnServices)
            {
                if (s.Unreadable) parts.Add(L("diag.vpn.serviceUnreadable", s.Product, s.E.Name));
                else if (s.E.Running) parts.Add(L("diag.vpn.serviceRunning", s.Product));
                if (st == CheckStatus.Ok && (s.Unreadable || s.E.Running)) st = CheckStatus.Info;
            }
            return parts.Count == 0 ? (CheckStatus.Ok, L("diag.vpn.none")) : (st, JoinL(parts));
        }

        static LocText ProcList(IEnumerable<ProcFinding> list) => JoinL(list.Select(f => L("diag.owner.item", f.P.Name, f.P.Pid, f.Why)).ToList());

        /// <summary>
        /// The Find Problems rows of the conflict diagnosis (the home page card reads the same report): WinDivert programs, the old
        /// service, other DPI tools, WinDivert driver entries, anti-cheat, the information card and VPN/WARP.
        /// </summary>
        public static List<(LocText Title, CheckStatus Status, LocText Detail, string Code)> ConflictItems(ConflictReport cr, bool legacyService)
        {
            var l = new List<(LocText, CheckStatus, LocText, string)>();
            if (cr.Deferred) l.Add((L("diag.conflict.title"), CheckStatus.Skip, L("diag.conflict.deferred"), ""));
            else
            {
                var drv = cr.Foreign(true).ToList();
                var mine = cr.Processes.Where(p => p.DriverTool && (p.Owner == ProcOwner.Own || p.Owner == ProcOwner.ScanCandidate)).ToList();
                l.Add((L("diag.conflict.title"), drv.Count > 0 ? CheckStatus.Warn : CheckStatus.Ok,
                       drv.Count > 0 ? L("diag.conflict.list", drv.Count, ProcList(drv)) : mine.Count > 0 ? L("diag.conflict.onlyOwn", ProcList(mine)) : L("diag.none"), "NSF-301"));
            }
            l.Add((L("diag.legacyService.title"), legacyService ? CheckStatus.Warn : CheckStatus.Ok, legacyService ? L("diag.legacyService.found") : L("diag.none"), "NSF-302"));
            if (cr.Deferred) return l;
            var other = cr.Foreign(false).ToList();
            l.Add((L("diag.otherDpi.title"), other.Count > 0 ? CheckStatus.Warn : CheckStatus.Ok, other.Count > 0 ? L("diag.otherDpi.found", ProcList(other)) : L("diag.none"), "NSF-303"));
            // WinDivert driver entries (every entry found is listed; read only)
            l.Add((L("diag.windivert.title"), cr.WinDivert.Any(w => w.Unreadable) ? CheckStatus.Info : CheckStatus.Ok,
                   cr.WinDivert.Count == 0 ? L("diag.windivert.none") : JoinL(cr.WinDivert.Select(EntryText).ToList()), ""));
            // anti-cheat: an active kernel driver needs the driver type AND the running state; "access denied" is never "not found"
            l.Add((L("diag.anticheat.title"), cr.AntiCheat.Count == 0 ? CheckStatus.Ok : CheckStatus.Info,
                   cr.AntiCheat.Count == 0 ? L("diag.anticheat.none") : JoinL(cr.AntiCheat.Select(AntiCheatText).ToList()), ""));
            if (cr.Notice != null) l.Add((cr.Notice.Title, CheckStatus.Info, cr.Notice.Text, ""));
            var (vst, vtext) = VpnText(cr);
            l.Add((L("diag.vpn.title"), vst, vtext, vst == CheckStatus.Info ? "" : "NSF-304"));
            return l;
        }

        public static List<string> Antivirus()
        {
            var list = new List<string>();
            try
            {
                using (var q = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT displayName FROM AntiVirusProduct"))
                    foreach (ManagementObject mo in q.Get())
                        using (mo)
                        {
                            string n = mo["displayName"] as string;
                            if (!string.IsNullOrEmpty(n) && !list.Contains(n)) list.Add(n);
                        }
            }
            catch (Exception ign) { App.Ignored("Antivirus information could not be read", ign); }
            return list;
        }

        /// <summary>
        /// DPI tools that are not this app's (another copy, a script, another program). A folder prefix is not proof: the exact
        /// executable path and the PID of this app's engine, its service or a scan candidate are; unreadable ones are listed too.
        /// </summary>
        public static List<string> RunningOtherDpi()
        {
            var src = Conflicts.Source;
            var ctx = src.Context();
            return src.Processes(Conflicts.DriverTools.Concat(Conflicts.OtherTools))
                      .Select(p => (p, o: Conflicts.Classify(p, ctx, out var why), why))
                      .Where(x => x.o == ProcOwner.OtherInstall || x.o == ProcOwner.Unknown)
                      .Select(x => L("diag.owner.item", x.p.Name, x.p.Pid, x.why).Text).ToList();
        }

        public static async Task<List<CheckItem>> RunAsync(Action<CheckItem> onItem)
        {
            var items = new List<CheckItem>();
            void Add(LocText title, CheckStatus st, LocText detail, string code = "")
            {
                var it = new CheckItem { TitleValue = title, Status = st, DetailValue = detail, Code = code };
                items.Add(it);
                if (!string.IsNullOrEmpty(code) && (st == CheckStatus.Fail || st == CheckStatus.Warn)) App.Problems.Report(code, detail);
                else if (!string.IsNullOrEmpty(code) && st == CheckStatus.Ok) App.Problems.Clear(code);
                App.Post(() => onItem?.Invoke(it));
            }
            var eng = App.Engine;

            // ------------------------------------------------ app
            bool admin = App.IsAdmin();
            Add(L("diag.admin.title"), admin ? CheckStatus.Ok : CheckStatus.Fail,
                admin ? L("diag.admin.ok") : L("diag.admin.fail"), "NSF-101");

            bool temp = App.RunningFromTemp;
            Add(L("diag.folder.title"), temp ? CheckStatus.Warn : CheckStatus.Ok,
                temp ? L("diag.folder.temp", App.BaseDir) : L("engine.raw", App.BaseDir), "NSF-103");

            // the engine in use must be complete and official; the other engines are reported without an error code
            var cur = App.Engine.Current;
            string missing = Engine.MissingFile(cur);
            Add(L("diag.files.title"), missing == null ? CheckStatus.Ok : CheckStatus.Fail,
                missing == null ? L("diag.files.okEngine", cur.DisplayName) : L("diag.files.missing", missing), "NSF-102");
            if (missing == null)
                using (var held = Integrity.VerifyAndLock(Engines.BinRoot, cur.VerifiedFiles, out string intErr))
                    Add(L("diag.integrity.title"), held != null ? CheckStatus.Ok : CheckStatus.Fail,
                        held != null ? L("diag.integrity.okEngine", cur.DisplayName) : L("engine.raw", intErr), "NSF-105");
            foreach (var oe in Engines.All.Where(x => x.Kind != cur.Kind && x.Available(out _)))
            {
                string m2 = Engine.MissingFile(oe);
                string e2 = "";
                bool good = m2 == null;
                if (good) using (var h2 = Integrity.VerifyAndLock(Engines.BinRoot, oe.VerifiedFiles, out e2)) good = h2 != null;
                Add(L("diag.otherEngine.title", oe.DisplayName), good ? CheckStatus.Ok : CheckStatus.Info,
                    good ? L("diag.integrity.okEngine", oe.DisplayName) : L("diag.otherEngine.problem", m2 != null ? L("diag.files.missing", m2).Text : e2));
            }
            bool prot = InstallGuard.Evaluate(true);
            Add(L("diag.installType.title"), prot ? CheckStatus.Ok : CheckStatus.Info,
                prot ? L("diag.installType.installed")
                     : L("diag.installType.portable", InstallGuard.Reason));

            await Task.Run(() =>
            {
                string bfe = "";
                bool bfeOk = false;
                try { using (var sc = new ServiceController("BFE")) { bfeOk = sc.Status == ServiceControllerStatus.Running; bfe = sc.Status.ToString(); } }
                catch (Exception ex) { bfe = ex.Message; }
                Add(L("diag.bfe.title"), bfeOk ? CheckStatus.Ok : CheckStatus.Fail, bfeOk ? L("diag.running") : L("diag.bfe.notRunning", bfe), "NSF-205");
            });

            // ------------------------------------------------ conflicts: the same read-only diagnosis the home page shows
            await Task.Run(() => eng.Poll());
            var cr = await Conflicts.RefreshAsync();
            foreach (var (title, st, detail, code) in ConflictItems(cr, eng.LegacyServiceExists)) Add(title, st, detail, code);
            if (!cr.Deferred && VpnText(cr).Status == CheckStatus.Info) App.Problems.Clear("NSF-304");

            var adapters = await Task.Run(() => NetTest.Adapters());
            var proxy = NetTest.SystemProxy();
            var ourProxy = ProxyTools.ActiveSystemEntry();
            if (ourProxy != null)
                Add(L("diag.proxy.title"), CheckStatus.Info, L("diag.proxy.ours", ourProxy.Title, proxy.Server));
            else
                Add(L("diag.proxy.title"), proxy.Enabled ? CheckStatus.Warn : CheckStatus.Ok, proxy.Enabled ? L("diag.proxy.on", proxy.Server) : L("diag.off"), "NSF-802");

            var av = await Task.Run(() => Antivirus());
            var thirdParty = av.Where(n => n.IndexOf("Windows Defender", StringComparison.OrdinalIgnoreCase) < 0 &&
                                           n.IndexOf("Microsoft Defender", StringComparison.OrdinalIgnoreCase) < 0).ToList();
            Add(L("diag.av.title"), thirdParty.Count > 0 ? CheckStatus.Info : CheckStatus.Ok,
                av.Count == 0 ? L("diag.av.unknown") : L(thirdParty.Count > 0 ? "diag.av.listThirdParty" : "engine.raw", string.Join(", ", av)), "NSF-207");
            if (thirdParty.Count > 0) App.Problems.Clear("NSF-207");

            // ------------------------------------------------ network
            int inetMs = 0;
            bool inet = await Task.Run(() => NetTest.InternetOk(out inetMs));
            Add(L("diag.internet.title"), inet ? CheckStatus.Ok : CheckStatus.Fail, inet ? L("diag.internet.ok", inetMs) : L("diag.internet.fail"), "NSF-801");

            var skew = await Task.Run(() => NetTest.ClockSkewMinutes());
            if (skew.HasValue)
                Add(L("diag.clock.title"), skew.Value > 5 ? CheckStatus.Fail : CheckStatus.Ok,
                    skew.Value > 5 ? L("diag.clock.skewed", Math.Round(skew.Value)) : L("diag.correct"), "NSF-803");
            else
                Add(L("diag.clock.title"), CheckStatus.Skip, L("diag.notMeasured"));

            var hosts = NetTest.HostsDiscordLines();
            Add(L("diag.hosts.title"), hosts.Count > 0 ? CheckStatus.Warn : CheckStatus.Ok,
                hosts.Count > 0 ? L("diag.hosts.found", hosts.Count, string.Join(" | ", hosts.Take(3))) : L("diag.hosts.none"), "NSF-405");

            // ------------------------------------------------ DNS
            bool running = eng.State == EngineState.Running;
            var prof = running ? eng.ActiveProfile : App.SelectedProfile;
            if (inet)
            {
                var rep = await Task.Run(() => { Native.FlushDns(); return NetTest.CheckDns("discord.com"); });
                if (rep.Reference.Count == 0)
                    Add(L("diag.dns.title"), CheckStatus.Skip, L("diag.dns.noReference"));
                else if (running && prof != null && prof.UsesDnsRedirect)
                    Add(L("diag.dns.titleOn"), rep.Blocked ? CheckStatus.Fail : CheckStatus.Ok,
                        rep.Blocked ? L("diag.dns.wrongDespite", string.Join(", ", rep.System.Take(2))) : L("diag.dns.correctAddress", rep.System.FirstOrDefault()), "NSF-403");
                else
                    Add(running ? L("diag.dns.titleNoRedirect") : L("diag.dns.titleOff"), rep.Blocked ? CheckStatus.Warn : CheckStatus.Ok,
                        rep.Blocked ? L("diag.dns.blocked") : L("diag.dns.systemOk"), "NSF-401");

                var target = prof?.DnsTarget;
                if (prof != null && target != null && System.Net.IPAddress.TryParse(target.Value.Addr, out _))
                {
                    var r = await Task.Run(() => NetTest.TimedQuery("discord.com", target.Value.Addr, target.Value.Port, 2500));
                    Add(L("diag.redirectDns.title"), r.Ok ? CheckStatus.Ok : CheckStatus.Fail,
                        L(r.Ok ? "diag.redirectDns.ok" : "diag.redirectDns.fail", target.Value.Addr + ":" + target.Value.Port, r.Ms), "NSF-402");
                }
                bool v6 = adapters.Any(a => a.HasGlobalV6 && !a.IsVpn);
                if (v6 && prof != null && prof.UsesDnsRedirect && !prof.UseRaw && prof.Dns == DnsChoice.Custom && string.IsNullOrWhiteSpace(prof.CustomDns6))
                    Add(L("diag.ipv6.title"), CheckStatus.Warn, L("diag.ipv6.notRedirected"), "NSF-404");
                else
                    Add(L("diag.ipv6.title"), CheckStatus.Ok, v6 ? L("diag.ipv6.redirected") : L("diag.ipv6.none"), "NSF-404");
            }

            // ------------------------------------------------ protection
            if (eng.State == EngineState.Error)
                Add(L("diag.protection.title"), CheckStatus.Fail, L("diag.protection.error", eng.LastError), eng.LastErrorCode);
            else if (running)
                Add(L("diag.protection.title"), CheckStatus.Ok, L("diag.protection.running", prof?.Name + (eng.RunningAsService ? Loc.T("diag.protection.serviceSuffix") : "")));
            else
                Add(L("diag.protection.title"), CheckStatus.Warn, L("diag.protection.off"));

            if (eng.ServiceInstalled)
            {
                bool elsewhere = await Task.Run(() => Engine.ServicePointsElsewhere());
                Add(L("diag.service.title"), elsewhere ? CheckStatus.Warn : CheckStatus.Ok,
                    elsewhere ? L("diag.service.elsewhere") : L("diag.service.ok"), "NSF-704");
            }

            // ------------------------------------------------ discord
            if (inet)
            {
                var res = await Actions.QuickTestAsync();
                if (res != null)
                {
                    int ok = res.Count(x => x.Ok);
                    var fails = res.Where(x => !x.Ok).ToList();
                    string code = "";
                    if (fails.Count > 0)
                    {
                        if (App.Settings.TargetedMode && fails.Any(f => !Domains.Covered(f.Host, App.Settings.TargetDomains))) code = "NSF-506";
                        else if (ok > 0) code = "NSF-505";
                        else code = fails.GroupBy(f => f.Code).OrderByDescending(g => g.Count()).First().Key;
                    }
                    Add(L("diag.discord.title"), ok == res.Count ? CheckStatus.Ok : ok == 0 ? CheckStatus.Fail : CheckStatus.Warn,
                        L(fails.Count > 0 ? "diag.discord.partial" : "diag.discord.all", ok, res.Count, string.Join(", ", fails.Select(f => f.Host + " (" + f.Detail + ")"))),
                        code);
                }
            }
            bool dRunning = DiscordHelper.IsRunning;
            if (dRunning && running && eng.StartedAt.HasValue && DiscordHelper.StartedBefore(eng.StartedAt.Value))
                Add(L("diag.discordApp.title"), CheckStatus.Info, L("diag.discordApp.before"), "NSF-901");
            else
                Add(L("diag.discordApp.title"), CheckStatus.Ok, dRunning ? L("diag.open") : L("diag.closed"));

            return items;
        }
    }

    /// <summary>Exports the profiles as standalone .cmd scripts.</summary>
    public static class Scripts
    {
        public static string Ascii(string s)
        {
            var map = new Dictionary<char, string>
            {
                ['\u00e7'] = "c", ['\u00c7'] = "C", ['\u011f'] = "g", ['\u011e'] = "G", ['\u0131'] = "i", ['\u0130'] = "I", ['\u00f6'] = "o", ['\u00d6'] = "O",
                ['\u015f'] = "s", ['\u015e'] = "S", ['\u00fc'] = "u", ['\u00dc'] = "U", ['–'] = "-", ['—'] = "-", ['’'] = "'", ['…'] = "...", ['→'] = "->", ['·'] = "-",
            };
            var sb = new StringBuilder();
            foreach (char c in s ?? "")
            {
                if (map.TryGetValue(c, out var r)) sb.Append(r);
                else if (c < 128) sb.Append(c);
            }
            return sb.ToString();
        }

        public static string Slug(string s)
        {
            var a = Ascii(s).ToLowerInvariant();
            var sb = new StringBuilder();
            foreach (char c in a)
                sb.Append(char.IsLetterOrDigit(c) ? c : '_');
            return string.Join("_", sb.ToString().Split(new[] { '_' }, StringSplitOptions.RemoveEmptyEntries));
        }

        static IEnumerable<string> Wrap(string text, int width)
        {
            var words = text.Split(' ');
            var line = new StringBuilder();
            foreach (var w in words)
            {
                if (line.Length + w.Length + 1 > width && line.Length > 0) { yield return line.ToString(); line.Clear(); }
                if (line.Length > 0) line.Append(' ');
                line.Append(w);
            }
            if (line.Length > 0) yield return line.ToString();
        }

        /// <summary>A translated text made safe for REM/echo lines of a .cmd script (ASCII, no special characters).</summary>
        static string CmdText(string key, params object[] args) => CmdLine.RemText(Ascii(Loc.T(key, args)));

        /// <param name="binRef">goodbyedpi folder; if relative, relative to the script's location (%~dp0).</param>
        /// <summary>
        /// Builds a .cmd script for a profile. If the parameters do not pass the allow list no script is built (no command can be injected);
        /// the name and description are written to REM lines with safe characters only (no line break can be added).
        /// </summary>
        public static string Build(Profile p, string binRef)
        {
            if (!p.IsGoodbyeDpi)
                throw new InvalidDataException(Loc.T("scripts.goodbyeDpiOnly", CmdLine.RemText(Ascii(p.Name))));
            if (!ArgPolicy.ValidateProfile(p, out string argErr))
                throw new InvalidDataException(Loc.T("scripts.unsafeProfile", CmdLine.RemText(Ascii(p.Name)), argErr));
            if (!CmdLine.QuotedSafe(binRef))
                throw new InvalidDataException(Loc.T("scripts.unsafePath"));
            var sb = new StringBuilder();
            sb.AppendLine("@ECHO OFF");
            sb.AppendLine("REM ================================================================");
            sb.AppendLine("REM  NSF Shield - " + CmdText("scripts.method", p.Name));
            foreach (var l in Wrap(CmdLine.RemText(Ascii(p.Description)), 62)) sb.AppendLine("REM  " + l);
            sb.AppendLine("REM  " + CmdText("scripts.dnsRedirect", p.DnsLabel));
            sb.AppendLine("REM  " + CmdText("scripts.usage1"));
            sb.AppendLine("REM  " + CmdText("scripts.usage2"));
            sb.AppendLine("REM  " + CmdText("scripts.usage3"));
            sb.AppendLine("REM ================================================================");
            sb.AppendLine("PUSHD \"%~dp0\"");
            sb.AppendLine("set _arch=x86");
            sb.AppendLine("IF \"%PROCESSOR_ARCHITECTURE%\"==\"AMD64\" (set _arch=x86_64)");
            sb.AppendLine("IF DEFINED PROCESSOR_ARCHITEW6432 (set _arch=x86_64)");
            sb.AppendLine("PUSHD \"" + binRef + "\\%_arch%\"");
            sb.AppendLine("start \"\" goodbyedpi.exe " + p.BuildArgs(null));
            sb.AppendLine("POPD");
            sb.AppendLine("POPD");
            return sb.ToString();
        }

        public static void Write(Profile p, string path, string binRef) =>
            File.WriteAllText(path, Build(p, binRef).Replace("\n", "\r\n").Replace("\r\r\n", "\r\n"), Encoding.ASCII);

        public const string StopScript = "stop.cmd", ResetScript = "reset.cmd", ReadmeFile = "README.txt";

        public static void ExportAll(string dir)
        {
            Directory.CreateDirectory(dir);
            int i = 0;
            // the scripts run goodbyedpi.exe directly; Zapret and ByeDPI are started by the app only
            foreach (var p in Profiles.BuiltIns.Where(x => x.IsGoodbyeDpi))
            {
                i++;
                string name = i.ToString("00") + "_" + Slug(p.Name) + ".cmd";
                Write(p, Path.Combine(dir, name), "..\\bin");
            }
            // Administrator rights are not forced from inside the script (no script interpreter is used): the user is asked to right-click → Run as administrator
            string needAdmin = "net session >NUL 2>&1 || (echo " + CmdText("scripts.needAdmin") + " & pause & exit /b 1)\r\n";
            File.WriteAllText(Path.Combine(dir, StopScript),
                "@ECHO OFF\r\nREM " + CmdText("scripts.stop.rem") + "\r\n" + needAdmin +
                "taskkill /F /IM goodbyedpi.exe\r\npause\r\n", Encoding.ASCII);
            File.WriteAllText(Path.Combine(dir, ResetScript),
                "@ECHO OFF\r\nREM " + CmdText("scripts.reset.rem") + "\r\n" + needAdmin +
                "taskkill /F /IM goodbyedpi.exe >NUL 2>&1\r\n" +
                "for %%s in (GoodbyeDPI NSFShield WinDivert WinDivert14) do (sc stop %%s >NUL 2>&1 & sc delete %%s >NUL 2>&1)\r\n" +
                "ipconfig /flushdns >NUL\r\necho " + CmdText("scripts.reset.done") + "\r\npause\r\n", Encoding.ASCII);
            var readme = new StringBuilder();
            string title = Ascii(Loc.T("scripts.readme.title"));
            readme.AppendLine(title);
            readme.AppendLine(new string('=', title.Length));
            readme.AppendLine();
            foreach (var l in Wrap(Ascii(Loc.T("scripts.readme.intro")), 72)) readme.AppendLine(l);
            readme.AppendLine();
            readme.AppendLine(Ascii(Loc.T("scripts.readme.usage")));
            for (int k = 1; k <= 4; k++) readme.AppendLine("  " + k + ") " + Ascii(Loc.T("scripts.readme.step" + k)));
            readme.AppendLine();
            foreach (var l in Wrap(Ascii(Loc.T("scripts.readme.order")), 72)) readme.AppendLine(l);
            readme.AppendLine();
            i = 0;
            foreach (var p in Profiles.BuiltIns.Where(x => x.IsGoodbyeDpi))
            {
                i++;
                readme.AppendLine(i.ToString("00") + "  " + Ascii(p.Name));
                foreach (var l in Wrap(Ascii(p.Description), 70)) readme.AppendLine("    " + l);
            }
            readme.AppendLine();
            readme.AppendLine(StopScript + "  : " + Ascii(Loc.T("scripts.readme.stop")));
            readme.AppendLine(ResetScript + " : " + Ascii(Loc.T("scripts.readme.reset")));
            File.WriteAllText(Path.Combine(dir, ReadmeFile), readme.ToString().Replace("\n", "\r\n").Replace("\r\r\n", "\r\n"), Encoding.ASCII);
        }
    }
}
