using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace NSFShield
{
    /// <summary>The bypass engines NSF Shield can run. Only one runs at a time; the selected profile decides which.</summary>
    public enum EngineKind { GoodbyeDpi, Zapret, ByeDpi }

    /// <summary>The managed domain lists given to an engine for one start (full paths; null = the list is not used).</summary>
    public sealed class ListBinding
    {
        public string Include, Exclude;
        /// <summary>ByeDPI: the SOCKS port to listen on (0 = the port from the settings); a scan trial passes its own.</summary>
        public int Port;
        public static readonly ListBinding None = new ListBinding();
        /// <summary>Short names shown in previews instead of full paths.</summary>
        public static ListBinding Display(bool include, bool exclude) => new ListBinding
        {
            Include = include ? @"…\lists\" + Hostlists.IncludeName : null,
            Exclude = exclude ? @"…\lists\" + Hostlists.ExcludeName : null,
        };

        /// <summary>The same list files (paths compared case-insensitively; null only matches null).</summary>
        public bool SameFiles(ListBinding o) =>
            o != null && string.Equals(Include, o.Include, StringComparison.OrdinalIgnoreCase) && string.Equals(Exclude, o.Exclude, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// One bypass engine: its files, the allow list of its parameters, its command line and its console messages.
    /// <see cref="Engine"/> runs whichever engine the selected profile belongs to.
    /// </summary>
    public interface IDpiEngine
    {
        EngineKind Kind { get; }
        /// <summary>Stable id ("goodbyedpi", "zapret", "byedpi"): locale keys, logs.</summary>
        string Id { get; }
        /// <summary>Name shown in the UI: "GoodbyeDPI", "Zapret (winws)", "ByeDPI (ciadpi)".</summary>
        string DisplayName { get; }
        string ProcessName { get; }
        string ExeName { get; }
        /// <summary>Folder of the engine files (bin\x86_64, bin\zapret, bin\byedpi).</summary>
        string BinDir { get; }
        string ExePath { get; }
        /// <summary>Files checked against the embedded SHA-256 before every start, relative to bin\ (e.g. zapret\winws.exe).</summary>
        IReadOnlyList<string> VerifiedFiles { get; }
        /// <summary>Loads the WinDivert kernel driver.</summary>
        bool UsesDriver { get; }
        /// <summary>Full path of the driver file it loads (null if none).</summary>
        string DriverPath { get; }
        /// <summary>Can run as the SYSTEM background service (protected installation only).</summary>
        bool SupportsService { get; }
        bool SupportsInclude { get; }
        bool SupportsExclude { get; }
        /// <summary>Local port the engine listens on (127.0.0.1); 0 = none. Readiness is checked on this port.</summary>
        int ListenPort { get; }
        bool Available(out LocText reason);
        /// <summary>Checks the profile's parameters against this engine's allow list.</summary>
        bool Validate(Profile p, out string error);
        /// <summary>Command line arguments; with <paramref name="display"/> short names are used instead of full paths.</summary>
        string BuildArgs(Profile p, ListBinding lists, bool display = false);
        /// <summary>
        /// What the bound lists cannot cover in this profile (the same analysis <see cref="BuildArgs"/> uses, so the preview
        /// and the start agree). <paramref name="blocked"/>: targeted mode would leave no rule – the start must stop.
        /// </summary>
        List<LocText> ScopeNotes(Profile p, ListBinding lists, out bool blocked);
        bool IsReady(string output);
        bool LooksLikeError(string output);
        (string Code, LocText Hint) Diagnose(string output);
    }

    public static class Engines
    {
        public static readonly IDpiEngine GoodbyeDpi = new GoodbyeDpiEngine();
        public static readonly IDpiEngine Zapret = new ZapretEngine();
        public static readonly IDpiEngine ByeDpi = new ByeDpiEngine();
        public static readonly IReadOnlyList<IDpiEngine> All = new[] { GoodbyeDpi, Zapret, ByeDpi };

        public static IDpiEngine Get(EngineKind k) => k == EngineKind.Zapret ? Zapret : k == EngineKind.ByeDpi ? ByeDpi : GoodbyeDpi;
        public static IDpiEngine Of(Profile p) => Get(p?.Engine ?? EngineKind.GoodbyeDpi);

        public static string BinRoot => Path.Combine(App.BaseDir, "bin");

        /// <summary>Processes of the engines that load WinDivert (two of them must not run at the same time).</summary>
        public static readonly string[] DriverProcessNames = { "goodbyedpi", "winws" };
        public static readonly string[] AllProcessNames = { "goodbyedpi", "winws", "ciadpi" };

        /// <summary>
        /// Joins arguments into a command line. Only tokens with spaces are quoted (CommandLineToArgvW and Cygwin's Windows
        /// rules); the allow lists never let quotes, glob characters or trailing backslashes through.
        /// </summary>
        public static string Join(IEnumerable<string> argv) => string.Join(" ", argv.Select(Quote));
        public static string Quote(string a) => a.Length > 0 && a.IndexOfAny(new[] { ' ', '\t', '"' }) < 0 ? a : Engine.Esc(a);

        /// <summary>The tokens of a command line (double quotes group; the quotes are removed).</summary>
        internal static List<string> CommandTokens(string command)
        {
            var list = new List<string>();
            var cur = new System.Text.StringBuilder();
            bool quoted = false, any = false;
            foreach (char c in command ?? "")
            {
                if (c == '"') { quoted = !quoted; any = true; continue; }
                if (!quoted && (c == ' ' || c == '\t')) { if (any || cur.Length > 0) list.Add(cur.ToString()); cur.Clear(); any = false; continue; }
                cur.Append(c);
            }
            if (any || cur.Length > 0) list.Add(cur.ToString());
            return list;
        }

        /// <summary>Splits stored parameters on spaces, tabs and line breaks.</summary>
        public static List<string> Tokens(string s) =>
            (s ?? "").Split(new[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).ToList();

        public static LocText Unavailable64(IDpiEngine e) => new LocText("engines.only64", e.DisplayName);

        /// <summary>Zapret and ByeDPI ship x64 binaries only (the self-test replaces this to check the filter of a 32-bit Windows).</summary>
        internal static Func<bool> Is64BitOs = () => Environment.Is64BitOperatingSystem;
    }

    // ================================================================================== GoodbyeDPI

    sealed class GoodbyeDpiEngine : IDpiEngine
    {
        /// <summary>GoodbyeDPI applies its one --blacklist to all of its work (no rule groups).</summary>
        public List<LocText> ScopeNotes(Profile p, ListBinding lists, out bool blocked) { blocked = false; return new List<LocText>(); }

        public EngineKind Kind => EngineKind.GoodbyeDpi;
        public string Id => "goodbyedpi";
        public string DisplayName => "GoodbyeDPI";
        public string ProcessName => "goodbyedpi";
        public string ExeName => "goodbyedpi.exe";
        public string BinDir => Engine.BinDir;
        public string ExePath => Engine.ExePath;
        public IReadOnlyList<string> VerifiedFiles => Engine.RequiredFiles.Select(f => Engine.Arch + "\\" + f).ToList();
        public bool UsesDriver => true;
        public string DriverPath => Path.Combine(BinDir, Environment.Is64BitOperatingSystem ? "WinDivert64.sys" : "WinDivert32.sys");
        public bool SupportsService => true;
        public bool SupportsInclude => true;
        /// <summary>GoodbyeDPI 0.2.3rc3 only has --blacklist (apply only to these); there is no exclude list.</summary>
        public bool SupportsExclude => false;
        public int ListenPort => 0;
        public bool Available(out LocText reason) { reason = null; return true; }

        public bool Validate(Profile p, out string error)
        {
            if (p == null) { error = Loc.T("args.noProfile"); return false; }
            if (p.Engine != EngineKind.GoodbyeDpi) { error = Loc.T("engines.wrongEngine", DisplayName); return false; }
            return ArgPolicy.Validate(p.BuildArgs(null), out error);
        }

        public string BuildArgs(Profile p, ListBinding lists, bool display = false) => p.BuildArgs(lists?.Include);

        public bool IsReady(string output) => (output ?? "").Contains("Filter activated");
        public bool LooksLikeError(string output) => Engine.LooksLikeGoodbyeDpiError(output ?? "");
        public (string Code, LocText Hint) Diagnose(string output) => Engine.Diagnose(output);
    }

    // ================================================================================== Zapret (winws)

    sealed class ZapretEngine : IDpiEngine
    {
        public EngineKind Kind => EngineKind.Zapret;
        public string Id => "zapret";
        public string DisplayName => "Zapret (winws)";
        public string ProcessName => "winws";
        public string ExeName => "winws.exe";
        public string BinDir => Path.Combine(Engines.BinRoot, "zapret");
        public string ExePath => Path.Combine(BinDir, ExeName);
        public static string PayloadDir => Path.Combine(Engines.BinRoot, "zapret", "payloads");

        public IReadOnlyList<string> VerifiedFiles =>
            new[] { @"zapret\winws.exe", @"zapret\cygwin1.dll", @"zapret\WinDivert.dll", @"zapret\WinDivert64.sys" }
            .Concat(WinwsPolicy.Payloads.Select(n => @"zapret\payloads\" + n)).ToList();

        public bool UsesDriver => true;
        public string DriverPath => Path.Combine(BinDir, "WinDivert64.sys");
        public bool SupportsService => true;
        public bool SupportsInclude => true;
        public bool SupportsExclude => true;
        public int ListenPort => 0;

        public bool Available(out LocText reason)
        {
            reason = Engines.Is64BitOs() ? null : Engines.Unavailable64(this);
            return reason == null;
        }

        public bool Validate(Profile p, out string error)
        {
            if (p == null) { error = Loc.T("args.noProfile"); return false; }
            if (p.Engine != EngineKind.Zapret) { error = Loc.T("engines.wrongEngine", DisplayName); return false; }
            return WinwsPolicy.Validate(p.EngineArgs, out error);
        }

        /// <summary>
        /// The rules of a profile under the bound lists – the one plan of the command preview and of the start. Every rule
        /// (--new section) that can know the host name (TCP, QUIC on UDP 443, or no filter) gets the include list and the
        /// exclude list unless it places that list itself (one rule placing its own list never exempts the other rules).
        /// In targeted mode a rule that cannot be limited to the target sites (no host name, e.g. Discord voice/STUN) is left
        /// out instead of running for all traffic; its capture filters (--wf-*) stay. If no rule is left, the start stops.
        /// The exclude list cannot reach a rule without host names: such a rule keeps working and is reported.
        /// </summary>
        internal static (List<string> Tokens, int LeftOut, int ExcludeMissed, bool Blocked) Plan(Profile p, ListBinding lists, bool display)
        {
            lists = lists ?? ListBinding.None;
            var tokens = Engines.Tokens(p?.EngineArgs);
            var sections = new List<List<string>> { new List<string>() };
            foreach (var t in tokens)
            {
                if (t == "--new") { sections.Add(new List<string>()); continue; }
                sections[sections.Count - 1].Add(t);
            }
            bool includeOn = lists.Include != null;
            var kept = new List<List<string>>();
            var carried = new List<string>();   // capture filters of a rule that was left out
            int leftOut = 0, missed = 0;
            foreach (var section in sections)
            {
                bool hostOk = HostCapable(section);
                if (includeOn && !hostOk)
                {
                    leftOut++;
                    carried.AddRange(section.Where(t => t.StartsWith("--wf-")));
                    continue;
                }
                if (!hostOk && lists.Exclude != null) missed++;
                var sec = new List<string>();
                foreach (var t in section)
                {
                    int eq = t.IndexOf('=');
                    string name = eq > 0 ? t.Substring(0, eq) : t, val = eq > 0 ? t.Substring(eq + 1) : null;
                    if (name == "--hostlist" || name == "--hostlist-exclude")
                    {
                        string file = name == "--hostlist" ? lists.Include : lists.Exclude;
                        if (file != null) sec.Add(name + "=" + file);   // a list that is turned off is left out
                        continue;
                    }
                    if (val != null && WinwsPolicy.IsPayloadOption(name) && WinwsPolicy.Payloads.Contains(val))
                    {
                        sec.Add(name + "=" + (display ? @"payloads\" + val : Path.Combine(PayloadDir, val)));
                        continue;
                    }
                    sec.Add(t);
                }
                if (hostOk)
                {
                    if (includeOn && !section.Any(t => t.StartsWith("--hostlist="))) sec.Add("--hostlist=" + lists.Include);
                    if (lists.Exclude != null && !section.Any(t => t.StartsWith("--hostlist-exclude="))) sec.Add("--hostlist-exclude=" + lists.Exclude);
                }
                kept.Add(sec);
            }
            bool blocked = includeOn && kept.Count == 0;
            var outTokens = new List<string>(carried.Distinct());
            for (int i = 0; i < kept.Count; i++)
            {
                if (i > 0) outTokens.Add("--new");
                outTokens.AddRange(kept[i]);
            }
            return (outTokens, leftOut, missed, blocked);
        }

        public string BuildArgs(Profile p, ListBinding lists, bool display = false) => Engines.Join(Plan(p, lists, display).Tokens);

        public List<LocText> ScopeNotes(Profile p, ListBinding lists, out bool blocked)
        {
            var (_, leftOut, missed, b) = Plan(p, lists, true);
            blocked = b;
            var notes = new List<LocText>();
            if (b) notes.Add(new LocText("lists.targetedNothingLeft", DisplayName));
            else if (leftOut > 0) notes.Add(new LocText("lists.targetedRulesLeftOut", leftOut));
            if (missed > 0) notes.Add(new LocText("lists.excludePartial", missed));
            return notes;
        }

        /// <summary>Does a rule see traffic with a host name (HTTP/TLS on TCP, QUIC on UDP 443)?</summary>
        internal static bool HostCapable(List<string> section)
        {
            string l7 = Value(section, "--filter-l7"), tcp = Value(section, "--filter-tcp"), udp = Value(section, "--filter-udp");
            if (l7 != null && !l7.Split(',').Any(x => x == "http" || x == "tls" || x == "quic")) return false;
            if (tcp != null) return true;
            if (udp != null) return udp.Split(',').Any(r => PortIn(r, 443));
            return true;   // no filter: the rule sees everything winws captures
        }

        static string Value(List<string> sec, string name)
        {
            var t = sec.LastOrDefault(x => x.StartsWith(name + "="));
            return t?.Substring(name.Length + 1);
        }

        static bool PortIn(string range, int port)
        {
            var parts = range.Split('-');
            if (!int.TryParse(parts[0], out int a)) return false;
            int b = parts.Length > 1 && int.TryParse(parts[1], out int bb) ? bb : a;
            return port >= a && port <= b;
        }

        public bool IsReady(string output) => (output ?? "").Contains("capture is started");

        public bool LooksLikeError(string output)
        {
            string t = output ?? "";
            return t.Contains("error opening filter") || t.Contains("unknown option") || t.Contains("already running") ||
                   t.Contains("load failed") || t.Contains("Invalid") || t.Contains("invalid") || t.Contains("bad value") ||
                   t.Contains("could not") || t.Contains("cannot") || t.Contains("must specify") || t.Contains("error ");
        }

        public (string Code, LocText Hint) Diagnose(string output)
        {
            string t = output ?? "";
            if (t.Contains("secure boot")) return ("NSF-203", new LocText("engine.hint.signature"));
            if (t.Contains("error opening filter")) return ("NSF-201", new LocText("engine.hint.driverLoad"));
            if (t.Contains("already running")) return ("NSF-301", new LocText("engines.zapret.alreadyRunning"));
            if (t.Contains("unknown option") || t.Contains("nvalid") || t.Contains("bad value") || t.Contains("must specify"))
                return ("NSF-603", new LocText("engine.hint.parameters"));
            if (t.Contains("load failed") || t.Contains("could not") || t.Contains("cannot"))
                return ("NSF-603", new LocText("engines.zapret.fileProblem"));
            return ("NSF-601", new LocText("engines.hint.generic", DisplayName));
        }
    }

    // ================================================================================== ByeDPI (ciadpi)

    sealed class ByeDpiEngine : IDpiEngine
    {
        public EngineKind Kind => EngineKind.ByeDpi;
        public string Id => "byedpi";
        public string DisplayName => "ByeDPI (ciadpi)";
        public string ProcessName => "ciadpi";
        public string ExeName => "ciadpi.exe";
        public string BinDir => Path.Combine(Engines.BinRoot, "byedpi");
        public string ExePath => Path.Combine(BinDir, ExeName);
        public IReadOnlyList<string> VerifiedFiles => new[] { @"byedpi\ciadpi.exe" };
        /// <summary>A local SOCKS proxy: no kernel driver (no conflict with kernel anti-cheats, works in the portable version).</summary>
        public bool UsesDriver => false;
        public string DriverPath => null;
        /// <summary>The Windows proxy setting belongs to the signed-in user, so ByeDPI runs with the app (not as a SYSTEM service).</summary>
        public bool SupportsService => false;
        public bool SupportsInclude => true;
        public bool SupportsExclude => true;
        public int ListenPort => ByeDpiNet.SocksPort;

        public bool Available(out LocText reason)
        {
            reason = Engines.Is64BitOs() ? null : Engines.Unavailable64(this);
            return reason == null;
        }

        public bool Validate(Profile p, out string error)
        {
            if (p == null) { error = Loc.T("args.noProfile"); return false; }
            if (p.Engine != EngineKind.ByeDpi) { error = Loc.T("engines.wrongEngine", DisplayName); return false; }
            return CiadpiPolicy.Validate(p.EngineArgs, out error);
        }

        /// <summary>
        /// Always listens on 127.0.0.1 only (ciadpi's own default is 0.0.0.0). Lists are bound with ByeDPI groups – the one plan
        /// of the command preview and of the start: exclude = a first group for the listed hosts without any method; include =
        /// every group (also an empty one, which is never dropped) limited to the list unless the group names a host list of
        /// its own, and a last group without any method for every other host. One group placing its own list never exempts
        /// the other groups.
        /// </summary>
        public string BuildArgs(Profile p, ListBinding lists, bool display = false)
        {
            lists = lists ?? ListBinding.None;
            var pairs = CiadpiPolicy.Pairs(p?.EngineArgs);
            var groups = new List<List<string>> { new List<string>() };
            foreach (var (name, val) in pairs)
            {
                if (name == "--auto") groups.Add(new List<string>());
                var g = groups[groups.Count - 1];
                if (name == "--hosts")
                {
                    string file = val == Hostlists.IncludeName ? lists.Include : val == Hostlists.ExcludeName ? lists.Exclude : null;
                    if (file != null) { g.Add(name); g.Add(file); }
                    continue;
                }
                g.Add(name);
                if (val != null) g.Add(val);
            }
            int port = lists.Port >= 1024 && lists.Port <= 65535 ? lists.Port : ByeDpiNet.SocksPort;
            var argv = new List<string> { "--ip", "127.0.0.1", "--port", port.ToString() };
            // the excluded hosts first: a group without any method, before every group of the profile
            if (lists.Exclude != null) argv.AddRange(new[] { "--hosts", lists.Exclude, "--auto", "none" });
            for (int i = 0; i < groups.Count; i++)
            {
                var g = groups[i];
                // a group that already names a host list of its own keeps it; every other group (an empty one too) gets the
                // include list, after its own "--auto <trigger>" (the first group has none)
                if (lists.Include != null && !g.Contains("--hosts"))
                {
                    int at = g.Count > 0 && g[0] == "--auto" ? 2 : 0;
                    g.InsertRange(at, new[] { "--hosts", lists.Include });
                }
                argv.AddRange(g);
            }
            // every host that no group took: a last group without any method
            if (lists.Include != null) argv.AddRange(new[] { "--auto", "none" });
            return Engines.Join(argv);
        }

        /// <summary>Every ByeDPI group is limited by the lists (see <see cref="BuildArgs"/>): nothing is left uncovered.</summary>
        public List<LocText> ScopeNotes(Profile p, ListBinding lists, out bool blocked) { blocked = false; return new List<LocText>(); }

        public bool IsReady(string output) => false;   // ready = the port listens (see Engine)

        public bool LooksLikeError(string output)
        {
            string t = output ?? "";
            return t.Contains("unknown option") || t.Contains("invalid") || t.Contains("requires an argument") ||
                   t.Contains("bind") || t.Contains("listen") || t.Contains("error");
        }

        public (string Code, LocText Hint) Diagnose(string output)
        {
            string t = output ?? "";
            if (t.Contains("bind") || t.Contains("listen") || t.Contains("10048") || t.Contains("in use"))
                return ("NSF-808", new LocText("engines.byedpi.portBusy", ByeDpiNet.SocksPort));
            if (t.Contains("unknown option") || t.Contains("invalid") || t.Contains("requires an argument"))
                return ("NSF-603", new LocText("engine.hint.parameters"));
            return ("NSF-601", new LocText("engines.hint.generic", DisplayName));
        }
    }

    /// <summary>Plain-language explanation of Zapret / ByeDPI parameters (profiles page and editor).</summary>
    static class EngineHelp
    {
        public static IEnumerable<(string Title, string Text, bool Warn)> Explain(Profile p)
        {
            var list = new List<(string, string, bool)>();
            if (p.Engine == EngineKind.Zapret)
            {
                var t = Engines.Tokens(p.EngineArgs);
                int rules = 1 + t.Count(x => x == "--new");
                string V(string n) => t.Where(x => x.StartsWith(n + "=")).Select(x => x.Substring(n.Length + 1)).FirstOrDefault();
                list.Add((Loc.T("engineHelp.zapret.capture"), Loc.T("engineHelp.zapret.captureText", V("--wf-tcp") ?? "–", V("--wf-udp") ?? "–"), false));
                list.Add((Loc.T("engineHelp.zapret.rules", rules), Loc.T("engineHelp.zapret.rulesText"), false));
                var modes = t.Where(x => x.StartsWith("--dpi-desync=")).Select(x => x.Substring(13)).Distinct().ToList();
                if (modes.Count > 0) list.Add((Loc.T("engineHelp.zapret.methods"), string.Join(" · ", modes), false));
                if (t.Any(x => x.StartsWith("--filter-l7=") && (x.Contains("discord") || x.Contains("stun"))))
                    list.Add((Loc.T("engineHelp.zapret.voice"), Loc.T("engineHelp.zapret.voiceText"), false));
                if (t.Any(x => x.StartsWith("--filter-udp=") && x.Contains("443")))
                    list.Add((Loc.T("engineHelp.zapret.quic"), Loc.T("engineHelp.zapret.quicText"), false));
                var payloads = t.Select(x => x.Split('=')).Where(x => x.Length == 2 && WinwsPolicy.Payloads.Contains(x[1])).Select(x => x[1]).Distinct().ToList();
                if (payloads.Count > 0) list.Add((Loc.T("engineHelp.zapret.payloads"), string.Join(", ", payloads), false));
                list.Add((Loc.T("engineHelp.driver"), Loc.T("engineHelp.zapret.driverText"), false));
                list.Add((Loc.T("engineHelp.noDns"), Loc.T("engineHelp.noDnsText"), true));
            }
            else if (p.Engine == EngineKind.ByeDpi)
            {
                var pairs = CiadpiPolicy.Pairs(p.EngineArgs);
                var methods = pairs.Where(x => x.Name != "--auto" && x.Name != "--timeout" && x.Name != "--hosts")
                                   .Select(x => x.Name.Substring(2) + (x.Value != null ? " " + x.Value : "")).ToList();
                list.Add((Loc.T("engineHelp.byedpi.proxy"), Loc.T("engineHelp.byedpi.proxyText", ByeDpiNet.SocksPort, ByeDpiNet.HttpPort), false));
                if (methods.Count > 0) list.Add((Loc.T("engineHelp.byedpi.methods"), string.Join(" · ", methods), false));
                if (pairs.Any(x => x.Name == "--auto"))
                    list.Add((Loc.T("engineHelp.byedpi.auto"), Loc.T("engineHelp.byedpi.autoText"), false));
                list.Add((Loc.T("engineHelp.byedpi.noDriver"), Loc.T("engineHelp.byedpi.noDriverText"), false));
                list.Add((Loc.T("engineHelp.byedpi.tcpOnly"), Loc.T("engineHelp.byedpi.tcpOnlyText"), true));
                list.Add((Loc.T("engineHelp.noDns"), Loc.T("engineHelp.noDnsText"), true));
            }
            return list;
        }
    }
}
