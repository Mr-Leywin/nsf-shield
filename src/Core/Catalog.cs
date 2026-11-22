using System;
using System.Collections.Generic;
using System.Linq;

namespace NSFShield
{
    /// <summary>
    /// The profile catalog of the three engines: a stable order (recommended first), the one rule that decides which profiles a
    /// list shows (home page, profiles page, tray), scenario tags and the technical summary of a profile.
    /// </summary>
    public static class ProfileCatalog
    {
        /// <summary>
        /// Order of the recommended profiles (Simple, and the scanner's "recommended first"). It never depends on measurements,
        /// so the same request always tries the same candidates in the same order.
        /// </summary>
        public static readonly string[] RecommendedOrder =
        {
            "tr-recommended", "zapret-discord", "byedpi-recommended", "zapret-general", "tr-adguard", "tr-quad9", "tr-opendns",
        };

        static int Layer(Profile p) => p.Tier == ProfileTier.Recommended ? 0 : p.BuiltIn ? 1 : 2;

        static int RecIndex(Profile p)
        {
            int i = Array.IndexOf(RecommendedOrder, p.Id);
            return i < 0 ? 999 : i;
        }

        /// <summary>Stable catalog order: recommended (fixed order), other built-ins (engine, list order), custom (engine, name, id).</summary>
        public static List<Profile> Order(IEnumerable<Profile> list) =>
            list.OrderBy(Layer).ThenBy(RecIndex).ThenBy(p => (int)p.Engine).ThenBy(p => p.BuiltIn ? p.Priority : 0)
                .ThenBy(p => p.BuiltIn ? "" : p.Name, StringComparer.Ordinal).ThenBy(p => p.Id, StringComparer.Ordinal).ToList();

        /// <summary>Position in the catalog order (ties in the scanner are broken by it).</summary>
        public static int Position(Profile p, IList<Profile> ordered) => ordered.ToList().FindIndex(x => x.Id == p.Id);

        public static List<Profile> Recommended(EngineKind? engine = null) =>
            Order(Profiles.BuiltIns.Where(p => p.Tier == ProfileTier.Recommended && (engine == null || p.Engine == engine)));

        /// <summary>Does the level show the specialized and custom profiles?</summary>
        public static bool ShowsExperts(UiLevel level, bool showExperts) => level == UiLevel.Advanced || (level == UiLevel.Standard && showExperts);

        /// <summary>
        /// The profiles a list shows. Simple: the recommended ones; Standard: the recommended ones, the others on request;
        /// Advanced: all. The profile that is selected or actually running is always shown once, even if it is specialized or
        /// custom (it is not added to the recommended scan because of that). <paramref name="engine"/> null = all engines.
        /// </summary>
        public static List<Profile> Visible(IEnumerable<Profile> all, UiLevel level, bool showExperts, EngineKind? engine, string selectedId, string runningId)
        {
            var src = all.ToList();
            bool experts = ShowsExperts(level, showExperts);
            var list = src.Where(p => (engine == null || p.Engine == engine) && (p.Tier == ProfileTier.Recommended || experts)).ToList();
            foreach (var id in new[] { selectedId, runningId })
            {
                if (string.IsNullOrEmpty(id)) continue;
                var x = src.FirstOrDefault(p => p.Id == id);
                if (x != null && (engine == null || x.Engine == engine) && !list.Any(p => p.Id == x.Id)) list.Add(x);
            }
            return Order(list);
        }

        /// <summary>Is the profile only shown because it is selected or running (the "exception" in a filtered list)?</summary>
        public static bool IsException(Profile p, UiLevel level, bool showExperts) =>
            p.Tier != ProfileTier.Recommended && !ShowsExperts(level, showExperts);

        /// <summary>The visible profiles of the UI right now (level, "show expert profiles", the selected and the running profile).</summary>
        public static List<Profile> VisibleNow(EngineKind? engine, UiLevel? level = null) =>
            Visible(App.AllProfiles, level ?? App.Settings.UiLevel, App.Settings.ShowExpertProfiles, engine, App.Settings.SelectedProfileId,
                    App.Engine != null && App.Engine.IsActive ? App.Engine.ActiveProfile?.Id : null);

        /// <summary>
        /// The one profile the Home page shows (card name, the engine of the list and the closed box): the profile of the running
        /// or starting engine (its snapshot, even when the catalog no longer has it or has an edited copy), otherwise the saved
        /// selection; a missing or old id falls back to the default profile, the same fallback as <see cref="App.SelectedProfile"/>.
        /// </summary>
        public static Profile Effective(EngineState state, Profile active, string selectedId, IEnumerable<Profile> all)
        {
            if ((state == EngineState.Running || state == EngineState.Starting) && active != null) return active;
            return all.FirstOrDefault(p => p.Id == selectedId) ?? Profiles.BuiltIns[0];
        }

        /// <summary>
        /// The items of the Home page box: the visible profiles of the effective profile's engine, with the effective profile itself in
        /// place of the catalog entry of the same id (a running snapshot), or added once when the visible list does not have it.
        /// </summary>
        public static List<Profile> HomeItems(Profile effective, IEnumerable<Profile> visible)
        {
            var list = visible.Where(p => p.Engine == effective.Engine).ToList();
            int i = list.FindIndex(p => p.Id == effective.Id);
            if (i >= 0) list[i] = effective;
            else list.Add(effective);
            return list;
        }

        public static string TagText(string tag) => Loc.T("profiles.tag." + tag);

        public static IEnumerable<string> ScenarioTags(Profile p) => (p.Tags ?? new string[0]).Select(TagText);

        /// <summary>Technical tags (Advanced): engine, capture filter or proxy, methods, DNS, QUIC handling.</summary>
        public static List<string> TechnicalTags(Profile p) => Capability.Of(p).Tags();
    }

    /// <summary>
    /// What a profile can touch, read from its parameters: the captured ports and protocols (Zapret), the DNS redirection and QUIC
    /// block (GoodbyeDPI), the local TCP proxy (ByeDPI). The scanner uses it to say what its UDP/STUN result means.
    /// </summary>
    public sealed class Capability
    {
        public EngineKind Engine;
        public string TcpPorts = "", UdpPorts = "", L7 = "", Methods = "", Dns = "";
        public bool QuicBlocked, TcpProxyOnly;

        public static Capability Of(Profile p)
        {
            var c = new Capability { Engine = p.Engine };
            if (p.Engine == EngineKind.Zapret)
            {
                var t = Engines.Tokens(p.EngineArgs);
                string All(string n) => string.Join(",", t.Where(x => x.StartsWith(n + "=")).Select(x => x.Substring(n.Length + 1)).Distinct());
                c.TcpPorts = All("--wf-tcp");
                c.UdpPorts = All("--wf-udp");
                c.L7 = string.Join(",", t.Where(x => x.StartsWith("--filter-l7=")).SelectMany(x => x.Substring(12).Split(',')).Distinct());
                c.Methods = string.Join(",", t.Where(x => x.StartsWith("--dpi-desync=")).SelectMany(x => x.Substring(13).Split(',')).Distinct());
            }
            else if (p.Engine == EngineKind.ByeDpi)
            {
                c.TcpProxyOnly = true;
                c.Methods = string.Join(",", CiadpiPolicy.Pairs(p.EngineArgs).Select(x => x.Name.TrimStart('-'))
                                  .Where(n => n != "auto" && n != "timeout" && n != "hosts" && n != "proto").Distinct());
            }
            else
            {
                c.Dns = p.UsesDnsRedirect ? p.DnsLabel : "";
                var a = " " + p.BuildArgs(null) + " ";
                c.QuicBlocked = a.Contains(" -q ") || (p.UseRaw && a.Contains(" --block-quic "));
                c.Methods = p.UseRaw ? "raw" : string.Join(" ", Engines.Tokens(p.BuildArgs(null)).TakeWhile(x => !x.StartsWith("--dns")));
            }
            return c;
        }

        /// <summary>Is a UDP port inside the profile's capture/rules? (Zapret only; GoodbyeDPI and ByeDPI do not handle that UDP.)</summary>
        public bool CapturesUdp(int port) =>
            Engine == EngineKind.Zapret && UdpPorts.Split(',').Where(r => r.Length > 0).Any(r =>
            {
                var x = r.Split('-');
                return int.TryParse(x[0], out int a) && port >= a && port <= (x.Length > 1 && int.TryParse(x[1], out int b) ? b : a);
            });

        /// <summary>"na": not measured on this path (ByeDPI: TCP proxy); "profile": the port is in the profile's rules; "general": plain UDP access.</summary>
        public string UdpScope(int port) => TcpProxyOnly ? "na" : CapturesUdp(port) ? "profile" : "general";

        public List<string> Tags()
        {
            var l = new List<string>();
            if (Engine == EngineKind.Zapret)
            {
                if (TcpPorts.Length > 0) l.Add("TCP " + TcpPorts);
                if (UdpPorts.Length > 0) l.Add("UDP " + UdpPorts);
                if (L7.Length > 0) l.Add("L7 " + L7);
                if (Methods.Length > 0) l.Add(Methods);
            }
            else if (Engine == EngineKind.ByeDpi)
            {
                l.Add("SOCKS5 127.0.0.1 (TCP)");
                if (Methods.Length > 0) l.Add(Methods);
            }
            else
            {
                if (Methods.Length > 0) l.Add(Methods);
                l.Add(Dns.Length > 0 ? "DNS " + Dns : Loc.T("profiles.tech.noDns"));
                if (QuicBlocked) l.Add(Loc.T("profiles.tech.quicBlocked"));
            }
            return l;
        }
    }

    /// <summary>
    /// The command a profile runs, built with the same validation, list paths, port, payload paths and Windows quoting as a
    /// real start – without writing a list, taking a lock, opening a port or starting anything. The display form uses short
    /// names (not runnable); the full form is only for an explicit "Copy command".
    /// </summary>
    public static class CommandPreview
    {
        public static bool TryBuild(Profile p, AppSettings s, bool full, out string command, out string error)
        {
            command = null;
            if (!ArgPolicy.ValidateProfile(p, out error)) return false;
            var eng = Engines.Of(p);
            var lists = Hostlists.Plan(eng, s);
            command = full
                ? Engine.Esc(eng.ExePath) + " " + eng.BuildArgs(p, lists)
                : eng.ExeName + " " + eng.BuildArgs(p, ListBinding.Display(lists.Include != null, lists.Exclude != null), true);
            error = "";
            return true;
        }

        /// <summary>The display form (short names) or the validation error.</summary>
        public static string Display(Profile p, AppSettings s) => TryBuild(p, s, false, out var c, out var e) ? c : "✗ " + e;
    }
}
