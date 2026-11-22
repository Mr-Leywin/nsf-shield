using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace NSFShield
{
    /// <summary>Checks shared by the Zapret and ByeDPI allow lists.</summary>
    static class PolicyText
    {
        /// <summary>
        /// The only characters a Zapret/ByeDPI parameter may contain. Shell characters (&amp; | % ; &gt; &lt;), quotes, '@'
        /// (winws reads a config or writes a log file after it), '$', '!', glob characters (* ? [ ~ {), slashes and
        /// backslashes (paths), and control characters (CR, LF) can never pass.
        /// </summary>
        public static bool Allowed(char c) =>
            (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == ' ' || c == '-' || c == '_' || c == '.' || c == ',' || c == ':' || c == '=' || c == '+' || c == '#';

        public static bool CheckChars(string args, int max, out string error)
        {
            error = "";
            if (args.Length > max) { error = Loc.T("args.tooLong"); return false; }
            foreach (char c in args)
                if (!Allowed(c))
                {
                    error = Loc.T("args.badChar", c < 32 ? Loc.T("args.controlChar") : "'" + c + "'");
                    return false;
                }
            return true;
        }

        public static bool IntIn(string v, int min, int max) =>
            v != null && Regex.IsMatch(v, @"^-?\d{1,7}$") && int.TryParse(v, out int n) && n >= min && n <= max;

        public static bool Words(string v, ICollection<string> set, int maxItems = 8) =>
            v != null && Regex.IsMatch(v, "^[a-z0-9_]+(,[a-z0-9_]+)*$") && v.Split(',').Length <= maxItems && v.Split(',').All(set.Contains);

        /// <summary>Port list: 443 / 80,443 / 50000-50100 (1–65535, ranges ascending).</summary>
        public static bool Ports(string v)
        {
            if (v == null || !Regex.IsMatch(v, @"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?){0,15}$")) return false;
            foreach (var r in v.Split(','))
            {
                var p = r.Split('-').Select(int.Parse).ToArray();
                if (p.Any(x => x < 1 || x > 65535) || (p.Length == 2 && p[0] > p[1])) return false;
            }
            return true;
        }

        /// <summary>Is the name an abbreviation of one of the options? (getopt_long accepts them.)</summary>
        public static string AbbreviationOf(string name, IEnumerable<string> options) =>
            name.Length >= 3 ? options.FirstOrDefault(o => o.Length > name.Length && o.StartsWith(name, StringComparison.Ordinal)) : null;
    }

    /// <summary>
    /// Allow list for winws (zapret) parameters. winws parses its options with getopt_long_only, which also accepts
    /// abbreviations (--dry, --hostlist-auto-d) and single-dash forms (-new); the live test shows that "--hostlist-auto-d=x"
    /// silently becomes the file-writing --hostlist-auto-debug. So only the full option names in "--name" or "--name=value"
    /// form are accepted, every value is checked by type, and options that write files or take a free path are refused:
    /// payload options only take the names of the verified files in bin\zapret\payloads, list options only the managed
    /// data\lists files.
    /// </summary>
    public static class WinwsPolicy
    {
        /// <summary>Fake payloads shipped in bin\zapret\payloads (their SHA-256 is embedded in <see cref="Integrity"/>).</summary>
        public static readonly string[] Payloads =
        {
            "discord-ip-discovery-with-port.bin", "discord-ip-discovery-without-port.bin", "dtls_clienthello_w3_org.bin",
            "http_iana_org.bin", "quic_initial_facebook_com.bin", "quic_initial_www_google_com.bin", "stun.bin",
            "tls_clienthello_iana_org.bin", "tls_clienthello_www_google_com.bin", "zero_256.bin", "zero_512.bin",
        };

        enum K { Flag, Opt01, Int, Ports, L3, Words, Positions, PayloadOrHex, AutoTtl, Signed, Cutoff, Mods, Domains, ManagedInclude, ManagedExclude, Rx }

        sealed class Spec
        {
            public K Kind;
            public int Min, Max;
            public HashSet<string> Set;
            public Regex Rx;
            public bool OptionalValue;
        }

        static Spec S(K k, bool opt = false) => new Spec { Kind = k, OptionalValue = opt };
        static Spec I(int min, int max) => new Spec { Kind = K.Int, Min = min, Max = max };
        static Spec W(params string[] set) => new Spec { Kind = K.Words, Set = new HashSet<string>(set) };
        static Spec OW(params string[] set) => new Spec { Kind = K.Words, Set = new HashSet<string>(set), OptionalValue = true };
        static Spec X(string rx, bool opt = false) => new Spec { Kind = K.Rx, Rx = new Regex(rx), OptionalValue = opt };

        static readonly string[] Fooling = { "none", "md5sig", "ts", "badseq", "badsum", "datanoack", "hopbyhop", "hopbyhop2" };
        static readonly string[] DesyncModes =
        {
            "fake", "fakeknown", "rst", "rstack", "synack", "syndata", "split", "split2", "disorder", "disorder2", "multisplit",
            "multidisorder", "fakedsplit", "fakeddisorder", "hostfakesplit", "ipfrag1", "ipfrag2", "hopbyhop", "destopt",
            "ipfrag1", "udplen", "tamper",
        };
        static readonly string[] L7 = { "http", "tls", "quic", "wireguard", "dht", "discord", "stun", "xmpp", "dns", "mtproto", "unknown" };
        static readonly string[] TcpFlags = { "fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr", "ae", "r1", "r2", "r3" };

        static readonly Dictionary<string, Spec> Opts = new Dictionary<string, Spec>(StringComparer.Ordinal)
        {
            // rules (profiles)
            ["--new"] = S(K.Flag), ["--skip"] = S(K.Flag),
            ["--filter-tcp"] = S(K.Ports), ["--filter-udp"] = S(K.Ports), ["--filter-l3"] = S(K.L3), ["--filter-l7"] = W(L7),
            // WinDivert capture filter (only the simple forms; raw filters and --wf-save are refused)
            ["--wf-tcp"] = S(K.Ports), ["--wf-udp"] = S(K.Ports), ["--wf-l3"] = S(K.L3),
            ["--wf-filter-lan"] = X("^[01]$"), ["--wf-iface"] = X(@"^\d{1,5}(:\d{1,5})?$"),
            // methods
            ["--dpi-desync"] = W(DesyncModes),
            ["--dpi-desync-fooling"] = W(Fooling), ["--dup-fooling"] = W(Fooling),
            ["--dpi-desync-repeats"] = I(1, 100),
            ["--dpi-desync-skip-nosni"] = S(K.Opt01, true), ["--dpi-desync-any-protocol"] = S(K.Opt01, true),
            ["--dpi-desync-ttl"] = I(0, 255), ["--dpi-desync-ttl6"] = I(0, 255),
            ["--dpi-desync-autottl"] = S(K.AutoTtl, true), ["--dpi-desync-autottl6"] = S(K.AutoTtl, true),
            ["--dpi-desync-split-pos"] = S(K.Positions), ["--dpi-desync-split-http-req"] = S(K.Positions),
            ["--dpi-desync-split-tls"] = S(K.Positions), ["--dpi-desync-split-seqovl"] = S(K.Positions),
            ["--dpi-desync-hostfakesplit-midhost"] = S(K.Positions),
            ["--dpi-desync-split-seqovl-pattern"] = S(K.PayloadOrHex), ["--dpi-desync-fakedsplit-pattern"] = S(K.PayloadOrHex),
            ["--dpi-desync-udplen-pattern"] = S(K.PayloadOrHex),
            ["--dpi-desync-fake-http"] = S(K.PayloadOrHex), ["--dpi-desync-fake-tls"] = S(K.PayloadOrHex),
            ["--dpi-desync-fake-unknown"] = S(K.PayloadOrHex), ["--dpi-desync-fake-syndata"] = S(K.PayloadOrHex),
            ["--dpi-desync-fake-quic"] = S(K.PayloadOrHex), ["--dpi-desync-fake-wireguard"] = S(K.PayloadOrHex),
            ["--dpi-desync-fake-dht"] = S(K.PayloadOrHex), ["--dpi-desync-fake-discord"] = S(K.PayloadOrHex),
            ["--dpi-desync-fake-stun"] = S(K.PayloadOrHex), ["--dpi-desync-fake-unknown-udp"] = S(K.PayloadOrHex),
            ["--dpi-desync-fake-tls-mod"] = S(K.Mods), ["--dpi-desync-fake-tcp-mod"] = S(K.Mods),
            ["--dpi-desync-fakedsplit-mod"] = S(K.Mods), ["--dpi-desync-hostfakesplit-mod"] = S(K.Mods),
            ["--dpi-desync-ipfrag-pos-tcp"] = I(8, 9216), ["--dpi-desync-ipfrag-pos-udp"] = I(8, 9216),
            ["--dpi-desync-ts-increment"] = S(K.Signed), ["--dpi-desync-badseq-increment"] = S(K.Signed),
            ["--dpi-desync-badack-increment"] = S(K.Signed), ["--dpi-desync-udplen-increment"] = I(-1024, 1024),
            ["--dpi-desync-cutoff"] = S(K.Cutoff), ["--dpi-desync-start"] = S(K.Cutoff),
            ["--dpi-desync-tcp-flags-set"] = OW(TcpFlags), ["--dpi-desync-tcp-flags-unset"] = OW(TcpFlags),
            ["--dup"] = I(0, 1024), ["--dup-ttl"] = I(0, 255), ["--dup-ttl6"] = I(0, 255),
            ["--dup-autottl"] = S(K.AutoTtl, true), ["--dup-autottl6"] = S(K.AutoTtl, true),
            ["--dup-tcp-flags-set"] = OW(TcpFlags), ["--dup-tcp-flags-unset"] = OW(TcpFlags),
            ["--dup-ts-increment"] = S(K.Signed), ["--dup-badseq-increment"] = S(K.Signed), ["--dup-badack-increment"] = S(K.Signed),
            ["--dup-start"] = S(K.Cutoff), ["--dup-cutoff"] = S(K.Cutoff),
            ["--orig-ttl"] = I(0, 255), ["--orig-ttl6"] = I(0, 255),
            ["--orig-autottl"] = S(K.AutoTtl, true), ["--orig-autottl6"] = S(K.AutoTtl, true),
            ["--orig-tcp-flags-set"] = OW(TcpFlags), ["--orig-tcp-flags-unset"] = OW(TcpFlags),
            ["--orig-mod-start"] = S(K.Cutoff), ["--orig-mod-cutoff"] = S(K.Cutoff),
            // HTTP/TCP tricks
            ["--hostcase"] = S(K.Flag), ["--hostnospace"] = S(K.Flag), ["--domcase"] = S(K.Flag), ["--methodeol"] = S(K.Flag),
            ["--hostspell"] = X("^[A-Za-z]{4}$"), ["--ip-id"] = W("seq", "zero"),
            ["--wsize"] = X(@"^\d{1,5}(:\d{1,2})?$"), ["--wssize"] = X(@"^\d{1,5}(:\d{1,2})?$"),
            ["--wssize-cutoff"] = S(K.Cutoff), ["--synack-split"] = OW("syn", "synack", "acksyn"),
            ["--ctrack-timeouts"] = X(@"^\d{1,6}(:\d{1,6}){0,3}$"), ["--ctrack-disable"] = S(K.Opt01, true),
            ["--ipcache-lifetime"] = I(0, 864000), ["--ipcache-hostname"] = S(K.Opt01, true),
            // domain lists: inline domains, or the app's managed list files by name only
            ["--hostlist"] = S(K.ManagedInclude), ["--hostlist-exclude"] = S(K.ManagedExclude),
            ["--hostlist-domains"] = S(K.Domains), ["--hostlist-exclude-domains"] = S(K.Domains),
        };

        /// <summary>Options refused on purpose (they write files, take a free path or change how winws runs).</summary>
        static readonly Dictionary<string, string> Forbidden = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["--hostlist-auto"] = "args.forbidden.writesFile", ["--hostlist-auto-debug"] = "args.forbidden.writesFile",
            ["--hostlist-auto-fail-threshold"] = "args.forbidden.autoList", ["--hostlist-auto-fail-time"] = "args.forbidden.autoList",
            ["--hostlist-auto-retrans-threshold"] = "args.forbidden.autoList",
            ["--debug"] = "args.forbidden.writesFile", ["--pidfile"] = "args.forbidden.writesFile", ["--wf-save"] = "args.forbidden.writesFile",
            ["--ipset"] = "args.forbidden.freePath", ["--ipset-exclude"] = "args.forbidden.freePath",
            ["--ipset-ip"] = "args.forbidden.notSupported", ["--ipset-exclude-ip"] = "args.forbidden.notSupported",
            ["--wf-raw"] = "args.forbidden.rawFilter", ["--wf-raw-part"] = "args.forbidden.rawFilter",
            ["--dry-run"] = "args.forbidden.notSupported", ["--version"] = "args.forbidden.notSupported", ["--comment"] = "args.forbidden.notSupported",
            ["--daemon"] = "args.forbidden.notSupported", ["--user"] = "args.forbidden.notSupported", ["--uid"] = "args.forbidden.notSupported",
            ["--ssid-filter"] = "args.forbidden.notSupported", ["--nlm-filter"] = "args.forbidden.notSupported", ["--nlm-list"] = "args.forbidden.notSupported",
            ["--filter-ssid"] = "args.forbidden.notSupported",
        };

        public static bool IsPayloadOption(string name) => Opts.TryGetValue(name, out var s) && s.Kind == K.PayloadOrHex;
        public static IEnumerable<string> KnownOptions => Opts.Keys;

        public static bool Validate(string args, out string error)
        {
            args = args ?? "";
            if (!PolicyText.CheckChars(args, 8000, out error)) return false;
            var tokens = Engines.Tokens(args);
            if (tokens.Count == 0) { error = Loc.T("args.empty"); return false; }
            bool capture = false;
            int rules = 1;
            foreach (var tok in tokens)
            {
                if (!tok.StartsWith("--"))
                {
                    error = tok.StartsWith("-") && tok.Length > 2 ? Loc.T("args.singleDash", tok) : Loc.T("args.unexpectedValue") + " " + tok;
                    return false;
                }
                int eq = tok.IndexOf('=');
                string name = eq > 0 ? tok.Substring(0, eq) : tok, val = eq > 0 ? tok.Substring(eq + 1) : null;
                if (Forbidden.TryGetValue(name, out var why)) { error = Loc.T(why, name); return false; }
                if (!Opts.TryGetValue(name, out var s))
                {
                    string full = PolicyText.AbbreviationOf(name, Opts.Keys.Concat(Forbidden.Keys));
                    error = full != null ? Loc.T("args.abbreviation", name, full) : Loc.T("args.unknown", name);
                    return false;
                }
                if (name == "--new") { if (++rules > 32) { error = Loc.T("args.tooManyRules", 32); return false; } }
                if (name == "--wf-tcp" || name == "--wf-udp") capture = true;
                if (!ValueOk(s, val, out string vErr)) { error = name + " " + vErr; return false; }
            }
            if (!capture) { error = Loc.T("args.winwsNeedsCapture"); return false; }
            error = "";
            return true;
        }

        static bool ValueOk(Spec s, string v, out string error)
        {
            error = "";
            if (s.Kind == K.Flag)
            {
                if (v != null) { error = Loc.T("args.noValue"); return false; }
                return true;
            }
            if (v == null)
            {
                if (s.OptionalValue) return true;
                error = Loc.T("args.missingValueEq");
                return false;
            }
            bool ok;
            switch (s.Kind)
            {
                case K.Opt01: ok = v == "0" || v == "1"; break;
                case K.Int: ok = PolicyText.IntIn(v, s.Min, s.Max); if (!ok) { error = Loc.T("args.range", s.Min, s.Max); return false; } break;
                case K.Ports: ok = PolicyText.Ports(v); break;
                case K.L3: ok = Regex.IsMatch(v, "^(ipv4|ipv6)(,(ipv4|ipv6))?$"); break;
                case K.Words: ok = PolicyText.Words(v, s.Set); break;
                case K.Positions: ok = v.Length <= 200 && Regex.IsMatch(v, @"^[a-z0-9+\-]+(,[a-z0-9+\-]+){0,15}$"); break;
                case K.PayloadOrHex:
                    ok = Payloads.Contains(v) || Regex.IsMatch(v, "^0x([0-9a-fA-F]{2}){1,1024}$");
                    if (!ok) { error = Loc.T("args.payloadName", v); return false; }
                    break;
                case K.AutoTtl: ok = Regex.IsMatch(v, @"^-?\d{1,3}(:\d{1,3}-\d{1,3})?$"); break;
                case K.Signed: ok = Regex.IsMatch(v, @"^-?(\d{1,10}|0x[0-9a-fA-F]{1,8})$"); break;
                case K.Cutoff: ok = Regex.IsMatch(v, @"^[nds]?\d{1,6}$"); break;
                case K.Mods: ok = v.Length <= 300 && v.Split(',').All(ModOk); break;
                case K.Domains: ok = v.Length <= 2000 && v.Split(',').All(d => Hostlists.IsValidDomain(d)); break;
                case K.ManagedInclude:
                    ok = v == Hostlists.IncludeName;
                    if (!ok) { error = Loc.T("args.managedList", Hostlists.IncludeName); return false; }
                    break;
                case K.ManagedExclude:
                    ok = v == Hostlists.ExcludeName;
                    if (!ok) { error = Loc.T("args.managedList", Hostlists.ExcludeName); return false; }
                    break;
                case K.Rx: ok = s.Rx.IsMatch(v); break;
                default: ok = false; break;
            }
            if (!ok) error = Loc.T("args.invalidValue") + " " + v;
            return ok;
        }

        /// <summary>"rnd", "dupsid", "sni=www.google.com", "altorder=1" …: a word, optionally "=" and a number or a host name.</summary>
        static bool ModOk(string m)
        {
            var kv = m.Split(new[] { '=' }, 2);
            if (!Regex.IsMatch(kv[0], "^[a-z0-9_]{1,24}$")) return false;
            if (kv.Length == 1) return true;
            return Regex.IsMatch(kv[1], @"^-?\d{1,6}$") || Hostlists.IsValidDomain(kv[1]);
        }
    }

    /// <summary>
    /// Allow list for ciadpi (ByeDPI) parameters. ciadpi parses with getopt_long (the live test shows "--hel" is accepted as
    /// --help), so only full long names are accepted, as "--name value" or "--name=value". The listening address and port are
    /// always set by the app (127.0.0.1); options that bind elsewhere, write files or read free paths are refused.
    /// </summary>
    public static class CiadpiPolicy
    {
        enum K { Flag, Int, Pos, Words, Rx, ManagedList }

        sealed class Spec
        {
            public K Kind;
            public int Min, Max;
            public HashSet<string> Set;
            public Regex Rx;
        }

        static Spec I(int min, int max) => new Spec { Kind = K.Int, Min = min, Max = max };
        static Spec W(params string[] set) => new Spec { Kind = K.Words, Set = new HashSet<string>(set) };
        static Spec X(string rx) => new Spec { Kind = K.Rx, Rx = new Regex(rx) };
        static Spec S(K k) => new Spec { Kind = k };

        static readonly Dictionary<string, Spec> Opts = new Dictionary<string, Spec>(StringComparer.Ordinal)
        {
            ["--split"] = S(K.Pos), ["--disorder"] = S(K.Pos), ["--oob"] = S(K.Pos), ["--disoob"] = S(K.Pos),
            ["--fake"] = S(K.Pos), ["--tlsrec"] = S(K.Pos), ["--fake-offset"] = S(K.Pos),
            ["--ttl"] = I(1, 255), ["--def-ttl"] = I(1, 255),
            ["--auto"] = W("torst", "redirect", "ssl_err", "none", "t", "r", "s", "n"),
            ["--auto-mode"] = I(0, 3), ["--cache-ttl"] = I(1, 2592000), ["--timeout"] = X(@"^\d{1,3}(\.\d{1,3})?$"),
            ["--proto"] = W("tls", "http", "udp", "ipv4", "t", "h", "u", "i"),
            ["--pf"] = X(@"^\d{1,5}(-\d{1,5})?$"), ["--round"] = X(@"^\d{1,4}(-\d{1,4})?$"),
            ["--fake-sni"] = X(@"^[a-z0-9.#\-]{1,253}$"), ["--fake-tls-mod"] = X(@"^(rand|orig|msize=-?\d{1,5})(,(rand|orig|msize=-?\d{1,5})){0,2}$"),
            ["--oob-data"] = X("^[A-Za-z0-9]$"), ["--mod-http"] = W("hcsmix", "dcsmix", "rmspace", "h", "d", "r"),
            ["--tlsminor"] = I(0, 255), ["--udp-fake"] = I(0, 100), ["--max-conn"] = I(1, 4096), ["--buf-size"] = I(1024, 1048576),
            ["--no-domain"] = S(K.Flag), ["--no-udp"] = S(K.Flag),
            ["--hosts"] = S(K.ManagedList),
        };

        static readonly Dictionary<string, string> Forbidden = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["--ip"] = "args.forbidden.listenAddress", ["--port"] = "args.forbidden.listenAddress", ["--conn-ip"] = "args.forbidden.listenAddress",
            ["--transparent"] = "args.forbidden.listenAddress",
            ["--cache-dump"] = "args.forbidden.writesFile", ["--pidfile"] = "args.forbidden.writesFile", ["--debug"] = "args.forbidden.writesFile",
            ["--fake-data"] = "args.forbidden.freePath", ["--ipset"] = "args.forbidden.freePath",
            ["--daemon"] = "args.forbidden.notSupported", ["--help"] = "args.forbidden.notSupported", ["--version"] = "args.forbidden.notSupported",
            ["--md5sig"] = "args.forbidden.linuxOnly", ["--drop-sack"] = "args.forbidden.linuxOnly", ["--tfo"] = "args.forbidden.linuxOnly",
        };

        static readonly Regex PosRx = new Regex(@"^-?\d{1,5}(:\d{1,5}:\d{1,5})?(\+[shn][em]?)?$");

        public static IEnumerable<string> KnownOptions => Opts.Keys;

        /// <summary>The parameters as (name, value) pairs ("--name value" and "--name=value" both accepted); invalid text gives what it can.</summary>
        public static List<(string Name, string Value)> Pairs(string args)
        {
            var list = new List<(string, string)>();
            var t = Engines.Tokens(args);
            for (int i = 0; i < t.Count; i++)
            {
                string tok = t[i];
                int eq = tok.IndexOf('=');
                if (tok.StartsWith("--") && eq > 0) { list.Add((tok.Substring(0, eq), tok.Substring(eq + 1))); continue; }
                bool takesValue = Opts.TryGetValue(tok, out var s) && s.Kind != K.Flag;
                if (takesValue && i + 1 < t.Count) { list.Add((tok, t[i + 1])); i++; }
                else list.Add((tok, null));
            }
            return list;
        }

        public static bool Validate(string args, out string error)
        {
            args = args ?? "";
            if (!PolicyText.CheckChars(args, 4000, out error)) return false;
            var tokens = Engines.Tokens(args);
            if (tokens.Count == 0) { error = Loc.T("args.empty"); return false; }
            bool method = false;
            for (int i = 0; i < tokens.Count; i++)
            {
                string tok = tokens[i];
                if (!tok.StartsWith("--"))
                {
                    error = tok.StartsWith("-") && tok.Length >= 2 && !char.IsDigit(tok[1]) ? Loc.T("args.singleDash", tok) : Loc.T("args.unexpectedValue") + " " + tok;
                    return false;
                }
                int eq = tok.IndexOf('=');
                string name = eq > 0 ? tok.Substring(0, eq) : tok, val = eq > 0 ? tok.Substring(eq + 1) : null;
                if (Forbidden.TryGetValue(name, out var why)) { error = Loc.T(why, name); return false; }
                if (!Opts.TryGetValue(name, out var s))
                {
                    string full = PolicyText.AbbreviationOf(name, Opts.Keys.Concat(Forbidden.Keys));
                    error = full != null ? Loc.T("args.abbreviation", name, full) : Loc.T("args.unknown", name);
                    return false;
                }
                if (s.Kind == K.Flag)
                {
                    if (val != null) { error = name + " " + Loc.T("args.noValue"); return false; }
                    continue;
                }
                if (val == null)
                {
                    if (i + 1 >= tokens.Count) { error = name + " " + Loc.T("args.missingValue"); return false; }
                    val = tokens[++i];
                }
                if (!ValueOk(s, val, out string vErr)) { error = name + " " + vErr; return false; }
                if (name == "--split" || name == "--disorder" || name == "--oob" || name == "--disoob" || name == "--fake" ||
                    name == "--tlsrec" || name == "--mod-http" || name == "--tlsminor" || name == "--udp-fake")
                    method = true;
            }
            if (!method) { error = Loc.T("args.byedpiNeedsMethod"); return false; }
            error = "";
            return true;
        }

        static bool ValueOk(Spec s, string v, out string error)
        {
            error = "";
            bool ok;
            switch (s.Kind)
            {
                case K.Int: ok = PolicyText.IntIn(v, s.Min, s.Max); if (!ok) { error = Loc.T("args.range", s.Min, s.Max); return false; } break;
                case K.Pos: ok = PosRx.IsMatch(v); break;
                case K.Words: ok = PolicyText.Words(v, s.Set); break;
                case K.Rx: ok = s.Rx.IsMatch(v); break;
                case K.ManagedList:
                    ok = v == Hostlists.IncludeName || v == Hostlists.ExcludeName;
                    if (!ok) { error = Loc.T("args.managedList", Hostlists.IncludeName + " / " + Hostlists.ExcludeName); return false; }
                    break;
                default: ok = false; break;
            }
            if (!ok) error = Loc.T("args.invalidValue") + " " + v;
            return ok;
        }
    }
}
