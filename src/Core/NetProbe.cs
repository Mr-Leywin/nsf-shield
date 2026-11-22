using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace NSFShield
{
    // ======================================================================================= addresses

    /// <summary>What kind of address a DNS answer gave (only <see cref="Public"/> addresses are ever contacted by the scanner).</summary>
    public enum AddressClass { Public, Unspecified, Loopback, Private, LinkLocal, SharedCgnat, Multicast, Broadcast, Documentation, Reserved, Ipv4Mapped, UniqueLocal, SiteLocal, Transition }

    public static class IpPolicy
    {
        public static AddressClass Classify(IPAddress a)
        {
            if (a == null) return AddressClass.Unspecified;
            var b = a.GetAddressBytes();
            if (b.Length == 4) return Classify4(b, 0);
            if (b.Length != 16) return AddressClass.Reserved;
            bool zero10 = true;
            for (int i = 0; i < 10; i++) if (b[i] != 0) { zero10 = false; break; }
            if (zero10 && b[10] == 0xff && b[11] == 0xff) return AddressClass.Ipv4Mapped;          // ::ffff:a.b.c.d
            if (zero10 && b[10] == 0 && b[11] == 0)
            {
                bool rest0 = b.Skip(12).Take(3).All(x => x == 0);
                if (rest0 && b[15] == 0) return AddressClass.Unspecified;                          // ::
                if (rest0 && b[15] == 1) return AddressClass.Loopback;                             // ::1
                return AddressClass.Reserved;                                                      // ::a.b.c.d (deprecated)
            }
            if (b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b)
            {
                // NAT64: 64:ff9b::/96 is routed through a NAT64 gateway; the embedded IPv4 address must be public too
                if (b.Skip(4).Take(8).All(x => x == 0)) return Classify4(b, 12) == AddressClass.Public ? AddressClass.Public : AddressClass.Transition;
                return AddressClass.Reserved;                                                      // 64:ff9b:1::/48 local use
            }
            if (b[0] == 0x01 && b[1] == 0x00 && b.Skip(2).Take(6).All(x => x == 0)) return AddressClass.Reserved;   // 100::/64 discard
            if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8) return AddressClass.Documentation;     // 2001:db8::/32
            if (b[0] == 0x20 && b[1] == 0x01 && b[2] < 0x02) return AddressClass.Transition;                        // 2001::/23 (Teredo, IETF)
            if (b[0] == 0x20 && b[1] == 0x02) return AddressClass.Transition;                                       // 2002::/16 6to4
            if (b[0] == 0x3f && b[1] == 0xff && (b[2] & 0xf0) == 0) return AddressClass.Documentation;              // 3fff::/20
            if (b[0] == 0x5f && b[1] == 0x00) return AddressClass.Reserved;                                         // 5f00::/16 SRv6
            if ((b[0] & 0xfe) == 0xfc) return AddressClass.UniqueLocal;                                             // fc00::/7
            if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return AddressClass.LinkLocal;                               // fe80::/10
            if (b[0] == 0xfe && (b[1] & 0xc0) == 0xc0) return AddressClass.SiteLocal;                               // fec0::/10
            if (b[0] == 0xff) return AddressClass.Multicast;                                                        // ff00::/8
            if ((b[0] & 0xe0) != 0x20) return AddressClass.Reserved;                                                // not 2000::/3
            return AddressClass.Public;
        }

        static AddressClass Classify4(byte[] b, int o)
        {
            byte a0 = b[o], a1 = b[o + 1], a2 = b[o + 2], a3 = b[o + 3];
            if (a0 == 0) return AddressClass.Unspecified;
            if (a0 == 10) return AddressClass.Private;
            if (a0 == 100 && (a1 & 0xc0) == 64) return AddressClass.SharedCgnat;
            if (a0 == 127) return AddressClass.Loopback;
            if (a0 == 169 && a1 == 254) return AddressClass.LinkLocal;
            if (a0 == 172 && (a1 & 0xf0) == 16) return AddressClass.Private;
            if (a0 == 192 && a1 == 0 && a2 == 0) return AddressClass.Reserved;
            if (a0 == 192 && a1 == 0 && a2 == 2) return AddressClass.Documentation;
            if (a0 == 192 && a1 == 88 && a2 == 99) return AddressClass.Transition;
            if (a0 == 192 && a1 == 168) return AddressClass.Private;
            if (a0 == 198 && (a1 & 0xfe) == 18) return AddressClass.Reserved;
            if (a0 == 198 && a1 == 51 && a2 == 100) return AddressClass.Documentation;
            if (a0 == 203 && a1 == 0 && a2 == 113) return AddressClass.Documentation;
            if (a0 == 255 && a1 == 255 && a2 == 255 && a3 == 255) return AddressClass.Broadcast;
            if (a0 >= 224 && a0 <= 239) return AddressClass.Multicast;
            if (a0 >= 240) return AddressClass.Reserved;
            return AddressClass.Public;
        }

        public static bool IsPublic(IPAddress a) => Classify(a) == AddressClass.Public;

        /// <summary>
        /// True only if the answer has addresses and every one is public. A mixed answer (public and private) is refused as a
        /// whole: <paramref name="worst"/> is the first non-public class.
        /// </summary>
        public static bool AllPublic(IList<IPAddress> list, out AddressClass worst)
        {
            worst = AddressClass.Public;
            if (list == null || list.Count == 0) { worst = AddressClass.Unspecified; return false; }
            foreach (var a in list)
            {
                var c = Classify(a);
                if (c != AddressClass.Public) { worst = c; return false; }
            }
            return true;
        }
    }

    // ======================================================================================= scan targets

    /// <summary>
    /// What a working target answers: an explicit, checkable expectation (default targets). Redirects are never judged by the
    /// status table: they pass only when their Location, read against the real request URI, points at one of
    /// <see cref="RedirectHosts"/> over HTTPS on the default port.
    /// </summary>
    public sealed class TargetExpectation
    {
        public string Path = "/";
        public int[] Statuses = new int[0];
        /// <summary>Hosts a redirect of this target may point at (lower case); empty: no redirect is accepted.</summary>
        public string[] RedirectHosts = new string[0];
        /// <summary>The fixed Discord Gateway target: a bounded WebSocket opening instead of "GET /".</summary>
        public bool WebSocket;
        public bool Accepts(int status) => Statuses.Contains(status);
        public TargetExpectation Copy() => new TargetExpectation { Path = Path, Statuses = (int[])Statuses.Clone(), RedirectHosts = (string[])RedirectHosts.Clone(), WebSocket = WebSocket };
        public string Describe()
        {
            var parts = new List<string>();
            var s = Statuses.OrderBy(x => x).ToList();
            for (int i = 0; i < s.Count;)
            {
                int j = i;
                while (j + 1 < s.Count && s[j + 1] == s[j] + 1) j++;
                parts.Add(j > i ? s[i] + "–" + s[j] : s[i].ToString());
                i = j + 1;
            }
            return string.Join(", ", parts);
        }
    }

    /// <summary>
    /// Targets of the smart scanner: host names only. A new entry is checked strictly (it is not "cleaned" like the domain
    /// lists): ASCII/punycode DNS names with the label rules of <see cref="Hostlists.IsValidDomain"/>; a scheme, path, query,
    /// port, space, control character, wildcard, IP address or a local/special-use name is refused.
    /// </summary>
    public static class ScanTargets
    {
        public const int MaxTargets = 12;

        /// <summary>Special-use and local names (RFC 6761/6762/8375 and common LAN suffixes).</summary>
        static readonly string[] LocalSuffixes =
        {
            "localhost", "local", "localdomain", "lan", "home", "internal", "intranet", "corp", "private", "home.arpa", "arpa",
            "test", "example", "invalid", "onion", "alt",
        };

        public static bool IsValid(string s) => IsValid(s, out _);

        /// <summary>Strict check of one target; <paramref name="reasonKey"/> is a locale key ("scan.target.bad.*").</summary>
        public static bool IsValid(string s, out string reasonKey)
        {
            reasonKey = null;
            if (string.IsNullOrEmpty(s)) { reasonKey = "scan.target.bad.empty"; return false; }
            if (s.Length > 253) { reasonKey = "scan.target.bad.tooLong"; return false; }
            foreach (char c in s)
            {
                if (char.IsWhiteSpace(c) || char.IsControl(c)) { reasonKey = "scan.target.bad.space"; return false; }
                if (c == ':') { reasonKey = s.Contains("://") ? "scan.target.bad.scheme" : "scan.target.bad.port"; return false; }
                if (c == '/' || c == '\\') { reasonKey = "scan.target.bad.path"; return false; }
                if (c == '?' || c == '#' || c == '&' || c == '=') { reasonKey = "scan.target.bad.query"; return false; }
                if (c == '*') { reasonKey = "scan.target.bad.wildcard"; return false; }
                if (c == '[' || c == ']') { reasonKey = "scan.target.bad.ip"; return false; }
                if (c == '@') { reasonKey = "scan.target.bad.credentials"; return false; }
                if (c > 127) { reasonKey = "scan.target.bad.ascii"; return false; }
                if (!(char.IsLetterOrDigit(c) || c == '.' || c == '-')) { reasonKey = "scan.target.bad.chars"; return false; }
            }
            if (IPAddress.TryParse(s, out _)) { reasonKey = "scan.target.bad.ip"; return false; }
            string d = s.ToLowerInvariant();
            if (!Hostlists.IsValidDomain(d))
            {
                string tld = d.Split('.').Last();
                reasonKey = tld.Length > 0 && tld.All(char.IsDigit) ? "scan.target.bad.ip" : "scan.target.bad.invalid";
                return false;
            }
            var labels = d.Split('.');
            string last = labels[labels.Length - 1], last2 = labels.Length >= 2 ? labels[labels.Length - 2] + "." + last : last;
            if (LocalSuffixes.Contains(last) || LocalSuffixes.Contains(last2)) { reasonKey = "scan.target.bad.local"; return false; }
            return true;
        }

        /// <summary>
        /// The scanner's targets after loading the settings. Saved targets are checked strictly again. The first time (the list
        /// is empty: older settings; the UI never empties it) they are taken from the quick-test list: URLs give
        /// their host name, everything else must pass the strict check; duplicates go; with nothing usable the default Discord
        /// targets are used. The quick-test list itself is never changed.
        /// </summary>
        public static List<string> Init(List<string> targets, List<string> testHosts)
        {
            var list = new List<string>();
            foreach (var t in targets ?? new List<string>())
            {
                string d = (t ?? "").ToLowerInvariant();
                if (IsValid(d) && !list.Contains(d)) list.Add(d);
            }
            if (list.Count == 0)
            {
                foreach (var h in testHosts ?? new List<string>())
                {
                    string host = h ?? "";
                    if (host.Contains("://"))
                    {
                        if (!Uri.TryCreate(host, UriKind.Absolute, out var u) || (u.Scheme != Uri.UriSchemeHttps && u.Scheme != Uri.UriSchemeHttp)) continue;
                        host = u.Host;
                    }
                    host = host.ToLowerInvariant();
                    if (IsValid(host) && !list.Contains(host)) list.Add(host);
                }
            }
            if (list.Count == 0) list = AppSettings.DefaultTestHosts.ToList();
            return list.Take(MaxTargets).ToList();
        }

        static int[] Range(int a, int b) => Enumerable.Range(a, b - a + 1).ToArray();

        /// <summary>The fixed Discord Gateway target and the WebSocket address the scanner opens (no credentials, no Identify).</summary>
        public const string GatewayHost = "gateway.discord.gg", GatewayPath = "/?v=10&encoding=json";

        public static bool IsGateway(string host) => string.Equals(host, GatewayHost, StringComparison.OrdinalIgnoreCase);

        static TargetExpectation Cdn(string host) =>
            new TargetExpectation { Statuses = Range(200, 299).Concat(new[] { 400, 403, 404 }).ToArray(), RedirectHosts = new[] { host } };

        /// <summary>
        /// The default targets: the web pages answer 2xx (or redirect inside Discord over HTTPS); the CDN and update hosts answer
        /// 400/403/404 on their root on purpose; the Gateway is only "working" when its WebSocket opening completes. Together with
        /// the certificate check for the original name these are the expected results.
        /// </summary>
        static readonly Dictionary<string, TargetExpectation> Expected = new Dictionary<string, TargetExpectation>(StringComparer.OrdinalIgnoreCase)
        {
            ["discord.com"] = new TargetExpectation { Statuses = Range(200, 299), RedirectHosts = new[] { "discord.com" } },
            ["discordapp.com"] = new TargetExpectation { Statuses = Range(200, 299), RedirectHosts = new[] { "discordapp.com", "discord.com" } },
            [GatewayHost] = new TargetExpectation { Path = GatewayPath, Statuses = new[] { 101 }, WebSocket = true },
            ["cdn.discordapp.com"] = Cdn("cdn.discordapp.com"),
            ["media.discordapp.net"] = Cdn("media.discordapp.net"),
            ["updates.discord.com"] = new TargetExpectation { Statuses = Range(200, 299).Concat(new[] { 400, 403, 404 }).ToArray(), RedirectHosts = new[] { "updates.discord.com", "discord.com" } },
        };

        /// <summary>The explicit expectation of a default target (a copy; null: other targets, judged by the general rule).</summary>
        public static TargetExpectation ExpectationFor(string host) =>
            Expected.TryGetValue(host ?? "", out var e) ? e.Copy() : null;

        /// <summary>The registrable part of a host name (two labels, three for names like x.com.tr).</summary>
        public static string Site(string host)
        {
            var l = (host ?? "").ToLowerInvariant().Split('.');
            if (l.Length <= 2) return string.Join(".", l);
            bool cc2 = l[l.Length - 1].Length == 2 && l[l.Length - 2].Length <= 3;
            return string.Join(".", l.Skip(l.Length - (cc2 ? 3 : 2)));
        }
    }

    // ======================================================================================= probe results

    public enum DnsStatus { Ok, NxDomain, NoData, Timeout, Error }

    public sealed class DnsAnswer
    {
        public DnsStatus Status;
        public List<IPAddress> Addresses = new List<IPAddress>();
        public int Ms;
        public string Detail = "";
    }

    public enum ProbeStage { Dns, Connect, Tunnel, Tls, Http, Done }
    public enum TargetVerdict { Pass, Partial, Fail, Unmeasured, OutOfScope }

    /// <summary>One HTTPS measurement of one target (one new connection, pinned to a checked public address).</summary>
    public sealed class TargetProbe
    {
        public string Host = "";
        public string Ip = "";
        public ProbeStage Stage = ProbeStage.Dns;
        public TargetVerdict Verdict = TargetVerdict.Fail;
        public int? DnsMs, ConnectMs, TunnelMs, TlsMs, HttpMs;
        public int Status;
        public string Location = "";
        public LocText Detail;
        public string Code = "";
        public string Via = "direct";
        /// <summary>The measurement was the Gateway's WebSocket opening ("Gateway connection"), not "GET /".</summary>
        public bool WebSocket;
        /// <summary>Time from the connection to the response headers (DNS not included); null when not measured.</summary>
        public int? TotalMs => Stage == ProbeStage.Done && ConnectMs.HasValue ? (ConnectMs ?? 0) + (TunnelMs ?? 0) + (TlsMs ?? 0) + (HttpMs ?? 0) : (int?)null;

        /// <summary>"DNS ✓ · TCP ✓ · TLS ✓ · HTTP 200" (the layers this measurement reached).</summary>
        public string Layers
        {
            get
            {
                var p = new List<string>();
                string M(ProbeStage s) => Stage > s ? "✓" : Stage == s ? "✗" : "–";
                p.Add("DNS " + M(ProbeStage.Dns));
                p.Add((Via == "direct" ? "TCP " : "SOCKS ") + (Stage > ProbeStage.Tunnel ? "✓" : Stage == ProbeStage.Connect || Stage == ProbeStage.Tunnel ? "✗" : "–"));
                p.Add("TLS " + M(ProbeStage.Tls));
                p.Add((WebSocket ? "WS " : "HTTP ") + (Stage == ProbeStage.Done ? Status.ToString() : Stage == ProbeStage.Http ? "✗" : "–"));
                return string.Join(" · ", p);
            }
        }
    }

    sealed class ProbeFail : Exception
    {
        public readonly ProbeStage Stage;
        public readonly LocText Text;
        public readonly string Code;
        public ProbeFail(ProbeStage stage, string code, LocText text) : base(text?.English) { Stage = stage; Code = code; Text = text; }
    }

    /// <summary>Result of the TLS step (the stream is only usable when Ok).</summary>
    public sealed class TlsOutcome
    {
        public Stream Stream;
        public bool Ok;
        public bool CertError;
        public bool Timeout;
        public SslPolicyErrors Errors;
        public string Message = "";
    }

    /// <summary>TLS rule of the scanner: the certificate chain and the original host name must be valid; nothing is retried weaker.</summary>
    public static class TlsPolicy
    {
        public static bool Accept(SslPolicyErrors e) => e == SslPolicyErrors.None;
    }

    /// <summary>How a measurement reaches the target: directly, or through the SOCKS5 port of a ByeDPI candidate on 127.0.0.1.</summary>
    public sealed class ProbeTransport
    {
        public static readonly ProbeTransport Direct = new ProbeTransport(null, 0);
        public readonly IPEndPoint Socks;
        /// <summary>The candidate process that must own the SOCKS port (0: not checked, e.g. a test server in this process).</summary>
        public readonly int OwnerPid;
        ProbeTransport(IPEndPoint socks, int ownerPid) { Socks = socks; OwnerPid = ownerPid; }
        public bool IsDirect => Socks == null;
        /// <summary>Only a loopback SOCKS5 port can be used (a candidate's own ciadpi, identified by its PID).</summary>
        public static ProbeTransport Socks5(int port, int ownerPid = 0) => new ProbeTransport(new IPEndPoint(IPAddress.Loopback, port), ownerPid);
        /// <summary>Is the port still owned by that process (read from the TCP table; replaceable in tests)?</summary>
        public static Func<int, int, bool> OwnerCheck = (port, pid) => PortOwner.OwnedBy(port, pid, out _);
        public override string ToString() => IsDirect ? "direct" : "SOCKS5 " + Socks + (OwnerPid > 0 ? " (PID " + OwnerPid + ")" : "");
    }

    /// <summary>The parts of a measurement that tests replace with controlled answers and loopback servers.</summary>
    public sealed class ProbeEnv
    {
        public Func<string, int, CancellationToken, Task<DnsAnswer>> Resolve = NetProbe.SystemResolveAsync;
        public Func<IPEndPoint, int, CancellationToken, Task<Stream>> Connect = NetProbe.TcpConnectAsync;
        public Func<Stream, string, int, CancellationToken, Task<TlsOutcome>> Tls = NetProbe.StrictTlsAsync;
        public int DnsTimeoutMs = 4000, ConnectTimeoutMs = 5000, TlsTimeoutMs = 6000, HttpTimeoutMs = 6000;
        public int MaxHeaderBytes = 16 * 1024, MaxBodyBytes = 64 * 1024;
        public int Concurrency = 4;
    }

    /// <summary>Parsed status line and headers of an HTTP/1.x response.</summary>
    public sealed class HttpHead
    {
        public int Status;
        public string Version = "";
        public readonly Dictionary<string, string> Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string, int> counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        public byte[] Rest = new byte[0];

        public string this[string name] => Headers.TryGetValue(name, out var v) ? v : null;
        /// <summary>How many times a header line came (a repeated Location or WebSocket header is not trusted).</summary>
        public int CountOf(string name) => counts.TryGetValue(name, out var n) ? n : 0;

        /// <summary>Parses the head (bytes up to and including the empty line); null if it is not a valid HTTP/1.x response.</summary>
        public static HttpHead Parse(byte[] buf, int headLen, int total)
        {
            string text;
            try { text = Encoding.ASCII.GetString(buf, 0, headLen); } catch { return null; }
            var lines = text.Split(new[] { "\r\n" }, StringSplitOptions.None);
            var first = lines[0].Split(new[] { ' ' }, 3);
            if (first.Length < 2 || !(first[0] == "HTTP/1.1" || first[0] == "HTTP/1.0")) return null;
            if (first[1].Length != 3 || !int.TryParse(first[1], out int st) || st < 100 || st > 599) return null;
            var h = new HttpHead { Status = st, Version = first[0] };
            foreach (var l in lines.Skip(1))
            {
                if (l.Length == 0) break;
                int c = l.IndexOf(':');
                if (c <= 0) return null;
                string n = l.Substring(0, c).Trim(), v = l.Substring(c + 1).Trim();
                if (n.Any(ch => ch <= 32 || ch > 126)) return null;
                h.Headers[n] = h.Headers.TryGetValue(n, out var old) ? old + ", " + v : v;
                h.counts[n] = h.CountOf(n) + 1;
            }
            h.Rest = buf.Skip(headLen).Take(total - headLen).ToArray();
            return h;
        }
    }

    public enum RedirectCheck { Ok, Missing, Repeated, Malformed, Downgrade, External }

    /// <summary>
    /// A redirect answer is read, never followed: its Location is resolved against the real request URI (https://host + path)
    /// and accepted only for HTTPS on the default port to an allowed host. A missing, repeated, malformed (control characters,
    /// backslashes, credentials, other schemes), protocol-relative external, external or HTTPS→HTTP Location is not a success.
    /// </summary>
    public static class Redirects
    {
        /// <summary>Only these are redirects (304 "not modified", 300 and 305/306 are not).</summary>
        public static readonly int[] Codes = { 301, 302, 303, 307, 308 };
        public const int MaxLocation = 2048;

        public static RedirectCheck Check(string host, string path, string location, bool repeated, Func<string, bool> allowed, out string target)
        {
            target = "";
            if (repeated) return RedirectCheck.Repeated;
            if (string.IsNullOrEmpty(location)) return RedirectCheck.Missing;
            if (location.Length > MaxLocation || location.Any(c => c <= 32 || c > 126 || c == '\\')) return RedirectCheck.Malformed;
            if (!Uri.TryCreate("https://" + host + (string.IsNullOrEmpty(path) ? "/" : path), UriKind.Absolute, out var request)) return RedirectCheck.Malformed;
            if (!Uri.TryCreate(request, location, out var u) || !u.IsAbsoluteUri || u.Host.Length == 0) return RedirectCheck.Malformed;
            if (u.UserInfo.Length > 0) return RedirectCheck.Malformed;
            target = u.Authority.ToLowerInvariant();
            if (u.Scheme == Uri.UriSchemeHttp) return RedirectCheck.Downgrade;
            if (u.Scheme != Uri.UriSchemeHttps) return RedirectCheck.Malformed;
            if (!u.IsDefaultPort || u.HostNameType != UriHostNameType.Dns) return RedirectCheck.External;
            string to = u.Host.ToLowerInvariant();
            return allowed != null && allowed(to) ? RedirectCheck.Ok : RedirectCheck.External;
        }

        /// <summary>
        /// Other targets (no explicit expectation): exactly the same host, or the same host with/without "www.". A wider
        /// "same registrable site" rule is not used: on shared domains (github.io, blogspot.com, cloudfront.net …) a sibling
        /// name belongs to someone else.
        /// </summary>
        public static bool SameSite(string host, string to)
        {
            host = (host ?? "").ToLowerInvariant();
            to = (to ?? "").ToLowerInvariant();
            if (host.Length == 0 || to.Length == 0) return false;
            return to == host || to == "www." + host || host == "www." + to;
        }
    }

    /// <summary>How an HTTP answer of a target is judged ("the server answered" is not the same as "the target works").</summary>
    public static class HttpEval
    {
        /// <summary>Judges an answer to "GET <paramref name="exp"/>.Path" (or "/").</summary>
        public static (TargetVerdict Verdict, LocText Text, string Code) Judge(string host, int status, string location, TargetExpectation exp) =>
            Judge(host, exp?.Path ?? "/", status, location, false, exp);

        public static (TargetVerdict Verdict, LocText Text, string Code) Judge(string host, string path, int status, string location, bool locationRepeated, TargetExpectation exp)
        {
            host = (host ?? "").ToLowerInvariant();
            if (status == 407) return (TargetVerdict.Fail, new LocText("scan.http.proxyAuth"), "NSF-806");
            if (status == 451) return (TargetVerdict.Fail, new LocText("scan.http.blocked", status), "NSF-501");
            if (status >= 500) return (TargetVerdict.Fail, new LocText("scan.http.serverError", status), "NSF-505");
            if (status >= 300 && status < 400)
            {
                // redirects first: a status table never accepts a redirect without its Location being checked
                if (!Redirects.Codes.Contains(status)) return (TargetVerdict.Partial, new LocText("scan.http.unclear", status), "NSF-505");
                Func<string, bool> allowed = exp != null ? (Func<string, bool>)(to => exp.RedirectHosts.Contains(to)) : to => Redirects.SameSite(host, to);
                var rc = Redirects.Check(host, path, location, locationRepeated, allowed, out string target);
                switch (rc)
                {
                    case RedirectCheck.Ok: return (TargetVerdict.Pass, new LocText("scan.http.redirectOk", status, target), "");
                    case RedirectCheck.Missing: return (TargetVerdict.Partial, new LocText("scan.http.redirectMissing", status), "NSF-505");
                    case RedirectCheck.Repeated:
                    case RedirectCheck.Malformed: return (TargetVerdict.Partial, new LocText("scan.http.redirectBad", status), "NSF-505");
                    case RedirectCheck.Downgrade: return (TargetVerdict.Partial, new LocText("scan.http.redirectDowngrade", status, target), "NSF-505");
                    default: return (TargetVerdict.Partial, new LocText("scan.http.redirectAway", status, target.Length > 0 ? target : "?"), "NSF-505");
                }
            }
            if (exp != null)
                return exp.Accepts(status)
                    ? (TargetVerdict.Pass, new LocText("scan.http.expected", status), "")
                    : (TargetVerdict.Partial, new LocText("scan.http.unexpected", status, exp.Describe()), "NSF-505");
            if (status >= 200 && status < 300) return (TargetVerdict.Pass, new LocText("scan.http.expected", status), "");
            return (TargetVerdict.Partial, new LocText("scan.http.unclear", status), "NSF-505");
        }
    }

    /// <summary>
    /// The Gateway check: a bounded WebSocket opening (RFC 6455) of the Discord Gateway address. Only "101 Switching Protocols"
    /// with Upgrade: websocket, a Connection header with the "upgrade" token, no extension or sub-protocol that was not asked
    /// for and a Sec-WebSocket-Accept made from this request's fresh key is a working "Gateway connection". No token, credentials
    /// or Identify are ever sent; the connection is closed as soon as the answer is read. It says nothing about a Discord
    /// session, voice or games.
    /// </summary>
    public static class WsHandshake
    {
        const string Magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

        public static string NewKey()
        {
            var b = new byte[16];
            using (var r = RandomNumberGenerator.Create()) r.GetBytes(b);
            return Convert.ToBase64String(b);
        }

        public static string Accept(string key)
        {
            using (var sha = SHA1.Create()) return Convert.ToBase64String(sha.ComputeHash(Encoding.ASCII.GetBytes(key + Magic)));
        }

        public static string Request(string host, string path, string key) =>
            "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: " + NetTest.UserAgent +
            "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n\r\n";

        static bool HasToken(string v, string token) =>
            (v ?? "").Split(',').Any(t => string.Equals(t.Trim(), token, StringComparison.OrdinalIgnoreCase));

        public static (TargetVerdict Verdict, LocText Text, string Code) Judge(HttpHead h, string key)
        {
            int st = h.Status;
            // a WebSocket opening is an HTTP/1.1 exchange (RFC 6455 §4.1): a 101 in any other version is not accepted
            if (st == 101 && h.Version != "HTTP/1.1") return (TargetVerdict.Fail, new LocText("scan.gateway.badHeaders"), "NSF-505");
            if (st == 101)
            {
                bool up = h.CountOf("Upgrade") == 1 && string.Equals((h["Upgrade"] ?? "").Trim(), "websocket", StringComparison.OrdinalIgnoreCase);
                bool conn = HasToken(h["Connection"], "upgrade");
                if (!up || !conn || h["Sec-WebSocket-Extensions"] != null || h["Sec-WebSocket-Protocol"] != null)
                    return (TargetVerdict.Fail, new LocText("scan.gateway.badHeaders"), "NSF-505");
                if (h.CountOf("Sec-WebSocket-Accept") != 1 || !string.Equals((h["Sec-WebSocket-Accept"] ?? "").Trim(), Accept(key), StringComparison.Ordinal))
                    return (TargetVerdict.Fail, new LocText("scan.gateway.badAccept"), "NSF-505");
                return (TargetVerdict.Pass, new LocText("scan.gateway.ok"), "");
            }
            if (st == 407) return (TargetVerdict.Fail, new LocText("scan.http.proxyAuth"), "NSF-806");
            if (st == 451) return (TargetVerdict.Fail, new LocText("scan.http.blocked", st), "NSF-501");
            if (st >= 500) return (TargetVerdict.Fail, new LocText("scan.http.serverError", st), "NSF-505");
            if (st == 429) return (TargetVerdict.Partial, new LocText("scan.gateway.rateLimited"), "NSF-505");
            return (TargetVerdict.Partial, new LocText("scan.gateway.notUpgraded", st), "NSF-505");
        }

        /// <summary>A masked close frame (1000, normal closure); best effort, the connection is closed right after it.</summary>
        public static byte[] CloseFrame()
        {
            var m = new byte[4];
            using (var r = RandomNumberGenerator.Create()) r.GetBytes(m);
            return new byte[] { 0x88, 0x82, m[0], m[1], m[2], m[3], (byte)(0x03 ^ m[0]), (byte)(0xE8 ^ m[1]) };
        }
    }

    // ======================================================================================= the probe

    /// <summary>
    /// Network measurements of the smart scanner. Every connection goes to an address that was checked to be public and is
    /// pinned to it (the name is resolved once per connection; a SOCKS5 proxy gets the address, never the name, so it cannot
    /// resolve it again); TLS uses the OS protocol policy, a full chain check and the original host name (SNI, certificate,
    /// Host header); no request is sent before that check passed. No redirects are followed, no credentials or cookies sent.
    /// </summary>
    public static class NetProbe
    {
        // ------------------------------------------------------------------ building blocks (replaceable in tests)

        public static async Task<DnsAnswer> SystemResolveAsync(string host, int timeoutMs, CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            var t = Dns.GetHostAddressesAsync(host);
            var done = await Task.WhenAny(t, Task.Delay(timeoutMs, ct)).ConfigureAwait(false);
            if (done != t)
            {
                Observe(t);
                ct.ThrowIfCancellationRequested();
                return new DnsAnswer { Status = DnsStatus.Timeout, Ms = (int)sw.ElapsedMilliseconds };
            }
            try
            {
                var a = await t.ConfigureAwait(false);
                var list = a.Where(x => x.AddressFamily == AddressFamily.InterNetwork || x.AddressFamily == AddressFamily.InterNetworkV6).ToList();
                return new DnsAnswer { Status = list.Count > 0 ? DnsStatus.Ok : DnsStatus.NoData, Addresses = list, Ms = (int)sw.ElapsedMilliseconds };
            }
            catch (SocketException se)
            {
                var st = se.SocketErrorCode == SocketError.HostNotFound ? DnsStatus.NxDomain
                       : se.SocketErrorCode == SocketError.NoData ? DnsStatus.NoData : DnsStatus.Error;
                return new DnsAnswer { Status = st, Ms = (int)sw.ElapsedMilliseconds, Detail = se.SocketErrorCode.ToString() };
            }
            catch (Exception ex) { return new DnsAnswer { Status = DnsStatus.Error, Ms = (int)sw.ElapsedMilliseconds, Detail = ex.GetType().Name }; }
        }

        public static async Task<Stream> TcpConnectAsync(IPEndPoint ep, int timeoutMs, CancellationToken ct)
        {
            var s = new Socket(ep.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                var t = Task.Factory.FromAsync(s.BeginConnect, s.EndConnect, (EndPoint)ep, null);
                using (ct.Register(() => { try { s.Close(); } catch { } }))
                {
                    if (await Task.WhenAny(t, Task.Delay(timeoutMs)).ConfigureAwait(false) != t)
                    {
                        s.Close();
                        Observe(t);
                        throw new ProbeFail(ProbeStage.Connect, "NSF-503", new LocText("scan.probe.connectTimeout"));
                    }
                    try { await t.ConfigureAwait(false); }
                    catch (Exception) when (ct.IsCancellationRequested) { throw new OperationCanceledException(ct); }
                    catch (SocketException se) { throw new ProbeFail(ProbeStage.Connect, "NSF-503", new LocText("scan.probe.connectFailed", se.SocketErrorCode.ToString())); }
                    catch (ObjectDisposedException) { throw new ProbeFail(ProbeStage.Connect, "NSF-503", new LocText("scan.probe.connectFailed", "closed")); }
                }
                ct.ThrowIfCancellationRequested();
                return new NetworkStream(s, true);
            }
            catch { try { s.Close(); } catch { } throw; }
        }

        public static async Task<TlsOutcome> StrictTlsAsync(Stream raw, string host, int timeoutMs, CancellationToken ct)
        {
            var seen = SslPolicyErrors.None;
            bool checkedCert = false;
            var ssl = new SslStream(raw, false, (s, cert, chain, errs) => { seen = errs; checkedCert = true; return TlsPolicy.Accept(errs); });
            try
            {
                var t = ssl.AuthenticateAsClientAsync(host, null, SslProtocols.None, false);
                await Bounded(t, timeoutMs, ct, () => ssl.Dispose()).ConfigureAwait(false);
                return new TlsOutcome { Ok = true, Stream = ssl };
            }
            catch (TimeoutException) { ssl.Dispose(); return new TlsOutcome { Timeout = true, Message = "timeout" }; }
            catch (OperationCanceledException) { ssl.Dispose(); throw; }
            catch (Exception ex)
            {
                ssl.Dispose();
                if (checkedCert && seen != SslPolicyErrors.None) return new TlsOutcome { CertError = true, Errors = seen, Message = seen.ToString() };
                var se = (ex as IOException)?.InnerException as SocketException;
                return new TlsOutcome { Message = se?.SocketErrorCode.ToString() ?? ex.GetType().Name };
            }
        }

        /// <summary>Waits for a task with a time limit and the cancellation; on either, <paramref name="abort"/> closes the stream.</summary>
        internal static async Task Bounded(Task t, int timeoutMs, CancellationToken ct, Action abort)
        {
            using (var cts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                var delay = Task.Delay(timeoutMs, cts.Token);
                var done = await Task.WhenAny(t, delay).ConfigureAwait(false);
                if (done != t)
                {
                    try { abort?.Invoke(); } catch { }
                    Observe(t);
                    ct.ThrowIfCancellationRequested();
                    throw new TimeoutException();
                }
                cts.Cancel();
                await t.ConfigureAwait(false);
            }
        }

        static void Observe(Task t) => t.ContinueWith(x => { var _ = x.Exception; }, TaskContinuationOptions.OnlyOnFaulted);

        static async Task<byte[]> ReadExactAsync(Stream s, int n, int timeoutMs, CancellationToken ct)
        {
            var b = new byte[n];
            int got = 0;
            while (got < n)
            {
                var t = s.ReadAsync(b, got, n - got);
                await Bounded(t, timeoutMs, ct, s.Dispose).ConfigureAwait(false);
                if (t.Result <= 0) throw new IOException("closed");
                got += t.Result;
            }
            return b;
        }

        static async Task WriteAllAsync(Stream s, byte[] b, int timeoutMs, CancellationToken ct) =>
            await Bounded(s.WriteAsync(b, 0, b.Length), timeoutMs, ct, s.Dispose).ConfigureAwait(false);

        /// <summary>
        /// SOCKS5 CONNECT to a numeric address (ATYP 1 for IPv4, 4 for IPv6 – never the name, so the proxy cannot resolve it
        /// again). A refused CONNECT is a failure of the candidate's tunnel; there is no fallback to a direct connection.
        /// </summary>
        public static async Task Socks5ConnectAsync(Stream s, IPAddress ip, int port, int timeoutMs, CancellationToken ct)
        {
            try
            {
                await WriteAllAsync(s, new byte[] { 5, 1, 0 }, timeoutMs, ct).ConfigureAwait(false);
                var m = await ReadExactAsync(s, 2, timeoutMs, ct).ConfigureAwait(false);
                if (m[0] != 5 || m[1] != 0) throw new ProbeFail(ProbeStage.Tunnel, "NSF-808", new LocText("scan.probe.socksAuth"));
                // the one SOCKS5 encoder of the app (IPv4 ATYP 1, IPv6 ATYP 4)
                await WriteAllAsync(s, ProxyTools.Socks5Connect(ip.ToString(), port), timeoutMs, ct).ConfigureAwait(false);
                var h = await ReadExactAsync(s, 4, timeoutMs, ct).ConfigureAwait(false);
                if (h[0] != 5 || h[2] != 0) throw new ProbeFail(ProbeStage.Tunnel, "NSF-808", new LocText("scan.probe.socksBad"));
                if (h[1] != 0) throw new ProbeFail(ProbeStage.Tunnel, "NSF-503", new LocText("scan.probe.socksRefused", h[1]));
                int alen = h[3] == 1 ? 4 : h[3] == 4 ? 16 : h[3] == 3 ? (await ReadExactAsync(s, 1, timeoutMs, ct).ConfigureAwait(false))[0] : -1;
                if (alen < 0) throw new ProbeFail(ProbeStage.Tunnel, "NSF-808", new LocText("scan.probe.socksBad"));
                await ReadExactAsync(s, alen + 2, timeoutMs, ct).ConfigureAwait(false);
            }
            catch (TimeoutException) { throw new ProbeFail(ProbeStage.Tunnel, "NSF-502", new LocText("scan.probe.socksTimeout")); }
            catch (IOException) when (!ct.IsCancellationRequested) { throw new ProbeFail(ProbeStage.Tunnel, "NSF-808", new LocText("scan.probe.socksClosed")); }
            catch (ObjectDisposedException) when (!ct.IsCancellationRequested) { throw new ProbeFail(ProbeStage.Tunnel, "NSF-808", new LocText("scan.probe.socksClosed")); }
        }

        /// <summary>Sends "GET path" and reads the response head (bounded); with <paramref name="body"/> also the body (bounded).</summary>
        public static async Task<(HttpHead Head, byte[] Body)> HttpGetAsync(Stream s, string host, string path, string accept, bool body, ProbeEnv env, CancellationToken ct)
        {
            if (host.Any(c => c < 33 || c > 126) || path.Any(c => c < 33 || c > 126)) throw new ArgumentException("bad request line");
            var req = "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: " + NetTest.UserAgent + "\r\nAccept: " + (accept ?? "*/*") +
                      "\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n";
            var head = await RequestHeadAsync(s, req, env, ct).ConfigureAwait(false);
            if (!body) return (head, null);
            return (head, await ReadBodyAsync(s, head, env, ct).ConfigureAwait(false));
        }

        /// <summary>
        /// The Gateway's WebSocket opening: a fresh key, the upgrade request (no credentials, token or Identify) and the bounded
        /// response head. The caller judges it with <see cref="WsHandshake.Judge"/> and closes the connection.
        /// </summary>
        public static async Task<(HttpHead Head, string Key)> WebSocketOpenAsync(Stream s, string host, string path, ProbeEnv env, CancellationToken ct)
        {
            if (host.Any(c => c < 33 || c > 126) || path.Any(c => c < 33 || c > 126)) throw new ArgumentException("bad request line");
            string key = WsHandshake.NewKey();
            var head = await RequestHeadAsync(s, WsHandshake.Request(host, path, key), env, ct).ConfigureAwait(false);
            return (head, key);
        }

        /// <summary>
        /// Time left until a stage's single deadline (the whole request head or body shares one limit: a server that sends one
        /// byte at a time cannot extend it). At the deadline the stage fails with a timeout.
        /// </summary>
        internal static int Left(DateTime deadline)
        {
            double ms = (deadline - DateTime.UtcNow).TotalMilliseconds;
            if (ms <= 0) throw new TimeoutException();
            return (int)Math.Ceiling(ms);
        }

        static async Task<HttpHead> RequestHeadAsync(Stream s, string req, ProbeEnv env, CancellationToken ct)
        {
            var deadline = DateTime.UtcNow.AddMilliseconds(env.HttpTimeoutMs);
            await WriteAllAsync(s, Encoding.ASCII.GetBytes(req), Left(deadline), ct).ConfigureAwait(false);
            var buf = new byte[env.MaxHeaderBytes + 4096];
            int got = 0, headEnd = -1;
            while (headEnd < 0)
            {
                if (got >= env.MaxHeaderBytes) throw new ProbeFail(ProbeStage.Http, "NSF-505", new LocText("scan.probe.headTooLarge"));
                var t = s.ReadAsync(buf, got, Math.Min(buf.Length - got, 4096));
                await Bounded(t, Left(deadline), ct, s.Dispose).ConfigureAwait(false);
                if (t.Result <= 0) throw new ProbeFail(ProbeStage.Http, "NSF-501", new LocText("scan.probe.httpClosed"));
                int from = Math.Max(0, got - 3);
                got += t.Result;
                for (int i = from; i + 3 < got; i++)
                    if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') { headEnd = i + 4; break; }
                if (headEnd > env.MaxHeaderBytes) throw new ProbeFail(ProbeStage.Http, "NSF-505", new LocText("scan.probe.headTooLarge"));
            }
            var head = HttpHead.Parse(buf, headEnd, got);
            if (head == null) throw new ProbeFail(ProbeStage.Http, "NSF-505", new LocText("scan.probe.notHttp"));
            return head;
        }

        static async Task<byte[]> ReadBodyAsync(Stream s, HttpHead head, ProbeEnv env, CancellationToken ct)
        {
            var ms = new MemoryStream();
            ms.Write(head.Rest, 0, head.Rest.Length);
            var tmp = new byte[8192];
            var deadline = DateTime.UtcNow.AddMilliseconds(env.HttpTimeoutMs);
            while (true)
            {
                if (ms.Length > env.MaxBodyBytes) throw new ProbeFail(ProbeStage.Http, "NSF-505", new LocText("scan.probe.bodyTooLarge"));
                var t = s.ReadAsync(tmp, 0, tmp.Length);
                try { await Bounded(t, Left(deadline), ct, s.Dispose).ConfigureAwait(false); }
                catch (IOException) { break; }
                if (t.Result <= 0) break;
                ms.Write(tmp, 0, t.Result);
            }
            var raw = ms.ToArray();
            if ((head["Transfer-Encoding"] ?? "").IndexOf("chunked", StringComparison.OrdinalIgnoreCase) >= 0) raw = Dechunk(raw, env.MaxBodyBytes);
            else if (int.TryParse(head["Content-Length"] ?? "", out int cl) && cl >= 0 && cl < raw.Length) raw = raw.Take(cl).ToArray();
            return raw;
        }

        /// <summary>Decodes a chunked body (bounded); a malformed body gives an empty result.</summary>
        public static byte[] Dechunk(byte[] raw, int max)
        {
            var o = new MemoryStream();
            int p = 0;
            while (p < raw.Length)
            {
                int eol = -1;
                for (int i = p; i + 1 < raw.Length; i++) if (raw[i] == '\r' && raw[i + 1] == '\n') { eol = i; break; }
                if (eol < 0) return new byte[0];
                string sz = Encoding.ASCII.GetString(raw, p, eol - p).Split(';')[0].Trim();
                if (!int.TryParse(sz, System.Globalization.NumberStyles.HexNumber, null, out int n) || n < 0 || n > max) return new byte[0];
                p = eol + 2;
                if (n == 0) break;
                if (p + n > raw.Length || o.Length + n > max) return new byte[0];
                o.Write(raw, p, n);
                p += n + 2;
            }
            return o.ToArray();
        }

        // ------------------------------------------------------------------ one target

        /// <summary>Opens a connection to ip:port the way the transport says (direct, or the candidate's SOCKS5 port).</summary>
        static async Task<Stream> OpenAsync(IPAddress ip, int port, ProbeTransport via, ProbeEnv env, TargetProbe r, CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            r.Stage = ProbeStage.Connect;
            if (via.IsDirect)
            {
                var s = await env.Connect(new IPEndPoint(ip, port), env.ConnectTimeoutMs, ct).ConfigureAwait(false);
                r.ConnectMs = (int)sw.ElapsedMilliseconds;
                return s;
            }
            // the candidate's port must still belong to the candidate (a port taken over after it exited is never measured)
            if (via.OwnerPid > 0 && !ProbeTransport.OwnerCheck(via.Socks.Port, via.OwnerPid))
                throw new ProbeFail(ProbeStage.Tunnel, "NSF-808", new LocText("scan.probe.socksOwner", via.Socks.Port));
            var ps = await env.Connect(via.Socks, env.ConnectTimeoutMs, ct).ConfigureAwait(false);
            r.ConnectMs = (int)sw.ElapsedMilliseconds;
            sw.Restart();
            r.Stage = ProbeStage.Tunnel;
            try { await Socks5ConnectAsync(ps, ip, port, env.ConnectTimeoutMs, ct).ConfigureAwait(false); }
            catch { ps.Dispose(); throw; }
            r.TunnelMs = (int)sw.ElapsedMilliseconds;
            return ps;
        }

        /// <summary>
        /// One HTTPS measurement of a target: system DNS (only public addresses, a mixed answer is refused), a new connection
        /// to the checked address, strict TLS for the original name, then "GET /" and the target's expectation – or, for the
        /// fixed Gateway target only, the WebSocket opening ("Gateway connection") over the same pinned, verified connection
        /// and the same transport (direct, or the candidate's SOCKS5 port; never the system proxy, never a fallback).
        /// </summary>
        public static async Task<TargetProbe> HttpsAsync(string host, ProbeTransport via, ProbeEnv env, CancellationToken ct)
        {
            var r = new TargetProbe { Host = host, Via = via.IsDirect ? "direct" : "socks", WebSocket = ScanTargets.IsGateway(host) };
            Stream s = null;
            try
            {
                var dns = await env.Resolve(host, env.DnsTimeoutMs, ct).ConfigureAwait(false);
                r.DnsMs = dns.Ms;
                if (dns.Status != DnsStatus.Ok)
                {
                    r.Detail = DnsText(dns);
                    r.Code = "NSF-401";
                    return r;
                }
                if (!IpPolicy.AllPublic(dns.Addresses, out var worst))
                {
                    r.Detail = new LocText("scan.probe.notPublic", worst.ToString(), string.Join(", ", dns.Addresses.Take(3)));
                    r.Code = "NSF-401";
                    return r;
                }
                var ip = dns.Addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? dns.Addresses[0];
                r.Ip = ip.ToString();
                s = await OpenAsync(ip, 443, via, env, r, ct).ConfigureAwait(false);

                r.Stage = ProbeStage.Tls;
                var sw = Stopwatch.StartNew();
                var tls = await env.Tls(s, host, env.TlsTimeoutMs, ct).ConfigureAwait(false);
                if (!tls.Ok)
                {
                    r.Detail = tls.CertError ? new LocText("scan.probe.certError", tls.Message) : tls.Timeout ? new LocText("scan.probe.tlsTimeout") : new LocText("scan.probe.tlsFailed", tls.Message);
                    r.Code = tls.CertError ? "NSF-504" : tls.Timeout ? "NSF-502" : "NSF-501";
                    return r;
                }
                s = tls.Stream;
                r.TlsMs = (int)sw.ElapsedMilliseconds;

                r.Stage = ProbeStage.Http;
                sw.Restart();
                var exp = ScanTargets.ExpectationFor(host);
                if (r.WebSocket)
                {
                    var (wh, key) = await WebSocketOpenAsync(s, ScanTargets.GatewayHost, ScanTargets.GatewayPath, env, ct).ConfigureAwait(false);
                    r.HttpMs = (int)sw.ElapsedMilliseconds;
                    r.Status = wh.Status;
                    r.Stage = ProbeStage.Done;
                    var (wv, wtext, wcode) = WsHandshake.Judge(wh, key);
                    r.Verdict = wv;
                    r.Detail = wtext;
                    r.Code = wcode;
                    if (wh.Status == 101)
                        try { await WriteAllAsync(s, WsHandshake.CloseFrame(), Math.Min(1000, env.HttpTimeoutMs), ct).ConfigureAwait(false); }
                        catch (Exception ign) when (!(ign is OperationCanceledException)) { }
                    return r;
                }
                var (head, _) = await HttpGetAsync(s, host, exp?.Path ?? "/", null, false, env, ct).ConfigureAwait(false);
                r.HttpMs = (int)sw.ElapsedMilliseconds;
                r.Status = head.Status;
                r.Location = head["Location"] ?? "";
                r.Stage = ProbeStage.Done;
                var (v, text, code) = HttpEval.Judge(host, exp?.Path ?? "/", head.Status, r.Location, head.CountOf("Location") > 1, exp);
                r.Verdict = v;
                r.Detail = text;
                r.Code = code;
                return r;
            }
            catch (ProbeFail pf)
            {
                r.Stage = pf.Stage;
                r.Detail = pf.Text;
                r.Code = pf.Code;
                return r;
            }
            catch (TimeoutException)
            {
                r.Detail = new LocText(r.Stage == ProbeStage.Http ? "scan.probe.httpTimeout" : "scan.probe.connectTimeout");
                r.Code = "NSF-502";
                return r;
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) when (ex is IOException || ex is ObjectDisposedException || ex is SocketException)
            {
                if (ct.IsCancellationRequested) throw new OperationCanceledException(ct);
                r.Detail = new LocText(r.Stage == ProbeStage.Http ? "scan.probe.httpClosed" : "scan.probe.connectFailed", ex.GetType().Name);
                r.Code = "NSF-501";
                return r;
            }
            finally { try { s?.Dispose(); } catch { } }
        }

        public static LocText DnsText(DnsAnswer d)
        {
            switch (d.Status)
            {
                case DnsStatus.NxDomain: return new LocText("scan.dns.nxdomain");
                case DnsStatus.NoData: return new LocText("scan.dns.nodata");
                case DnsStatus.Timeout: return new LocText("scan.dns.timeout");
                case DnsStatus.Error: return new LocText("scan.dns.error");
                default: return new LocText("scan.dns.ok", string.Join(", ", d.Addresses.Take(2)));
            }
        }
    }

    // ======================================================================================= DNS over HTTPS (JSON)

    public sealed class DohServer
    {
        public string Host, Path;
        public IPAddress[] Bootstrap;
        /// <summary>Cloudflare needs "Accept: application/dns-json".</summary>
        public bool JsonAccept;
    }

    public enum DohStatus { Ok, NxDomain, NoData, ServerFail, Invalid, Unreachable }

    public sealed class DohAnswer
    {
        public DohStatus Status;
        public List<IPAddress> Addresses = new List<IPAddress>();
        public List<string> Chain = new List<string>();
        public string Detail = "";
    }

    public sealed class DohResult
    {
        public DohStatus Status = DohStatus.Unreachable;
        public List<IPAddress> Addresses = new List<IPAddress>();
        public string Server = "";
        public int Ms;
        public string Detail = "";
        /// <summary>The answers of the two record types, kept apart (a missing AAAA answer never turns an empty A into "no data").</summary>
        public DohStatus A = DohStatus.Unreachable, Aaaa = DohStatus.Unreachable;
    }

    /// <summary>
    /// Independent reference answers over HTTPS (JSON API): https://dns.google/resolve first, https://cloudflare-dns.com/dns-query
    /// second. The servers are reached by their fixed addresses (no system DNS, no system proxy, no candidate tunnel) and their
    /// certificates are checked for their names; the answer's status, question, record types and CNAME chain are checked.
    /// </summary>
    public static class Doh
    {
        public static readonly DohServer Google = new DohServer { Host = "dns.google", Path = "/resolve", Bootstrap = new[] { IPAddress.Parse("8.8.8.8"), IPAddress.Parse("8.8.4.4") } };
        public static readonly DohServer Cloudflare = new DohServer { Host = "cloudflare-dns.com", Path = "/dns-query", Bootstrap = new[] { IPAddress.Parse("1.1.1.1"), IPAddress.Parse("1.0.0.1") }, JsonAccept = true };
        public static readonly DohServer[] Servers = { Google, Cloudflare };

        public static string RequestPath(DohServer s, string name, int type) =>
            s.Path + "?name=" + Uri.EscapeDataString(name) + "&type=" + (type == 28 ? "AAAA" : "A");

        static string Norm(string n) => (n ?? "").Trim().TrimEnd('.').ToLowerInvariant();

        /// <summary>Checks and reads one JSON answer for (name, type 1 = A / 28 = AAAA).</summary>
        public static DohAnswer Parse(string json, string name, int type)
        {
            Dictionary<string, object> root;
            try { root = new JavaScriptSerializer { MaxJsonLength = 256 * 1024 }.DeserializeObject(json) as Dictionary<string, object>; }
            catch { return new DohAnswer { Status = DohStatus.Invalid, Detail = "json" }; }
            if (root == null || !(root.TryGetValue("Status", out var stObj) && stObj is int st)) return new DohAnswer { Status = DohStatus.Invalid, Detail = "status" };
            if (!(root.TryGetValue("Question", out var qo) && qo is object[] qs && qs.Length == 1 && qs[0] is Dictionary<string, object> q &&
                  q.TryGetValue("name", out var qn) && qn is string qns && Norm(qns) == Norm(name) &&
                  q.TryGetValue("type", out var qt) && qt is int qti && qti == type))
                return new DohAnswer { Status = DohStatus.Invalid, Detail = "question" };
            if (st == 3) return new DohAnswer { Status = DohStatus.NxDomain };
            if (st != 0) return new DohAnswer { Status = DohStatus.ServerFail, Detail = "rcode " + st };
            var res = new DohAnswer { Status = DohStatus.NoData };
            var chain = new List<string> { Norm(name) };
            var answers = root.TryGetValue("Answer", out var ao) && ao is object[] arr ? arr.OfType<Dictionary<string, object>>().ToList() : new List<Dictionary<string, object>>();
            // follow the CNAME chain from the question name (bounded); records for other names are ignored
            for (int pass = 0; pass < 10; pass++)
            {
                bool grew = false;
                foreach (var a in answers)
                    if (a.TryGetValue("type", out var t) && t is int ti && ti == 5 && a.TryGetValue("name", out var n) && n is string ns &&
                        chain.Contains(Norm(ns)) && a.TryGetValue("data", out var d) && d is string ds && Hostlists.IsValidDomain(Norm(ds)) && !chain.Contains(Norm(ds)))
                    { chain.Add(Norm(ds)); grew = true; }
                if (!grew) break;
            }
            foreach (var a in answers)
            {
                if (!(a.TryGetValue("type", out var t) && t is int ti && (ti == 1 || ti == 28) && ti == type)) continue;
                if (!(a.TryGetValue("name", out var n) && n is string ns && chain.Contains(Norm(ns)))) continue;
                if (!(a.TryGetValue("data", out var d) && d is string ds && IPAddress.TryParse(ds, out var ip))) continue;
                if (ip.AddressFamily != (ti == 1 ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6)) continue;
                if (!res.Addresses.Any(x => x.Equals(ip))) res.Addresses.Add(ip);
            }
            res.Chain = chain;
            if (res.Addresses.Count > 0) res.Status = DohStatus.Ok;
            return res;
        }

        /// <summary>One query to one server (fixed address, strict TLS for its name, bounded answer).</summary>
        public static async Task<DohAnswer> QueryAsync(DohServer srv, IPAddress at, string name, int type, ProbeEnv env, CancellationToken ct)
        {
            Stream s = null;
            try
            {
                s = await env.Connect(new IPEndPoint(at, 443), env.ConnectTimeoutMs, ct).ConfigureAwait(false);
                var tls = await env.Tls(s, srv.Host, env.TlsTimeoutMs, ct).ConfigureAwait(false);
                if (!tls.Ok) return new DohAnswer { Status = DohStatus.Unreachable, Detail = tls.CertError ? "certificate: " + tls.Message : "tls: " + tls.Message };
                s = tls.Stream;
                var (head, body) = await NetProbe.HttpGetAsync(s, srv.Host, RequestPath(srv, name, type), srv.JsonAccept ? "application/dns-json" : "application/json", true, env, ct).ConfigureAwait(false);
                if (head.Status != 200) return new DohAnswer { Status = DohStatus.Unreachable, Detail = "HTTP " + head.Status };
                return Parse(Encoding.UTF8.GetString(body ?? new byte[0]), name, type);
            }
            catch (OperationCanceledException) { throw; }
            catch (ProbeFail pf) { return new DohAnswer { Status = DohStatus.Unreachable, Detail = pf.Text?.English ?? pf.Code }; }
            catch (Exception ex) { return new DohAnswer { Status = DohStatus.Unreachable, Detail = ex.GetType().Name }; }
            finally { try { s?.Dispose(); } catch { } }
        }

        /// <summary>A and AAAA of a name: Google first; Cloudflare when Google cannot be reached or answers invalidly.</summary>
        public static async Task<DohResult> ResolveAsync(string name, ProbeEnv env, CancellationToken ct, IEnumerable<DohServer> servers = null)
        {
            var sw = Stopwatch.StartNew();
            var last = new DohResult();
            foreach (var srv in servers ?? Servers)
            {
                var a = await QueryAsync(srv, srv.Bootstrap[0], name, 1, env, ct).ConfigureAwait(false);
                if (a.Status == DohStatus.Unreachable && srv.Bootstrap.Length > 1) a = await QueryAsync(srv, srv.Bootstrap[1], name, 1, env, ct).ConfigureAwait(false);
                if (a.Status == DohStatus.Unreachable || a.Status == DohStatus.Invalid)
                {
                    last = new DohResult { Status = a.Status, Server = srv.Host, Ms = (int)sw.ElapsedMilliseconds, Detail = a.Detail };
                    continue;
                }
                var r = new DohResult { Server = srv.Host, Detail = a.Detail, A = a.Status };
                if (a.Status == DohStatus.Ok || a.Status == DohStatus.NoData)
                {
                    var aaaa = await QueryAsync(srv, srv.Bootstrap[0], name, 28, env, ct).ConfigureAwait(false);
                    if (aaaa.Status == DohStatus.Unreachable && srv.Bootstrap.Length > 1) aaaa = await QueryAsync(srv, srv.Bootstrap[1], name, 28, env, ct).ConfigureAwait(false);
                    r.Aaaa = aaaa.Status;
                    r.Addresses = a.Addresses.Concat(aaaa.Status == DohStatus.Ok ? aaaa.Addresses : new List<IPAddress>()).ToList();
                    r.Status = Combine(a.Status, aaaa.Status, r.Addresses.Count);
                    if (r.Status == DohStatus.Unreachable)
                    {
                        // an empty A answer and no AAAA answer is not "no data": the next server is asked, otherwise it stays unclear
                        last = new DohResult { Status = DohStatus.Unreachable, Server = srv.Host, A = a.Status, Aaaa = aaaa.Status, Detail = "AAAA: " + aaaa.Detail };
                        continue;
                    }
                }
                else r.Status = a.Status;
                r.Ms = (int)sw.ElapsedMilliseconds;
                return r;
            }
            last.Ms = (int)sw.ElapsedMilliseconds;
            return last;
        }

        /// <summary>
        /// The result of the two record types: any address is Ok; "no data" only when both types answered without data; an empty
        /// A answer next to a missing/invalid AAAA answer stays unclear (Unreachable), never NoData.
        /// </summary>
        public static DohStatus Combine(DohStatus a, DohStatus aaaa, int addresses)
        {
            if (addresses > 0) return DohStatus.Ok;
            if (a == DohStatus.NoData && aaaa == DohStatus.NoData) return DohStatus.NoData;
            if (a == DohStatus.NoData && aaaa == DohStatus.NxDomain) return DohStatus.NoData;
            return DohStatus.Unreachable;
        }
    }

    // ======================================================================================= system DNS vs DoH

    public enum DnsVerdict { Match, DifferentPublic, Interference, NotFound, DohUnavailable, Unclear, NotPublicTarget }

    public sealed class DnsComparison
    {
        public string Host = "";
        public DnsAnswer System;
        public DohResult Doh;
        public DnsVerdict Verdict;
        /// <summary>true: the system DNS looks right; false: a sign of interference; null: cannot be said.</summary>
        public bool? Ok => Verdict == DnsVerdict.Match || Verdict == DnsVerdict.DifferentPublic ? true : Verdict == DnsVerdict.Interference ? false : (bool?)null;
        public LocText Text => new LocText("scan.dnsVerdict." + Verdict, Host);

        /// <summary>
        /// Two different public answers are normal (CDNs answer per location). A missing, empty, private or failed system answer
        /// for a name that DoH resolves to public addresses is a sign of interference. A certificate error is never a DNS verdict.
        /// </summary>
        public static DnsComparison Compare(string host, DnsAnswer sys, DohResult doh)
        {
            var c = new DnsComparison { Host = host, System = sys, Doh = doh };
            bool sysPublic = sys.Status == DnsStatus.Ok && IpPolicy.AllPublic(sys.Addresses, out _);
            if (doh == null || doh.Status == DohStatus.Unreachable || doh.Status == DohStatus.Invalid || doh.Status == DohStatus.ServerFail)
                c.Verdict = DnsVerdict.DohUnavailable;
            else if (doh.Status == DohStatus.NxDomain || doh.Status == DohStatus.NoData)
                c.Verdict = sys.Status == DnsStatus.NxDomain || sys.Status == DnsStatus.NoData ? DnsVerdict.NotFound : DnsVerdict.Unclear;
            else if (!IpPolicy.AllPublic(doh.Addresses, out _))
                c.Verdict = DnsVerdict.NotPublicTarget;
            else if (!sysPublic)
                c.Verdict = DnsVerdict.Interference;
            else
                c.Verdict = sys.Addresses.Any(a => doh.Addresses.Any(b => b.Equals(a))) ? DnsVerdict.Match : DnsVerdict.DifferentPublic;
            return c;
        }

        /// <summary>System DNS and DoH of one name (DoH is skipped when it was found unreachable before).</summary>
        public static async Task<DnsComparison> CheckAsync(string host, ProbeEnv env, CancellationToken ct, bool skipDoh = false)
        {
            var sysT = env.Resolve(host, env.DnsTimeoutMs, ct);
            var dohT = skipDoh ? Task.FromResult(new DohResult { Status = DohStatus.Unreachable, Detail = "skipped" }) : NSFShield.Doh.ResolveAsync(host, env, ct);
            await Task.WhenAll(sysT, dohT).ConfigureAwait(false);
            return Compare(host, sysT.Result, dohT.Result);
        }
    }

    // ======================================================================================= STUN (RFC 8489)

    public enum StunStatus { Ok, Timeout, Invalid, ErrorResponse, NotMeasured, DnsFailed }

    public sealed class StunResult
    {
        public StunStatus Status = StunStatus.NotMeasured;
        public int? Ms;
        public IPEndPoint Mapped;
        public string Detail = "";
        /// <summary>"na" (not on this path), "general" (plain UDP access; not in the profile's rules) or "profile".</summary>
        public string Scope = "general";
    }

    /// <summary>
    /// A STUN Binding request to stun.cloudflare.com:3478/UDP: basic UDP reachability only. The answer must come from the
    /// server's address and port and carry the magic cookie, the random 96-bit transaction id, a consistent length and
    /// attributes inside the message. It says nothing about QUIC, WebRTC or Discord voice.
    /// </summary>
    public static class Stun
    {
        public const string Host = "stun.cloudflare.com";
        public const int Port = 3478;
        const uint Cookie = 0x2112A442;

        public static byte[] NewTransactionId()
        {
            var b = new byte[12];
            using (var r = RandomNumberGenerator.Create()) r.GetBytes(b);
            return b;
        }

        public static byte[] BindingRequest(byte[] txid)
        {
            if (txid == null || txid.Length != 12) throw new ArgumentException("txid");
            var m = new byte[20];
            m[0] = 0x00; m[1] = 0x01;              // Binding request
            m[2] = 0; m[3] = 0;                    // no attributes
            m[4] = 0x21; m[5] = 0x12; m[6] = 0xA4; m[7] = 0x42;
            Buffer.BlockCopy(txid, 0, m, 8, 12);
            return m;
        }

        /// <summary>Validates an answer to the request with <paramref name="txid"/>.</summary>
        public static StunResult Parse(byte[] d, int len, byte[] txid)
        {
            StunResult Bad(string why) => new StunResult { Status = StunStatus.Invalid, Detail = why };
            if (d == null || len < 20 || len > d.Length) return Bad("short");
            if ((d[0] & 0xC0) != 0) return Bad("not stun");
            int type = (d[0] << 8) | d[1], mlen = (d[2] << 8) | d[3];
            if (mlen % 4 != 0 || 20 + mlen != len) return Bad("length");
            if (d[4] != 0x21 || d[5] != 0x12 || d[6] != 0xA4 || d[7] != 0x42) return Bad("cookie");
            for (int i = 0; i < 12; i++) if (d[8 + i] != txid[i]) return Bad("transaction id");
            if (type != 0x0101 && type != 0x0111) return Bad("type 0x" + type.ToString("x4"));
            IPEndPoint mapped = null, plain = null;
            int pos = 20, err = 0;
            while (pos < len)
            {
                if (pos + 4 > len) return Bad("attribute header");
                int at = (d[pos] << 8) | d[pos + 1], al = (d[pos + 2] << 8) | d[pos + 3];
                int next = pos + 4 + ((al + 3) & ~3);
                if (next > len) return Bad("attribute length");
                int v = pos + 4;
                if ((at == 0x0020 || at == 0x0001) && al >= 8)
                {
                    int fam = d[v + 1];
                    int port = (d[v + 2] << 8) | d[v + 3];
                    byte[] addr = null;
                    if (fam == 1 && al == 8) addr = new[] { d[v + 4], d[v + 5], d[v + 6], d[v + 7] };
                    else if (fam == 2 && al == 20) { addr = new byte[16]; Buffer.BlockCopy(d, v + 4, addr, 0, 16); }
                    if (addr == null) return Bad("address family");
                    if (at == 0x0020)
                    {
                        port ^= 0x2112;
                        var key = new byte[16];
                        key[0] = 0x21; key[1] = 0x12; key[2] = 0xA4; key[3] = 0x42;
                        Buffer.BlockCopy(txid, 0, key, 4, 12);
                        for (int i = 0; i < addr.Length; i++) addr[i] ^= key[i];
                        mapped = new IPEndPoint(new IPAddress(addr), port);
                    }
                    else plain = new IPEndPoint(new IPAddress(addr), port);
                }
                else if (at == 0x0009 && al >= 4) err = (d[v + 2] & 7) * 100 + d[v + 3];
                pos = next;
            }
            if (type == 0x0111) return new StunResult { Status = StunStatus.ErrorResponse, Detail = "error " + err };
            var ep = mapped ?? plain;
            if (ep == null) return Bad("no mapped address");
            return new StunResult { Status = StunStatus.Ok, Mapped = ep };
        }

        /// <summary>Sends the request (up to <paramref name="attempts"/> times) and waits for a valid answer from exactly that server.</summary>
        public static async Task<StunResult> BindAsync(IPEndPoint server, int timeoutMs, int attempts, CancellationToken ct)
        {
            var txid = NewTransactionId();
            var req = BindingRequest(txid);
            StunResult invalid = null;
            var sw = Stopwatch.StartNew();
            // one receive is pending per socket at any time: a retransmission keeps waiting on the same receive (a new one
            // per attempt would leave earlier receives behind that could swallow the answer)
            Task<UdpReceiveResult> pending = null;
            using (var udp = new UdpClient(server.AddressFamily))
            using (ct.Register(() => { try { udp.Close(); } catch { } }))
            try
            {
                for (int a = 0; a < attempts; a++)
                {
                    try { await udp.SendAsync(req, req.Length, server).ConfigureAwait(false); }
                    catch (Exception) when (ct.IsCancellationRequested) { throw new OperationCanceledException(ct); }
                    catch (Exception ex) { return new StunResult { Status = StunStatus.Invalid, Detail = "send: " + ex.GetType().Name }; }
                    var until = DateTime.UtcNow.AddMilliseconds(timeoutMs);
                    while (true)
                    {
                        int left = (int)(until - DateTime.UtcNow).TotalMilliseconds;
                        if (left <= 0) break;
                        if (pending == null) { pending = udp.ReceiveAsync(); Receives++; }
                        if (await Task.WhenAny(pending, Task.Delay(left, ct)).ConfigureAwait(false) != pending)
                        {
                            ct.ThrowIfCancellationRequested();
                            break;   // the same receive goes on with the next attempt
                        }
                        var rt = pending;
                        pending = null;
                        UdpReceiveResult got;
                        try { got = await rt.ConfigureAwait(false); }
                        catch (Exception) when (ct.IsCancellationRequested) { throw new OperationCanceledException(ct); }
                        catch (SocketException) { continue; }   // e.g. ICMP port unreachable from an earlier send
                        if (!got.RemoteEndPoint.Address.Equals(server.Address) || got.RemoteEndPoint.Port != server.Port)
                        {
                            invalid = new StunResult { Status = StunStatus.Invalid, Detail = "source " + got.RemoteEndPoint };
                            continue;   // a datagram from somewhere else is ignored
                        }
                        var r = Parse(got.Buffer, got.Buffer.Length, txid);
                        if (r.Status == StunStatus.Ok || r.Status == StunStatus.ErrorResponse) { r.Ms = (int)sw.ElapsedMilliseconds; return r; }
                        invalid = r;
                    }
                }
            }
            finally
            {
                // the socket is closed right after this: a receive still pending then ends with an error that is observed here
                pending?.ContinueWith(x => { var _ = x.Exception; }, TaskContinuationOptions.OnlyOnFaulted);
            }
            return invalid ?? new StunResult { Status = StunStatus.Timeout, Detail = "timeout" };
        }

        /// <summary>Receives started by <see cref="BindAsync"/> (the self-test checks that retransmissions share one).</summary>
        internal static int Receives;

        /// <summary>Resolves the server (system DNS, public addresses only, IPv4 preferred) and runs the Binding test.</summary>
        public static async Task<StunResult> CheckAsync(ProbeEnv env, CancellationToken ct, int timeoutMs = 2500)
        {
            var dns = await env.Resolve(Host, env.DnsTimeoutMs, ct).ConfigureAwait(false);
            if (dns.Status != DnsStatus.Ok || !IpPolicy.AllPublic(dns.Addresses, out _))
                return new StunResult { Status = StunStatus.DnsFailed, Detail = dns.Status.ToString() };
            var ip = dns.Addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? dns.Addresses[0];
            return await BindAsync(new IPEndPoint(ip, Port), timeoutMs, 2, ct).ConfigureAwait(false);
        }
    }
}
