using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Xml.Serialization;
using Microsoft.Win32;

namespace NSFShield
{
    public enum ProxyKind { Http, Socks5 }

    /// <summary>A saved proxy server. The password is stored with Windows DPAPI (only this user can decrypt it).</summary>
    public class ProxyEntry
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public string Name { get; set; } = "";
        public ProxyKind Kind { get; set; } = ProxyKind.Http;
        public string Host { get; set; } = "";
        public int Port { get; set; } = 8080;
        public string User { get; set; } = "";
        public string PassData { get; set; } = "";
        public string LastResult { get; set; } = "";
        public bool LastOk { get; set; }
        public DateTime? LastTest { get; set; }
        public int LastMs { get; set; }
        /// <summary>Port the local bridge listens on for this proxy (127.0.0.1).</summary>
        public int LocalPort { get; set; }

        static readonly byte[] Entropy = Encoding.UTF8.GetBytes("NSFShield.Proxy");

        [XmlIgnore]
        public string Password
        {
            get
            {
                if (string.IsNullOrEmpty(PassData)) return "";
                try { return Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(PassData), Entropy, DataProtectionScope.CurrentUser)); }
                catch { return ""; }
            }
            set
            {
                PassData = string.IsNullOrEmpty(value) ? ""
                    : Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(value), Entropy, DataProtectionScope.CurrentUser));
            }
        }

        public string Address => (Host.Contains(":") && !Host.StartsWith("[") ? "[" + Host + "]" : Host) + ":" + Port;
        public string Scheme => Kind == ProxyKind.Http ? "http" : "socks5";
        public string KindLabel => Kind == ProxyKind.Http ? "HTTP" : "SOCKS5";
        public bool HasAuth => !string.IsNullOrEmpty(User);
        public string Title => string.IsNullOrWhiteSpace(Name) ? Address : Name;
    }

    public class ProxyTestResult
    {
        public bool Reach, Tunnel, Tls, Ok, KindFixed;
        public int ConnectMs, TotalMs;
        public string ExitIp = "", Country = "", Message = "", Code = "";
    }

    sealed class ProxyFail : Exception
    {
        public readonly string Code;
        public ProxyFail(string code, string msg) : base(msg) { Code = code; }
    }

    public static class ProxyTools
    {
        // ------------------------------------------------------------ parsing

        /// <summary>
        /// Accepts the forms "1.2.3.4:8080", "http://host:port", "socks5://user:password@host:port", "host:port:user:password".
        /// </summary>
        public static bool TryParse(string text, ProxyKind defaultKind, out ProxyEntry p, out string error)
        {
            p = null;
            error = "";
            string s = (text ?? "").Trim();
            if (s.Length == 0) { error = Loc.T("proxy.parse.empty"); return false; }
            var kind = defaultKind;
            int i = s.IndexOf("://", StringComparison.Ordinal);
            if (i > 0)
            {
                // only http:// and socks5:// (socks5h://): an https:// proxy (TLS to the proxy) is not supported and is never
                // turned silently into a plain HTTP proxy that would send the password unencrypted
                string scheme = s.Substring(0, i).ToLowerInvariant();
                if (scheme == "socks5" || scheme == "socks5h") kind = ProxyKind.Socks5;
                else if (scheme == "http") kind = ProxyKind.Http;
                else if (scheme == "https") { error = Loc.T("proxy.parse.httpsUnsupported"); return false; }
                else { error = Loc.T("proxy.parse.badScheme", scheme); return false; }
                s = s.Substring(i + 3);
            }
            else if (s.IndexOf(":/", StringComparison.Ordinal) > 0 || s.StartsWith("//")) { error = Loc.T("proxy.parse.format"); return false; }
            s = s.TrimEnd('/');
            string user = "", pass = "";
            int at = s.LastIndexOf('@');
            if (at > 0)
            {
                string cred = s.Substring(0, at);
                s = s.Substring(at + 1);
                int c = cred.IndexOf(':');
                user = Uri.UnescapeDataString(c >= 0 ? cred.Substring(0, c) : cred);
                pass = c >= 0 ? Uri.UnescapeDataString(cred.Substring(c + 1)) : "";
            }
            string host;
            int port;
            if (s.StartsWith("["))
            {
                int e = s.IndexOf(']');
                if (e < 0 || e + 2 > s.Length || s[e + 1] != ':' || !int.TryParse(s.Substring(e + 2), out port)) { error = Loc.T("proxy.parse.badIpv6"); return false; }
                host = s.Substring(1, e - 1);
            }
            else
            {
                var parts = s.Split(new[] { ':', ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2 || !int.TryParse(parts[1], out port)) { error = Loc.T("proxy.parse.format"); return false; }
                host = parts[0];
                if (parts.Length >= 4 && user.Length == 0) { user = parts[2]; pass = parts[3]; }   // ip:port:user:password
            }
            if (port < 1 || port > 65535) { error = Loc.T("proxy.parse.port"); return false; }
            if (Uri.CheckHostName(host) == UriHostNameType.Unknown) { error = Loc.T("proxy.parse.badHost") + " " + host; return false; }
            p = new ProxyEntry { Kind = kind, Host = host, Port = port, User = user, Password = pass };
            return true;
        }

        /// <summary>
        /// A saved proxy that can be used: a defined type (HTTP or SOCKS5), a plain host name or IP address (no scheme such as
        /// "https://", no path) and a port. Checked when the settings are read and again before every connection.
        /// </summary>
        public static bool ValidEntry(ProxyEntry p, out string error)
        {
            error = "";
            if (p == null) { error = Loc.T("proxy.parse.empty"); return false; }
            if (!Enum.IsDefined(typeof(ProxyKind), p.Kind)) { error = Loc.T("proxy.parse.badScheme", p.Kind); return false; }
            string host = (p.Host ?? "").Trim();
            if (host.StartsWith("https:", StringComparison.OrdinalIgnoreCase)) { error = Loc.T("proxy.parse.httpsUnsupported"); return false; }
            if (host.Length == 0 || host.Contains("://") || host.IndexOfAny(new[] { '/', '\\', '@', ' ', '"' }) >= 0 || host.Any(char.IsControl) ||
                Uri.CheckHostName(host) == UriHostNameType.Unknown) { error = Loc.T("proxy.parse.badHost") + " " + ArgPolicy.CleanText(host, 60); return false; }
            if (p.Port < 1 || p.Port > 65535) { error = Loc.T("proxy.parse.port"); return false; }
            return true;
        }

        /// <summary>
        /// The SOCKS5 CONNECT request (RFC 1928) shared by the proxy test, the local bridge and the scanner: IPv4 as ATYP 1,
        /// IPv6 as ATYP 4 (16 bytes), a host name as ATYP 3 (at most 255 bytes).
        /// </summary>
        public static byte[] Socks5Connect(string host, int port)
        {
            var conn = new List<byte> { 5, 1, 0 };
            string h = (host ?? "").Trim('[', ']');
            if (IPAddress.TryParse(h, out var ip) && (ip.AddressFamily == AddressFamily.InterNetwork || ip.AddressFamily == AddressFamily.InterNetworkV6))
            {
                conn.Add((byte)(ip.AddressFamily == AddressFamily.InterNetworkV6 ? 4 : 1));
                conn.AddRange(ip.GetAddressBytes());
            }
            else
            {
                var hb = Encoding.ASCII.GetBytes(h);
                if (hb.Length == 0 || hb.Length > 255) throw new ArgumentException("host name length");
                conn.Add(3);
                conn.Add((byte)hb.Length);
                conn.AddRange(hb);
            }
            conn.Add((byte)(port >> 8));
            conn.Add((byte)port);
            return conn.ToArray();
        }

        // ------------------------------------------------------------ test

        static int Remaining(Stopwatch sw, int timeout) => Math.Max(500, timeout - (int)sw.ElapsedMilliseconds);

        static byte[] ReadExact(Stream s, int n)
        {
            var b = new byte[n];
            int got = 0;
            while (got < n)
            {
                int r = s.Read(b, got, n - got);
                if (r <= 0) throw new ProxyFail("NSF-805", Loc.T("proxy.closed"));
                got += r;
            }
            return b;
        }

        /// <summary>Opens a tunnel to host:port through the proxy.</summary>
        internal static Stream OpenTunnel(ProxyEntry p, string host, int port, int timeout, Stopwatch sw, ProxyTestResult r, out TcpClient client)
        {
            // checked again before every connection (a settings file edited by hand, an old entry)
            if (!ValidEntry(p, out string invalid)) { client = null; throw new ProxyFail("NSF-805", invalid); }
            client = new TcpClient();
            try
            {
                var t = client.ConnectAsync(p.Host, p.Port);
                if (!t.Wait(timeout)) throw new ProxyFail("NSF-805", Loc.T("proxy.noAnswer"));
            }
            catch (AggregateException ex)
            {
                var se = ex.InnerException as SocketException;
                throw new ProxyFail("NSF-805", Loc.T("proxy.connectFailed", se != null ? " (" + se.SocketErrorCode + ")" : ""));
            }
            if (r != null) { r.Reach = true; r.ConnectMs = (int)sw.ElapsedMilliseconds; }
            client.ReceiveTimeout = client.SendTimeout = Remaining(sw, timeout);
            var s = client.GetStream();

            if (p.Kind == ProxyKind.Http)
            {
                var req = new StringBuilder();
                req.Append("CONNECT " + host + ":" + port + " HTTP/1.1\r\nHost: " + host + ":" + port + "\r\n");
                if (p.HasAuth)
                    req.Append("Proxy-Authorization: Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(p.User + ":" + p.Password)) + "\r\n");
                req.Append("User-Agent: " + NetTest.UserAgent + "\r\n\r\n");
                var bytes = Encoding.ASCII.GetBytes(req.ToString());
                s.Write(bytes, 0, bytes.Length);
                // read the response headers
                var head = new StringBuilder();
                var one = new byte[1];
                while (!head.ToString().EndsWith("\r\n\r\n") && head.Length < 8192)
                {
                    if (s.Read(one, 0, 1) <= 0) throw new ProxyFail("NSF-805", Loc.T("proxy.closedMaybeSocks"));
                    head.Append((char)one[0]);
                }
                string status = head.ToString().Split('\n')[0].Trim();
                var parts = status.Split(' ');
                int code = parts.Length > 1 && int.TryParse(parts[1], out int c) ? c : 0;
                if (code == 407) throw new ProxyFail("NSF-806", Loc.T("proxy.auth407"));
                if (code != 200) throw new ProxyFail("NSF-807", Loc.T("proxy.noTunnel", host) + " " + status);
            }
            else
            {
                s.Write(p.HasAuth ? new byte[] { 5, 2, 0, 2 } : new byte[] { 5, 1, 0 }, 0, p.HasAuth ? 4 : 3);
                var hello = ReadExact(s, 2);
                if (hello[0] != 5) throw new ProxyFail("NSF-805", Loc.T("proxy.notSocks"));
                if (hello[1] == 0xFF) throw new ProxyFail("NSF-806", Loc.T("proxy.socksAuth"));
                if (hello[1] == 2)
                {
                    var u = Encoding.UTF8.GetBytes(p.User);
                    var pw = Encoding.UTF8.GetBytes(p.Password);
                    var auth = new List<byte> { 1, (byte)u.Length };
                    auth.AddRange(u);
                    auth.Add((byte)pw.Length);
                    auth.AddRange(pw);
                    s.Write(auth.ToArray(), 0, auth.Count);
                    var ar = ReadExact(s, 2);
                    if (ar[1] != 0) throw new ProxyFail("NSF-806", Loc.T("proxy.socksAuthRejected"));
                }
                var conn = Socks5Connect(host, port);
                s.Write(conn, 0, conn.Length);
                var rep = ReadExact(s, 4);
                if (rep[1] != 0)
                {
                    string[] why = { "", "", Loc.T("proxy.socks.1"), Loc.T("proxy.socks.2"), Loc.T("proxy.socks.3"), Loc.T("proxy.socks.4"), Loc.T("proxy.socks.5"), Loc.T("proxy.socks.6"), Loc.T("proxy.socks.7"), Loc.T("proxy.socks.8") };
                    throw new ProxyFail("NSF-807", Loc.T("proxy.socksConnectFailed", host, rep[1] < why.Length ? why[rep[1]] : Loc.T("proxy.socksCode", rep[1])));
                }
                int alen = rep[3] == 1 ? 4 : rep[3] == 4 ? 16 : ReadExact(s, 1)[0];
                ReadExact(s, alen + 2);
            }
            if (r != null) r.Tunnel = true;
            return s;
        }

        /// <summary>A single attempt: connection, tunnel and an encrypted connection to the target (no record/log).</summary>
        static ProxyTestResult TestOnce(ProxyEntry p, string target, int timeout)
        {
            var r = new ProxyTestResult();
            var sw = Stopwatch.StartNew();
            TcpClient client = null;
            try
            {
                var s = OpenTunnel(p, target, 443, timeout, sw, r, out client);
                using (var ssl = new SslStream(s, false, (a, b, c, e) => e == SslPolicyErrors.None))
                {
                    try { ssl.AuthenticateAsClient(target, null, SslProtocols.None, false); }
                    catch (AuthenticationException) { throw new ProxyFail("NSF-807", Loc.T("proxy.badCert", target)); }
                    catch (IOException) { throw new ProxyFail("NSF-807", Loc.T("proxy.tlsCut")); }
                    r.Tls = true;
                }
                r.TotalMs = (int)sw.ElapsedMilliseconds;
                r.Ok = true;
                r.Message = target + Loc.T("proxy.reachable", target, r.TotalMs);
            }
            catch (ProxyFail f) { r.Code = f.Code; r.Message = f.Message; }
            catch (IOException)
            {
                // If it connected but was cut during the handshake, the type is most likely wrong (HTTP ↔ SOCKS5)
                r.Code = r.Reach && !r.Tunnel ? "NSF-805" : r.Reach ? "NSF-807" : "NSF-805";
                r.Message = r.Reach && !r.Tunnel ? Loc.T("proxy.handshakeCut") : Loc.T("proxy.noAnswerOrCut");
            }
            catch (Exception ex) { r.Code = "NSF-805"; r.Message = ex.Message; }
            finally { try { client?.Close(); } catch { } }
            return r;
        }

        /// <summary>Largest answer read from the exit address service (its real answer is a few hundred bytes).</summary>
        internal const int MaxExitInfoBytes = 4096;

        /// <summary>
        /// The exit IP/country through the proxy (Cloudflare's trace page). Normal TLS validation of one.one.one.one (no
        /// certificate exception) and a small answer limit; if either fails the exit information stays unknown.
        /// </summary>
        static void FillExitInfo(ProxyEntry p, ProxyTestResult r)
        {
            TcpClient client = null;
            try
            {
                var sw2 = Stopwatch.StartNew();
                var s = OpenTunnel(p, "1.1.1.1", 443, 7000, sw2, null, out client);
                using (var ssl = new SslStream(s, false, (a, b, c, e) => TlsPolicy.Accept(e)))
                {
                    ssl.AuthenticateAsClient("one.one.one.one", null, SslProtocols.None, false);
                    var req = Encoding.ASCII.GetBytes("GET /cdn-cgi/trace HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\nUser-Agent: " + NetTest.UserAgent + "\r\n\r\n");
                    ssl.Write(req, 0, req.Length);
                    ParseExitInfo(ReadLimited(ssl, MaxExitInfoBytes), r);
                }
            }
            catch (Exception ign) { App.Ignored("Proxy exit information could not be read", ign); r.ExitIp = ""; r.Country = ""; }
            finally { try { client?.Close(); } catch { } }
        }

        /// <summary>Reads at most <paramref name="max"/> bytes (more is an error: the answer is not used).</summary>
        internal static string ReadLimited(Stream s, int max)
        {
            var ms = new MemoryStream();
            var buf = new byte[1024];
            int n;
            while ((n = s.Read(buf, 0, buf.Length)) > 0)
            {
                if (ms.Length + n > max) throw new InvalidDataException("answer too large");
                ms.Write(buf, 0, n);
            }
            return Encoding.ASCII.GetString(ms.ToArray());
        }

        /// <summary>"ip=" and "loc=" lines of the trace answer; values that are not an IP address / a two-letter code are ignored.</summary>
        internal static void ParseExitInfo(string body, ProxyTestResult r)
        {
            foreach (var raw in (body ?? "").Split('\n'))
            {
                string line = raw.Trim();
                if (line.StartsWith("ip=") && IPAddress.TryParse(line.Substring(3), out _)) r.ExitIp = line.Substring(3);
                else if (line.StartsWith("loc=") && System.Text.RegularExpressions.Regex.IsMatch(line.Substring(4), "^[A-Z]{2}$")) r.Country = line.Substring(4);
            }
        }

        /// <summary>
        /// Tests the proxy: connection, tunnel, an encrypted connection to Discord and the exit IP/country.
        /// If it connected but the handshake failed, it also tries the other type (HTTP ↔ SOCKS5) and saves the right one.
        /// </summary>
        public static ProxyTestResult Test(ProxyEntry p, string target = "discord.com", int timeout = 9000, bool exitInfo = true, bool log = true)
        {
            var r = TestOnce(p, target, timeout);
            if (!r.Ok && r.Reach && !r.Tunnel && r.Code == "NSF-805")
            {
                var other = p.Kind == ProxyKind.Http ? ProxyKind.Socks5 : ProxyKind.Http;
                var q = new ProxyEntry { Kind = other, Host = p.Host, Port = p.Port, User = p.User, PassData = p.PassData };
                var r2 = TestOnce(q, target, timeout);
                if (r2.Ok || r2.Tunnel)
                {
                    r2.KindFixed = true;
                    r2.Message += " " + Loc.T("proxy.kindFixed", q.KindLabel);
                    p.Kind = other;
                    r = r2;
                }
            }
            if (r.Ok && exitInfo) FillExitInfo(p, r);
            p.LastTest = DateTime.Now;
            p.LastOk = r.Ok;
            p.LastMs = r.Ok ? r.TotalMs : 0;
            p.LastResult = r.Ok ? Loc.T("proxy.working") + " · " + r.TotalMs + " ms" + (r.Country.Length > 0 ? " · " + r.Country : "") : r.Code + " " + r.Message;
            if (log) App.Log(TestLogLine(p, r), r.Ok ? LogLevel.Success : LogLevel.Warn);
            return r;
        }

        /// <summary>
        /// The log line of a proxy test (it names the proxy's address; the support package replaces every saved proxy's host,
        /// address, name and user name with "Proxy #n", see <see cref="Support.MaskSaved"/>).
        /// </summary>
        internal static string TestLogLine(ProxyEntry p, ProxyTestResult r) =>
            "Proxy test (" + p.KindLabel + " " + p.Address + "): " + (r.Ok ? "working, " + r.TotalMs + " ms, exit IP " + r.ExitIp + " " + r.Country : "[" + r.Code + "] " + r.Message) +
            (r.KindFixed ? " – type corrected to " + p.KindLabel + " " : "");

        /// <summary>Parses a pasted proxy list (one proxy per line; comments and empty lines are skipped).</summary>
        public static List<ProxyEntry> ParseList(string text, ProxyKind defaultKind, out int invalid)
        {
            var list = new List<ProxyEntry>();
            invalid = 0;
            foreach (var raw in (text ?? "").Split(new[] { '\r', '\n', ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#") || line.StartsWith("//")) continue;
                if (TryParse(line, defaultKind, out var p, out _))
                {
                    if (!list.Any(x => x.Host == p.Host && x.Port == p.Port)) list.Add(p);
                }
                else invalid++;
            }
            return list;
        }

        /// <summary>Tests many proxies at the same time (at most 24 in parallel).</summary>
        public static List<(ProxyEntry P, ProxyTestResult R)> BulkTest(List<ProxyEntry> items, Action<int, int> progress, CancellationToken ct)
        {
            var results = new (ProxyEntry, ProxyTestResult)[items.Count];
            int done = 0;
            var opts = new System.Threading.Tasks.ParallelOptions { MaxDegreeOfParallelism = 24, CancellationToken = ct };
            try
            {
                System.Threading.Tasks.Parallel.For(0, items.Count, opts, i =>
                {
                    var r = Test(items[i], "discord.com", 7000, exitInfo: false, log: false);
                    results[i] = (items[i], r);
                    progress?.Invoke(Interlocked.Increment(ref done), items.Count);
                });
            }
            catch (OperationCanceledException) { }
            var list = results.Where(x => x.Item1 != null).ToList();
            foreach (var x in list.Where(x => x.Item2.Ok)) FillExitInfo(x.Item1, x.Item2);
            App.Log("Bulk proxy test: " + list.Count(x => x.Item2.Ok) + "/" + items.Count + " proxies working.", LogLevel.Info);
            return list;
        }

        // ------------------------------------------------------------ Windows proxy

        const string InetKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

        [DllImport("wininet.dll", SetLastError = true)]
        static extern bool InternetSetOption(IntPtr h, int option, IntPtr buffer, int len);

        internal static void NotifyChanged()
        {
            if (App.Preview) return;   // the preview and its self-test never announce anything to Windows
            try { ProxyRecovery.Announce(); }
            catch (Exception ign) { App.Ignored("Windows proxy change could not be announced", ign); }
        }

        public static (bool Enabled, string Server) CurrentSystem() => NetTest.SystemProxy();

        /// <summary>A saved proxy, or the ByeDPI engine's local proxy (per-program rules can use it while ByeDPI runs).</summary>
        public static ProxyEntry Find(string id) =>
            id == ByeDpiNet.ProxyMarker ? ByeDpiNet.Entry : App.Settings.Proxies.FirstOrDefault(x => x.Id == id);

        /// <summary>The proxies a per-program rule can choose: the saved ones and the ByeDPI engine.</summary>
        public static List<ProxyEntry> RuleChoices() => App.Settings.Proxies.Concat(new[] { ByeDpiNet.Entry }).ToList();

        public static ProxyEntry ActiveSystemEntry()
        {
            var id = App.Settings.SystemProxyId;
            if (string.IsNullOrEmpty(id)) return null;
            var cur = CurrentSystem();
            if (!cur.Enabled) return null;
            return Find(id);
        }

        // ------------------------------------------------------------ the Windows proxy of the signed-in user (ProxyRecovery rules)

        internal const string LocalBypass = "<local>;localhost;127.*;10.*;172.16.*;192.168.*";

        /// <summary>The ProxyServer text NSF Shield writes for a proxy entry.</summary>
        public static string SystemServer(ProxyEntry p) => p.Kind == ProxyKind.Http ? p.Address : "socks=" + p.Address;

        /// <summary>
        /// Sets a saved proxy as the Windows proxy, by the same rules as the ByeDPI engine: a record of NSF Shield's earlier change
        /// is undone first; the recovery record (values before and after) and the settings marker are written and read back
        /// before Windows is changed; a failed write in the middle is undone at once. Throws (with a text for the user) when the
        /// Windows proxy was not changed.
        /// </summary>
        public static void ApplySystem(ProxyEntry p)
        {
            var s = App.Settings;
            var old = ProxyRecovery.Read();
            if (old != null)
            {
                var back = ProxyRecovery.Restore(old);
                if (back.Outcome == ProxyRecovery.Outcome.Failed) throw new IOException(Loc.T("proxy.sys.previousNotRestored", back.Error));
            }
            var live = ProxyRecovery.Live();
            if (live == null) throw new IOException(Loc.T("proxy.sys.unreadable"));
            string server = SystemServer(p);
            // a general proxy stays set across sign-ins (the user's choice): no sign-in restore
            var rec = new ProxyRecord { Owner = p.Id, AtSignIn = false, Backup = live, Written = ProxyRecovery.For(server, LocalBypass) };
            if (!ProxyRecovery.Arm(rec, null, out string armErr)) throw new IOException(Loc.T("proxy.sys.notPrepared", armErr));
            string oldId = s.SystemProxyId;
            s.SystemProxyId = p.Id;
            if (!App.TrySave())
            {
                s.SystemProxyId = oldId;
                ProxyRecovery.Drop();
                throw new IOException(Loc.T("proxy.sys.notSaved"));
            }
            if (!ProxyRecovery.WriteLive(rec.Written, out string writeErr))
            {
                var undo = ProxyRecovery.Restore(ProxyRecovery.Read() ?? rec);
                if (undo.Outcome != ProxyRecovery.Outcome.Failed) { s.SystemProxyId = ""; App.TrySave(); }
                App.Log("Windows proxy could not be set (" + writeErr + "); undo: " + undo, LogLevel.Warn);
                throw new IOException(Loc.T("proxy.sys.writeFailed", writeErr));
            }
            NotifyChanged();
            App.Problems.Clear("NSF-802");
            App.Log("Windows proxy set: " + p.KindLabel + " " + p.Address, LogLevel.Success);
        }

        /// <summary>
        /// The user turns the Windows proxy off (or a proxy entry is deleted): the values NSF Shield wrote go back to those from
        /// before, values the user changed meanwhile are kept, and everything is read back. The record is kept when that could not
        /// be verified (it can be tried again).
        /// </summary>
        public static bool RestoreSystem()
        {
            var s = App.Settings;
            var rec = ProxyRecovery.Read();
            if (rec == null)
            {
                if (!string.IsNullOrEmpty(s.SystemProxyId)) { s.SystemProxyId = ""; App.TrySave(); }
                return true;
            }
            var res = ProxyRecovery.Restore(rec);
            NotifyChanged();
            if (res.Outcome == ProxyRecovery.Outcome.Failed)
            {
                App.Log("The Windows proxy setting could not be restored exactly (" + res.Error + "); the recovery record is kept.", LogLevel.Warn);
                return false;
            }
            s.SystemProxyId = "";
            App.TrySave();
            App.Log("Windows proxy setting restored" + (res.KeptNames.Count > 0 ? "; values changed by the user were kept: " + string.Join(", ", res.KeptNames) : "") + ".", LogLevel.Info);
            return true;
        }

        /// <summary>Has NSF Shield changed the Windows proxy (a recovery record)?</summary>
        public static bool HasRecord => ProxyRecovery.RecordPresent;

        // ------------------------------------------------------------ open Discord with a proxy

        public static string ChromiumArg(ProxyEntry p) => "--proxy-server=" + p.Scheme + "://" + p.Address;

        static string DiscordUpdater(out string flavor)
        {
            flavor = "Discord";
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            foreach (var f in new[] { "Discord", "DiscordPTB", "DiscordCanary" })
            {
                string upd = Path.Combine(local, f, "Update.exe");
                if (File.Exists(upd)) { flavor = f; return upd; }
            }
            return null;
        }

        /// <summary>Creates a .lnk shortcut that starts Discord with proxy parameters.</summary>
        public static string CreateShortcut(ProxyEntry p, string path)
        {
            string upd = DiscordUpdater(out string flavor);
            if (upd == null) throw new InvalidOperationException(Loc.T("proxy.discordNotFound"));
            var t = Type.GetTypeFromProgID("WScript.Shell");
            object sh = Activator.CreateInstance(t);
            try
            {
                object lnk = t.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, sh, new object[] { path });
                var lt = lnk.GetType();
                lt.InvokeMember("TargetPath", BindingFlags.SetProperty, null, lnk, new object[] { upd });
                lt.InvokeMember("Arguments", BindingFlags.SetProperty, null, lnk,
                    new object[] { "--processStart " + flavor + ".exe --process-start-args \"" + ChromiumArg(p) + "\"" });
                lt.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, lnk, new object[] { Path.GetDirectoryName(upd) });
                string ico = Path.Combine(Path.GetDirectoryName(upd), "app.ico");
                if (File.Exists(ico)) lt.InvokeMember("IconLocation", BindingFlags.SetProperty, null, lnk, new object[] { ico });
                lt.InvokeMember("Description", BindingFlags.SetProperty, null, lnk, new object[] { "Discord – " + p.KindLabel + " proxy " + p.Address });
                lt.InvokeMember("Save", BindingFlags.InvokeMethod, null, lnk, null);
                Marshal.FinalReleaseComObject(lnk);
            }
            finally { Marshal.FinalReleaseComObject(sh); }
            return path;
        }

        /// <summary>Closes Discord and opens it again with the proxy (with normal user rights).</summary>
        public static bool LaunchDiscord(ProxyEntry p, out string message)
        {
            try
            {
                string lnk = Path.Combine(Path.GetTempPath(), "NSFShield-Discord-Proxy.lnk");
                CreateShortcut(p, lnk);
                foreach (var d in DiscordHelper.Processes()) using (d) { try { d.Kill(); } catch (Exception ign) { App.Ignored("Discord could not be closed", ign); } }
                foreach (var d in DiscordHelper.Processes()) using (d) { try { d.WaitForExit(4000); } catch { } }
                Thread.Sleep(800);
                bool ok = Sys.OpenAsUser(lnk);
                message = ok ? Loc.T("proxy.discordOpening", p.KindLabel, p.Address) : Loc.T("discord.startFailed");
                App.Log(message, ok ? LogLevel.Success : LogLevel.Warn);
                return ok;
            }
            catch (Exception ex)
            {
                message = ex.Message;
                App.Log("Discord could not be opened with the proxy: " + ex.Message, LogLevel.Warn);
                return false;
            }
        }
    }
}
