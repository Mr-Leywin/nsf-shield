using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace NSFShield
{
    public class HostResult
    {
        public string Host;
        public bool Ok;
        public int Ms;
        public string Ip = "";
        /// <summary>string or <see cref="LocText"/>; <see cref="Detail"/> renders it in the UI language.</summary>
        public object DetailValue = "";
        public string Detail { get => DetailValue?.ToString() ?? ""; set => DetailValue = value; }
        public string DetailEnglish => DetailValue is LocText l ? l.English : Detail;
        /// <summary>Related error code if it failed (NSF-5xx / NSF-401).</summary>
        public string Code = "";
        /// <summary>Is the address returned by the system DNS correct (null: not checked).</summary>
        public bool? DnsOk;
    }

    public class DnsReport
    {
        public string Host;
        public List<IPAddress> System = new List<IPAddress>();
        public List<IPAddress> Reference = new List<IPAddress>();
        public string ReferenceServer = "";
        public bool Blocked;
        public string Verdict = "";
    }

    public enum ProbeKind { Ok, ConnectFail, ConnectTimeout, Reset, Timeout, CertError, Other }

    public class ProbeResult
    {
        public string Ip = "";
        public bool TcpOk, TlsOk;
        public int TcpMs, TlsMs;
        public ProbeKind Kind = ProbeKind.Other;
        public string Message = "";

        public string Describe() => DescribeText().Text;

        public LocText DescribeText()
        {
            switch (Kind)
            {
                case ProbeKind.Ok: return new LocText("net.probe.ok", TlsMs);
                case ProbeKind.ConnectFail: return new LocText(Message.Length > 0 ? "net.probe.connectFailWhy" : "net.probe.connectFail", Message);
                case ProbeKind.ConnectTimeout: return new LocText("net.probe.connectTimeout");
                case ProbeKind.Reset: return new LocText("net.probe.reset");
                case ProbeKind.Timeout: return new LocText("net.probe.timeout");
                case ProbeKind.CertError: return new LocText("net.probe.certError", Message);
                default: return new LocText("engine.raw", Message);
            }
        }
    }

    public class SiteReport
    {
        public string Host;
        public List<IPAddress> Sys = new List<IPAddress>();
        public List<IPAddress> Ref = new List<IPAddress>();
        public string RefServer = "";
        public bool DnsPoisoned;
        public ProbeResult ProbeRef, ProbeSys;
        public HostResult Http;
        public bool ProtectionOn;
        public string Verdict = "", Advice = "", Code = "";
        public bool Ok;
    }

    public class DnsTestRow
    {
        public string Name, Server = "";
        public int Port;
        public DnsChoice Id = DnsChoice.None;
        public bool IsSystem, Answered;
        public int Ms;
        public List<IPAddress> Ips = new List<IPAddress>();
        public bool? Correct;
        public string Note = "";
    }

    public class AdapterInfo
    {
        public string Name, Description, Type, Speed, Id;
        /// <summary>IPv4 interface index (route lookups); -1 if the adapter has none.</summary>
        public int IfIndex = -1;
        public List<string> V4 = new List<string>(), V6 = new List<string>(), Gateways = new List<string>(), Dns = new List<string>();
        public bool Dhcp, IsVpn, HasGlobalV6;
    }

    public static class NetTest
    {
        public static string UserAgent => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NSFShield/" + App.Version;

        /// <summary>While the ByeDPI engine runs, the connection tests go through its local bridge (null = direct).</summary>
        public static IWebProxy EngineProxy;

        // ================================================================ HTTPS test

        public static HostResult TestHost(string host, int timeoutMs = 7000)
        {
            var r = new HostResult { Host = host };
            var sw = Stopwatch.StartNew();
            try
            {
                var uri = new Uri(host.Contains("://") ? host : "https://" + host + "/");
                try
                {
                    var ips = Dns.GetHostAddresses(uri.Host);
                    var ip = ips.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? ips.FirstOrDefault();
                    r.Ip = ip?.ToString() ?? "";
                }
                catch (SocketException)
                {
                    r.Ok = false;
                    r.DetailValue = new LocText("net.dnsFailed");
                    r.Code = "NSF-401";
                    r.Ms = (int)sw.ElapsedMilliseconds;
                    return r;
                }

                var req = (HttpWebRequest)WebRequest.Create(uri);
                req.Method = "GET";
                req.Timeout = timeoutMs;
                req.ReadWriteTimeout = timeoutMs;
                req.KeepAlive = false;
                req.ConnectionGroupName = Guid.NewGuid().ToString("N");   // every test uses a new connection
                req.AllowAutoRedirect = false;
                req.Proxy = EngineProxy;   // direct, or through the local bridge while the ByeDPI (proxy) engine runs
                req.UserAgent = UserAgent;
                req.CachePolicy = new System.Net.Cache.RequestCachePolicy(System.Net.Cache.RequestCacheLevel.NoCacheNoStore);
                using (var resp = (HttpWebResponse)req.GetResponse())
                {
                    r.Ok = true;
                    r.DetailValue = new LocText("net.reachable", (int)resp.StatusCode);
                }
            }
            catch (WebException ex) when (ex.Response is HttpWebResponse hr)
            {
                r.Ok = true;
                r.DetailValue = new LocText("net.reachable", (int)hr.StatusCode);
                try { hr.Close(); } catch { }
            }
            catch (WebException ex)
            {
                r.Ok = false;
                (r.DetailValue, r.Code) = Describe(ex);
            }
            catch (Exception ex)
            {
                r.Ok = false;
                r.Detail = ex.Message;
                r.Code = "NSF-501";
            }
            r.Ms = (int)sw.ElapsedMilliseconds;
            return r;
        }

        static (LocText, string) Describe(WebException ex)
        {
            switch (ex.Status)
            {
                case WebExceptionStatus.Timeout: return (new LocText("net.timeout"), "NSF-502");
                case WebExceptionStatus.NameResolutionFailure: return (new LocText("net.dnsFailed"), "NSF-401");
                case WebExceptionStatus.ConnectFailure: return (new LocText("net.connectFail"), "NSF-503");
                case WebExceptionStatus.ReceiveFailure:
                case WebExceptionStatus.ConnectionClosed:
                case WebExceptionStatus.SendFailure:
                case WebExceptionStatus.KeepAliveFailure:
                    return (new LocText("net.reset"), "NSF-501");
                case WebExceptionStatus.SecureChannelFailure: return (new LocText("net.tlsFailed"), "NSF-501");
                case WebExceptionStatus.TrustFailure: return (new LocText("net.certMismatch"), "NSF-504");
                default: return (new LocText("engine.raw", ex.Status + ": " + ex.Message), "NSF-501");
            }
        }

        public static async Task<List<HostResult>> TestManyAsync(IEnumerable<string> hosts, int timeoutMs = 7000)
        {
            var tasks = hosts.Select(h => Task.Run(() => TestHost(h, timeoutMs))).ToList();
            var res = await Task.WhenAll(tasks);
            return res.ToList();
        }

        // ================================================================ raw DNS query

        public static List<IPAddress> QueryA(string host, string server, int port, int timeoutMs = 2500)
        {
            var result = new List<IPAddress>();
            var serverIp = IPAddress.Parse(server);
            using (var udp = new UdpClient(serverIp.AddressFamily))
            {
                udp.Client.ReceiveTimeout = timeoutMs;
                var q = new List<byte>();
                int id = new Random(Guid.NewGuid().GetHashCode()).Next(1, 65535);
                q.Add((byte)(id >> 8)); q.Add((byte)id);
                q.Add(0x01); q.Add(0x00);                 // standard query, recursion desired
                q.AddRange(new byte[] { 0, 1, 0, 0, 0, 0, 0, 0 });
                foreach (var label in host.TrimEnd('.').Split('.'))
                {
                    var b = Encoding.ASCII.GetBytes(label);
                    q.Add((byte)b.Length);
                    q.AddRange(b);
                }
                q.Add(0);
                q.AddRange(new byte[] { 0, 1, 0, 1 });     // A, IN
                udp.Send(q.ToArray(), q.Count, new IPEndPoint(serverIp, port));
                var sw = Stopwatch.StartNew();
                while (sw.ElapsedMilliseconds < timeoutMs)
                {
                    IPEndPoint ep = null;
                    byte[] r = udp.Receive(ref ep);
                    if (r.Length < 12 || r[0] != q[0] || r[1] != q[1]) continue;   // some other answer
                    int qd = (r[4] << 8) | r[5], an = (r[6] << 8) | r[7];
                    int pos = 12;
                    for (int i = 0; i < qd; i++) { pos = SkipName(r, pos); pos += 4; }
                    for (int i = 0; i < an && pos + 10 <= r.Length; i++)
                    {
                        pos = SkipName(r, pos);
                        if (pos + 10 > r.Length) break;
                        int type = (r[pos] << 8) | r[pos + 1];
                        int rdlen = (r[pos + 8] << 8) | r[pos + 9];
                        pos += 10;
                        if (type == 1 && rdlen == 4 && pos + 4 <= r.Length)
                            result.Add(new IPAddress(new[] { r[pos], r[pos + 1], r[pos + 2], r[pos + 3] }));
                        pos += rdlen;
                    }
                    break;
                }
            }
            return result;
        }

        static int SkipName(byte[] r, int pos)
        {
            while (pos < r.Length)
            {
                int len = r[pos];
                if (len == 0) return pos + 1;
                if ((len & 0xC0) == 0xC0) return pos + 2;
                pos += len + 1;
            }
            return pos;
        }

        /// <summary>Queries while measuring the time; (false, time) if there is no answer.</summary>
        public static (bool Ok, int Ms, List<IPAddress> Ips) TimedQuery(string host, string server, int port, int timeoutMs = 2500)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                var ips = QueryA(host, server, port, timeoutMs);
                return (true, (int)sw.ElapsedMilliseconds, ips);
            }
            catch { return (false, (int)sw.ElapsedMilliseconds, new List<IPAddress>()); }
        }

        public static bool SameNet(IPAddress a, IPAddress b)
        {
            var x = a.GetAddressBytes();
            var y = b.GetAddressBytes();
            return x.Length == 4 && y.Length == 4 && x[0] == y[0] && x[1] == y[1];
        }

        public static bool Overlap(IEnumerable<IPAddress> a, IEnumerable<IPAddress> b) =>
            a.Any(x => b.Any(y => SameNet(x, y)));

        /// <summary>Asks independent DNS servers on non-53 ports at the same time; returns the union of the answers.</summary>
        public static (List<IPAddress> Ips, string Server) ReferenceLookup(string host, int timeoutMs = 2500)
        {
            var provs = DnsProviders.All.Where(p => !p.StandardPort).ToList();
            var tasks = provs.Select(p => Task.Run(() => (P: p, R: TimedQuery(host, p.V4, p.V4Port, timeoutMs)))).ToArray();
            try { Task.WaitAll(tasks); } catch { }
            var ok = tasks.Where(t => t.Status == TaskStatus.RanToCompletion && t.Result.R.Ok && t.Result.R.Ips.Count > 0)
                          .Select(t => t.Result).OrderBy(x => x.R.Ms).ToList();
            if (ok.Count == 0) return (new List<IPAddress>(), "");
            var all = ok.SelectMany(x => x.R.Ips).GroupBy(i => i.ToString()).Select(g => g.First()).ToList();
            return (all, string.Join(", ", ok.Take(2).Select(x => x.P.Name)));
        }

        public static List<IPAddress> SystemLookup(string host)
        {
            try { return Dns.GetHostAddresses(host).Where(a => a.AddressFamily == AddressFamily.InterNetwork).ToList(); }
            catch { return new List<IPAddress>(); }
        }

        public static DnsReport CheckDns(string host)
        {
            var rep = new DnsReport { Host = host };
            rep.System = SystemLookup(host);
            var (refIps, server) = ReferenceLookup(host);
            rep.Reference = refIps;
            rep.ReferenceServer = server;

            if (rep.Reference.Count == 0)
                rep.Verdict = Loc.T("net.dnsReport.noReference");
            else if (rep.System.Count == 0)
            {
                rep.Blocked = true;
                rep.Verdict = Loc.T("net.dnsReport.noAnswer");
            }
            else if (!Overlap(rep.System, rep.Reference))
            {
                rep.Blocked = true;
                rep.Verdict = Loc.T("net.dnsReport.fake");
            }
            else
                rep.Verdict = Loc.T("net.dnsReport.ok");
            return rep;
        }

        // ================================================================ TCP/TLS probe

        public static ProbeResult Probe(string host, IPAddress ip, int timeoutMs = 5000)
        {
            var r = new ProbeResult { Ip = ip?.ToString() ?? "" };
            if (ip == null) { r.Kind = ProbeKind.ConnectFail; r.Message = "no address"; return r; }
            var sw = Stopwatch.StartNew();
            using (var tcp = new TcpClient(ip.AddressFamily))
            {
                try
                {
                    var t = tcp.ConnectAsync(ip, 443);
                    if (!t.Wait(timeoutMs)) { r.Kind = ProbeKind.ConnectTimeout; return r; }
                }
                catch (AggregateException ex)
                {
                    r.Kind = ProbeKind.ConnectFail;
                    r.Message = (ex.InnerException as SocketException)?.SocketErrorCode.ToString() ?? ex.InnerException?.Message ?? "";
                    return r;
                }
                r.TcpOk = true;
                r.TcpMs = (int)sw.ElapsedMilliseconds;
                sw.Restart();
                tcp.ReceiveTimeout = tcp.SendTimeout = timeoutMs;
                SslPolicyErrors errs = SslPolicyErrors.None;
                try
                {
                    using (var ns = tcp.GetStream())
                    using (var ssl = new SslStream(ns, false, (s, cert, chain, e) => { errs = e; return true; }))
                    {
                        ns.ReadTimeout = ns.WriteTimeout = timeoutMs;
                        ssl.AuthenticateAsClient(host, null, SslProtocols.None, false);
                        r.TlsMs = (int)sw.ElapsedMilliseconds;
                        if (errs != SslPolicyErrors.None)
                        {
                            r.Kind = ProbeKind.CertError;
                            r.Message = errs.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch) ? "name mismatch" : errs.ToString();
                        }
                        else
                        {
                            r.TlsOk = true;
                            r.Kind = ProbeKind.Ok;
                        }
                    }
                }
                catch (IOException ex)
                {
                    var se = ex.InnerException as SocketException;
                    r.Kind = se != null && se.SocketErrorCode == SocketError.TimedOut ? ProbeKind.Timeout : ProbeKind.Reset;
                    r.Message = se?.SocketErrorCode.ToString() ?? ex.Message;
                }
                catch (AuthenticationException ex) { r.Kind = ProbeKind.Reset; r.Message = ex.Message; }
                catch (Exception ex) { r.Kind = ProbeKind.Other; r.Message = ex.Message; }
            }
            return r;
        }

        /// <summary>Examines step by step why a site does not open: DNS, TCP, TLS, HTTP.</summary>
        public static SiteReport AnalyzeSite(string host)
        {
            var rep = new SiteReport { Host = host, ProtectionOn = App.Engine != null && App.Engine.State == EngineState.Running };
            Native.FlushDns();
            rep.Sys = SystemLookup(host);
            var (refIps, server) = ReferenceLookup(host);
            rep.Ref = refIps;
            rep.RefServer = server;
            rep.DnsPoisoned = rep.Ref.Count > 0 && (rep.Sys.Count == 0 || !Overlap(rep.Sys, rep.Ref));

            var target = rep.Ref.FirstOrDefault() ?? rep.Sys.FirstOrDefault();
            if (target != null) rep.ProbeRef = Probe(host, target);
            if (rep.DnsPoisoned && rep.Sys.Count > 0) rep.ProbeSys = Probe(host, rep.Sys[0], 4000);
            rep.Http = TestHost(host);

            bool ipBlock = rep.ProbeRef != null && !rep.ProbeRef.TcpOk;
            bool sniBlock = rep.ProbeRef != null && rep.ProbeRef.TcpOk &&
                            (rep.ProbeRef.Kind == ProbeKind.Reset || rep.ProbeRef.Kind == ProbeKind.Timeout);
            if (rep.Http.Ok && !rep.DnsPoisoned)
            {
                rep.Ok = true;
                rep.Verdict = Loc.T("net.site.reachable");
                rep.Advice = rep.ProtectionOn ? Loc.T("net.site.okWithProtection") : Loc.T("net.site.okWithout");
            }
            else if (target == null)
            {
                rep.Verdict = Loc.T("net.site.notFound");
                rep.Advice = Loc.T("net.site.notFoundAdvice");
                rep.Code = "NSF-401";
            }
            else if (ipBlock)
            {
                rep.Verdict = Loc.T("net.site.ipBlock");
                rep.Advice = Loc.T("net.site.ipBlockAdvice");
                rep.Code = "NSF-503";
            }
            else if (rep.DnsPoisoned && sniBlock)
            {
                rep.Verdict = Loc.T("net.site.dnsAndSni");
                rep.Advice = Loc.T("net.site.dnsAndSniAdvice");
                rep.Code = rep.ProtectionOn ? "NSF-501" : "NSF-401";
            }
            else if (rep.DnsPoisoned)
            {
                rep.Verdict = Loc.T("net.site.dnsOnly");
                rep.Advice = rep.ProtectionOn
                    ? Loc.T("net.site.dnsOnlyOn")
                    : Loc.T("net.site.dnsOnlyOff");
                rep.Code = rep.ProtectionOn ? "NSF-403" : "NSF-401";
            }
            else if (sniBlock)
            {
                rep.Verdict = Loc.T("net.site.sni");
                rep.Advice = rep.ProtectionOn
                    ? Loc.T("net.site.sniOn")
                    : Loc.T("net.site.sniOff");
                rep.Code = rep.Http.Code == "NSF-502" ? "NSF-502" : "NSF-501";
            }
            else if (rep.ProbeRef != null && rep.ProbeRef.Kind == ProbeKind.CertError)
            {
                rep.Verdict = Loc.T("net.site.cert");
                rep.Advice = Loc.T("net.site.certAdvice");
                rep.Code = "NSF-504";
            }
            else
            {
                rep.Verdict = rep.Http.Ok ? Loc.T("net.site.reachable") : Loc.T("net.site.unclear");
                rep.Ok = rep.Http.Ok;
                rep.Advice = rep.Http.Ok ? Loc.T("net.site.opens") : Loc.T("net.site.httpFailed") + " " + rep.Http.Detail;
                rep.Code = rep.Http.Ok ? "" : rep.Http.Code;
            }
            return rep;
        }

        // ================================================================ DNS servers

        public static List<DnsTestRow> TestDnsServers(string host)
        {
            var rows = new List<DnsTestRow>();
            var tasks = DnsProviders.All.Select(p => Task.Run(() =>
            {
                var r = TimedQuery(host, p.V4, p.V4Port);
                return new DnsTestRow
                {
                    Name = p.Name, Server = p.V4, Port = p.V4Port, Id = p.Id,
                    Answered = r.Ok, Ms = r.Ms, Ips = r.Ips,
                };
            })).ToList();
            var sysTask = Task.Run(() =>
            {
                Native.FlushDns();
                var sw = Stopwatch.StartNew();
                var ips = SystemLookup(host);
                return new DnsTestRow { Name = Loc.T("net.dnsTest.system"), IsSystem = true, Answered = ips.Count > 0, Ms = (int)sw.ElapsedMilliseconds, Ips = ips };
            });
            try { Task.WaitAll(tasks.Cast<Task>().Concat(new[] { sysTask }).ToArray()); } catch { }
            foreach (var t in tasks) if (t.Status == TaskStatus.RanToCompletion) rows.Add(t.Result);
            if (sysTask.Status == TaskStatus.RanToCompletion) rows.Insert(0, sysTask.Result);

            // Reference: answers from non-53 ports (the provider cannot touch them)
            var reference = rows.Where(r => !r.IsSystem && r.Port != 53 && r.Answered).SelectMany(r => r.Ips).ToList();
            bool redirect = App.Engine != null && App.Engine.State == EngineState.Running && (App.Engine.ActiveProfile?.UsesDnsRedirect ?? false);
            foreach (var r in rows)
            {
                if (!r.Answered) { r.Note = Loc.T("net.dnsTest.noAnswer"); continue; }
                if (reference.Count == 0) { r.Note = Loc.T("net.dnsTest.noCompare"); continue; }
                r.Correct = r.Ips.Count > 0 && Overlap(r.Ips, reference);
                r.Note = r.Correct == true ? Loc.T("net.dnsTest.correct") : r.Ips.Count == 0 ? Loc.T("net.dnsTest.empty") : Loc.T("net.dnsTest.fake");
                if ((r.Port == 53 || r.IsSystem) && redirect)
                    r.Note += Loc.T("net.dnsTest.redirected");
            }
            return rows;
        }

        // ================================================================ general connectivity / system

        public static bool TcpReachable(string ip, int port, int timeoutMs, out int ms)
        {
            var sw = Stopwatch.StartNew();
            ms = 0;
            try
            {
                using (var c = new TcpClient(AddressFamily.InterNetwork))
                {
                    var t = c.ConnectAsync(IPAddress.Parse(ip), port);
                    bool ok = t.Wait(timeoutMs) && c.Connected;
                    ms = (int)sw.ElapsedMilliseconds;
                    return ok;
                }
            }
            catch { ms = (int)sw.ElapsedMilliseconds; return false; }
        }

        /// <summary>Is there general internet access? (Cloudflare, Google, Quad9 port 443)</summary>
        public static bool InternetOk(out int ms)
        {
            ms = 0;
            var targets = new[] { "1.1.1.1", "8.8.8.8", "9.9.9.9" };
            var tasks = targets.Select(ip => Task.Run(() => { bool ok = TcpReachable(ip, 443, 3500, out int m); return (ok, m); })).ToArray();
            try { Task.WaitAll(tasks); } catch { }
            var good = tasks.Where(t => t.Status == TaskStatus.RanToCompletion && t.Result.ok).Select(t => t.Result.m).ToList();
            if (good.Count == 0) return false;
            ms = good.Min();
            return true;
        }

        /// <summary>Difference of the computer clock from the real time (minutes). null if it cannot be measured.</summary>
        public static double? ClockSkewMinutes()
        {
            try
            {
                var req = (HttpWebRequest)WebRequest.Create("http://www.msftconnecttest.com/connecttest.txt");
                req.Timeout = 5000;
                req.Proxy = null;
                req.KeepAlive = false;
                req.UserAgent = UserAgent;
                using (var resp = (HttpWebResponse)req.GetResponse())
                {
                    string d = resp.Headers["Date"];
                    if (DateTime.TryParse(d, System.Globalization.CultureInfo.InvariantCulture,
                            System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out var server))
                        return Math.Abs((DateTime.UtcNow - server).TotalMinutes);
                }
            }
            catch (Exception ign) { App.Ignored("Server time could not be read", ign); }
            return null;
        }

        public static (bool Enabled, string Server) SystemProxy()
        {
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings"))
                {
                    if (k == null) return (false, "");
                    bool en = Convert.ToInt32(k.GetValue("ProxyEnable", 0)) != 0;
                    string server = k.GetValue("ProxyServer", "") as string ?? "";
                    string pac = k.GetValue("AutoConfigURL", "") as string ?? "";
                    if (!en && pac.Length > 0) return (true, "PAC: " + pac);
                    return (en, server);
                }
            }
            catch { return (false, ""); }
        }

        public static string HostsPath => Path.Combine(Environment.SystemDirectory, "drivers", "etc", "hosts");

        public static List<string> HostsDiscordLines()
        {
            try
            {
                return File.ReadAllLines(HostsPath)
                    .Select(l => l.Trim())
                    .Where(l => l.Length > 0 && !l.StartsWith("#") && l.IndexOf("discord", StringComparison.OrdinalIgnoreCase) >= 0)
                    .ToList();
            }
            catch { return new List<string>(); }
        }

        static readonly string[] VpnWords = { "vpn", "tap-windows", "wireguard", "wintun", "openvpn", "warp", "cloudflare", "nordlynx", "proton",
                                              "tailscale", "zerotier", "hamachi", "fortinet", "anyconnect", "pangp", "radmin", "softether", "outline" };

        public static List<AdapterInfo> Adapters()
        {
            var list = new List<AdapterInfo>();
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    var ip = ni.GetIPProperties();
                    var a = new AdapterInfo
                    {
                        Name = ni.Name, Description = ni.Description, Id = ni.Id, Type = TypeName(ni.NetworkInterfaceType),
                        Speed = ni.Speed > 0 ? (ni.Speed >= 1000000000 ? (ni.Speed / 1000000000) + " Gbit/s" : (ni.Speed / 1000000) + " Mbit/s") : "",
                    };
                    foreach (var u in ip.UnicastAddresses)
                    {
                        if (u.Address.AddressFamily == AddressFamily.InterNetwork) a.V4.Add(u.Address.ToString());
                        else if (u.Address.AddressFamily == AddressFamily.InterNetworkV6 && !u.Address.IsIPv6LinkLocal)
                        {
                            a.V6.Add(u.Address.ToString());
                            if (!u.Address.IsIPv6SiteLocal && !u.Address.ToString().StartsWith("fd", StringComparison.OrdinalIgnoreCase)) a.HasGlobalV6 = true;
                        }
                    }
                    a.Gateways = ip.GatewayAddresses.Select(g => g.Address.ToString()).Where(s => s != "0.0.0.0").ToList();
                    a.Dns = ip.DnsAddresses.Select(d => d.ToString()).Where(s => !s.StartsWith("fec0:")).ToList();
                    try { a.Dhcp = ip.GetIPv4Properties()?.IsDhcpEnabled ?? false; } catch { }
                    try { a.IfIndex = ip.GetIPv4Properties()?.Index ?? -1; } catch { }
                    string all = (a.Name + " " + a.Description).ToLowerInvariant();
                    a.IsVpn = ni.NetworkInterfaceType == NetworkInterfaceType.Ppp || VpnWords.Any(w => all.Contains(w));
                    if (a.V4.Count == 0 && a.V6.Count == 0) continue;
                    if (all.Contains("vethernet") || all.Contains("hyper-v") || all.Contains("virtualbox") || all.Contains("vmware")) continue;
                    list.Add(a);
                }
            }
            catch (Exception ign) { App.Ignored("Network adapters could not be read", ign); }
            return list;
        }

        static string TypeName(NetworkInterfaceType t)
        {
            switch (t)
            {
                case NetworkInterfaceType.Ethernet:
                case NetworkInterfaceType.GigabitEthernet:
                case NetworkInterfaceType.FastEthernetT: return Loc.T("net.adapter.wired");
                case NetworkInterfaceType.Wireless80211: return Loc.T("net.adapter.wifi");
                case NetworkInterfaceType.Ppp: return "PPP / VPN";
                case NetworkInterfaceType.Tunnel: return Loc.T("net.adapter.tunnel");
                case NetworkInterfaceType.Wwanpp:
                case NetworkInterfaceType.Wwanpp2: return Loc.T("net.adapter.mobile");
                default: return t.ToString();
            }
        }
    }
}
