#if PREVIEW
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace NSFShield
{
    /// <summary>
    /// stage 5: Gateway WebSocket check and redirect rules, the read-only conflict / anti-cheat / VPN diagnosis, the network
    /// change flow, the NSF1 profile code, the bilingual guide, self-test exit codes, release notes and the package.
    /// Offline: fake SCM/process/adapter sources, a manual clock and loopback servers only.
    /// </summary>
    static partial class SelfTest
    {
        // ============================================================================ helpers

        sealed class WsRecord { public string Request = ""; public bool CloseFrame; public int Atyp; public byte[] Addr; }

        /// <summary>A loopback server for several connections: optional SOCKS5 first, then one HTTP request and a fixed answer.</summary>
        static (int Port, List<WsRecord> Records) FakeWs(Func<string, string> answer, int connections, bool socks = false)
        {
            var l = new TcpListener(IPAddress.Loopback, 0);
            l.Start();
            int port = ((IPEndPoint)l.LocalEndpoint).Port;
            var recs = new List<WsRecord>();
            Task.Run(async () =>
            {
                try
                {
                    for (int n = 0; n < connections; n++)
                    {
                        var acc = l.AcceptTcpClientAsync();
                        if (await Task.WhenAny(acc, Task.Delay(6000)) != acc) return;
                        using (var c = acc.Result)
                        {
                            var rec = new WsRecord();
                            lock (recs) recs.Add(rec);
                            try
                            {
                                var s = c.GetStream();
                                s.ReadTimeout = 4000;
                                byte[] R(int k) { var b = new byte[k]; int g = 0; while (g < k) { int r = s.Read(b, g, k - g); if (r <= 0) throw new IOException(); g += r; } return b; }
                                if (socks)
                                {
                                    var greet = R(2); R(greet[1]);
                                    s.Write(new byte[] { 5, 0 }, 0, 2);
                                    var h = R(4);
                                    rec.Atyp = h[3];
                                    rec.Addr = h[3] == 1 ? R(4) : h[3] == 4 ? R(16) : R(R(1)[0]);
                                    R(2);
                                    s.Write(new byte[] { 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 }, 0, 10);
                                }
                                var sb = new StringBuilder();
                                var buf = new byte[4096];
                                while (sb.ToString().IndexOf("\r\n\r\n", StringComparison.Ordinal) < 0)
                                {
                                    int k = s.Read(buf, 0, buf.Length);
                                    if (k <= 0) break;
                                    sb.Append(Encoding.ASCII.GetString(buf, 0, k));
                                }
                                rec.Request = sb.ToString();
                                var ans = Encoding.ASCII.GetBytes(answer(rec.Request));
                                s.Write(ans, 0, ans.Length);
                                s.ReadTimeout = 1500;
                                try { int k = s.Read(buf, 0, buf.Length); rec.CloseFrame = k >= 2 && buf[0] == 0x88 && (buf[1] & 0x80) != 0; } catch { }
                            }
                            catch { }
                        }
                    }
                }
                finally { l.Stop(); }
            });
            return (port, recs);
        }

        static string WsKey(string req) => Regex.Match(req ?? "", @"Sec-WebSocket-Key: (\S+)").Groups[1].Value;

        static string Ws101(string req, string accept = null, string extra = "") =>
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + (accept ?? WsHandshake.Accept(WsKey(req))) + "\r\n" + extra + "\r\n";

        static ProbeEnv WsEnv(int port, List<IPEndPoint> conns) => new ProbeEnv
        {
            Resolve = Answer("162.159.135.232"),
            Connect = async (ep, t, ct) => { lock (conns) conns.Add(ep); return await NetProbe.TcpConnectAsync(new IPEndPoint(IPAddress.Loopback, port), t, ct); },
            Tls = (s, h, t, ct) => Task.FromResult(new TlsOutcome { Ok = true, Stream = s }),   // tests only: loopback speaks plain HTTP
            ConnectTimeoutMs = 3000, TlsTimeoutMs = 3000, HttpTimeoutMs = 3000,
        };

        static TargetProbe PassProbe(string h) => new TargetProbe
        {
            Host = h, Ip = "104.16.1.1", Verdict = TargetVerdict.Pass, Stage = ProbeStage.Done, ConnectMs = 5, TlsMs = 5, HttpMs = 10, Status = 200,
            Detail = new LocText("scan.http.expected", 200),
        };

        sealed class ManualDebounce : IDebounce
        {
            public long Now, Due = -1;
            public int Restarts;
            public event Action Elapsed;
            public void Restart() { Restarts++; Due = Now + NetChangeFlow.QuietMs; }
            public void Stop() => Due = -1;
            public void Advance(int ms) { Now += ms; if (Due >= 0 && Now >= Due) { Due = -1; Elapsed?.Invoke(); } }
            public void Dispose() => Due = -1;
        }

        sealed class FakeConflictSource : IConflictSource
        {
            public ConflictContext Ctx = new ConflictContext();
            public List<ProcEntry> Procs = new List<ProcEntry>();
            public Dictionary<string, ScmEntry> Services = new Dictionary<string, ScmEntry>(StringComparer.OrdinalIgnoreCase);
            public List<AdapterInfo> Ads = new List<AdapterInfo>();
            public int? Best;
            public int Calls;
            public ConflictContext Context() { Calls++; return Ctx; }
            public List<ProcEntry> Processes(IEnumerable<string> names) { var n = names.ToList(); return Procs.Where(p => n.Contains(p.Name, StringComparer.OrdinalIgnoreCase)).ToList(); }
            public ScmEntry Service(string name) => Services.TryGetValue(name, out var e) ? e : new ScmEntry { Name = name, Read = ScmRead.NotFound, Win32Error = 1060 };
            public List<AdapterInfo> Adapters() => Ads;
            public int? BestRouteIndex() => Best;
        }

        const string Own = @"C:\Program Files\NSF Shield";
        static ScmEntry Svc(string name, uint type, uint state, string image = "") => new ScmEntry { Name = name, Read = ScmRead.Ok, Type = type, State = state, ImagePath = image };
        static ScmEntry Denied(string name) => new ScmEntry { Name = name, Read = ScmRead.AccessDenied, Win32Error = 5 };

        static FakeConflictSource BaseSource()
        {
            var f = new FakeConflictSource();
            f.Ctx.BaseDir = Own;
            f.Ctx.OwnExes.Add(Own + @"\bin\x86_64\goodbyedpi.exe");
            f.Ctx.OwnExes.Add(Own + @"\bin\zapret\winws.exe");
            f.Ctx.OwnExes.Add(Own + @"\bin\byedpi\ciadpi.exe");
            f.Ctx.ByeDpiAvailable = true;
            return f;
        }

        static bool WaitFor(Func<bool> cond, int ms = 4000)
        {
            var sw = Stopwatch.StartNew();
            while (sw.ElapsedMilliseconds < ms) { if (cond()) return true; Thread.Sleep(25); }
            return cond();
        }

        // ============================================================================ the tests

        static void Stage5Tests(Action<string, bool, string> Check)
        {
            var oldSettings = App.Settings;
            var oldEngine = App.Engine;
            var oldSource = Conflicts.Source;
            App.Settings = new AppSettings();
            App.Settings.Normalize();
            if (App.Engine == null) App.Engine = new Engine();
            string repo = Repo;
            string root = Path.Combine(Path.GetTempPath(), "nsf stage5 " + Guid.NewGuid().ToString("N").Substring(0, 6));
            try
            {
                var ctx = SynchronizationContext.Current;
                SynchronizationContext.SetSynchronizationContext(null);
                Gateway5(Check);
                Redirect5(Check);
                Diag5(Check);
                Net5(Check);
                Share5(Check, repo);
                Guide5(Check, repo, root);
                Build5(Check, repo, root);
                SynchronizationContext.SetSynchronizationContext(ctx);
                // last: building pages and the main window installs a WinForms context on this thread
                Ui5(Check);
                SynchronizationContext.SetSynchronizationContext(null);
            }
            catch (Exception ex) { Check("stage 5 tests ran without an exception", false, ex.GetType().Name + ": " + ex.Message + " @ " + (ex.StackTrace ?? "").Split('\n').FirstOrDefault()?.Trim()); }
            finally
            {
                Conflicts.Source = oldSource;
                Conflicts.DebugSet(null);
                App.Settings = oldSettings;
                App.Engine = oldEngine;
                try { Directory.Delete(root, true); } catch { }
            }
        }

        // ---------------------------------------------------------------------------- Gateway (WebSocket opening)
        static void Gateway5(Action<string, bool, string> Check)
        {
            Check("gateway: the accept value of RFC 6455 is computed from the key", WsHandshake.Accept("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", "");
            var exp = ScanTargets.ExpectationFor(ScanTargets.GatewayHost);
            Check("gateway: the fixed target uses the WebSocket opening (not \"GET /\") and accepts only 101",
                  exp.WebSocket && exp.Path == "/?v=10&encoding=json" && exp.Statuses.SequenceEqual(new[] { 101 }) && ScanTargets.ExpectationFor("discord.com").WebSocket == false, exp.Path);

            var conns = new List<IPEndPoint>();
            var ok = FakeWs(r => Ws101(r) + "\u0081\u0005hello", 2);
            var p1 = NetProbe.HttpsAsync("gateway.discord.gg", ProbeTransport.Direct, WsEnv(ok.Port, conns), CancellationToken.None).Result;
            var p2 = NetProbe.HttpsAsync("gateway.discord.gg", ProbeTransport.Direct, WsEnv(ok.Port, conns), CancellationToken.None).Result;
            WaitFor(() => { lock (ok.Records) return ok.Records.Count == 2 && ok.Records.All(x => x.Request.Length > 0); });
            var req = ok.Records.FirstOrDefault()?.Request ?? "";
            Check("gateway: a valid 101 with Upgrade, Connection and the right accept value is a \"Gateway connection\" (Pass)",
                  p1.Verdict == TargetVerdict.Pass && p1.WebSocket && p1.Status == 101 && p1.Detail?.Key == "scan.gateway.ok" && p1.Layers.Contains("WS 101") && p1.TotalMs.HasValue,
                  p1.Layers + " " + p1.Detail?.English);
            Check("gateway: the request is a bounded WebSocket opening of /?v=10&encoding=json for the original host name",
                  req.StartsWith("GET /?v=10&encoding=json HTTP/1.1\r\n") && req.Contains("\r\nHost: gateway.discord.gg\r\n") && req.Contains("\r\nUpgrade: websocket\r\n") &&
                  req.Contains("\r\nConnection: Upgrade\r\n") && req.Contains("\r\nSec-WebSocket-Version: 13\r\n") && Convert.FromBase64String(WsKey(req)).Length == 16, req.Split('\r')[0]);
            Check("gateway: no credentials, token, cookie, origin or Identify payload is ever sent",
                  ok.Records.All(r => r.Request.IndexOf("Authorization", StringComparison.OrdinalIgnoreCase) < 0 && r.Request.IndexOf("token", StringComparison.OrdinalIgnoreCase) < 0 &&
                                      r.Request.IndexOf("Cookie", StringComparison.OrdinalIgnoreCase) < 0 && r.Request.IndexOf("identify", StringComparison.OrdinalIgnoreCase) < 0 &&
                                      r.Request.EndsWith("\r\n\r\n")), "");
            Check("gateway: every opening uses a fresh key", ok.Records.Count == 2 && WsKey(ok.Records[0].Request) != WsKey(ok.Records[1].Request), "");
            Check("gateway: the connection goes to the checked public address on 443 (pinned) and is closed after the answer (close frame)",
                  conns.Count == 2 && conns.All(e => e.Address.ToString() == "162.159.135.232" && e.Port == 443) && ok.Records.All(r => r.CloseFrame) && p2.Verdict == TargetVerdict.Pass, "");

            foreach (var (name, answer, want, key) in new (string, Func<string, string>, TargetVerdict, string)[]
            {
                ("a 101 with the accept value of another (stale) key", r => Ws101(r, WsHandshake.Accept("dGhlIHNhbXBsZSBub25jZQ==")), TargetVerdict.Fail, "scan.gateway.badAccept"),
                ("a 101 without the accept header", r => "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", TargetVerdict.Fail, "scan.gateway.badAccept"),
                ("a 101 without the Upgrade header", r => "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + WsHandshake.Accept(WsKey(r)) + "\r\n\r\n", TargetVerdict.Fail, "scan.gateway.badHeaders"),
                ("a 101 with Connection: keep-alive", r => Ws101(r).Replace("Connection: Upgrade", "Connection: keep-alive"), TargetVerdict.Fail, "scan.gateway.badHeaders"),
                ("a 101 with an extension that was not asked for", r => Ws101(r, null, "Sec-WebSocket-Extensions: permessage-deflate\r\n"), TargetVerdict.Fail, "scan.gateway.badHeaders"),
                ("a 101 with the accept header twice", r => Ws101(r, null, "Sec-WebSocket-Accept: " + WsHandshake.Accept(WsKey(r)) + "\r\n"), TargetVerdict.Fail, "scan.gateway.badAccept"),
                ("426 (the old expectation) is no longer a success", r => "HTTP/1.1 426 Upgrade Required\r\nContent-Length: 0\r\n\r\n", TargetVerdict.Partial, "scan.gateway.notUpgraded"),
                ("403 is not raised to a success", r => "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n", TargetVerdict.Partial, "scan.gateway.notUpgraded"),
                ("429 is not raised to a success", r => "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n", TargetVerdict.Partial, "scan.gateway.rateLimited"),
                ("200 (a plain page) is not a Gateway connection", r => "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", TargetVerdict.Partial, "scan.gateway.notUpgraded"),
                ("407 (proxy authentication) fails", r => "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n", TargetVerdict.Fail, "scan.http.proxyAuth"),
                ("451 fails", r => "HTTP/1.1 451 Unavailable For Legal Reasons\r\nContent-Length: 0\r\n\r\n", TargetVerdict.Fail, "scan.http.blocked"),
                ("503 fails", r => "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n", TargetVerdict.Fail, "scan.http.serverError"),
            })
            {
                var srv = FakeWs(answer, 1);
                var x = NetProbe.HttpsAsync("gateway.discord.gg", ProbeTransport.Direct, WsEnv(srv.Port, new List<IPEndPoint>()), CancellationToken.None).Result;
                Check("gateway: " + name + " → " + want, x.Verdict == want && x.Detail?.Key == key && x.WebSocket, x.Verdict + " " + x.Detail?.Key);
            }

            // through a ByeDPI candidate's SOCKS5 port: the same check, the checked address, never a direct fallback
            var socksSrv = FakeWs(r => Ws101(r), 1, socks: true);
            var sconns = new List<IPEndPoint>();
            var viaSocks = NetProbe.HttpsAsync("gateway.discord.gg", ProbeTransport.Socks5(socksSrv.Port), PlainEnv(Answer("162.159.135.232"), sconns, true), CancellationToken.None).Result;
            WaitFor(() => { lock (socksSrv.Records) return socksSrv.Records.Count == 1 && socksSrv.Records[0].Request.Length > 0; });
            var srec = socksSrv.Records.FirstOrDefault();
            Check("gateway: through the candidate's SOCKS5 port the tunnel gets the checked address (ATYP 1, 443) and the opening passes",
                  viaSocks.Verdict == TargetVerdict.Pass && viaSocks.Via == "socks" && srec != null && srec.Atyp == 1 && new IPAddress(srec.Addr).ToString() == "162.159.135.232" &&
                  sconns.All(e => IPAddress.IsLoopback(e.Address)), viaSocks.Layers);
            var refused = FakeSocks(5);
            sconns.Clear();
            var viaRefused = NetProbe.HttpsAsync("gateway.discord.gg", ProbeTransport.Socks5(refused.Port), PlainEnv(Answer("162.159.135.232"), sconns, true), CancellationToken.None).Result;
            refused.Done.Wait(3000);
            Check("gateway: a refused tunnel fails the candidate; no direct connection, no other proxy",
                  viaRefused.Verdict == TargetVerdict.Fail && viaRefused.Stage == ProbeStage.Tunnel && sconns.Count == 1 && sconns.All(e => IPAddress.IsLoopback(e.Address)), viaRefused.Detail?.English);
            var rec = new RecordingStream();
            var envCert = new ProbeEnv
            {
                Resolve = Answer("162.159.135.232"),
                Connect = (ep, t, ct) => Task.FromResult<Stream>(rec),
                Tls = (s2, h, t, ct) => Task.FromResult(new TlsOutcome { CertError = true, Errors = System.Net.Security.SslPolicyErrors.RemoteCertificateNameMismatch, Message = "RemoteCertificateNameMismatch" }),
            };
            var cert = NetProbe.HttpsAsync("gateway.discord.gg", ProbeTransport.Direct, envCert, CancellationToken.None).Result;
            Check("gateway: a TLS certificate error stops before any WebSocket byte (NSF-504)", cert.Stage == ProbeStage.Tls && cert.Code == "NSF-504" && rec.Writes == 0 && cert.Verdict == TargetVerdict.Fail, cert.Code);
            var priv = NetProbe.HttpsAsync("gateway.discord.gg", ProbeTransport.Direct, PlainEnv(Answer("10.0.0.7"), sconns, false), CancellationToken.None).Result;
            Check("gateway: a private DNS answer is never contacted", priv.Stage == ProbeStage.Dns && priv.Detail?.Key == "scan.probe.notPublic", "");
            var slow = FakeRaw(new byte[0], 3000);
            var envSlow = WsEnv(slow.Port, new List<IPEndPoint>());
            envSlow.HttpTimeoutMs = 600;
            var sw = Stopwatch.StartNew();
            var timeout = NetProbe.HttpsAsync("gateway.discord.gg", ProbeTransport.Direct, envSlow, CancellationToken.None).Result;
            Check("gateway: a server that never answers ends at the time limit", timeout.Verdict == TargetVerdict.Fail && timeout.Code == "NSF-502" && sw.ElapsedMilliseconds < 3000, sw.ElapsedMilliseconds + " ms");

            // two rounds through the scanner: a wrong Gateway answer never reaches a full score or an automatic apply
            foreach (var (name, answer, full) in new (string, Func<string, string>, bool)[]
            {
                ("426", r => "HTTP/1.1 426 Upgrade Required\r\nContent-Length: 0\r\n\r\n", false),
                ("a 101 with a wrong accept value", r => Ws101(r, "AAAAAAAAAAAAAAAAAAAAAAAAAAA="), false),
                ("a valid 101 (control)", r => Ws101(r), true),
            })
            {
                var srv = FakeWs(answer, 6);
                var host = new FakeHost();
                host.ProbeFn = (h, via, ct) => h == ScanTargets.GatewayHost ? NetProbe.HttpsAsync(h, via, WsEnv(srv.Port, new List<IPEndPoint>()), ct) : Task.FromResult(PassProbe(h));
                var reqS = ScanRequest.Create(ScanScope.AllEngines, ScanMode.StopOnFirstMatch, true, new[] { "zapret-discord" }, new[] { "discord.com", "gateway.discord.gg" }, udp: false);
                var o = RunScan(reqS, host);
                var row = o.Rows.FirstOrDefault();
                bool okRun = row != null && (full ? row.IsFull && row.Score == 100 && o.Applied != null && host.Applies == 1
                                                  : !row.IsFull && row.Score == 50 && o.Applied == null && host.Applies == 0 && row.Status == ScanRow.Partial);
                Check("gateway: two rounds with " + name + (full ? " reach a full score and are applied" : " never reach a full score or an automatic apply"),
                      okRun, row == null ? "no row" : row.Status + " " + row.Score + "% applied=" + (o.Applied?.Id ?? "-"));
            }
        }

        // ---------------------------------------------------------------------------- redirects
        static void Redirect5(Action<string, bool, string> Check)
        {
            foreach (var (host, status, loc, want, key) in new[]
            {
                ("discord.com", 301, "https://discord.com/app", TargetVerdict.Pass, "scan.http.redirectOk"),
                ("discord.com", 302, "/login", TargetVerdict.Pass, "scan.http.redirectOk"),
                ("discord.com", 307, "login?next=1", TargetVerdict.Pass, "scan.http.redirectOk"),
                ("discord.com", 308, "../app", TargetVerdict.Pass, "scan.http.redirectOk"),
                ("discord.com", 302, "", TargetVerdict.Partial, "scan.http.redirectMissing"),
                ("discord.com", 302, "https://evil.example.net/", TargetVerdict.Partial, "scan.http.redirectAway"),
                ("discord.com", 302, "//evil.example.net/x", TargetVerdict.Partial, "scan.http.redirectAway"),
                ("discord.com", 301, "http://discord.com/", TargetVerdict.Partial, "scan.http.redirectDowngrade"),
                ("discord.com", 302, "https://discord.com:8443/", TargetVerdict.Partial, "scan.http.redirectAway"),
                ("discord.com", 302, "https://discord.com@evil.example.net/", TargetVerdict.Partial, "scan.http.redirectBad"),
                ("discord.com", 302, "/\\evil.example.net", TargetVerdict.Partial, "scan.http.redirectBad"),
                ("discord.com", 302, "https://discord.com/\r\nX-A: b", TargetVerdict.Partial, "scan.http.redirectBad"),
                ("discord.com", 302, "javascript:alert(1)", TargetVerdict.Partial, "scan.http.redirectBad"),
                ("discord.com", 302, "https://1.2.3.4/", TargetVerdict.Partial, "scan.http.redirectAway"),
                ("discord.com", 304, "", TargetVerdict.Partial, "scan.http.unclear"),
                ("discord.com", 300, "https://discord.com/", TargetVerdict.Partial, "scan.http.unclear"),
                ("discordapp.com", 301, "https://discord.com/", TargetVerdict.Pass, "scan.http.redirectOk"),
                ("cdn.discordapp.com", 302, "https://discord.com/", TargetVerdict.Partial, "scan.http.redirectAway"),
                ("cdn.discordapp.com", 403, "", TargetVerdict.Pass, "scan.http.expected"),
                ("example.org", 302, "https://www.example.org/", TargetVerdict.Pass, "scan.http.redirectOk"),
                ("example.org", 302, "https://example.org.evil.net/", TargetVerdict.Partial, "scan.http.redirectAway"),
                ("example.org", 308, "ftp://example.org/", TargetVerdict.Partial, "scan.http.redirectBad"),
                ("example.org", 404, "", TargetVerdict.Partial, "scan.http.unclear"),
            })
            {
                var v = HttpEval.Judge(host, status, loc, ScanTargets.ExpectationFor(host));
                Check("redirect: " + host + " " + status + (loc.Length > 0 ? " → " + loc.Replace("\r\n", "\\r\\n") : "") + " is " + want, v.Verdict == want && v.Text.Key == key, v.Verdict + " " + v.Text.Key);
            }
            var rep = HttpEval.Judge("discord.com", "/", 302, "/a, /b", true, ScanTargets.ExpectationFor("discord.com"));
            Check("redirect: a repeated Location header is not trusted", rep.Verdict == TargetVerdict.Partial && rep.Text.Key == "scan.http.redirectBad", rep.Text.Key);
            byte[] B(string t) => Encoding.ASCII.GetBytes(t);
            string twoText = "HTTP/1.1 302 Found\r\nLocation: /a\r\nLocation: https://evil.example.net/\r\n\r\n";
            var two = HttpHead.Parse(B(twoText), twoText.Length, twoText.Length);
            Check("redirect: the response head counts repeated headers", two != null && two.CountOf("location") == 2 && two.CountOf("x") == 0, "");
            var srv = FakeRaw(B("HTTP/1.1 302 Found\r\nLocation: /a\r\nLocation: /b\r\nContent-Length: 0\r\n\r\n"));
            var conns = new List<IPEndPoint>();
            var env = WsEnv(srv.Port, conns);
            env.Resolve = Answer("104.16.1.1");
            var x = NetProbe.HttpsAsync("discord.com", ProbeTransport.Direct, env, CancellationToken.None).Result;
            Check("redirect: the probe reads the answer once and does not follow the redirect", x.Verdict == TargetVerdict.Partial && x.Detail?.Key == "scan.http.redirectBad" && conns.Count == 1, x.Detail?.Key);
        }

        // ---------------------------------------------------------------------------- conflict / anti-cheat / VPN diagnosis
        static void Diag5(Action<string, bool, string> Check)
        {
            var f = BaseSource();
            f.Ctx.OwnPids.Add(100);
            f.Ctx.TrialPids.Add(200);
            ProcEntry P(string name, int pid, string path, bool denied = false) => new ProcEntry { Name = name, Pid = pid, Path = path, AccessDenied = denied };
            var cases = new (ProcEntry Proc, ProcOwner Want, string Why)[]
            {
                (P("winws", 100, Own + @"\bin\zapret\winws.exe"), ProcOwner.Own, "diag.owner.own"),
                (P("winws", 200, Own + @"\bin\zapret\winws.exe"), ProcOwner.ScanCandidate, "diag.owner.candidate"),
                (P("winws", 300, Own + @"\bin\zapret\winws.exe"), ProcOwner.Unknown, "diag.owner.ownFileUnknownPid"),
                (P("winws", 100, @"D:\other copy\NSF Shield\bin\zapret\winws.exe"), ProcOwner.OtherInstall, "diag.owner.other"),
                (P("goodbyedpi", 400, Own + @"\bin\x86_64-copy\goodbyedpi.exe"), ProcOwner.OtherInstall, "diag.owner.other"),
                (P("winws", 410, Own + @"\bin\zapret\..\zapret2\winws.exe"), ProcOwner.OtherInstall, "diag.owner.other"),
                (P("goodbyedpi", 500, null, true), ProcOwner.Unknown, "diag.owner.denied"),
                (P("goodbyedpi", 501, null), ProcOwner.Unknown, "diag.owner.unreadable"),
            };
            foreach (var (proc, want, why) in cases)
            {
                var o = Conflicts.Classify(proc, f.Ctx, out var w);
                Check("owner: " + proc.Name + " PID " + proc.Pid + " " + (proc.Path ?? "(unreadable)").Replace(Own, "<install>") + " is " + want, o == want && w.Key == why, o + " " + w.Key);
            }
            Check("owner: neither the name nor the folder prefix alone is proof (a copy inside the own folder tree is not ours)",
                  Conflicts.Classify(P("winws", 100, Own + @"\bin\zapret-old\winws.exe"), f.Ctx, out _) == ProcOwner.OtherInstall, "");

            // a scan that cannot be told apart is deferred; a clear one is not
            var fs = BaseSource();
            fs.Ctx.ScanBusy = true;
            fs.Ctx.TrialPids.Add(200);
            fs.Procs.Add(P("winws", 200, Own + @"\bin\zapret\winws.exe"));
            var r1 = Conflicts.Evaluate(fs);
            fs.Procs.Add(P("winws", 201, Own + @"\bin\zapret\winws.exe"));
            var r2 = Conflicts.Evaluate(fs);
            Check("owner: during a scan the candidate is told apart; an unknown process defers the diagnosis until the scan ends",
                  !r1.Deferred && r1.Processes.Single().Owner == ProcOwner.ScanCandidate && r2.Deferred && r2.WinDivert.Count == 0, "");

            // WinDivert entries: every one, read only, the different results kept apart
            var fw = BaseSource();
            fw.Services["WinDivert"] = Svc("WinDivert", 1, 4, @"\??\" + Own + @"\bin\zapret\WinDivert64.sys");
            fw.Services["WinDivert14"] = Svc("WinDivert14", 1, 1, @"\??\D:\tools\gdpi\WinDivert64.sys");
            fw.Services["WinDivert1.4"] = Denied("WinDivert1.4");
            var rw = Conflicts.Evaluate(fw);
            var t0 = Diagnostics.EntryText(rw.WinDivert[0]).English; var t1 = Diagnostics.EntryText(rw.WinDivert[1]).English; var t2 = Diagnostics.EntryText(rw.WinDivert[2]).English;
            Check("windivert: all found entries are listed (not only the first), with type, state and folder",
                  rw.WinDivert.Count == 3 && rw.WinDivert[0].InOurFolder && !rw.WinDivert[2].InOurFolder && t0.Contains("kernel driver") && t0.Contains("running") && t0.Contains("this installation") &&
                  t2.Contains("stopped") && t2.Contains("another folder"), t0 + " | " + t2);
            Check("windivert: access denied is its own result (not \"not found\", not \"stopped\")", rw.WinDivert[1].Unreadable && t1.Contains("access denied") && !t1.Contains("not found"), t1);
            var fn = BaseSource();
            Check("windivert: entries that do not exist are not listed", Conflicts.Evaluate(fn).WinDivert.Count == 0, "");

            // anti-cheat: driver type AND running state; user-mode services are information only; unreadable is never "none"
            var fa = BaseSource();
            fa.Services["vgk"] = Svc("vgk", 1, 4, @"system32\drivers\vgk.sys");
            fa.Services["FACEIT"] = Svc("FACEIT", 1, 1);
            fa.Services["EasyAntiCheat"] = Svc("EasyAntiCheat", 0x10, 4);
            fa.Services["BEDaisy"] = Denied("BEDaisy");
            var ra = Conflicts.Evaluate(fa);
            var vgk = ra.AntiCheat.First(a => a.E.Name == "vgk");
            var faceit = ra.AntiCheat.First(a => a.E.Name == "FACEIT");
            var eac = ra.AntiCheat.First(a => a.E.Name == "EasyAntiCheat");
            var be = ra.AntiCheat.First(a => a.E.Name == "BEDaisy");
            Check("anticheat: a running kernel driver is an active driver; a stopped driver and a user-mode service are not",
                  vgk.ActiveDriver && !faceit.ActiveDriver && !eac.ActiveDriver && eac.UserService && ra.AntiCheat.Count == 4 &&
                  Diagnostics.AntiCheatText(vgk).Key == "diag.anticheat.activeDriver" && Diagnostics.AntiCheatText(faceit).Key == "diag.anticheat.driverInstalled" &&
                  Diagnostics.AntiCheatText(eac).Key == "diag.anticheat.userService", "");
            Check("anticheat: an entry that cannot be read is \"could not be checked\", never \"not found\"",
                  be.Unreadable && Diagnostics.AntiCheatText(be).Key == "diag.anticheat.unreadable" && Diagnostics.AntiCheatText(be).English.Contains("does not mean it is absent"), "");
            var fu = BaseSource();
            fu.Services["vgk"] = Svc("vgk", 0x10, 4);
            Check("anticheat: a running entry of the right name but user-mode type is not taken for a kernel driver", !Conflicts.Evaluate(fu).AntiCheat.Single().ActiveDriver, "");
            Check("anticheat: only the explicit small list is checked (no guessed names)",
                  Conflicts.AntiCheat.Select(a => a.Service).SequenceEqual(new[] { "vgk", "FACEIT", "EasyAntiCheat", "EasyAntiCheat_EOS", "BEDaisy" }), "");

            // the information card
            var fc = BaseSource();
            fc.Services["vgk"] = Svc("vgk", 1, 4);
            fc.Ctx.Running = Engines.GoodbyeDpi;
            var n1 = Conflicts.Evaluate(fc).Notice;
            fc.Ctx.ByeDpiAvailable = false;
            fc.Ctx.ByeDpiWhy = Engines.Unavailable64(Engines.ByeDpi);
            var n2 = Conflicts.Evaluate(fc).Notice;
            fc.Ctx.Running = Engines.ByeDpi;
            fc.Ctx.ByeDpiAvailable = true;
            var n3 = Conflicts.Evaluate(fc).Notice;
            fc.Ctx.Running = null;
            var n4 = Conflicts.Evaluate(fc).Notice;
            fc.Ctx.Running = Engines.Zapret;
            fc.Services["vgk"] = Svc("vgk", 1, 1);
            var n5 = Conflicts.Evaluate(fc).Notice;
            Check("notice: an active anti-cheat driver next to a running WinDivert engine explains ByeDPI and may open the profile page",
                  n1 != null && n1.OpenProfiles && n1.Text.Key == "diag.notice.anticheatByeDpi" && n1.Text.English.Contains("no anti-cheat compatibility is guaranteed"), n1?.Text.English);
            Check("notice: where ByeDPI cannot run the card says why and offers no switch",
                  n2 != null && !n2.OpenProfiles && n2.Text.Key == "diag.notice.anticheatNoByeDpi" && n2.Text.English.Contains("64-bit"), n2?.Text.English);
            Check("notice: no card for the driverless engine, with protection off, or for a stopped anti-cheat driver", n3 == null && n4 == null && n5 == null, "");

            // VPN / WARP: adapter, product service and route are separate findings
            AdapterInfo Ad(string name, int idx, bool vpn) => new AdapterInfo { Name = name, Description = name, IfIndex = idx, IsVpn = vpn, V4 = { "10.0.0.2" }, Gateways = { "10.0.0.1" } };
            var fv = BaseSource();
            fv.Ads.Add(Ad("Ethernet", 5, false));
            fv.Ads.Add(Ad("Cloudflare WARP", 9, true));
            fv.Best = 9;
            var v1 = Diagnostics.VpnText(Conflicts.Evaluate(fv));
            fv.Best = 5;
            var v2 = Diagnostics.VpnText(Conflicts.Evaluate(fv));
            fv.Best = null;
            var v3 = Diagnostics.VpnText(Conflicts.Evaluate(fv));
            var fv2 = BaseSource();
            fv2.Services["CloudflareWARP"] = Svc("CloudflareWARP", 0x10, 4);
            var v4 = Diagnostics.VpnText(Conflicts.Evaluate(fv2));
            var v5 = Diagnostics.VpnText(Conflicts.Evaluate(BaseSource()));
            Check("vpn: the internet route through the VPN adapter is a warning (NSF-304)", v1.Status == CheckStatus.Warn && v1.Text.Key == "diag.vpn.route", v1.Text.English);
            Check("vpn: an Up adapter that does not carry the route is information only", v2.Status == CheckStatus.Info && v2.Text.Key == "diag.vpn.upNoRoute", v2.Text.English);
            Check("vpn: an unreadable route is said so (no guess)", v3.Status == CheckStatus.Info && v3.Text.Key == "diag.vpn.upRouteUnknown", v3.Text.English);
            Check("vpn: a running WARP service without an Up adapter is not an active tunnel", v4.Status == CheckStatus.Info && v4.Text.Key == "diag.vpn.serviceRunning" && v4.Text.English.Contains("not an active tunnel"), v4.Text.English);
            Check("vpn: nothing found → OK", v5.Status == CheckStatus.Ok && v5.Text.Key == "diag.vpn.none", "");

            // the shared result: Find Problems and the home page read the same one; a deferred run waits for the scan gate
            var fr = BaseSource();
            fr.Services["vgk"] = Svc("vgk", 1, 4);
            Conflicts.Source = fr;
            Conflicts.DebugSet(null);
            var shared = Task.Run(() => Conflicts.RefreshAsync()).Result;
            Check("shared: the diagnosis result is kept for the home page", Conflicts.Latest == shared && !shared.Deferred, "");
            var fd = BaseSource();
            fd.Ctx.ScanBusy = true;
            fd.Procs.Add(P("winws", 777, Own + @"\bin\zapret\winws.exe"));
            Conflicts.Source = fd;
            var deferred = Task.Run(() => Conflicts.RefreshAsync()).Result;
            Check("shared: during a scan an unclear result is not stored; one refresh waits for the scan to end",
                  deferred.Deferred && Conflicts.Latest == shared && Conflicts.DebugPending, "");
            fd.Ctx.ScanBusy = false;
            var tok = ScanGate.TryAcquire();
            ScanGate.Release(tok);
            bool after = WaitFor(() => Conflicts.Latest != shared);
            Check("shared: when the scan gate is free the waiting diagnosis runs once", after && !Conflicts.DebugPending && Conflicts.Latest.Processes.Single().Owner == ProcOwner.Unknown, "");
            Conflicts.Source = new LiveConflictSource();

            // the live readers are read only and tell the results apart
            var none = ScmReader.Query("NSFShield_no_such_service_5");
            var bfe = ScmReader.Query("BFE");
            var tcpip = ScmReader.Query("Tcpip");
            Check("scm: a missing service is \"not found\"; a user-mode service and a kernel driver are told apart (read only)",
                  none.Read == ScmRead.NotFound && bfe.Read == ScmRead.Ok && !bfe.IsDriver && tcpip.Read == ScmRead.Ok && tcpip.IsDriver && tcpip.Running,
                  none.Read + " / BFE " + bfe.Read + " " + bfe.Type + " / Tcpip " + tcpip.Read + " " + tcpip.Type + " " + tcpip.State);
            var self = Process.GetCurrentProcess();
            string selfPath = ProcReader.ImagePath(self.Id, out bool selfDenied);
            Check("process: the executable path is read with the limited query right", selfPath != null && !selfDenied &&
                  string.Equals(Path.GetFullPath(selfPath), Path.GetFullPath(Assembly.GetEntryAssembly().Location), StringComparison.OrdinalIgnoreCase), "");
            Check("diagnosis: no hard-coded prefix match is left in the DPI tool check (exact path + PID)",
                  !File.ReadAllText(Path.Combine(Repo, @"src\Core\Diagnostics.cs")).Contains("MainModule.FileName.StartsWith"), "");
        }

        // ---------------------------------------------------------------------------- network change flow
        static void Net5(Action<string, bool, string> Check)
        {
            NetState S(string adapter, string dns, DohState doh = DohState.Unknown, bool online = true) =>
                new NetState { Online = online, AdapterId = adapter, AdapterName = adapter, RouteKnown = adapter != null, Candidates = 1, DnsChoice = dns, Doh = doh };
            var deb = new ManualDebounce();
            var pending = new List<TaskCompletionSource<NetState>>();
            var notes = new List<(NetState Old, NetState New)>();
            bool busy = false;
            int otherCalls = 0;
            var flow = new NetChangeFlow(deb, () => { otherCalls++; return null; }, a => a(), () => busy, (o, n) => notes.Add((o, n)),
                                         f => { var t = new TaskCompletionSource<NetState>(); pending.Add(t); return t.Task; });
            flow.Prime();
            pending[0].SetResult(S("Wi-Fi", "auto"));
            Check("net: the first picture is taken silently", flow.Applied == 1 && notes.Count == 0 && flow.Last.AdapterName == "Wi-Fi", "");
            flow.Signal(); deb.Advance(1000); flow.Signal(); deb.Advance(1000); flow.Signal(); deb.Advance(2000);
            int readsBefore = flow.Reads;
            deb.Advance(500);
            Check("net: events are joined until 2.5 s after the last one (one read)", readsBefore == 1 && flow.Reads == 2 && deb.Restarts == 3, "reads " + flow.Reads);
            pending[1].SetResult(S("Wi-Fi", "auto"));
            Check("net: the same state is not reported again", notes.Count == 0 && flow.Applied == 2, "");
            flow.Signal(); deb.Advance(2500);
            flow.Signal(); deb.Advance(2500);
            pending[3].SetResult(S("Ethernet", "cloudflare", DohState.Configured));
            pending[2].SetResult(S("Wi-Fi", "auto"));
            Check("net: an older read that returns late never overwrites the newer state",
                  flow.Last.AdapterName == "Ethernet" && flow.Dropped == 1 && notes.Count == 1 && notes[0].New.AdapterName == "Ethernet" && notes[0].Old.AdapterName == "Wi-Fi", "");
            busy = true;
            flow.Signal(); deb.Advance(2500);
            flow.Signal(); deb.Advance(2500);
            int readsBusy = flow.Reads;
            busy = false;
            flow.OnScanReleased();
            flow.OnScanReleased();
            Check("net: during a scan one refresh is kept and done once when the gate is free", readsBusy == 4 && flow.Reads == 5 && !flow.Pending, "reads " + flow.Reads);
            pending[4].SetResult(S("Ethernet", "cloudflare", DohState.Configured));
            busy = true;
            flow.Signal(); deb.Advance(2500);
            busy = false;
            flow.OnScanReleased();
            busy = true;
            pending[5].SetResult(S("Hotspot", "auto"));
            Check("net: a read that returns while a scan runs is kept for later", flow.Pending && flow.Last.AdapterName == "Ethernet", "");
            busy = false;
            flow.OnScanReleased();
            pending[6].SetResult(S("Hotspot", "auto"));
            Check("net: after the scan the newest state is reported once", flow.Last.AdapterName == "Hotspot" && notes.Count == 2, "");
            flow.Signal(); deb.Advance(2500);
            flow.Dispose();
            pending[7].SetResult(S(null, "auto", DohState.Unknown, false));
            flow.Signal(); deb.Advance(5000);
            Check("net: after Dispose a late read changes nothing and new events are ignored",
                  notes.Count == 2 && flow.Last.AdapterName == "Hotspot" && flow.Reads == 8 && deb.Due < 0, "");
            Check("net: the flow only reads; it never starts a test, a repair, a scan or an engine (no other call)", otherCalls == 0 && !Actions.Testing && !Actions.Scanning, "");
            Check("net: network events no longer start the connection watchdog's test and repair",
                  !File.ReadAllText(Path.Combine(Repo, @"src\UI\MainForm.cs")).Contains("WatchCheckAsync(\"network changed\")") &&
                  File.ReadAllText(Path.Combine(Repo, @"src\UI\MainForm.cs")).Contains("WatchCheckAsync(\"periodic check\")"), "");

            // which adapter carries the route; DNS label and encrypted DNS states
            AdapterInfo A(string name, int idx) => new AdapterInfo { Name = name, Id = "{" + name + "}", Type = "x", IfIndex = idx, V4 = { "192.0.2.10" }, Gateways = { "192.0.2.1" } };
            var two = new List<AdapterInfo> { A("Wi-Fi", 7), A("Ethernet", 3) };
            var choice = new Dictionary<string, string> { ["Wi-Fi"] = "auto", ["Ethernet"] = "cloudflare" };
            var routed = NetStateReader.Pick(two, 3, a => choice[a.Name], id => DohState.Configured);
            var noRoute = NetStateReader.Pick(two, null, a => choice[a.Name], id => DohState.Unknown);
            var oneOnly = NetStateReader.Pick(new List<AdapterInfo> { A("Wi-Fi", 7) }, null, a => "auto", id => DohState.Unknown);
            var agree = NetStateReader.Pick(two, 99, a => "auto", id => DohState.Unknown);
            var offline = NetStateReader.Pick(new List<AdapterInfo>(), null, a => "x", id => DohState.Unknown);
            Check("net: the adapter of the internet route is taken from the route table, not from list order",
                  routed.AdapterName == "Ethernet" && routed.RouteKnown && routed.DnsChoice == "cloudflare", routed.AdapterName);
            Check("net: several adapters without a readable route: no adapter is claimed ('mixed' or the common choice)",
                  noRoute.AdapterName == null && noRoute.DnsChoice == "mixed" && agree.AdapterName == null && agree.DnsChoice == "auto" && oneOnly.AdapterName == "Wi-Fi" && !oneOnly.RouteKnown && !offline.Online, "");
            App.Settings.DohBackups.Add(new DohBackup { Server = "1.1.1.1", Existed = true });
            string lab1 = SystemDns.StatusLabel(S("Ethernet", "cloudflare", DohState.Configured)), lab2 = SystemDns.StatusLabel(S("Ethernet", "cloudflare", DohState.Unknown));
            string lab3 = SystemDns.StatusLabel(S("Ethernet", "cloudflare", DohState.NotConfigured)), lab4 = SystemDns.StatusLabel(S("Ethernet", "cloudflare", DohState.Unsupported));
            Check("dns: \"DoH\" is shown only when encrypted DNS is registered (saved backups are no proof)",
                  lab1 == "Cloudflare DoH" && lab2 == "Cloudflare" && lab3 == "Cloudflare" && lab4 == "Cloudflare" && SystemDns.StatusLabel(S(null, "mixed")) == Loc.T("home.chip.dnsMixed"), lab1 + " / " + lab2);
            App.Settings.DohBackups.Clear();
            Check("dns: the tooltip tells unsupported, registered, not registered and unknown apart and names the adapter",
                  new[] { DohState.Unsupported, DohState.Configured, DohState.NotConfigured, DohState.Unknown }.Select(d => SystemDns.StatusTip(S("Ethernet", "cloudflare", d))).Distinct().Count() == 4 &&
                  SystemDns.StatusTip(routed).Contains("Ethernet") && SystemDns.StatusTip(noRoute).Contains("2 adapters"), SystemDns.StatusTip(noRoute));
            var sA = S("Ethernet", "auto");
            SystemDns.Publish(sA);
            bool staleTaken = SystemDns.Publish(S("Wi-Fi", "custom"), 1);
            Check("dns: a status read that started earlier never overwrites a newer picture", !staleTaken && SystemDns.Status == sA, "");
            Check("dns: automatic (DHCP) DNS is not marked as a problem on the home page",
                  !File.ReadAllText(Path.Combine(Repo, @"src\UI\HomePage.cs")).Contains("sysChoice == \"auto\" && st == EngineState.Running ? Amber"), "");
        }

        // ---------------------------------------------------------------------------- NSF1 profile codes
        static void Share5(Action<string, bool, string> Check, string repo)
        {
            int saves0 = SettingsStore.SaveRequests, customs0 = App.Settings.CustomProfiles.Count;
            var st0 = App.Engine.State;
            // NSF1 round trips of every built-in (compared by the method, not by the id)
            var bad = new List<string>();
            foreach (var b in Profiles.BuiltIns)
            {
                var c = b.CloneAsCustom();
                if (!ProfileCode.TryToCode(c, out string code, out string err)) { bad.Add(b.Id + ": " + err); continue; }
                if (!code.StartsWith(ProfileCode.Prefix) || !ProfileCode.TryFromCode(code, out var back, out err) || !ProfileCode.SameMethod(c, back) || back.Id == c.Id) bad.Add(b.Id + ": " + err);
            }
            Check("nsf1: every built-in profile of the three engines round-trips (same engine and validated engine arguments)", bad.Count == 0, string.Join("; ", bad.Take(3)));
            var raw = new Profile { Name = "raw", Engine = EngineKind.GoodbyeDpi, UseRaw = true, RawArgs = "-9 --dns-addr 77.88.8.8 --dns-port 1253" };
            var structured = new Profile
            {
                Name = "s", Mode = "-5", Dns = DnsChoice.Custom, CustomDns4 = "9.9.9.9", CustomDns4Port = 9953, CustomDns6 = "2620:fe::fe", CustomDns6Port = 9953, Ttl = "auto",
                HttpsFrag = 2, FakeGen = 4, FakeResend = 2, WrongSeq = true, BlockQuic = true, AllowNoSni = true, ExtraArgs = "--max-payload",
            };
            bool rawOk = ProfileCode.TryFromCode(ProfileCode.ToCode(raw), out var rawBack, out _);
            bool stOk = ProfileCode.TryFromCode(ProfileCode.ToCode(structured), out var stBack, out _);
            Check("nsf1: raw and structured GoodbyeDPI profiles keep their mode and every field",
                  rawOk && rawBack.UseRaw && rawBack.RawArgs == raw.RawArgs && stOk && !stBack.UseRaw && ProfileCode.SameMethod(structured, stBack) && stBack.AllowNoSni &&
                  stBack.CustomDns6 == "2620:fe::fe" && stBack.Ttl == "auto" && stBack.ExtraArgs == "--max-payload", "");
            string Xml(string code) { var b = Convert.FromBase64String(code.Substring(5)); using (var z = new DeflateStream(new MemoryStream(b), CompressionMode.Decompress)) using (var r = new StreamReader(z)) return r.ReadToEnd(); }
            var zc = Profiles.BuiltIns.First(x => x.Id == "zapret-discord").CloneAsCustom();
            string zx = Xml(ProfileCode.ToCode(zc));
            Check("nsf1: the document is version 1 with the engine and the method only (no id, group, tier, path, port or list content)",
                  zx.StartsWith("<profile version=\"1\" engine=\"zapret\">") && zx.Contains("<args>") && !zx.Contains(zc.Id) && !zx.Contains("Group") && !zx.Contains("Priority") &&
                  !zx.Contains("\\") && !zx.Contains("--port") && !zx.Contains(App.BaseDir) && zx.Contains("tls_clienthello_www_google_com.bin"), zx.Substring(0, Math.Min(80, zx.Length)));

            // strict reader
            string Doc(string body, string attrs = "version=\"1\" engine=\"zapret\"") => "<profile " + attrs + ">" + body + "</profile>";
            string ZA = "<args>--wf-tcp=443 --filter-tcp=443 --dpi-desync=multidisorder --dpi-desync-split-pos=1</args>";
            string Pk(string xml, int v = 1) => ProfileCode.PackRaw(v, Encoding.UTF8.GetBytes(xml));
            foreach (var (name, xml, key) in new[]
            {
                ("an unknown document version", Doc(ZA, "version=\"2\" engine=\"zapret\""), "profiles.code.unsupportedVersion"),
                ("a missing engine (never mapped to GoodbyeDPI)", Doc(ZA, "version=\"1\""), "profiles.code.noEngine"),
                ("an unknown engine", Doc(ZA, "version=\"1\" engine=\"spoofdpi\""), "profiles.code.unknownEngine"),
                ("an unknown attribute", Doc(ZA, "version=\"1\" engine=\"zapret\" id=\"x\""), "profiles.code.unknownField"),
                ("a repeated field", Doc("<name>a</name><name>b</name>" + ZA), "profiles.code.duplicateField"),
                ("an unknown field", Doc("<path>C:\\x</path>" + ZA), "profiles.code.unknownField"),
                ("GoodbyeDPI fields in a Zapret code", Doc("<mode>-9</mode>" + ZA), "profiles.code.conflicting"),
                ("raw and structured GoodbyeDPI fields together", Doc("<raw>-9</raw><mode>-9</mode>", "version=\"1\" engine=\"goodbyedpi\""), "profiles.code.conflicting"),
                ("Zapret without its arguments", Doc("<name>a</name>"), "profiles.code.missingField"),
                ("an unknown option flag", Doc("<flags>wrongseq rm-rf</flags>", "version=\"1\" engine=\"goodbyedpi\""), "profiles.code.badFlag"),
                ("a repeated option flag", Doc("<flags>wrongseq wrongseq</flags>", "version=\"1\" engine=\"goodbyedpi\""), "profiles.code.duplicateField"),
                ("an invalid mode", Doc("<mode>-0</mode>", "version=\"1\" engine=\"goodbyedpi\""), "profiles.code.badValue"),
                ("an invalid TTL", Doc("<ttl>0</ttl>", "version=\"1\" engine=\"goodbyedpi\""), "profiles.code.badValue"),
                ("an invalid port", Doc("<dns>Custom</dns><dns4>1.1.1.1</dns4><dns4port>70000</dns4port>", "version=\"1\" engine=\"goodbyedpi\""), "profiles.code.badValue"),
                ("a DNS address without the custom DNS choice", Doc("<dns>Yandex</dns><dns4>1.1.1.1</dns4>", "version=\"1\" engine=\"goodbyedpi\""), "profiles.code.conflicting"),
                ("an attribute on a field", Doc("<name lang=\"x\">a</name>" + ZA), "profiles.code.unknownField"),
                ("a nested element", Doc("<name><b>a</b></name>" + ZA), "profiles.code.corrupt"),
                ("a document type definition", "<!DOCTYPE profile [<!ENTITY a \"x\">]>" + Doc("<name>&a;</name>" + ZA), "profiles.code.dtd"),
                ("an entity expansion bomb", "<?xml version=\"1.0\"?><!DOCTYPE p [<!ENTITY a \"aaaaaaaaaa\"><!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\">]>" + Doc("<name>&b;</name>" + ZA), "profiles.code.dtd"),
                ("an unsafe argument (checked before any preview)", Doc("<args>--wf-tcp=443 --filter-tcp=443 --hostlist-auto=x.txt</args>"), "profiles.code.unsafe"),
            })
            {
                bool okr = ProfileCode.TryFromCode(Pk(xml), out var pr, out var err);
                Check("nsf1: refused – " + name, !okr && pr == null && IsMsg(err, key), err);
            }
            bool v2 = ProfileCode.TryFromCode(Pk(Doc(ZA), 2), out _, out var v2Err);
            Check("nsf1: a code of another format version (NSF2:) is refused as unsupported", !v2 && IsMsg(v2Err, "profiles.code.unsupportedVersion"), v2Err);

            // broken data, several codes
            string good = ProfileCode.ToCode(zc);
            foreach (var (name, text, key) in new[]
            {
                ("a cut-off code", good.Substring(0, good.Length - 7), "profiles.code.corrupt"),
                ("invalid Base64", "NSF1:@@@@", "profiles.code.empty"),
                ("bytes that are not Deflate", "NSF1:" + Convert.ToBase64String(Encoding.ASCII.GetBytes("this is not deflate data at all")), "profiles.code.corrupt"),
                ("Deflate data that is not XML", ProfileCode.PackRaw(1, Encoding.ASCII.GetBytes("not xml")), "profiles.code.corrupt"),
                ("an empty code", "NSF1:", "profiles.code.empty"),
                ("no code", "hello friend", "profiles.code.noCode"),
                ("two different codes", good + " and " + ProfileCode.ToCode(Profiles.BuiltIns.First(x => x.Id == "byedpi-oob").CloneAsCustom()), "profiles.code.multiple"),
                ("codes of two format versions together", good + " " + Pk(Doc(ZA), 2), "profiles.code.multiple"),
            })
            {
                bool okb = ProfileCode.TryFromCode(text, out var pb, out var err);
                Check("nsf: refused – " + name, !okb && IsMsg(err, key), err);
            }
            Check("nsf: the same code pasted twice is one code", ProfileCode.TryFromCode(good + "\n" + good, out _, out _), "");

            // limits: at the limit accepted, one unit more refused (before decoding / decompression)
            string padded = good + new string(' ', ProfileCode.MaxInputChars - good.Length);
            Check("limit: pasted text of exactly 128 Ki characters is read; one more character is refused",
                  padded.Length == ProfileCode.MaxInputChars && ProfileCode.TryFromCode(padded, out _, out _) &&
                  !ProfileCode.TryFromCode(padded + " ", out _, out var tl) && tl == Loc.T("profiles.code.tooLong", 128), "");
            string head = "<profile version=\"1\" engine=\"zapret\"><name>limit</name>" + ZA, tail = "</profile>";
            byte[] XmlOf(int size) => Encoding.ASCII.GetBytes(head + new string(' ', size - head.Length - tail.Length) + tail);
            string stored64 = ProfileCode.PackRaw(1, XmlOf(ProfileCode.MaxCompressedBytes - 5), stored: true);
            string stored65 = ProfileCode.PackRaw(1, XmlOf(ProfileCode.MaxCompressedBytes - 4), stored: true);
            int len64 = Convert.FromBase64String(stored64.Substring(5)).Length, len65 = Convert.FromBase64String(stored65.Substring(5)).Length;
            bool in64 = ProfileCode.TryFromCode(stored64, out _, out var e64);
            bool in65 = ProfileCode.TryFromCode(stored65, out _, out var e65);
            Check("limit: packed data of exactly 64 KiB is read; one byte more is refused",
                  len64 == 65536 && len65 == 65537 && in64 && !in65 && e65 == Loc.T("profiles.code.tooLarge"), len64 + "/" + len65 + " " + e64 + " " + e65);
            string x64 = ProfileCode.PackRaw(1, XmlOf(ProfileCode.MaxXmlBytes)), x65 = ProfileCode.PackRaw(1, XmlOf(ProfileCode.MaxXmlBytes + 1));
            Check("limit: unpacked XML of exactly 64 KiB is read; one byte more is refused (read incrementally)",
                  ProfileCode.TryFromCode(x64, out _, out var ex64) && !ProfileCode.TryFromCode(x65, out _, out var ex65) && ex65 == Loc.T("profiles.code.tooLarge"), ex64);
            var bomb = ProfileCode.PackRaw(1, Encoding.ASCII.GetBytes("<Profile>" + new string(' ', 20 * 1024 * 1024) + "</Profile>"));
            var bsw = Stopwatch.StartNew();
            bool bombOk = ProfileCode.TryFromCode(bomb, out _, out var bombErr);
            Check("limit: a Deflate bomb (20 MiB unpacked) is refused early", !bombOk && bombErr == Loc.T("profiles.code.tooLarge") && bsw.ElapsedMilliseconds < 2000 && bomb.Length < ProfileCode.MaxInputChars, bsw.ElapsedMilliseconds + " ms");

            // the writer never makes a code its own reader refuses; unsafe profiles are not shared
            var evil = new Profile { Name = "x", Engine = EngineKind.ByeDpi, EngineArgs = "--ip 0.0.0.0 --split 1" };
            Check("nsf1: an unsafe profile is not written", !ProfileCode.TryToCode(evil, out var ec, out var ee) && ec == null && ee.Length > 0, ee);
            var weird = zc.CloneAsCustom();
            weird.Name = "a\u0001b\uD800c<d>&e";
            weird.Description = new string('x', 5000);
            bool wOk = ProfileCode.TryToCode(weird, out var wc, out var we);
            Profile wb = null;
            if (wOk) wOk = ProfileCode.TryFromCode(wc, out wb, out _);
            Check("nsf1: control characters, lone surrogates and long texts are cleaned before writing; the code reads back",
                  wOk && wb.Name == "a b?c<d>&e" && wb.Description.Length == 600, we + " " + wb?.Name);
            Check("nsf: reading codes saved nothing, added no profile and started nothing",
                  SettingsStore.SaveRequests == saves0 && App.Settings.CustomProfiles.Count == customs0 && App.Engine.State == st0, "");
            var trDoc = Newtonsoft(Path.Combine(repo, "locales", "tr.json"));
            Check("nsf: every new message exists in English and Turkish",
                  new[] { "tooLong", "tooLarge", "multiple", "dtd", "unsupportedVersion", "noEngine", "unknownEngine", "unknownField", "duplicateField", "conflicting", "missingField", "badValue", "badFlag", "roundTrip" }
                      .All(k => Loc.Has("profiles.code." + k) && trDoc.Contains("\"" + k + "\"")), "");
        }

        /// <summary>Is the message the text of this key (with any arguments)?</summary>
        static bool IsMsg(string msg, string key)
        {
            string tpl = Loc.T(key, "\u0001", "\u0002", "\u0003");
            string rx = "^" + Regex.Escape(tpl).Replace("\u0001", ".*").Replace("\u0002", ".*").Replace("\u0003", ".*") + "$";
            return msg != null && Regex.IsMatch(msg, rx, RegexOptions.Singleline);
        }

        static string Newtonsoft(string path) => File.ReadAllText(path, Encoding.UTF8);

        // ---------------------------------------------------------------------------- the bilingual guide
        static void Guide5(Action<string, bool, string> Check, string repo, string root)
        {
            // an installation folder with a space and Turkish letters (written as escapes: no hard-coded Turkish text in the code)
            string dir = Path.Combine(root, "Program Files", "NSF Shield \u011f\u00fc\u015f\u0131\u00f6\u00e7 Test");
            Directory.CreateDirectory(dir);
            string main = Path.Combine(dir, Guide.FileName);
            Guide.Build(Path.Combine(repo, "docs", "Guide.html"), main);
            string html = File.ReadAllText(main, Encoding.UTF8);
            string en = Path.Combine(dir, Guide.EntryDir, "en.html"), tr = Path.Combine(dir, Guide.EntryDir, "tr.html");
            Check("guide: the main file and the two fixed entry pages are written", File.Exists(main) && File.Exists(en) && File.Exists(tr), "");
            Check("guide: no placeholder is left", !Regex.IsMatch(html, "<!--(VERSION|ERROR_COUNT|PROFILE_COUNT|ERROR_CODES|PROFILES)"), "");
            var ids = Regex.Matches(html, "\\sid=\"([^\"]+)\"").Cast<Match>().Select(m => m.Groups[1].Value).ToList();
            var dup = ids.GroupBy(x => x).Where(g => g.Count() > 1).Select(g => g.Key).ToList();
            Check("guide: no HTML id appears twice", dup.Count == 0, string.Join(",", dup.Take(5)));
            string enPart = html.Substring(html.IndexOf("<main class=\"lang\" id=\"en\""), html.IndexOf("<main class=\"lang\" id=\"tr\"") - html.IndexOf("<main class=\"lang\" id=\"en\""));
            string trPart = html.Substring(html.IndexOf("<main class=\"lang\" id=\"tr\""));
            var enLinks = Regex.Matches(enPart, "href=\"#([^\"]+)\"").Cast<Match>().Select(m => m.Groups[1].Value).ToList();
            var trLinks = Regex.Matches(trPart, "href=\"#([^\"]+)\"").Cast<Match>().Select(m => m.Groups[1].Value).ToList();
            Check("guide: every in-page link has a target and stays in its own language",
                  enLinks.Count > 20 && trLinks.Count > 20 && enLinks.All(l => l.StartsWith("en-") && ids.Contains(l)) && trLinks.All(l => l.StartsWith("tr-") && ids.Contains(l)),
                  string.Join(",", enLinks.Concat(trLinks).Where(l => !ids.Contains(l)).Take(5)));
            int nEn = Regex.Matches(enPart, "id=\"en-NSF-\\d{3}\"").Count, nTr = Regex.Matches(trPart, "id=\"tr-NSF-\\d{3}\"").Count;
            Loc.Init("tr");
            string trTitle = ErrorCatalog.Get("NSF-204").Title, trName = Profiles.BuiltIns.First(p => p.Id == "zapret-discord").Name;
            Loc.Init("en");
            string enTitle = ErrorCatalog.Get("NSF-204").Title, enName = Profiles.BuiltIns.First(p => p.Id == "zapret-discord").Name;
            Check("guide: each language has the whole error catalog in its own words",
                  nEn == ErrorCatalog.All.Count && nTr == ErrorCatalog.All.Count && enPart.Contains(WebUtility.HtmlEncode(enTitle)) && trPart.Contains(WebUtility.HtmlEncode(trTitle)) &&
                  enTitle != trTitle && !enPart.Contains(WebUtility.HtmlEncode(trTitle)), nEn + "/" + nTr);
            var s = new AppSettings();
            var missing = Profiles.BuiltIns.Where(p => !(CommandPreview.TryBuild(p, s, false, out var c, out _) && enPart.Contains(WebUtility.HtmlEncode(c)) && trPart.Contains(WebUtility.HtmlEncode(c)))).Select(p => p.Id).ToList();
            Check("guide: every built-in profile shows its own engine's validated short command in both languages",
                  missing.Count == 0 && enPart.Contains("winws.exe --wf-tcp") && enPart.Contains("ciadpi.exe") && enPart.Contains(WebUtility.HtmlEncode(enName)) && trPart.Contains(WebUtility.HtmlEncode(trName)),
                  string.Join(",", missing.Take(4)));
            Check("guide: no external request while loading or switching (no remote script, style, image or frame)",
                  !Regex.IsMatch(html, "<(script|img|iframe|link|source|video|audio)[^>]+(src|href)=\"(https?:)?//", RegexOptions.IgnoreCase) && !html.Contains("@import") &&
                  !Regex.IsMatch(html, "url\\((\"|')?(https?:)?//") && !html.Contains("fetch(") && !html.Contains("XMLHttpRequest"), "");
            Check("guide: a visible language switch works both ways (#en / #tr) and a default is chosen without a hash",
                  html.Contains("<a href=\"#en\" hreflang=\"en\"") && html.Contains("<a href=\"#tr\" hreflang=\"tr\"") && html.Contains("navigator.language") &&
                  html.Contains("hashchange") && html.Contains("html.nojs .lang"), "");
            foreach (var lang in Guide.Languages)
            {
                string entry = File.ReadAllText(Path.Combine(dir, Guide.EntryDir, lang + ".html"), Encoding.UTF8);
                // the relative link of the entry page, resolved like a browser does (the fragment is not part of the file)
                var target = new Uri(new Uri(Path.Combine(dir, Guide.EntryDir, lang + ".html")), "../Guide.html");
                Check("guide: the " + lang + " entry page leads to the main file's " + lang + " part (folder with spaces and Turkish letters)",
                      entry.Contains("url=../Guide.html#" + lang + "\"") && entry.Contains("href=\"../Guide.html#" + lang + "\"") && File.Exists(target.LocalPath) &&
                      string.Equals(Path.GetFullPath(target.LocalPath), Path.GetFullPath(main), StringComparison.OrdinalIgnoreCase), target.LocalPath.Replace(root, "<tmp>"));
            }
            Check("guide: the app opens a plain entry file of its language (no '#' or '?lang=' in a file path)",
                  Guide.EntryFor(dir, "tr") == tr && Guide.EntryFor(dir, "en") == en && Guide.EntryFor(dir, "de") == en &&
                  new[] { Guide.EntryFor(dir, "tr"), Guide.EntryFor(dir, "en") }.All(p => p.IndexOfAny(new[] { '#', '?' }) < 0), "");
            File.Delete(tr);
            File.Delete(en);
            Check("guide: without entry pages the bilingual main file is opened; with nothing there is no path", Guide.EntryFor(dir, "tr") == main && Guide.EntryFor(Path.Combine(root, "none"), "en") == null, "");
            string about = File.ReadAllText(Path.Combine(Repo, @"src\UI\OtherPages.cs")), sys = File.ReadAllText(Path.Combine(Repo, @"src\Core\SystemTools.cs"));
            Check("guide: the About button uses the entry page and opens it as the normal user (Explorer, no elevated fallback)",
                  about.Contains("Guide.EntryFor(App.BaseDir, Loc.Current)") && about.Contains("Sys.OpenAsUser(guide)") &&
                  Regex.IsMatch(sys, @"OpenAsUser\(string path\)\s*\{\s*try\s*\{\s*Process\.Start\(new ProcessStartInfo\(Explorer,") && !sys.Contains("\"runas\""), "");
        }

        // ---------------------------------------------------------------------------- exit codes, release notes, package, CI
        static void Build5(Action<string, bool, string> Check, string repo, string root)
        {
            string exe = Assembly.GetEntryAssembly().Location;
            Directory.CreateDirectory(root);
            int Child(string args, out string report, string outName = null)
            {
                string outPath = outName == null ? null : Path.Combine(root, outName);
                report = null;
                using (var p = Process.Start(new ProcessStartInfo(exe, args.Replace("{out}", "\"" + outPath + "\"")) { UseShellExecute = false, CreateNoWindow = true }))
                {
                    if (!p.WaitForExit(60000)) { try { p.Kill(); } catch { } return -999; }
                    if (outPath != null && File.Exists(outPath)) report = File.ReadAllText(outPath, Encoding.UTF8);
                    return p.ExitCode;
                }
            }
            int cOk = Child("--selftest-probe ok {out}", out var rOk, "p-ok.txt");
            int cFail = Child("--selftest-probe fail {out}", out var rFail, "p-fail.txt");
            int cThrow = Child("--selftest-probe throw {out}", out var rThrow, "p-throw.txt");
            int cEmpty = Child("--selftest-probe empty {out}", out var rEmpty, "p-empty.txt");
            int cInc = Child("--selftest-probe incomplete {out}", out var rInc, "p-inc.txt");
            int cUsage = Child("--selftest", out _);
            Directory.CreateDirectory(Path.Combine(root, "as-dir.txt"));
            int cWrite = Child("--selftest-probe ok {out}", out _, "as-dir.txt");
            Check("exit code: a complete run without failures gives 0 and its report", cOk == 0 && rOk != null && rOk.StartsWith("OK   probe check"), cOk.ToString());
            Check("exit code: a failed check gives 1 (the report keeps the FAIL line)", cFail == 1 && rFail != null && rFail.Contains("FAIL probe failure"), cFail.ToString());
            Check("exit code: an unexpected exception gives 3 and a FAIL line", cThrow == 3 && rThrow != null && rThrow.StartsWith("FAIL unexpected exception: InvalidOperationException"), cThrow.ToString());
            Check("exit code: a run without any check gives 5; an incomplete run gives 6", cEmpty == 5 && cInc == 6, cEmpty + " " + cInc);
            Check("exit code: a missing output argument gives 64; a report that cannot be written gives 4", cUsage == 64 && cWrite == 4, cUsage + " " + cWrite);

            // release notes: the updater finds the right hashes by file name even if the changelog contains a hash
            string zipSha = new string('a', 64), setupSha = new string('b', 64), trap = new string('c', 64);
            string body = "### Notes\n- SHA-256 of an old file: `" + trap + "`";
            string notes = ReleaseNotes.Build("1.0.0", zipSha, setupSha, body, "owner/repo", File.ReadAllText(Path.Combine(repo, ".github", "release-notes.md"), Encoding.UTF8));
            string FromNotes(string asset) { var m = Regex.Match(notes, Regex.Escape(asset) + @"\)?\W{0,6}`([0-9a-fA-F]{64})`"); return m.Success ? m.Groups[1].Value.ToLowerInvariant() : ""; }
            Check("release notes: the ZIP and the Setup hashes are found by file name", FromNotes("NSF-Shield-1.0.0.zip") == zipSha && FromNotes("NSF-Shield-1.0.0-Setup.exe") == setupSha, "");
            string json = "{\"tag_name\":\"v1.0.0\",\"name\":\"NSF Shield 1.0.0\",\"draft\":false,\"prerelease\":false,\"body\":" + new System.Web.Script.Serialization.JavaScriptSerializer().Serialize(notes) +
                          ",\"assets\":[{\"name\":\"NSF-Shield-1.0.0.zip\",\"browser_download_url\":\"https://github.com/o/r/releases/download/v1.0.0/NSF-Shield-1.0.0.zip\",\"size\":1}," +
                          "{\"name\":\"NSF-Shield-1.0.0-Setup.exe\",\"browser_download_url\":\"https://github.com/o/r/releases/download/v1.0.0/NSF-Shield-1.0.0-Setup.exe\",\"size\":2}," +
                          "{\"name\":\"NSF-Shield-1.0.0.SHA256SUMS.txt\",\"browser_download_url\":\"https://github.com/o/r/releases/download/v1.0.0/NSF-Shield-1.0.0.SHA256SUMS.txt\",\"size\":3}]}";
            var info = Updater.Parse(json);
            Check("release notes: the updater reads both hashes; an installed copy only uses the verified Setup",
                  info != null && info.Sha256 == zipSha && info.SetupSha256 == setupSha && Updater.UseSetup(info, true) && !Updater.UseSetup(info, false), info?.SetupSha256?.Substring(0, 8));
            Check("release notes: the user-facing text recommends Setup for new installations and explains the ZIP",
                  notes.Contains("**NSF-Shield-1.0.0-Setup.exe**") && notes.Contains("NSF-Shield-1.0.0.zip") && !notes.Contains("{ZIP}") && !notes.Contains("{SUMS}") && notes.Contains("NSF-Shield-1.0.0.SHA256SUMS.txt") && !notes.Contains("{REPO}") &&
                  notes.IndexOf(body, StringComparison.Ordinal) > notes.IndexOf(setupSha, StringComparison.Ordinal), "");
            Check("release notes: the changelog section of this version is found", ReleaseNotes.ChangelogSection(File.ReadAllText(Path.Combine(repo, "CHANGELOG.md"), Encoding.UTF8), "1.0.0").Length > 500, "");

            // the workflow (checked as text; it is not run here)
            string yml = File.ReadAllText(Path.Combine(repo, ".github", "workflows", "build.yml"));
            var uses = Regex.Matches(yml, @"uses:\s*([^\s#]+)").Cast<Match>().Select(m => m.Groups[1].Value).ToList();
            Check("ci: every action is pinned to a full commit SHA", uses.Count >= 5 && uses.All(u => Regex.IsMatch(u, "@[0-9a-f]{40}$")), string.Join(", ", uses.Where(u => !Regex.IsMatch(u, "@[0-9a-f]{40}$"))));
            Check("ci: Inno Setup 6.7.3 is downloaded with its SHA-256 checked; permissions are read-only except the tag-only release job",
                  yml.Contains("INNO_VERSION: '6.7.3'") && yml.Contains("$h -ne $env:INNO_SHA256") && Regex.IsMatch(yml, @"permissions:\s*\n\s*contents: read") &&
                  Regex.IsMatch(yml, @"release:\s*\n\s*if: startsWith\(github\.ref, 'refs/tags/v'\)"), "");
            Check("ci: the unit test step checks the process exit code and a fresh report of this run",
                  yml.Contains("$p.ExitCode -ne 0") && yml.Contains("-PassThru") && yml.Contains("LastWriteTimeUtc") && yml.Contains("Length -eq 0"), "");
            Check("ci: the artifact and the attestation name exactly this version's three release files (no wide glob over old dist files)",
                  !yml.Contains("dist/NSF-Shield-*") && yml.Contains("dist/NSF-Shield-${{ env.NSF_VERSION }}.zip") && yml.Contains("dist/NSF-Shield-${{ env.NSF_VERSION }}-Setup.exe") &&
                  Regex.IsMatch(yml, @"subject-path: \|\s*\n\s*dist/NSF-Shield-\$\{\{ env\.NSF_VERSION \}\}\.zip\s*\n\s*dist/NSF-Shield-\$\{\{ env\.NSF_VERSION \}\}-Setup\.exe\s*\n\s*dist/NSF-Shield-\$\{\{ env\.NSF_VERSION \}\}\.SHA256SUMS\.txt\s*\n"), "");
            Check("ci: the versioned SHA256SUMS of the build is published as it is (ZIP and Setup first); the notes come from the release notes tool",
                  yml.Contains("$sums = \"dist\\NSF-Shield-$v.SHA256SUMS.txt\"") && yml.Contains("gh release create $env:GITHUB_REF_NAME $setup $zip $sums") &&
                  !yml.Contains("dist\\SHA256SUMS.txt") && yml.Contains("--release-notes"), "");
            Check("ci: the runner label is not described as a fixed machine image", !Regex.IsMatch(yml, "immutable|fixed image|pinned runner", RegexOptions.IgnoreCase) && yml.Contains("moving image"), "");

            // build.ps1 (checked as text) and the manifest of the last build
            string ps = File.ReadAllText(Path.Combine(repo, "build.ps1"));
            Check("build: helper exit codes are checked and old outputs are removed before (no stale guide, scripts or icon)",
                  ps.Contains("Invoke-Helper") && Regex.Matches(ps, "Invoke-Helper ").Count >= 3 && ps.Contains("Remove-Item $ico"), "");
            Check("build: the reproducibility check needs the Setup and unsigned builds; a skipped part never reports three outputs",
                  ps.Contains("three-output") && ps.Contains("NSF_SIGN_ARGS") && ps.Contains("not a three-output check"), "");
            string ver = Assembly.GetEntryAssembly().GetName().Version.ToString(3);
            string sums = Path.Combine(repo, "dist", "NSF-Shield-" + ver + ".SHA256SUMS.txt"), pkg = Path.Combine(App.BaseDir, "package", "NSF Shield");
            if (File.Exists(sums) && Directory.Exists(pkg) && File.GetLastWriteTimeUtc(sums) >= File.GetLastWriteTimeUtc(Path.Combine(pkg, "NSFShield.exe")).AddMinutes(-10))
            {
                var lines = File.ReadAllText(sums).Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries).Select(l => l.Split(new[] { "  " }, 2, StringSplitOptions.None)).ToList();
                var files = Directory.GetFiles(pkg, "*", SearchOption.AllDirectories).Select(f => "NSF Shield/" + f.Substring(pkg.Length + 1).Replace('\\', '/')).ToList();
                var sorted = files.ToArray(); Array.Sort(sorted, StringComparer.Ordinal);
                var listed = lines.Skip(2).Select(l => l[1]).ToList();
                bool hashes = lines.Skip(2).All(l => Integrity.Sha256File(Path.Combine(pkg, l[1].Substring("NSF Shield/".Length).Replace('/', '\\'))) == l[0]);
                Check("manifest: the ZIP first, then the Setup, then every package file once in ordinal order with its real hash",
                      lines.Count >= 2 && lines[0][1] == "NSF-Shield-" + ver + ".zip" && lines[1][1] == "NSF-Shield-" + ver + "-Setup.exe" &&
                      listed.SequenceEqual(sorted) && listed.Distinct().Count() == listed.Count && hashes, lines.Count + " lines, " + files.Count + " files");
                Check("manifest: engines, 11 payloads, locales, licenses, the guide and its entry pages, README and scripts are covered; the manifest is not",
                      new[] { "NSF Shield/NSFShield.exe", "NSF Shield/bin/zapret/winws.exe", "NSF Shield/bin/byedpi/ciadpi.exe", "NSF Shield/bin/x86_64/WinDivert64.sys", "NSF Shield/Guide.html",
                              "NSF Shield/guide/en.html", "NSF Shield/guide/tr.html", "NSF Shield/README.txt", "NSF Shield/locales/tr.json", "NSF Shield/scripts/stop.cmd" }.All(listed.Contains) &&
                      listed.Count(l => l.StartsWith("NSF Shield/bin/zapret/payloads/")) == 11 && listed.Count(l => l.StartsWith("NSF Shield/licenses/")) >= 10 &&
                      !listed.Any(l => l.Contains("SHA256SUMS")), "");
                string zip = Path.Combine(repo, "dist", "NSF-Shield-" + ver + ".zip");
                using (var za = ZipFile.OpenRead(zip))
                {
                    var entries = za.Entries.Where(e => e.Length > 0 || !e.FullName.EndsWith("/")).ToDictionary(e => e.FullName, e => e);
                    bool same = entries.Count == files.Count && files.All(f => entries.ContainsKey(f) && Sha(entries[f]) == Integrity.Sha256File(Path.Combine(pkg, f.Substring("NSF Shield/".Length).Replace('/', '\\'))));
                    Check("manifest: the ZIP holds exactly the package tree, byte for byte", same, entries.Count + " entries");
                }
            }
            else Check("manifest: the last build's manifest and package (run build.ps1 first)", false, sums.Replace(repo, "<repo>"));
        }

        static string Sha(ZipArchiveEntry e)
        {
            using (var s = e.Open()) using (var h = System.Security.Cryptography.SHA256.Create()) return BitConverter.ToString(h.ComputeHash(s)).Replace("-", "").ToLowerInvariant();
        }

        // ---------------------------------------------------------------------------- UI: home card, profile tab, main window lifecycle
        static void Ui5(Action<string, bool, string> Check)
        {
            int sel0 = Actions.SelectRequests, save0 = SettingsStore.SaveRequests;
            string selected0 = App.Settings.SelectedProfileId;
            var f = BaseSource();
            f.Services["vgk"] = Svc("vgk", 1, 4);
            f.Ctx.Running = Engines.GoodbyeDpi;
            var rep = Conflicts.Evaluate(f);
            App.Engine.DebugSet(EngineState.Running, Profiles.BuiltIns.First(p => p.Id == "tr-recommended"));
            App.Problems.ClearWhere(e => true);
            App.Settings.InstallerHintDismissed = true;   // the portable-copy notice comes before the card; not part of this test
            Conflicts.DebugSet(rep);
            using (var home = new HomePage())
            {
                Check("home: the diagnosis card is shown from the shared result (title and the profile button)",
                      home.ShownNotice == rep.Notice && home.BannerTitle == rep.Notice.Title.Text && home.BannerButtonVisible, home.BannerTitle);
            }
            f.Ctx.ByeDpiAvailable = false;
            f.Ctx.ByeDpiWhy = Engines.Unavailable64(Engines.ByeDpi);
            Conflicts.DebugSet(Conflicts.Evaluate(f));
            using (var home2 = new HomePage())
                Check("home: where ByeDPI cannot run the card has no button", home2.ShownNotice != null && !home2.BannerButtonVisible, "");
            App.Problems.Report("NSF-301", new LocText("engine.processCount", 1));
            using (var home3 = new HomePage())
                Check("home: a real problem banner comes before the information card", home3.ShownNotice == null && home3.BannerTitle != null && home3.BannerTitle.StartsWith("NSF-301"), home3.BannerTitle);
            App.Problems.ClearWhere(e => true);
            var oldLevel = App.Settings.UiLevel;
            App.Settings.UiLevel = UiLevel.Standard;
            using (var pp = new ProfilesPage())
            {
                pp.ShowEngineTab(EngineKind.ByeDpi);
                Check("home: the card's link only shows the ByeDPI tab (nothing selected, saved or started)",
                      pp.ListedProfiles().All(p => p.Engine == EngineKind.ByeDpi) && App.Settings.SelectedProfileId == selected0, "");
            }
            App.Settings.UiLevel = oldLevel;
            Check("home: showing the card selected no profile, saved nothing and kept the engine state",
                  Actions.SelectRequests == sel0 && SettingsStore.SaveRequests == save0 && App.Engine.State == EngineState.Running, (Actions.SelectRequests - sel0) + " " + (SettingsStore.SaveRequests - save0));

            // the main window subscribes once, keeps the watcher through rebuilds and the tray, and undoes it on close
            var recorder = new RecordingNetEvents();
            var oldInstance = MainForm.Instance;
            MainForm.NetEventsOverride = recorder;
            var form = new MainForm();
            try
            {
                var h = form.Handle;
                Check("window: one subscription to both network events at start (PREVIEW never subscribes to the real events)",
                      recorder.Active == 1 && recorder.Subscribes == 1 && recorder.Address != null && recorder.Availability != null, "");
                form.Rebuild();
                Loc.Init("tr"); form.Rebuild(); Loc.Init("en"); form.Rebuild();
                var lvl = App.Settings.UiLevel;
                UiLevelSwitch.Set(UiLevel.Advanced, null); UiLevelSwitch.Set(lvl, null);
                form.HideToTray();
                Check("window: rebuilding for language, theme or UI level and hiding to the tray does not subscribe again",
                      recorder.Subscribes == 1 && recorder.Active == 1 && form.NetWatch != null && !form.Visible, "");
                var flow = form.NetWatch.Flow;
                form.Dispose();
                recorder.RaiseAddress();
                flow.Prime();
                Check("window: the real close unsubscribes both events and stops the watcher; a late event or read does nothing",
                      recorder.Active == 0 && recorder.Unsubscribes == 1 && recorder.Address == null && flow.Reads == 0, "reads " + flow.Reads);
            }
            finally
            {
                if (!form.IsDisposed) form.Dispose();
                MainForm.NetEventsOverride = null;
                MainForm.Instance = oldInstance;
                App.Engine.DebugSet(EngineState.Stopped, null);
                Conflicts.DebugSet(null);
            }
        }
    }
}
#endif
