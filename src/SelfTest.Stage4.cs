#if PREVIEW
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace NSFShield
{
    /// <summary>stage 4: profile catalog, three UI levels, command preview, the smart scanner and its network measurements.</summary>
    static partial class SelfTest
    {
        /// <summary>id|engine|group|arguments of the 30 built-in profiles of stage 3 (commit 1a31c5c): they must never change.</summary>
        static readonly string[] Stage3BuiltIns =
        {
            "tr-recommended|GoodbyeDpi|recommended|-9 --dns-addr 77.88.8.8 --dns-port 1253 --dnsv6-addr 2a02:6b8::feed:0ff --dnsv6-port 1253",
            "tr-adguard|GoodbyeDpi|recommended|-9 --dns-addr 94.140.14.14 --dns-port 5353 --dnsv6-addr 2a10:50c0::ad1:ff --dnsv6-port 5353",
            "tr-quad9|GoodbyeDpi|recommended|-9 --dns-addr 9.9.9.9 --dns-port 9953 --dnsv6-addr 2620:fe::fe --dnsv6-port 9953",
            "tr-opendns|GoodbyeDpi|recommended|-9 --dns-addr 208.67.222.222 --dns-port 5353 --dnsv6-addr 2620:119:35::35 --dnsv6-port 5353",
            "tr-autottl|GoodbyeDpi|alternative|-5 --dns-addr 77.88.8.8 --dns-port 1253 --dnsv6-addr 2a02:6b8::feed:0ff --dnsv6-port 1253",
            "tr-legacy1-dns|GoodbyeDpi|alternative|--set-ttl 3 --dns-addr 77.88.8.8 --dns-port 1253 --dnsv6-addr 2a02:6b8::feed:0ff --dnsv6-port 1253",
            "tr-legacy2-dns|GoodbyeDpi|alternative|-4 --set-ttl 5 --dns-addr 77.88.8.8 --dns-port 1253 --dnsv6-addr 2a02:6b8::feed:0ff --dnsv6-port 1253",
            "tr-wrongseq|GoodbyeDpi|alternative|-6 --dns-addr 77.88.8.8 --dns-port 1253 --dnsv6-addr 2a02:6b8::feed:0ff --dnsv6-port 1253",
            "tr-wrongchk|GoodbyeDpi|alternative|-7 --dns-addr 77.88.8.8 --dns-port 1253 --dnsv6-addr 2a02:6b8::feed:0ff --dnsv6-port 1253",
            "tr-mode8|GoodbyeDpi|alternative|-8 --dns-addr 77.88.8.8 --dns-port 1253 --dnsv6-addr 2a02:6b8::feed:0ff --dnsv6-port 1253",
            "tr-fakegen|GoodbyeDpi|alternative|-9 --fake-gen 5 --dns-addr 77.88.8.8 --dns-port 1253 --dnsv6-addr 2a02:6b8::feed:0ff --dnsv6-port 1253",
            "tr-resend|GoodbyeDpi|alternative|-9 --fake-gen 3 --fake-resend 3 --dns-addr 77.88.8.8 --dns-port 1253 --dnsv6-addr 2a02:6b8::feed:0ff --dnsv6-port 1253",
            "tr-e1|GoodbyeDpi|alternative|-9 -e 1 --dns-addr 77.88.8.8 --dns-port 1253 --dnsv6-addr 2a02:6b8::feed:0ff --dnsv6-port 1253",
            "tr-sni|GoodbyeDpi|alternative|-9 --frag-by-sni --dns-addr 77.88.8.8 --dns-port 1253 --dnsv6-addr 2a02:6b8::feed:0ff --dnsv6-port 1253",
            "tr-native|GoodbyeDpi|alternative|-f 2 -e 2 --wrong-chksum --wrong-seq --native-frag --max-payload -q --dns-addr 77.88.8.8 --dns-port 1253 --dnsv6-addr 2a02:6b8::feed:0ff --dnsv6-port 1253",
            "tr-alt|GoodbyeDpi|alternative|-5 -e 1 -q --fake-gen 5 --dns-addr 77.88.8.8 --dns-port 1253 --dnsv6-addr 2a02:6b8::feed:0ff --dnsv6-port 1253",
            "tr-compatible|GoodbyeDpi|alternative|-1 --dns-addr 77.88.8.8 --dns-port 1253 --dnsv6-addr 2a02:6b8::feed:0ff --dnsv6-port 1253",
            "tr-classic2|GoodbyeDpi|alternative|-2 --dns-addr 77.88.8.8 --dns-port 1253 --dnsv6-addr 2a02:6b8::feed:0ff --dnsv6-port 1253",
            "dns-only|GoodbyeDpi|alternative|--dns-addr 77.88.8.8 --dns-port 1253 --dnsv6-addr 2a02:6b8::feed:0ff --dnsv6-port 1253",
            "legacy-1|GoodbyeDpi|nodns|--set-ttl 3",
            "legacy-2|GoodbyeDpi|nodns|-4 --set-ttl 5",
            "plain|GoodbyeDpi|nodns|-9",
            "zapret-discord|Zapret|recommended|" + Profiles.ZapretDiscord,
            "zapret-aggressive|Zapret|alternative|" + Profiles.ZapretAggressive,
            "zapret-tls|Zapret|alternative|" + Profiles.ZapretTlsOnly,
            "zapret-split|Zapret|alternative|" + Profiles.ZapretSplitOnly,
            "byedpi-recommended|ByeDpi|recommended|--split 1+s --disorder 3+s --mod-http=h,d --auto=torst --tlsrec 1+s",
            "byedpi-fake|ByeDpi|alternative|--disorder 1 --fake -1 --ttl 8",
            "byedpi-tlsrec|ByeDpi|alternative|--split 1+s --tlsrec 3+s --auto=torst --timeout 3 --disorder 1 --tlsrec 1+s",
            "byedpi-oob|ByeDpi|alternative|--split 1+s --oob 3+s --auto=torst --disorder 3+s",
        };

        // ============================================================================ fakes for the scanner

        sealed class FakeTrial : ITrial
        {
            public FakeHost H;
            public ProbeTransport Transport => ProbeTransport.Direct;
            public int Pid => 4242;
            public bool Alive(out LocText why)
            {
                bool ok = H.TrialAlive?.Invoke() ?? true;
                why = ok ? null : new LocText("scan.trial.exited");
                return ok;
            }
            public void Dispose()
            {
                if (H.current == null) return;
                H.current = null;
                H.Disposed++;
                H.OnDispose?.Invoke();
            }
        }

        /// <summary>A scan host without any system access: verdicts per (profile, target, round, start number).</summary>
        sealed class FakeHost : IScanHost
        {
            public EnvSnapshot Env = new EnvSnapshot { State = EngineState.Stopped };
            public Func<string, string, int, int, TargetVerdict> Verdict = (pid, host, round, start) => TargetVerdict.Fail;
            public Func<string, int> Ms = pid => 100;
            public Func<Profile, LocText> Unavailable = p => null;
            public HashSet<string> StartFails = new HashSet<string>();
            public LocText DriverBlock;
            public bool ApplyOk = true;
            public int Captures, Suspends, Restores, Applies, Disposed, Active, MaxActive, Probes;
            public readonly List<string> Started = new List<string>();
            public Func<CancellationToken, Task> ProbeDelay;
            public Func<Profile, IReadOnlyList<string>, bool, ListPlan> PlanFn;
            public Action OnDispose;
            /// <summary>Stage 6: whether the running candidate is still alive (null: always).</summary>
            public Func<bool> TrialAlive;
            public string current;
            readonly Dictionary<string, int> rounds = new Dictionary<string, int>();
            readonly Dictionary<string, int> starts = new Dictionary<string, int>();

            public EnvSnapshot Capture() { Captures++; return Env; }
            public SuspendResult Suspend(EnvSnapshot env, object token) { Suspends++; return new SuspendResult { DriverBlock = DriverBlock, DriverBlockCode = DriverBlock != null ? "NSF-301" : "" }; }
            public Task<bool> PretestAsync(CancellationToken ct) => Task.FromResult(true);
            public Task<DnsComparison> CompareDnsAsync(string host, bool skipDoh, CancellationToken ct)
            {
                var ip = IPAddress.Parse("104.16.1.1");
                return Task.FromResult(DnsComparison.Compare(host, new DnsAnswer { Status = DnsStatus.Ok, Addresses = { ip } }, new DohResult { Status = DohStatus.Ok, Addresses = { ip } }));
            }

            /// <summary>Stage 5: a target measured by the real probe (loopback servers) instead of the verdict table.</summary>
            public Func<string, ProbeTransport, CancellationToken, Task<TargetProbe>> ProbeFn;

            public async Task<TargetProbe> ProbeAsync(string host, ProbeTransport via, CancellationToken ct)
            {
                if (ProbeFn != null) { lock (this) Probes++; return await ProbeFn(host, via, ct); }
                string pid = current;
                int a = Interlocked.Increment(ref Active);
                lock (this) { MaxActive = Math.Max(MaxActive, a); Probes++; }
                try
                {
                    if (ProbeDelay != null) await ProbeDelay(ct);
                    ct.ThrowIfCancellationRequested();
                    int round, start;
                    lock (this)
                    {
                        string k = (pid ?? "-") + "|" + host;
                        rounds[k] = round = (rounds.TryGetValue(k, out var r) ? r : 0) + 1;
                        start = pid != null && starts.TryGetValue(pid, out var s) ? s : 0;
                    }
                    var v = Verdict(pid, host, round, start);
                    int ms = Ms(pid);
                    return new TargetProbe
                    {
                        Host = host, Ip = "104.16.1.1", Verdict = v, Stage = v == TargetVerdict.Fail ? ProbeStage.Tls : ProbeStage.Done,
                        ConnectMs = 5, TlsMs = 10, HttpMs = ms - 15, Status = 200, Code = v == TargetVerdict.Pass ? "" : "NSF-501",
                        Detail = new LocText(v == TargetVerdict.Pass ? "scan.http.expected" : "scan.probe.tlsFailed", "x"),
                    };
                }
                finally { Interlocked.Decrement(ref Active); }
            }

            public Task<StunResult> StunAsync(CancellationToken ct) => Task.FromResult(new StunResult { Status = StunStatus.Ok, Ms = 30 });
            public bool Available(Profile p, out LocText why) { why = Unavailable(p); return why == null; }
            public ListPlan PlanLists(Profile p, IReadOnlyList<string> targets, bool widen) => PlanFn?.Invoke(p, targets, widen) ?? new ListPlan();

            public Task<TrialStart> StartTrialAsync(Profile p, ListPlan lists, CancellationToken ct)
            {
                ct.ThrowIfCancellationRequested();
                Started.Add(p.Id);
                lock (this) starts[p.Id] = (starts.TryGetValue(p.Id, out var s) ? s : 0) + 1;
                if (StartFails.Contains(p.Id)) return Task.FromResult(new TrialStart { Error = new LocText("engine.raw", "fail"), Code = "NSF-601" });
                current = p.Id;
                return Task.FromResult(new TrialStart { Trial = new FakeTrial { H = this } });
            }

            public void FlushDns() { }
            public bool Apply(Profile p, EnvSnapshot env, object token, out LocText error)
            {
                Applies++;
                error = ApplyOk ? null : new LocText("scan.apply.failedWhy", "NSF-601", "test");
                return ApplyOk;
            }
            public RestoreReport Restore(EnvSnapshot env, object token) { Restores++; return new RestoreReport(); }
        }

        sealed class FakeScm : IServiceControl
        {
            public ServiceInfo Info = new ServiceInfo();
            public bool StopWorks = true;
            public int StopCalls, StartCalls, SetCalls;
            static ServiceInfo Copy(ServiceInfo i) => new ServiceInfo { Exists = i.Exists, Status = i.Status, StartType = i.StartType, ImagePath = i.ImagePath, Owned = i.Owned };
            public ServiceInfo Query(string name) => Copy(Info);
            public bool Stop(string name, TimeSpan wait) { StopCalls++; if (StopWorks) Info.Status = ServiceControllerStatus.Stopped; return StopWorks; }
            public bool Start(string name, TimeSpan wait) { StartCalls++; Info.Status = ServiceControllerStatus.Running; return true; }
            public bool SetStartType(string name, ServiceStartMode m) { SetCalls++; Info.StartType = m; return true; }
            public int CreateCalls, ConfigCalls, DeleteCalls;
            public bool ConfigWorks = true;
            public bool Create(string name, string bin, string display, out string o) { CreateCalls++; o = ""; Info = new ServiceInfo { Exists = true, ImagePath = bin, StartType = ServiceStartMode.Automatic, Owned = ServiceOwnership.OwnedEngine(bin) }; return true; }
            public bool Configure(string name, string bin, out string o) { ConfigCalls++; o = ConfigWorks ? "" : "config failed"; if (!ConfigWorks) return false; Info.ImagePath = bin; Info.Owned = ServiceOwnership.OwnedEngine(bin); Info.StartType = ServiceStartMode.Automatic; return true; }
            public bool SetCommand(string name, string bin, out string o) { ConfigCalls++; o = ""; Info.ImagePath = bin; Info.Owned = ServiceOwnership.OwnedEngine(bin); return true; }
            public bool Delete(string name, out string o) { DeleteCalls++; o = ""; Info = new ServiceInfo(); return true; }
        }

        /// <summary>A stream that records what is written (and reads nothing).</summary>
        sealed class RecordingStream : MemoryStream
        {
            public int Writes;
            public override void Write(byte[] buffer, int offset, int count) { Writes++; base.Write(buffer, offset, count); }
            public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct) { Writes++; return base.WriteAsync(buffer, offset, count, ct); }
        }

        static Profile BI(string id) => Profiles.BuiltIns.First(p => p.Id == id);

        static ScanOutcome RunScan(ScanRequest req, IScanHost host, CancellationToken ct = default(CancellationToken)) =>
            Task.Run(() => new Scanner(req, host).RunAsync(ct)).GetAwaiter().GetResult();

        static string repo4;

        static readonly string[] T3 = { "discord.com", "gateway.discord.gg", "cdn.discordapp.com" };

        // ============================================================================ loopback servers

        /// <summary>A one-connection SOCKS5 server: records the CONNECT request; replies with <paramref name="rep"/>, then answers one HTTP request.</summary>
        static (int Port, Task<(int Atyp, byte[] Addr, int DstPort, bool GotGet)> Done) FakeSocks(byte rep, string httpAnswer = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        {
            var l = new TcpListener(IPAddress.Loopback, 0);
            l.Start();
            int port = ((IPEndPoint)l.LocalEndpoint).Port;
            var t = Task.Run<(int Atyp, byte[] Addr, int DstPort, bool GotGet)>(async () =>
            {
                try
                {
                    var acc = l.AcceptTcpClientAsync();
                    if (await Task.WhenAny(acc, Task.Delay(8000)) != acc) return (0, null, 0, false);
                    using (var c = acc.Result)
                    {
                        var s = c.GetStream();
                        s.ReadTimeout = 5000;
                        byte[] R(int n) { var b = new byte[n]; int g = 0; while (g < n) { int r = s.Read(b, g, n - g); if (r <= 0) throw new IOException(); g += r; } return b; }
                        var greet = R(2); R(greet[1]);
                        s.Write(new byte[] { 5, 0 }, 0, 2);
                        var h = R(4);
                        byte[] addr = h[3] == 1 ? R(4) : h[3] == 4 ? R(16) : R(R(1)[0]);
                        var pb = R(2);
                        s.Write(new byte[] { 5, rep, 0, 1, 0, 0, 0, 0, 0, 0 }, 0, 10);
                        bool get = false;
                        if (rep == 0)
                        {
                            var buf = new byte[4096];
                            int n = s.Read(buf, 0, buf.Length);
                            get = n > 3 && Encoding.ASCII.GetString(buf, 0, n).StartsWith("GET / HTTP/1.1");
                            var ans = Encoding.ASCII.GetBytes(httpAnswer);
                            s.Write(ans, 0, ans.Length);
                        }
                        return ((int)h[3], addr, (pb[0] << 8) | pb[1], get);
                    }
                }
                catch { return (-1, null, 0, false); }
                finally { l.Stop(); }
            });
            return (port, t);
        }

        /// <summary>A one-connection TCP server that answers with fixed bytes and reports whether an HTTP request ever arrived.</summary>
        static (int Port, Task<bool> SawGet) FakeRaw(byte[] answer, int listenMs = 1500)
        {
            var l = new TcpListener(IPAddress.Loopback, 0);
            l.Start();
            int port = ((IPEndPoint)l.LocalEndpoint).Port;
            var t = Task.Run<bool>(async () =>
            {
                try
                {
                    var acc = l.AcceptTcpClientAsync();
                    if (await Task.WhenAny(acc, Task.Delay(8000)) != acc) return false;
                    using (var c = acc.Result)
                    {
                        var s = c.GetStream();
                        var all = new StringBuilder();
                        var buf = new byte[8192];
                        var first = s.ReadAsync(buf, 0, buf.Length);
                        if (await Task.WhenAny(first, Task.Delay(3000)) == first && first.Result > 0) all.Append(Encoding.ASCII.GetString(buf, 0, first.Result));
                        try { s.Write(answer, 0, answer.Length); } catch { }
                        var sw = Stopwatch.StartNew();
                        while (sw.ElapsedMilliseconds < listenMs)
                        {
                            var rt = s.ReadAsync(buf, 0, buf.Length);
                            if (await Task.WhenAny(rt, Task.Delay(listenMs)) != rt) break;
                            int n;
                            try { n = rt.Result; } catch { break; }
                            if (n <= 0) break;
                            all.Append(Encoding.ASCII.GetString(buf, 0, n));
                        }
                        return all.ToString().Contains("GET ");
                    }
                }
                catch { return false; }
                finally { l.Stop(); }
            });
            return (port, t);
        }

        static byte[] StunAnswer(byte[] txid, IPEndPoint mapped, ushort type = 0x0101, int lengthDelta = 0, byte[] cookie = null, int attrLenDelta = 0)
        {
            var attr = new List<byte> { 0x00, 0x20, 0x00, (byte)(8 + attrLenDelta), 0x00, 0x01 };
            int xport = mapped.Port ^ 0x2112;
            attr.Add((byte)(xport >> 8)); attr.Add((byte)xport);
            var a = mapped.Address.GetAddressBytes();
            var key = new byte[] { 0x21, 0x12, 0xA4, 0x42 };
            for (int i = 0; i < 4; i++) attr.Add((byte)(a[i] ^ key[i]));
            var m = new List<byte> { (byte)(type >> 8), (byte)type, 0, (byte)(attr.Count + lengthDelta) };
            m.AddRange(cookie ?? key);
            m.AddRange(txid);
            m.AddRange(attr);
            return m.ToArray();
        }

        /// <summary>A loopback STUN server; <paramref name="answer"/> builds the reply from the request (null = no reply); <paramref name="fromOther"/> replies from another socket.</summary>
        static (IPEndPoint Ep, Task Done) FakeStun(Func<byte[], byte[]> answer, bool fromOther = false)
        {
            var u = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var ep = (IPEndPoint)u.Client.LocalEndPoint;
            var t = Task.Run(async () =>
            {
                try
                {
                    var rt = u.ReceiveAsync();
                    if (await Task.WhenAny(rt, Task.Delay(5000)) != rt) return;
                    var req = rt.Result;
                    var ans = answer(req.Buffer);
                    if (ans == null) return;
                    if (fromOther) using (var o = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0))) o.Send(ans, ans.Length, req.RemoteEndPoint);
                    else u.Send(ans, ans.Length, req.RemoteEndPoint);
                }
                catch { }
                finally { await Task.Delay(400); u.Close(); }
            });
            return (ep, t);
        }

        static ProbeEnv PlainEnv(Func<string, int, CancellationToken, Task<DnsAnswer>> resolve, List<IPEndPoint> connects, bool realConnect)
        {
            return new ProbeEnv
            {
                Resolve = resolve,
                Connect = async (ep, t, ct) =>
                {
                    lock (connects) connects.Add(ep);
                    if (realConnect && IPAddress.IsLoopback(ep.Address)) return await NetProbe.TcpConnectAsync(ep, t, ct);
                    throw new ProbeFail(ProbeStage.Connect, "NSF-503", new LocText("scan.probe.connectFailed", "test"));
                },
                // tests only: the loopback servers speak plain HTTP; the real probe always uses NetProbe.StrictTlsAsync
                Tls = (s, h, t, ct) => Task.FromResult(new TlsOutcome { Ok = true, Stream = s }),
                ConnectTimeoutMs = 3000, TlsTimeoutMs = 3000, HttpTimeoutMs = 3000,
            };
        }

        static Func<string, int, CancellationToken, Task<DnsAnswer>> Answer(params string[] ips) =>
            (h, t, ct) => Task.FromResult(new DnsAnswer { Status = DnsStatus.Ok, Addresses = ips.Select(IPAddress.Parse).ToList() });

        // ============================================================================ the tests

        static void Stage4Tests(Action<string, bool, string> Check)
        {
            var oldSettings = App.Settings;
            var oldEngine = App.Engine;
            string oldBase = App.BaseDir, oldData = App.DataDir;
            var oldIs64 = Engines.Is64BitOs;
            App.Settings = new AppSettings();
            App.Settings.Normalize();
            if (App.Engine == null) App.Engine = new Engine();
            string repo = Repo;
            repo4 = repo;
            string root = Path.Combine(Path.GetTempPath(), "nsf stage4 " + Guid.NewGuid().ToString("N").Substring(0, 6));
            try
            {
                // blocking waits below must not need the UI thread: no WinForms synchronization context while they run
                var ctx = SynchronizationContext.Current;
                SynchronizationContext.SetSynchronizationContext(null);
                Catalog4(Check);
                Settings4(Check, root);
                Requests4(Check);
                Scanner4(Check);
                Host4(Check);
                Net4(Check);
                Live4(Check, repo, root);
                SynchronizationContext.SetSynchronizationContext(ctx);
                // last: building pages installs a WinForms context on this thread
                Levels4(Check, repo);
                SynchronizationContext.SetSynchronizationContext(null);
            }
            catch (Exception ex) { Check("stage 4 tests ran without an exception", false, ex.GetType().Name + ": " + ex.Message + " @ " + (ex.StackTrace ?? "").Split('\n').FirstOrDefault()?.Trim()); }
            finally
            {
                Engines.Is64BitOs = oldIs64;
                App.BaseDir = oldBase;
                App.DataDir = oldData;
                App.Settings = oldSettings;
                App.Engine = oldEngine;
                try { Directory.Delete(root, true); } catch { }
            }
        }

        // ---------------------------------------------------------------------------- catalog
        static void Catalog4(Action<string, bool, string> Check)
        {
            var now = Profiles.BuiltIns.Take(Stage3BuiltIns.Length)
                .Select(p => p.Id + "|" + p.Engine + "|" + p.Group + "|" + (p.IsGoodbyeDpi ? p.BuildArgs(null) : p.EngineArgs)).ToList();
            var diff = Stage3BuiltIns.Where((l, i) => i >= now.Count || now[i] != l).ToList();
            Check("catalog: the 30 profiles of stage 3 keep their id, order, group and arguments", diff.Count == 0, diff.FirstOrDefault() ?? "");
            int g = Profiles.BuiltIns.Count(p => p.Engine == EngineKind.GoodbyeDpi), z = Profiles.BuiltIns.Count(p => p.Engine == EngineKind.Zapret),
                b = Profiles.BuiltIns.Count(p => p.Engine == EngineKind.ByeDpi);
            Check("catalog: 22 GoodbyeDPI, 9 Zapret and 7 ByeDPI built-in profiles (old ones included)", g == 22 && z == 9 && b == 7, g + "/" + z + "/" + b);
            Check("catalog: every built-in id is unique", Profiles.BuiltIns.Select(p => p.Id).Distinct().Count() == Profiles.BuiltIns.Count, "");
            foreach (var p in Profiles.BuiltIns.Where(x => !x.IsGoodbyeDpi))
                Check("catalog: built-in passes its engine's allow list (ArgPolicy): " + p.Id, ArgPolicy.ValidateProfile(p, out var e), e);
            foreach (var k in new[] { EngineKind.Zapret, EngineKind.ByeDpi })
            {
                var args = Profiles.BuiltIns.Where(p => p.Engine == k).Select(p => string.Join(" ", Engines.Tokens(p.EngineArgs))).ToList();
                Check("catalog: no " + k + " profile repeats another one's command under a new name", args.Distinct().Count() == args.Count, "");
            }
            var rec = ProfileCatalog.Recommended().Select(p => p.Id).ToList();
            Check("catalog: recommended layer = the recommended group, in the fixed order (stable)",
                  rec.SequenceEqual(ProfileCatalog.RecommendedOrder) && Profiles.BuiltIns.Where(p => p.Tier == ProfileTier.Recommended).Count() == rec.Count &&
                  ProfileCatalog.Recommended().Select(p => p.Id).SequenceEqual(rec), string.Join(",", rec));
            Check("catalog: every engine keeps a recommended profile first in its list (Group/Priority)",
                  Engines.All.All(e => Profiles.ForEngine(Profiles.BuiltIns, e.Kind).First().Group == Profiles.GroupRecommended), "");
            var custom = BI("zapret-tls").CloneAsCustom();
            Check("catalog: custom profiles are specialized; a copy has no tags", custom.Tier == ProfileTier.Specialized && custom.Tags.Length == 0 && BI("zapret-discord").Tier == ProfileTier.Recommended, "");
            var tags = Profiles.BuiltIns.SelectMany(p => p.Tags).Distinct().ToList();
            Check("catalog: every scenario tag and layer has a text in both languages", tags.All(t => Loc.Has("profiles.tag." + t)) &&
                  new[] { "Recommended", "Specialized", "custom" }.All(t => Loc.Has("profiles.tier." + t)), string.Join(",", tags.Where(t => !Loc.Has("profiles.tag." + t))));
            Check("catalog: ISP and mobile labels are only trial scenarios (\"try-…\")",
                  tags.Where(t => t.EndsWith("-tt") || t == "tt" || t.Contains("telekom") || t.Contains("superonline") || t.Contains("vodafone") || t.Contains("mobile")).All(t => t.StartsWith("try-")), "");
            var ser = new System.Xml.Serialization.XmlSerializer(typeof(Profile));
            var sw = new StringWriter();
            ser.Serialize(sw, BI("zapret-voice").CloneAsCustom());
            Check("catalog: the layer and tags are never written to settings", !sw.ToString().Contains("<Tags") && !sw.ToString().Contains("<Tier"), "");
            Check("catalog: ByeDPI descriptions name the first-tried method and the fallback group",
                  Profiles.BuiltIns.Where(p => p.Engine == EngineKind.ByeDpi && p.EngineArgs.Contains("--auto=torst")).All(p => Loc.En("profiles.builtin." + p.Id + ".description").Contains("First tried") && Loc.En("profiles.builtin." + p.Id + ".description").Contains("allback")), "");
            Check("catalog: \"TLS record split only\" uses no other method", CiadpiPolicy.Pairs(Profiles.ByeDpiTlsrecOnly).All(x => x.Name == "--tlsrec" || x.Name == "--auto") &&
                  CiadpiPolicy.Pairs(Profiles.ByeDpiTlsrec).Any(x => x.Name == "--split"), "");
            var capZ = Capability.Of(BI("zapret-discord"));
            Check("capability: Zapret capture ports, rule protocols and methods are read from the profile",
                  capZ.TcpPorts == "80,443" && capZ.UdpPorts == "443,50000-50100" && capZ.L7 == "discord,stun" && capZ.Methods.Contains("multidisorder"), capZ.TcpPorts + " " + capZ.UdpPorts + " " + capZ.L7);
            var capG = Capability.Of(BI("tr-native"));
            Check("capability: GoodbyeDPI DNS redirect and QUIC block are named (a block is not a QUIC success)",
                  capG.Dns.Length > 0 && capG.QuicBlocked && !Capability.Of(BI("tr-recommended")).QuicBlocked && Capability.Of(BI("plain")).Dns.Length == 0, capG.Dns);
            var stunZ = new Profile { Engine = EngineKind.Zapret, EngineArgs = "--wf-udp=3478 --filter-udp=3478 --dpi-desync=fake" };
            Check("capability: STUN 3478 is outside the built-in rules → general UDP; ByeDPI → N/A; a rule for 3478 → profile",
                  capZ.UdpScope(Stun.Port) == "general" && Capability.Of(BI("byedpi-oob")).UdpScope(Stun.Port) == "na" &&
                  Capability.Of(BI("tr-recommended")).UdpScope(Stun.Port) == "general" && Capability.Of(stunZ).UdpScope(Stun.Port) == "profile", "");
        }

        // ---------------------------------------------------------------------------- levels, filters, command preview
        static void Levels4(Action<string, bool, string> Check, string repo)
        {
            var s = App.Settings;
            var all = App.AllProfiles.ToList();
            var simple = ProfileCatalog.Visible(all, UiLevel.Simple, false, null, "tr-recommended", null);
            Check("filter: Simple lists the recommended profiles of every engine", simple.Select(p => p.Id).SequenceEqual(ProfileCatalog.RecommendedOrder), string.Join(",", simple.Select(p => p.Id)));
            var simpleEx = ProfileCatalog.Visible(all, UiLevel.Simple, false, null, "zapret-lastresort", "zapret-lastresort");
            Check("filter: the selected/running expert profile is shown once in Simple",
                  simpleEx.Count(p => p.Id == "zapret-lastresort") == 1 && simpleEx.Count == ProfileCatalog.RecommendedOrder.Length + 1 &&
                  ProfileCatalog.IsException(BI("zapret-lastresort"), UiLevel.Simple, false), "");
            var stdOff = ProfileCatalog.Visible(all, UiLevel.Standard, false, EngineKind.Zapret, "zapret-ttl", "zapret-voice");
            Check("filter: Standard without experts: the engine's recommended + the selected and the running profile",
                  stdOff.Select(p => p.Id).SequenceEqual(new[] { "zapret-discord", "zapret-general", "zapret-ttl", "zapret-voice" }), string.Join(",", stdOff.Select(p => p.Id)));
            var stdOn = ProfileCatalog.Visible(all, UiLevel.Standard, true, EngineKind.Zapret, "zapret-ttl", null);
            var adv = ProfileCatalog.Visible(all, UiLevel.Advanced, false, EngineKind.Zapret, "zapret-ttl", null);
            Check("filter: Standard with \"show expert profiles\" and Advanced list every profile of the engine, recommended first",
                  stdOn.Count == 9 && adv.Count == 9 && adv[0].Id == "zapret-discord" && adv[1].Id == "zapret-general" && !ProfileCatalog.IsException(BI("zapret-ttl"), UiLevel.Advanced, false), "");
            Check("filter: another engine's selected profile is not added to an engine's list",
                  !ProfileCatalog.Visible(all, UiLevel.Standard, false, EngineKind.ByeDpi, "zapret-ttl", null).Any(p => p.Engine != EngineKind.ByeDpi), "");
            Check("filter: the exception is not added to the recommended scan",
                  !ScanCatalog.Candidates(ScanScope.Recommended, EngineKind.Zapret, all).Any(p => p.Id == "zapret-lastresort"), "");
            s.SelectedProfileId = "zapret-voice";
            var tray = new ProfileTrayChoices().Items().Select(c => c.Id).ToList();
            Check("tray: the active engine's recommended profiles and the selected expert profile, once each",
                  tray.SequenceEqual(new[] { "zapret-discord", "zapret-general", "zapret-voice" }) && tray.Distinct().Count() == tray.Count, string.Join(",", tray));
            s.SelectedProfileId = "tr-recommended";

            // ------------------------------------------------ the two level switches behave the same; a rebuild has no side effects
            int saves0 = SettingsStore.SaveRequests, ch0 = UiLevelSwitch.Changes;
            s.UiLevel = UiLevel.Standard;
            bool same = UiLevelSwitch.Set(UiLevel.Standard, null);
            bool changed = UiLevelSwitch.Set(UiLevel.Advanced, null);
            Check("levels: the switch ignores the same level and saves a new one once",
                  !same && changed && s.UiLevel == UiLevel.Advanced && SettingsStore.SaveRequests == saves0 + 1 && UiLevelSwitch.Changes == ch0 + 1, "");
            string ap = File.ReadAllText(Path.Combine(repo, @"src\UI\AppearancePage.cs")), op = File.ReadAllText(Path.Combine(repo, @"src\UI\OtherPages.cs"));
            Check("levels: the Appearance and Settings pages use the same switch",
                  ap.Contains("UiLevelSwitch.Set((UiLevel)seg.SelectedIndex, this)") && op.Contains("UiLevelSwitch.Set((UiLevel)seg.SelectedIndex, this)") &&
                  !ap.Contains("App.Settings.UiLevel = (UiLevel)seg") && !op.Contains("App.Settings.UiLevel = (UiLevel)seg"), "");
            try
            {
                Theme.Apply(Palettes.Resolve(s));
                s.SelectedProfileId = "zapret-voice";
                foreach (var lvl in new[] { UiLevel.Simple, UiLevel.Standard, UiLevel.Advanced })
                {
                    s.UiLevel = lvl;
                    int sv = SettingsStore.SaveRequests, sel = Actions.SelectRequests, refused = ScanGate.Refused;
                    var state = App.Engine.State;
                    var pages = new List<Control> { new HomePage(), new ProfilesPage(), new SettingsPage(), new AppearancePage(), new SitesPage() };
                    foreach (var pg in pages) { var h = pg.Handle; }
                    var pp = (ProfilesPage)pages[1];
                    pp.OnActivated();
                    var listed = pp.ListedProfiles().Select(p => p.Id).ToList();
                    foreach (var pg in pages) pg.Dispose();
                    Check("levels: building the pages at " + lvl + " selects no engine, starts/stops nothing and writes no setting",
                          SettingsStore.SaveRequests == sv && Actions.SelectRequests == sel && ScanGate.Refused == refused && App.Engine.State == state && s.SelectedProfileId == "zapret-voice", "");
                    Check("levels: the profiles page at " + lvl + " shows the selected expert profile",
                          listed.Contains("zapret-voice") && (lvl != UiLevel.Simple || listed.Count == ProfileCatalog.RecommendedOrder.Length + 1), string.Join(",", listed));
                }
            }
            catch (Exception ex) { Check("levels: pages could be built", false, ex.GetType().Name + ": " + ex.Message); }
            finally { s.UiLevel = UiLevel.Simple; s.SelectedProfileId = "tr-recommended"; }
            string mf = File.ReadAllText(Path.Combine(repo, @"src\UI\MainForm.cs"));
            Check("levels: Simple reaches the plain profiles page from the normal navigation", mf.Contains("(\"profiles\", \"nav.profiles\", GProfiles, UiLevel.Simple)"), "");
            string home = File.ReadAllText(Path.Combine(repo, @"src\UI\HomePage.cs"));
            Check("levels: Simple home has \"Find & connect\": recommended of every engine, stop at the first full success, apply",
                  home.Contains("ScanRequest.SimpleConnect(\"home\"), autoStart: true") && Loc.Has("home.findAndConnect"), "");
        }

        // ---------------------------------------------------------------------------- settings, targets, command preview
        static void Settings4(Action<string, bool, string> Check, string root)
        {
            foreach (var ok in new[] { "discord.com", "gateway.discord.gg", "xn--mteri-kva70e.com.tr", "a-b.example.org", "Discord.com" })
                Check("targets: accepted " + ok, ScanTargets.IsValid(ok.ToLowerInvariant()), "");
            foreach (var (bad, why) in new[]
            {
                ("https://discord.com", "scheme"), ("discord.com:443", "port"), ("discord.com/app", "path"), ("discord.com?x=1", "query"), (" discord.com", "space"),
                ("disc ord.com", "space"), ("discord.com\t", "space"), ("*.discord.com", "wildcard"), ("1.2.3.4", "ip"), ("[::1]", "ip"), ("2001:db8::1", "port"),
                ("localhost", "invalid"), ("printer.local", "local"), ("router.lan", "local"), ("x.home.arpa", "local"), ("site.test", "local"), ("m\u00fc\u015fteri.com", "ascii"),
                ("discord.com.", "invalid"), ("-x.com", "invalid"), ("x\u0001.com", "space"), ("user@discord.com", "credentials"), ("", "empty"), (new string('a', 64) + ".com", "invalid"),
            })
                Check("targets: rejected (" + why + ") " + bad.Replace("\t", "\\t").Replace("\u0001", "\\x01"), !ScanTargets.IsValid(bad, out var key) && key == "scan.target.bad." + why, ScanTargets.IsValid(bad, out var k2) ? "accepted" : k2);
            var st = new AppSettings { TestHosts = new List<string> { "https://Discord.com/app", "gateway.discord.gg", "bad host", "localhost", "discord.com", "ftp://x.org" } };
            var hostsBefore = st.TestHosts.ToList();
            st.Normalize();
            Check("targets: first use takes the valid host names of the quick-test list (URLs give their host, duplicates go)",
                  st.TestTargets.SequenceEqual(new[] { "discord.com", "gateway.discord.gg" }), string.Join(",", st.TestTargets));
            Check("targets: the quick-test list itself is not changed", st.TestHosts.SequenceEqual(hostsBefore), string.Join(",", st.TestHosts));
            var st2 = new AppSettings { TestHosts = new List<string> { "bad host", "localhost" } };
            st2.Normalize();
            Check("targets: nothing usable → the default targets", st2.TestTargets.SequenceEqual(AppSettings.DefaultTestHosts), "");
            var st3 = new AppSettings { TestTargets = new List<string> { "discord.com", "1.2.3.4", "discord.com" } };
            st3.Normalize();
            Check("targets: saved targets are checked strictly when loaded", st3.TestTargets.SequenceEqual(new[] { "discord.com" }), "");
            Directory.CreateDirectory(root);
            string imp = Path.Combine(root, "import4.xml");
            SettingsStore.Export(new AppSettings { TestTargets = new List<string> { "https://evil.example.org/x" } }, imp);
            Check("targets: importing settings with an invalid scan target is refused", Throws<InvalidDataException>(() => SettingsStore.Import(imp)), "");
            SettingsStore.Export(new AppSettings { TestTargets = new List<string> { "discord.com", "example.org" }, ShowExpertProfiles = true, ScanScope = ScanScope.DriverlessOnly }, imp);
            var back = SettingsStore.Import(imp);
            Check("settings: scan targets, \"show expert profiles\" and the scope survive a backup",
                  back.TestTargets.SequenceEqual(new[] { "discord.com", "example.org" }) && back.ShowExpertProfiles && back.ScanScope == ScanScope.DriverlessOnly, "");
            File.WriteAllText(imp, "<?xml version=\"1.0\"?><AppSettings><Version>3</Version><SelectedProfileId>zapret-tls</SelectedProfileId><TestHosts><string>https://discord.com/</string></TestHosts></AppSettings>");
            var old3 = SettingsStore.ReadFile(imp);
            old3.Normalize();
            Check("settings: a stage-3 settings file (no TestTargets) loads; targets come from its test list",
                  old3.SelectedProfileId == "zapret-tls" && old3.TestTargets.SequenceEqual(new[] { "discord.com" }) && old3.TestHosts[0] == "https://discord.com/", string.Join(",", old3.TestTargets));

            // ------------------------------------------------ command preview = the real command
            string pkg = Path.Combine(root, "pkg");
            App.BaseDir = pkg;
            App.DataDir = Path.Combine(pkg, "data");
            var s = App.Settings;
            s.TargetedMode = true;
            s.TargetDomains = new List<string> { "discord.com", "discord.gg" };
            s.ExcludeEnabled = true;
            s.ExcludeDomains = new List<string> { "turkiye.gov.tr" };
            s.ByeDpiPort = 18990;
            foreach (var id in new[] { "zapret-discord", "byedpi-recommended", "tr-recommended" })
            {
                var p = BI(id);
                var eng = Engines.Of(p);
                bool ok = CommandPreview.TryBuild(p, s, true, out var full, out var err);
                bool listsAbsent = !Directory.Exists(Hostlists.Dir);
                string real;
                using (Hostlists.Prepare(eng, s, out var bind, out _)) real = Engine.Esc(eng.ExePath) + " " + eng.BuildArgs(p, bind);
                Check("command: the copied command of " + id + " equals the real start (lists, port, payload paths, quoting); the preview wrote no list",
                      ok && full == real && listsAbsent, "");
                Directory.Delete(Hostlists.Dir, true);
                CommandPreview.TryBuild(p, s, false, out var disp, out _);
                Check("command: the shown preview of " + id + " has short names only (no local path)", !disp.Contains(pkg) && !disp.Contains(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)) && disp.StartsWith(eng.ExeName), disp.Length > 80 ? disp.Substring(0, 80) + "…" : disp);
            }
            var bad3 = new Profile { Engine = EngineKind.Zapret, EngineArgs = "--wf-tcp=443 --debug=@x.txt" };
            Check("command: an invalid draft gives its error and no command (copy is off)", !CommandPreview.TryBuild(bad3, s, true, out var c3, out var e3) && c3 == null && e3.Length > 0 &&
                  CommandPreview.Display(bad3, s).StartsWith("✗ "), e3);
            string eng4 = File.ReadAllText(Path.Combine(repo4, @"src\Core\Engine.cs"));
            Check("command: the log gets the short form only (no user folder in the log)",
                  eng4.Contains("App.Log(\"Command: \" + eng.ExeName + \" \" + eng.BuildArgs(p, ListBinding.Display(lists.Include != null, lists.Exclude != null), true)") &&
                  !eng4.Contains("App.Log(\"Command: \" + eng.ExeName + \" \" + args"), "");
            s.TargetedMode = s.ExcludeEnabled = false;
            s.ByeDpiPort = ByeDpiNet.DefaultPort;
        }

        // ---------------------------------------------------------------------------- requests
        static void Requests4(Action<string, bool, string> Check)
        {
            var r = ScanRequest.Create(ScanScope.AllEngines, ScanMode.FullBenchmark, true, new[] { "zapret-discord", "zapret-discord", "nope", "tr-recommended", "byedpi-oob" },
                                       new[] { "Discord.com", "https://x.org", "discord.com", "localhost", "1.2.3.4", "cdn.discordapp.com" });
            Check("request: duplicates and unknown ids are left out, the order is the catalog's (recommended first)",
                  r.CandidateIds.SequenceEqual(new[] { "tr-recommended", "zapret-discord", "byedpi-oob" }) && r.Rejected.Contains("duplicate:zapret-discord") && r.Rejected.Contains("candidate:nope"),
                  string.Join(",", r.CandidateIds) + " | " + string.Join(",", r.Rejected));
            Check("request: only valid targets stay (lower case, no duplicates)", r.Targets.SequenceEqual(new[] { "discord.com", "cdn.discordapp.com" }) && r.Rejected.Count(x => x.StartsWith("target:")) == 3, string.Join(",", r.Targets));
            Check("request: a comparison never applies by itself", !r.AutoApply, "");
            var p = App.Settings.CustomProfiles;
            var cust = BI("zapret-tls").CloneAsCustom();
            p.Add(cust);
            var r2 = ScanRequest.Create(ScanScope.ActiveEngine, ScanMode.StopOnFirstMatch, true, new[] { cust.Id }, new[] { "discord.com" });
            string before = cust.EngineArgs;
            cust.EngineArgs = "--wf-tcp=443 --dpi-desync=fake";
            Check("request: the candidates are fixed when the request is made (a later edit does not change it)", r2.Candidates[0].EngineArgs == before && r2.AutoApply, "");
            p.Remove(cust);
            App.Settings.ScanAll = true;
            var simple = ScanRequest.SimpleConnect();
            Check("request: Simple \"find & connect\" = recommended of every engine, stop at the first full success, apply; the saved \"try all\" does not change it",
                  simple.Scope == ScanScope.Recommended && simple.Mode == ScanMode.StopOnFirstMatch && simple.AutoApply &&
                  simple.CandidateIds.SequenceEqual(ProfileCatalog.RecommendedOrder), string.Join(",", simple.CandidateIds));
            App.Settings.ScanAll = false;
            var heal = ScanRequest.Heal();
            Check("request: automatic repair scans the active engine and applies the first full success",
                  heal.Scope == ScanScope.ActiveEngine && heal.AutoApply && heal.Candidates.All(x => x.Engine == App.Engine.Current.Kind), "");
            var all = App.AllProfiles.ToList();
            Check("request: the scopes (recommended, active engine, all engines, driverless only)",
                  ScanCatalog.Candidates(ScanScope.Recommended, EngineKind.Zapret, all).Count == 7 && ScanCatalog.Candidates(ScanScope.ActiveEngine, EngineKind.Zapret, all).Count == 9 &&
                  ScanCatalog.Candidates(ScanScope.AllEngines, EngineKind.Zapret, all).Count == 38 && ScanCatalog.Candidates(ScanScope.DriverlessOnly, EngineKind.Zapret, all).All(x => x.Engine == EngineKind.ByeDpi), "");
            Check("request: the same scope gives the same order every time",
                  ScanCatalog.Candidates(ScanScope.AllEngines, EngineKind.GoodbyeDpi, all).Select(x => x.Id).SequenceEqual(ScanCatalog.Candidates(ScanScope.AllEngines, EngineKind.GoodbyeDpi, all.AsEnumerable().Reverse()).Select(x => x.Id)), "");
            string cl = File.ReadAllText(Path.Combine(repo4, @"src\UI\MainForm.cs")), sd = File.ReadAllText(Path.Combine(repo4, @"src\UI\ScanDialog.cs")), ac = File.ReadAllText(Path.Combine(repo4, @"src\Core\Actions.cs"));
            Check("entry points: --scan/--scan-all, tray, home, network page, troubleshooting and auto-repair all use the scan window or the new scanner",
                  cl.Contains("ScanDialog.CommandLineRequest(scanAll)") && sd.Contains("ScanRequest.ForScope(ScanScope.ActiveEngine, ScanMode.FullBenchmark, false, \"cli\")") &&
                  ac.Contains("new Scanner(ScanRequest.Heal())") && !ac.Contains("Full = false"), "");
        }

        // ---------------------------------------------------------------------------- the scanner (fakes)
        static void Scanner4(Action<string, bool, string> Check)
        {
            ScanRequest Req(ScanMode m, bool apply, params string[] ids) => ScanRequest.Create(ScanScope.AllEngines, m, apply, ids, T3);
            var three = new[] { "tr-recommended", "zapret-discord", "byedpi-recommended" };

            // StopOnFirstMatch
            var h1 = new FakeHost { Verdict = (pid, host, rd, st) => pid == "zapret-discord" ? TargetVerdict.Pass : TargetVerdict.Fail };
            var o1 = RunScan(Req(ScanMode.StopOnFirstMatch, true, three), h1);
            Check("scan: stop at the first full success (recommended order), then apply it",
                  h1.Started.SequenceEqual(new[] { "tr-recommended", "zapret-discord" }) && o1.Applied?.Id == "zapret-discord" && h1.Applies == 1 && h1.Restores == 0 && h1.Disposed == 2,
                  string.Join(",", h1.Started) + " applied=" + o1.Applied?.Id);
            Check("scan: every probe has ended and the gate is free after the scan", h1.Active == 0 && !ScanGate.Busy && h1.MaxActive <= 4, "max " + h1.MaxActive);

            // FullBenchmark
            var h2 = new FakeHost
            {
                Verdict = (pid, host, rd, st) => pid == "byedpi-recommended" ? (host == "discord.com" ? TargetVerdict.Pass : TargetVerdict.Partial) : pid == null ? TargetVerdict.Fail : TargetVerdict.Pass,
                Ms = pid => pid == "zapret-discord" ? 200 : 300,
            };
            var o2 = RunScan(Req(ScanMode.FullBenchmark, true, three), h2);
            var rank = Scanner.Rank(o2.Rows).Select(x => x.P.Id).ToList();
            Check("scan: a comparison tries every selected candidate once and applies nothing",
                  h2.Started.SequenceEqual(three) && h2.Applies == 0 && h2.Restores == 1 && o2.Applied == null && !o2.Request.AutoApply, string.Join(",", h2.Started));
            Check("scan: ranking = score, then the average HTTPS time, then the catalog order",
                  rank.SequenceEqual(new[] { "zapret-discord", "tr-recommended", "byedpi-recommended" }) && o2.Suggested?.P.Id == "zapret-discord", string.Join(",", rank));
            var byRow = o2.Rows.First(x => x.P.Id == "byedpi-recommended");
            Check("scan: a partial row: score from the targets that passed both rounds; the time only from successful measurements",
                  byRow.Status == ScanRow.Partial && byRow.Score == 33 && byRow.AvgMs == 300 && o2.Rows.First(x => x.P.Id == "zapret-discord").Score == 100, byRow.Score + " " + byRow.AvgMs);

            // tie: same score and time → catalog order, then the id
            var h3 = new FakeHost { Verdict = (pid, host, rd, st) => pid == null ? TargetVerdict.Fail : TargetVerdict.Pass };
            var o3 = RunScan(Req(ScanMode.FullBenchmark, false, "tr-quad9", "tr-adguard"), h3);
            Check("scan: a tie is broken by the catalog order (stable)", Scanner.Rank(o3.Rows).Select(x => x.P.Id).SequenceEqual(new[] { "tr-adguard", "tr-quad9" }), "");

            // round 2 decides; no measurement = no time (never 0 ms)
            var h4 = new FakeHost { Verdict = (pid, host, rd, st) => pid == null ? TargetVerdict.Fail : rd == 2 && host == "cdn.discordapp.com" ? TargetVerdict.Fail : TargetVerdict.Pass };
            var o4 = RunScan(Req(ScanMode.StopOnFirstMatch, true, "zapret-tls"), h4);
            var r4 = o4.Rows[0];
            Check("scan: a target that fails the second round is not a full success (both rounds needed for auto apply)",
                  r4.Status == ScanRow.Partial && r4.Score == 66 && o4.Applied == null && h4.Applies == 0, r4.Status + " " + r4.Score);
            var h5 = new FakeHost();
            var o5 = RunScan(Req(ScanMode.StopOnFirstMatch, true, "zapret-tls"), h5);
            Check("scan: nothing passed → no average time is shown (null, not 0 ms)", o5.Rows[0].AvgMs == null && o5.Rows[0].Status == ScanRow.Failed && o5.Applied == null && h5.Restores == 1, "");

            // empty selection / empty targets
            var h6 = new FakeHost();
            var o6 = RunScan(ScanRequest.Create(ScanScope.Recommended, ScanMode.StopOnFirstMatch, true, new string[0], T3), h6);
            var o6b = RunScan(ScanRequest.Create(ScanScope.Recommended, ScanMode.StopOnFirstMatch, true, three, new string[0]), h6);
            Check("scan: an empty candidate or target list is reported and protection is not touched",
                  o6.Summary?.Key == "scan.noCandidates" && o6b.Summary?.Key == "scan.noTargets" && h6.Captures == 0 && h6.Restores == 0 && h6.Started.Count == 0, "");

            // late cancel: after the winner was measured, before it is applied
            var cts7 = new CancellationTokenSource();
            var h7 = new FakeHost { Verdict = (pid, host, rd, st) => pid == null ? TargetVerdict.Fail : TargetVerdict.Pass };
            h7.OnDispose = () => cts7.Cancel();
            var o7 = RunScan(Req(ScanMode.StopOnFirstMatch, true, three), h7, cts7.Token);
            Check("scan: a late cancel never applies an earlier successful row; the state is restored",
                  o7.Cancelled && o7.Applied == null && h7.Applies == 0 && h7.Restores == 1 && h7.Active == 0 && !ScanGate.Busy, "");

            // cancel in the middle of the measurements
            var cts8 = new CancellationTokenSource();
            var h8 = new FakeHost { ProbeDelay = async ct => { await Task.Delay(30, ct); } };
            h8.Verdict = (pid, host, rd, st) => { if (pid == "zapret-discord") cts8.Cancel(); return TargetVerdict.Fail; };
            var o8 = RunScan(Req(ScanMode.FullBenchmark, false, three), h8, cts8.Token);
            Check("scan: a cancel during a round stops the candidate, ends every probe and restores the state",
                  o8.Cancelled && h8.Active == 0 && h8.Disposed == h8.Started.Count && h8.Restores == 1 && !h8.Started.Contains("byedpi-recommended") && !ScanGate.Busy,
                  string.Join(",", h8.Started) + " disposed=" + h8.Disposed);

            // one owner: double start, profile change, engine start, watchdog while a scan runs
            int inside = 0;
            bool secondBusy = false, startRefused = false, selectRefused = false;
            var h9 = new FakeHost();
            h9.ProbeDelay = async ct =>
            {
                if (Interlocked.Exchange(ref inside, 1) == 1) return;
                var o = await new Scanner(Req(ScanMode.StopOnFirstMatch, true, three), new FakeHost()).RunAsync(CancellationToken.None);
                secondBusy = o.Busy;
                int before = ScanGate.Refused;
                startRefused = !App.Engine.Start(BI("tr-recommended")) && ScanGate.Refused == before + 1;
                string sel = App.Settings.SelectedProfileId;
                await Actions.SelectProfileAsync(BI("zapret-discord"));
                await Actions.StartAsync();
                selectRefused = App.Settings.SelectedProfileId == sel;
            };
            RunScan(Req(ScanMode.StopOnFirstMatch, true, "tr-recommended"), h9);
            Check("scan: one owner – a second scan, an engine start and a profile change are refused while a scan runs",
                  secondBusy && startRefused && selectRefused && !ScanGate.Busy && ScanGate.Allows(null), "busy=" + secondBusy + " start=" + startRefused + " select=" + selectRefused);

            // failed apply: back to the previous state, no success in the history
            var h10 = new FakeHost { Verdict = (pid, host, rd, st) => pid == null ? TargetVerdict.Fail : TargetVerdict.Pass, ApplyOk = false };
            var o10 = RunScan(Req(ScanMode.StopOnFirstMatch, true, three), h10);
            var hist = History.Snapshot().LastOrDefault(x => x.Kind == "scan");
            Check("scan: a failed apply is rolled back (restore) and no success is written to the history",
                  o10.ApplyFailed && o10.Applied == null && h10.Restores == 1 && hist != null && hist.Ok == 0, "");

            // off before the scan + AutoStartProtection: stays off (the fake host records only one restore, the live restore is tested below)
            App.Settings.AutoStartProtection = true;
            var h11 = new FakeHost { Env = new EnvSnapshot { State = EngineState.Stopped } };
            var o11 = RunScan(Req(ScanMode.StopOnFirstMatch, true, three), h11);
            Check("scan: protection that was off stays off when nothing worked (AutoStartProtection does not replace it)", h11.Applies == 0 && h11.Restores == 1 && o11.Applied == null, "");

            // driver block (service timeout, foreign WinDivert program): WinDivert candidates skipped with the reason, ByeDPI still tried
            var h12 = new FakeHost { DriverBlock = new LocText("scan.block.foreignProcess", "winws (PID 1)") };
            var o12 = RunScan(Req(ScanMode.FullBenchmark, false, three), h12);
            Check("scan: an unsafe driver situation skips the WinDivert candidates with the reason; ByeDPI is still tried",
                  h12.Started.SequenceEqual(new[] { "byedpi-recommended" }) &&
                  o12.Rows.Where(x => x.P.Engine != EngineKind.ByeDpi).All(x => x.Status == ScanRow.Skipped && x.Note?.Key == "scan.block.foreignProcess"), string.Join(",", h12.Started));

            // 32-bit Windows: Zapret and ByeDPI are shown as unavailable (NSF-107), GoodbyeDPI is tried
            var h13 = new FakeHost { Unavailable = p => p.Engine == EngineKind.GoodbyeDpi ? null : Engines.Unavailable64(Engines.Of(p)) };
            var o13 = RunScan(Req(ScanMode.FullBenchmark, false, three), h13);
            Check("scan: candidates of an unavailable engine are shown with NSF-107, never silently dropped",
                  o13.Rows.Count == 3 && h13.Started.SequenceEqual(new[] { "tr-recommended" }) && o13.Rows.Where(x => x.P.Engine != EngineKind.GoodbyeDpi).All(x => x.Status == ScanRow.Unavailable && x.Code == "NSF-107"), "");

            // a start failure is shown, the scan goes on
            var h14 = new FakeHost { StartFails = { "tr-recommended" }, Verdict = (pid, host, rd, st) => pid == null ? TargetVerdict.Fail : TargetVerdict.Pass };
            var o14 = RunScan(Req(ScanMode.StopOnFirstMatch, true, three), h14);
            Check("scan: a candidate that cannot start is shown and the next one is tried", o14.Rows[0].Status == ScanRow.StartFailed && o14.Applied?.Id == "zapret-discord", "");

            // list scope: an out-of-scope target never counts; a result found with a temporary wider list is checked with the real lists first
            var h15 = new FakeHost
            {
                Verdict = (pid, host, rd, st) => pid == null ? TargetVerdict.Fail : TargetVerdict.Pass,
                PlanFn = (p, t, w) => new ListPlan { Include = new List<string> { "discord.com" }, InScope = h => h == "discord.com" },
            };
            var o15 = RunScan(Req(ScanMode.StopOnFirstMatch, false, "zapret-discord"), h15);
            var r15 = o15.Rows[0];
            Check("scan: targets outside the site lists are not counted as the profile's success",
                  r15.Required == 1 && r15.PassedBoth == 1 && r15.Targets.Count(x => !x.InScope) == 2 && r15.Targets.Where(x => !x.InScope).All(x => x.R1 == null), "");
            var h16 = new FakeHost
            {
                Verdict = (pid, host, rd, st) => pid == null ? TargetVerdict.Fail : st >= 2 ? TargetVerdict.Fail : TargetVerdict.Pass,
                PlanFn = (p, t, w) => w ? new ListPlan { Widened = true, Added = { "gateway.discord.gg" } } : new ListPlan { InScope = h => h == "discord.com" },
            };
            var o16 = ScanOutcomeWiden(h16);
            Check("scan: a result found only with the temporary wider list is not applied when the real lists fail",
                  o16.Suggested != null && o16.Applied == null && h16.Applies == 0 && o16.NotAppliedWhy?.Key == "scan.notVerifiedReal" && h16.Started.Count == 2 && h16.Restores == 1, "");
            var h17 = new FakeHost { PlanFn = (p, t, w) => new ListPlan { InScope = h => false } };
            var o17 = RunScan(Req(ScanMode.StopOnFirstMatch, true, "zapret-discord"), h17);
            Check("scan: a profile that applies to no target is shown (no silent widening)", o17.Rows[0].Status == ScanRow.NoScope && h17.Started.Count == 0, "");
        }

        static ScanOutcome ScanOutcomeWiden(FakeHost h) =>
            RunScan(ScanRequest.Create(ScanScope.AllEngines, ScanMode.StopOnFirstMatch, true, new[] { "zapret-discord" }, T3, widen: true), h);

        // ---------------------------------------------------------------------------- the live host (no system change: fake SCM)
        static void Host4(Action<string, bool, string> Check)
        {
            var s = App.Settings;
            string ownImage = "\"" + Engines.Zapret.ExePath + "\" --wf-tcp=443";
            Check("service: a command line of this installation's engine is ours; another folder's is not",
                  ServiceOwnership.OwnedEngine(ownImage) == EngineKind.Zapret && ServiceOwnership.OwnedEngine(Engines.GoodbyeDpi.ExePath + " -9") == EngineKind.GoodbyeDpi &&
                  ServiceOwnership.OwnedEngine("\"C:\\Other\\bin\\zapret\\winws.exe\" --wf-tcp=443") == null && ServiceOwnership.OwnedEngine("") == null &&
                  ServiceOwnership.ExeOf("\"C:\\a b\\x.exe\" -q") == "C:\\a b\\x.exe", "");
            var running = new ServiceInfo { Exists = true, Status = ServiceControllerStatus.Running, StartType = ServiceStartMode.Automatic, ImagePath = ownImage, Owned = EngineKind.Zapret };
            object token = ScanGate.TryAcquire();
            EnvSnapshot Snap(EngineState st, Profile active, bool svc, ServiceInfo si) => new EnvSnapshot
            {
                State = st, ActiveProfile = active, RunningAsService = svc, Service = si, SelectedId = s.SelectedProfileId,
                LastGoodbyeDpi = s.LastGoodbyeDpiProfileId, LastZapret = s.LastZapretProfileId, LastByeDpi = s.LastByeDpiProfileId,
            };
            try
            {
                var scmT = new FakeScm { Info = running, StopWorks = false };
                var hT = new LiveScanHost(scmT);
                var envT = Snap(EngineState.Running, BI("zapret-discord"), true, scmT.Query("x"));
                var rT = hT.Suspend(envT, token);
                Check("service: a service that does not stop in time blocks the WinDivert candidates (the SCM is asked, not the settings)",
                      rT.DriverBlock?.Key == "scan.block.serviceTimeout" && rT.DriverBlockCode == "NSF-702" && scmT.StopCalls == 1, rT.DriverBlock?.Key ?? "none");
                var scmF = new FakeScm { Info = new ServiceInfo { Exists = true, Status = ServiceControllerStatus.Running, ImagePath = "\"D:\\Old\\goodbyedpi.exe\" -9" } };
                var envF = Snap(EngineState.Stopped, null, false, scmF.Query("x"));
                var rF = new LiveScanHost(scmF).Suspend(envF, token);
                Check("service: another installation's service is never stopped; WinDivert candidates are skipped instead",
                      scmF.StopCalls == 0 && rF.DriverBlock?.Key == "scan.block.serviceNotOwned", rF.DriverBlock?.Key ?? "none");
                var scmO = new FakeScm { Info = running };
                var envO = Snap(EngineState.Running, BI("zapret-discord"), true, scmO.Query("x"));
                var rO = new LiveScanHost(scmO).Suspend(envO, token);
                bool foreignHere = Engines.DriverProcessNames.Any(n => Process.GetProcessesByName(n).Length > 0);
                Check("service: the own service is stopped and confirmed stopped by the SCM" + (foreignHere ? " (a WinDivert program runs on this computer: its block is reported)" : ""),
                      scmO.StopCalls == 1 && envO.ServiceStopped && (rO.DriverBlock == null || (foreignHere && rO.DriverBlock.Key == "scan.block.foreignProcess")), rO.DriverBlock?.Key ?? "none");
                var rep = new LiveScanHost(scmO).Restore(envO, token);
                Check("restore: the own service comes back through the SCM (its verified command line is not rebuilt)",
                      scmO.StartCalls == 1 && scmO.Info.Status == ServiceControllerStatus.Running && rep.Done.Any(d => d.Key == "scan.restore.service"), string.Join(",", rep.Problems.Select(x => x.Key)));
                var rep2 = new LiveScanHost(scmO).Restore(envO, token);
                Check("restore: a second call does nothing (one cleanup path, safe to repeat)", scmO.StartCalls == 1 && rep2.Done.Count == 0 && rep2.Problems.Count == 0, "");
                var scmW = new FakeScm { Info = running };
                var envW = Snap(EngineState.Running, BI("zapret-discord"), true, scmW.Query("x"));
                new LiveScanHost(scmW).Suspend(envW, token);
                scmW.Info.ImagePath = "\"" + Engines.ByeDpi.ExePath + "\" --ip 127.0.0.1";   // a failed apply changed the service
                var repW = new LiveScanHost(scmW).Restore(envW, token);
                // stage 6 (B6): the changed command line is never started as it is – the command read before the scan comes back first
                // (and is read back), only then the service runs again as it did before
                Check("restore: a service changed by a failed apply is not started as it is; its command from before the scan comes back first",
                      scmW.Info.ImagePath == envW.Service.ImagePath && scmW.StartCalls == 1 && scmW.Info.Status == ServiceControllerStatus.Running &&
                      repW.Problems.Any(x => x.Key == "scan.restore.engineFailed") && !repW.Done.Any(x => x.Key == "scan.restore.service"), "preview: the engine start itself is not run");
                var scmOff = new FakeScm { Info = new ServiceInfo { Exists = true, Status = ServiceControllerStatus.Stopped, StartType = ServiceStartMode.Automatic, ImagePath = ownImage, Owned = EngineKind.Zapret } };
                var envOff = new EnvSnapshot { State = EngineState.Stopped, SelectedId = "tr-recommended", Service = scmOff.Query("x") };
                s.AutoStartProtection = true;
                s.SelectedProfileId = "zapret-voice";
                var repOff = new LiveScanHost(scmOff).Restore(envOff, token);
                Check("restore: protection that was off stays off (AutoStartProtection is not used), the selected profile comes back",
                      scmOff.StartCalls == 0 && repOff.Done.Any(d => d.Key == "scan.restore.off") && s.SelectedProfileId == "tr-recommended" && repOff.Ok, string.Join(",", repOff.Problems.Select(x => x.Key)));
                scmOff.Info.StartType = ServiceStartMode.Manual;
                envOff.Restored = false;
                new LiveScanHost(scmOff).Restore(envOff, token);
                Check("restore: the start type of the own service is set back as it was", scmOff.SetCalls == 1 && scmOff.Info.StartType == ServiceStartMode.Automatic, "");
                var envB = Snap(EngineState.Running, BI("byedpi-recommended"), false, new ServiceInfo());
                envB.ByeDpiAttached = true;
                var rB = new LiveScanHost(new FakeScm()).Suspend(envB, token);
                Check("byedpi: a running ByeDPI with the Windows proxy stays on during the scan (the proxy never points at a dead port)",
                      !envB.Suspended && rB.Notes.Any(n => n.Key == "scan.byedpiKept"), "");
            }
            finally { ScanGate.Release(token); }

            // site lists of a candidate
            s.TargetedMode = true;
            s.TargetDomains = new List<string> { "discord.com", "discord.gg" };
            s.ExcludeEnabled = true;
            s.ExcludeDomains = new List<string> { "cdn.discordapp.com" };
            var targets = new[] { "discord.com", "gateway.discord.gg", "cdn.discordapp.com", "example.org" };
            var pz = ScanLists.Plan(Engines.Zapret, s, targets, false);
            Check("lists: a candidate uses the user's lists; a target outside them is out of scope",
                  pz.Include.SequenceEqual(new[] { "discord.com", "discord.gg" }) && pz.Exclude.SequenceEqual(new[] { "cdn.discordapp.com" }) &&
                  pz.InScope("discord.com") && pz.InScope("gateway.discord.gg") && !pz.InScope("cdn.discordapp.com") && !pz.InScope("example.org") && !pz.Widened, "");
            var pw = ScanLists.Plan(Engines.Zapret, s, targets, true);
            Check("lists: the temporary wider list adds the uncovered targets; an excluded target stays excluded; the settings are not changed",
                  pw.Widened && pw.Added.SequenceEqual(new[] { "example.org" }) && !pw.InScope("cdn.discordapp.com") && pw.InScope("example.org") &&
                  s.TargetDomains.SequenceEqual(new[] { "discord.com", "discord.gg" }), string.Join(",", pw.Added));
            var pg = ScanLists.Plan(Engines.GoodbyeDpi, s, targets, false);
            Check("lists: GoodbyeDPI cannot exclude: the warning is kept and the excluded target is in its scope",
                  pg.Exclude == null && pg.Warnings.Any(w => w.Key == "lists.excludeUnsupported") && pg.InScope("discord.com") && !pg.InScope("example.org"), "");
            var zexp = new Profile { Engine = EngineKind.Zapret, EngineArgs = "--wf-tcp=80,443 --filter-tcp=80 --dpi-desync=fake --new --filter-tcp=443 --hostlist=include.txt --dpi-desync=fake" };
            string zargs = Engines.Zapret.BuildArgs(zexp, new ListBinding { Include = @"C:\scan x\include.txt", Exclude = @"C:\scan x\exclude.txt" });
            var secs = zargs.Split(new[] { " --new " }, StringSplitOptions.None);
            // stage 6 (B9): the explicit include reference keeps its place, but the exclude list is never dropped because of it;
            // stage 7: one rule placing its own include list never exempts the other rules from the target list
            Check("lists: an explicit include reference keeps its meaning with the candidate's own list file; both lists reach every host rule",
                  secs[0].Contains("\"--hostlist=C:\\scan x\\include.txt\"") && secs[0].Contains("\"--hostlist-exclude=C:\\scan x\\exclude.txt\"") &&
                  secs[1].Contains("\"--hostlist=C:\\scan x\\include.txt\"") && secs[1].Contains("\"--hostlist-exclude=C:\\scan x\\exclude.txt\"") &&
                  secs.All(x => x.Split(new[] { "--hostlist=" }, StringSplitOptions.None).Length == 2), zargs);
            string bargs = Engines.ByeDpi.BuildArgs(BI("byedpi-oob"), new ListBinding { Port = 18999 });
            Check("byedpi: a candidate listens on its own port, not the one in the settings", bargs.StartsWith("--ip 127.0.0.1 --port 18999 "), bargs);
            s.TargetedMode = s.ExcludeEnabled = false;
        }

        // ---------------------------------------------------------------------------- network measurements (controlled answers, loopback)
        static void Net4(Action<string, bool, string> Check)
        {
            foreach (var (ip, cls) in new[]
            {
                ("8.8.8.8", AddressClass.Public), ("104.16.1.1", AddressClass.Public), ("10.1.2.3", AddressClass.Private), ("172.16.0.1", AddressClass.Private),
                ("172.32.0.1", AddressClass.Public), ("192.168.1.1", AddressClass.Private), ("127.0.0.1", AddressClass.Loopback), ("169.254.1.1", AddressClass.LinkLocal),
                ("100.64.0.1", AddressClass.SharedCgnat), ("100.128.0.1", AddressClass.Public), ("0.0.0.0", AddressClass.Unspecified), ("224.0.0.1", AddressClass.Multicast),
                ("255.255.255.255", AddressClass.Broadcast), ("240.0.0.1", AddressClass.Reserved), ("192.0.2.1", AddressClass.Documentation), ("198.18.0.1", AddressClass.Reserved),
                ("::", AddressClass.Unspecified), ("::1", AddressClass.Loopback), ("::ffff:8.8.8.8", AddressClass.Ipv4Mapped), ("fd00::1", AddressClass.UniqueLocal),
                ("fe80::1", AddressClass.LinkLocal), ("ff02::1", AddressClass.Multicast), ("2001:db8::1", AddressClass.Documentation), ("2001::1", AddressClass.Transition),
                ("2002:c000:204::1", AddressClass.Transition), ("2606:4700::6810:101", AddressClass.Public), ("64:ff9b::808:808", AddressClass.Public),
                ("64:ff9b::a00:1", AddressClass.Transition), ("fec0::1", AddressClass.SiteLocal), ("4000::1", AddressClass.Reserved),
            })
                Check("address: " + ip + " is " + cls, IpPolicy.Classify(IPAddress.Parse(ip)) == cls, IpPolicy.Classify(IPAddress.Parse(ip)).ToString());
            Check("address: a mixed public/private answer is refused as a whole",
                  !IpPolicy.AllPublic(new[] { IPAddress.Parse("104.16.1.1"), IPAddress.Parse("10.0.0.1") }, out var worst) && worst == AddressClass.Private &&
                  !IpPolicy.AllPublic(new IPAddress[0], out _) && IpPolicy.AllPublic(new[] { IPAddress.Parse("104.16.1.1"), IPAddress.Parse("2606:4700::1") }, out _), "");

            // the probe never contacts a non-public address and pins the checked one
            var conn = new List<IPEndPoint>();
            var mixed = NetProbe.HttpsAsync("discord.com", ProbeTransport.Direct, PlainEnv(Answer("104.16.1.1", "192.168.1.10"), conn, false), CancellationToken.None).Result;
            var priv6 = NetProbe.HttpsAsync("discord.com", ProbeTransport.Direct, PlainEnv(Answer("fd00::5"), conn, false), CancellationToken.None).Result;
            var mapped = NetProbe.HttpsAsync("discord.com", ProbeTransport.Direct, PlainEnv(Answer("::ffff:104.16.1.1"), conn, false), CancellationToken.None).Result;
            Check("probe: private, mixed and IPv4-mapped answers are never contacted (DNS layer failure)",
                  conn.Count == 0 && new[] { mixed, priv6, mapped }.All(x => x.Stage == ProbeStage.Dns && x.Detail?.Key == "scan.probe.notPublic"), mixed.Detail?.Key);
            int calls = 0;
            Func<string, int, CancellationToken, Task<DnsAnswer>> changing = (h, t, ct) =>
                Task.FromResult(new DnsAnswer { Status = DnsStatus.Ok, Addresses = { IPAddress.Parse(Interlocked.Increment(ref calls) == 1 ? "104.16.1.1" : "127.0.0.1") } });
            var envC = PlainEnv(changing, conn, false);
            var c1 = NetProbe.HttpsAsync("discord.com", ProbeTransport.Direct, envC, CancellationToken.None).Result;
            var c2 = NetProbe.HttpsAsync("discord.com", ProbeTransport.Direct, envC, CancellationToken.None).Result;
            Check("probe: DNS that changes between connections: each connection is pinned to its own checked public address",
                  conn.Count == 1 && conn[0].Address.ToString() == "104.16.1.1" && conn[0].Port == 443 && c1.Ip == "104.16.1.1" && c2.Detail?.Key == "scan.probe.notPublic", string.Join(",", conn));
            foreach (var (st, key) in new[] { (DnsStatus.NxDomain, "scan.dns.nxdomain"), (DnsStatus.NoData, "scan.dns.nodata"), (DnsStatus.Timeout, "scan.dns.timeout"), (DnsStatus.Error, "scan.dns.error") })
            {
                var x = NetProbe.HttpsAsync("discord.com", ProbeTransport.Direct, PlainEnv((h, t, ct) => Task.FromResult(new DnsAnswer { Status = st }), conn, false), CancellationToken.None).Result;
                Check("probe: system DNS " + st + " is a DNS failure (\"resolution error\" when the system cannot say more)", x.Stage == ProbeStage.Dns && x.Detail?.Key == key && x.Code == "NSF-401", "");
            }

            // SOCKS5: the real target address, never the name; a refused CONNECT is a failure without a direct fallback
            var srv = FakeSocks(0);
            conn.Clear();
            var viaOk = NetProbe.HttpsAsync("discord.com", ProbeTransport.Socks5(srv.Port), PlainEnv(Answer("104.16.1.1"), conn, true), CancellationToken.None).Result;
            var got = srv.Done.Result;
            Check("socks: the candidate's tunnel gets the checked IPv4 address (ATYP 1), port 443 – the proxy cannot resolve the name again",
                  got.Atyp == 1 && got.Addr != null && new IPAddress(got.Addr).ToString() == "104.16.1.1" && got.DstPort == 443 && got.GotGet &&
                  viaOk.Verdict == TargetVerdict.Pass && conn.All(e => IPAddress.IsLoopback(e.Address)) && viaOk.TunnelMs.HasValue, viaOk.Layers + " " + viaOk.Detail?.English);
            var srv6 = FakeSocks(0);
            var via6 = NetProbe.HttpsAsync("discord.com", ProbeTransport.Socks5(srv6.Port), PlainEnv(Answer("2606:4700::6810:101"), conn, true), CancellationToken.None).Result;
            var got6 = srv6.Done.Result;
            Check("socks: an IPv6 address is sent as an address (ATYP 4), not in the domain-name field",
                  got6.Atyp == 4 && got6.Addr != null && new IPAddress(got6.Addr).ToString() == "2606:4700::6810:101" && via6.Verdict == TargetVerdict.Pass, "atyp=" + got6.Atyp);
            var srvR = FakeSocks(5);
            conn.Clear();
            var refused = NetProbe.HttpsAsync("discord.com", ProbeTransport.Socks5(srvR.Port), PlainEnv(Answer("104.16.1.1"), conn, true), CancellationToken.None).Result;
            srvR.Done.Wait(3000);
            Check("socks: a refused CONNECT fails the candidate; no direct connection is tried",
                  refused.Stage == ProbeStage.Tunnel && refused.Verdict == TargetVerdict.Fail && refused.Detail?.Key == "scan.probe.socksRefused" && conn.All(e => IPAddress.IsLoopback(e.Address)) && conn.Count == 1, refused.Detail?.English);
            bool loopOnly;
            try { ProbeTransport.Socks5(0); loopOnly = ProbeTransport.Socks5(1080).Socks.Address.Equals(IPAddress.Loopback); } catch { loopOnly = false; }
            Check("socks: a test transport can only point at 127.0.0.1", loopOnly, "");

            // TLS: no HTTP request before a valid certificate for the original name; a certificate error is not a DNS verdict
            Check("tls: only a chain and name without errors is accepted (nothing is retried weaker)",
                  TlsPolicy.Accept(SslPolicyErrors.None) && !TlsPolicy.Accept(SslPolicyErrors.RemoteCertificateNameMismatch) && !TlsPolicy.Accept(SslPolicyErrors.RemoteCertificateChainErrors) &&
                  !TlsPolicy.Accept(SslPolicyErrors.RemoteCertificateNotAvailable), "");
            var rec = new RecordingStream();
            var envCert = new ProbeEnv
            {
                Resolve = Answer("104.16.1.1"),
                Connect = (ep, t, ct) => Task.FromResult<Stream>(rec),
                Tls = (s2, h, t, ct) => Task.FromResult(new TlsOutcome { CertError = true, Errors = SslPolicyErrors.RemoteCertificateNameMismatch, Message = "RemoteCertificateNameMismatch" }),
            };
            var cert = NetProbe.HttpsAsync("discord.com", ProbeTransport.Direct, envCert, CancellationToken.None).Result;
            Check("tls: a wrong certificate stops before any HTTP byte and is reported as a certificate error (NSF-504), not DNS poisoning",
                  cert.Stage == ProbeStage.Tls && cert.Code == "NSF-504" && cert.Detail?.Key == "scan.probe.certError" && rec.Writes == 0, cert.Code);
            var garbage = FakeRaw(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"));
            TlsOutcome real;
            using (var raw = NetProbe.TcpConnectAsync(new IPEndPoint(IPAddress.Loopback, garbage.Port), 3000, CancellationToken.None).Result)
                real = NetProbe.StrictTlsAsync(raw, "discord.com", 3000, CancellationToken.None).Result;
            Check("tls: the real TLS step against a server without a valid certificate fails and sends no HTTP request", !real.Ok && !garbage.SawGet.Result, real.Message);

            // HTTP: "the server answered" is not "the target works"
            foreach (var (host, status, loc, want) in new[]
            {
                ("discord.com", 200, "", TargetVerdict.Pass), ("discord.com", 301, "https://discord.com/app", TargetVerdict.Pass), ("discord.com", 404, "", TargetVerdict.Partial),
                ("cdn.discordapp.com", 404, "", TargetVerdict.Pass), ("cdn.discordapp.com", 429, "", TargetVerdict.Partial), ("gateway.discord.gg", 426, "", TargetVerdict.Partial),
                ("example.org", 200, "", TargetVerdict.Pass), ("example.org", 403, "", TargetVerdict.Partial), ("example.org", 302, "http://blocked.example.net/", TargetVerdict.Partial),
                ("example.org", 302, "/login", TargetVerdict.Pass), ("example.org", 302, "https://www.example.org/", TargetVerdict.Pass), ("discord.com", 451, "", TargetVerdict.Fail),
                ("discord.com", 503, "", TargetVerdict.Fail), ("discord.com", 407, "", TargetVerdict.Fail), ("example.org", 500, "", TargetVerdict.Fail),
            })
            {
                var v = HttpEval.Judge(host, status, loc, ScanTargets.ExpectationFor(host)).Verdict;
                Check("http: " + host + " " + status + (loc.Length > 0 ? " → " + loc : "") + " is " + want, v == want, v.ToString());
            }
            Check("http: the default targets have an explicit expectation, other targets the general rule",
                  AppSettings.DefaultTestHosts.All(h => ScanTargets.ExpectationFor(h) != null) && ScanTargets.ExpectationFor("example.org") == null &&
                  ScanTargets.ExpectationFor("cdn.discordapp.com").Describe() == "200–299, 400, 403–404", ScanTargets.ExpectationFor("cdn.discordapp.com").Describe());
            byte[] H(string t) => Encoding.ASCII.GetBytes(t);
            HttpHead Ph(string t) { var b = H(t); int e = t.IndexOf("\r\n\r\n", StringComparison.Ordinal); return HttpHead.Parse(b, e < 0 ? b.Length : e + 4, b.Length); }
            var okHead = Ph("HTTP/1.1 302 Found\r\nLocation: /x\r\nSet-Cookie: a=1\r\n\r\nbody");
            Check("http: a response head is parsed (status, headers, the rest kept apart)", okHead != null && okHead.Status == 302 && okHead["location"] == "/x" && okHead.Rest.Length == 4, "");
            Check("http: invalid status lines and headers are refused",
                  Ph("HTTP/2 200 OK\r\n\r\n") == null && Ph("HTTP/1.1 2000 OK\r\n\r\n") == null &&
                  Ph("HTTP/1.1 200 OK\r\nBad Header\r\n\r\n") == null && Ph("SSH-2.0-x\r\n\r\n") == null, "");
            var big = FakeRaw(H("HTTP/1.1 200 OK\r\n" + string.Concat(Enumerable.Repeat("X-Pad: " + new string('a', 100) + "\r\n", 40))), 300);
            string bigKey;
            using (var bs = NetProbe.TcpConnectAsync(new IPEndPoint(IPAddress.Loopback, big.Port), 3000, CancellationToken.None).Result)
            {
                try { NetProbe.HttpGetAsync(bs, "example.org", "/", null, false, new ProbeEnv { MaxHeaderBytes = 1024, HttpTimeoutMs = 3000 }, CancellationToken.None).Wait(); bigKey = "none"; }
                catch (AggregateException ae) { bigKey = (ae.InnerException as ProbeFail)?.Text?.Key ?? ae.InnerException?.GetType().Name; }
            }
            Check("http: an answer with oversized headers is cut off (bounded)", bigKey == "scan.probe.headTooLarge", bigKey);
            Check("http: chunked bodies are decoded with limits", Encoding.ASCII.GetString(NetProbe.Dechunk(H("4\r\nabcd\r\n2;x=1\r\nef\r\n0\r\n\r\n"), 100)) == "abcdef" &&
                  NetProbe.Dechunk(H("zz\r\nab\r\n"), 100).Length == 0 && NetProbe.Dechunk(H("ffff\r\nab\r\n"), 100).Length == 0, "");

            // DNS over HTTPS (JSON) and the comparison
            string q(string n, int t) => "\"Question\":[{\"name\":\"" + n + "\",\"type\":" + t + "}]";
            var gA = Doh.Parse("{\"Status\":0,\"TC\":false,\"RD\":true,\"RA\":true," + q("discord.com.", 1) + ",\"Answer\":[{\"name\":\"discord.com.\",\"type\":1,\"TTL\":300,\"data\":\"162.159.128.233\"}]}", "discord.com", 1);
            Check("doh: an A answer is read (Status, question name/type, record type)", gA.Status == DohStatus.Ok && gA.Addresses.Single().ToString() == "162.159.128.233", gA.Status.ToString());
            var cn = Doh.Parse("{\"Status\":0," + q("www.example.org.", 1) + ",\"Answer\":[{\"name\":\"www.example.org.\",\"type\":5,\"data\":\"cdn.example.net.\"},{\"name\":\"cdn.example.net.\",\"type\":1,\"data\":\"104.16.2.2\"},{\"name\":\"evil.example.\",\"type\":1,\"data\":\"10.0.0.1\"}]}", "www.example.org", 1);
            Check("doh: the CNAME chain is followed; records for other names are ignored", cn.Status == DohStatus.Ok && cn.Addresses.Single().ToString() == "104.16.2.2" && cn.Chain.Contains("cdn.example.net"), string.Join(",", cn.Addresses));
            var aaaa = Doh.Parse("{\"Status\":0," + q("discord.com", 28) + ",\"Answer\":[{\"name\":\"discord.com\",\"type\":28,\"data\":\"2606:4700::6810:101\"},{\"name\":\"discord.com\",\"type\":1,\"data\":\"1.2.3.4\"}]}", "discord.com", 28);
            Check("doh: AAAA answers only give IPv6 addresses", aaaa.Status == DohStatus.Ok && aaaa.Addresses.Single().ToString() == "2606:4700::6810:101", "");
            Check("doh: NXDOMAIN, NODATA, SERVFAIL, a wrong question and broken JSON are told apart",
                  Doh.Parse("{\"Status\":3," + q("nx.example.org.", 1) + "}", "nx.example.org", 1).Status == DohStatus.NxDomain &&
                  Doh.Parse("{\"Status\":0," + q("discord.com.", 1) + "}", "discord.com", 1).Status == DohStatus.NoData &&
                  Doh.Parse("{\"Status\":2," + q("discord.com.", 1) + "}", "discord.com", 1).Status == DohStatus.ServerFail &&
                  Doh.Parse("{\"Status\":0," + q("other.com.", 1) + ",\"Answer\":[{\"name\":\"other.com.\",\"type\":1,\"data\":\"1.1.1.1\"}]}", "discord.com", 1).Status == DohStatus.Invalid &&
                  Doh.Parse("{\"Status\":0," + q("discord.com.", 28) + "}", "discord.com", 1).Status == DohStatus.Invalid &&
                  Doh.Parse("{not json", "discord.com", 1).Status == DohStatus.Invalid && Doh.Parse("{\"Status\":\"0\"}", "discord.com", 1).Status == DohStatus.Invalid, "");
            Check("doh: fixed endpoints, name and type parameters, JSON accept header for Cloudflare",
                  Doh.RequestPath(Doh.Google, "discord.com", 1) == "/resolve?name=discord.com&type=A" && Doh.RequestPath(Doh.Cloudflare, "discord.com", 28) == "/dns-query?name=discord.com&type=AAAA" &&
                  Doh.Google.Host == "dns.google" && Doh.Cloudflare.Host == "cloudflare-dns.com" && Doh.Cloudflare.JsonAccept && !Doh.Google.JsonAccept, "");
            var dohConn = new List<IPEndPoint>();
            bool sysUsed = false;
            var envD = new ProbeEnv
            {
                Resolve = (h, t, ct) => { sysUsed = true; return Task.FromResult(new DnsAnswer()); },
                Connect = (ep, t, ct) => { lock (dohConn) dohConn.Add(ep); throw new ProbeFail(ProbeStage.Connect, "NSF-503", new LocText("scan.probe.connectFailed", "x")); },
            };
            var down = Doh.ResolveAsync("discord.com", envD, CancellationToken.None).Result;
            Check("doh: unreachable DoH is reported; the fixed addresses are used directly (no system DNS, no proxy, Google then Cloudflare)",
                  down.Status == DohStatus.Unreachable && !sysUsed && dohConn.Select(e => e.ToString()).SequenceEqual(new[] { "8.8.8.8:443", "8.8.4.4:443", "1.1.1.1:443", "1.0.0.1:443" }),
                  string.Join(",", dohConn));
            DnsAnswer Sys(DnsStatus st, params string[] ips) => new DnsAnswer { Status = st, Addresses = ips.Select(IPAddress.Parse).ToList() };
            DohResult Dh(DohStatus st, params string[] ips) => new DohResult { Status = st, Addresses = ips.Select(IPAddress.Parse).ToList() };
            foreach (var (name, sys, doh, want, ok) in new[]
            {
                ("same answer", Sys(DnsStatus.Ok, "162.159.128.233"), Dh(DohStatus.Ok, "162.159.128.233", "162.159.137.232"), DnsVerdict.Match, (bool?)true),
                ("two different public CDN answers", Sys(DnsStatus.Ok, "104.16.1.1"), Dh(DohStatus.Ok, "172.64.1.1"), DnsVerdict.DifferentPublic, (bool?)true),
                ("system NXDOMAIN, DoH public", Sys(DnsStatus.NxDomain), Dh(DohStatus.Ok, "104.16.1.1"), DnsVerdict.Interference, (bool?)false),
                ("system NODATA, DoH public", Sys(DnsStatus.NoData), Dh(DohStatus.Ok, "104.16.1.1"), DnsVerdict.Interference, (bool?)false),
                ("system timeout, DoH public", Sys(DnsStatus.Timeout), Dh(DohStatus.Ok, "104.16.1.1"), DnsVerdict.Interference, (bool?)false),
                ("system private, DoH public", Sys(DnsStatus.Ok, "127.0.0.1"), Dh(DohStatus.Ok, "104.16.1.1"), DnsVerdict.Interference, (bool?)false),
                ("system mixed, DoH public", Sys(DnsStatus.Ok, "104.16.1.1", "10.0.0.1"), Dh(DohStatus.Ok, "104.16.1.1"), DnsVerdict.Interference, (bool?)false),
                ("both NXDOMAIN", Sys(DnsStatus.NxDomain), Dh(DohStatus.NxDomain), DnsVerdict.NotFound, (bool?)null),
                ("DoH unreachable", Sys(DnsStatus.Ok, "104.16.1.1"), Dh(DohStatus.Unreachable), DnsVerdict.DohUnavailable, (bool?)null),
                ("DoH says private", Sys(DnsStatus.Ok, "10.0.0.1"), Dh(DohStatus.Ok, "10.0.0.1"), DnsVerdict.NotPublicTarget, (bool?)null),
                ("system answers, DoH NODATA", Sys(DnsStatus.Ok, "104.16.1.1"), Dh(DohStatus.NoData), DnsVerdict.Unclear, (bool?)null),
            })
            {
                var c = DnsComparison.Compare("discord.com", sys, doh);
                Check("dns: " + name + " → " + want, c.Verdict == want && c.Ok == ok && Loc.Has("scan.dnsVerdict." + want), c.Verdict.ToString());
            }
            string act = File.ReadAllText(Path.Combine(repo4, @"src\Core\Actions.cs"));
            Check("dns: the quick test and auto-repair use the same system-vs-DoH verdict (no /16 comparison)",
                  act.Contains("DnsComparison.CheckAsync(main") && !act.Contains("NetTest.Overlap") && !act.Contains("ReferenceLookup"), "");

            // STUN (RFC 8489)
            var tx = Stun.NewTransactionId();
            var req = Stun.BindingRequest(tx);
            Check("stun: a Binding request has type 0x0001, length 0, the magic cookie and a random 96-bit id",
                  req.Length == 20 && req[0] == 0 && req[1] == 1 && req[2] == 0 && req[3] == 0 && req[4] == 0x21 && req[7] == 0x42 && req.Skip(8).SequenceEqual(tx) &&
                  !Stun.NewTransactionId().SequenceEqual(tx) && tx.Any(b => b != 0), "");
            var mappedEp = new IPEndPoint(IPAddress.Parse("203.0.113.5"), 54321);
            var good = Stun.Parse(StunAnswer(tx, mappedEp), StunAnswer(tx, mappedEp).Length, tx);
            Check("stun: a valid answer gives the XOR-mapped address", good.Status == StunStatus.Ok && good.Mapped.Equals(mappedEp), good.Detail);
            var other = Stun.NewTransactionId();
            foreach (var (name, bytes) in new[]
            {
                ("transaction id mismatch", StunAnswer(other, mappedEp)), ("length mismatch", StunAnswer(tx, mappedEp, lengthDelta: 4)),
                ("wrong magic cookie", StunAnswer(tx, mappedEp, cookie: new byte[] { 1, 2, 3, 4 })), ("attribute longer than the message", StunAnswer(tx, mappedEp, attrLenDelta: 12)),
                ("not a response type", StunAnswer(tx, mappedEp, type: 0x0001)), ("too short", new byte[12]),
            })
            {
                var pr = Stun.Parse(bytes, bytes.Length, tx);
                Check("stun: refused – " + name, pr.Status == StunStatus.Invalid, pr.Status + " " + pr.Detail);
            }
            var errAns = new List<byte> { 0x01, 0x11, 0, 8, 0x21, 0x12, 0xA4, 0x42 };
            errAns.AddRange(tx);
            errAns.AddRange(new byte[] { 0x00, 0x09, 0x00, 0x04, 0, 0, 4, 20 });
            Check("stun: an error response is told apart", Stun.Parse(errAns.ToArray(), errAns.Count, tx).Status == StunStatus.ErrorResponse, "");
            var s1 = FakeStun(r => StunAnswer(r.Skip(8).Take(12).ToArray(), mappedEp));
            var b1 = Stun.BindAsync(s1.Ep, 1500, 1, CancellationToken.None).Result;
            Check("stun live (loopback): a correct answer from the server's address and port", b1.Status == StunStatus.Ok && b1.Mapped.Equals(mappedEp) && b1.Ms.HasValue, b1.Status + " " + b1.Detail);
            var s2 = FakeStun(r => StunAnswer(r.Skip(8).Take(12).ToArray(), mappedEp), fromOther: true);
            var b2 = Stun.BindAsync(s2.Ep, 700, 1, CancellationToken.None).Result;
            Check("stun live (loopback): an answer from another source port is ignored", b2.Status == StunStatus.Invalid && b2.Detail.StartsWith("source"), b2.Status + " " + b2.Detail);
            var s3 = FakeStun(r => StunAnswer(Stun.NewTransactionId(), mappedEp));
            var b3 = Stun.BindAsync(s3.Ep, 700, 1, CancellationToken.None).Result;
            Check("stun live (loopback): an answer with another transaction id is refused", b3.Status == StunStatus.Invalid && b3.Detail == "transaction id", b3.Detail);
            var s4 = FakeStun(r => null);
            var b4 = Stun.BindAsync(s4.Ep, 400, 1, CancellationToken.None).Result;
            Check("stun live (loopback): no answer is a separate timeout result", b4.Status == StunStatus.Timeout, b4.Status.ToString());
            Check("stun: the live endpoint is stun.cloudflare.com:3478/UDP; the result is optional (not in the score)",
                  Stun.Host == "stun.cloudflare.com" && Stun.Port == 3478 && Scanner.Rank(new[]
                  {
                      new ScanRow { P = BI("tr-quad9"), Status = ScanRow.Full, Score = 100, AvgMs = 200, Order = 1, Udp = new StunResult { Status = StunStatus.Timeout } },
                      new ScanRow { P = BI("tr-adguard"), Status = ScanRow.Full, Score = 100, AvgMs = 200, Order = 0, Udp = new StunResult { Status = StunStatus.Ok } },
                  }).First().P.Id == "tr-adguard", "");
            Check("stun: ByeDPI shows \"N/A – not measured on this TCP proxy path\"", Scanner.StunText(new StunResult { Status = StunStatus.NotMeasured, Scope = "na" }) == Loc.T("scan.udp.na") &&
                  Loc.En("scan.udp.na").Contains("N/A"), "");
            // cancellation of a probe ends its connection and its task
            var slow = FakeRaw(new byte[0], 3000);
            var ctsP = new CancellationTokenSource(300);
            bool cancelled;
            var envS = PlainEnv(Answer("104.16.1.1"), new List<IPEndPoint>(), true);
            envS.Connect = (ep, t, ct) => NetProbe.TcpConnectAsync(new IPEndPoint(IPAddress.Loopback, slow.Port), t, ct);
            var sw = Stopwatch.StartNew();
            try { NetProbe.HttpsAsync("discord.com", ProbeTransport.Direct, envS, ctsP.Token).Wait(); cancelled = false; }
            catch (AggregateException ae) { cancelled = ae.InnerException is OperationCanceledException; }
            Check("cancel: a probe waiting for an answer is cancelled at once (its connection is closed)", cancelled && sw.ElapsedMilliseconds < 2500, sw.ElapsedMilliseconds + " ms");
        }

        // ---------------------------------------------------------------------------- live: the packaged binaries (loopback only)
        static void Live4(Action<string, bool, string> Check, string repo, string root)
        {
            string tz = Path.Combine(repo, @"third_party\zapret"), tb = Path.Combine(repo, @"third_party\byedpi");
            string pkg = Path.Combine(root, "live");
            Directory.CreateDirectory(Path.Combine(pkg, @"bin\zapret\payloads"));
            Directory.CreateDirectory(Path.Combine(pkg, @"bin\byedpi"));
            foreach (var f in Directory.GetFiles(Path.Combine(tz, "x86_64"))) File.Copy(f, Path.Combine(pkg, @"bin\zapret", Path.GetFileName(f)));
            foreach (var f in Directory.GetFiles(Path.Combine(tz, "payloads"))) File.Copy(f, Path.Combine(pkg, @"bin\zapret\payloads", Path.GetFileName(f)));
            File.Copy(Path.Combine(tb, @"x86_64\ciadpi.exe"), Path.Combine(pkg, @"bin\byedpi\ciadpi.exe"));
            string tg = Path.Combine(repo, @"third_party\goodbyedpi", Engine.Arch);
            Directory.CreateDirectory(Path.Combine(pkg, "bin", Engine.Arch));
            foreach (var f in Directory.GetFiles(tg)) File.Copy(f, Path.Combine(pkg, "bin", Engine.Arch, Path.GetFileName(f)));
            App.BaseDir = pkg;
            App.DataDir = Path.Combine(pkg, "data");
            var s = App.Settings;
            s.TargetedMode = true;
            s.TargetDomains = new List<string> { "discord.com", "discord.gg" };
            s.ExcludeEnabled = true;
            s.ExcludeDomains = new List<string> { "turkiye.gov.tr" };
            string ld = Path.Combine(pkg, @"data\lists");
            var inc = Hostlists.WriteAtomic(Hostlists.IncludeName, s.TargetDomains, ld);
            var exc = Hostlists.WriteAtomic(Hostlists.ExcludeName, s.ExcludeDomains, ld);
            var combos = new[] { ("no lists", new ListBinding()), ("include", new ListBinding { Include = inc }), ("exclude", new ListBinding { Exclude = exc }), ("both", new ListBinding { Include = inc, Exclude = exc }) };

            if (!Engines.Is64BitOs())
            {
                Check("live: the x64 Zapret/ByeDPI binaries cannot run on this 32-bit Windows (reported, not counted as passed)", true, "skipped");
                return;
            }
            // winws: every built-in, with every list combination (syntax check only – not a field result)
            string winws = Path.Combine(pkg, @"bin\zapret\winws.exe");
            foreach (var p in Profiles.ForEngine(Profiles.BuiltIns, EngineKind.Zapret))
                foreach (var (name, b) in combos.Skip(1).Take(2))
                {
                    var r = RunCapture(winws, "--dry-run " + Engines.Zapret.BuildArgs(p, b));
                    Check("winws live: " + p.Id + " + " + name + " passes --dry-run", r.Code == 0 && r.Output.Contains("command line parameters verified"), r.Code + " " + Last(r.Output));
                }
            // ciadpi: every built-in with every list combination through the shared launcher: its own PID must listen on 127.0.0.1
            foreach (var p in Profiles.ForEngine(Profiles.BuiltIns, EngineKind.ByeDpi))
                foreach (var (name, b0) in combos)
                {
                    int port = PortOwner.PickTrialPort(new[] { ByeDpiNet.SocksPort, ByeDpiNet.HttpPort }, 19200, 19400);
                    var b = new ListBinding { Include = b0.Include, Exclude = b0.Exclude, Port = port };
                    var lr = EngineLauncher.Launch(Engines.ByeDpi, Engines.ByeDpi.BuildArgs(p, b), port, null, CancellationToken.None);
                    bool owned = lr.Ok && PortOwner.OwnedBy(port, lr.Process.Id, out string who);
                    PortOwner.OwnedBy(port, lr.Ok ? lr.Process.Id : -1, out who);
                    try { if (lr.Ok && !lr.Process.HasExited) { lr.Process.Kill(); lr.Process.WaitForExit(3000); } } catch { }
                    Check("ciadpi live: " + p.Id + " + " + name + " listens on 127.0.0.1 with its own PID (shared readiness check)", owned, lr.Ok ? who : lr.Code + " " + lr.Error?.English);
                }

            // a port held by another process: refused, never used
            int busyPort = UsePort(out var busy);
            int me = Process.GetCurrentProcess().Id;
            var ls = PortOwner.Listeners(busyPort);
            Check("port: the TCP table names the owner of a listening port",
                  ls.Any(l => l.Pid == me && IPAddress.IsLoopback(l.Address)) && PortOwner.OwnedBy(busyPort, me, out _) && !PortOwner.OwnedBy(busyPort, me + 1, out _) && !PortOwner.Unused(busyPort), string.Join(", ", ls));
            Check("port: the ownership rule refuses a wrong PID and a non-loopback listener",
                  !PortOwner.Check(new List<PortOwner.Listener> { new PortOwner.Listener { Address = IPAddress.Loopback, Port = 1, Pid = 5 } }, 6, out _) &&
                  !PortOwner.Check(new List<PortOwner.Listener> { new PortOwner.Listener { Address = IPAddress.Any, Port = 1, Pid = 5 } }, 5, out _) &&
                  !PortOwner.Check(new List<PortOwner.Listener>(), 5, out _) &&
                  PortOwner.Check(new List<PortOwner.Listener> { new PortOwner.Listener { Address = IPAddress.Loopback, Port = 1, Pid = 5 }, new PortOwner.Listener { Address = IPAddress.IPv6Loopback, Port = 1, Pid = 5 } }, 5, out _), "");
            var lb = EngineLauncher.Launch(Engines.ByeDpi, Engines.ByeDpi.BuildArgs(BI("byedpi-oob"), new ListBinding { Port = busyPort }), busyPort, null, CancellationToken.None);
            bool exited = !lb.Ok;
            if (lb.Ok) try { lb.Process.Kill(); } catch { }
            Check("port: ciadpi on a port that another process holds is not accepted as ready", exited && (lb.Code == "NSF-808" || lb.Code.StartsWith("NSF-6")), lb.Code + " " + lb.Error?.English);
            int pick = PortOwner.PickTrialPort(new[] { busyPort, ByeDpiNet.SocksPort, ByeDpiNet.HttpPort }, busyPort, busyPort + 40);
            Check("port: a trial port is never the busy one nor the ports of a running ByeDPI and its bridge",
                  pick != 0 && pick != busyPort && pick != ByeDpiNet.SocksPort && pick != ByeDpiNet.HttpPort && PortOwner.Unused(pick), pick.ToString());
            busy.Stop();

            // a live ByeDPI trial: own process, port, list files and locks; everything is released when it ends
            object token = ScanGate.TryAcquire();
            try
            {
                var host = new LiveScanHost(new FakeScm());
                var plan = ScanLists.Plan(Engines.ByeDpi, s, T3, false);
                var ts = host.StartTrialAsync(BI("byedpi-recommended"), plan, CancellationToken.None).Result;
                var tr = ts.Trial as LiveTrial;
                bool okT = tr != null && tr.Process != null && !tr.Process.HasExited;
                int tport = tr?.Port ?? 0, tpid = tr?.Pid ?? 0;
                string dir = tr?.Dir;
                bool owned = okT && PortOwner.OwnedBy(tport, tpid, out _);
                bool listsThere = dir != null && File.Exists(Path.Combine(dir, Hostlists.IncludeName)) && File.Exists(Path.Combine(dir, Hostlists.ExcludeName));
                bool listLocked = listsThere && IsWriteLocked(Path.Combine(dir, Hostlists.IncludeName));
                bool exeLocked = IsWriteLocked(Path.Combine(pkg, @"bin\byedpi\ciadpi.exe"));
                bool liveListsUntouched = File.ReadAllText(inc) == "discord.com\ndiscord.gg\n";
                Check("trial live: a ByeDPI candidate runs with its own process, port (not the settings' port), list folder and locks",
                      okT && owned && tport != ByeDpiNet.SocksPort && tport != ByeDpiNet.HttpPort && listsThere && listLocked && exeLocked && liveListsUntouched &&
                      ts.Trial.Transport.Socks != null && ts.Trial.Transport.Socks.Port == tport, ts.Code + " " + ts.Error?.English);
                // a probe through the candidate that is cancelled while it waits
                var ctsL = new CancellationTokenSource(200);
                var envL = new ProbeEnv { Resolve = async (h, t, ct) => { await Task.Delay(5000, ct); return new DnsAnswer(); } };
                bool canc;
                try { NetProbe.HttpsAsync("discord.com", ts.Trial.Transport, envL, ctsL.Token).Wait(); canc = false; } catch (AggregateException ae) { canc = ae.InnerException is OperationCanceledException; }
                ts.Trial.Dispose();
                Thread.Sleep(200);
                bool gone = tr?.Process == null && (tpid == 0 || !ProcessAlive(tpid));
                Check("trial live: after a cancel the candidate ends – process gone, port free, list folder deleted, files writable again",
                      canc && gone && tport > 0 && PortOwner.Unused(tport) && dir != null && !Directory.Exists(dir) && !IsWriteLocked(Path.Combine(pkg, @"bin\byedpi\ciadpi.exe")), "port " + tport);
                var pre = new CancellationTokenSource();
                pre.Cancel();
                bool preCancelled;
                try { host.StartTrialAsync(BI("byedpi-oob"), plan, pre.Token).Wait(); preCancelled = false; } catch (AggregateException ae) { preCancelled = ae.InnerException is OperationCanceledException; }
                string scanDir = Path.Combine(App.DataDir, "scan");
                Check("trial live: a cancel before the start leaves no process, port or list folder",
                      preCancelled && (!Directory.Exists(scanDir) || Directory.GetDirectories(scanDir).Length == 0) && OwnCiadpi(pkg) == 0, "");
                Retry(() => File.WriteAllText(Path.Combine(pkg, @"bin\byedpi\ciadpi.exe"), "not the real file"));
                var tsBad = host.StartTrialAsync(BI("byedpi-oob"), plan, CancellationToken.None).Result;
                Check("trial live: a candidate whose file does not match the embedded SHA-256 is not started (NSF-105)",
                      tsBad.Trial == null && tsBad.Code == "NSF-105" && tsBad.EngineWide && OwnCiadpi(pkg) == 0, tsBad.Code);
                Retry(() => File.Copy(Path.Combine(tb, @"x86_64\ciadpi.exe"), Path.Combine(pkg, @"bin\byedpi\ciadpi.exe"), true));

                // 32-bit Windows: the engines are filtered by Available()
                Engines.Is64BitOs = () => false;
                bool z = host.Available(BI("zapret-discord"), out var whyZ), bd = host.Available(BI("byedpi-oob"), out var whyB), gd = host.Available(BI("tr-recommended"), out _);
                Check("x86: Zapret and ByeDPI are unavailable with the NSF-107 reason; GoodbyeDPI stays",
                      !z && !bd && gd && whyZ?.Key == "engines.only64" && !Engines.Zapret.Available(out _), whyZ?.English);
                Engines.Is64BitOs = () => Environment.Is64BitOperatingSystem;
            }
            finally
            {
                ScanGate.Release(token);
                s.TargetedMode = s.ExcludeEnabled = false;
            }
        }

        static void Retry(Action a)
        {
            for (int i = 0; ; i++)
            {
                try { a(); return; }
                catch (IOException) when (i < 20) { Thread.Sleep(150); }
                catch (UnauthorizedAccessException) when (i < 20) { Thread.Sleep(150); }
            }
        }

        static bool IsWriteLocked(string path)
        {
            try { using (new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite)) { } return false; }
            catch (IOException) { return true; }
            catch (UnauthorizedAccessException) { return true; }
        }

        static bool ProcessAlive(int pid)
        {
            try { using (var p = Process.GetProcessById(pid)) return !p.HasExited; } catch { return false; }
        }

        static int OwnCiadpi(string pkg)
        {
            int n = 0;
            foreach (var p in Process.GetProcessesByName("ciadpi"))
                using (p) try { if (p.MainModule.FileName.StartsWith(pkg, StringComparison.OrdinalIgnoreCase)) n++; } catch { }
            return n;
        }
    }
}
#endif
