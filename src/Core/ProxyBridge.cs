using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NSFShield
{
    /// <summary>
    /// Local proxy bridge: opens an unencrypted HTTP + SOCKS5 proxy on 127.0.0.1 and forwards the connections to the selected
    /// proxy (with a user name/password if needed). This way programs that do not support proxies with passwords
    /// (Discord, browsers) can use them too. Only reachable from this computer.
    /// </summary>
    public static class ProxyBridge
    {
        sealed class Listener
        {
            public ProxyEntry P;
            public TcpListener L;
            public int Active;
            public long Total;
            /// <summary>Every accepted connection and its upstream tunnel: closed together when the bridge stops.</summary>
            public readonly HashSet<TcpClient> Clients = new HashSet<TcpClient>();
            public readonly CancellationTokenSource Stop = new CancellationTokenSource();

            public bool Track(TcpClient c)
            {
                lock (Clients)
                {
                    if (Stop.IsCancellationRequested) return false;
                    Clients.Add(c);
                    return true;
                }
            }

            public void Untrack(TcpClient c) { lock (Clients) Clients.Remove(c); }

            public int CloseAll()
            {
                List<TcpClient> all;
                lock (Clients) { all = Clients.ToList(); Clients.Clear(); }
                foreach (var c in all) try { c.Close(); } catch { }
                return all.Count;
            }
        }

        /// <summary>Time a client has to send its first request (SOCKS greeting or HTTP head) before the connection is closed.</summary>
        internal static int HeaderTimeoutMs = 15000;

        static readonly object gate = new object();
        static readonly Dictionary<string, Listener> map = new Dictionary<string, Listener>();

        public const int BasePort = 18901;

        /// <summary>Assigns fixed local ports to the saved proxies.</summary>
        public static void AssignPorts(List<ProxyEntry> proxies)
        {
            var used = new HashSet<int>(proxies.Where(p => p.LocalPort > 0).Select(p => p.LocalPort));
            foreach (var p in proxies.Where(p => p.LocalPort <= 0))
            {
                int port = BasePort;
                while (used.Contains(port)) port++;
                p.LocalPort = port;
                used.Add(port);
            }
        }

        public static string LocalUrl(ProxyEntry p) => "http://127.0.0.1:" + p.LocalPort;

        public static bool IsRunning(ProxyEntry p)
        {
            lock (gate) return p != null && map.ContainsKey(p.Id);
        }

        public static int ActiveConnections
        {
            get { lock (gate) return map.Values.Sum(l => l.Active); }
        }

        public static int RunningCount
        {
            get { lock (gate) return map.Count; }
        }

        public static (int Active, long Total) Stats(ProxyEntry p)
        {
            lock (gate) return map.TryGetValue(p.Id, out var l) ? (l.Active, l.Total) : (0, 0);
        }

        /// <summary>Starts the bridge for this proxy (does nothing if it is running).</summary>
        public static bool Ensure(ProxyEntry p, out string error)
        {
            error = "";
            lock (gate)
            {
                if (!ProxyTools.ValidEntry(p, out string invalid)) { error = invalid; return false; }
                if (map.TryGetValue(p.Id, out var cur))
                {
                    cur.P = p;   // the settings may have changed
                    return true;
                }
                if (p.LocalPort <= 0) AssignPorts(App.Settings?.Proxies ?? new List<ProxyEntry> { p });
                try
                {
                    var l = new TcpListener(IPAddress.Loopback, p.LocalPort);
                    l.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ExclusiveAddressUse, true);
                    l.Start(64);
                    var li = new Listener { P = p, L = l };
                    map[p.Id] = li;
                    _ = AcceptLoop(li);
                }
                catch (Exception ex)
                {
                    error = Loc.T("bridge.portFailed", p.LocalPort) + " " + ex.Message;
                    App.Log(error, LogLevel.Warn);
                    return false;
                }
            }
            App.Log("Local proxy bridge opened: 127.0.0.1:" + p.LocalPort + " → " + p.KindLabel + " " + p.Address, LogLevel.Info);
            App.RaiseStatus();
            return true;
        }

        /// <summary>Stops the listener and closes every connection it accepted (open tunnels too). Returns the number closed.</summary>
        public static int Stop(string proxyId)
        {
            Listener l;
            lock (gate)
            {
                if (!map.TryGetValue(proxyId, out l)) return 0;
                map.Remove(proxyId);
            }
            try { l.Stop.Cancel(); } catch { }
            try { l.L.Stop(); } catch { }
            int closed = l.CloseAll();
            App.Log("Local proxy bridge closed (port " + l.P.LocalPort + (closed > 0 ? ", " + closed + " connection(s) closed" : "") + ").", LogLevel.Info);
            App.RaiseStatus();
            return closed;
        }

        public static void StopAll()
        {
            List<string> ids;
            lock (gate) ids = map.Keys.ToList();
            foreach (var id in ids) Stop(id);
        }

        /// <summary>Starts the bridges the saved programs need and closes the ones no longer needed.</summary>
        public static void Sync()
        {
            var s = App.Settings;
            var need = new HashSet<string>(s.ProxyApps
                .Select(a => (App: a, P: s.Proxies.FirstOrDefault(p => p.Id == a.ProxyId)))
                .Where(x => x.P != null && AppProxy.NeedsBridge(x.App, x.P))
                .Select(x => x.P.Id));
            foreach (var id in need) { var p = s.Proxies.First(x => x.Id == id); Ensure(p, out _); }
            List<string> running;
            lock (gate) running = map.Keys.ToList();
            // the bridges of the engines (ByeDPI) are managed by the engine itself
            foreach (var id in running.Where(id => !need.Contains(id) && !s.Proxies.Any(p => p.Id == id) && !id.StartsWith("engine:"))) Stop(id);
        }

        // ================================================================ connection handling

        static async Task AcceptLoop(Listener l)
        {
            while (true)
            {
                TcpClient c;
                try { c = await l.L.AcceptTcpClientAsync().ConfigureAwait(false); }
                catch { return; }   // stopped
                _ = Task.Run(() => Handle(l, c));
            }
        }

        static async Task Handle(Listener l, TcpClient c)
        {
            Interlocked.Increment(ref l.Active);
            Interlocked.Increment(ref l.Total);
            TcpClient up = null;
            // the client must send its request within the time limit; the bridge's stop closes it at any point
            var head = CancellationTokenSource.CreateLinkedTokenSource(l.Stop.Token);
            head.CancelAfter(HeaderTimeoutMs);
            var headReg = head.Token.Register(() => { try { c.Close(); } catch { } });
            try
            {
                if (!l.Track(c)) return;
                c.NoDelay = true;
                var cs = c.GetStream();
                var first = new byte[1];
                if (await cs.ReadAsync(first, 0, 1).ConfigureAwait(false) != 1) return;
                if (first[0] == 5) up = await HandleSocks(l.P, cs).ConfigureAwait(false);
                else up = await HandleHttp(l.P, cs, first[0]).ConfigureAwait(false);
                if (up == null) return;
                headReg.Dispose();   // the tunnel is open: no head time limit any more (the stop still closes both sides)
                if (!l.Track(up)) return;
                await Pump(c, up).ConfigureAwait(false);
            }
            catch { }
            finally
            {
                headReg.Dispose();
                head.Dispose();
                if (up != null) { l.Untrack(up); try { up.Close(); } catch { } }
                l.Untrack(c);
                try { c.Close(); } catch { }
                Interlocked.Decrement(ref l.Active);
            }
        }

        static async Task<byte[]> ReadN(Stream s, int n)
        {
            var b = new byte[n];
            int got = 0;
            while (got < n)
            {
                int r = await s.ReadAsync(b, got, n - got).ConfigureAwait(false);
                if (r <= 0) throw new IOException("connection closed");
                got += r;
            }
            return b;
        }

        /// <summary>Opens a tunnel to host:port through the upstream proxy (runs the synchronous code on a worker thread).</summary>
        static Task<(Stream S, TcpClient C)> Upstream(ProxyEntry p, string host, int port) => Task.Run(() =>
        {
            var s = ProxyTools.OpenTunnel(p, host, port, 15000, Stopwatch.StartNew(), null, out var client);
            client.ReceiveTimeout = client.SendTimeout = 0;
            client.NoDelay = true;
            return (s, client);
        });

        static async Task<TcpClient> HandleSocks(ProxyEntry p, Stream cs)
        {
            int n = (await ReadN(cs, 1).ConfigureAwait(false))[0];
            await ReadN(cs, n).ConfigureAwait(false);
            await cs.WriteAsync(new byte[] { 5, 0 }, 0, 2).ConfigureAwait(false);   // no authentication (local only)
            var req = await ReadN(cs, 4).ConfigureAwait(false);
            string host;
            switch (req[3])
            {
                case 1: host = new IPAddress(await ReadN(cs, 4).ConfigureAwait(false)).ToString(); break;
                case 4: host = new IPAddress(await ReadN(cs, 16).ConfigureAwait(false)).ToString(); break;
                default:
                    int len = (await ReadN(cs, 1).ConfigureAwait(false))[0];
                    host = Encoding.ASCII.GetString(await ReadN(cs, len).ConfigureAwait(false));
                    break;
            }
            var pb = await ReadN(cs, 2).ConfigureAwait(false);
            int port = (pb[0] << 8) | pb[1];
            if (req[1] != 1)
            {
                await cs.WriteAsync(new byte[] { 5, 7, 0, 1, 0, 0, 0, 0, 0, 0 }, 0, 10).ConfigureAwait(false);
                return null;
            }
            try
            {
                var (s, c) = await Upstream(p, host, port).ConfigureAwait(false);
                await cs.WriteAsync(new byte[] { 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 }, 0, 10).ConfigureAwait(false);
                return c;
            }
            catch
            {
                await cs.WriteAsync(new byte[] { 5, 5, 0, 1, 0, 0, 0, 0, 0, 0 }, 0, 10).ConfigureAwait(false);
                return null;
            }
        }

        static async Task<TcpClient> HandleHttp(ProxyEntry p, Stream cs, byte firstByte)
        {
            // read the request headers
            var buf = new List<byte> { firstByte };
            var tmp = new byte[4096];
            int headEnd = -1;
            while (headEnd < 0)
            {
                if (buf.Count > 65536) return null;
                int r = await cs.ReadAsync(tmp, 0, tmp.Length).ConfigureAwait(false);
                if (r <= 0) return null;
                buf.AddRange(tmp.Take(r));
                for (int i = Math.Max(0, buf.Count - r - 3); i + 3 < buf.Count; i++)
                    if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') { headEnd = i + 4; break; }
            }
            string head = Encoding.ASCII.GetString(buf.Take(headEnd).ToArray());
            byte[] rest = buf.Skip(headEnd).ToArray();
            var lines = head.Split(new[] { "\r\n" }, StringSplitOptions.None).ToList();
            var parts = lines[0].Split(' ');
            if (parts.Length < 3) return null;
            string method = parts[0], target = parts[1], version = parts[2];

            async Task Reply(string status)
            {
                var b = Encoding.ASCII.GetBytes(version + " " + status + "\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
                try { await cs.WriteAsync(b, 0, b.Length).ConfigureAwait(false); } catch { }
            }

            if (method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
            {
                int colon = target.LastIndexOf(':');
                string host = colon > 0 ? target.Substring(0, colon).Trim('[', ']') : target;
                int port = colon > 0 && int.TryParse(target.Substring(colon + 1), out int pp) ? pp : 443;
                try
                {
                    var (s, c) = await Upstream(p, host, port).ConfigureAwait(false);
                    var ok = Encoding.ASCII.GetBytes(version + " 200 Connection established\r\n\r\n");
                    await cs.WriteAsync(ok, 0, ok.Length).ConfigureAwait(false);
                    if (rest.Length > 0) await s.WriteAsync(rest, 0, rest.Length).ConfigureAwait(false);
                    return c;
                }
                catch (Exception ex)
                {
                    await Reply(ex is ProxyFail pf && pf.Code == "NSF-806" ? "407 Upstream Auth Failed" : "502 Bad Gateway").ConfigureAwait(false);
                    return null;
                }
            }

            // Unencrypted HTTP request (GET http://site/path HTTP/1.1)
            if (!Uri.TryCreate(target, UriKind.Absolute, out var uri) || uri.Scheme != "http") { await Reply("400 Bad Request").ConfigureAwait(false); return null; }
            var headers = lines.Skip(1).Where(h => h.Length > 0 &&
                !h.StartsWith("Proxy-Connection:", StringComparison.OrdinalIgnoreCase) &&
                !h.StartsWith("Proxy-Authorization:", StringComparison.OrdinalIgnoreCase) &&
                !h.StartsWith("Connection:", StringComparison.OrdinalIgnoreCase)).ToList();
            headers.Add("Connection: close");
            try
            {
                TcpClient c;
                Stream s;
                string firstLine;
                if (p.Kind == ProxyKind.Http)
                {
                    // HTTP upstream proxy: forward the request as is, add the credentials
                    c = new TcpClient();
                    var t = c.ConnectAsync(p.Host, p.Port);
                    if (await Task.WhenAny(t, Task.Delay(15000)).ConfigureAwait(false) != t || !c.Connected) throw new IOException("upstream proxy did not answer");
                    s = c.GetStream();
                    firstLine = method + " " + target + " " + version;
                    if (p.HasAuth) headers.Add("Proxy-Authorization: Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(p.User + ":" + p.Password)));
                }
                else
                {
                    (s, c) = await Upstream(p, uri.Host, uri.Port).ConfigureAwait(false);
                    firstLine = method + " " + uri.PathAndQuery + " " + version;
                }
                var outHead = Encoding.ASCII.GetBytes(firstLine + "\r\n" + string.Join("\r\n", headers) + "\r\n\r\n");
                await s.WriteAsync(outHead, 0, outHead.Length).ConfigureAwait(false);
                if (rest.Length > 0) await s.WriteAsync(rest, 0, rest.Length).ConfigureAwait(false);
                return c;
            }
            catch
            {
                await Reply("502 Bad Gateway").ConfigureAwait(false);
                return null;
            }
        }

        /// <summary>Copies data in both directions between two connections.</summary>
        static async Task Pump(TcpClient a, TcpClient b)
        {
            var sa = a.GetStream();
            var sb = b.GetStream();
            async Task Copy(Stream from, Stream to, TcpClient toClient)
            {
                try { await from.CopyToAsync(to, 32768).ConfigureAwait(false); } catch { }
                try { toClient.Client.Shutdown(SocketShutdown.Send); } catch { }
            }
            var t1 = Copy(sa, sb, b);
            var t2 = Copy(sb, sa, a);
            var first = await Task.WhenAny(t1, t2).ConfigureAwait(false);
            // the other direction stays open for at most 30 more seconds
            await Task.WhenAny(first == t1 ? t2 : t1, Task.Delay(30000)).ConfigureAwait(false);
        }
    }
}
