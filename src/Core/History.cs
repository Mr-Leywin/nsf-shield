using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;

namespace NSFShield
{
    public sealed class HistoryEntry
    {
        public DateTime Time;
        /// <summary>Kind id: "test", "repair", "scan", "speed", "update" (display name: "history.kind.&lt;id&gt;").</summary>
        public string Kind = "test";
        public string Profile = "";
        public int Ok, Total, Ms;
        public bool? DnsOk;
        public bool Running;
        public string Note = "";

        public bool Success => Total > 0 && Ok == Total && DnsOk != false;
    }

    /// <summary>History of connection tests, repairs and scans (data\history.csv).</summary>
    public static class History
    {
        static readonly object gate = new object();
        static readonly List<HistoryEntry> items = new List<HistoryEntry>();
        static string FilePath => Path.Combine(App.DataDir, "history.csv");
        const int Keep = 1000;

        public static event Action Changed;

        static string Esc(string s) => (s ?? "").Replace(";", ",").Replace("\r", " ").Replace("\n", " ");

        public static void Load()
        {
            lock (gate)
            {
                items.Clear();
                try
                {
                    if (!File.Exists(FilePath)) return;
                    var lines = File.ReadAllLines(FilePath, Encoding.UTF8);
                    foreach (var line in lines.Skip(Math.Max(0, lines.Length - Keep)))
                    {
                        var f = line.Split(';');
                        if (f.Length < 9 || !DateTime.TryParseExact(f[0], "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.None, out var t)) continue;
                        items.Add(new HistoryEntry
                        {
                            Time = t, Kind = f[1], Profile = f[2], Ok = int.Parse(f[3]), Total = int.Parse(f[4]), Ms = int.Parse(f[5]),
                            DnsOk = f[6] == "1" ? true : f[6] == "0" ? (bool?)false : null, Running = f[7] == "1", Note = f[8],
                        });
                    }
                }
                catch (Exception ign) { App.Ignored("History could not be read", ign); }
            }
        }


        /// <summary>Display name of a kind id in the current UI language.</summary>
        public static string KindName(string kind) => Loc.Has("history.kind." + kind) ? Loc.T("history.kind." + kind) : kind;

        public static void Add(HistoryEntry e)
        {
            lock (gate)
            {
                items.Add(e);
                if (items.Count > Keep) items.RemoveRange(0, items.Count - Keep);
                if (!App.Preview)
                {
                    try
                    {
                        Directory.CreateDirectory(App.DataDir);
                        File.AppendAllText(FilePath,
                            string.Join(";", e.Time.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture), Esc(e.Kind), Esc(e.Profile), e.Ok, e.Total, e.Ms,
                                e.DnsOk == true ? "1" : e.DnsOk == false ? "0" : "", e.Running ? "1" : "0", Esc(e.Note)) + Environment.NewLine, Encoding.UTF8);
                        var fi = new FileInfo(FilePath);
                        if (fi.Length > 512 * 1024) Compact();
                    }
                    catch (Exception ign) { App.Ignored("History could not be saved", ign); }
                }
            }
            App.Post(() => Changed?.Invoke());
        }

        static void Compact()
        {
            var lines = File.ReadAllLines(FilePath, Encoding.UTF8);
            File.WriteAllLines(FilePath, lines.Skip(lines.Length / 2), Encoding.UTF8);
        }

        public static List<HistoryEntry> Snapshot()
        {
            lock (gate) return items.ToList();
        }

        public static void Clear()
        {
            lock (gate)
            {
                items.Clear();
                try { File.Delete(FilePath); } catch (Exception ign) { App.Ignored("History could not be deleted", ign); }
            }
            App.Post(() => Changed?.Invoke());
        }
    }

    public sealed class SpeedResult
    {
        public int PingMs, JitterMs;
        public double DownMbps, UpMbps;
        public long DownBytes, UpBytes;
        public string Error = "";
    }

    /// <summary>Latency, download and upload measurement with the Cloudflare speed server.</summary>
    public static class SpeedTest
    {
        public static SpeedResult Run(Action<string, double> progress, System.Threading.CancellationToken ct)
        {
            var r = new SpeedResult();
            try
            {
                // latency: 7 TCP connections to 1.1.1.1:443, median and jitter
                progress?.Invoke(Loc.T("speed.measuringPing"), 0.02);
                var pings = new List<int>();
                for (int i = 0; i < 7 && !ct.IsCancellationRequested; i++)
                    if (NetTest.TcpReachable("1.1.1.1", 443, 3000, out int ms)) pings.Add(ms);
                if (pings.Count == 0) { r.Error = Loc.T("speed.noInternet"); return r; }
                pings.Sort();
                r.PingMs = pings[pings.Count / 2];
                r.JitterMs = pings.Count > 1 ? (int)pings.Zip(pings.Skip(1), (a, b) => Math.Abs(b - a)).Average() : 0;

                // download: at most 10 s or 50 MB
                progress?.Invoke(Loc.T("speed.measuringDown"), 0.1);
                var req = (HttpWebRequest)WebRequest.Create("https://speed.cloudflare.com/__down?bytes=50000000");
                req.Proxy = null;
                req.Timeout = 10000;
                req.ReadWriteTimeout = 10000;
                req.UserAgent = NetTest.UserAgent;
                req.ConnectionGroupName = Guid.NewGuid().ToString("N");
                var sw = Stopwatch.StartNew();
                using (var resp = req.GetResponse())
                using (var s = resp.GetResponseStream())
                {
                    var buf = new byte[65536];
                    sw.Restart();
                    int n;
                    while (sw.ElapsedMilliseconds < 10000 && !ct.IsCancellationRequested && (n = s.Read(buf, 0, buf.Length)) > 0)
                    {
                        r.DownBytes += n;
                        if ((r.DownBytes & 0x3FFFFF) < 65536) progress?.Invoke(Loc.T("speed.downloading", (r.DownBytes * 8 / Math.Max(1, sw.Elapsed.TotalSeconds) / 1e6).ToString("0.0")), 0.1 + 0.5 * Math.Min(1, sw.ElapsedMilliseconds / 10000.0));
                    }
                    try { req.Abort(); } catch { }
                }
                r.DownMbps = r.DownBytes * 8 / Math.Max(0.2, sw.Elapsed.TotalSeconds) / 1e6;

                // upload: 10 MB (at most ~10 s)
                if (!ct.IsCancellationRequested)
                {
                    progress?.Invoke(Loc.T("speed.measuringUp"), 0.65);
                    var up = (HttpWebRequest)WebRequest.Create("https://speed.cloudflare.com/__up");
                    up.Method = "POST";
                    up.Proxy = null;
                    up.Timeout = 15000;
                    up.ReadWriteTimeout = 15000;
                    up.UserAgent = NetTest.UserAgent;
                    up.ContentType = "application/octet-stream";
                    up.ConnectionGroupName = Guid.NewGuid().ToString("N");
                    up.AllowWriteStreamBuffering = false;
                    long total = 10 * 1024 * 1024;
                    up.ContentLength = total;
                    var data = new byte[65536];
                    new Random().NextBytes(data);
                    sw.Restart();
                    using (var s = up.GetRequestStream())
                    {
                        long sent = 0;
                        while (sent < total && !ct.IsCancellationRequested)
                        {
                            int n = (int)Math.Min(data.Length, total - sent);
                            s.Write(data, 0, n);
                            sent += n;
                            if (sw.ElapsedMilliseconds > 12000) break;
                            if ((sent & 0x1FFFFF) == 0) progress?.Invoke(Loc.T("speed.uploading", (sent * 8 / Math.Max(0.1, sw.Elapsed.TotalSeconds) / 1e6).ToString("0.0")), 0.65 + 0.33 * sent / total);
                        }
                        r.UpBytes = sent;
                    }
                    double secs = sw.Elapsed.TotalSeconds;
                    try { using (up.GetResponse()) { } } catch { }
                    r.UpMbps = r.UpBytes * 8 / Math.Max(0.2, secs) / 1e6;
                }
            }
            catch (Exception ex) { r.Error = ex.Message; }
            progress?.Invoke(Loc.T("speed.done"), 1);
            App.Log("Speed test: latency " + r.PingMs + " ms, download " + r.DownMbps.ToString("0.0") + " Mbit/s, upload " + r.UpMbps.ToString("0.0") + " Mbit/s" +
                    (r.Error.Length > 0 ? " (" + r.Error + ")" : ""), r.Error.Length > 0 ? LogLevel.Warn : LogLevel.Info);
            History.Add(new HistoryEntry
            {
                Time = DateTime.Now, Kind = "speed", Profile = App.Engine?.ActiveProfile?.Name ?? "", Ms = r.PingMs, Running = App.Engine?.State == EngineState.Running,
                Note = r.Error.Length > 0 ? r.Error : "↓ " + r.DownMbps.ToString("0.0") + " · ↑ " + r.UpMbps.ToString("0.0") + " Mbit/s",
            });
            return r;
        }
    }
}
