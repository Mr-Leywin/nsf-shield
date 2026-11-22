using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using Microsoft.Win32;

namespace NSFShield
{
    /// <summary>Runs Windows' own command line tools (netsh, sc) from System32 without opening a window.</summary>
    public static class Sys
    {
        static Encoding Oem
        {
            get
            {
                try { return Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage); }
                catch { return Encoding.Default; }
            }
        }

        /// <summary>
        /// Runs a program without opening a window; reads the output asynchronously (the buffer cannot fill up and block) and
        /// kills the process when the time runs out. Returns: (exit code, output); -1 could not start, -2 timeout.
        /// </summary>
        public static (int Code, string Output) Run(string file, string args, int timeoutMs = 20000)
        {
            try
            {
                var psi = new ProcessStartInfo(file, args)
                {
                    UseShellExecute = false, CreateNoWindow = true,
                    RedirectStandardOutput = true, RedirectStandardError = true,
                    StandardOutputEncoding = Oem, StandardErrorEncoding = Oem,
                    WorkingDirectory = Environment.SystemDirectory,
                };
                using (var p = Process.Start(psi))
                {
                    var o = p.StandardOutput.ReadToEndAsync();
                    var e = p.StandardError.ReadToEndAsync();
                    if (!p.WaitForExit(timeoutMs))
                    {
                        try { p.Kill(); } catch { }
                        try { p.WaitForExit(3000); } catch { }
                        App.Log(Path.GetFileName(file) + " " + args + " → " + (timeoutMs / 1000) + " s without finishing; killed.", LogLevel.Warn);
                        return (-2, "timeout");
                    }
                    // wait at most 5 s if child processes keep the streams open
                    string text = System.Threading.Tasks.Task.WaitAll(new System.Threading.Tasks.Task[] { o, e }, 5000) ? o.Result + e.Result
                                : (o.IsCompleted ? o.Result : "") + (e.IsCompleted ? e.Result : "");
                    App.Log(Path.GetFileName(file) + " " + args + " → " + p.ExitCode, LogLevel.Debug);
                    return (p.ExitCode, text.Trim());
                }
            }
            catch (Exception ex) { return (-1, ex.Message); }
        }

        public static string SystemExe(string name) => Path.Combine(Environment.SystemDirectory, name);

        /// <summary>
        /// explorer.exe passes at most this many characters of its argument on (MAX_PATH - 1): a longer address reaches the
        /// browser cut off – in the middle of an escape sequence GitHub answers "400 Bad Request".
        /// </summary>
        public const int MaxShellArgument = 259;

        /// <summary>Opens a program from an elevated process with normal user rights (through explorer).</summary>
        public static bool OpenAsUser(string path)
        {
            try
            {
                Process.Start(new ProcessStartInfo(Explorer, ShellArgument(path)) { UseShellExecute = false });
                return true;
            }
            catch { return false; }
        }

        /// <summary>The quoted explorer.exe argument; a longer one than explorer passes on is refused (never opened cut off).</summary>
        static string ShellArgument(string path)
        {
            if ((path ?? "").Length > MaxShellArgument)
            {
                App.Log("Not opened: the address is longer than " + MaxShellArgument + " characters (explorer.exe would cut it).", LogLevel.Warn);
                throw new ArgumentException("too long for explorer.exe", nameof(path));
            }
            return "\"" + path + "\"";
        }

        public static void OpenUri(string uri)
        {
            try { Process.Start(new ProcessStartInfo(uri) { UseShellExecute = true }); } catch (Exception ign) { App.Ignored("Address could not be opened", ign); }
        }

        static string Explorer => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");

        public static void OpenFolder(string dir)
        {
            try { Process.Start(new ProcessStartInfo(Explorer, "\"" + dir + "\"") { UseShellExecute = false }); } catch (Exception ign) { App.Ignored("Folder could not be opened", ign); }
        }

        public static void SelectFile(string file)
        {
            try { Process.Start(new ProcessStartInfo(Explorer, "/select,\"" + file + "\"") { UseShellExecute = false }); } catch (Exception ign) { App.Ignored("File could not be shown", ign); }
        }
    }

    // ==================================================================== Discord

    public static class DiscordHelper
    {
        static readonly string[] Names = { "Discord", "DiscordPTB", "DiscordCanary" };

        public static List<Process> Processes() => Names.SelectMany(n => Process.GetProcessesByName(n)).ToList();

        public static bool IsRunning
        {
            get
            {
                var l = Processes();
                bool r = l.Count > 0;
                foreach (var p in l) p.Dispose();
                return r;
            }
        }

        public static DateTime? EarliestStart()
        {
            DateTime? min = null;
            foreach (var p in Processes())
                using (p)
                {
                    try { var t = p.StartTime; if (min == null || t < min) min = t; } catch { }
                }
            return min;
        }

        /// <summary>Was Discord opened before the given time?</summary>
        public static bool StartedBefore(DateTime t)
        {
            var s = EarliestStart();
            return s.HasValue && s.Value < t.AddSeconds(-3);
        }

        static string ShortcutFor(string name)
        {
            string prog = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs), "Discord Inc");
            string file = name == "DiscordPTB" ? "Discord PTB.lnk" : name == "DiscordCanary" ? "Discord Canary.lnk" : "Discord.lnk";
            foreach (var f in new[] { Path.Combine(prog, file), Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), file) })
                if (File.Exists(f)) return f;
            return null;
        }

        /// <summary>Closes Discord completely and opens it again with normal user rights.</summary>
        public static bool Restart(out string message)
        {
            string flavor = "Discord", exe = null;
            var procs = Processes();
            foreach (var p in procs)
            {
                try { if (exe == null) { exe = p.MainModule.FileName; flavor = p.ProcessName; } } catch { }
            }
            foreach (var p in procs)
                using (p)
                {
                    try { if (!p.HasExited) p.Kill(); } catch (Exception ign) { App.Ignored("Discord could not be closed", ign); }
                }
            foreach (var p in Processes()) using (p) { try { p.WaitForExit(4000); } catch { } }
            Thread.Sleep(800);

            string launch = ShortcutFor(flavor);
            if (launch == null)
            {
                string upd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), flavor, "Update.exe");
                if (exe != null && File.Exists(exe)) launch = exe;
                else if (File.Exists(upd))
                {
                    // Discord.exe in the newest app-* folder
                    var dir = Directory.GetDirectories(Path.GetDirectoryName(upd), "app-*").OrderByDescending(d => d).FirstOrDefault();
                    if (dir != null && File.Exists(Path.Combine(dir, flavor + ".exe"))) launch = Path.Combine(dir, flavor + ".exe");
                }
            }
            if (launch == null)
            {
                message = procs.Count > 0 ? Loc.T("discord.noShortcut") : Loc.T("discord.notInstalled");
                App.Log(message, LogLevel.Warn);
                return procs.Count > 0;
            }
            bool ok = Sys.OpenAsUser(launch);
            message = ok ? (procs.Count > 0 ? Loc.T("discord.restarted") : Loc.T("discord.started")) : Loc.T("discord.startFailed");
            App.Log(message, ok ? LogLevel.Success : LogLevel.Warn);
            if (ok) App.Problems.Clear("NSF-901");
            return ok;
        }
    }

    // ==================================================================== Windows DNS setting

    public sealed class SystemDnsChoice
    {
        public string Id, V4a, V4b, V6a, V6b, Doh;
        string name = "", note = "";
        /// <summary>Brand name, or a locale key for a translated name.</summary>
        public string Name { get => Loc.Has(name) ? Loc.T(name) : name; set => name = value ?? ""; }
        /// <summary>Locale key of the note.</summary>
        public string Note { get => Loc.T(note); set => note = value ?? ""; }
        public bool IsAuto => Id == "auto";
    }

    public static class SystemDns
    {
        public static readonly List<SystemDnsChoice> Choices = new List<SystemDnsChoice>
        {
            new SystemDnsChoice { Id = "auto", Name = "sysdns.auto.name", Note = "sysdns.auto.note" },
            new SystemDnsChoice { Id = "cloudflare", Name = "Cloudflare", V4a = "1.1.1.1", V4b = "1.0.0.1", V6a = "2606:4700:4700::1111", V6b = "2606:4700:4700::1001",
                Doh = "https://cloudflare-dns.com/dns-query", Note = "sysdns.cloudflare.note" },
            new SystemDnsChoice { Id = "google", Name = "Google", V4a = "8.8.8.8", V4b = "8.8.4.4", V6a = "2001:4860:4860::8888", V6b = "2001:4860:4860::8844",
                Doh = "https://dns.google/dns-query", Note = "sysdns.google.note" },
            new SystemDnsChoice { Id = "quad9", Name = "Quad9", V4a = "9.9.9.9", V4b = "149.112.112.112", V6a = "2620:fe::fe", V6b = "2620:fe::9",
                Doh = "https://dns.quad9.net/dns-query", Note = "sysdns.quad9.note" },
            new SystemDnsChoice { Id = "adguard", Name = "AdGuard", V4a = "94.140.14.14", V4b = "94.140.15.15", V6a = "2a10:50c0::ad1:ff", V6b = "2a10:50c0::ad2:ff",
                Doh = "https://dns.adguard-dns.com/dns-query", Note = "sysdns.adguard.note" },
            new SystemDnsChoice { Id = "opendns", Name = "OpenDNS", V4a = "208.67.222.222", V4b = "208.67.220.220", V6a = "2620:119:35::35", V6b = "2620:119:53::53",
                Doh = "https://doh.opendns.com/dns-query", Note = "sysdns.opendns.note" },
        };

        /// <summary>Windows 11 (build 22000+) supports encrypted DNS (DoH) and the 'netsh dns ... encryption' commands.</summary>
        public static bool DohSupported => DohSupportedOn(WindowsBuild);
        public static bool DohSupportedOn(int build) => build >= 22000;

        public static string DohUnsupportedMessage(int build) =>
            Loc.T("sysdns.dohUnsupported", build);

        /// <summary>Is it a safe DoH template that may go on a netsh command line (https, no spaces, no command characters).</summary>
        internal static bool SafeTemplate(string t) =>
            !string.IsNullOrEmpty(t) && Uri.TryCreate(t, UriKind.Absolute, out var u) && u.Scheme == "https" && CmdLine.BareSafe(t) && !t.Contains(" ") && !t.Contains("\"");

        /// <summary>
        /// netsh commands for a DNS choice. On Windows 11 well-known servers (1.1.1.1, 8.8.8.8, 9.9.9.9…) are already registered
        /// (Auto-upgrade: no): 'set' is used if the entry exists, 'add' otherwise (tested live on this machine: both set
        /// Auto-upgrade to yes with exit code 0; 'delete' removes the entry). The result is always read back with 'show encryption' and verified.
        /// </summary>
        internal static List<(string Ip, string Add, string Set)> DohCommands(SystemDnsChoice c)
        {
            var list = new List<(string, string, string)>();
            if (!SafeTemplate(c.Doh)) return list;
            foreach (var ip in new[] { c.V4a, c.V4b, c.V6a, c.V6b })
            {
                if (string.IsNullOrEmpty(ip) || !IPAddress.TryParse(ip, out _)) continue;
                string tail = " dohtemplate=" + c.Doh + " autoupgrade=yes udpfallback=no";
                list.Add((ip, "dns add encryption server=" + ip + tail, "dns set encryption server=" + ip + tail));
            }
            return list;
        }

        /// <summary>Entry read from the output of 'netsh dns show encryption server=…'.</summary>
        internal sealed class DohEntry
        {
            /// <summary>False when netsh failed: the entry is unknown (never taken for "no entry").</summary>
            public bool Readable = true;
            public bool Exists;
            public string Template = "";
            public bool? AutoUpgrade, UdpFallback;
        }

        static bool? YesNo(string v)
        {
            v = (v ?? "").Trim().ToLowerInvariant();
            // netsh prints localized values on Turkish Windows
            if (v == "yes" || v == "evet" || v == "enabled" || v == "etkin" || v == "a\u00e7\u0131k") return true;
            if (v == "no" || v == "hay\u0131r" || v == "hayir" || v == "disabled" || v == "devre d\u0131\u015f\u0131" || v == "kapal\u0131") return false;
            return null;
        }

        /// <summary>Parses the encryption entry of one server (netsh prints nothing if there is no entry).</summary>
        internal static DohEntry ParseEncryption(string output)
        {
            var e = new DohEntry();
            foreach (var raw in (output ?? "").Split('\n'))
            {
                var m = System.Text.RegularExpressions.Regex.Match(raw.Trim(), @"^(.+?)\s+:\s*(.*)$");
                if (!m.Success) continue;
                string key = m.Groups[1].Value.ToLowerInvariant(), val = m.Groups[2].Value.Trim();
                e.Exists = true;
                if (val.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) e.Template = val;
                else if (key.Contains("upgrade") || key.Contains("y\u00fckselt")) e.AutoUpgrade = YesNo(val);
                else if (key.Contains("fallback") || key.Contains("geri")) e.UdpFallback = YesNo(val);
            }
            return e;
        }

        /// <summary>
        /// Reads one server's entry. netsh answers a missing entry with exit code 0 and no output (Exists = false); any other exit
        /// code is an unreadable entry (Readable = false), which never counts as missing.
        /// </summary>
        static DohEntry QueryDoh(string netsh, string ip)
        {
            var r = Netsh(netsh, "dns show encryption server=" + ip);
            return r.Code != 0 ? new DohEntry { Readable = false } : ParseEncryption(r.Output);
        }

        /// <summary>Reads (never writes) the encrypted DNS entry of one server; null if the address is not valid.</summary>
        internal static DohEntry ReadEncryption(string ip) =>
            IPAddress.TryParse(ip ?? "", out _) ? QueryDoh(Sys.SystemExe("netsh.exe"), ip) : null;

        /// <summary>DoH value in the output of 'netsh dns show global' (enabled/disabled/auto; null if it cannot be read).</summary>
        internal static string ParseGlobalDoh(string output)
        {
            foreach (var raw in (output ?? "").Split('\n'))
            {
                var m = System.Text.RegularExpressions.Regex.Match(raw.Trim(), @"^DoH[^:]*:\s*(\S+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                if (m.Success) return m.Groups[1].Value.ToLowerInvariant();
            }
            return null;
        }

        static string Short(string s)
        {
            s = (s ?? "").Replace("\r", " ").Replace("\n", " ").Trim();
            return s.Length > 160 ? s.Substring(0, 160) + "…" : s;
        }

        static string Fmt(bool? b) => b == null ? "unreadable" : b.Value ? "yes" : "no";

        /// <summary>Real Windows build number (not affected by the compatibility layer).</summary>
        public static int WindowsBuild
        {
            get
            {
                try
                {
                    using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                        if (int.TryParse(k?.GetValue("CurrentBuildNumber") as string, out int b)) return b;
                }
                catch (Exception ign) { App.Ignored("Windows build number could not be read", ign); }
                return Environment.OSVersion.Version.Build;
            }
        }

        public static List<AdapterInfo> TargetAdapters() =>
            NetTest.Adapters().Where(a => !a.IsVpn && (a.Gateways.Count > 0 || a.V4.Count > 0)).ToList();

        // ------------------------------------------------------------ status for the home page

        static readonly object statusSync = new object();
        static NetState status;
        static DateTime statusAt = DateTime.MinValue;
        static int statusBusy;
        static long statusGen;

        /// <summary>The DNS choice on the adapter of the internet route ("auto", a provider id, "custom", "mixed"; null until read).</summary>
        public static string StatusChoiceId => status?.DnsChoice;
        /// <summary>The last network picture (null until read).</summary>
        public static NetState Status => status;

        /// <summary>
        /// Reads the network picture in the background (at most every 20 s unless forced). A newer read or a picture published
        /// by the network watcher wins: an older read that returns later never overwrites it.
        /// </summary>
        public static void RefreshStatus(bool force = false)
        {
            if (App.Preview) return;
            if (!force && (DateTime.Now - statusAt).TotalSeconds < 20) return;
            if (System.Threading.Interlocked.Exchange(ref statusBusy, 1) == 1 && !force) return;
            statusAt = DateTime.Now;
            long g = System.Threading.Interlocked.Increment(ref statusGen);
            System.Threading.Tasks.Task.Run(() =>
            {
                try { Publish(NetStateReader.Read(force), g); }
                catch (Exception ign) { App.Ignored("DNS status could not be read", ign); }
                finally { if (System.Threading.Interlocked.Read(ref statusGen) == g) statusBusy = 0; }
            });
        }

        /// <summary>
        /// Sets the network picture. <paramref name="gen"/> = 0: a picture of the network watcher (newer than every read started
        /// before); otherwise only the newest read is taken. Raises a status change when something visible changed.
        /// </summary>
        public static bool Publish(NetState s, long gen = 0)
        {
            if (s == null) return false;
            bool changed;
            lock (statusSync)
            {
                if (gen == 0) System.Threading.Interlocked.Increment(ref statusGen);
                else if (gen != System.Threading.Interlocked.Read(ref statusGen)) return false;
                changed = status == null || status.Key != s.Key || status.AdapterName != s.AdapterName;
                status = s;
                statusAt = DateTime.Now;
            }
            if (changed) App.RaiseStatus();
            return true;
        }

        /// <summary>Short label of the Windows DNS: provider (+ "DoH" only when encrypted DNS is really registered), "System", "Custom" or "Mixed".</summary>
        public static string StatusLabel(NetState s)
        {
            string id = s?.DnsChoice;
            if (id == null) return "…";
            if (id == "auto") return Loc.T("home.chip.dnsSystem");
            if (id == "custom") return Loc.T("home.chip.dnsCustom");
            if (id == "mixed") return Loc.T("home.chip.dnsMixed");
            var c = Choices.FirstOrDefault(x => x.Id == id);
            return (c?.Name ?? id) + (s.Doh == DohState.Configured ? " DoH" : "");
        }

        /// <summary>The tooltip: DNS choice, encrypted DNS state and the adapter (with how it was found).</summary>
        public static string StatusTip(NetState s)
        {
            if (s == null) return Loc.T("home.dnsTip.unknown");
            string adapter = s.AdapterName != null
                ? Loc.T(s.RouteKnown ? "home.dnsTip.adapterRoute" : "home.dnsTip.adapterOnly", s.AdapterName + (string.IsNullOrEmpty(s.AdapterType) ? "" : " (" + s.AdapterType + ")"))
                : Loc.T(s.Candidates > 1 ? "home.dnsTip.adapterSeveral" : "home.dnsTip.adapterNone", s.Candidates);
            return Loc.T("home.dnsTip.line", StatusLabel(s), Loc.T("home.dnsTip.doh." + s.Doh), adapter);
        }

        static string Reg(bool v6) => v6 ? @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\" : @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\";

        /// <summary>DNS servers entered manually on the adapter (empty if automatic/DHCP or unreadable; for display).</summary>
        public static List<string> StaticServers(string adapterId, bool v6) => ReadStatic(adapterId, v6) ?? new List<string>();

        /// <summary>
        /// The manual DNS servers of an adapter: an empty list when there are none (automatic/DHCP, or no key for that family),
        /// null when they cannot be read (a backup or a check never takes "unreadable" for "automatic").
        /// </summary>
        internal static List<string> ReadStatic(string adapterId, bool v6)
        {
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(Reg(v6) + adapterId))
                {
                    if (k == null) return new List<string>();
                    string s = k.GetValue("NameServer", "") as string;
                    if (s == null) return null;   // a value of another type: not readable as a server list
                    return s.Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries).ToList();
                }
            }
            catch (Exception ex) { App.Ignored("DNS servers of an adapter could not be read", ex); return null; }
        }

        /// <summary>Which choice the current setting corresponds to ("auto", a provider id or "custom").</summary>
        public static string CurrentChoiceId(AdapterInfo a)
        {
            var v4 = StaticServers(a.Id, false);
            if (v4.Count == 0) return "auto";
            var c = Choices.FirstOrDefault(x => !x.IsAuto && v4[0] == x.V4a);
            return c?.Id ?? "custom";
        }

        /// <summary>
        /// Backs up the adapter's DNS servers before the first change. False when they cannot be read or the backup cannot be
        /// saved: then the adapter is not changed (an unreadable setting is never recorded as "automatic").
        /// </summary>
        static bool Backup(AdapterInfo a)
        {
            var list = App.Settings.DnsBackups;
            if (list.Any(b => b.Adapter == a.Name)) return true;
            var v4 = ReadServers(a.Id, false);
            var v6 = ReadServers(a.Id, true);
            if (v4 == null || v6 == null) return false;
            var b = new DnsBackup { Adapter = a.Name, V4Dhcp = v4.Count == 0, V4 = v4, V6Dhcp = v6.Count == 0, V6 = v6 };
            list.Add(b);
            if (App.TrySave()) return true;
            list.Remove(b);
            return false;
        }

        static string Q(string s) => "\"" + s + "\"";

        /// <summary>Runs netsh (the self-test replaces it with a recorder).</summary>
        internal static Func<string, string, (int Code, string Output)> Netsh = (exe, args) => Sys.Run(exe, args);
        /// <summary>Reads the manual DNS servers of an adapter by its id (null: unreadable; every restore is checked by reading it back).</summary>
        internal static Func<string, bool, List<string>> ReadServers = ReadStatic;
        /// <summary>The adapters the DNS page changes (the self-test replaces it).</summary>
        internal static Func<List<AdapterInfo>> Targets = TargetAdapters;
        /// <summary>The id of the adapter with this name (null when it is not there now).</summary>
        internal static Func<string, string> AdapterId = name => NetTest.Adapters().FirstOrDefault(a => a.Name == name)?.Id;
        /// <summary>Empties the Windows DNS cache after a change (the self-test replaces it: no system change in tests).</summary>
        internal static Action Flush = () => Native.FlushDns();

        /// <summary>The result of reading a setting back: as expected, different, or not readable (adapter missing, read error).</summary>
        internal enum ReadBack { Verified, Different, Unreadable }

        /// <summary>Does the adapter now have exactly these manual servers (an empty list: automatic/DHCP)?</summary>
        internal static ReadBack CheckServers(string adapter, bool v6, IList<string> expected)
        {
            string id = AdapterId(adapter);
            if (id == null) return ReadBack.Unreadable;
            var now = ReadServers(id, v6);
            if (now == null) return ReadBack.Unreadable;
            var want = (expected ?? new List<string>()).Where(s => !string.IsNullOrWhiteSpace(s)).ToList();
            if (now.Count != want.Count) return ReadBack.Different;
            for (int i = 0; i < want.Count; i++)
            {
                if (!IPAddress.TryParse(now[i], out var a) || !IPAddress.TryParse(want[i], out var b) || !a.Equals(b)) return ReadBack.Different;
            }
            return ReadBack.Verified;
        }

        internal static bool HasServers(string adapter, bool v6, IList<string> expected) => CheckServers(adapter, v6, expected) == ReadBack.Verified;

        static bool SetServers(string adapter, bool v6, IList<string> servers, StringBuilder log)
        {
            string fam = v6 ? "ipv6" : "ipv4";
            string netsh = Sys.SystemExe("netsh.exe");
            if (string.IsNullOrWhiteSpace(adapter) || adapter.IndexOf('"') >= 0 || CmdLine.HasControlChars(adapter))
            {
                log.AppendLine(fam + " → " + Loc.T("sysdns.invalidAdapter"));
                return false;
            }
            if (servers != null && servers.Count > 0)
            {
                // addresses from the settings file are validated before they are given to netsh
                var family = v6 ? System.Net.Sockets.AddressFamily.InterNetworkV6 : System.Net.Sockets.AddressFamily.InterNetwork;
                var valid = servers.Where(s => s != null && s.IndexOf('%') < 0 && IPAddress.TryParse(s, out var ip) && ip.AddressFamily == family).ToList();
                if (valid.Count != servers.Count) log.AppendLine(fam + " → " + Loc.T("sysdns.invalidAddresses", servers.Count - valid.Count));
                if (valid.Count == 0) return false;
                servers = valid;
            }
            if (servers == null || servers.Count == 0)
            {
                // already automatic (e.g. IPv6 never had manual servers): nothing to change, which is a success
                if (HasServers(adapter, v6, null)) { log.AppendLine(fam + " → " + Loc.T("sysdns.automatic") + ": " + Loc.T("common.ok")); return true; }
                var r = Netsh(netsh, "interface " + fam + " set dnsservers name=" + Q(adapter) + " source=dhcp");
                log.AppendLine(fam + " → " + Loc.T("sysdns.automatic") + ": " + (r.Code == 0 ? Loc.T("common.ok") : r.Output));
                return r.Code == 0;
            }
            var r1 = Netsh(netsh, "interface " + fam + " set dnsservers name=" + Q(adapter) + " source=static address=" + servers[0] + " register=primary validate=no");
            bool ok = r1.Code == 0;
            string err = r1.Output;
            // every further server counts too (a failed secondary server is a failed step, not a success)
            for (int i = 1; i < servers.Count && ok; i++)
            {
                var ra = Netsh(netsh, "interface " + fam + " add dnsservers name=" + Q(adapter) + " address=" + servers[i] + " index=" + (i + 1) + " validate=no");
                if (ra.Code != 0) { ok = false; err = ra.Output; }
            }
            log.AppendLine(fam + " → " + string.Join(", ", servers) + ": " + (ok ? Loc.T("common.ok") : err));
            return ok;
        }

        public static bool Apply(SystemDnsChoice c, bool doh, IEnumerable<AdapterInfo> adapters, out string report)
        {
            var log = new StringBuilder();
            bool allOk = true;
            foreach (var a in adapters)
            {
                log.AppendLine("■ " + a.Name);
                if (!Backup(a))
                {
                    // without a readable, saved backup the adapter is not changed
                    log.AppendLine(Loc.T("sysdns.backupUnreadable", a.Name));
                    allOk = false;
                    continue;
                }
                // IPv6 counts as much as IPv4: a failed step is reported, never shown as success
                if (c.IsAuto)
                {
                    allOk &= SetServers(a.Name, false, null, log);
                    allOk &= SetServers(a.Name, true, null, log);
                }
                else
                {
                    allOk &= SetServers(a.Name, false, new[] { c.V4a, c.V4b }, log);
                    if (a.V6.Count > 0 || a.HasGlobalV6) allOk &= SetServers(a.Name, true, new[] { c.V6a, c.V6b }, log);
                }
            }
            if (!c.IsAuto && doh)
            {
                if (DohSupported) allOk &= EnableDoh(c, log);
                else
                {
                    log.AppendLine(DohUnsupportedMessage(WindowsBuild));
                    App.Log("Encrypted DNS (DoH) is not supported on this Windows build (" + WindowsBuild + ").", LogLevel.Warn);
                }
            }
            else if (c.IsAuto && DohSupported) allOk &= RestoreDoh(log);   // returning to automatic also restores the encrypted DNS entries
            Flush();
            report = log.ToString().Trim();
            App.Log("Windows DNS setting: " + c.Id + (doh ? " (encrypted)" : "") + (allOk ? " applied." : " – some steps failed."), allOk ? LogLevel.Success : LogLevel.Warn);
            return allOk;
        }

        /// <summary>
        /// Enables encrypted DNS with Windows' own tool (netsh dns ... encryption); no other script interpreter is used.
        /// Only called on Windows 11 (Apply checks it).
        /// </summary>
        static bool EnableDoh(SystemDnsChoice c, StringBuilder log)
        {
            string netsh = Sys.SystemExe("netsh.exe");
            // allow DoH globally (the default on Windows 11 is "enabled"; if it is off it is turned on and the old value is backed up)
            string global = ParseGlobalDoh(Netsh(netsh, "dns show global").Output);
            if (global != null && !global.StartsWith("enab"))
            {
                if (App.Settings.GlobalDohBackup == null) App.Settings.GlobalDohBackup = global;
                var g = Netsh(netsh, "dns set global doh=yes");
                if (g.Code != 0) g = Netsh(netsh, "dns add global doh=yes");
                if (g.Code != 0) { log.AppendLine(Loc.T("sysdns.dohGlobalFailed") + " " + Short(g.Output)); App.Log("netsh dns global doh=yes: " + g.Output, LogLevel.Warn); }
            }
            var cmds = DohCommands(c);
            if (cmds.Count == 0)
            {
                log.AppendLine(Loc.T("sysdns.dohNoTemplate"));
                return false;
            }
            var done = new List<string>();
            var failed = new List<string>();
            foreach (var cmd in cmds)
            {
                var before = QueryDoh(netsh, cmd.Ip);
                if (!before.Readable && !App.Settings.DohBackups.Any(b => b.Server == cmd.Ip))
                {
                    // an unreadable entry is not changed: its old state could not be restored
                    failed.Add(cmd.Ip + " → " + Loc.T("sysdns.dohUnreadable"));
                    App.Log("[DoH] " + cmd.Ip + ": the current entry could not be read; it was not changed.", LogLevel.Warn);
                    continue;
                }
                if (!App.Settings.DohBackups.Any(b => b.Server == cmd.Ip))
                    App.Settings.DohBackups.Add(new DohBackup
                    {
                        Server = cmd.Ip, Existed = before.Exists, Template = before.Template,
                        AutoUpgrade = before.AutoUpgrade ?? false, UdpFallback = before.UdpFallback ?? false,
                    });
                var r = Netsh(netsh, before.Exists ? cmd.Set : cmd.Add);
                // instead of trusting netsh's exit code, the result is read back for every server
                var after = QueryDoh(netsh, cmd.Ip);
                bool good = after.Readable && after.Exists && after.AutoUpgrade == true && after.UdpFallback == false &&
                            string.Equals(after.Template, c.Doh, StringComparison.OrdinalIgnoreCase);
                if (good) { done.Add(cmd.Ip); continue; }
                string why = r.Code != 0 ? Loc.T("sysdns.netshFailed", r.Code, Short(r.Output)) : Loc.T("sysdns.notVerified", Fmt(after.AutoUpgrade), after.Template.Length > 0 ? after.Template : Loc.T("sysdns.none"));
                failed.Add(cmd.Ip + " → " + why);
                App.Log("[DoH] " + cmd.Ip + ": " + why, LogLevel.Warn);
            }
            App.Save();
            if (failed.Count == 0)
                log.AppendLine(Loc.T("sysdns.dohVerified", string.Join(", ", done)));
            else
            {
                log.AppendLine(Loc.T("sysdns.dohPartial", done.Count, cmds.Count));
                foreach (var f in failed) log.AppendLine("  " + f);
            }
            App.Log("Encrypted DNS: " + done.Count + "/" + cmds.Count + " server(s) verified (" + c.Id + ").", failed.Count == 0 ? LogLevel.Success : LogLevel.Warn);
            return failed.Count == 0;
        }

        /// <summary>
        /// Restores the encrypted DNS entries changed by NSF Shield: an entry that existed before is written back with its old template and
        /// Auto-upgrade/UDP-fallback values, an entry added by NSF Shield is deleted. The result is verified by reading it back.
        /// </summary>
        public static bool RestoreDoh(StringBuilder log)
        {
            var s = App.Settings;
            if (s.DohBackups.Count == 0 && s.GlobalDohBackup == null) return true;
            string netsh = Sys.SystemExe("netsh.exe");
            bool ok = true;
            foreach (var b in s.DohBackups.ToList())
            {
                if (!IPAddress.TryParse(b.Server ?? "", out _)) { s.DohBackups.Remove(b); continue; }
                (int Code, string Output) r;
                if (!b.Existed) r = Netsh(netsh, "dns delete encryption server=" + b.Server);
                else
                    r = Netsh(netsh, "dns set encryption server=" + b.Server + (SafeTemplate(b.Template) ? " dohtemplate=" + b.Template : "") +
                                       " autoupgrade=" + (b.AutoUpgrade ? "yes" : "no") + " udpfallback=" + (b.UdpFallback ? "yes" : "no"));
                var after = QueryDoh(netsh, b.Server);
                // only an entry read back exactly as it was (template, auto upgrade and UDP fallback together) frees its backup;
                // an unreadable entry or a template that cannot be written back safely keeps it
                bool templateBack = SafeTemplate(b.Template)
                    ? string.Equals(after.Template, b.Template, StringComparison.OrdinalIgnoreCase)
                    : string.IsNullOrEmpty(b.Template) && string.IsNullOrEmpty(after.Template);
                bool good = after.Readable && (b.Existed
                    ? after.Exists && after.AutoUpgrade == b.AutoUpgrade && after.UdpFallback == b.UdpFallback && templateBack
                    : !after.Exists);
                if (good) { s.DohBackups.Remove(b); continue; }
                ok = false;
                string why = b.Server + " → " + (r.Code != 0 ? Loc.T("sysdns.netshFailedShort", Short(r.Output))
                                                : !after.Readable ? Loc.T("sysdns.dohUnreadable")
                                                : b.Existed && !templateBack ? Loc.T("sysdns.dohTemplateNotRestored")
                                                : Loc.T("sysdns.restoreNotVerified", Fmt(after.AutoUpgrade)));
                log.AppendLine(Loc.T("sysdns.dohRestoreFailed") + " " + why);
                App.Log("[DoH] restore: " + why, LogLevel.Warn);
            }
            if (s.GlobalDohBackup != null)
            {
                string v = s.GlobalDohBackup.StartsWith("dis") ? "no" : s.GlobalDohBackup.StartsWith("auto") ? "auto" : "yes";
                var g = Netsh(netsh, "dns set global doh=" + v);
                // read back: the backup goes only when Windows reports the old value again
                string now = ParseGlobalDoh(Netsh(netsh, "dns show global").Output) ?? "";
                bool back = v == "no" ? now.StartsWith("dis") : v == "auto" ? now.StartsWith("auto") : now.StartsWith("enab");
                if (g.Code == 0 && back) s.GlobalDohBackup = null;
                else { ok = false; log.AppendLine(Loc.T("sysdns.dohGlobalRestoreFailed") + " " + Short(g.Output)); }
            }
            App.Save();
            if (ok) log.AppendLine(Loc.T("sysdns.dohRestored"));
            return ok;
        }

        /// <param name="onlyBackups">true: only adapters changed by NSF Shield (with a backup) are restored (for uninstalling).</param>
        public static bool Restore(out string report, bool onlyBackups = false)
        {
            var log = new StringBuilder();
            bool ok = true;
            var adapters = onlyBackups ? new List<AdapterInfo>() : Targets();
            // the adapters with a backup at the start: a restored static adapter is never taken for one without a backup below
            var backedUp = new HashSet<string>(App.Settings.DnsBackups.Select(b => b.Adapter), StringComparer.Ordinal);
            int failed = 0;
            foreach (var b in App.Settings.DnsBackups.ToList())
            {
                log.AppendLine("■ " + b.Adapter);
                bool b4 = SetServers(b.Adapter, false, b.V4Dhcp ? null : b.V4, log);
                bool b6 = SetServers(b.Adapter, true, b.V6Dhcp ? null : b.V6, log);
                // the backup of an adapter goes only when IPv4 and IPv6 read back as they were; otherwise (different or unreadable)
                // it stays for a retry
                var r4 = CheckServers(b.Adapter, false, b.V4Dhcp ? null : b.V4);
                var r6 = CheckServers(b.Adapter, true, b.V6Dhcp ? null : b.V6);
                if (b4 && b6 && r4 == ReadBack.Verified && r6 == ReadBack.Verified) App.Settings.DnsBackups.Remove(b);
                else
                {
                    ok = false; failed++;
                    log.AppendLine(Loc.T(r4 == ReadBack.Unreadable || r6 == ReadBack.Unreadable ? "sysdns.restoreUnreadable" : "sysdns.restoreKept", b.Adapter));
                }
            }
            foreach (var a in adapters.Where(a => !backedUp.Contains(a.Name)))
            {
                log.AppendLine("■ " + a.Name);
                ok &= SetServers(a.Name, false, null, log);
                ok &= SetServers(a.Name, true, null, log);
            }
            ok &= RestoreDoh(log);   // the encrypted DNS entries also go back to their state before NSF Shield
            App.Save();
            Flush();
            report = log.ToString().Trim();
            App.Log(ok ? "Windows DNS settings were restored." : "Windows DNS settings were restored only in part (" + failed + " adapter backup(s) kept for a retry).", ok ? LogLevel.Success : LogLevel.Warn);
            return ok;
        }
    }
}
