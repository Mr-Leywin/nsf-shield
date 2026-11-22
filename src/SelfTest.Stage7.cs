#if PREVIEW
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NSFShield
{
    /// <summary>
    /// In-memory replacement of the HKCU values that <see cref="ProxyRecovery"/> reads and writes (Internet Settings, the
    /// recovery record, RunOnce). The preview installs it at start, so no preview path can touch the real Windows proxy.
    /// </summary>
    static class MemRegistry
    {
        public static readonly Dictionary<string, ProxyValue> Inet = new Dictionary<string, ProxyValue>(StringComparer.OrdinalIgnoreCase);
        public static readonly Dictionary<string, string> Text = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        /// <summary>A write of this value name (Internet Settings) or key\name (text) fails when it returns true.</summary>
        public static Func<string, bool> FailWrite = n => false;
        /// <summary>A read of this value name fails (unreadable) when it returns true.</summary>
        public static Func<string, bool> FailRead = n => false;
        public static int Announced, Writes;

        public static void Install()
        {
            ProxyRecovery.ReadValue = n => FailRead(n) ? (ProxyValue?)null : Inet.TryGetValue(n, out var v) ? v : ProxyValue.Absent;
            ProxyRecovery.WriteValue = (n, v) =>
            {
                Writes++;
                if (FailWrite(n)) throw new UnauthorizedAccessException("write denied (test)");
                if (v.Exists) Inet[n] = v; else Inet.Remove(n);
            };
            ProxyRecovery.ReadText = (k, n) => Text.TryGetValue(k + "\\" + n, out var v) ? v : null;
            ProxyRecovery.WriteText = (k, n, v) =>
            {
                if (FailWrite(k + "\\" + n)) throw new UnauthorizedAccessException("write denied (test)");
                if (v == null) Text.Remove(k + "\\" + n); else Text[k + "\\" + n] = v;
            };
            ProxyRecovery.Announce = () => Announced++;
            ByeDpiNet.Helper = () => ("\"C:\\Program Files\\NSF Shield\\bin\\" + ProxyRecovery.HelperFile + "\" --restore", null);
        }

        public static void Reset()
        {
            Inet.Clear();
            Text.Clear();
            FailWrite = n => false;
            FailRead = n => false;
            Announced = Writes = 0;
        }

        public static string RunOnce(string name) => Text.TryGetValue(ProxyRecovery.RunOnceKey + "\\" + name, out var v) ? v : null;
        public static bool HasRecord => Text.ContainsKey(ProxyRecovery.RecordKey + "\\" + ProxyRecovery.RecordValue);
    }

    /// <summary>
    /// second audit (stage 7): behaviour tests with fakes only – the Home profile box, DNS/DoH restore (fake netsh and
    /// adapter view), the Windows proxy recovery record (in-memory registry), the service transaction (scripted SCM), process
    /// closing by handle (the test's own ping process), the 2.x service and data folder, the scan reservation, path safety,
    /// the installer switch, the ZIP update, the targeted mode scope, settings saving, the support package and the setup
    /// package script. Nothing touches a real service, driver, DNS/proxy setting or another program.
    /// </summary>
    static partial class SelfTest
    {
        static void Stage7Tests(Action<string, bool, string> Check)
        {
            var oldSettings = App.Settings;
            if (App.Engine == null) App.Engine = new Engine();
            string root = Path.Combine(Path.GetTempPath(), "nsf stage7 " + Guid.NewGuid().ToString("N").Substring(0, 6));
            Directory.CreateDirectory(root);
            var ctx = SynchronizationContext.Current;
            void Part(string name, Action a)
            {
                try { a(); }
                catch (Exception ex) { Check("stage 7 " + name + " ran without an exception", false, ex.GetType().Name + ": " + ex.Message + " @ " + (ex.StackTrace ?? "").Split('\n').FirstOrDefault()?.Trim()); }
            }
            try
            {
                SynchronizationContext.SetSynchronizationContext(null);
                App.Settings = new AppSettings();
                App.Settings.Normalize();
                Part("home", () => Home7(Check));
                Part("dns", () => Dns7(Check));
                Part("proxy", () => Proxy7(Check));
                Part("helper", () => Helper7(Check));
                Part("service", () => Txn7(Check));
                Part("process", () => Proc7(Check));
                Part("b11", () => B11_7(Check, root));
                Part("b13", () => B13_7(Check));
                Part("paths", () => Paths7(Check, root));
                Part("switch", () => Switch7(Check, root));
                Part("zip", () => Zip7(Check, root));
                Part("scope", () => Scope7(Check));
                Part("settings", () => Settings7(Check, root));
                Part("support", () => Support7(Check, root));
                Part("setup script", () => Iss7(Check));
            }
            finally
            {
                SynchronizationContext.SetSynchronizationContext(ctx);
                App.Settings = oldSettings;
                MemRegistry.Reset();
                try { Directory.Delete(root, true); } catch { }
            }
        }

        // ============================================================================ 1. the Home profile box

        static void Home7(Action<string, bool, string> Check)
        {
            var all = App.AllProfiles.ToList();
            var g = all.First(p => p.Engine == EngineKind.GoodbyeDpi && p.Tier == ProfileTier.Recommended);
            var z = all.First(p => p.Engine == EngineKind.Zapret && p.Tier == ProfileTier.Recommended);
            var snap = z.CloneAsCustom(); snap.Id = "removed-running-snapshot"; snap.Name = "snapshot";
            Check("home: a running snapshot the catalog no longer has is the one shown profile",
                  ReferenceEquals(ProfileCatalog.Effective(EngineState.Running, snap, g.Id, all), snap), "");
            Check("home: starting shows the starting profile; stopped and error show the saved selection",
                  ReferenceEquals(ProfileCatalog.Effective(EngineState.Starting, z, g.Id, all), z) &&
                  ReferenceEquals(ProfileCatalog.Effective(EngineState.Stopped, z, g.Id, all), g) &&
                  ReferenceEquals(ProfileCatalog.Effective(EngineState.Error, z, g.Id, all), g), "");
            Check("home: an old or missing id falls back to the default profile, like App.SelectedProfile",
                  ReferenceEquals(ProfileCatalog.Effective(EngineState.Stopped, null, "removed-old-id", all), Profiles.BuiltIns[0]), "");
            var items = ProfileCatalog.HomeItems(snap, ProfileCatalog.Visible(all, UiLevel.Standard, false, EngineKind.Zapret, g.Id, null));
            Check("home: the box lists the shown profile's engine only and the snapshot exactly once",
                  items.Count(i => i.Id == snap.Id) == 1 && items.Contains(snap) && items.All(i => i.Engine == EngineKind.Zapret), items.Count + " items");
            var edited = z.CloneAsCustom(); edited.Id = z.Id; edited.Name = "edited running copy";
            var items2 = ProfileCatalog.HomeItems(edited, ProfileCatalog.Visible(all, UiLevel.Standard, false, EngineKind.Zapret, g.Id, z.Id));
            Check("home: a running copy with a catalog id replaces that entry (card and box show the same object)",
                  items2.Count(i => i.Id == z.Id) == 1 && items2.Contains(edited) && !items2.Contains(z), "");
        }

        // ============================================================================ 3. DNS and DoH restore

        static void Dns7(Action<string, bool, string> Check)
        {
            var oldNetsh = SystemDns.Netsh; var oldRead = SystemDns.ReadServers; var oldId = SystemDns.AdapterId; var oldFlush = SystemDns.Flush; var oldTargets = SystemDns.Targets;
            var state = new Dictionary<string, List<string>>();   // "<id>|4" / "<id>|6" → manual servers
            var cmds = new List<string>();
            Func<string, bool, bool> unreadable = (id, v6) => false;
            (int, string) showEncryption = (0, "");
            try
            {
                SystemDns.AdapterId = name => name == "Ethernet A" ? "{A}" : name == "Wi-Fi B" ? "{B}" : null;
                SystemDns.ReadServers = (id, v6) => unreadable(id, v6) ? null : state.TryGetValue(id + "|" + (v6 ? "6" : "4"), out var l) ? l.ToList() : new List<string>();
                SystemDns.Flush = () => { };
                var adapters = new List<AdapterInfo> { new AdapterInfo { Name = "Ethernet A", Id = "{A}" }, new AdapterInfo { Name = "Wi-Fi B", Id = "{B}" } };
                SystemDns.Targets = () => adapters.ToList();
                SystemDns.Netsh = (exe, args) =>
                {
                    cmds.Add(args);
                    var m = System.Text.RegularExpressions.Regex.Match(args, "^interface (ipv4|ipv6) (set|add) dnsservers name=\"([^\"]+)\" (?:source=(dhcp|static)\\s*)?(?:address=(\\S+))?");
                    if (m.Success)
                    {
                        string id = SystemDns.AdapterId(m.Groups[3].Value), key = id + "|" + (m.Groups[1].Value == "ipv6" ? "6" : "4");
                        if (m.Groups[4].Value == "dhcp") state[key] = new List<string>();
                        else if (m.Groups[2].Value == "set") state[key] = new List<string> { m.Groups[5].Value };
                        else state[key].Add(m.Groups[5].Value);
                        return (0, "");
                    }
                    if (args.StartsWith("dns show encryption")) return showEncryption;
                    if (args.StartsWith("dns show global")) return (0, "");
                    return (0, "");
                };
                void Setup()
                {
                    state.Clear(); cmds.Clear();
                    state["{A}|4"] = new List<string> { "1.1.1.1", "1.0.0.1" }; state["{A}|6"] = new List<string> { "2606:4700:4700::1111" };
                    state["{B}|4"] = new List<string> { "1.1.1.1", "1.0.0.1" };
                    App.Settings.DnsBackups = new List<DnsBackup>
                    {
                        new DnsBackup { Adapter = "Ethernet A", V4Dhcp = false, V4 = new List<string> { "192.0.2.53", "198.51.100.53" }, V6Dhcp = false, V6 = new List<string> { "2001:db8::53" } },
                    };
                    App.Settings.DohBackups = new List<DohBackup>();
                    App.Settings.GlobalDohBackup = null;
                    unreadable = (id, v6) => false;
                }
                Setup();
                bool ok = SystemDns.Restore(out string rep, onlyBackups: false);
                Check("dns normal restore (onlyBackups: false): the restored static adapter keeps its old servers (never turned to DHCP), the adapter without a backup goes to automatic",
                      ok && state["{A}|4"].SequenceEqual(new[] { "192.0.2.53", "198.51.100.53" }) && state["{A}|6"].SequenceEqual(new[] { "2001:db8::53" }) &&
                      state["{B}|4"].Count == 0 && App.Settings.DnsBackups.Count == 0 && !cmds.Any(c => c.Contains("\"Ethernet A\" source=dhcp")),
                      string.Join(" | ", cmds));
                Setup();
                ok = SystemDns.Restore(out rep, onlyBackups: true);
                Check("dns uninstall restore (onlyBackups: true): only the adapter with a backup is changed (the other one keeps its servers)",
                      ok && state["{A}|4"].SequenceEqual(new[] { "192.0.2.53", "198.51.100.53" }) && state["{B}|4"].SequenceEqual(new[] { "1.1.1.1", "1.0.0.1" }) &&
                      !cmds.Any(c => c.Contains("Wi-Fi B")), string.Join(" | ", cmds));
                Setup();
                unreadable = (id, v6) => id == "{A}" && cmds.Count > 0;   // readable before, unreadable after the restore commands
                ok = SystemDns.Restore(out rep, onlyBackups: true);
                Check("dns: a setting that cannot be read back after the restore keeps its backup (unreadable is not 'verified')",
                      !ok && App.Settings.DnsBackups.Count == 1 && rep.Contains(Loc.T("sysdns.restoreUnreadable", "Ethernet A")), rep.Replace("\r\n", " | "));
                Setup();
                App.Settings.DnsBackups.Clear();
                unreadable = (id, v6) => id == "{A}";
                var cf = SystemDns.Choices.First(c => c.Id == "cloudflare");
                ok = SystemDns.Apply(cf, false, new[] { adapters[0] }, out rep);
                Check("dns: an adapter whose current servers cannot be read is not changed and gets no 'automatic' backup",
                      !ok && App.Settings.DnsBackups.Count == 0 && !cmds.Any(c => c.Contains("Ethernet A")), rep.Replace("\r\n", " | "));
                // DoH: a failed query is never "no entry"; a template that cannot be written back keeps the backup
                Setup();
                App.Settings.DohBackups = new List<DohBackup> { new DohBackup { Server = "1.1.1.1", Existed = false } };
                showEncryption = (1, "The parameter is incorrect.");
                var log = new StringBuilder();
                bool dohOk = SystemDns.RestoreDoh(log);
                Check("doh: a backup is kept when the entry cannot be read back (netsh error is not 'deleted')", !dohOk && App.Settings.DohBackups.Count == 1, log.ToString());
                App.Settings.DohBackups = new List<DohBackup> { new DohBackup { Server = "1.1.1.1", Existed = true, Template = "http://not safe", AutoUpgrade = false, UdpFallback = false } };
                showEncryption = (0, "DNS-over-HTTPS template : https://cloudflare-dns.com/dns-query\r\nAuto-upgrade : no\r\nUDP-fallback : no\r\n");
                log.Clear();
                dohOk = SystemDns.RestoreDoh(log);
                Check("doh: an old template that cannot be written back safely keeps the backup", !dohOk && App.Settings.DohBackups.Count == 1, log.ToString());
                App.Settings.DohBackups = new List<DohBackup>();
                showEncryption = (1, "error");
                cmds.Clear();
                var enable = typeof(SystemDns).GetMethod("EnableDoh", BindingFlags.Static | BindingFlags.NonPublic);
                log.Clear();
                bool en = (bool)enable.Invoke(null, new object[] { cf, log });
                Check("doh: an entry whose current state cannot be read is not changed and gets no 'did not exist' backup",
                      !en && App.Settings.DohBackups.Count == 0 && !cmds.Any(c => c.StartsWith("dns add encryption") || c.StartsWith("dns set encryption")), log.ToString());
                showEncryption = (0, "");
                var none = SystemDns.ReadEncryption("1.1.1.1");
                Check("doh: an empty answer with exit code 0 is 'no entry' (readable)", none != null && none.Readable && !none.Exists, "");
            }
            finally
            {
                SystemDns.Netsh = oldNetsh; SystemDns.ReadServers = oldRead; SystemDns.AdapterId = oldId; SystemDns.Flush = oldFlush; SystemDns.Targets = oldTargets;
                App.Settings.DnsBackups = new List<DnsBackup>(); App.Settings.DohBackups = new List<DohBackup>(); App.Settings.GlobalDohBackup = null;
            }
        }

        // ============================================================================ 3. the Windows proxy recovery

        static void Proxy7(Action<string, bool, string> Check)
        {
            var reg = MemRegistry.Inet;
            var s = App.Settings;
            var oldPersist = ByeDpiNet.Persist;
            var apply = typeof(ByeDpiNet).GetMethod("ApplySystem", BindingFlags.Static | BindingFlags.NonPublic);
            bool Arm() { try { apply.Invoke(null, null); return true; } catch (TargetInvocationException ex) when (ex.InnerException is IOException) { return false; } }
            string longPac = "http://pac.example.test/" + new string('p', 3000) + ".pac";
            void UserState()
            {
                MemRegistry.Reset();
                reg["ProxyEnable"] = ProxyValue.Number(1);
                reg["ProxyServer"] = ProxyValue.Text("proxy.example.test:3128");
                reg["ProxyOverride"] = ProxyValue.Text("*.corp.example.test;<local>");
                reg["AutoConfigURL"] = ProxyValue.Text(longPac);
                s.SystemProxyId = "";
            }
            bool IsUserState() =>
                reg["ProxyEnable"].Data == "1" && reg["ProxyServer"].Data == "proxy.example.test:3128" && reg["ProxyOverride"].Data == "*.corp.example.test;<local>" &&
                reg.TryGetValue("AutoConfigURL", out var pac) && pac.Data == longPac;
            try
            {
                UserState();
                bool armed = Arm();
                var rec = ProxyRecovery.Read();
                Check("proxy: the record (four values before and after, with existence; a 3000-character PAC too) and the sign-in entry are written and read back before Windows is changed",
                      armed && rec != null && rec.Owner == ByeDpiNet.ProxyMarker && rec.AtSignIn && rec.Backup[3].Data == longPac && !rec.Written[3].Exists &&
                      MemRegistry.RunOnce(ProxyRecovery.RunOnceName)?.EndsWith("\" --restore") == true && reg["ProxyServer"].Data == ByeDpiNet.BridgeAddress &&
                      !reg.ContainsKey("AutoConfigURL"), "");
                var r = ByeDpiNet.RestoreOwned("test");
                Check("proxy: the long PAC and every other value come back exactly; record and sign-in entry go", r == ByeDpiNet.RestoreResult.Restored && IsUserState() &&
                      !MemRegistry.HasRecord && MemRegistry.RunOnce(ProxyRecovery.RunOnceName) == null && s.SystemProxyId == "", "");

                // a failed 2nd write: NSF Shield's own value goes back at once, nothing stays recorded
                UserState();
                MemRegistry.FailWrite = n => n == "ProxyServer";
                bool a2 = Arm();
                MemRegistry.FailWrite = n => false;
                Check("proxy: a failed 2nd write (ProxyServer) is undone at once – the first value goes back, no record or marker stays",
                      !a2 && IsUserState() && !MemRegistry.HasRecord && s.SystemProxyId == "", "");
                // a failed 3rd write whose undo fails too: the record stays; the next attempt (retry) restores it
                UserState();
                int enableFails = 0;
                MemRegistry.FailWrite = n => n == "ProxyOverride" || (n == "ProxyServer" && reg.TryGetValue("ProxyServer", out var sv) && sv.Data == ByeDpiNet.BridgeAddress && enableFails++ < 1);
                bool a3 = Arm();
                bool kept = MemRegistry.HasRecord && s.SystemProxyId == ByeDpiNet.ProxyMarker;
                MemRegistry.FailWrite = n => false;
                bool retried = ByeDpiNet.RecoverStale("retry");
                Check("proxy: a failed 3rd write whose undo also fails keeps the record; the retry restores everything and drops it",
                      !a3 && kept && retried && IsUserState() && !MemRegistry.HasRecord && s.SystemProxyId == "", "enable failures " + enableFails);

                // an interrupted restore of NSF Shield itself (the enable flag already back, power lost) is finished, not taken for a user change
                UserState();
                Arm();
                reg["ProxyEnable"] = ProxyValue.Number(1);   // the user's value (equal to the written one): nothing to see here
                reg["ProxyOverride"] = ProxyValue.Text("*.corp.example.test;<local>");   // already written back before the power loss
                var res = ProxyRecovery.Restore(ProxyRecovery.Read());
                Check("proxy: an interrupted restore of NSF Shield is completed (values equal to the backup count as done, never as the user's)",
                      res.Outcome == ProxyRecovery.Outcome.Restored && res.KeptNames.Count == 0 && IsUserState() && !MemRegistry.HasRecord, res.ToString());

                // the user changed only the PAC or only the exception list: those stay, NSF Shield's other values go back
                UserState();
                Arm();
                reg["AutoConfigURL"] = ProxyValue.Text("http://user.example.test/new.pac");
                var r4 = ByeDpiNet.RestoreOwned("test");
                Check("proxy: a PAC the user set meanwhile is kept; enable, server and exceptions go back",
                      r4 == ByeDpiNet.RestoreResult.UserChanged && reg["AutoConfigURL"].Data == "http://user.example.test/new.pac" &&
                      reg["ProxyServer"].Data == "proxy.example.test:3128" && reg["ProxyOverride"].Data == "*.corp.example.test;<local>" && !MemRegistry.HasRecord, "");
                UserState();
                Arm();
                reg["ProxyOverride"] = ProxyValue.Text("<local>;*.user.example.test");
                var r5 = ProxyRecovery.Restore(ProxyRecovery.Read());
                Check("proxy: an exception list the user set meanwhile is kept; the other values go back",
                      r5.Outcome == ProxyRecovery.Outcome.UserKept && r5.KeptNames.SequenceEqual(new[] { "ProxyOverride" }) && reg["ProxyOverride"].Data == "<local>;*.user.example.test" &&
                      reg["ProxyServer"].Data == "proxy.example.test:3128" && reg["AutoConfigURL"].Data == longPac, r5.ToString());

                // power loss: at the next sign-in the helper restores it when NSF Shield does not run; while it runs, nothing changes
                UserState();
                Arm();
                string helper = @"C:\Program Files\NSF Shield\bin\" + ProxyRecovery.HelperFile;
                MemRegistry.Text.Remove(ProxyRecovery.RunOnceKey + "\\" + ProxyRecovery.RunOnceName);   // Windows removes the entry before it runs it
                var (c1, n1) = ProxyRecovery.SignInRestore(helper, () => true);
                bool untouched = reg["ProxyServer"].Data == ByeDpiNet.BridgeAddress && MemRegistry.HasRecord && MemRegistry.RunOnce(ProxyRecovery.RunOnceName) != null;
                var (c2, n2) = ProxyRecovery.SignInRestore(helper, () => false);
                Check("proxy: sign-in after a power loss – while NSF Shield runs nothing changes (the entry is renewed); otherwise the helper restores it",
                      c1 == 0 && untouched && c2 == 0 && IsUserState() && !MemRegistry.HasRecord, n1 + " / " + n2);
                MemRegistry.FailWrite = n => n == "ProxyServer";
                UserState(); MemRegistry.FailWrite = n => false; Arm();
                MemRegistry.FailWrite = n => n == "ProxyServer";
                var (c3, n3) = ProxyRecovery.SignInRestore(helper, () => false);
                MemRegistry.FailWrite = n => false;
                Check("proxy: a sign-in restore that fails keeps the record and renews the sign-in entry (exit code 1)",
                      c3 == 1 && MemRegistry.HasRecord && MemRegistry.RunOnce(ProxyRecovery.RunOnceName) != null, n3);
                ByeDpiNet.RestoreOwned("cleanup");

                // a torn record is never used: preparing refuses, the start check removes it without touching the live setting
                UserState();
                string full = new ProxyRecord { Owner = ByeDpiNet.ProxyMarker, AtSignIn = true, Backup = ProxyRecovery.Live(), Written = ProxyRecovery.For(ByeDpiNet.BridgeAddress, ProxyTools.LocalBypass) }.Serialize();
                MemRegistry.Text[ProxyRecovery.RecordKey + "\\" + ProxyRecovery.RecordValue] = full.Substring(0, full.Length / 2);
                bool tornArm = Arm();
                ByeDpiNet.StartupCheck();
                Check("proxy: a torn record is never used – preparing refuses and the start check removes it; the live setting is unchanged",
                      !tornArm && !MemRegistry.HasRecord && IsUserState(), "");

                // an unreadable live value: nothing is prepared or written
                UserState();
                MemRegistry.FailRead = n => n == "ProxyOverride";
                bool unread = Arm();
                MemRegistry.FailRead = n => false;
                Check("proxy: an unreadable value stops the change before anything is written", !unread && MemRegistry.Writes == 0 && !MemRegistry.HasRecord && IsUserState(), "");

                // general proxies: the same record and ownership rules (no sign-in restore: the user's own proxy stays set)
                UserState();
                var p1 = new ProxyEntry { Id = "p-test-1", Kind = ProxyKind.Http, Host = "proxy-one.example.test", Port = 3128 };
                var p2 = new ProxyEntry { Id = "p-test-2", Kind = ProxyKind.Socks5, Host = "proxy-two.example.test", Port = 1080 };
                ProxyTools.ApplySystem(p1);
                var g1 = ProxyRecovery.Read();
                bool okP1 = g1 != null && g1.Owner == p1.Id && !g1.AtSignIn && MemRegistry.RunOnce(ProxyRecovery.RunOnceName) == null && reg["ProxyServer"].Data == "proxy-one.example.test:3128";
                ProxyTools.ApplySystem(p2);
                var g2 = ProxyRecovery.Read();
                bool okP2 = g2 != null && g2.Owner == p2.Id && g2.Backup[1].Data == "proxy.example.test:3128" && reg["ProxyServer"].Data == "socks=proxy-two.example.test:1080";
                reg["ProxyOverride"] = ProxyValue.Text("<local>;*.mine.example.test");
                bool off = ProxyTools.RestoreSystem();
                Check("proxy: a saved proxy uses the same record (switching keeps the values from before NSF Shield); turning it off keeps the user's exception list",
                      okP1 && okP2 && off && reg["ProxyServer"].Data == "proxy.example.test:3128" && reg["ProxyOverride"].Data == "<local>;*.mine.example.test" &&
                      reg["AutoConfigURL"].Data == longPac && !MemRegistry.HasRecord && s.SystemProxyId == "", "");

            }
            finally
            {
                ByeDpiNet.Persist = oldPersist;
                MemRegistry.Reset();
                s.SystemProxyId = "";
            }
        }

        /// <summary>The sign-in recovery helper of this build: asInvoker, no other dependency, its hash embedded and checked.</summary>
        static void Helper7(Action<string, bool, string> Check)
        {
            string exe = Path.Combine(Repo, "build", ProxyRecovery.HelperFile);
            Check("recovery helper: built by build.ps1 before the app (its SHA-256 is the one embedded in NSFShield.exe)",
                  File.Exists(exe) && Integrity.Sha256File(exe) == BuildInfo.RecoveryHelperSha256 &&
                  Integrity.Known.TryGetValue(ProxyRecovery.HelperFile, out var h) && h == BuildInfo.RecoveryHelperSha256, exe);
            if (!File.Exists(exe)) return;
            var bytes = File.ReadAllBytes(exe);
            string ascii = Encoding.ASCII.GetString(bytes), wide = Encoding.Unicode.GetString(bytes);
            Check("recovery helper: its manifest runs it as the signed-in user (asInvoker), never elevated",
                  ascii.Contains("level=\"asInvoker\"") && !ascii.Contains("requireAdministrator"), "");
            var refs = Assembly.ReflectionOnlyLoadFrom(exe).GetReferencedAssemblies().Select(a => a.Name).OrderBy(x => x).ToList();
            Check("recovery helper: no reference besides mscorlib, System and System.Core", refs.All(r => r == "mscorlib" || r == "System" || r == "System.Core"), string.Join(",", refs));
            var bad = new[] { "power" + "shell", "w" + "script", "c" + "script", "ms" + "hta", "cmd.exe", "reg.exe" }
                .Where(x => ascii.IndexOf(x, StringComparison.OrdinalIgnoreCase) >= 0 || wide.IndexOf(x, StringComparison.OrdinalIgnoreCase) >= 0).ToList();
            Check("recovery helper: no script host and no reg.exe/cmd in the program", bad.Count == 0, string.Join(",", bad));
            var fv = FileVersionInfo.GetVersionInfo(exe);
            Check("recovery helper: version information of NSF Shield (the same version and publisher as the app)",
                  fv.CompanyName == App.Publisher && fv.ProductName == "NSF Shield" && fv.FileVersion == typeof(App).Assembly.GetName().Version.ToString(), fv.CompanyName + " " + fv.FileVersion);
            string build = File.ReadAllText(Path.Combine(Repo, "build.ps1")), iss = File.ReadAllText(Path.Combine(Repo, @"installer\NSFShield.iss")),
                   un = File.ReadAllText(Path.Combine(Repo, @"src\Core\Uninstall.cs"));
            Check("recovery helper: in the package (bin), the ZIP and SHA256SUMS (package tree), the reproducibility check, the setup script's allowed programs and the upgrade/uninstall closing",
                  build.Contains("Copy-Item $helperExe (Join-Path $appDir \"bin\\$helperName\")") && build.Contains("$helperName = (Get-Sha256 (Join-Path $appDir \"bin\\$helperName\"))") &&
                  iss.Contains("'{app}\\bin\\NSFShieldProxyRecovery.exe'") && iss.Contains("Names[3] := 'NSFShieldProxyRecovery.exe';") &&
                  un.Contains("ProxyRecovery.HelperFile") && File.ReadAllText(Path.Combine(Repo, @"src\Core\Updater.cs")).Contains("ProxyRecovery.HelperFile"), "");
        }

        // ============================================================================ 4. the service transaction

        /// <summary>A scripted SCM: one service whose state the test can change at any call.</summary>
        sealed class Scm7 : IServiceControl
        {
            public ServiceInfo Cur = new ServiceInfo { Read = ScmRead.NotFound };
            public bool CreateResult = true, StartResult = true, DeleteResult = true;
            public Action OnCreate, OnStart;
            public readonly List<string> Calls = new List<string>();
            static ServiceInfo Copy(ServiceInfo i) => new ServiceInfo { Exists = i.Exists, Read = i.Read, Status = i.Status, StartType = i.StartType, ImagePath = i.ImagePath, Owned = i.Owned };
            public ServiceInfo Query(string n) { Calls.Add("query"); return Copy(Cur); }
            public bool Stop(string n, TimeSpan w) { Calls.Add("stop"); if (Cur.Exists) Cur.Status = ServiceControllerStatus.Stopped; return true; }
            public bool Start(string n, TimeSpan w) { Calls.Add("start"); OnStart?.Invoke(); if (StartResult && Cur.Exists) Cur.Status = ServiceControllerStatus.Running; return StartResult; }
            public bool SetStartType(string n, ServiceStartMode m) { Calls.Add("starttype"); if (Cur.Exists) Cur.StartType = m; return Cur.Exists; }
            public bool Create(string n, string bin, string d, out string o)
            {
                Calls.Add("create"); o = CreateResult ? "" : "create failed";
                OnCreate?.Invoke();
                if (CreateResult) Cur = new ServiceInfo { Exists = true, ImagePath = bin, StartType = ServiceStartMode.Automatic, Owned = EngineKind.GoodbyeDpi };
                return CreateResult;
            }
            public bool Configure(string n, string bin, out string o) { Calls.Add("config"); o = ""; if (!Cur.Exists) return false; Cur.ImagePath = bin; Cur.StartType = ServiceStartMode.Automatic; return true; }
            public bool SetCommand(string n, string bin, out string o) { Calls.Add("setcommand"); o = ""; if (!Cur.Exists) return false; Cur.ImagePath = bin; return true; }
            public bool Delete(string n, out string o) { Calls.Add("delete"); o = DeleteResult ? "" : "delete failed"; if (DeleteResult) Cur = new ServiceInfo { Read = ScmRead.NotFound }; return DeleteResult; }
        }

        static void Txn7(Action<string, bool, string> Check)
        {
            string bin = "\"" + Engines.GoodbyeDpi.ExePath + "\" -9", old = "\"" + Engines.GoodbyeDpi.ExePath + "\" -5", foreign = "\"C:\\Other\\tool.exe\" --run";
            // a failed create while somebody else creates a service of that name: it is never taken for ours
            var s1 = new Scm7 { CreateResult = false };
            s1.OnCreate = () => s1.Cur = new ServiceInfo { Exists = true, ImagePath = foreign, Status = ServiceControllerStatus.Running, StartType = ServiceStartMode.Automatic };
            var r1 = ServiceStart.Run(s1, "NSFShield", bin, false, null);
            Check("service: a service that appears during a failed create is left alone (no stop, no delete, no start type change)",
                  !r1.Ok && r1.RolledBack == null && r1.Error?.Key == "engine.serviceAppeared" && !s1.Calls.Contains("stop") && !s1.Calls.Contains("delete") &&
                  !s1.Calls.Contains("starttype") && s1.Cur.ImagePath == foreign && s1.Cur.Running, string.Join(",", s1.Calls));
            // access denied / query error before the change: nothing is changed
            foreach (var read in new[] { ScmRead.AccessDenied, ScmRead.Error })
            {
                var s2 = new Scm7 { Cur = new ServiceInfo { Read = read } };
                var r2 = ServiceStart.Run(s2, "NSFShield", bin, true, null);
                Check("service: " + read + " before the change refuses it (not taken for 'not found'; no create, config or start)",
                      !r2.Ok && r2.Error?.Key == "engine.serviceUnreadable" && s2.Calls.All(c => c == "query"), string.Join(",", s2.Calls));
            }
            // the identity changed before the rollback: the service is not stopped, reconfigured or retyped again
            var s3 = new Scm7 { Cur = new ServiceInfo { Exists = true, ImagePath = old, StartType = ServiceStartMode.Manual, Status = ServiceControllerStatus.Stopped, Owned = EngineKind.GoodbyeDpi }, StartResult = false };
            s3.OnStart = () => s3.Cur.ImagePath = foreign;
            var r3 = ServiceStart.Run(s3, "NSFShield", bin, false, null);
            int at = s3.Calls.LastIndexOf("start");
            Check("service: a rollback re-reads the service first – changed by somebody else, it is left as it is (no stop, command or start type change)",
                  !r3.Ok && r3.RolledBack == false && s3.Cur.ImagePath == foreign && !s3.Calls.Skip(at + 1).Any(c => c == "stop" || c == "setcommand" || c == "starttype" || c == "delete"),
                  string.Join(",", s3.Calls) + " / " + r3.RollbackDetail);
            // an existing service that is gone during the rollback is never a successful restore
            var s4 = new Scm7 { Cur = new ServiceInfo { Exists = true, ImagePath = old, StartType = ServiceStartMode.Automatic, Status = ServiceControllerStatus.Running, Owned = EngineKind.GoodbyeDpi }, StartResult = false };
            s4.OnStart = () => s4.Cur = new ServiceInfo { Read = ScmRead.NotFound };
            var r4 = ServiceStart.Run(s4, "NSFShield", bin, false, null);
            Check("service: a service that existed before and is gone now is not a successful rollback", !r4.Ok && r4.RolledBack == false, r4.RollbackDetail);
            // a created service whose delete fails while the SCM cannot be read: not "removed"
            var s5 = new Scm7 { StartResult = false, DeleteResult = false };
            var r5 = ServiceStart.Run(s5, "NSFShield", bin, false, null);
            Check("service: a created service that could not be deleted is not reported as rolled back", !r5.Ok && r5.RolledBack == false, r5.RollbackDetail);
            // control: a service this attempt created and that failed is removed and reported as rolled back
            var s6 = new Scm7 { StartResult = false };
            var r6 = ServiceStart.Run(s6, "NSFShield", bin, false, null);
            Check("service: a service created by the failed attempt is removed (its identity checked first)", !r6.Ok && r6.RolledBack == true && s6.Cur.Missing && s6.Calls.Contains("delete"), string.Join(",", s6.Calls));
        }

        // ============================================================================ 4. closing processes by handle

        static void Proc7(Action<string, bool, string> Check)
        {
            string ping = Path.Combine(Environment.SystemDirectory, "PING.EXE");
            var p = Process.Start(new ProcessStartInfo(ping, "-n 60 127.0.0.1") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true });
            try
            {
                bool left = !ProcReader.TerminateIf(p.Id, path => false, out string why1) && !p.HasExited;
                Check("process: a process whose path is not this installation's is left running (read through the closing handle)", left, why1);
                bool closed = ProcReader.TerminateIf(p.Id, path => ProcReader.IsFile(path, ping), out string why2);
                p.WaitForExit(3000);
                Check("process: the exact exe (long form and physical path) is closed", closed && p.HasExited, why2 ?? "");
                // an id that cannot belong to a process (multiple of 4 above any real one); the predicate refuses everything anyway
                Check("process: a process id that runs nothing is not closed", !ProcReader.TerminateIf(0x7FFFFFFC, path => false, out string why3), why3);
                Check("process: the physical path check refuses another file", !ProcReader.IsFile(ping, Path.Combine(Environment.SystemDirectory, "notepad.exe")) &&
                      ProcReader.IsUnder(ping, Environment.SystemDirectory) && !ProcReader.IsUnder(ping, Path.GetTempPath()), "");
            }
            finally { try { if (!p.HasExited) p.Kill(); } catch { } p.Dispose(); }
        }

        // ============================================================================ 4. B11: a service that runs another engine of this folder

        static void B11_7(Action<string, bool, string> Check, string root)
        {
            string repo = Repo;   // read before App.BaseDir is pointed at the package below
            // the service view: unreadable, another installation's, this folder's with another program
            var oldScm = Engine.Scm; var oldGuard = Engine.FreshGuard; var oldBase = App.BaseDir; var oldData = App.DataDir;
            try
            {
                var f = new Scm7 { Cur = new ServiceInfo { Read = ScmRead.AccessDenied } };
                Engine.Scm = f;
                var t1 = Engine.CheckServiceTarget();
                f.Cur = new ServiceInfo { Exists = true, ImagePath = "\"C:\\Other\\goodbyedpi.exe\" -9", Owned = null };
                var t2 = Engine.CheckServiceTarget();
                string pkg = Path.Combine(repo, @"build\package\NSF Shield");
                if (Directory.Exists(pkg))
                {
                    App.BaseDir = pkg;
                    App.DataDir = Path.Combine(root, "b11 data");
                    Directory.CreateDirectory(App.DataDir);
                    var prof = Profiles.BuiltIns.First(x => x.Engine == EngineKind.GoodbyeDpi);
                    string otherCmd = "\"" + Path.Combine(pkg, @"bin\old\goodbyedpi.exe") + "\" -9 --blacklist \"" + Path.Combine(pkg, @"data\lists\include.txt") + "\"";
                    f.Cur = new ServiceInfo { Exists = true, ImagePath = otherCmd, Owned = EngineKind.GoodbyeDpi, StartType = ServiceStartMode.Manual, Status = ServiceControllerStatus.Stopped };
                    var t3 = Engine.CheckServiceTarget();
                    App.Settings.TargetedMode = true; App.Settings.TargetDomains = new List<string> { "discord.com" };
                    Engine.FreshGuard = () => (true, "");
                    bool ok = App.Engine.RepointStoppedService(prof, out var err);
                    Check("b11: the service view tells unreadable, another installation's and this folder's service of another program apart",
                          t1 == Engine.ServiceTarget.Unknown && t2 == Engine.ServiceTarget.Foreign && t3 == Engine.ServiceTarget.NeedsRepoint, t1 + " " + t2 + " " + t3);
                    Check("b11: a stopped service gets the verified command with data\\lists and stays stopped with its start type; never a general start",
                          ok && !f.Cur.Running && f.Cur.StartType == ServiceStartMode.Manual && !f.Cur.ImagePath.Contains(@"bin\old\") &&
                          f.Cur.ImagePath.Contains(Path.Combine(App.DataDir, "lists")) && File.Exists(Path.Combine(App.DataDir, @"lists\" + Hostlists.IncludeName)) &&
                          !f.Calls.Contains("start"), err?.English + " / " + f.Cur.ImagePath);
                    f.Cur.Status = ServiceControllerStatus.Running;
                    Check("b11: a running service is never 'repointed while stopped' (it is restarted by the owner rule instead)", !App.Engine.RepointStoppedService(prof, out _), "");
                    string mf = File.ReadAllText(Path.Combine(repo, @"src\UI\MainForm.cs")), ac = File.ReadAllText(Path.Combine(repo, @"src\Core\Actions.cs"));
                    Check("b11: the automatic step runs without a general takeover and reports a failed repoint",
                          mf.Contains("repointOk = await Actions.RepointServiceAsync();") && mf.Contains("if (repointed && !repointOk)") &&
                          ac.Contains("App.Engine.Start(p, takeOver: false) && Engine.CheckServiceTarget() == Engine.ServiceTarget.ThisFolder"), "");
                }
                else Check("b11: the package folder for the repoint test exists (a full build)", false, pkg);
            }
            finally
            {
                Engine.Scm = oldScm; Engine.FreshGuard = oldGuard; App.BaseDir = oldBase; App.DataDir = oldData;
                App.Settings.TargetedMode = false; App.Settings.TargetDomains = new List<string>();
            }
        }

        // ============================================================================ 4. B13: the scan reservation

        static void B13_7(Action<string, bool, string> Check)
        {
            var host = new FakeHost();
            var req = ScanRequest.Create(ScanScope.AllEngines, ScanMode.FullBenchmark, false, new[] { Profiles.BuiltIns[0].Id }, T3);
            var cts = new CancellationTokenSource();
            cts.Cancel();
            var o1 = RunScan(req, host, cts.Token);
            Check("b13: a scan cancelled before it starts records and pauses nothing and is not reported as busy",
                  o1.Cancelled && !o1.Busy && host.Captures == 0 && host.Suspends == 0 && !ScanGate.Busy, "");
            var host2 = new FakeHost();
            Check("b13: a user operation is accepted", ScanGate.TryBeginUser(), "");
            var cts2 = new CancellationTokenSource();
            var task = Task.Run(() => new Scanner(req, host2).RunAsync(cts2.Token));
            Thread.Sleep(200);
            cts2.Cancel();
            var o2 = task.GetAwaiter().GetResult();
            ScanGate.EndUser();
            Check("b13: a scan cancelled while it waits for the user's operation pauses nothing (zero Suspend) and is not reported as busy",
                  o2.Cancelled && !o2.Busy && host2.Captures == 0 && host2.Suspends == 0 && !ScanGate.Busy, "");
            // a profile selection: the settings write happens inside one reservation; a scan cannot take the engine in between
            int ops = -1; bool scanGot = false;
            Action probe = () => { ops = ScanGate.UserOps; var t = ScanGate.TryAcquire(); if (t != null) { scanGot = true; ScanGate.Release(t); } };
            var sel = App.Settings.SelectedProfileId;
            var other = Profiles.BuiltIns.First(p => p.Id != sel);
            App.StatusChanged += probe;
            try { Task.Run(() => Actions.SelectProfileAsync(other)).GetAwaiter().GetResult(); }
            finally { App.StatusChanged -= probe; }
            Check("b13: a profile selection writes the settings inside a reservation (no scan can take the engine meanwhile)",
                  ops == 1 && !scanGot && App.Settings.SelectedProfileId == other.Id && ScanGate.UserOps == 0, "ops " + ops);
            var token = ScanGate.TryAcquire();
            try
            {
                int saves = SettingsStore.SaveRequests;
                Task.Run(() => Actions.SelectProfileAsync(Profiles.BuiltIns[0])).GetAwaiter().GetResult();
                bool applied = Task.Run(() => Actions.ApplyProfileAsync(Profiles.BuiltIns[0])).GetAwaiter().GetResult();
                Check("b13: while a scan owns the engine, a selection or an apply changes no setting", !applied && App.Settings.SelectedProfileId == other.Id && SettingsStore.SaveRequests == saves, "");
            }
            finally { ScanGate.Release(token); }
            App.Settings.SelectedProfileId = sel;
            string eng = File.ReadAllText(Path.Combine(Repo, @"src\Core\Engine.cs"));
            int ar = eng.IndexOf("void TryAutoRestart()", StringComparison.Ordinal);
            Check("b13: the automatic restart takes part in the reservation (and never takes over)",
                  ar > 0 && eng.IndexOf("ScanGate.TryBeginUser()", ar, StringComparison.Ordinal) > ar && eng.IndexOf("Start(prof, takeOver: false)", ar, StringComparison.Ordinal) > ar, "");
        }

        // ============================================================================ 5. paths and the setup package's folder check

        static void Paths7(Action<string, bool, string> Check, string root)
        {
            // a folder of this test with a deny entry for the current user (inherited by its file); removed again below
            string denied = Path.Combine(root, "denied"), deniedFile = Path.Combine(denied, "f.txt");
            Directory.CreateDirectory(denied); File.WriteAllText(deniedFile, "x");
            var me = System.Security.Principal.WindowsIdentity.GetCurrent().User;
            var rule = new System.Security.AccessControl.FileSystemAccessRule(me, System.Security.AccessControl.FileSystemRights.ReadAttributes | System.Security.AccessControl.FileSystemRights.ListDirectory,
                System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Deny);
            var acl = Directory.GetAccessControl(denied); acl.AddAccessRule(rule); Directory.SetAccessControl(denied, acl);
            PathSafety.Kind deniedKind;
            try { deniedKind = PathSafety.Reparse(deniedFile); }
            finally { var acl2 = Directory.GetAccessControl(denied); acl2.RemoveAccessRule(rule); Directory.SetAccessControl(denied, acl2); }
            Check("paths: a path that cannot be read is Unreadable (never taken for 'not there'); a missing one is None",
                  deniedKind == PathSafety.Kind.Unreadable && PathSafety.Reparse(Path.Combine(root, "missing")) == PathSafety.Kind.None &&
                  PathSafety.Reparse(@"C:\a|b") == PathSafety.Kind.Unreadable, deniedKind.ToString());
            string longDir = Path.Combine(root, "a long folder name for eight three");
            Directory.CreateDirectory(longDir);
            var sb = new StringBuilder(1024);
            string shortDir = GetShortPathNameW(longDir, sb, 1024) > 0 ? sb.ToString() : longDir;
            Check("paths: the long form of a path that does not exist yet expands its existing parent",
                  string.Equals(PathSafety.LongPath(Path.Combine(shortDir, @"missing\x.txt")), Path.Combine(longDir, @"missing\x.txt"), StringComparison.OrdinalIgnoreCase), shortDir);
            // the setup package's check, run as the program itself (exit codes 0 / 1 / 2 / 3)
            string self = Process.GetCurrentProcess().MainModule.FileName;
            int Cli(string dir, out string reason)
            {
                string rep = Path.Combine(root, "check-" + Guid.NewGuid().ToString("N").Substring(0, 6) + ".txt");
                var p = Process.Start(new ProcessStartInfo(self, "--check-install-dir \"" + dir + "\" \"" + rep + "\"") { UseShellExecute = false, CreateNoWindow = true });
                p.WaitForExit(60000);
                reason = File.Exists(rep) ? File.ReadAllText(rep) : "";
                return p.ExitCode;
            }
            string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            int c1 = Cli(Path.Combine(pf, "NSF Shield self-test absent " + Guid.NewGuid().ToString("N").Substring(0, 6)), out string w1);
            int c2 = Cli(root, out string w2);
            string file = Path.Combine(root, "a file.txt"); File.WriteAllText(file, "x");
            int c3 = Cli(file, out string w3);
            // an existing folder this account cannot read: a subfolder of the deny-entry folder (its attributes cannot be read
            // through the folder either). This holds for an elevated account such as a CI runner too, where a system folder like
            // System Volume Information is readable.
            string deniedSub = Path.Combine(denied, "sub");
            Directory.CreateDirectory(deniedSub);
            int c4; string w4;
            var acl3 = Directory.GetAccessControl(denied); acl3.AddAccessRule(rule); Directory.SetAccessControl(denied, acl3);
            try { c4 = Cli(deniedSub, out w4); }
            finally { var acl4 = Directory.GetAccessControl(denied); acl4.RemoveAccessRule(rule); Directory.SetAccessControl(denied, acl4); }
            Check("setup check: a folder that does not exist yet under a protected parent is 'absent' (1) – a first installation",
                  c1 == InstallGuard.SetupAbsent, c1 + " " + w1);
            Check("setup check: a folder other accounts can write to is unsafe (2), a file is unsafe (2)", c2 == InstallGuard.SetupUnsafe && c3 == InstallGuard.SetupUnsafe, c2 + " " + w2 + " / " + c3);
            Check("setup check: an existing path that cannot be read is 'unreadable' (3), never 'absent'", c4 == InstallGuard.SetupUnreadable, c4 + " " + w4);
            string inst = Path.Combine(root, "junction target");
            Directory.CreateDirectory(inst);
            string link = Path.Combine(root, "junction to it");
            if (MakeJunction(link, inst))
            {
                int c5 = Cli(Path.Combine(link, "NSF Shield"), out string w5);
                Check("setup check: a folder behind a junction is unsafe (2)", c5 == InstallGuard.SetupUnsafe, c5 + " " + w5);
            }
        }

        // ============================================================================ 5. the installer switch

        static void Switch7(Action<string, bool, string> Check, string root)
        {
            string inst = Path.Combine(root, "switch installed"), data = Path.Combine(inst, "data"), src = Path.Combine(root, "switch portable data");
            Directory.CreateDirectory(data); Directory.CreateDirectory(src);
            File.WriteAllText(Path.Combine(data, "settings.xml"), "<AppSettings />");
            File.WriteAllText(Path.Combine(src, "history.csv"), "time;kind\n");
            string outside = Path.Combine(root, "outside secret.txt");
            File.WriteAllText(outside, "secret");
            bool hl = CreateHardLinkW(Path.Combine(src, "history.csv.link"), outside, IntPtr.Zero);
            bool refusedLink = false;
            if (hl) try { using (InstallerSwitch.OpenPlain(Path.Combine(src, "history.csv.link"), src, 1 << 20)) { } } catch (InvalidDataException) { refusedLink = true; }
            Check("switch: a source with a second hard link is refused (a planted link to another file is never copied)", !hl || refusedLink, hl ? "" : "(no hard links here)");
            bool refusedExisting = false;
            try { InstallerSwitch.WriteNew(Path.Combine(data, "settings.xml"), data, s => s.WriteByte(1), replace: false); } catch (IOException) { refusedExisting = true; }
            Check("switch: a new file is never written over an existing one unless it is a plain file of the folder", refusedExisting && File.ReadAllText(Path.Combine(data, "settings.xml")) == "<AppSettings />", "");
            var s0 = new AppSettings(); s0.Normalize();
            string target = InstallerSwitch.Transfer(s0, inst, src);
            Check("switch: the settings, the before-switch backup and the history are written as new files (unique temporary names), nothing left behind",
                  File.Exists(target) && File.ReadAllText(target + ".before-switch") == "<AppSettings />" && File.ReadAllText(Path.Combine(data, "history.csv")) == "time;kind\n" &&
                  !Directory.GetFiles(data, "*.tmp").Any() && SettingsStore.ReadFile(target) != null, "");
            string isrc = File.ReadAllText(Path.Combine(Repo, @"src\Core\InstallerSwitch.cs"));
            Check("switch: the temporary settings file is created with CreateNew under a unique name", isrc.Contains("new FileStream(tmp, FileMode.CreateNew") && !isrc.Contains("target + \".tmp\""), "");
        }

        // ============================================================================ 5. the ZIP update

        static void Zip7(Action<string, bool, string> Check, string root)
        {
            string Make(string name, string oldExe)
            {
                string t = Path.Combine(root, name);
                string srcDir = Path.Combine(t, @"data\update\v9"), dstDir = t;
                Directory.CreateDirectory(Path.Combine(srcDir, @"bin\x86_64"));
                Directory.CreateDirectory(Path.Combine(dstDir, @"bin\x86_64"));
                File.WriteAllText(Path.Combine(srcDir, "NSFShield.exe"), "new");
                File.WriteAllText(Path.Combine(srcDir, @"bin\x86_64\goodbyedpi.exe"), "new-gdpi");
                File.WriteAllText(Path.Combine(dstDir, "NSFShield.exe"), oldExe);
                File.WriteAllText(Path.Combine(dstDir, @"bin\x86_64\goodbyedpi.exe"), "old-gdpi");
                return t;
            }
            string a = Make("zip no manifest", "old");
            int rc = Updater.Apply(Path.Combine(a, @"data\update\v9"), a, 999999, "3.0.0", false, false);
            Check("zip: the current protocol refuses a package folder without its trusted manifest (nothing copied)", rc == 1 && File.ReadAllText(Path.Combine(a, "NSFShield.exe")) == "old", "rc " + rc);
            // a file changed after the manifest was written: refused before anything is copied
            string b = Make("zip changed", "old");
            string srcB = Path.Combine(b, @"data\update\v9");
            Updater.WriteManifest(Updater.ManifestPath(srcB), Updater.HashTree(srcB));
            File.WriteAllText(Path.Combine(srcB, @"bin\x86_64\goodbyedpi.exe"), "tampered");
            rc = Updater.Apply(srcB, b, 999999, "3.0.0", false, false);
            Check("zip: a package file changed after it was verified is refused (target untouched)", rc == 1 && File.ReadAllText(Path.Combine(b, @"bin\x86_64\goodbyedpi.exe")) == "old-gdpi", "rc " + rc);
            // the bytes written are checked against the expected hash (not against the source read again)
            var copy = typeof(Updater).GetMethod("CopyDir", BindingFlags.Static | BindingFlags.NonPublic);
            string c = Path.Combine(root, "zip copy"); Directory.CreateDirectory(Path.Combine(c, "from")); File.WriteAllText(Path.Combine(c, @"from\x.bin"), "abc");
            var wrong = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["x.bin"] = new string('0', 64) };
            bool threw = false;
            try { copy.Invoke(null, new object[] { Path.Combine(c, "from"), Path.Combine(c, "to"), null, (Action<string>)(l => { }), null, wrong, "" }); }
            catch (TargetInvocationException ex) when (ex.InnerException is IOException) { threw = true; }
            Check("zip: a copy is checked against the manifest hash; a mismatch is never written into place", threw && !File.Exists(Path.Combine(c, @"to\x.bin")), "");
            // a hard link in the target is replaced, never written through
            string d = Make("zip hard link", "old");
            string outside = Path.Combine(root, "zip outside.txt"); File.WriteAllText(outside, "outside");
            File.Delete(Path.Combine(d, @"bin\x86_64\goodbyedpi.exe"));
            bool hl = CreateHardLinkW(Path.Combine(d, @"bin\x86_64\goodbyedpi.exe"), outside, IntPtr.Zero);
            string srcD = Path.Combine(d, @"data\update\v9");
            Updater.WriteManifest(Updater.ManifestPath(srcD), Updater.HashTree(srcD));
            rc = Updater.Apply(srcD, d, 999999, "3.0.0", false, false);
            Check("zip: a target file with a second hard link is replaced, the other file is never changed", !hl || (rc == 0 && File.ReadAllText(outside) == "outside" &&
                  File.ReadAllText(Path.Combine(d, @"bin\x86_64\goodbyedpi.exe")) == "new-gdpi"), "rc " + rc);
            // rollback: a folder the update added that holds a user's file is kept and the result is a recovery error
            string e = Path.Combine(root, "zip rollback"), bak = Path.Combine(e, "bak"), dst = Path.Combine(e, "dst");
            Directory.CreateDirectory(bak); Directory.CreateDirectory(Path.Combine(dst, "newdir"));
            File.WriteAllText(Path.Combine(bak, "NSFShield.exe"), "old"); File.WriteAllText(Path.Combine(dst, "NSFShield.exe"), "new");
            File.WriteAllText(Path.Combine(dst, @"newdir\added.txt"), "added"); File.WriteAllText(Path.Combine(dst, @"newdir\user.txt"), "the user's");
            var lines = new List<string>();
            bool intact = Updater.RestoreBackup(bak, dst, new List<string> { Path.Combine(dst, "newdir") + "\\", Path.Combine(dst, @"newdir\added.txt") }, l => lines.Add(l));
            Check("zip: a rollback that cannot empty a folder the update added is a recovery error; the user's file is never deleted",
                  !intact && File.Exists(Path.Combine(dst, @"newdir\user.txt")) && File.ReadAllText(Path.Combine(dst, "NSFShield.exe")) == "old", string.Join(" | ", lines));
            Directory.Delete(Path.Combine(dst, "newdir"), true);
            File.WriteAllText(Path.Combine(dst, "stray.dll"), "not in the backup");
            lines.Clear();
            intact = Updater.RestoreBackup(bak, dst, new List<string>(), l => lines.Add(l));
            Check("zip: after the rollback the managed file set must be exactly the previous one (an extra file is kept and reported)",
                  !intact && File.Exists(Path.Combine(dst, "stray.dll")), string.Join(" | ", lines));
            File.Delete(Path.Combine(dst, "stray.dll"));
            intact = Updater.RestoreBackup(bak, dst, new List<string>(), l => lines.Add(l));
            Check("zip: a complete rollback is verified as the previous file set", intact, string.Join(" | ", lines));
        }

        // ============================================================================ 5. the targeted mode scope

        static void Scope7(Action<string, bool, string> Check)
        {
            var z = Engines.Get(EngineKind.Zapret);
            var lists = new ListBinding { Include = @"C:\L\include.txt", Exclude = @"C:\L\exclude.txt" };
            var inc = new ListBinding { Include = @"C:\L\include.txt" };
            var exc = new ListBinding { Exclude = @"C:\L\exclude.txt" };
            List<List<string>> Sections(string args) => Engines.Tokens(args).Aggregate(new List<List<string>> { new List<string>() }, (acc, t) => { if (t == "--new") acc.Add(new List<string>()); else acc.Last().Add(t); return acc; });
            var own = new Profile { Engine = EngineKind.Zapret, EngineArgs = "--wf-tcp=443 --wf-udp=443 --filter-tcp=443 --hostlist=" + Hostlists.IncludeName + " --dpi-desync=fake --new --filter-udp=443 --dpi-desync=fake" };
            var s1 = Sections(z.BuildArgs(own, inc));
            Check("scope zapret: one rule placing its own include list never exempts the other rules (each rule gets the target list)",
                  s1.Count == 2 && s1.All(sec => sec.Count(t => t == "--hostlist=" + inc.Include) == 1), string.Join(" || ", s1.Select(x => string.Join(" ", x))));
            var discord = Profiles.BuiltIns.First(p => p.Id == "zapret-discord");
            var s2 = Sections(z.BuildArgs(discord, inc));
            var notes = z.ScopeNotes(discord, inc, out bool blocked);
            Check("scope zapret: in targeted mode a rule without host names (Discord voice) is left out – never run for all traffic – and its capture filter stays",
                  s2.Count == 3 && !s2.Any(sec => sec.Contains("--filter-l7=discord,stun")) && s2[0].Contains("--wf-udp=443,50000-50100") &&
                  s2.All(sec => sec.Contains("--hostlist=" + inc.Include)) && !blocked && notes.Any(n => n.Key == "lists.targetedRulesLeftOut"), string.Join(" || ", s2.Select(x => string.Join(" ", x))));
            var voice = new Profile { Engine = EngineKind.Zapret, EngineArgs = "--wf-udp=50000-50100 --filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake" };
            z.ScopeNotes(voice, inc, out bool blocked2);
            Check("scope zapret: targeted mode that would leave no rule stops the start (fail-closed)", blocked2, "");
            var s3 = Sections(z.BuildArgs(discord, exc));
            var notes3 = z.ScopeNotes(discord, exc, out _);
            Check("scope zapret: the exclude list goes into every rule with host names (also next to the profile's own lists); rules without host names are reported",
                  s3.Where(sec => !sec.Contains("--filter-l7=discord,stun")).All(sec => sec.Contains("--hostlist-exclude=" + exc.Exclude)) && notes3.Any(n => n.Key == "lists.excludePartial"), "");
            Check("scope zapret: the command preview and the start use the same plan (same rules, only the file names differ)",
                  Sections(z.BuildArgs(discord, ListBinding.Display(true, false), true)).Count == s2.Count, "");
            var b = Engines.Get(EngineKind.ByeDpi);
            var bp = new Profile { Engine = EngineKind.ByeDpi, EngineArgs = "--hosts " + Hostlists.IncludeName + " --split 1+s --auto=torst --disorder 3+s" };
            string a1 = b.BuildArgs(bp, lists);
            var t1 = Engines.CommandTokens(a1);
            int autoTorst = t1.IndexOf("torst");
            Check("scope byedpi: one group placing its own include list never exempts the other groups; the excluded hosts come first; every other host gets a last group without methods",
                  t1.Take(8).SequenceEqual(new[] { "--ip", "127.0.0.1", "--port", ByeDpiNet.SocksPort.ToString(), "--hosts", lists.Exclude, "--auto", "none" }) &&
                  autoTorst > 0 && t1[autoTorst + 1] == "--hosts" && t1[autoTorst + 2] == lists.Include && t1.Skip(t1.Count - 2).SequenceEqual(new[] { "--auto", "none" }), a1);
            var empty = new Profile { Engine = EngineKind.ByeDpi, EngineArgs = "--auto=torst --split 1+s" };
            var t2 = Engines.CommandTokens(b.BuildArgs(empty, inc));
            Check("scope byedpi: an empty group is never dropped – it gets the target list too",
                  t2.Count >= 6 && t2[4] == "--hosts" && t2[5] == inc.Include && t2.IndexOf("torst") > 5, string.Join(" ", t2));
        }

        // ============================================================================ 6. settings saving

        static void Settings7(Action<string, bool, string> Check, string root)
        {
            string path = Path.Combine(root, "settings7.xml");
            var good = new AppSettings(); good.Normalize();
            Check("settings: a normal save works and reads back", SettingsStore.SaveTo(good, path) && SettingsStore.ReadFile(path) != null, "");
            byte[] before = File.ReadAllBytes(path);
            var big = new AppSettings(); big.Normalize();
            big.CustomProfiles.Add(new Profile { Engine = EngineKind.Zapret, Name = "big", EngineArgs = new string('a', (int)(SettingsStore.MaxFileBytes + 1024)) });
            bool saved = SettingsStore.SaveTo(big, path);
            Check("settings: a file larger than the read limit (16 MiB) is never put in place – the previous settings stay and the caller gets false",
                  !saved && File.ReadAllBytes(path).SequenceEqual(before) && !Directory.GetFiles(root, "settings7.xml.*.tmp").Any(), "");
            var tasks = Enumerable.Range(0, 8).Select(i => Task.Run(() => { var s = new AppSettings(); s.Normalize(); s.WatchMinutes = i; return SettingsStore.SaveTo(s, path); })).ToArray();
            Task.WaitAll(tasks);
            Check("settings: eight parallel saves – one writer at a time, each replaced in one step, the file reads back, no temporary file left",
                  tasks.All(t => t.Result) && SettingsStore.ReadFile(path) != null && !Directory.GetFiles(root, "settings7.xml.*.tmp").Any(), "");
        }

        // ============================================================================ 6. the support package

        static void Support7(Action<string, bool, string> Check, string root)
        {
            var oldData = App.DataDir;
            var s = App.Settings;
            try
            {
                App.DataDir = Path.Combine(root, "support data");
                Directory.CreateDirectory(App.DataDir);
                var p = new ProxyEntry { Id = "p-secret", Kind = ProxyKind.Http, Host = "secret-proxy.private-test.example", Port = 8443, Name = "My Secret Proxy", User = "proxyuser42" };
                s.Proxies = new List<ProxyEntry> { p };
                s.ProxyApps = new List<ProxyApp> { new ProxyApp { Id = "a1", Name = "SecretApp", ExePath = @"D:\Tools\SecretApp\SecretApp.exe", ProxyId = p.Id } };
                var r = new ProxyTestResult { Ok = true, TotalMs = 120, ExitIp = "203.0.113.9", Country = "TR" };
                File.WriteAllLines(App.LogFile, new[]
                {
                    "2026-11-22 12:00:00 [Info] " + ProxyTools.TestLogLine(p, r),
                    "2026-11-22 12:00:01 [Info] Started SecretApp with proxy secret-proxy.private-test.example:8443 (user proxyuser42)",
                    "2026-11-22 12:00:02 [Warn] NSF-805 SECRET-PROXY.PRIVATE-TEST.EXAMPLE did not answer",
                }, Encoding.UTF8);
                File.WriteAllText(Path.Combine(App.DataDir, "history.csv"), "time;note\n2026-11-22;proxy secret-proxy.private-test.example ok\n", Encoding.UTF8);
                string zip = Path.Combine(root, "support7.zip");
                Support.CreatePackage(zip);
                var leaks = new List<string>();
                string log = "";
                using (var za = ZipFile.OpenRead(zip))
                    foreach (var e in za.Entries)
                    {
                        string text;
                        using (var rd = new StreamReader(e.Open(), Encoding.UTF8)) text = rd.ReadToEnd();
                        if (e.FullName == "app-log.txt") log = text;
                        foreach (var secret in new[] { "secret-proxy", "private-test", "My Secret Proxy", "proxyuser42", "SecretApp", "203.0.113.9" })
                            if (text.IndexOf(secret, StringComparison.OrdinalIgnoreCase) >= 0) leaks.Add(e.FullName + ": " + secret);
                    }
                Check("support: a real package – no saved proxy host (a made-up DNS name), name or user, no program rule name or path in any text entry, app-log.txt included",
                      leaks.Count == 0 && log.Contains("Proxy #1") && log.Contains("App #1"), string.Join("; ", leaks));
            }
            finally
            {
                App.DataDir = oldData;
                s.Proxies = new List<ProxyEntry>(); s.ProxyApps = new List<ProxyApp>();
            }
        }

        // ============================================================================ 5. the setup package script (compiled by the build; not run here)

        static string Between(string s, string from, string to)
        {
            int a = s.IndexOf(from, StringComparison.Ordinal);
            int b = a < 0 ? -1 : s.IndexOf(to, a, StringComparison.Ordinal);
            return a < 0 || b < 0 ? "" : s.Substring(a, b - a);
        }

        static void Iss7(Action<string, bool, string> Check)
        {
            string iss = File.ReadAllText(Path.Combine(Repo, @"installer\NSFShield.iss"));
            string code = iss.Substring(iss.IndexOf("[Code]", StringComparison.Ordinal));
            Check("setup: no script host anywhere in the setup script (processes closed with the Win32 API by their physical path)",
                  iss.IndexOf("power" + "shell", StringComparison.OrdinalIgnoreCase) < 0 && !iss.Contains("taskkill") && code.Contains("QueryFullProcessImageNameW") &&
                  code.Contains("TerminateProcess(H, 1)") && code.Contains("IsAllowedExe(Path, IncludeApp)"), "");
            Check("setup: Win32 ABI – BOOL results are LongBool, handles THandle, SERVICE_STATUS seven Cardinals, W entries with String, stdcall",
                  code.Contains("function QueryServiceStatus(Service: THandle; var Status: TServiceStatus): LongBool;") &&
                  code.Contains("function CloseServiceHandle(Handle: THandle): LongBool;") && code.Contains("function OpenProcess(Access: Cardinal; Inherit: LongBool; Pid: Cardinal): THandle;") &&
                  System.Text.RegularExpressions.Regex.Matches(Between(code, "TServiceStatus = record", "end;"), ": Cardinal;").Count == 7 &&
                  System.Text.RegularExpressions.Regex.Matches(code, @"external '([^']*)'").Cast<System.Text.RegularExpressions.Match>().All(m => m.Groups[1].Value.EndsWith(" stdcall")) &&
                  !System.Text.RegularExpressions.Regex.IsMatch(code, @"\): Boolean;\s*\r?\n\s*external"), "");
            Check("setup: the target folder is checked by the new program from the setup's temporary folder; unsafe or unreadable stops the setup before anything runs",
                  iss.Contains("DestName: \"NSFShieldSetupCheck.exe\"; Flags: dontcopy") && code.Contains("ExtractTemporaryFile('NSFShieldSetupCheck.exe')") &&
                  code.Contains("if (DirState <> DIR_PROTECTED) and (DirState <> DIR_ABSENT) then") && !code.Contains("commonpf64"), "");
            Check("setup: [Run] starts the program only from a folder verified again; no unconditional [UninstallRun]",
                  iss.Contains("Check: AppDirOk") && iss.Contains("Check: IsSilentUpdate and AppDirOk") && !iss.Contains("[UninstallRun]\r\nFilename"), "");
            Check("setup: a service that cannot be checked or stopped stops the setup; one that cannot be started again is reported (never a silent success)",
                  code.Contains("Result := CustomMessage('ServiceNotStopped');") && code.Contains("if ServiceWasRunning and not StartServiceLogged then\r\n      ReportServiceNotRestored;") &&
                  code.Contains("function StartServiceLogged: Boolean;") && code.Contains("Result := State = 4;"), "");
            Check("setup: the uninstaller runs the clean-up program only when it is exactly the installed one (locked, recorded SHA-256, its own folder check), otherwise removes it",
                  code.Contains("GetSHA256OfFile(Exe), Recorded") && code.Contains("UninstallLock := CreateFileW(Exe, GENERIC_READ, FILE_SHARE_READ") &&
                  code.Contains("Result := RunDirCheck(Exe, ExpandConstant('{app}'), Report) = DIR_PROTECTED;") && code.Contains("DeleteFile(Exe);"), "");
            Check("setup: every new text of the setup is in both languages", new[] { "UnsafeDir", "ServiceNotStopped", "ProcessesNotStopped", "ServiceNotRestored" }
                  .All(k => iss.Contains("en." + k + "=") && iss.Contains("tr." + k + "=")), "");
        }
    }
}
#endif
