using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using Microsoft.Win32;

namespace NSFShield
{
    /// <summary>
    /// The network side of the ByeDPI engine. ciadpi is a SOCKS proxy on 127.0.0.1; NSF Shield puts its local bridge in front
    /// of it (HTTP CONNECT + SOCKS5 on the next port, also on 127.0.0.1 only) and, if wanted, points the Windows proxy
    /// setting at the bridge. The Windows proxy must never stay pointed at a dead port:
    ///  - before the change a recovery record (the four values before and after, each with its existence) and a sign-in entry
    ///    are written and read back (<see cref="ProxyRecovery"/>); if that fails, the Windows proxy is not changed;
    ///  - normal stop, app exit, Windows shutdown: <see cref="Detach"/> restores the values that are still NSF Shield's;
    ///  - the app crashes or is killed: a small guard process (NSFShield.exe --proxy-guard) does the same as soon as the app is gone;
    ///  - power loss: at the next sign-in the recovery helper (bin\NSFShieldProxyRecovery.exe, asInvoker, no script host) does it
    ///    when NSF Shield is not running; the app checks it again at start.
    /// </summary>
    public static class ByeDpiNet
    {
        /// <summary>Settings.SystemProxyId while the Windows proxy points at the ByeDPI bridge (persisted before the change).</summary>
        public const string ProxyMarker = "engine:byedpi";
        public const int DefaultPort = 18980;

        public static int SocksPort
        {
            get
            {
                int p = App.Settings?.ByeDpiPort ?? DefaultPort;
                return p >= 1024 && p <= 65000 ? p : DefaultPort;
            }
        }

        public static int HttpPort => SocksPort + 1;
        public static string BridgeAddress => "127.0.0.1:" + HttpPort;

        /// <summary>The virtual proxy entry of the engine (usable in per-program rules; never saved in the proxy list).</summary>
        public static ProxyEntry Entry => new ProxyEntry
        {
            Id = ProxyMarker, Name = "ByeDPI (127.0.0.1)", Kind = ProxyKind.Socks5, Host = "127.0.0.1", Port = SocksPort, LocalPort = HttpPort,
        };

        public static bool Attached { get; private set; }
        public static bool SystemProxyActive => App.Settings?.SystemProxyId == ProxyMarker;

        /// <summary>Is there a recovery record of the ByeDPI engine (also one written before a crash)?</summary>
        static bool RecordIsOurs() => ProxyRecovery.Read()?.Owner == ProxyMarker;

        static EventWaitHandle guardStop;

        /// <summary>Is the port free on 127.0.0.1 (nothing else listens there)?</summary>
        public static bool PortFree(int port)
        {
            try
            {
                var l = new TcpListener(IPAddress.Loopback, port);
                l.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ExclusiveAddressUse, true);
                l.Start();
                l.Stop();
                return true;
            }
            catch (SocketException) { return false; }
        }

        /// <summary>Waits until something accepts connections on 127.0.0.1:port (the process must stay alive).</summary>
        public static bool WaitListening(int port, Process p, int timeoutMs)
        {
            var sw = Stopwatch.StartNew();
            while (sw.ElapsedMilliseconds < timeoutMs)
            {
                try { if (p != null && p.HasExited) return false; } catch { return false; }
                try
                {
                    using (var c = new TcpClient(AddressFamily.InterNetwork))
                    {
                        var t = c.ConnectAsync(IPAddress.Loopback, port);
                        if (t.Wait(300) && c.Connected) return true;
                    }
                }
                catch (Exception) { }
                Thread.Sleep(150);
            }
            return false;
        }

        /// <summary>
        /// Listening sockets on the port: true if every one is bound to a loopback address (127.0.0.1 / ::1) – ciadpi must never be
        /// reachable from the network.
        /// </summary>
        public static bool LoopbackOnly(int port, out string bound)
        {
            var eps = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Where(e => e.Port == port).ToList();
            bound = string.Join(", ", eps.Select(e => e.Address + ":" + e.Port));
            return eps.Count > 0 && eps.All(e => IPAddress.IsLoopback(e.Address));
        }

        /// <summary>
        /// After ciadpi listens: opens the bridge, routes the app's own tests through it and, unless it is a scan (quiet) or the
        /// user turned it off, points the Windows proxy at it. Returns problems that do not stop protection.
        /// </summary>
        public static List<(string Code, LocText Text)> Attach(bool quiet)
        {
            var warn = new List<(string, LocText)>();
            if (!ProxyBridge.Ensure(Entry, out string err)) { warn.Add(("NSF-808", new LocText("engine.raw", err))); return warn; }
            NetTest.EngineProxy = new WebProxy("http://" + BridgeAddress);
            Attached = true;
            if (quiet || !App.Settings.ByeDpiSystemProxy) return warn;
            var s = App.Settings;
            var cur = ProxyTools.CurrentSystem();
            if (!string.IsNullOrEmpty(s.SystemProxyId) && s.SystemProxyId != ProxyMarker && cur.Enabled)
            {
                // the user's own proxy is set as the Windows proxy: do not replace it silently
                warn.Add(("NSF-809", new LocText("engines.byedpi.systemProxyBusy", cur.Server)));
                return warn;
            }
            try
            {
                ApplySystem();
                StartGuard();
            }
            catch (Exception ex)
            {
                warn.Add(("NSF-809", new LocText("engines.byedpi.systemProxyFailed", ex.Message)));
            }
            return warn;
        }

        /// <summary>Undoes everything <see cref="Attach"/> did (safe to call more than once).</summary>
        public static void Detach()
        {
            try
            {
                if (SystemProxyActive || RecordIsOurs()) RestoreOwned("stop");
            }
            catch (Exception ex) { App.Log("Windows proxy could not be restored: " + ex.Message, LogLevel.Warn); }
            StopGuard();
            try { ProxyBridge.Stop(ProxyMarker); } catch (Exception ign) { App.Ignored("ByeDPI bridge could not be stopped", ign); }
            NetTest.EngineProxy = null;
            Attached = false;
        }

        /// <summary>Saves the settings with the proxy marker (the self-test replaces it to simulate a failed save).</summary>
        internal static Func<bool> Persist = () => App.TrySave();

        /// <summary>
        /// The sign-in entry of the recovery helper, after the helper was checked (a plain file in bin with its embedded SHA-256;
        /// the self-test replaces it). Null with the reason when it is missing or changed: then the Windows proxy is not changed.
        /// </summary>
        internal static Func<(string Command, string Error)> Helper = () =>
        {
            string path = Path.Combine(App.BaseDir, "bin", ProxyRecovery.HelperFile);
            using (var hold = Integrity.VerifyAndLock(new[] { (ProxyRecovery.HelperFile, path) }, out string err))
                return hold == null ? (null, err) : (ProxyRecovery.HelperCommand(path), null);
        };

        static void ApplySystem()
        {
            var s = App.Settings;
            // the recovery is prepared and read back before Windows is changed (record, sign-in entry, settings marker); if any
            // step fails, the Windows proxy is not touched at all
            var (helper, helperErr) = Helper();
            if (helper == null) throw new IOException(Loc.T("engines.byedpi.recoveryMissing", helperErr));
            var live = ProxyRecovery.Live();
            if (live == null) throw new IOException(Loc.T("proxy.sys.unreadable"));
            var rec = new ProxyRecord { Owner = ProxyMarker, AtSignIn = true, Backup = live, Written = ProxyRecovery.For(BridgeAddress, ProxyTools.LocalBypass) };
            if (!ProxyRecovery.Arm(rec, helper, out string armErr)) throw new IOException(Loc.T("proxy.sys.notPrepared", armErr));
            string oldId = s.SystemProxyId;
            s.SystemProxyId = ProxyMarker;
            if (!Persist())
            {
                s.SystemProxyId = oldId;
                ProxyRecovery.Drop();
                throw new IOException(Loc.T("engines.byedpi.backupNotSaved"));
            }
            if (!ProxyRecovery.WriteLive(rec.Written, out string writeErr))
            {
                // a failed write in the middle: NSF Shield's own values go back at once (the record stays if that fails too)
                var back = ProxyRecovery.Restore(ProxyRecovery.Read() ?? rec);
                if (back.Outcome != ProxyRecovery.Outcome.Failed) { s.SystemProxyId = oldId ?? ""; Persist(); }
                App.Log("Windows proxy could not be set (" + writeErr + "); undo: " + back, LogLevel.Warn);
                throw new IOException(Loc.T("proxy.sys.writeFailed", writeErr));
            }
            ProxyTools.NotifyChanged();
            App.Log("Windows proxy set to the ByeDPI bridge: " + BridgeAddress, LogLevel.Success);
        }

        public enum RestoreResult { Restored, UserChanged, Failed }

        /// <summary>
        /// The one restore path of the ByeDPI proxy (stop, crash guard, app start, upgrade, uninstall; the sign-in helper runs the
        /// same <see cref="ProxyRecovery.Restore"/>): the values still NSF Shield's go back, the user's are kept. The record and the
        /// sign-in entry are removed only after the restore was read back; on a failure they stay for the next attempt.
        /// </summary>
        public static RestoreResult RestoreOwned(string reason)
        {
            var s = App.Settings;
            var rec = ProxyRecovery.Read();
            if (rec == null)
            {
                // nothing recorded any more (e.g. the sign-in helper restored it): only the marker goes
                if (s.SystemProxyId == ProxyMarker) { s.SystemProxyId = ""; App.TrySave(); }
                return RestoreResult.UserChanged;
            }
            var res = ProxyRecovery.Restore(rec);
            if (res.Outcome == ProxyRecovery.Outcome.Failed)
            {
                App.Log("The Windows proxy could not be restored exactly (" + reason + "): " + res.Error + "; the recovery record is kept.", LogLevel.Warn);
                return RestoreResult.Failed;
            }
            if (s.SystemProxyId == rec.Owner || s.SystemProxyId == ProxyMarker) s.SystemProxyId = "";
            App.TrySave();
            ProxyTools.NotifyChanged();
            if (res.Outcome == ProxyRecovery.Outcome.UserKept)
                App.Log("Windows proxy restored (" + reason + "); values changed by the user were kept: " + string.Join(", ", res.KeptNames) + ".", LogLevel.Info);
            else App.Log("Windows proxy setting restored (" + reason + ").", LogLevel.Info);
            return res.Outcome == ProxyRecovery.Outcome.Restored ? RestoreResult.Restored : RestoreResult.UserChanged;
        }

        /// <summary>
        /// Called with the periodic status check: while the Windows proxy is set for ByeDPI, a change of the proxy itself by the
        /// user (another server, proxy turned off) is noticed at once: NSF Shield's remaining values go back and its record and
        /// sign-in entry are dropped, so a later restore can never overwrite the user's own proxy. A changed exception list or
        /// configuration script alone keeps the record (those values are the user's and stay at the restore).
        /// </summary>
        public static void CheckOwnership()
        {
            var s = App.Settings;
            if (s == null || s.SystemProxyId != ProxyMarker) return;
            var rec = ProxyRecovery.Read();
            if (rec == null || rec.Owner != ProxyMarker) return;
            var live = ProxyRecovery.Live();
            if (live == null || ProxyRecovery.ProxyStillOurs(rec, live)) return;
            RestoreOwned("the Windows proxy was changed");
        }
        static string GuardEventName(int pid) => @"Local\NSFShield_ProxyGuard_" + pid;

        /// <summary>Starts the guard process (not in the kill-on-close job, so it outlives a crash of the app).</summary>
        static void StartGuard()
        {
            if (App.Preview) return;
            try
            {
                int me = Process.GetCurrentProcess().Id;
                StopGuard();
                guardStop = new EventWaitHandle(false, EventResetMode.ManualReset, GuardEventName(me));
                var psi = new ProcessStartInfo(Process.GetCurrentProcess().MainModule.FileName, "--proxy-guard " + me + " " + HttpPort)
                {
                    UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = App.BaseDir,
                };
                using (Process.Start(psi)) { }
            }
            catch (Exception ex) { App.Log("The proxy guard could not be started (the next start of the app restores the proxy): " + ex.Message, LogLevel.Warn); }
        }

        static void StopGuard()
        {
            try { guardStop?.Set(); guardStop?.Dispose(); } catch (Exception ign) { App.Ignored("Proxy guard could not be stopped", ign); }
            guardStop = null;
        }

        /// <summary>
        /// At app start: the last result of the sign-in helper goes to the log (value names only), and a recovery record that is
        /// not complete (it cannot be used safely) is removed without touching the live setting, so a new one can be prepared.
        /// </summary>
        public static void StartupCheck()
        {
            string last = ProxyRecovery.ReadText(ProxyRecovery.RecordKey, "ProxyRecoveryLast");
            if (last != null)
            {
                App.Log("Proxy recovery at sign-in: " + ArgPolicy.CleanText(last, 300), LogLevel.Info);
                ProxyRecovery.WriteText(ProxyRecovery.RecordKey, "ProxyRecoveryLast", null);
            }
            if (ProxyRecovery.RecordPresent && ProxyRecovery.Read() == null)
            {
                App.Log("The proxy recovery record is not complete; it was removed and the Windows proxy was left as it is.", LogLevel.Warn);
                ProxyRecovery.Drop();
            }
        }

        /// <summary>
        /// Did the Windows proxy stay pointed at our bridge although ByeDPI no longer runs (crash, kill, power loss)? Then the
        /// previous setting is restored. Called at app start, by the guard and before an upgrade.
        /// </summary>
        public static bool RecoverStale(string reason)
        {
            var s = App.Settings;
            if (s == null || Attached) return false;
            if (!RecordIsOurs() && (s.SystemProxyId != ProxyMarker || ProxyRecovery.Read() != null)) return false;
            try
            {
                var r = RestoreOwned(reason);
                if (r == RestoreResult.Restored) App.Log("The Windows proxy still pointed at the ByeDPI bridge (" + reason + "); the previous setting was restored.", LogLevel.Warn);
                return r == RestoreResult.Restored;
            }
            catch (Exception ex)
            {
                // the record stays (marker, backup, sign-in entry): the next start tries again
                App.Log("The Windows proxy could not be restored (" + reason + "): " + ex.Message, LogLevel.Error);
                return false;
            }
        }

        /// <summary>--proxy-guard &lt;app pid&gt; &lt;bridge port&gt;: waits for the app (or a clean stop) and restores the proxy if needed.</summary>
        public static int GuardMain(string[] args)
        {
            int i = Array.IndexOf(args, "--proxy-guard");
            if (i < 0 || args.Length < i + 3 || !int.TryParse(args[i + 1], out int pid) || !int.TryParse(args[i + 2], out int port)) return 2;
            Process app;
            try { app = Process.GetProcessById(pid); } catch { app = null; }
            EventWaitHandle stop;
            try { stop = EventWaitHandle.OpenExisting(GuardEventName(pid)); } catch { stop = null; }
            if (app != null)
            {
                using (var appWait = new ManualResetEvent(false))
                {
                    appWait.SafeWaitHandle = new Microsoft.Win32.SafeHandles.SafeWaitHandle(app.Handle, false);
                    var handles = stop != null ? new WaitHandle[] { appWait, stop } : new WaitHandle[] { appWait };
                    int which = WaitHandle.WaitAny(handles);
                    if (which == 1) return 0;   // stopped cleanly; the app restored the proxy itself
                }
            }
            // the app is gone: is there still a recovery record of the ByeDPI engine?
            try
            {
                if (!RecordIsOurs()) return 0;
                App.Settings = SettingsStore.Load();
                RecoverStale("the app closed unexpectedly");
            }
            catch (Exception ex) { App.Log("Proxy guard: " + ex.Message, LogLevel.Warn); return 1; }
            return 0;
        }
    }
}
