using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NSFShield
{
    /// <summary>Does a service command line run an engine of this installation? (Only then the scan may stop and start it.)</summary>
    public static class ServiceOwnership
    {
        /// <summary>The exe of a service command line ("C:\x y\a.exe" args, or C:\x\a.exe args); null if it cannot be read.</summary>
        public static string ExeOf(string imagePath)
        {
            if (string.IsNullOrWhiteSpace(imagePath)) return null;
            string cmd = imagePath.Trim();
            if (cmd.StartsWith("\"")) { int e = cmd.IndexOf('"', 1); return e > 1 ? cmd.Substring(1, e - 1) : null; }
            int x = cmd.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            return x > 0 ? cmd.Substring(0, x + 4) : null;
        }

        /// <summary>
        /// The engine whose exe (in this installation's bin folder) the service runs; null for anything else. Both paths are
        /// compared in their long form, so an 8.3 short name in the service command still matches.
        /// </summary>
        public static EngineKind? OwnedEngine(string imagePath)
        {
            string exe = ExeOf(imagePath);
            if (exe == null) return null;
            try { Path.GetFullPath(exe); } catch { return null; }
            foreach (var e in Engines.All)
                if (PathSafety.Same(exe, e.ExePath)) return e.Kind;
            return null;
        }

        /// <summary>
        /// The strict form for removing an entry (uninstall): the exe must exist and its physical final path must be the
        /// final path of an engine of this installation. If either cannot be read, the owner is unknown (null).
        /// </summary>
        public static EngineKind? OwnedEngineVerified(string imagePath)
        {
            var k = OwnedEngine(imagePath);
            if (k == null) return null;
            string exe = ExeOf(imagePath);
            string a = PathSafety.FinalPath(exe), b = PathSafety.FinalPath(Engines.Get(k.Value).ExePath);
            return a != null && b != null && string.Equals(a, b, StringComparison.OrdinalIgnoreCase) ? k : null;
        }
    }

    /// <summary>The SCM view of a service (replaceable in tests).</summary>
    public interface IServiceControl
    {
        ServiceInfo Query(string name);
        bool Stop(string name, TimeSpan wait);
        bool Start(string name, TimeSpan wait);
        bool SetStartType(string name, ServiceStartMode mode);
        /// <summary>Creates the service (automatic start) with this command line; false with the tool's message.</summary>
        bool Create(string name, string binPath, string displayName, out string output);
        /// <summary>Sets the command line (and automatic start) of an existing service.</summary>
        bool Configure(string name, string binPath, out string output);
        /// <summary>Restores an earlier command line exactly as it was read (the start type is set separately).</summary>
        bool SetCommand(string name, string binPath, out string output);
        bool Delete(string name, out string output);
    }

    /// <summary>
    /// One change of this installation's service as a transaction: the state before it (existence, command line, start type,
    /// running) is read first and must be known (not found, or read; an access error or a failed query refuses the change).
    /// A rollback acts only on what this transaction is proven to have done – a service it created (its create call succeeded)
    /// or an existing one it reconfigured – and re-reads the service's identity (its command line is still the one this
    /// transaction wrote) before every stop, delete or start type change; a service that changed hands meanwhile, or one
    /// that appeared during a failed create, is left alone. A service that existed before and is gone now is never a
    /// successful restore.
    /// </summary>
    public sealed class ServiceTxn
    {
        readonly IServiceControl scm;
        readonly string name;
        public readonly ServiceInfo Before;
        /// <summary>This transaction's create call succeeded (only then the service is its own to delete).</summary>
        public bool Created { get; private set; }
        /// <summary>This transaction reconfigured the existing service (the call succeeded or the SCM shows its command line).</summary>
        public bool Changed { get; private set; }
        /// <summary>A failed create, and a service of that name exists now: it is somebody else's (never removed).</summary>
        public bool ForeignAppeared { get; private set; }
        public bool Touched => Created || Changed;
        string applied;

        ServiceTxn(IServiceControl scm, string name) { this.scm = scm; this.name = name; Before = scm.Query(name); }

        public static ServiceTxn Begin(IServiceControl scm, string name) => new ServiceTxn(scm, name);

        /// <summary>The state before the change is known (an existing service that was read, or one that is known to be missing).</summary>
        public bool Readable => Before.Exists ? !Before.Unknown : Before.Missing;

        static bool SameCommand(ServiceInfo s, string bin) =>
            s != null && s.Exists && !s.Unknown && string.Equals((s.ImagePath ?? "").Trim(), (bin ?? "").Trim(), StringComparison.OrdinalIgnoreCase);

        /// <summary>Creates the service or points the existing one at <paramref name="binPath"/> (automatic start).</summary>
        public bool Apply(string binPath, string displayName, out string output)
        {
            output = "";
            if (!Readable) { output = "SCM: " + Before.Read; return false; }
            applied = binPath;
            if (Before.Exists)
            {
                bool ok = scm.Configure(name, binPath, out output);
                Changed = ok || SameCommand(scm.Query(name), binPath);
                return ok;
            }
            bool created = scm.Create(name, binPath, displayName, out output);
            Created = created;
            if (!created && scm.Query(name).Exists) ForeignAppeared = true;
            return created;
        }

        /// <summary>Did the SCM keep exactly this command line?</summary>
        public bool Verify(string binPath) => SameCommand(scm.Query(name), binPath);

        /// <summary>Undoes the change and checks the SCM afterwards; true when the service is as it was before.</summary>
        public bool Rollback(out string detail)
        {
            detail = "";
            if (!Touched) return true;
            var now = scm.Query(name);
            if (Created)
            {
                if (now.Missing) return true;
                if (!SameCommand(now, applied)) { detail = now.Unknown ? "SCM: " + now.Read : "the service no longer has the command line of this attempt; it is left as it is"; return false; }
                scm.Stop(name, TimeSpan.FromSeconds(15));
                var again = scm.Query(name);
                if (again.Missing) return true;
                if (!SameCommand(again, applied)) { detail = "the service changed while it was being removed; it is left as it is"; return false; }
                if (!scm.Delete(name, out string o)) detail = o;
                var after = scm.Query(name);
                if (!after.Missing && detail.Length == 0) detail = after.Unknown ? "SCM: " + after.Read : "the service is still there";
                return after.Missing;
            }
            // an existing service that this transaction reconfigured
            if (!now.Exists) { detail = now.Missing ? "the service that existed before is gone" : "SCM: " + now.Read; return false; }
            if (!SameCommand(now, applied)) { detail = "the service no longer has the command line of this attempt; it is left as it is"; return false; }
            scm.Stop(name, TimeSpan.FromSeconds(15));
            if (!SameCommand(scm.Query(name), applied)) { detail = "the service changed while it was being restored; it is left as it is"; return false; }
            bool ok = scm.SetCommand(name, Before.ImagePath, out string o2);
            if (!ok) detail = o2;
            var mid = scm.Query(name);
            if (!SameCommand(mid, Before.ImagePath)) { if (detail.Length == 0) detail = "SCM: " + (mid.Exists ? mid.ImagePath : mid.Read.ToString()); return false; }
            ok &= scm.SetStartType(name, Before.StartType);
            if (Before.Running) ok &= scm.Start(name, TimeSpan.FromSeconds(20));
            var end = scm.Query(name);
            bool same = SameCommand(end, Before.ImagePath) && end.StartType == Before.StartType && end.Running == Before.Running;
            if (!same && detail.Length == 0) detail = "SCM: " + (end.ImagePath ?? "") + " · " + end.StartType + " · " + end.Status;
            return ok && same;
        }
    }

    /// <summary>
    /// Starting protection as this installation's service: create or point the service at the verified command, read it back,
    /// (re)start it and check that it keeps running. Any failure undoes the change (<see cref="ServiceTxn"/>). A service of
    /// another installation is changed only on an explicit user start (<paramref name="takeOver"/>).
    /// </summary>
    public static class ServiceStart
    {
        public sealed class Result
        {
            public bool Ok, Created;
            public LocText Error;
            public string Code = "";
            /// <summary>null: nothing had to be undone; true/false: the rollback did / did not restore the old state.</summary>
            public bool? RolledBack;
            public string RollbackDetail = "";
        }

        public static Result Run(IServiceControl scm, string name, string bin, bool takeOver, Action settle)
        {
            var res = new Result();
            var txn = ServiceTxn.Begin(scm, name);
            if (!txn.Readable)
            {
                // the state before cannot be read (access denied, query error): nothing is changed, so nothing must be undone
                res.Error = new LocText("engine.serviceUnreadable", txn.Before.Read.ToString());
                res.Code = "NSF-701";
                return res;
            }
            if (txn.Before.Exists && txn.Before.Owned == null && !takeOver)
            {
                res.Error = new LocText("engine.serviceForeign", ServiceOwnership.ExeOf(txn.Before.ImagePath) ?? "?");
                res.Code = "NSF-701";
                return res;
            }
            Result Undo(LocText err, string code)
            {
                res.Error = err;
                res.Code = code;
                if (txn.Touched)
                {
                    res.RolledBack = txn.Rollback(out string d);
                    res.RollbackDetail = d;
                }
                return res;
            }
            if (!txn.Apply(bin, "NSF Shield", out string o))
                return Undo(txn.ForeignAppeared ? new LocText("engine.serviceAppeared", o)
                          : new LocText(txn.Before.Exists ? "engine.serviceConfigFailed" : "engine.serviceCreateFailed", o), "NSF-701");
            res.Created = txn.Created;
            if (!txn.Verify(bin)) return Undo(new LocText("engine.serviceNotVerified"), "NSF-701");
            if (scm.Query(name).Running && !scm.Stop(name, TimeSpan.FromSeconds(15))) return Undo(new LocText("engine.serviceStartTimeout"), "NSF-702");
            if (!scm.Start(name, TimeSpan.FromSeconds(15))) return Undo(new LocText("engine.serviceStartTimeout"), "NSF-702");
            settle?.Invoke();
            if (!scm.Query(name).Running) return Undo(new LocText("engine.serviceStoppedAfterStart"), "NSF-702");
            res.Ok = true;
            return res;
        }
    }

    sealed class ScmControl : IServiceControl
    {
        public bool Create(string name, string binPath, string displayName, out string output)
        {
            var r = Engine.Sc("create " + name + " binPath= " + Engine.Esc(binPath) + " start= auto DisplayName= " + Engine.Esc(displayName));
            output = r.Output;
            if (r.Code == 0) Engine.Sc("failure " + name + " reset= 86400 actions= restart/5000/restart/15000/restart/60000");
            return r.Code == 0;
        }

        public bool Configure(string name, string binPath, out string output)
        {
            var r = Engine.Sc("config " + name + " binPath= " + Engine.Esc(binPath) + " start= auto");
            output = r.Output;
            return r.Code == 0;
        }

        public bool SetCommand(string name, string binPath, out string output)
        {
            var r = Engine.Sc("config " + name + " binPath= " + Engine.Esc(binPath ?? ""));
            output = r.Output;
            return r.Code == 0;
        }

        public bool Delete(string name, out string output)
        {
            var r = Engine.Sc("delete " + name);
            output = r.Output;
            return r.Code == 0;
        }

        /// <summary>
        /// The service as the SCM reports it: not found, access denied and other errors are told apart (an unreadable service is
        /// never taken for a missing one). The owner is decided by the strict rule of this installation (the exe exists and its
        /// physical final path is an engine of this folder); a command line that cannot be read makes the state unknown.
        /// </summary>
        public ServiceInfo Query(string name)
        {
            var i = new ServiceInfo();
            try
            {
                using (var sc = new ServiceController(name))
                {
                    sc.Refresh();
                    i.Status = sc.Status;
                    i.StartType = sc.StartType;
                    i.Exists = true;
                }
            }
            catch (InvalidOperationException ex)
            {
                int code = (ex.InnerException as System.ComponentModel.Win32Exception)?.NativeErrorCode ?? 0;
                if (code == 1060) return new ServiceInfo { Read = ScmRead.NotFound };   // ERROR_SERVICE_DOES_NOT_EXIST
                if (code == 5) return new ServiceInfo { Read = ScmRead.AccessDenied };
                App.Ignored("Service state could not be read", ex);
                return new ServiceInfo { Read = ScmRead.Error };
            }
            catch (Exception ign) { App.Ignored("Service state could not be read", ign); return new ServiceInfo { Read = ScmRead.Error }; }
            try { i.ImagePath = DriverControl.ImagePath(name) ?? ""; }
            catch (Exception ign)
            {
                App.Ignored("Service path could not be read", ign);
                i.Read = ex(ign);
                return i;
            }
            i.Owned = ServiceOwnership.OwnedEngineVerified(i.ImagePath);
            return i;
        }

        static ScmRead ex(Exception e) => e is UnauthorizedAccessException || e is System.Security.SecurityException ? ScmRead.AccessDenied : ScmRead.Error;

        public bool Stop(string name, TimeSpan wait)
        {
            try
            {
                using (var sc = new ServiceController(name))
                {
                    sc.Refresh();
                    if (sc.Status == ServiceControllerStatus.Stopped) return true;
                    if (sc.Status != ServiceControllerStatus.StopPending) sc.Stop();
                    sc.WaitForStatus(ServiceControllerStatus.Stopped, wait);
                    sc.Refresh();
                    return sc.Status == ServiceControllerStatus.Stopped;
                }
            }
            catch (System.ServiceProcess.TimeoutException) { return false; }
            catch (Exception ex) { App.Log("The service could not be stopped: " + ex.Message, LogLevel.Warn); return false; }
        }

        public bool Start(string name, TimeSpan wait)
        {
            try
            {
                using (var sc = new ServiceController(name))
                {
                    sc.Refresh();
                    if (sc.Status != ServiceControllerStatus.Running) { if (sc.Status == ServiceControllerStatus.Stopped) sc.Start(); sc.WaitForStatus(ServiceControllerStatus.Running, wait); }
                    sc.Refresh();
                    return sc.Status == ServiceControllerStatus.Running;
                }
            }
            catch (System.ServiceProcess.TimeoutException) { return false; }
            catch (Exception ex) { App.Log("The service could not be started: " + ex.Message, LogLevel.Warn); return false; }
        }

        public bool SetStartType(string name, ServiceStartMode mode)
        {
            string t = mode == ServiceStartMode.Automatic ? "auto" : mode == ServiceStartMode.Manual ? "demand" : mode == ServiceStartMode.Disabled ? "disabled" : null;
            return t != null && Engine.Sc("config " + name + " start= " + t).Code == 0;
        }
    }

    /// <summary>A candidate running for a scan: its own process, port, list folder, list locks and integrity lock.</summary>
    sealed class LiveTrial : ITrial
    {
        public Process Process;
        public Hostlists.Hold Lists;
        public IDisposable Files;
        public string Dir;
        public int Port;
        /// <summary>The candidate's PID as registered in <see cref="ScanTrials"/> (diagnosis: "scan candidate", not a foreign program).</summary>
        public int RegisteredPid;
        public ProbeTransport Transport { get; set; } = ProbeTransport.Direct;
        public int Pid { get { try { return Process?.Id ?? 0; } catch { return 0; } } }

        /// <summary>The candidate process still runs and – for ByeDPI – its PID still owns the trial port on 127.0.0.1.</summary>
        public bool Alive(out LocText why)
        {
            why = null;
            var p = Process;
            int pid;
            try
            {
                if (p == null || p.HasExited) { why = new LocText("scan.trial.exited"); return false; }
                pid = p.Id;
            }
            catch { why = new LocText("scan.trial.exited"); return false; }
            if (Port > 0 && !PortOwner.OwnedBy(Port, pid, out string detail)) { why = new LocText("scan.trial.portLost", Port, detail); return false; }
            return true;
        }

        public void Dispose()
        {
            var p = Process;
            Process = null;
            if (p != null)
            {
                try { if (!p.HasExited) { p.Kill(); p.WaitForExit(3000); } } catch (Exception ign) { App.Ignored("Scan candidate could not be closed", ign); }
                try { p.Dispose(); } catch { }
            }
            if (RegisteredPid > 0) { ScanTrials.Remove(RegisteredPid); RegisteredPid = 0; }
            try { Files?.Dispose(); } catch (Exception ign) { App.Ignored("Engine files could not be released", ign); }
            Files = null;
            try { Lists?.Dispose(); } catch (Exception ign) { App.Ignored("Scan lists could not be released", ign); }
            Lists = null;
            if (Dir != null)
            {
                try { Directory.Delete(Dir, true); } catch (Exception ign) { App.Ignored("Scan list folder could not be deleted", ign); }
                Dir = null;
            }
        }
    }

    /// <summary>
    /// The live side of a scan. A candidate never goes through the general start (Engine.Start with its side effects): it is
    /// validated, its files are checked against the embedded SHA-256 and kept locked, it gets its own list files and port and
    /// is started and checked for readiness the same way (<see cref="EngineLauncher"/>). Foreign goodbyedpi/winws processes,
    /// another program's service or driver and the old GoodbyeDPI service are never stopped; WinDivert candidates are skipped
    /// with the reason instead.
    /// </summary>
    public sealed class LiveScanHost : IScanHost
    {
        readonly IServiceControl scm;
        public ProbeEnv Env = new ProbeEnv();

        public LiveScanHost(IServiceControl scm = null) { this.scm = scm ?? new ScmControl(); }

        public EnvSnapshot Capture()
        {
            var s = App.Settings;
            var e = App.Engine;
            var (state, active, svc) = e.ScanState();
            return new EnvSnapshot
            {
                SelectedId = s.SelectedProfileId, LastGoodbyeDpi = s.LastGoodbyeDpiProfileId, LastZapret = s.LastZapretProfileId, LastByeDpi = s.LastByeDpiProfileId,
                State = state, ActiveProfile = active, RunningAsService = svc, ServiceModeSetting = s.ServiceMode,
                Service = scm.Query(Engine.ServiceName),
                ByeDpiAttached = ByeDpiNet.Attached, ByeDpiSystemProxy = ByeDpiNet.SystemProxyActive, SystemProxy = NetTest.SystemProxy().Server,
            };
        }

        public SuspendResult Suspend(EnvSnapshot env, object token)
        {
            var r = new SuspendResult();
            // our own WinDivert engine (app mode) is paused; a running ByeDPI stays as it is (no driver, the Windows proxy keeps a live address)
            bool ownService = env.Service.Running && env.Service.Owned != null;
            Func<bool> stopService = ownService ? () => scm.Stop(Engine.ServiceName, TimeSpan.FromSeconds(15)) : (Func<bool>)null;
            // a service of another installation is never paused (its state stays as it is; WinDivert candidates are skipped below)
            bool foreignService = env.RunningAsService && env.Service.Running && env.Service.Owned == null;
            if (env.WasActive && !env.ByeDpiAttached && !foreignService)
            {
                App.Engine.SuspendForScan(token, stopService);
                env.Suspended = true;
                r.Notes.Add(new LocText("scan.paused", env.ActiveProfile?.Name ?? ""));
            }
            else if (ownService) App.Engine.SuspendForScan(token, stopService, keepProcess: true);
            env.ServiceStopped = ownService;
            if (env.ByeDpiAttached) r.Notes.Add(new LocText("scan.byedpiKept"));

            // the SCM must confirm it: a service that is still running would conflict with every WinDivert candidate
            var now = scm.Query(Engine.ServiceName);
            if (now.Running)
            {
                r.DriverBlock = now.Owned != null ? new LocText("scan.block.serviceTimeout") : new LocText("scan.block.serviceNotOwned", Path.GetFileName(ServiceOwnership.ExeOf(now.ImagePath) ?? "?"));
                r.DriverBlockCode = "NSF-702";
            }
            // WinDivert programs that are not ours (another copy, a script, the old GoodbyeDPI service): never closed by a scan
            var foreign = new List<string>();
            foreach (var n in Engines.DriverProcessNames)
                foreach (var p in Process.GetProcessesByName(n)) using (p) foreign.Add(n + " (PID " + p.Id + ")");
            if (foreign.Count > 0 && r.DriverBlock == null)
            {
                r.DriverBlock = new LocText("scan.block.foreignProcess", string.Join(", ", foreign));
                r.DriverBlockCode = "NSF-301";
            }
            string loaded = DriverControl.LoadedFile();
            if (loaded != null && !DriverControl.DriverInFolder(loaded, App.BaseDir))
                r.Notes.Add(new LocText("scan.foreignDriver", loaded));
            return r;
        }

        public Task<bool> PretestAsync(CancellationToken ct) => Task.Run(() => NetTest.InternetOk(out _), ct);

        public Task<DnsComparison> CompareDnsAsync(string host, bool skipDoh, CancellationToken ct) => DnsComparison.CheckAsync(host, Env, ct, skipDoh);

        public Task<TargetProbe> ProbeAsync(string host, ProbeTransport via, CancellationToken ct) => NetProbe.HttpsAsync(host, via, Env, ct);

        public Task<StunResult> StunAsync(CancellationToken ct) => Stun.CheckAsync(Env, ct);

        public bool Available(Profile p, out LocText why)
        {
            var eng = Engines.Of(p);
            if (!eng.Available(out why)) return false;
            string missing = Engine.MissingFile(eng);
            if (missing != null) { why = new LocText("engine.missingFile", missing, eng.BinDir); return false; }
            return true;
        }

        public ListPlan PlanLists(Profile p, IReadOnlyList<string> targets, bool widen) => ScanLists.Plan(Engines.Of(p), App.Settings, targets, widen);

        public void FlushDns() => Native.FlushDns();

        public Task<TrialStart> StartTrialAsync(Profile p, ListPlan lists, CancellationToken ct) => Task.Run(() => StartTrial(p, lists, ct), ct);

        TrialStart StartTrial(Profile p, ListPlan plan, CancellationToken ct)
        {
            var eng = Engines.Of(p);
            var tr = new LiveTrial();
            TrialStart Fail(LocText t, string code, bool isolation = false, bool engineWide = false, bool driverWide = false)
            {
                tr.Dispose();
                return new TrialStart { Error = t, Code = code, Isolation = isolation, EngineWide = engineWide, DriverWide = driverWide };
            }
            try
            {
                // the candidate's own list files (the live data\lists files and the settings are never touched)
                var binding = new ListBinding();
                if (plan.Include != null || plan.Exclude != null)
                {
                    tr.Dir = Path.Combine(App.DataDir, "scan", Guid.NewGuid().ToString("N").Substring(0, 10));
                    try { tr.Lists = Hostlists.WriteAndHold(plan.Include, plan.Exclude, tr.Dir, out binding); }
                    catch (Exception ex) { return Fail(new LocText("scan.trial.listsFailed", ex.Message), "NSF-606"); }
                }
                // ByeDPI: its own port, never the port of a running ByeDPI or its bridge
                if (eng.ListenPort > 0)
                {
                    tr.Port = PortOwner.PickTrialPort(new[] { ByeDpiNet.SocksPort, ByeDpiNet.HttpPort });
                    if (tr.Port == 0) return Fail(new LocText("scan.trial.noPort"), "NSF-808", isolation: true);
                    binding.Port = tr.Port;
                }
                // only a driver of this installation that the candidate does not use is unloaded (never another program's)
                var dlog = new StringBuilder();
                try { DriverControl.Release(App.BaseDir, dlog, eng.UsesDriver ? eng.DriverPath : null); }
                catch (Exception ex) { dlog.AppendLine("Driver check failed: " + ex.Message); }
                if (dlog.Length > 0) App.Log("[Scan] " + dlog.ToString().Trim().Replace(Environment.NewLine, " "), LogLevel.Debug);

                string args = eng.BuildArgs(p, binding);
                App.Log("[Scan] Candidate: " + p.Name + " – " + eng.ExeName + " " + eng.BuildArgs(p, ListBinding.Display(binding.Include != null, binding.Exclude != null), true)
                        .Replace("--port " + ByeDpiNet.SocksPort, "--port " + tr.Port), LogLevel.Debug);
                // the files are verified and stay write-locked until the candidate has stopped
                tr.Files = Integrity.VerifyAndLock(Engines.BinRoot, eng.VerifiedFiles, out string intErr);
                if (tr.Files == null) return Fail(new LocText("engine.integrityFailed", intErr, eng.DisplayName), "NSF-105", engineWide: true);
                ct.ThrowIfCancellationRequested();
                string console = "";
                var lr = EngineLauncher.Launch(eng, args, tr.Port, pr => { var t = ConsoleReader.Read(pr.Id); if (t != null) console = t; return console; }, ct,
                                               started: pr => { try { tr.RegisteredPid = pr.Id; ScanTrials.Add(pr.Id); } catch { } });
                if (!lr.Ok)
                {
                    bool driver = lr.Code == "NSF-201" || lr.Code == "NSF-202" || lr.Code == "NSF-203" || lr.Code == "NSF-204" || lr.Code == "NSF-205" || lr.Code == "NSF-206";
                    return Fail(lr.Error, lr.Code, isolation: lr.Code == "NSF-808", engineWide: lr.Code == "NSF-102", driverWide: driver);
                }
                tr.Process = lr.Process;
                // the transport carries the candidate's PID: every SOCKS connection checks that this process still owns the port
                tr.Transport = eng.ListenPort > 0 ? ProbeTransport.Socks5(tr.Port, tr.Pid) : ProbeTransport.Direct;
                return new TrialStart { Trial = tr };
            }
            catch (OperationCanceledException) { tr.Dispose(); throw; }
            catch (Exception ex) { return Fail(new LocText("engine.raw", ex.Message), "NSF-601"); }
        }

        public bool Apply(Profile p, EnvSnapshot env, object token, out LocText error)
        {
            error = null;
            var s = App.Settings;
            string sel = s.SelectedProfileId;
            var (g, z, b) = (s.LastGoodbyeDpiProfileId, s.LastZapretProfileId, s.LastByeDpiProfileId);
            s.SelectedProfileId = p.Id;
            s.RememberProfile(p);
            App.Save();
            // the real apply goes through the normal start (service mode, ByeDPI → app mode, the proxy rules stay in force) but
            // never takes over: other programs' goodbyedpi/winws processes and another installation's service are left alone;
            // a failed service start undoes its own change (ServiceStart / ServiceTxn)
            bool ok = App.Engine.Start(p, false, token, takeOver: false) && App.Engine.State == EngineState.Running;
            if (ok)
            {
                App.Log("Profile selected by the scan: " + p.Name + " [" + Engines.Of(p).DisplayName + "]", LogLevel.Success);
                return true;
            }
            error = new LocText("scan.apply.failedWhy", App.Engine.LastErrorCode, App.Engine.LastError);
            s.SelectedProfileId = sel;
            s.LastGoodbyeDpiProfileId = g; s.LastZapretProfileId = z; s.LastByeDpiProfileId = b;
            App.Save();
            return false;
        }

        public RestoreReport Restore(EnvSnapshot env, object token)
        {
            var rep = new RestoreReport();
            if (env.Restored) return rep;   // safe to call again
            env.Restored = true;
            var s = App.Settings;
            if (s.SelectedProfileId != env.SelectedId || s.LastGoodbyeDpiProfileId != env.LastGoodbyeDpi || s.LastZapretProfileId != env.LastZapret || s.LastByeDpiProfileId != env.LastByeDpi)
            {
                s.SelectedProfileId = env.SelectedId;
                s.LastGoodbyeDpiProfileId = env.LastGoodbyeDpi; s.LastZapretProfileId = env.LastZapret; s.LastByeDpiProfileId = env.LastByeDpi;
                App.Save();
            }
            var e = App.Engine;
            if (env.WasActive && env.ActiveProfile != null)
            {
                var (st, act, _) = e.ScanState();
                bool same = st == EngineState.Running && act?.Id == env.ActiveProfile.Id && (!env.ByeDpiAttached || ByeDpiNet.Attached);
                bool samePath = string.Equals(scm.Query(Engine.ServiceName).ImagePath, env.Service.ImagePath, StringComparison.OrdinalIgnoreCase);
                if (env.ServiceStopped && env.Service.Owned != null && env.RunningAsService && samePath)
                {
                    // the service of this installation comes back as it was (its verified command line is not rebuilt)
                    if (scm.Start(Engine.ServiceName, TimeSpan.FromSeconds(20))) { e.Poll(); rep.Done.Add(new LocText("scan.restore.service")); }
                    else rep.Problems.Add(new LocText("scan.restore.serviceFailed"));
                }
                else if (env.ServiceStopped && env.Service.Owned != null && env.RunningAsService)
                {
                    // a failed apply rewrote the service: it is set up again from the known, validated original profile (never from a raw command line)
                    bool ok = e.Start(env.ActiveProfile, false, token, takeOver: false) && e.State == EngineState.Running;
                    if (ok) rep.Done.Add(new LocText("scan.restore.engine", env.ActiveProfile.Name));
                    else rep.Problems.Add(new LocText("scan.restore.engineFailed", env.ActiveProfile.Name, e.LastErrorCode));
                }
                else if (!same)
                {
                    bool ok = e.Start(env.ActiveProfile, !env.RunningAsService, token, takeOver: false) && e.State == EngineState.Running;
                    if (ok) rep.Done.Add(new LocText("scan.restore.engine", env.ActiveProfile.Name));
                    else rep.Problems.Add(new LocText("scan.restore.engineFailed", env.ActiveProfile.Name, e.LastErrorCode));
                }
                else rep.Done.Add(new LocText("scan.restore.kept", env.ActiveProfile.Name));
                if (env.ServiceStopped && !env.RunningAsService && env.Service.Owned != null)
                {
                    // a service that ran beside a ByeDPI app (unusual) is started again too
                    if (!scm.Start(Engine.ServiceName, TimeSpan.FromSeconds(20))) rep.Problems.Add(new LocText("scan.restore.serviceFailed"));
                }
            }
            else
            {
                // protection was off: it stays off (AutoStartProtection does not replace the state before the scan)
                if (e.IsActive || e.State == EngineState.Error) e.Stop(true);
                if (env.Service.Exists && !env.Service.Running && env.Service.Owned != null && scm.Query(Engine.ServiceName).Running)
                    scm.Stop(Engine.ServiceName, TimeSpan.FromSeconds(15));
                rep.Done.Add(new LocText("scan.restore.off"));
            }
            // the service itself is checked against the snapshot: one created by the scan is removed, a command line of this
            // installation that was changed goes back to the one read before the scan (and is read back)
            rep.Problems.AddRange(RestoreServiceConfig(scm, env));
            var now = scm.Query(Engine.ServiceName);
            if (env.Service.Exists && now.Exists)
            {
                if (env.Service.StartType != now.StartType && env.Service.Owned != null && !scm.SetStartType(Engine.ServiceName, env.Service.StartType))
                    rep.Problems.Add(new LocText("scan.restore.startTypeFailed"));
                if (env.Service.Running != now.Running)
                    rep.Problems.Add(new LocText(env.Service.Running ? "scan.restore.serviceNotRunning" : "scan.restore.serviceStillRunning"));
            }
            if (env.ByeDpiSystemProxy && !ByeDpiNet.SystemProxyActive)
                rep.Problems.Add(new LocText("scan.restore.proxyChanged"));
            return rep;
        }

        /// <summary>
        /// After a scan without an applied result: the "NSFShield" service must be as it was before the scan. A service of this
        /// installation that did not exist is removed; one whose command line differs gets the command line read before the
        /// scan (verified by reading it back). Another installation's service is never changed.
        /// </summary>
        internal static List<LocText> RestoreServiceConfig(IServiceControl scm, EnvSnapshot env)
        {
            var problems = new List<LocText>();
            var now = scm.Query(Engine.ServiceName);
            if (!now.Exists) return problems;
            if (!env.Service.Exists)
            {
                if (now.Owned == null) return problems;
                scm.Stop(Engine.ServiceName, TimeSpan.FromSeconds(15));
                if (!scm.Delete(Engine.ServiceName, out _) || scm.Query(Engine.ServiceName).Exists) problems.Add(new LocText("scan.restore.serviceCreated"));
                return problems;
            }
            if (env.Service.Owned == null || now.Owned == null) return problems;
            if (string.Equals((now.ImagePath ?? "").Trim(), (env.Service.ImagePath ?? "").Trim(), StringComparison.OrdinalIgnoreCase)) return problems;
            bool wasRunning = now.Running;
            if (wasRunning) scm.Stop(Engine.ServiceName, TimeSpan.FromSeconds(15));
            bool ok = scm.SetCommand(Engine.ServiceName, env.Service.ImagePath, out _);
            var back = scm.Query(Engine.ServiceName);
            ok &= string.Equals((back.ImagePath ?? "").Trim(), (env.Service.ImagePath ?? "").Trim(), StringComparison.OrdinalIgnoreCase);
            if (env.Service.Running) ok &= scm.Start(Engine.ServiceName, TimeSpan.FromSeconds(20));
            if (!ok) problems.Add(new LocText("scan.restore.serviceCommandFailed"));
            return problems;
        }
    }

    /// <summary>Result of starting an engine process.</summary>
    public sealed class LaunchResult
    {
        public bool Ok;
        public Process Process;
        public LocText Error;
        public string Code = "";
        public string Warning;
    }

    /// <summary>
    /// Starts an engine process and waits for it to be ready: GoodbyeDPI and winws print a message; ByeDPI must listen on
    /// 127.0.0.1 with its own process id (read from the TCP table – a successful connection alone is no proof). Shared by a
    /// normal start and a scan candidate. No window, in the kill-on-close job; cancellation closes the process.
    /// </summary>
    public static class EngineLauncher
    {
        public static LaunchResult Launch(IDpiEngine eng, string args, int listenPort, Func<Process, string> console, CancellationToken ct,
                                          EventHandler exited = null, Action<Process> started = null)
        {
            var psi = new ProcessStartInfo(eng.ExePath, args)
            {
                UseShellExecute = false,
                CreateNoWindow = true,      // no window, but a console → the output can be read
                WorkingDirectory = eng.BinDir,
            };
            var p = new Process { StartInfo = psi, EnableRaisingEvents = exited != null };
            if (exited != null) p.Exited += exited;
            try { p.Start(); }
            catch (Exception ex)
            {
                bool notFound = ex is System.ComponentModel.Win32Exception w && w.NativeErrorCode == 2;
                return new LaunchResult { Error = new LocText("engine.cannotRun", ex.Message, eng.ExeName), Code = notFound ? "NSF-102" : "NSF-601" };
            }
            Native.AttachToKillJob(p.Handle);
            started?.Invoke(p);
            LaunchResult Fail(LocText t, string code)
            {
                try { if (!p.HasExited) { p.Kill(); p.WaitForExit(2000); } } catch (Exception ign) { App.Ignored(eng.ExeName + " could not be closed", ign); }
                return new LaunchResult { Error = t, Code = code };
            }
            string text = "";
            var sw = Stopwatch.StartNew();
            try
            {
                while (sw.ElapsedMilliseconds < 8000)
                {
                    ct.ThrowIfCancellationRequested();
                    if (p.WaitForExit(250))
                    {
                        text = console?.Invoke(p) ?? text;
                        int code = -1;
                        try { code = p.ExitCode; } catch { }
                        return new LaunchResult { Error = new LocText("engine.exitedImmediately", code, Engine.Explain(eng, text), eng.DisplayName), Code = eng.Diagnose(text).Code };
                    }
                    text = console?.Invoke(p) ?? text;
                    if (listenPort > 0)
                    {
                        if (PortOwner.WaitOwned(listenPort, p, 400, ct, out string who))
                        {
                            // never reachable from the network: stop at once if it listens anywhere but 127.0.0.1
                            if (!ByeDpiNet.LoopbackOnly(listenPort, out string bound)) return Fail(new LocText("engines.byedpi.notLoopback", bound), "NSF-605");
                            return new LaunchResult { Ok = true, Process = p };
                        }
                        var others = PortOwner.Listeners(listenPort).Where(l => l.Pid != p.Id).ToList();
                        if (others.Count > 0) return Fail(new LocText("engines.byedpi.portTaken", listenPort, string.Join(", ", others)), "NSF-808");
                    }
                    else if (eng.IsReady(text)) return new LaunchResult { Ok = true, Process = p };
                    if (eng.LooksLikeError(text)) return Fail(new LocText("engine.startFailed", Engine.Explain(eng, text), eng.DisplayName), eng.Diagnose(text).Code);
                }
            }
            catch (OperationCanceledException) { Fail(null, ""); throw; }
            if (listenPort > 0) return Fail(new LocText("engines.byedpi.noListen", listenPort), "NSF-808");
            return new LaunchResult { Ok = true, Process = p, Warning = "[NSF-604] " + eng.DisplayName + " is running but its status message could not be read; assuming it works." };
        }
    }
}
