using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.ServiceProcess;
using System.Text;
using System.Threading;

namespace NSFShield
{
    public enum EngineState { Stopped, Starting, Running, Stopping, Error }

    /// <summary>
    /// Runs the bypass engine of the selected profile (<see cref="IDpiEngine"/>: GoodbyeDPI, Zapret or ByeDPI) as a process or
    /// as the Windows service. Only one engine runs at a time: every start first stops whatever ran before (process, service,
    /// ByeDPI proxy) and unloads a WinDivert driver of this folder that the new engine does not use.
    /// </summary>
    public sealed class Engine
    {
        public const string ServiceName = "NSFShield";
        /// <summary>Name of the GoodbyeDPI engine (the engine shown in the UI comes from <see cref="Current"/>).</summary>
        public const string DisplayName = "GoodbyeDPI";
        public const string LegacyServiceName = "GoodbyeDPI";

        /// <summary>The SCM used for this installation's service (the self-test replaces it with a fake).</summary>
        internal static IServiceControl Scm = new ScmControl();

        readonly object gate = new object();
        Process proc;
        IDpiEngine procEngine;
        Hostlists.Hold listHold;
        bool userStop = true;
        string consoleText = "";
        int loggedLines;
        readonly List<DateTime> restarts = new List<DateTime>();
        int polling;

        public EngineState State { get; private set; } = EngineState.Stopped;
        LocText lastError;
        /// <summary>Last error message in the current UI language ("" if none).</summary>
        public string LastError => lastError?.Text ?? "";
        public string LastErrorCode { get; private set; } = "";
        public DateTime? StartedAt { get; private set; }
        public Profile ActiveProfile { get; private set; }
        public bool RunningAsService { get; private set; }
        /// <summary>Suppresses notifications and automatic restarts during an automatic scan.</summary>
        public bool Quiet { get; set; }
        public int ExternalCount { get; private set; }
        public bool LegacyServiceExists { get; private set; }
        public bool LegacyServiceRunning { get; private set; }
        public bool ServiceInstalled { get; private set; }

        public event Action<EngineState, EngineState> StateChanged;

        public bool IsActive => State == EngineState.Running || State == EngineState.Starting;

        /// <summary>PID of the engine process this app started (0 if none): diagnosis evidence, never a name match.</summary>
        public int OwnProcessId
        {
            get { var p = proc; try { return p != null && !p.HasExited ? p.Id : 0; } catch { return 0; } }
        }
        public bool HasConflict => ExternalCount > 0 || LegacyServiceExists;

        /// <summary>The engine running now, otherwise the engine of the selected profile.</summary>
        public IDpiEngine Current => Engines.Of(IsActive && ActiveProfile != null ? ActiveProfile : App.SelectedProfile);

        // GoodbyeDPI paths (bin\x86_64 or bin\x86); the other engines: IDpiEngine.BinDir
        public static string Arch => Environment.Is64BitOperatingSystem ? "x86_64" : "x86";
        public static string BinDir => Path.Combine(App.BaseDir, "bin", Arch);
        public static string ExePath => Path.Combine(BinDir, "goodbyedpi.exe");

        // ------------------------------------------------------------------ state

        void SetState(EngineState s, LocText error = null)
        {
            var old = State;
            State = s;
            if (error != null) lastError = error;
            else if (s == EngineState.Running || s == EngineState.Stopped) { lastError = null; LastErrorCode = ""; }
            App.Post(() => StateChanged?.Invoke(old, s));
            App.RaiseStatus();
        }

        void Fail(LocText msg, string code)
        {
            StartedAt = null;
            LastErrorCode = code ?? "";
            App.Log((code != null ? "[" + code + "] " : "") + msg.English, LogLevel.Error);
            if (!string.IsNullOrEmpty(code) && !Quiet) App.Problems.Report(code, msg);
            SetState(EngineState.Error, msg);
        }

        /// <summary>Clears old engine-related problem entries (after a successful start).</summary>
        static void ClearEngineProblems()
        {
            App.Problems.ClearWhere(e => (e.Category == ErrorCatalog.CatDriver && e.Code != "NSF-207") || e.Category == ErrorCatalog.CatGoodbyeDpi ||
                                         e.Code == "NSF-102" || e.Code == "NSF-105" || e.Code == "NSF-107" || e.Code == "NSF-701" || e.Code == "NSF-702" ||
                                         e.Code == "NSF-704" || e.Code == "NSF-301" || e.Code == "NSF-302" || e.Code == "NSF-808" || e.Code == "NSF-809");
        }

        /// <summary>Files of the GoodbyeDPI engine in bin\&lt;arch&gt;.</summary>
        public static string[] RequiredFiles => new[] { "goodbyedpi.exe", "WinDivert.dll", Environment.Is64BitOperatingSystem ? "WinDivert64.sys" : "WinDivert32.sys" };

        /// <summary>First missing GoodbyeDPI file (null if all exist).</summary>
        public static string MissingFile()
        {
            foreach (var f in RequiredFiles)
                if (!File.Exists(Path.Combine(BinDir, f))) return f;
            return null;
        }

        /// <summary>First missing file of an engine, relative to bin\ (null if all exist).</summary>
        public static string MissingFile(IDpiEngine e)
        {
            foreach (var f in e.VerifiedFiles)
                if (!File.Exists(Path.Combine(Engines.BinRoot, f))) return f;
            return null;
        }

#if PREVIEW
        public void DebugSet(EngineState s, Profile p, string err = null)
        {
            ActiveProfile = p; StartedAt = s == EngineState.Running ? DateTime.Now.AddMinutes(-83) : (DateTime?)null;
            State = s; lastError = err == null ? null : new LocText("engine.raw", err);
        }
        public void DebugConflict(int ext, bool legacy) { ExternalCount = ext; LegacyServiceExists = legacy; }
#endif

        // ------------------------------------------------------------------ start / stop

        /// <summary>
        /// Starts protection with a profile. While a scan owns the engine (<see cref="ScanGate"/>) only the scan itself may start
        /// one (<paramref name="scanToken"/>); every other start is refused. <paramref name="takeOver"/> = false (the scan's
        /// restore) does not close other programs' DPI processes or the old GoodbyeDPI service.
        /// </summary>
        public bool Start(Profile p, bool forceApp = false, object scanToken = null, bool takeOver = true)
        {
            if (!ScanGate.Allows(scanToken))
            {
                App.Log("Start ignored: a scan is running (" + (p?.Name ?? "") + ").", LogLevel.Debug);
                return false;
            }
            if (App.Preview) return false;
            lock (gate)
            {
                var eng = Engines.Of(p);
                bool asService = App.Settings.ServiceMode && !forceApp;
                if (asService && !InstallGuard.IsProtected)
                {
                    // The SYSTEM service only runs from a protected (installed) folder
                    App.Log("[NSF-705] The background service cannot be used in the portable version; starting in app mode.", LogLevel.Warn);
                    App.Settings.ServiceMode = false;
                    App.Post(App.Save);
                    asService = false;
                }
                if (asService && !eng.SupportsService)
                {
                    App.Log(eng.DisplayName + " runs with the app (it sets the Windows proxy of the signed-in user); service mode is used by GoodbyeDPI and Zapret.", LogLevel.Info);
                    asService = false;
                }
                var previous = procEngine ?? (RunningAsService ? Engines.Of(ActiveProfile) : null);
                ActiveProfile = p;
                SetState(EngineState.Starting);
                userStop = true;
                // takeOver = false (a scan's apply/restore): a NSFShield service of another installation is never stopped
                StopInternal(foreignService: takeOver);
                int killed = takeOver ? KillExternalInternal(-1, -1) : 0;
                if (killed > 0) App.Log("Closed " + killed + " conflicting DPI process(es)/service(s).", LogLevel.Warn);
                if (previous != null && previous.Kind != eng.Kind) App.Log("Engine changed: " + previous.DisplayName + " → " + eng.DisplayName, LogLevel.Info);
                if (!asService && App.Settings.ServiceMode && !eng.SupportsService)
                {
                    // the service of the other engine must not start at boot – only this installation's own service (strict owner
                    // rule, read right before the change); a service of another installation or an unreadable one is left alone
                    var svc = Scm.Query(ServiceName);
                    if (svc.Exists && svc.Owned != null && svc.StartType == System.ServiceProcess.ServiceStartMode.Automatic)
                        Scm.SetStartType(ServiceName, System.ServiceProcess.ServiceStartMode.Manual);
                    else if (svc.Exists && svc.Owned == null)
                        App.Log("The NSFShield service is not this installation's (or cannot be read); its start type is left as it is.", LogLevel.Warn);
                }

                if (!eng.Available(out var why))
                {
                    Fail(why, "NSF-107");
                    return false;
                }

                // only one engine: unload a WinDivert driver of this folder that the new engine does not load itself
                var dlog = new StringBuilder();
                try { DriverControl.Release(App.BaseDir, dlog, eng.UsesDriver ? eng.DriverPath : null); }
                catch (Exception ex) { dlog.AppendLine("Driver check failed: " + ex.Message); }
                if (dlog.Length > 0) App.Log(dlog.ToString().Trim().Replace(Environment.NewLine, " "), LogLevel.Info);
                string loaded = DriverControl.LoadedFile();
                if (loaded != null && !DriverControl.DriverInFolder(loaded, App.BaseDir))
                    App.Log("A WinDivert driver of another program is loaded (" + loaded + ")" +
                            (eng.UsesDriver ? "; the engine will use it." : "; ByeDPI does not need it."), LogLevel.Warn);

                string missing = MissingFile(eng);
                if (missing != null)
                {
                    Fail(new LocText("engine.missingFile", missing, eng.BinDir), "NSF-102");
                    return false;
                }

                if (!ArgPolicy.ValidateProfile(p, out string argErr))
                {
                    Fail(new LocText("engine.unsafeProfile", p.Name, argErr), "NSF-605");
                    return false;
                }

                if (!Quiet && App.Settings.CheckDnsOnStart && p.UsesDnsRedirect) CheckDnsTarget(p);

                // domain lists: written atomically to data\lists and kept closed for writing while the engine runs. The plan is
                // the one the command preview shows (Hostlists.Resolve); a list the user turned on that cannot be written and
                // locked stops the start (fail-closed: never "all traffic" instead of the user's limit)
                ListBinding lists;
                try
                {
                    listHold = Hostlists.Prepare(eng, App.Settings, out lists, out var listWarn);
                    // what the lists cannot cover in this profile (the same plan as the command preview): targeted mode that
                    // would leave no rule stops the start; rules left out or rules the exclusions cannot reach are reported
                    var scope = eng.ScopeNotes(p, lists, out bool scopeBlocked);
                    if (scopeBlocked)
                    {
                        ReleaseLists();
                        Fail(scope[0], "NSF-606");
                        return false;
                    }
                    listWarn.AddRange(scope);
                    foreach (var w in listWarn)
                    {
                        App.Log("[NSF-606] " + w.English, LogLevel.Warn);
                        if (!Quiet) App.Problems.Report("NSF-606", w);
                    }
                    if (listWarn.Count == 0) App.Problems.Clear("NSF-606");
                }
                catch (Exception ex)
                {
                    ReleaseLists();
                    Fail(new LocText("lists.writeFailedStop", ex.Message), "NSF-606");
                    return false;
                }

                if (eng.ListenPort > 0)
                {
                    foreach (int port in new[] { eng.ListenPort, ByeDpiNet.HttpPort })
                        if (!ByeDpiNet.PortFree(port))
                        {
                            ReleaseLists();
                            Fail(new LocText("engines.byedpi.portBusy", port), "NSF-808");
                            return false;
                        }
                }

                string args = eng.BuildArgs(p, lists);
                App.Log("Starting: " + p.Name + " [" + eng.DisplayName + "]" + (asService ? " (background service)" : ""), LogLevel.Info);
                // the log gets the short form: no full paths (a portable copy may live in the user's folder)
                App.Log("Command: " + eng.ExeName + " " + eng.BuildArgs(p, ListBinding.Display(lists.Include != null, lists.Exclude != null), true), LogLevel.Debug);

                bool ok;
                // the files are verified and kept write-locked until the start has finished
                using (var hold = Integrity.VerifyAndLock(Engines.BinRoot, eng.VerifiedFiles, out string intErr))
                {
                    if (hold == null)
                    {
                        ReleaseLists();
                        Fail(new LocText("engine.integrityFailed", intErr, eng.DisplayName), "NSF-105");
                        return false;
                    }
                    ok = asService ? StartService(eng, args, takeOver) : StartProcess(eng, args);
                }
                if (!ok) { ReleaseLists(); return false; }

                if (eng.Kind == EngineKind.ByeDpi)
                {
                    var warn = ByeDpiNet.Attach(Quiet);
                    if (warn.Any(w => w.Code == "NSF-808"))
                    {
                        var w0 = warn.First(w => w.Code == "NSF-808");
                        StopInternal();
                        Fail(w0.Text, w0.Code);
                        return false;
                    }
                    foreach (var w in warn)
                    {
                        App.Log("[" + w.Code + "] " + w.Text.English, LogLevel.Warn);
                        if (!Quiet) App.Problems.Report(w.Code, w.Text);
                    }
                }

                userStop = false;
                StartedAt = DateTime.Now;
                if (App.Settings.FlushDns) Native.FlushDns();
                if (!Quiet) ClearEngineProblems();
                SetState(EngineState.Running);
                App.Log("Protection active: " + p.Name + " [" + eng.DisplayName + "]", LogLevel.Success);
                return true;
            }
        }

        void ReleaseLists()
        {
            try { listHold?.Dispose(); } catch (Exception ign) { App.Ignored("List files could not be released", ign); }
            listHold = null;
        }

        bool StartProcess(IDpiEngine eng, string args)
        {
            consoleText = "";
            loggedLines = 0;
            // the same start and readiness checks as a scan candidate (ByeDPI: its own PID must listen on 127.0.0.1)
            var r = EngineLauncher.Launch(eng, args, eng.ListenPort, pr => { ReadConsoleIntoLog(pr); return consoleText; }, CancellationToken.None, OnExited,
                                          pr => { proc = pr; procEngine = eng; RunningAsService = false; });
            if (!r.Ok)
            {
                proc = null; procEngine = null;
                Fail(r.Error, r.Code);
                return false;
            }
            if (r.Warning != null) App.Log(r.Warning, LogLevel.Warn);
            return true;
        }

        internal static bool LooksLikeGoodbyeDpiError(string t) =>
            t.Contains("Error opening filter") || t.Contains("parameter error") || t.Contains("ERROR:") ||
            t.Contains("Unknown option") || t.Contains("unknown option") || t.Contains("requires an argument");

        void ReadConsoleIntoLog(Process p)
        {
            int pid;
            try { if (p.HasExited) return; pid = p.Id; } catch { return; }
            string t = ConsoleReader.Read(pid);
            if (t == null) return;
            consoleText = t;
            var lines = t.Split('\n');
            int count = lines.Length;
            while (count > 0 && lines[count - 1].Length == 0) count--;
            for (int i = loggedLines; i < count; i++)
                if (lines[i].Trim().Length > 0) App.Log(lines[i].TrimEnd(), LogLevel.Output);
            loggedLines = Math.Max(loggedLines, count);
        }

        /// <summary>Does the target server of the DNS redirection respond? If not, the whole internet may stop.</summary>
        void CheckDnsTarget(Profile p)
        {
            var t = p.DnsTarget;
            if (t == null) return;
            if (!System.Net.IPAddress.TryParse(t.Value.Addr, out _)) return;
            var r = NetTest.TimedQuery("discord.com", t.Value.Addr, t.Value.Port, 2000);
            if (!r.Ok) r = NetTest.TimedQuery("discord.com", t.Value.Addr, t.Value.Port, 2500);
            if (r.Ok)
            {
                App.Problems.Clear("NSF-402");
                App.Log("DNS server responds: " + t.Value.Addr + ":" + t.Value.Port + " (" + r.Ms + " ms)", LogLevel.Debug);
            }
            else
            {
                App.Log("[NSF-402] DNS server does not respond: " + t.Value.Addr + ":" + t.Value.Port +
                        ". Sites may not open while protection is on; choose a profile with a different DNS.", LogLevel.Warn);
                App.Problems.Report("NSF-402", t.Value.Addr + ":" + t.Value.Port);
            }
        }

        /// <summary>Command line run by the installed service (null if none).</summary>
        public static string ServicePath(string name)
        {
            try
            {
                using (var q = new ManagementObjectSearcher("SELECT PathName FROM Win32_Service WHERE Name='" + name + "'"))
                    foreach (ManagementObject mo in q.Get())
                        using (mo) return mo["PathName"] as string;
            }
            catch (Exception ign) { App.Ignored("Service path could not be read", ign); }
            return null;
        }

        /// <summary>
        /// Does the service run another engine or one in a different (old) folder than the selected engine? Then it is set up
        /// again with the verified command and data\lists.
        /// </summary>
        public static bool ServicePointsElsewhere() => CheckServiceTarget() == ServiceTarget.NeedsRepoint;

        public enum ServiceTarget { NoService, ThisFolder, NeedsRepoint, Foreign, Unknown }

        /// <summary>
        /// The service of this installation and the selected engine: NeedsRepoint when it runs another engine of this folder;
        /// Foreign for a service of another installation (never changed); Unknown when the SCM cannot
        /// be read (never taken for "no service" or "fine").
        /// </summary>
        public static ServiceTarget CheckServiceTarget()
        {
            var s = Scm.Query(ServiceName);
            if (s.Unknown) return ServiceTarget.Unknown;
            if (!s.Exists) return ServiceTarget.NoService;
            if (s.Owned == null) return ServiceTarget.Foreign;
            var eng = Engines.Of(RepointProfile(s.Owned.Value));
            bool otherExe = !PathSafety.Same(ServiceOwnership.ExeOf(s.ImagePath), eng.ExePath);
            return otherExe ? ServiceTarget.NeedsRepoint : ServiceTarget.ThisFolder;
        }

        /// <summary>The profile a service is set up again with: the selected one if its engine runs as a service, else the last one of the service's engine.</summary>
        public static Profile RepointProfile(EngineKind serviceEngine)
        {
            var sel = App.SelectedProfile;
            if (Engines.Of(sel).SupportsService) return sel;
            var all = Profiles.ForEngine(App.AllProfiles, serviceEngine).ToList();
            return all.FirstOrDefault(x => x.Id == App.Settings.LastProfileId(serviceEngine)) ?? all.FirstOrDefault() ?? sel;
        }

        /// <summary>
        /// A STOPPED service of this installation gets the verified command of <paramref name="p"/> with data\lists (written
        /// first) and keeps being stopped, with its start type as before. Transactional (<see cref="ServiceTxn"/>); true only when
        /// the SCM shows the new command, the service is still stopped, its start type is unchanged and the list files exist.
        /// </summary>
        public bool RepointStoppedService(Profile p, out LocText error)
        {
            error = null;
            lock (gate)
            {
                var eng = Engines.Of(p);
                var before = Scm.Query(ServiceName);
                if (!before.Exists || before.Unknown || before.Owned == null || before.Running || !eng.SupportsService)
                { error = new LocText("engine.repointRefused"); return false; }
                var (guardOk, guardWhy) = FreshGuard();
                if (!guardOk) { error = new LocText("engine.serviceInstalledOnly", guardWhy); return false; }
                if (!ArgPolicy.ValidateProfile(p, out string argErr)) { error = new LocText("engine.unsafeProfile", p.Name, argErr); return false; }
                ListBinding lists;
                Hostlists.Hold hold;
                try { hold = Hostlists.Prepare(eng, App.Settings, out lists, out _); }
                catch (Exception ex) { error = new LocText("lists.writeFailedStop", ex.Message); return false; }
                var scope = eng.ScopeNotes(p, lists, out bool scopeBlocked);
                if (scopeBlocked) { hold.Dispose(); error = scope[0]; return false; }
                using (hold)
                using (var files = Integrity.VerifyAndLock(Engines.BinRoot, eng.VerifiedFiles, out string intErr))
                {
                    if (files == null) { error = new LocText("engine.integrityFailed", intErr, eng.DisplayName); return false; }
                    string bin = "\"" + eng.ExePath + "\" " + eng.BuildArgs(p, lists);
                    var txn = ServiceTxn.Begin(Scm, ServiceName);
                    bool ok = txn.Apply(bin, "NSF Shield", out string o) && txn.Verify(bin);
                    // Configure sets an automatic start: the start type the service had stays
                    if (ok && Scm.Query(ServiceName).StartType != before.StartType) ok = Scm.SetStartType(ServiceName, before.StartType);
                    var now = Scm.Query(ServiceName);
                    bool listsThere = (lists.Include == null || File.Exists(lists.Include)) && (lists.Exclude == null || File.Exists(lists.Exclude));
                    ok = ok && now.Exists && !now.Running && now.StartType == before.StartType && txn.Verify(bin) && listsThere;
                    if (!ok)
                    {
                        bool back = txn.Rollback(out string d);
                        error = new LocText("engine.repointFailed", o + (back ? "" : " / " + d));
                        return false;
                    }
                }
                App.Log("The stopped service was set up again for this folder (data\\lists); it stays stopped.", LogLevel.Info);
                return true;
            }
        }

        static int SafeExitCode(Process p)
        {
            try { return p.ExitCode; } catch { return -1; }
        }

        /// <summary>Extracts the error code and a short explanation from GoodbyeDPI's output.</summary>
        public static (string Code, LocText Hint) Diagnose(string output)
        {
            string t = output ?? "";
            if (t.Contains("were not found"))
                return ("NSF-202", new LocText("engine.hint.driverFilesMissing"));
            if (t.Contains("incompatible version"))
                return ("NSF-206", new LocText("engine.hint.incompatible"));
            if (t.Contains("blocked by security software"))
                return ("NSF-204", new LocText("engine.hint.blockedByAv"));
            if (t.Contains("Base Filtering Engine"))
                return ("NSF-205", new LocText("engine.hint.bfe"));
            if (t.Contains("digital signature"))
                return ("NSF-203", new LocText("engine.hint.signature"));
            if (t.Contains("parameter error") || t.Contains("nknown option") || t.Contains("requires an argument") || t.Contains("Usage:"))
                return ("NSF-603", new LocText("engine.hint.parameters"));
            if (t.Contains("Error opening filter") || t.Contains("WinDivert"))
                return ("NSF-201", new LocText("engine.hint.driverLoad"));
            return ("NSF-601", new LocText("engine.hint.generic"));
        }

        /// <summary>GoodbyeDPI: the hint and the last lines of the output.</summary>
        public static LocText Explain(string output) => Explain(Engines.GoodbyeDpi, output);

        public static LocText Explain(IDpiEngine eng, string output)
        {
            string t = output ?? "";
            var hint = eng.Diagnose(t).Hint;
            string last = string.Join(" | ", t.Split('\n').Select(l => l.Trim())
                .Where(l => l.Length > 0 && !l.StartsWith("GoodbyeDPI") && !l.StartsWith("http") && !l.StartsWith("github version") &&
                            !l.StartsWith("we have ") && !l.StartsWith("windivert filter"))
                .Reverse().Take(3).Reverse());
            return last.Length > 0 ? new LocText("engine.hintWithOutput", hint, last) : hint;
        }

        void OnExited(object sender, EventArgs e)
        {
            lock (gate)
            {
                if (!ReferenceEquals(sender, proc)) return;
                var p = proc;
                var eng = procEngine ?? Engines.GoodbyeDpi;
                proc = null; procEngine = null;
                int code = SafeExitCode(p);
                if (userStop) return;
                RunningAsService = false;
                if (eng.Kind == EngineKind.ByeDpi) ByeDpiNet.Detach();   // the Windows proxy must not point at a dead port
                ReleaseLists();
                Fail(new LocText("engine.exitedUnexpectedly", code, Explain(eng, consoleText), eng.DisplayName), "NSF-602");
                TryAutoRestart();
            }
        }

        void TryAutoRestart()
        {
            if (!App.Settings.AutoRestart || Quiet || ActiveProfile == null) return;
            var now = DateTime.Now;
            restarts.RemoveAll(t => (now - t).TotalMinutes > 5);
            if (restarts.Count >= 3)
            {
                App.Log("Automatic restart limit reached (3 attempts in 5 minutes). Please check the log.", LogLevel.Warn);
                return;
            }
            restarts.Add(now);
            var prof = ActiveProfile;
            App.Log("Restarting automatically in 5 seconds…", LogLevel.Warn);
            ThreadPool.QueueUserWorkItem(_ =>
            {
                Thread.Sleep(5000);
                // the automatic restart takes part in the same protocol as a user start: accepted only while no scan owns the
                // engine, and until it has finished no scan can record the state
                if (!ScanGate.TryBeginUser()) { App.Log("Automatic restart skipped: a scan owns the engine.", LogLevel.Debug); return; }
                try
                {
                    bool go;
                    lock (gate) go = State == EngineState.Error && proc == null && !Quiet;
                    if (go) Start(prof, takeOver: false);
                }
                finally { ScanGate.EndUser(); }
            });
        }

        public void Stop(bool quiet = false)
        {
            if (App.Preview) return;
            lock (gate)
            {
                userStop = true;
                bool wasActive = State != EngineState.Stopped;
                if (wasActive) SetState(EngineState.Stopping);
                StopInternal();
                StartedAt = null;
                if (App.Settings.FlushDns) Native.FlushDns();
                SetState(EngineState.Stopped);
                if (wasActive && !quiet) App.Log("Protection stopped.", LogLevel.Info);
            }
        }

        /// <summary>The state a scan records before it starts (read under the engine lock).</summary>
        public (EngineState State, Profile Active, bool Service) ScanState()
        {
            lock (gate) return (State, ActiveProfile, RunningAsService);
        }

        /// <summary>
        /// Pauses the own engine for a scan: closes the own process (unless <paramref name="keepProcess"/>: a running ByeDPI stays)
        /// and runs <paramref name="stopService"/> (the scan stops this installation's service through the SCM and checks it).
        /// Foreign processes and services are never touched here.
        /// </summary>
        public void SuspendForScan(object token, Func<bool> stopService, bool keepProcess = false)
        {
            if (!ScanGate.Allows(token)) return;
            if (App.Preview) { stopService?.Invoke(); return; }
            lock (gate)
            {
                userStop = true;
                if (!keepProcess)
                {
                    if (ByeDpiNet.Attached) ByeDpiNet.Detach();
                    if (proc != null)
                    {
                        var p = proc;
                        proc = null; procEngine = null;
                        try { if (!p.HasExited) { p.Kill(); p.WaitForExit(3000); } } catch (Exception ign) { App.Ignored("Engine could not be closed", ign); }
                    }
                    ReleaseLists();
                }
                if (stopService != null)
                {
                    if (!stopService()) App.Log("The service did not stop in time (scan).", LogLevel.Warn);
                    RunningAsService = false;
                }
                if (!keepProcess)
                {
                    StartedAt = null;
                    SetState(EngineState.Stopped);
                }
            }
        }

        /// <summary>
        /// Stops whatever engine runs (process, service, the ByeDPI proxy) and releases the list files. The "NSFShield" service is
        /// stopped only when its command line runs an engine of this installation – or when <paramref name="foreignService"/>
        /// is set (an explicit start by the user, a reset or the removal of a service in an unsafe folder).
        /// </summary>
        void StopInternal(bool foreignService = false)
        {
            if (ByeDpiNet.Attached) ByeDpiNet.Detach();
            if (proc != null)
            {
                var p = proc;
                var eng = procEngine;
                proc = null; procEngine = null;
                try { if (!p.HasExited) { p.Kill(); p.WaitForExit(3000); } } catch (Exception ign) { App.Ignored((eng?.ExeName ?? "engine") + " could not be closed", ign); }
            }
            var svc = Scm.Query(ServiceName);
            if (svc.Running)
            {
                if (svc.Owned != null || foreignService)
                {
                    if (!Scm.Stop(ServiceName, TimeSpan.FromSeconds(15))) App.Log("The service did not stop in time.", LogLevel.Warn);
                }
                else App.Log("The NSFShield service runs a program of another installation; it is left running: " + (ServiceOwnership.ExeOf(svc.ImagePath) ?? "?"), LogLevel.Warn);
            }
            RunningAsService = false;
            ReleaseLists();
        }

        /// <summary>
        /// Stops WinDivert engines that do not belong to the app (GoodbyeDPI / winws: two of them conflict), the old service,
        /// and ciadpi copies of this folder left over from a crash.
        /// </summary>
        int KillExternalInternal(int keepPid1, int keepPid2)
        {
            int n = 0;
            try
            {
                using (var sc = new ServiceController(LegacyServiceName))
                {
                    if (sc.Status != ServiceControllerStatus.Stopped)
                    {
                        App.Log("Stopping the old 'GoodbyeDPI' service…", LogLevel.Warn);
                        sc.Stop();
                        sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(10));
                        n++;
                    }
                }
            }
            catch (InvalidOperationException) { }
            catch (Exception ex) { App.Log("The old service could not be stopped: " + ex.Message, LogLevel.Warn); }

            // the conflicting WinDivert tools (an explicit start by the user takes over): the exe name is read again through the
            // handle that closes the process, so a reused process id is never hit
            foreach (var pe in ProcReader.ByNames(Engines.DriverProcessNames))
            {
                if (pe.Pid == keepPid1 || pe.Pid == keepPid2) continue;
                string exeName = pe.Name + ".exe";
                if (ProcReader.TerminateIf(pe.Pid, path => string.Equals(Path.GetFileName(path), exeName, StringComparison.OrdinalIgnoreCase), out string why)) n++;
                else App.Log("Process was not closed (" + pe.Name + ", PID " + pe.Pid + "): " + why, LogLevel.Warn);
            }
            // ciadpi copies of this folder only (its exact exe, by the long form and the physical path)
            string ownCiadpi = Engines.Get(EngineKind.ByeDpi).ExePath;
            foreach (var pe in ProcReader.ByNames(new[] { "ciadpi" }))
            {
                if (pe.Pid == keepPid1 || pe.Pid == keepPid2) continue;
                if (ProcReader.TerminateIf(pe.Pid, path => ProcReader.IsFile(path, ownCiadpi), out _)) n++;
            }
            return n;
        }

        /// <summary>The banner's "Fix" button: closes conflicting processes and removes the old service.</summary>
        public void ResolveConflicts()
        {
            lock (gate)
            {
                int keep1 = -1, keep2 = -1;
                try { if (proc != null && !proc.HasExited) keep1 = proc.Id; } catch { }
                if (App.Settings.ServiceMode) keep2 = ServicePid(ServiceName);
                else
                {
                    // Also remove our own service left over while service mode is off
                    var r0 = Sc("stop " + ServiceName);
                    var r1 = Sc("delete " + ServiceName);
                    if (r1.Code == 0) App.Log("Removed the NSF Shield service that is no longer used.", LogLevel.Info);
                }
                int n = KillExternalInternal(keep1, keep2);
                var r = Sc("delete " + LegacyServiceName);
                if (r.Code == 0) App.Log("Removed the old 'GoodbyeDPI' service (it will no longer start at boot).", LogLevel.Success);
                App.Log("Conflicts resolved (" + n + " process(es)/service(s) closed).", LogLevel.Success);
                ExternalCount = 0;
                LegacyServiceExists = false;
                LegacyServiceRunning = false;
            }
            App.Problems.Clear("NSF-301");
            App.Problems.Clear("NSF-302");
            App.RaiseStatus();
            Poll();
        }

        // ------------------------------------------------------------------ service mode

        /// <summary>The fresh install-folder check before a service change (the self-test replaces it).</summary>
        internal static Func<(bool Ok, string Why)> FreshGuard = () => (InstallGuard.CheckFresh(out string why), why);

        bool StartService(IDpiEngine eng, string args, bool takeOver)
        {
            // checked again right now (not the cached state): the SYSTEM service only runs from a protected folder
            var (guardOk, guardWhy) = FreshGuard();
            if (!guardOk)
            {
                Fail(new LocText("engine.serviceInstalledOnly", guardWhy), "NSF-705");
                return false;
            }
            string bin = "\"" + eng.ExePath + "\" " + args;
            var r = ServiceStart.Run(Scm, ServiceName, bin, takeOver, () => Thread.Sleep(App.Preview ? 0 : 2000));
            if (!r.Ok)
            {
                if (r.RolledBack == false) App.Log("[NSF-701] The service could not be put back as it was: " + r.RollbackDetail, LogLevel.Error);
                else if (r.RolledBack == true) App.Log("The service was put back as it was before the failed start.", LogLevel.Info);
                Fail(r.Error, r.Code);
                return false;
            }
            if (r.Created) App.Log("Background service installed (starts automatically with Windows).", LogLevel.Success);
            Sc("description " + ServiceName + " " + Esc("NSF Shield – bypasses access blocking with " + eng.DisplayName + "."));
            ServiceInstalled = true;
            RunningAsService = true;
            return true;
        }

        public void UninstallService()
        {
            lock (gate)
            {
                bool was = RunningAsService;
                userStop = true;
                StopInternal(foreignService: true);
                var r = Sc("delete " + ServiceName);
                if (r.Code == 0) App.Log("Background service removed.", LogLevel.Info);
                ServiceInstalled = false;
                if (was) { StartedAt = null; SetState(EngineState.Stopped); }
            }
            App.RaiseStatus();
        }

        public void ResetAll()
        {
            lock (gate)
            {
                userStop = true;
                SetState(EngineState.Stopping);
                StopInternal(foreignService: true);
                ByeDpiNet.RecoverStale("reset");
                KillExternalInternal(-1, -1);
                foreach (var n in new[] { ServiceName, LegacyServiceName, "WinDivert", "WinDivert14" })
                {
                    Sc("stop " + n);
                    var r = Sc("delete " + n);
                    if (r.Code == 0) App.Log("Service removed: " + n, LogLevel.Info);
                }
                Native.FlushDns();
                StartedAt = null;
                ServiceInstalled = false;
                ExternalCount = 0;
                LegacyServiceExists = LegacyServiceRunning = false;
                SetState(EngineState.Stopped);
                App.Log("Reset finished. If the problem persists, restart the computer.", LogLevel.Success);
            }
        }

        // ------------------------------------------------------------------ periodic check

        public void Poll()
        {
            if (App.Preview) return;
            if (Interlocked.Exchange(ref polling, 1) == 1) return;
            try
            {
                bool legacyExists = false, legacyRunning = false, ourExists = false, ourRunning = false;
                foreach (var s in ServiceController.GetServices())
                {
                    using (s)
                    {
                        if (s.ServiceName.Equals(LegacyServiceName, StringComparison.OrdinalIgnoreCase))
                        {
                            legacyExists = true;
                            legacyRunning = s.Status != ServiceControllerStatus.Stopped;
                        }
                        else if (s.ServiceName.Equals(ServiceName, StringComparison.OrdinalIgnoreCase))
                        {
                            ourExists = true;
                            ourRunning = s.Status == ServiceControllerStatus.Running;
                        }
                    }
                }
                // WinDivert engines that are not this app's: told apart by the exact path and the PID (own engine, own service,
                // scan candidate), never by the name alone; a process that cannot be read counts as foreign
                var found = ProcReader.ByNames(Engines.DriverProcessNames);
                var ctx = new ConflictContext { TrialPids = ScanTrials.Snapshot() };
                foreach (var en in Engines.All) try { ctx.OwnExes.Add(Path.GetFullPath(en.ExePath)); } catch { }
                if (ourRunning)
                {
                    var svc = ScmReader.Query(ServiceName);
                    bool owned = ServiceOwnership.OwnedEngine(svc.ImagePath) != null;
                    if (svc.Running && svc.Pid > 0 && owned) ctx.OwnPids.Add(svc.Pid);
                    // a NSFShield service of another installation is never shown (or stopped) as this app's protection
                    if (!owned) ourRunning = false;
                }

                bool changed = legacyExists != LegacyServiceExists || legacyRunning != LegacyServiceRunning || ourExists != ServiceInstalled;
                LegacyServiceExists = legacyExists;
                LegacyServiceRunning = legacyRunning;
                ServiceInstalled = ourExists;

                if (Monitor.TryEnter(gate))
                {
                    try
                    {
                        bool serviceEngine = Engines.Of(ActiveProfile ?? App.SelectedProfile).SupportsService;
                        int own = OwnProcessId;
                        if (own > 0) ctx.OwnPids.Add(own);
                        var owners = found.Select(f => Conflicts.Classify(f, ctx, out _)).ToList();
                        int ext = owners.Count(o => o == ProcOwner.OtherInstall || o == ProcOwner.Unknown);
                        // during a scan a process that cannot be told apart yet is not reported (the count is kept until the scan ends)
                        bool unsure = ScanGate.Busy && owners.Contains(ProcOwner.Unknown);
                        if (!unsure && ext != ExternalCount) { ExternalCount = ext; changed = true; }

                        if (App.Settings.ServiceMode && serviceEngine && proc == null &&
                            State != EngineState.Starting && State != EngineState.Stopping)
                        {
                            if (ourRunning && State != EngineState.Running)
                            {
                                ActiveProfile = ActiveProfile ?? App.SelectedProfile;
                                StartedAt = StartedAt ?? DateTime.Now;
                                RunningAsService = true;
                                userStop = false;
                                SetState(EngineState.Running);
                            }
                            else if (!ourRunning && State == EngineState.Running && !userStop)
                            {
                                RunningAsService = false;
                                Fail(new LocText("engine.serviceStopped"), "NSF-702");
                            }
                        }
                        if (proc != null) ReadConsoleIntoLog(proc);
                    }
                    finally { Monitor.Exit(gate); }
                }
                // the user changed the Windows proxy while it was set for ByeDPI: NSF Shield's restore record is dropped at once
                try { ByeDpiNet.CheckOwnership(); } catch (Exception ign) { App.Ignored("Windows proxy check", ign); }
                if (changed)
                {
                    if (ExternalCount > 0) App.Problems.Report("NSF-301", new LocText("engine.processCount", ExternalCount)); else App.Problems.Clear("NSF-301");
                    if (LegacyServiceExists) App.Problems.Report("NSF-302"); else App.Problems.Clear("NSF-302");
                    App.RaiseStatus();
                }
            }
            catch (Exception ex) { App.Ignored("Status check", ex); }
            finally { Interlocked.Exchange(ref polling, 0); }
        }

        // ------------------------------------------------------------------ helpers

        public static bool ServiceExists(string name)
        {
            try
            {
                foreach (var s in ServiceController.GetServices())
                    using (s)
                        if (s.ServiceName.Equals(name, StringComparison.OrdinalIgnoreCase)) return true;
            }
            catch (Exception ign) { App.Ignored("Service list could not be read", ign); }
            return false;
        }

        static int ServicePid(string name)
        {
            try
            {
                using (var q = new ManagementObjectSearcher("SELECT ProcessId FROM Win32_Service WHERE Name='" + name + "'"))
                    foreach (ManagementObject mo in q.Get())
                        using (mo) return Convert.ToInt32(mo["ProcessId"]);
            }
            catch (Exception ign) { App.Ignored("Service process id could not be read", ign); }
            return -1;
        }

        public static (int Code, string Output) Sc(string args) => Sys.Run(Sys.SystemExe("sc.exe"), args, 30000);

        /// <summary>Exe path in the service's command line (quoted or unquoted).</summary>
        public static string ServiceExe(string name)
        {
            string cmd = ServicePath(name);
            if (string.IsNullOrWhiteSpace(cmd)) return null;
            cmd = cmd.Trim();
            if (cmd.StartsWith("\"")) { int e = cmd.IndexOf('"', 1); return e > 1 ? cmd.Substring(1, e - 1) : null; }
            int x = cmd.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            return x > 0 ? cmd.Substring(0, x + 4) : cmd;
        }

        /// <summary>
        /// For uninstalling: removes only what belongs to NSF Shield (its own service, the engine processes of this folder,
        /// the ByeDPI proxy, the WinDivert driver entry). Does not touch other programs' GoodbyeDPI service.
        /// </summary>
        public void RemoveForUninstall(UninstallReport report)
        {
            lock (gate)
            {
                userStop = true;
                StopInternal();
                // only the engine processes of this installation: the exact engine exe paths (never a name alone)
                foreach (var e in Engines.All)
                    foreach (var pe in ProcReader.ByNames(new[] { e.ProcessName }))
                    {
                        if (pe.Path == null || !PathSafety.Same(pe.Path, e.ExePath)) continue;
                        var exe = e.ExePath;
                        if (!ProcReader.TerminateIf(pe.Pid, path => ProcReader.IsFile(path, exe), out string why))
                            App.Log(e.ExeName + " was not closed (PID " + pe.Pid + "): " + why, LogLevel.Warn);
                    }
                // the NSFShield service and the WinDivert entries are removed only when their files are proven to be this
                // installation's (physical final paths); another installation's entry or one whose owner cannot be read stays
                RemoveOwnedEntries(Scm, report, DriverControl.DriverUserRunning(),
                                   ip => ServiceOwnership.OwnedEngineVerified(ip) != null, ip => DriverControl.DriverInFolderVerified(ip, App.BaseDir));
                StartedAt = null;
                ServiceInstalled = false;
                RunningAsService = false;
                SetState(EngineState.Stopped);
            }
        }

        /// <summary>
        /// Clean uninstall of the SCM entries: the "NSFShield" service and the WinDivert driver entries are stopped and deleted only
        /// when <paramref name="serviceOwned"/> / <paramref name="driverOwned"/> prove (from the registered image path) that they
        /// belong to this installation. Another installation's entry, or one whose owner cannot be read, is kept and reported.
        /// </summary>
        internal static void RemoveOwnedEntries(IServiceControl scm, UninstallReport report, bool otherDpiRunning, Func<string, bool> serviceOwned, Func<string, bool> driverOwned)
        {
            var svc = scm.Query(ServiceName);
            if (svc.Exists)
            {
                if (serviceOwned(svc.ImagePath))
                {
                    scm.Stop(ServiceName, TimeSpan.FromSeconds(15));
                    if (scm.Delete(ServiceName, out string o)) report.Add("engine.uninstall.serviceRemoved"); else report.Add("engine.uninstall.serviceRemoveFailed", o);
                }
                else report.Add("engine.uninstall.serviceKept", ServiceOwnership.ExeOf(svc.ImagePath) ?? "?");
            }
            foreach (var n in DriverControl.DriverServices)
            {
                var d = scm.Query(n);
                if (!d.Exists) continue;
                if (!driverOwned(d.ImagePath)) { report.Add("engine.uninstall.driverForeign", n); continue; }
                if (otherDpiRunning) { report.Add("engine.uninstall.driverKept", n); continue; }
                scm.Stop(n, TimeSpan.FromSeconds(10));
                if (scm.Delete(n, out _)) report.Add("engine.uninstall.driverRemoved", n);
            }
        }

        /// <summary>Quotes a single argument according to the CommandLineToArgvW rules.</summary>
        public static string Esc(string arg)
        {
            var sb = new StringBuilder("\"");
            int bs = 0;
            foreach (char c in arg)
            {
                if (c == '\\') { bs++; continue; }
                if (c == '"') sb.Append('\\', bs * 2 + 1);
                else sb.Append('\\', bs);
                sb.Append(c);
                bs = 0;
            }
            sb.Append('\\', bs * 2);
            sb.Append('"');
            return sb.ToString();
        }
    }
}
