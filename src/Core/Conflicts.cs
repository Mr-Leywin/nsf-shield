using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NSFShield
{
    // ======================================================================================= SCM (read only)

    /// <summary>How reading one SCM entry ended. "Not found" and "access denied" are different results.</summary>
    public enum ScmRead { Ok, NotFound, AccessDenied, Error }

    /// <summary>One service or driver entry as the SCM reports it (opened with the least rights: connect + query).</summary>
    public sealed class ScmEntry
    {
        public string Name = "";
        public ScmRead Read = ScmRead.Error;
        public int Win32Error;
        /// <summary>SERVICE_KERNEL_DRIVER 0x1, SERVICE_FILE_SYSTEM_DRIVER 0x2, SERVICE_WIN32_OWN_PROCESS 0x10, SERVICE_WIN32_SHARE_PROCESS 0x20.</summary>
        public uint Type;
        /// <summary>1 stopped, 2 start pending, 3 stop pending, 4 running, 5 continue pending, 6 pause pending, 7 paused.</summary>
        public uint State;
        public int Pid;
        /// <summary>The configured command line / driver path ("" when it could not be read).</summary>
        public string ImagePath = "";

        public bool IsDriver => Read == ScmRead.Ok && (Type & 0x3) != 0;
        public bool Running => Read == ScmRead.Ok && State == 4;
        public bool Stopped => Read == ScmRead.Ok && State == 1;
        public bool Pending => Read == ScmRead.Ok && (State == 2 || State == 3 || State == 5 || State == 6);
        public string StateKey => Read != ScmRead.Ok ? "diag.scm." + Read : Running ? "diag.scm.running" : Stopped ? "diag.scm.stopped" : Pending ? "diag.scm.pending" : State == 7 ? "diag.scm.paused" : "diag.scm.unknown";
        public string TypeKey => IsDriver ? "diag.scm.driver" : "diag.scm.service";
    }

    public static class ScmReader
    {
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "OpenSCManagerW")] static extern IntPtr OpenSCManager(string machine, string db, uint access);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "OpenServiceW")] static extern IntPtr OpenService(IntPtr scm, string name, uint access);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool CloseServiceHandle(IntPtr h);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool QueryServiceStatusEx(IntPtr h, int level, byte[] buf, int size, out int needed);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "QueryServiceConfigW")] static extern bool QueryServiceConfig(IntPtr h, IntPtr buf, int size, out int needed);

        [StructLayout(LayoutKind.Sequential)]
        struct QueryConfig { public uint Type, Start, ErrorControl; public IntPtr BinaryPath, LoadOrderGroup; public uint TagId; public IntPtr Dependencies, StartName, DisplayName; }

        const uint ScManagerConnect = 0x0001, ServiceQueryConfig = 0x0001, ServiceQueryStatus = 0x0004;
        const int ErrorAccessDenied = 5, ErrorServiceDoesNotExist = 1060, ErrorInvalidName = 123;

        static ScmRead FromError(int e) => e == ErrorAccessDenied ? ScmRead.AccessDenied : e == ErrorServiceDoesNotExist || e == ErrorInvalidName ? ScmRead.NotFound : ScmRead.Error;

        /// <summary>Reads one entry; nothing is started, stopped or changed. Without the config right the state is still read.</summary>
        public static ScmEntry Query(string name)
        {
            var r = new ScmEntry { Name = name ?? "" };
            IntPtr scm = OpenSCManager(null, null, ScManagerConnect);
            if (scm == IntPtr.Zero) { r.Win32Error = Marshal.GetLastWin32Error(); r.Read = FromError(r.Win32Error); return r; }
            try
            {
                bool config = true;
                IntPtr svc = OpenService(scm, name, ServiceQueryConfig | ServiceQueryStatus);
                if (svc == IntPtr.Zero && Marshal.GetLastWin32Error() == ErrorAccessDenied)
                {
                    config = false;
                    svc = OpenService(scm, name, ServiceQueryStatus);
                }
                if (svc == IntPtr.Zero) { r.Win32Error = Marshal.GetLastWin32Error(); r.Read = FromError(r.Win32Error); return r; }
                try
                {
                    var st = new byte[36];
                    if (!QueryServiceStatusEx(svc, 0, st, st.Length, out _)) { r.Win32Error = Marshal.GetLastWin32Error(); r.Read = FromError(r.Win32Error); return r; }
                    r.Type = BitConverter.ToUInt32(st, 0);
                    r.State = BitConverter.ToUInt32(st, 4);
                    r.Pid = BitConverter.ToInt32(st, 28);
                    r.Read = ScmRead.Ok;
                    if (config)
                    {
                        QueryServiceConfig(svc, IntPtr.Zero, 0, out int need);
                        if (need > 0 && need < 64 * 1024)
                        {
                            IntPtr buf = Marshal.AllocHGlobal(need);
                            try
                            {
                                if (QueryServiceConfig(svc, buf, need, out _))
                                {
                                    var qc = (QueryConfig)Marshal.PtrToStructure(buf, typeof(QueryConfig));
                                    r.ImagePath = qc.BinaryPath != IntPtr.Zero ? Marshal.PtrToStringUni(qc.BinaryPath) ?? "" : "";
                                }
                            }
                            finally { Marshal.FreeHGlobal(buf); }
                        }
                    }
                    return r;
                }
                finally { CloseServiceHandle(svc); }
            }
            finally { CloseServiceHandle(scm); }
        }
    }

    // ======================================================================================= processes (read only)

    public sealed class ProcEntry
    {
        public string Name = "";
        public int Pid;
        /// <summary>Full path of the executable; null when it could not be read (see <see cref="AccessDenied"/>).</summary>
        public string Path;
        public bool AccessDenied;
    }

    public static class ProcReader
    {
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "QueryFullProcessImageNameW")] static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder buf, ref int size);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
        const uint ProcessQueryLimitedInformation = 0x1000;

        /// <summary>The executable of a process, read with the least right (no module list, nothing is opened for writing).</summary>
        public static string ImagePath(int pid, out bool accessDenied)
        {
            accessDenied = false;
            IntPtr h = OpenProcess(ProcessQueryLimitedInformation, false, pid);
            if (h == IntPtr.Zero) { accessDenied = Marshal.GetLastWin32Error() == 5; return null; }
            try
            {
                var sb = new StringBuilder(1024);
                int n = sb.Capacity;
                return QueryFullProcessImageName(h, 0, sb, ref n) ? sb.ToString(0, n) : null;
            }
            finally { CloseHandle(h); }
        }

        [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateProcess(IntPtr h, uint code);
        [DllImport("kernel32.dll", SetLastError = true)] static extern uint WaitForSingleObject(IntPtr h, uint ms);
        const uint ProcessTerminate = 0x0001, Synchronize = 0x00100000;

        /// <summary>The self-test replaces the termination (no process is ever closed in a test).</summary>
        internal static Func<int, Func<string, bool>, (bool Closed, string Why)> TerminateOverride = null;

        /// <summary>
        /// Closes a process only when its executable – read through the same handle that closes it, so a reused process id can
        /// never be hit – passes <paramref name="isOurs"/>. A process whose path cannot be read, or that belongs to anything
        /// else, is left running. Waits up to <paramref name="waitMs"/> for it to end.
        /// </summary>
        public static bool TerminateIf(int pid, Func<string, bool> isOurs, out string why, uint waitMs = 3000)
        {
            if (TerminateOverride != null) { var r = TerminateOverride(pid, isOurs); why = r.Why; return r.Closed; }
            why = null;
            IntPtr h = OpenProcess(ProcessQueryLimitedInformation | ProcessTerminate | Synchronize, false, pid);
            if (h == IntPtr.Zero) { why = Marshal.GetLastWin32Error() == 5 ? "access denied" : "not running"; return false; }
            try
            {
                var sb = new StringBuilder(1024);
                int n = sb.Capacity;
                string path = QueryFullProcessImageName(h, 0, sb, ref n) ? sb.ToString(0, n) : null;
                if (path == null) { why = "path unreadable"; return false; }
                if (!isOurs(path)) { why = "not this installation's: " + path; return false; }
                if (!TerminateProcess(h, 1)) { why = "terminate failed (" + Marshal.GetLastWin32Error() + ")"; return false; }
                WaitForSingleObject(h, waitMs);
                return true;
            }
            finally { CloseHandle(h); }
        }

        /// <summary>The same file as <paramref name="expected"/>: the long form and, when both exist, the physical final path.</summary>
        public static bool IsFile(string path, string expected)
        {
            if (!PathSafety.Same(path, expected)) return false;
            string a = PathSafety.FinalPath(path), b = PathSafety.FinalPath(expected);
            return a != null && b != null && string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>Inside <paramref name="dir"/>: by the long form and by the physical final path of the file.</summary>
        public static bool IsUnder(string path, string dir)
        {
            if (!PathSafety.Inside(path, dir)) return false;
            string a = PathSafety.FinalPath(path), b = PathSafety.FinalPath(dir);
            return a != null && b != null && a.StartsWith(b.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);
        }

        public static List<ProcEntry> ByNames(IEnumerable<string> names)
        {
            var list = new List<ProcEntry>();
            foreach (var n in names.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                Process[] ps;
                try { ps = Process.GetProcessesByName(n); } catch (Exception ign) { App.Ignored("Process list could not be read", ign); continue; }
                foreach (var p in ps)
                    using (p)
                    {
                        int pid;
                        try { pid = p.Id; } catch { continue; }
                        list.Add(new ProcEntry { Name = n, Pid = pid, Path = ImagePath(pid, out bool denied), AccessDenied = denied });
                    }
            }
            return list;
        }
    }

    /// <summary>Interface index of the route Windows would use to reach the internet (a routing table lookup; nothing is sent).</summary>
    public static class Routes
    {
        [DllImport("iphlpapi.dll")] static extern int GetBestInterface(uint destAddr, out uint index);

        public static int? BestInterfaceIndex()
        {
            try
            {
                uint dst = BitConverter.ToUInt32(IPAddress.Parse("8.8.8.8").GetAddressBytes(), 0);
                return GetBestInterface(dst, out uint idx) == 0 ? (int)idx : (int?)null;
            }
            catch (Exception ign) { App.Ignored("Route could not be read", ign); return null; }
        }
    }

    /// <summary>PIDs of the scan's own candidates (registered when a candidate starts, removed when it is closed).</summary>
    public static class ScanTrials
    {
        static readonly HashSet<int> pids = new HashSet<int>();
        public static void Add(int pid) { if (pid > 0) lock (pids) pids.Add(pid); }
        public static void Remove(int pid) { lock (pids) pids.Remove(pid); }
        public static HashSet<int> Snapshot() { lock (pids) return new HashSet<int>(pids); }
    }

    // ======================================================================================= the diagnosis

    public enum ProcOwner { Own, ScanCandidate, OtherInstall, Unknown }

    public sealed class ProcFinding
    {
        public ProcEntry P;
        public ProcOwner Owner;
        public bool DriverTool;
        public LocText Why;
        public string Text => P.Name + ".exe (PID " + P.Pid + ") – " + Why?.Text;
    }

    public sealed class ServiceFinding
    {
        public string Product = "";
        public ScmEntry E;
        public bool InOurFolder;
        /// <summary>An active kernel driver: the SCM says it is a driver AND that it runs.</summary>
        public bool ActiveDriver => E.Read == ScmRead.Ok && E.IsDriver && E.Running;
        /// <summary>A user-mode service of the product (only information about the product, not a driver).</summary>
        public bool UserService => E.Read == ScmRead.Ok && !E.IsDriver;
        public bool Unreadable => E.Read == ScmRead.AccessDenied || E.Read == ScmRead.Error;
    }

    /// <summary>What the checks know about this installation and the running state (taken once per diagnosis).</summary>
    public sealed class ConflictContext
    {
        public HashSet<int> OwnPids = new HashSet<int>();
        public HashSet<int> TrialPids = new HashSet<int>();
        /// <summary>Full paths of this installation's engine executables.</summary>
        public HashSet<string> OwnExes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public string BaseDir = "";
        public bool ScanBusy;
        /// <summary>The engine that runs now (null: protection is off).</summary>
        public IDpiEngine Running;
        public bool ByeDpiAvailable;
        public LocText ByeDpiWhy;
    }

    /// <summary>The read-only view the diagnosis uses (replaced by fakes in the self-test).</summary>
    public interface IConflictSource
    {
        ConflictContext Context();
        List<ProcEntry> Processes(IEnumerable<string> names);
        ScmEntry Service(string name);
        List<AdapterInfo> Adapters();
        int? BestRouteIndex();
    }

    public sealed class LiveConflictSource : IConflictSource
    {
        public ConflictContext Context()
        {
            var c = new ConflictContext { BaseDir = App.BaseDir, ScanBusy = ScanGate.Busy, TrialPids = ScanTrials.Snapshot() };
            foreach (var e in Engines.All)
                try { c.OwnExes.Add(Path.GetFullPath(e.ExePath)); } catch { }
            int own = App.Engine?.OwnProcessId ?? 0;
            if (own > 0) c.OwnPids.Add(own);
            var svc = ScmReader.Query(Engine.ServiceName);
            if (svc.Running && svc.Pid > 0 && ServiceOwnership.OwnedEngine(svc.ImagePath) != null) c.OwnPids.Add(svc.Pid);
            var st = App.Engine?.State ?? EngineState.Stopped;
            if ((st == EngineState.Running || st == EngineState.Starting) && App.Engine.ActiveProfile != null) c.Running = Engines.Of(App.Engine.ActiveProfile);
            c.ByeDpiAvailable = Engines.ByeDpi.Available(out var why);
            c.ByeDpiWhy = why;
            return c;
        }
        public List<ProcEntry> Processes(IEnumerable<string> names) => ProcReader.ByNames(names);
        public ScmEntry Service(string name) => ScmReader.Query(name);
        public List<AdapterInfo> Adapters() => NetTest.Adapters();
        public int? BestRouteIndex() => Routes.BestInterfaceIndex();
    }

    /// <summary>A notice for the home page and Find Problems (information only: it opens the profile page at most).</summary>
    public sealed class ConflictNotice
    {
        public string Kind = "";
        public LocText Title, Text;
        /// <summary>The shorter text of the home page card (Find Problems shows <see cref="Text"/>).</summary>
        public LocText Short;
        /// <summary>True: the card may offer to open the profile page (ByeDPI tab); nothing is selected or started.</summary>
        public bool OpenProfiles;
    }

    public sealed class ConflictReport
    {
        public DateTime At = DateTime.Now;
        /// <summary>A scan owns the engine and some process could not be told apart: the diagnosis waits for the scan to end.</summary>
        public bool Deferred;
        public List<ProcFinding> Processes = new List<ProcFinding>();
        public List<ServiceFinding> WinDivert = new List<ServiceFinding>();
        public List<ServiceFinding> AntiCheat = new List<ServiceFinding>();
        public List<ServiceFinding> VpnServices = new List<ServiceFinding>();
        /// <summary>Virtual (VPN/tunnel) adapters that are Up.</summary>
        public List<AdapterInfo> VpnAdapters = new List<AdapterInfo>();
        /// <summary>true: the route to the internet goes through one of <see cref="VpnAdapters"/>; false: it does not; null: unknown.</summary>
        public bool? VpnRoute;
        public string VpnRouteAdapter = "";
        public ConflictNotice Notice;

        public IEnumerable<ProcFinding> Foreign(bool driverTools) =>
            Processes.Where(p => p.DriverTool == driverTools && (p.Owner == ProcOwner.OtherInstall || p.Owner == ProcOwner.Unknown));
    }

    public static class Conflicts
    {
        /// <summary>WinDivert engines (they load the driver) and other DPI tools (no driver).</summary>
        public static readonly string[] DriverTools = Engines.DriverProcessNames;
        public static readonly string[] OtherTools = { "ciadpi", "byedpi", "spoofdpi", "green-tunnel", "greentunnel", "dpitunnel-cli", "dpitunnel", "powertunnel" };

        /// <summary>
        /// The anti-cheat entries checked (a small explicit list; names that change between versions are not guessed). Only an
        /// entry the SCM reports as a kernel driver AND running counts as an active driver; a user-mode service only tells
        /// that the product is installed.
        /// </summary>
        public static readonly (string Service, string Product)[] AntiCheat =
        {
            ("vgk", "Riot Vanguard"), ("FACEIT", "FACEIT"), ("EasyAntiCheat", "EasyAntiCheat"), ("EasyAntiCheat_EOS", "EasyAntiCheat"), ("BEDaisy", "BattlEye"),
        };

        /// <summary>VPN products whose service is checked (information only: a running service is not an active tunnel).</summary>
        public static readonly (string Service, string Product)[] Vpn = { ("CloudflareWARP", "Cloudflare WARP") };

        static LocText L(string k, params object[] a) => new LocText(k, a);

        static string Full(string p) { try { return Path.GetFullPath(p); } catch { return null; } }

        /// <summary>
        /// Whose process is it? A name or a folder prefix is never proof: this installation's engine needs the exact executable
        /// path AND a PID the app started (its engine process or its own service); a scan candidate needs the exact path AND a
        /// registered candidate PID. The same file under an unknown PID, or a path that cannot be read, stays "unknown".
        /// </summary>
        public static ProcOwner Classify(ProcEntry p, ConflictContext c, out LocText why)
        {
            if (string.IsNullOrEmpty(p.Path))
            {
                why = L(p.AccessDenied ? "diag.owner.denied" : "diag.owner.unreadable");
                return ProcOwner.Unknown;
            }
            string full = Full(p.Path);
            bool ownFile = full != null && c.OwnExes.Contains(full);
            if (ownFile && c.OwnPids.Contains(p.Pid)) { why = L("diag.owner.own"); return ProcOwner.Own; }
            if (ownFile && c.TrialPids.Contains(p.Pid)) { why = L("diag.owner.candidate"); return ProcOwner.ScanCandidate; }
            if (ownFile) { why = L("diag.owner.ownFileUnknownPid"); return ProcOwner.Unknown; }
            why = L("diag.owner.other", ShortPath(full ?? p.Path));
            return ProcOwner.OtherInstall;
        }

        /// <summary>A path shown without the user folder (…\folder\file.exe).</summary>
        public static string ShortPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return "?";
            string file = Path.GetFileName(path), dir = Path.GetFileName(Path.GetDirectoryName(path) ?? "");
            return dir.Length > 0 ? "…\\" + dir + "\\" + file : file;
        }

        /// <summary>The whole read-only diagnosis (processes, WinDivert services, anti-cheat, VPN) from one source.</summary>
        public static ConflictReport Evaluate(IConflictSource src)
        {
            var c = src.Context();
            var r = new ConflictReport();
            foreach (var p in src.Processes(DriverTools.Concat(OtherTools)))
            {
                var o = Classify(p, c, out var why);
                r.Processes.Add(new ProcFinding { P = p, Owner = o, Why = why, DriverTool = DriverTools.Contains(p.Name, StringComparer.OrdinalIgnoreCase) });
            }
            if (c.ScanBusy && r.Processes.Any(p => p.Owner == ProcOwner.Unknown)) { r.Deferred = true; return r; }

            foreach (var name in DriverControl.DriverServices)
            {
                var e = src.Service(name);
                if (e.Read == ScmRead.NotFound) continue;
                r.WinDivert.Add(new ServiceFinding { Product = "WinDivert", E = e, InOurFolder = e.Read == ScmRead.Ok && DriverControl.DriverInFolder(e.ImagePath, c.BaseDir) });
            }
            foreach (var (name, product) in AntiCheat)
            {
                var e = src.Service(name);
                if (e.Read != ScmRead.NotFound) r.AntiCheat.Add(new ServiceFinding { Product = product, E = e });
            }
            foreach (var (name, product) in Vpn)
            {
                var e = src.Service(name);
                if (e.Read != ScmRead.NotFound) r.VpnServices.Add(new ServiceFinding { Product = product, E = e });
            }
            r.VpnAdapters = src.Adapters().Where(a => a.IsVpn).ToList();
            if (r.VpnAdapters.Count > 0)
            {
                int? best = src.BestRouteIndex();
                var via = best.HasValue ? r.VpnAdapters.FirstOrDefault(a => a.IfIndex == best.Value) : null;
                r.VpnRoute = !best.HasValue ? (bool?)null : via != null;
                r.VpnRouteAdapter = via?.Description ?? via?.Name ?? "";
            }
            r.Notice = NoticeFor(r, c);
            return r;
        }

        /// <summary>
        /// The information card: a verified active anti-cheat kernel driver while a WinDivert engine runs. It explains the
        /// driverless ByeDPI engine (or why it is not offered here); it never selects, starts or stops anything.
        /// </summary>
        public static ConflictNotice NoticeFor(ConflictReport r, ConflictContext c)
        {
            if (r.Deferred || c.Running == null || !c.Running.UsesDriver) return null;
            var ac = r.AntiCheat.FirstOrDefault(a => a.ActiveDriver);
            if (ac == null) return null;
            return c.ByeDpiAvailable
                ? new ConflictNotice { Kind = "anticheat", OpenProfiles = true, Title = L("diag.notice.anticheatTitle", ac.Product), Text = L("diag.notice.anticheatByeDpi", ac.Product, c.Running.DisplayName),
                                       Short = L("diag.notice.anticheatShortByeDpi", ac.Product, c.Running.DisplayName) }
                : new ConflictNotice { Kind = "anticheat", OpenProfiles = false, Title = L("diag.notice.anticheatTitle", ac.Product), Text = L("diag.notice.anticheatNoByeDpi", ac.Product, c.Running.DisplayName, c.ByeDpiWhy?.Text ?? ""),
                                       Short = L("diag.notice.anticheatShortNoByeDpi", ac.Product, c.Running.DisplayName, c.ByeDpiWhy?.Text ?? "") };
        }

        // ------------------------------------------------------------------ the shared result (Find Problems and the home page)

        static ConflictReport latest;
        static readonly object refreshGate = new object();
        static Task<ConflictReport> inflight;
        static bool pendingAfterScan;
        static DateTime lastStart = DateTime.MinValue;
        /// <summary>The source used by the live app (the self-test replaces it).</summary>
        public static IConflictSource Source = new LiveConflictSource();

        /// <summary>The last complete diagnosis (null until the first one ran).</summary>
        public static ConflictReport Latest => latest;
        /// <summary>Raised (on the UI thread) when a new diagnosis is available.</summary>
        public static event Action Updated;

        /// <summary>
        /// Runs the read-only diagnosis in the background. While a scan owns the engine and processes cannot be told apart,
        /// the last result stays and one new diagnosis follows when the scan has ended.
        /// </summary>
        /// <remarks>
        /// Callers that come while a diagnosis is running share it (the same task): a second caller never gets an empty result
        /// just because the first diagnosis has not finished yet.
        /// </remarks>
        public static Task<ConflictReport> RefreshAsync()
        {
            lock (refreshGate)
            {
                if (inflight != null && !inflight.IsCompleted) return inflight;
                lastStart = DateTime.Now;
                inflight = RunRefreshAsync();
                return inflight;
            }
        }

        static async Task<ConflictReport> RunRefreshAsync()
        {
            try
            {
                var src = Source;
                var r = await Task.Run(() => Evaluate(src)).ConfigureAwait(false);
                if (r.Deferred) { pendingAfterScan = true; return r; }
                latest = r;
                App.Post(() => Updated?.Invoke());
                return r;
            }
            catch (Exception ex) { App.Ignored("Conflict check", ex); return latest; }
        }

        /// <summary>The home page refreshes the diagnosis only when it is older than <paramref name="maxAge"/> (never the full Find Problems run).</summary>
        public static void RefreshIfStale(TimeSpan maxAge)
        {
            if (App.Preview) return;
            if (DateTime.Now - lastStart < maxAge) return;
            _ = RefreshAsync();
        }

        /// <summary>Called when the scan gate is free again: a diagnosis that waited for the scan runs once.</summary>
        public static void OnScanReleased()
        {
            if (!pendingAfterScan) return;
            pendingAfterScan = false;
            _ = RefreshAsync();
        }

#if PREVIEW
        /// <summary>Self-test and screenshots: sets the shared result directly.</summary>
        public static void DebugSet(ConflictReport r) { latest = r; pendingAfterScan = false; }
        public static bool DebugPending => pendingAfterScan;
#endif
    }
}
