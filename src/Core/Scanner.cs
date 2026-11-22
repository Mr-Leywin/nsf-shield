using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;

namespace NSFShield
{
    public enum ScanLineKind { Info, Step, Good, Warn, Bad, Muted }

    /// <summary>Which candidates a scan request contains.</summary>
    public enum ScanScope { Recommended, ActiveEngine, AllEngines, DriverlessOnly }

    /// <summary>StopOnFirstMatch: stops at the first full success (recommended first). FullBenchmark: tries every selected candidate once, never applies by itself.</summary>
    public enum ScanMode { StopOnFirstMatch, FullBenchmark }

    /// <summary>
    /// The one owner of the engine during a scan. While a scan holds it, nothing else may start an engine (double clicks,
    /// profile changes, the watchdog, automatic restarts, late UI events); only the scan's own restore/apply passes its token.
    /// </summary>
    public static class ScanGate
    {
        static readonly object sync = new object();
        static object owner;
        /// <summary>Starts refused because a scan owned the engine (log and tests).</summary>
        public static int Refused;

        public static bool Busy { get { lock (sync) return owner != null; } }

        // user start/stop requests that were accepted and have not finished yet (ordered with the scan under the same lock)
        static int userOps;

        /// <summary>
        /// A user's start/stop (or apply) request is accepted only when no scan owns the engine; until <see cref="EndUser"/> no
        /// scan can take the engine, so a scan never records the state in the middle of an accepted stop or start.
        /// </summary>
        public static bool TryBeginUser()
        {
            lock (sync)
            {
                if (owner != null) { Refused++; return false; }
                userOps++;
                return true;
            }
        }

        public static void EndUser()
        {
            lock (sync) { if (userOps > 0) userOps--; }
        }

        /// <summary>Accepted user requests still running (tests).</summary>
        public static int UserOps { get { lock (sync) return userOps; } }

        /// <summary>Takes the engine for a scan now, or null: another scan owns it or a user's start/stop is still running.</summary>
        public static object TryAcquire()
        {
            object t;
            lock (sync)
            {
                if (owner != null || userOps > 0) return null;
                owner = t = new object();
            }
            App.RaiseStatus();
            return t;
        }

        public enum AcquireResult { Acquired, Busy, Cancelled }

        /// <summary>
        /// Waits (at most <paramref name="waitMs"/>) until the user's start/stop requests accepted before the scan have finished,
        /// then takes the engine. Busy: another scan owns it, or the requests did not finish in time. Cancelled: the scan was
        /// cancelled before or while it waited (it never takes the engine then). No lock is held while it waits.
        /// </summary>
        public static async Task<(object Token, AcquireResult Result)> AcquireAsync(int waitMs = 30000, CancellationToken ct = default(CancellationToken))
        {
            var until = DateTime.UtcNow.AddMilliseconds(waitMs);
            while (true)
            {
                if (ct.IsCancellationRequested) return (null, AcquireResult.Cancelled);
                lock (sync) { if (owner != null) return (null, AcquireResult.Busy); }
                var t = TryAcquire();
                if (t != null)
                {
                    // cancelled in the same moment: the engine is given back untouched
                    if (ct.IsCancellationRequested) { Release(t); return (null, AcquireResult.Cancelled); }
                    return (t, AcquireResult.Acquired);
                }
                if (DateTime.UtcNow >= until) return (null, AcquireResult.Busy);
                try { await Task.Delay(50, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { return (null, AcquireResult.Cancelled); }
            }
        }

        /// <summary>Raised after a scan has released the engine (its restore has finished); handlers must not block.</summary>
        public static event Action Released;

        public static void Release(object token)
        {
            bool freed = false;
            lock (sync) { if (ReferenceEquals(owner, token)) { owner = null; freed = true; } }
            App.RaiseStatus();
            if (!freed) return;
            try { Conflicts.OnScanReleased(); } catch (Exception ign) { App.Ignored("Conflict check after the scan", ign); }
            try { Released?.Invoke(); } catch (Exception ign) { App.Ignored("Scan release handler", ign); }
        }

        public static bool Allows(object token)
        {
            lock (sync)
            {
                if (owner == null || ReferenceEquals(owner, token)) return true;
                Refused++;
                return false;
            }
        }
    }

    /// <summary>Candidate lists of the scopes (always in the stable catalog order, recommended first).</summary>
    public static class ScanCatalog
    {
        public static List<Profile> Candidates(ScanScope scope, EngineKind active, IEnumerable<Profile> all = null)
        {
            var src = (all ?? App.AllProfiles).ToList();
            switch (scope)
            {
                case ScanScope.Recommended: return ProfileCatalog.Order(src.Where(p => p.Tier == ProfileTier.Recommended));
                case ScanScope.ActiveEngine: return ProfileCatalog.Order(src.Where(p => p.Engine == active));
                case ScanScope.DriverlessOnly: return ProfileCatalog.Order(src.Where(p => !Engines.Of(p).UsesDriver));
                default: return ProfileCatalog.Order(src);
            }
        }
    }

    /// <summary>
    /// One scan request: candidates, targets, mode and the apply choice are fixed when it is created (a later change of the
    /// settings or of a profile does not change a running scan). Duplicate or unknown candidates and invalid targets are left
    /// out and listed in <see cref="Rejected"/>.
    /// </summary>
    public sealed class ScanRequest
    {
        public readonly ScanScope Scope;
        public readonly ScanMode Mode;
        public readonly bool AutoApply;
        public readonly bool WidenScope;
        public readonly bool Udp;
        public readonly string Source;
        public readonly IReadOnlyList<Profile> Candidates;
        public readonly IReadOnlyList<string> Targets;
        public readonly IReadOnlyList<string> Rejected;

        ScanRequest(ScanScope scope, ScanMode mode, bool autoApply, bool widen, bool udp, string source, List<Profile> c, List<string> t, List<string> rej)
        {
            Scope = scope; Mode = mode; AutoApply = autoApply && mode == ScanMode.StopOnFirstMatch; WidenScope = widen; Udp = udp; Source = source ?? "";
            Candidates = c.AsReadOnly(); Targets = t.AsReadOnly(); Rejected = rej.AsReadOnly();
        }

        public IEnumerable<string> CandidateIds => Candidates.Select(p => p.Id);

        public static ScanRequest Create(ScanScope scope, ScanMode mode, bool autoApply, IEnumerable<string> candidateIds, IEnumerable<string> targets,
                                         bool widen = false, bool udp = true, string source = "", IEnumerable<Profile> all = null)
        {
            var pool = (all ?? App.AllProfiles).ToList();
            var rej = new List<string>();
            var cands = new List<Profile>();
            foreach (var id in candidateIds ?? Enumerable.Empty<string>())
            {
                var p = pool.FirstOrDefault(x => x.Id == id);
                if (p == null) { rej.Add("candidate:" + ArgPolicy.CleanText(id ?? "", 40)); continue; }
                if (cands.Any(x => x.Id == id)) { rej.Add("duplicate:" + id); continue; }
                cands.Add(p.Snapshot());
            }
            // the catalog order: recommended first, stable
            cands = ProfileCatalog.Order(cands);
            var tl = new List<string>();
            foreach (var t in targets ?? Enumerable.Empty<string>())
            {
                string d = (t ?? "").ToLowerInvariant();
                if (!ScanTargets.IsValid(d)) { rej.Add("target:" + ArgPolicy.CleanText(t ?? "", 60)); continue; }
                if (tl.Contains(d)) continue;
                if (tl.Count >= ScanTargets.MaxTargets) { rej.Add("target:" + d); continue; }
                tl.Add(d);
            }
            return new ScanRequest(scope, mode, autoApply, widen, udp, source, cands, tl, rej);
        }

        /// <summary>A scope's candidates with the scanner's targets from the settings.</summary>
        public static ScanRequest ForScope(ScanScope scope, ScanMode mode, bool autoApply, string source, bool widen = false) =>
            Create(scope, mode, autoApply, ScanCatalog.Candidates(scope, App.Engine.Current.Kind).Select(p => p.Id),
                   App.Settings.TestTargets, widen, true, source);

        /// <summary>Simple "Find a working method and connect": the recommended candidates of every engine, stop at the first full success, apply it. The saved "try all" choice does not change it.</summary>
        public static ScanRequest SimpleConnect(string source = "simple") => ForScope(ScanScope.Recommended, ScanMode.StopOnFirstMatch, true, source);

        /// <summary>Automatic repair: the profiles of the active engine, the first full success is applied (as before).</summary>
        public static ScanRequest Heal() => ForScope(ScanScope.ActiveEngine, ScanMode.StopOnFirstMatch, true, "heal");
    }

    /// <summary>One target of one candidate: its two measurements (the second only after the first passed).</summary>
    public sealed class TargetRow
    {
        public string Host;
        public bool InScope = true;
        public bool Baseline;
        public TargetProbe R1, R2;
        public bool PassedBoth => InScope && R1?.Verdict == TargetVerdict.Pass && R2?.Verdict == TargetVerdict.Pass;
    }

    public sealed class ScanRow
    {
        public const string Pending = "pending", Testing = "testing", Skipped = "skipped", Unavailable = "unavailable", Invalid = "invalid",
                            StartFailed = "startFailed", Isolation = "isolation", Full = "full", Partial = "partial", Failed = "failed",
                            NoScope = "noScope", Cancelled = "cancelled";

        public Profile P;
        public string Status = Pending;
        public LocText Note;
        public string Code = "";
        public List<TargetRow> Targets = new List<TargetRow>();
        public int Required => Targets.Count(t => t.InScope);
        public int PassedBoth => Targets.Count(t => t.PassedBoth);
        /// <summary>Share of the required targets that passed in both rounds (percent); null when nothing was measured.</summary>
        public int? Score;
        /// <summary>Average time of the successful HTTPS measurements; null when there was none (never shown as 0 ms).</summary>
        public int? AvgMs;
        public StunResult Udp;
        public bool Widened;
        public int Order;
        public bool Tested;
        /// <summary>Why the candidate's measurement does not count: its process exited or lost its port during it (null: it ran throughout).</summary>
        public LocText Lost;

        public bool IsFull => Status == Full;
        public bool Measured => Status == Full || Status == Partial || Status == Failed;
        public string StatusText => Loc.T("scan.status." + Status);
        public IDpiEngine Engine => Engines.Of(P);
    }

    /// <summary>State before the scan (read from the engine, the SCM and the proxy settings – not only from the app settings).</summary>
    public sealed class EnvSnapshot
    {
        public string SelectedId = "";
        public string LastGoodbyeDpi = "", LastZapret = "", LastByeDpi = "";
        public EngineState State;
        public Profile ActiveProfile;
        public bool RunningAsService;
        public bool ServiceModeSetting;
        public ServiceInfo Service = new ServiceInfo();
        public bool ByeDpiAttached, ByeDpiSystemProxy;
        public string SystemProxy = "";
        public bool WasActive => State == EngineState.Running || State == EngineState.Starting;
        /// <summary>The scan stopped the original engine / the own service.</summary>
        public bool Suspended, ServiceStopped;
        public bool Restored;
    }

    /// <summary>The NSFShield service as the SCM reports it, and whether it runs an engine of this installation.</summary>
    public sealed class ServiceInfo
    {
        public bool Exists;
        /// <summary>Ok: the fields were read (Exists false: not found). AccessDenied / Error: nothing is known about the service.</summary>
        public ScmRead Read = ScmRead.Ok;
        /// <summary>The service is known not to exist (never true for an unreadable answer).</summary>
        public bool Missing => !Exists && (Read == ScmRead.Ok || Read == ScmRead.NotFound);
        /// <summary>The state could not be read: nothing may be decided (or changed) from it.</summary>
        public bool Unknown => Read == ScmRead.AccessDenied || Read == ScmRead.Error;
        public ServiceControllerStatus Status = ServiceControllerStatus.Stopped;
        public ServiceStartMode StartType = ServiceStartMode.Disabled;
        public string ImagePath = "";
        /// <summary>The engine of this installation the service runs (null: none, or the owner is unclear).</summary>
        public EngineKind? Owned;
        public bool Running => Exists && Status != ServiceControllerStatus.Stopped;
    }

    public sealed class SuspendResult
    {
        /// <summary>Why WinDivert candidates cannot be tried safely now (null: they can).</summary>
        public LocText DriverBlock;
        public string DriverBlockCode = "";
        public List<LocText> Notes = new List<LocText>();
    }

    /// <summary>A running candidate (its own process, port, list files and file locks).</summary>
    public interface ITrial : IDisposable
    {
        ProbeTransport Transport { get; }
        int Pid { get; }
        /// <summary>Does the candidate still run (and still own its port)? A measurement is only accepted while it does.</summary>
        bool Alive(out LocText why);
    }

    public sealed class TrialStart
    {
        public ITrial Trial;
        public LocText Error;
        public string Code = "";
        public bool Isolation;
        /// <summary>The failure concerns every candidate of the engine (missing files, integrity) or every WinDivert engine (driver).</summary>
        public bool EngineWide, DriverWide;
    }

    /// <summary>The domain lists of one candidate: the user's lists (never changed) or the temporary wider include list.</summary>
    public sealed class ListPlan
    {
        public List<string> Include, Exclude;
        public bool Widened;
        public List<string> Added = new List<string>();
        public List<LocText> Warnings = new List<LocText>();
        public Func<string, bool> InScope = h => true;
    }

    public sealed class RestoreReport
    {
        public List<LocText> Problems = new List<LocText>();
        public List<LocText> Done = new List<LocText>();
        public bool Ok => Problems.Count == 0;
    }

    /// <summary>Everything a scan does to the computer; the live implementation is <see cref="LiveScanHost"/>, the tests use fakes.</summary>
    public interface IScanHost
    {
        EnvSnapshot Capture();
        SuspendResult Suspend(EnvSnapshot env, object token);
        Task<bool> PretestAsync(CancellationToken ct);
        Task<DnsComparison> CompareDnsAsync(string host, bool skipDoh, CancellationToken ct);
        Task<TargetProbe> ProbeAsync(string host, ProbeTransport via, CancellationToken ct);
        Task<StunResult> StunAsync(CancellationToken ct);
        bool Available(Profile p, out LocText why);
        ListPlan PlanLists(Profile p, IReadOnlyList<string> targets, bool widen);
        Task<TrialStart> StartTrialAsync(Profile p, ListPlan lists, CancellationToken ct);
        void FlushDns();
        bool Apply(Profile p, EnvSnapshot env, object token, out LocText error);
        RestoreReport Restore(EnvSnapshot env, object token);
    }

    /// <summary>The lists a candidate is tried with (pure: settings in, plan out).</summary>
    public static class ScanLists
    {
        /// <summary>
        /// The user's include/exclude lists as the engine would use them; nothing in the settings or in data\lists is changed.
        /// With <paramref name="widen"/> the targets not covered by an active include list are added to a temporary copy (an
        /// excluded target stays excluded). A target outside the plan's scope is never counted as the profile's success.
        /// </summary>
        public static ListPlan Plan(IDpiEngine eng, AppSettings s, IReadOnlyList<string> targets, bool widen)
        {
            var plan = new ListPlan();
            bool incReq = Hostlists.IncludeOn(s), excReq = Hostlists.ExcludeOn(s);
            if (incReq && !eng.SupportsInclude) plan.Warnings.Add(new LocText("lists.includeUnsupported", eng.DisplayName));
            if (excReq && !eng.SupportsExclude) plan.Warnings.Add(new LocText("lists.excludeUnsupported", eng.DisplayName));
            if (incReq && eng.SupportsInclude) plan.Include = Hostlists.Clean(s.TargetDomains);
            if (excReq && eng.SupportsExclude) plan.Exclude = Hostlists.Clean(s.ExcludeDomains);
            if (widen && plan.Include != null)
                foreach (var t in targets)
                    if (!Domains.Covered(t, plan.Include) && !(plan.Exclude != null && Domains.Covered(t, plan.Exclude)) && plan.Include.Count < Hostlists.MaxEntries)
                    { plan.Include.Add(t); plan.Added.Add(t); }
            plan.Widened = plan.Added.Count > 0;
            var inc = plan.Include;
            var exc = plan.Exclude;
            plan.InScope = h => (inc == null || Domains.Covered(h, inc)) && (exc == null || !Domains.Covered(h, exc));
            return plan;
        }
    }

    /// <summary>What a scan found and did (the measured result, the suggested profile and the applied profile are separate).</summary>
    public sealed class ScanOutcome
    {
        public ScanRequest Request;
        public List<ScanRow> Rows = new List<ScanRow>();
        /// <summary>Best full success (StopOnFirstMatch: the first one).</summary>
        public ScanRow Suggested;
        /// <summary>The profile that was actually applied (only StopOnFirstMatch with auto apply, after a full success).</summary>
        public Profile Applied;
        public bool Busy, Cancelled, Aborted, ApplyFailed;
        public LocText ApplyError, Summary, NotAppliedWhy;
        public string FailCode = "";
        public bool? InternetOk;
        public List<DnsComparison> Dns = new List<DnsComparison>();
        public List<TargetRow> Baseline = new List<TargetRow>();
        public StunResult BaselineUdp;
        public RestoreReport Restore;
        public EnvSnapshot Env;
        public bool AllOpenWithout => Baseline.Count > 0 && Baseline.All(b => b.R1?.Verdict == TargetVerdict.Pass);
    }

    /// <summary>
    /// The smart scanner. It tries candidate profiles without the side effects of a normal start: the original state is
    /// recorded, the own WinDivert engine is paused (the SCM confirms a stopped service), every candidate runs as its own
    /// process with its own lists, port and file locks, and at the end one restore path brings back the original state
    /// (or the scan applies its result – only StopOnFirstMatch with auto apply after a full success in both rounds).
    /// </summary>
    public sealed class Scanner
    {
        public event Action<string, ScanLineKind> Line;
        public event Action<int, int, string> Progress;
        public event Action<ScanRow> RowChanged;

        public readonly ScanRequest Request;
        readonly IScanHost host;
        public readonly ScanOutcome Outcome = new ScanOutcome();
        public List<ScanRow> Rows => Outcome.Rows;

        public Scanner(ScanRequest request, IScanHost host = null)
        {
            Request = request;
            this.host = host ?? new LiveScanHost();
            Outcome.Request = request;
        }

        static LocText L(string key, params object[] args) => new LocText(key, args);

        void Emit(string mark, LocText text, ScanLineKind kind = ScanLineKind.Info)
        {
            string ui = mark + (text?.Text ?? ""), en = mark + (text?.English ?? "");
            App.Log("[Scan] " + en.Trim(), kind == ScanLineKind.Bad ? LogLevel.Warn : kind == ScanLineKind.Good ? LogLevel.Success : LogLevel.Info);
            App.Post(() => Line?.Invoke(ui, kind));
        }

        void Emit(LocText text, ScanLineKind kind = ScanLineKind.Info) => Emit("", text, kind);
        void Prog(int done, int total, string label) => App.Post(() => Progress?.Invoke(done, total, label));
        void Changed(ScanRow r) => App.Post(() => RowChanged?.Invoke(r));

        public async Task<ScanOutcome> RunAsync(CancellationToken ct)
        {
            var o = Outcome;
            // a start/stop the user asked for before the scan finishes first; then the scan records the state (never in between).
            // A scan cancelled before or while it waits records and pauses nothing and is not reported as "busy".
            var (token, got) = await ScanGate.AcquireAsync(30000, ct).ConfigureAwait(false);
            if (got == ScanGate.AcquireResult.Cancelled) { o.Cancelled = true; o.Summary = L("scan.cancelled"); return o; }
            if (token == null) { o.Busy = true; o.Summary = L("scan.busy"); return o; }
            ITrial trial = null;
            try
            {
                // an empty selection is reported; protection is not touched
                if (Request.Candidates.Count == 0) { o.Summary = L("scan.noCandidates"); Emit("✗ ", o.Summary, ScanLineKind.Warn); return o; }
                if (Request.Targets.Count == 0) { o.Summary = L("scan.noTargets"); Emit("✗ ", o.Summary, ScanLineKind.Warn); return o; }
                foreach (var r in Request.Rejected) Emit("   – ", L("scan.rejected", r), ScanLineKind.Muted);

                Prog(0, 1, Loc.T("scan.preparing"));
                o.Env = host.Capture();
                Emit(L("scan.env", o.Env.WasActive ? (o.Env.ActiveProfile?.Name ?? "") : Loc.T("scan.envOff"),
                       o.Env.RunningAsService ? Loc.T("home.mode.service") : Loc.T("home.mode.app")), ScanLineKind.Muted);
                var susp = await Task.Run(() => host.Suspend(o.Env, token)).ConfigureAwait(false);
                foreach (var n in susp.Notes) Emit("   ", n, ScanLineKind.Muted);
                if (susp.DriverBlock != null) Emit("   ! ", susp.DriverBlock, ScanLineKind.Warn);
                if (Request.Candidates.Any(p => Engines.Of(p).UsesDriver) && susp.DriverBlock == null)
                    Emit("   ", L("scan.driverNote"), ScanLineKind.Muted);
                ct.ThrowIfCancellationRequested();

                // ------------------------------------------------ 1) general connection (alone it never means "no internet")
                Emit("1/4  ", L("scan.step.internet"), ScanLineKind.Step);
                o.InternetOk = await host.PretestAsync(ct).ConfigureAwait(false);
                Emit(o.InternetOk == true ? "   ✓ " : "   ! ", L(o.InternetOk == true ? "scan.pretestOk" : "scan.pretestFailed"),
                     o.InternetOk == true ? ScanLineKind.Good : ScanLineKind.Warn);

                // ------------------------------------------------ 2) system DNS against DNS over HTTPS
                Emit("2/4  ", L("scan.step.dns"), ScanLineKind.Step);
                host.FlushDns();
                bool dohDown = false;
                foreach (var t in Request.Targets)
                {
                    ct.ThrowIfCancellationRequested();
                    var c = await host.CompareDnsAsync(t, dohDown, ct).ConfigureAwait(false);
                    if (c.Verdict == DnsVerdict.DohUnavailable) dohDown = true;
                    o.Dns.Add(c);
                    var kind = c.Verdict == DnsVerdict.Interference ? ScanLineKind.Warn : c.Ok == true ? ScanLineKind.Good : ScanLineKind.Muted;
                    Emit(c.Ok == true ? "   ✓ " : c.Ok == false ? "   ✗ " : "   ? ", c.Text, kind);
                }
                if (dohDown) Emit("   ", L("scan.dohDown"), ScanLineKind.Muted);
                if (o.Dns.Any(d => d.Verdict == DnsVerdict.Interference)) Emit("   ", L("scan.dohHint"), ScanLineKind.Muted);

                // ------------------------------------------------ 3) without protection: what opens anyway
                Emit("3/4  ", L("scan.step.baseline"), ScanLineKind.Step);
                var b1 = await RoundAsync(Request.Targets, ProbeTransport.Direct, ct).ConfigureAwait(false);
                o.Baseline = Request.Targets.Select((t, i) => new TargetRow { Host = t, R1 = b1[i], Baseline = true }).ToList();
                int openNow = o.Baseline.Count(b => b.R1.Verdict == TargetVerdict.Pass);
                Emit("   ", L("scan.baseline", openNow, Request.Targets.Count), openNow == 0 ? ScanLineKind.Muted : ScanLineKind.Info);
                if (Request.Udp)
                {
                    o.BaselineUdp = await host.StunAsync(ct).ConfigureAwait(false);
                    Emit("   ", L("scan.udpBaseline", StunText(o.BaselineUdp)), ScanLineKind.Muted);
                }

                // ------------------------------------------------ 4) candidates
                Emit("4/4  ", L(Request.Mode == ScanMode.StopOnFirstMatch ? "scan.step.firstMatch" : "scan.step.benchmark", Request.Candidates.Count), ScanLineKind.Step);
                var driverBlock = susp.DriverBlock;
                string driverCode = susp.DriverBlockCode;
                var engineBlock = new Dictionary<EngineKind, (LocText, string)>();
                int idx = 0;
                foreach (var p in Request.Candidates)
                {
                    ct.ThrowIfCancellationRequested();
                    var row = new ScanRow { P = p, Order = idx++ };
                    o.Rows.Add(row);
                    Prog(idx - 1, Request.Candidates.Count, p.Name);
                    var eng = Engines.Of(p);
                    if (!host.Available(p, out var why)) { Skip(row, ScanRow.Unavailable, why, "NSF-107"); continue; }
                    if (engineBlock.TryGetValue(eng.Kind, out var eb)) { Skip(row, ScanRow.Skipped, eb.Item1, eb.Item2); continue; }
                    if (eng.UsesDriver && driverBlock != null) { Skip(row, ScanRow.Skipped, driverBlock, driverCode); continue; }
                    if (!ArgPolicy.ValidateProfile(p, out string argErr)) { Skip(row, ScanRow.Invalid, L("engine.unsafeProfile", p.Name, argErr), "NSF-605"); continue; }

                    var plan = host.PlanLists(p, Request.Targets, Request.WidenScope);
                    row.Widened = plan.Widened;
                    foreach (var w in plan.Warnings) Emit("   ! ", w, ScanLineKind.Muted);
                    if (plan.Widened) Emit("   ! ", L("scan.widened", p.Name, string.Join(", ", plan.Added)), ScanLineKind.Warn);
                    row.Targets = Request.Targets.Select(t => new TargetRow { Host = t, InScope = plan.InScope(t) }).ToList();
                    if (row.Required == 0) { Skip(row, ScanRow.NoScope, L("scan.noScope", p.Name), "NSF-506"); continue; }

                    row.Status = ScanRow.Testing;
                    row.Tested = true;
                    Changed(row);
                    var ts = await host.StartTrialAsync(p, plan, ct).ConfigureAwait(false);
                    if (ts.Trial == null)
                    {
                        Skip(row, ts.Isolation ? ScanRow.Isolation : ScanRow.StartFailed, ts.Error, ts.Code);
                        row.Tested = true;
                        if (ts.DriverWide && eng.UsesDriver && driverBlock == null) { driverBlock = L("scan.block.driverFailed", ts.Code); driverCode = ts.Code; Emit("   ! ", driverBlock, ScanLineKind.Warn); }
                        if (ts.EngineWide && !engineBlock.ContainsKey(eng.Kind)) engineBlock[eng.Kind] = (L("scan.block.engineFailed", eng.DisplayName, ts.Code), ts.Code);
                        continue;
                    }
                    trial = ts.Trial;
                    try { await MeasureAsync(row, trial, ct).ConfigureAwait(false); }
                    finally { trial.Dispose(); trial = null; }
                    Evaluate(row);
                    Report(row);
                    Changed(row);
                    if (Request.Mode == ScanMode.StopOnFirstMatch && row.IsFull) break;
                }
                Prog(Request.Candidates.Count, Request.Candidates.Count, Loc.T("scan.done"));

                // ------------------------------------------------ result: suggested profile
                var ranked = Rank(o.Rows);
                o.Suggested = Request.Mode == ScanMode.StopOnFirstMatch ? o.Rows.FirstOrDefault(r => r.IsFull) : ranked.FirstOrDefault(r => r.IsFull);

                // ------------------------------------------------ apply (StopOnFirstMatch + auto apply only)
                if (Request.AutoApply && o.Suggested != null)
                {
                    ct.ThrowIfCancellationRequested();
                    var win = o.Suggested;
                    bool verified = true;
                    if (win.Widened)
                    {
                        // found with the temporary wider list: it must work with the real lists before it is applied
                        Emit("   ", L("scan.reverify", win.P.Name), ScanLineKind.Muted);
                        verified = await ReverifyAsync(win.P, ct).ConfigureAwait(false);
                        if (!verified) o.NotAppliedWhy = L("scan.notVerifiedReal", win.P.Name);
                    }
                    ct.ThrowIfCancellationRequested();
                    if (verified)
                    {
                        Emit("   ", L("scan.applying", win.P.Name), ScanLineKind.Muted);
                        bool ok = await Task.Run(() => { bool r = host.Apply(win.P, o.Env, token, out var err); o.ApplyError = err; return r; }).ConfigureAwait(false);
                        if (ok) { o.Applied = win.P; o.Env.Restored = true; }
                        else o.ApplyFailed = true;
                    }
                }
            }
            catch (OperationCanceledException) { o.Cancelled = true; }
            catch (Exception ex)
            {
                o.Aborted = true;
                Emit(L("scan.error", ex.Message), ScanLineKind.Bad);
            }
            finally
            {
                // the one cleanup path: the candidate stops, then the original state comes back (unless the result was applied)
                try { trial?.Dispose(); } catch (Exception ign) { App.Ignored("Scan trial could not be closed", ign); }
                if (o.Env != null && o.Applied == null)
                {
                    try { o.Restore = await Task.Run(() => host.Restore(o.Env, token)).ConfigureAwait(false); }
                    catch (Exception ex) { o.Restore = new RestoreReport(); o.Restore.Problems.Add(L("scan.restore.error", ex.Message)); }
                }
                foreach (var r in o.Rows.Where(r => r.Status == ScanRow.Testing || r.Status == ScanRow.Pending)) { r.Status = ScanRow.Cancelled; Changed(r); }
                Finish(o);
                ScanGate.Release(token);
            }
            return o;
        }

        void Skip(ScanRow row, string status, LocText why, string code)
        {
            row.Status = status;
            row.Note = why;
            row.Code = code ?? "";
            Emit("   – ", L("scan.skipped", row.P.Name, why), ScanLineKind.Muted);
            Changed(row);
        }

        async Task<List<TargetProbe>> RoundAsync(IEnumerable<string> hosts, ProbeTransport via, CancellationToken ct)
        {
            using (var sem = new SemaphoreSlim(4))
            {
                var tasks = hosts.Select(async h =>
                {
                    await sem.WaitAsync(ct).ConfigureAwait(false);
                    try { return await host.ProbeAsync(h, via, ct).ConfigureAwait(false); }
                    finally { sem.Release(); }
                }).ToList();
                try { return (await Task.WhenAll(tasks).ConfigureAwait(false)).ToList(); }
                catch
                {
                    // every probe has ended before the round returns (no task outlives a cancelled scan)
                    try { await Task.WhenAll(tasks.Select(t => t.ContinueWith(_ => { }))).ConfigureAwait(false); } catch { }
                    throw;
                }
            }
        }

        /// <summary>How often a running candidate is checked during its measurement.</summary>
        internal static int AliveCheckMs = 300;

        /// <summary>
        /// Measures a candidate while watching it: if its process exits (or loses its port) the measurement is cancelled at once
        /// and the row is marked; a success is only accepted when the candidate still runs (and owns its port) at the end.
        /// </summary>
        async Task MeasureAsync(ScanRow row, ITrial trial, CancellationToken ct)
        {
            using (var lcts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                var watch = WatchAsync(trial, row, lcts);
                try { await MeasureCoreAsync(row, trial.Transport, lcts.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested && row.Lost != null) { /* the candidate is gone */ }
                finally
                {
                    try { lcts.Cancel(); } catch (ObjectDisposedException) { }
                    try { await watch.ConfigureAwait(false); } catch { }
                }
                if (row.Lost == null && !trial.Alive(out var why)) row.Lost = why;
            }
        }

        static async Task WatchAsync(ITrial trial, ScanRow row, CancellationTokenSource lcts)
        {
            try
            {
                while (!lcts.IsCancellationRequested)
                {
                    await Task.Delay(AliveCheckMs, lcts.Token).ConfigureAwait(false);
                    if (!trial.Alive(out var why)) { row.Lost = why; lcts.Cancel(); return; }
                }
            }
            catch (OperationCanceledException) { }
            catch (ObjectDisposedException) { }
        }

        /// <summary>Two independent rounds (new connections; the second only for the targets that passed the first) and UDP.</summary>
        async Task MeasureCoreAsync(ScanRow row, ProbeTransport via, CancellationToken ct)
        {
            await Task.Delay(400, ct).ConfigureAwait(false);
            host.FlushDns();
            var scoped = row.Targets.Where(t => t.InScope).ToList();
            var r1 = await RoundAsync(scoped.Select(t => t.Host), via, ct).ConfigureAwait(false);
            for (int i = 0; i < scoped.Count; i++) scoped[i].R1 = r1[i];
            var again = scoped.Where(t => t.R1.Verdict == TargetVerdict.Pass).ToList();
            if (again.Count > 0)
            {
                await Task.Delay(600, ct).ConfigureAwait(false);
                host.FlushDns();
                var r2 = await RoundAsync(again.Select(t => t.Host), via, ct).ConfigureAwait(false);
                for (int i = 0; i < again.Count; i++) again[i].R2 = r2[i];
            }
            var cap = Capability.Of(row.P);
            if (cap.TcpProxyOnly) row.Udp = new StunResult { Status = StunStatus.NotMeasured, Scope = "na" };
            else if (Request.Udp)
            {
                row.Udp = await host.StunAsync(ct).ConfigureAwait(false);
                row.Udp.Scope = cap.UdpScope(Stun.Port);
            }
        }

        /// <summary>Score, latency and status of a measured row.</summary>
        public static void Evaluate(ScanRow row)
        {
            int req = row.Required, both = row.PassedBoth;
            row.Score = req > 0 ? both * 100 / req : (int?)null;
            var ms = row.Targets.Where(t => t.InScope).SelectMany(t => new[] { t.R1, t.R2 })
                        .Where(x => x != null && x.Verdict == TargetVerdict.Pass && x.TotalMs.HasValue).Select(x => x.TotalMs.Value).ToList();
            row.AvgMs = ms.Count > 0 ? (int)Math.Round(ms.Average()) : (int?)null;
            bool any = row.Targets.Any(t => t.InScope && t.R1 != null && (t.R1.Verdict == TargetVerdict.Pass || t.R1.Verdict == TargetVerdict.Partial));
            row.Status = req == 0 ? ScanRow.NoScope : both == req ? ScanRow.Full : both > 0 || any ? ScanRow.Partial : ScanRow.Failed;
            if (row.Status != ScanRow.Full)
            {
                var fails = row.Targets.Where(t => t.InScope).Select(t => t.R2 != null && t.R2.Verdict != TargetVerdict.Pass ? t.R2 : t.R1)
                                       .Where(x => x != null && x.Verdict != TargetVerdict.Pass).ToList();
                var top = fails.GroupBy(f => f.Code).OrderByDescending(g => g.Count()).FirstOrDefault();
                row.Code = top?.Key ?? "";
                row.Note = top?.First().Detail;
            }
            if (row.Lost != null)
            {
                // the candidate exited or lost its port during the measurement: whatever was measured is not its result
                row.Status = ScanRow.Failed;
                row.Code = "NSF-602";
                row.Note = row.Lost;
            }
        }

        /// <summary>
        /// Ranking: score, then the average HTTPS time of the successful measurements (no measurement = last), then the catalog
        /// order, then the id. Optional UDP/STUN and N/A never change it.
        /// </summary>
        public static List<ScanRow> Rank(IEnumerable<ScanRow> rows) =>
            rows.Where(r => r.Measured).OrderByDescending(r => r.Score ?? -1).ThenBy(r => r.AvgMs ?? int.MaxValue)
                .ThenBy(r => r.Order).ThenBy(r => r.P.Id, StringComparer.Ordinal).ToList();

        void Report(ScanRow row)
        {
            string ms = row.AvgMs.HasValue ? row.AvgMs + " ms" : "—";
            var text = L("scan.rowResult", row.P.Name, row.StatusText, row.Score.HasValue ? row.Score + "%" : "—", ms, row.PassedBoth, row.Required);
            Emit(row.IsFull ? "   ✓ " : row.Status == ScanRow.Partial ? "   ~ " : "   ✗ ", text,
                 row.IsFull ? ScanLineKind.Good : row.Status == ScanRow.Partial ? ScanLineKind.Warn : ScanLineKind.Bad);
            if (!row.IsFull && row.Note != null) Emit("      ", row.Note, ScanLineKind.Muted);
            if (row.Udp != null) Emit("      ", L("scan.udpRow", StunText(row.Udp)), ScanLineKind.Muted);
        }

        public static string StunText(StunResult u)
        {
            if (u == null) return "—";
            if (u.Scope == "na" || u.Status == StunStatus.NotMeasured) return Loc.T("scan.udp.na");
            string s = u.Status == StunStatus.Ok ? Loc.T("scan.udp.ok", u.Ms ?? 0) : Loc.T("scan.udp." + u.Status);
            return s + (u.Scope == "general" ? " · " + Loc.T("scan.udp.general") : u.Scope == "profile" ? " · " + Loc.T("scan.udp.profile") : "");
        }

        async Task<bool> ReverifyAsync(Profile p, CancellationToken ct)
        {
            var plan = host.PlanLists(p, Request.Targets, false);
            var row = new ScanRow { P = p, Targets = Request.Targets.Select(t => new TargetRow { Host = t, InScope = plan.InScope(t) }).ToList() };
            if (row.Required == 0) return false;
            var ts = await host.StartTrialAsync(p, plan, ct).ConfigureAwait(false);
            if (ts.Trial == null) return false;
            try { await MeasureAsync(row, ts.Trial, ct).ConfigureAwait(false); }
            finally { ts.Trial.Dispose(); }
            Evaluate(row);
            return row.IsFull;
        }

        void Finish(ScanOutcome o)
        {
            var s = App.Settings;
            if (o.Busy) return;
            if (o.Applied != null)
            {
                o.Summary = L("scan.applied", o.Applied.Name, o.Suggested?.AvgMs.HasValue == true ? o.Suggested.AvgMs + " ms" : "—");
                Emit("✓ ", o.Summary, ScanLineKind.Good);
            }
            else if (o.Cancelled) { o.Summary = L("scan.cancelled"); Emit(o.Summary, ScanLineKind.Warn); }
            else if (o.ApplyFailed) { o.Summary = L("scan.applyFailed", o.Suggested?.P.Name ?? "", o.ApplyError); Emit("✗ ", o.Summary, ScanLineKind.Bad); }
            else if (o.Suggested != null)
            {
                o.Summary = L(Request.Mode == ScanMode.FullBenchmark ? "scan.suggestedBenchmark" : "scan.suggested", o.Suggested.P.Name);
                Emit("✓ ", o.Summary, ScanLineKind.Good);
                if (o.NotAppliedWhy != null) Emit("   ", o.NotAppliedWhy, ScanLineKind.Warn);
            }
            else if (o.Summary == null && o.Rows.Count > 0)
            {
                o.FailCode = GuessFailCode(o);
                var none = L("scan.noneWorked");
                o.Summary = o.FailCode.Length > 0 ? L("scan.noneWorkedCause", none, o.FailCode, ErrorCatalog.Get(o.FailCode)?.Title ?? "") : none;
                Emit("✗ ", o.Summary, ScanLineKind.Bad);
                if (o.FailCode.Length > 0 && !o.Aborted) App.Problems.Report(o.FailCode, L("scan.problemSource"));
            }
            if (o.AllOpenWithout && o.Rows.Any(r => r.Measured)) Emit("   ", L("scan.openWithout"), ScanLineKind.Muted);
            if (o.Restore != null)
            {
                foreach (var d in o.Restore.Done) Emit("   ", d, ScanLineKind.Muted);
                foreach (var pr in o.Restore.Problems) Emit("   ! ", pr, ScanLineKind.Bad);
            }
            // only the time and the result name are kept; candidates never become the selected profile here
            if (o.Rows.Count > 0 && s != null)
            {
                s.LastScanTime = DateTime.Now;
                s.LastScanResult = o.Applied?.Name ?? o.Suggested?.P.Name ?? "";
                App.Save();
            }
            Actions.LastHeal = DateTime.Now;   // auto-repair must not kick in again right after a scan
            bool success = o.Applied != null && (o.Restore == null || o.Restore.Ok);
            if (o.Rows.Count > 0)
                History.Add(new HistoryEntry
                {
                    Time = DateTime.Now, Kind = "scan", Profile = (o.Applied ?? o.Suggested?.P)?.Name ?? "", Ok = success ? 1 : 0, Total = 1, Running = success,
                    Note = Loc.T("scan.historyNote", o.Summary?.Text ?? "", o.Rows.Count(r => r.Tested)),
                });
        }

        static string GuessFailCode(ScanOutcome o)
        {
            var tested = o.Rows.Where(r => r.Measured).ToList();
            if (tested.Count == 0)
            {
                var codes0 = o.Rows.Select(r => r.Code).Where(c => !string.IsNullOrEmpty(c)).ToList();
                return codes0.GroupBy(c => c).OrderByDescending(g => g.Count()).Select(g => g.Key).FirstOrDefault() ?? "";
            }
            // the fixed connection test failed and nothing opened, not even without protection or through DNS: no internet
            if (o.InternetOk == false && o.Baseline.All(b => b.R1?.Stage == ProbeStage.Dns || b.R1?.Stage == ProbeStage.Connect) &&
                tested.All(r => r.Targets.All(t => t.R1 == null || t.R1.Stage <= ProbeStage.Connect)))
                return "NSF-801";
            if (o.Dns.Count > 0 && o.Dns.All(d => d.Verdict == DnsVerdict.Interference) && tested.All(r => r.Targets.All(t => t.R1 == null || t.R1.Stage == ProbeStage.Dns)))
                return "NSF-403";
            var codes = tested.SelectMany(r => r.Targets).Select(t => t.R2 != null && t.R2.Verdict != TargetVerdict.Pass ? t.R2 : t.R1)
                              .Where(x => x != null && x.Verdict != TargetVerdict.Pass && x.Code.Length > 0).Select(x => x.Code).ToList();
            if (codes.Count == 0) return "NSF-505";
            return codes.GroupBy(c => c).OrderByDescending(g => g.Count()).First().Key;
        }

        /// <summary>The non-DNS (DPI) parameters of a profile: profiles with the same signature behave the same.</summary>
        internal static string DpiSignature(Profile p)
        {
            if (!p.IsGoodbyeDpi) return p.Engine + ":" + string.Join(" ", Engines.Tokens(p.EngineArgs));
            if (p.UseRaw)
            {
                var t = (p.RawArgs ?? "").Split(new[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).ToList();
                var keep = new List<string>();
                for (int i = 0; i < t.Count; i++)
                {
                    if (t[i].StartsWith("--dns")) { if (t[i] != "--dns-verb") i++; continue; }
                    keep.Add(t[i]);
                }
                return "raw:" + string.Join(" ", keep);
            }
            var c = p.CloneAsCustom();
            c.Dns = DnsChoice.None;
            c.CustomDns4 = c.CustomDns6 = "";
            return c.BuildArgs(null);
        }
    }
}
