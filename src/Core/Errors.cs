using System;
using System.Collections.Generic;
using System.Linq;

namespace NSFShield
{
    public enum Severity { Info, Warning, Error }

    /// <summary>Actions the "Fix" buttons of the error code page can perform.</summary>
    public enum FixKind
    {
        None, RestartAsAdmin, OpenAppFolder, ResetAll, ResolveConflicts, FlushDns, FindBest, OpenProfiles,
        OpenDnsPage, TestDnsServers, StartBfe, OpenWindowsSecurity, RestartDiscord, StartProtection, OpenLog,
        OpenSites, OpenProxySettings, OpenDateTime, DisableServiceMode, OpenHosts, SiteAnalysis, OpenSettings, OpenProxyPage, ReportFalsePositive
    }

    /// <summary>
    /// One entry of the error catalog. The code, category, severity and fixes are fixed in code; all text comes from
    /// the language files ("errors.&lt;code&gt;.title|summary|causes|steps|detect") so it follows the UI language.
    /// </summary>
    public sealed class ErrorInfo
    {
        public string Code;
        /// <summary>Category id (see <see cref="ErrorCatalog.Categories"/>).</summary>
        public string Category;
        public Severity Severity = Severity.Error;
        public FixKind Fix, Fix2;

        string K(string field) => "errors." + Code + "." + field;
        public string Title => Loc.T(K("title"));
        public string Summary => Loc.T(K("summary"));
        public string[] Causes => Loc.List(K("causes"));
        public string[] Steps => Loc.List(K("steps"));
        public string Detect => Loc.Has(K("detect")) ? Loc.T(K("detect")) : "";
        public string CategoryName => ErrorCatalog.CategoryName(Category);

        public static string FixLabel(FixKind f) => f == FixKind.None ? "" : Loc.T("errors.fix." + f);
    }

    /// <summary>All error/warning types the app knows, with their solutions.</summary>
    public static class ErrorCatalog
    {
        public const string CatApp = "app", CatDriver = "driver", CatConflict = "conflict", CatDns = "dns", CatAccess = "access",
                            CatGoodbyeDpi = "goodbyedpi", CatService = "service", CatNetwork = "network", CatDiscord = "discord", CatProxy = "proxy";

        /// <summary>Category ids in display order.</summary>
        public static readonly string[] Categories =
            { CatApp, CatDriver, CatConflict, CatDns, CatAccess, CatGoodbyeDpi, CatService, CatNetwork, CatDiscord, CatProxy };

        public static string CategoryName(string id) => Loc.T("errors.category." + id);

        static ErrorInfo E(string code, string cat, Severity sev, FixKind fix = FixKind.None, FixKind fix2 = FixKind.None)
            => new ErrorInfo { Code = code, Category = cat, Severity = sev, Fix = fix, Fix2 = fix2 };

        public static readonly List<ErrorInfo> All = new List<ErrorInfo>
        {
            // ------------------------------------------------------------ 1xx application
            E("NSF-101", CatApp, Severity.Error, FixKind.RestartAsAdmin),
            E("NSF-102", CatApp, Severity.Error, FixKind.OpenAppFolder, FixKind.ReportFalsePositive),
            E("NSF-103", CatApp, Severity.Warning, FixKind.OpenAppFolder),
            E("NSF-104", CatApp, Severity.Warning, FixKind.OpenAppFolder, FixKind.OpenWindowsSecurity),
            E("NSF-105", CatApp, Severity.Error, FixKind.OpenAppFolder, FixKind.OpenLog),
            E("NSF-106", CatApp, Severity.Info, FixKind.OpenLog),
            E("NSF-107", CatApp, Severity.Error, FixKind.OpenProfiles),

            // ------------------------------------------------------------ 2xx driver
            E("NSF-201", CatDriver, Severity.Error, FixKind.ResetAll, FixKind.OpenLog),
            E("NSF-202", CatDriver, Severity.Error, FixKind.OpenAppFolder, FixKind.ReportFalsePositive),
            E("NSF-203", CatDriver, Severity.Error, FixKind.OpenAppFolder),
            E("NSF-204", CatDriver, Severity.Error, FixKind.ReportFalsePositive, FixKind.OpenWindowsSecurity),
            E("NSF-205", CatDriver, Severity.Error, FixKind.StartBfe),
            E("NSF-206", CatDriver, Severity.Error, FixKind.ResetAll),
            E("NSF-207", CatDriver, Severity.Info, FixKind.ReportFalsePositive),

            // ------------------------------------------------------------ 3xx conflicts
            E("NSF-301", CatConflict, Severity.Warning, FixKind.ResolveConflicts),
            E("NSF-302", CatConflict, Severity.Warning, FixKind.ResolveConflicts),
            E("NSF-303", CatConflict, Severity.Warning, FixKind.StartProtection),
            E("NSF-304", CatConflict, Severity.Warning, FixKind.OpenProxySettings),

            // ------------------------------------------------------------ 4xx DNS
            E("NSF-401", CatDns, Severity.Warning, FixKind.FindBest, FixKind.OpenDnsPage),
            E("NSF-402", CatDns, Severity.Error, FixKind.TestDnsServers, FixKind.FindBest),
            E("NSF-403", CatDns, Severity.Warning, FixKind.FlushDns, FixKind.OpenDnsPage),
            E("NSF-404", CatDns, Severity.Warning, FixKind.OpenProfiles),
            E("NSF-405", CatDns, Severity.Warning, FixKind.OpenHosts, FixKind.FlushDns),

            // ------------------------------------------------------------ 5xx access
            E("NSF-501", CatAccess, Severity.Error, FixKind.FindBest, FixKind.OpenProfiles),
            E("NSF-502", CatAccess, Severity.Error, FixKind.FindBest, FixKind.SiteAnalysis),
            E("NSF-503", CatAccess, Severity.Error, FixKind.SiteAnalysis),
            E("NSF-504", CatAccess, Severity.Error, FixKind.FlushDns, FixKind.OpenDateTime),
            E("NSF-505", CatAccess, Severity.Warning, FixKind.OpenSites, FixKind.FindBest),
            E("NSF-506", CatAccess, Severity.Warning, FixKind.OpenSites),

            // ------------------------------------------------------------ 6xx GoodbyeDPI
            E("NSF-601", CatGoodbyeDpi, Severity.Error, FixKind.OpenLog, FixKind.ResetAll),
            E("NSF-602", CatGoodbyeDpi, Severity.Error, FixKind.StartProtection, FixKind.OpenLog),
            E("NSF-603", CatGoodbyeDpi, Severity.Error, FixKind.OpenProfiles),
            E("NSF-604", CatGoodbyeDpi, Severity.Info, FixKind.OpenLog),
            E("NSF-605", CatGoodbyeDpi, Severity.Error, FixKind.OpenProfiles),
            E("NSF-606", CatGoodbyeDpi, Severity.Warning, FixKind.OpenSites, FixKind.OpenProfiles),

            // ------------------------------------------------------------ 7xx service
            E("NSF-701", CatService, Severity.Error, FixKind.DisableServiceMode, FixKind.ResetAll),
            E("NSF-702", CatService, Severity.Error, FixKind.DisableServiceMode, FixKind.OpenLog),
            E("NSF-703", CatService, Severity.Warning, FixKind.OpenSettings),
            E("NSF-704", CatService, Severity.Warning, FixKind.StartProtection),
            E("NSF-705", CatService, Severity.Warning, FixKind.OpenSettings),

            // ------------------------------------------------------------ 8xx network
            E("NSF-801", CatNetwork, Severity.Error),
            E("NSF-802", CatNetwork, Severity.Warning, FixKind.OpenProxySettings),
            E("NSF-803", CatNetwork, Severity.Error, FixKind.OpenDateTime),

            // ------------------------------------------------------------ 9xx Discord
            E("NSF-901", CatDiscord, Severity.Info, FixKind.RestartDiscord),
            E("NSF-902", CatDiscord, Severity.Warning, FixKind.RestartDiscord, FixKind.OpenSites),
            E("NSF-903", CatDiscord, Severity.Info, FixKind.RestartDiscord),
            E("NSF-904", CatDiscord, Severity.Warning, FixKind.RestartDiscord, FixKind.FlushDns),

            // ------------------------------------------------------------ proxy
            E("NSF-805", CatProxy, Severity.Error, FixKind.OpenProxyPage),
            E("NSF-806", CatProxy, Severity.Error, FixKind.OpenProxyPage),
            E("NSF-807", CatProxy, Severity.Warning, FixKind.OpenProxyPage),
            E("NSF-808", CatProxy, Severity.Error, FixKind.OpenSettings, FixKind.OpenLog),
            E("NSF-809", CatProxy, Severity.Warning, FixKind.OpenProxyPage, FixKind.OpenSettings),
        };

        public static ErrorInfo Get(string code) => All.FirstOrDefault(e => e.Code == code);
    }

    public sealed class DetectedProblem
    {
        public string Code;
        /// <summary>Extra detail (technical text or a <see cref="LocText"/> rendered in the current language).</summary>
        public object DetailValue;
        public DateTime Time;
        public string Detail => DetailValue?.ToString() ?? "";
        public ErrorInfo Info => ErrorCatalog.Get(Code);
    }

    /// <summary>Problems detected at run time (home page banner and Troubleshooting page).</summary>
    public sealed class ProblemCenter
    {
        readonly object gate = new object();
        readonly List<DetectedProblem> items = new List<DetectedProblem>();

        /// <param name="detail">Technical text (address, path…) or a <see cref="LocText"/>.</param>
        public void Report(string code, object detail = null)
        {
            if (ErrorCatalog.Get(code) == null) return;
            lock (gate)
            {
                items.RemoveAll(p => p.Code == code);
                items.Add(new DetectedProblem { Code = code, DetailValue = detail ?? "", Time = DateTime.Now });
            }
            App.RaiseStatus();
        }

        public void Clear(string code)
        {
            bool removed;
            lock (gate) removed = items.RemoveAll(p => p.Code == code) > 0;
            if (removed) App.RaiseStatus();
        }

        public void ClearWhere(Func<ErrorInfo, bool> pred)
        {
            bool removed;
            lock (gate) removed = items.RemoveAll(p => p.Info != null && pred(p.Info)) > 0;
            if (removed) App.RaiseStatus();
        }

        public List<DetectedProblem> Snapshot()
        {
            lock (gate) return items.OrderByDescending(p => (int)(p.Info?.Severity ?? Severity.Info)).ThenByDescending(p => p.Time).ToList();
        }

        public DetectedProblem Top => Snapshot().FirstOrDefault();
    }
}
