#if PREVIEW
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace NSFShield
{
    /// <summary>
    /// pre-release security audit (B1–B13, M1–M11, L1–L4): one offline regression test (or more) per finding. Fakes only:
    /// a fake SCM, a fake netsh/adapter view, an in-memory Windows proxy key, loopback servers and temporary folders. Nothing
    /// here touches a real service, driver, DNS/proxy setting, running protection or another program.
    /// </summary>
    static partial class SelfTest
    {
        // ============================================================================ helpers

        /// <summary>An SCM with several services (by name), configurable start/config failures.</summary>
        sealed class Scm6 : IServiceControl
        {
            public readonly Dictionary<string, ServiceInfo> S = new Dictionary<string, ServiceInfo>(StringComparer.OrdinalIgnoreCase);
            public bool StartWorks = true, ConfigWrites = true;
            public int Stops, Starts, Deletes, Configs, Creates, SetCommands;
            public Func<string, EngineKind?> OwnedFn = ServiceOwnership.OwnedEngine;
            ServiceInfo Get(string n) => S.TryGetValue(n, out var i) ? i : null;
            static ServiceInfo Copy(ServiceInfo i) => i == null ? new ServiceInfo() : new ServiceInfo { Exists = i.Exists, Status = i.Status, StartType = i.StartType, ImagePath = i.ImagePath, Owned = i.Owned };
            public ServiceInfo Query(string n) => Copy(Get(n));
            public bool Stop(string n, TimeSpan w) { Stops++; var i = Get(n); if (i != null) i.Status = ServiceControllerStatus.Stopped; return true; }
            public bool Start(string n, TimeSpan w) { Starts++; var i = Get(n); if (i == null || !StartWorks) return false; i.Status = ServiceControllerStatus.Running; return true; }
            public bool SetStartType(string n, ServiceStartMode m) { var i = Get(n); if (i == null) return false; i.StartType = m; return true; }
            public bool Create(string n, string bin, string d, out string o) { Creates++; o = ""; S[n] = new ServiceInfo { Exists = true, ImagePath = bin, StartType = ServiceStartMode.Automatic, Owned = OwnedFn(bin) }; return true; }
            public bool Configure(string n, string bin, out string o)
            {
                Configs++; o = "";
                var i = Get(n);
                if (i == null) return false;
                if (ConfigWrites) { i.ImagePath = bin; i.Owned = OwnedFn(bin); }
                i.StartType = ServiceStartMode.Automatic;
                return true;
            }
            public bool SetCommand(string n, string bin, out string o) { SetCommands++; o = ""; var i = Get(n); if (i == null) return false; i.ImagePath = bin; i.Owned = OwnedFn(bin); return true; }
            public bool Delete(string n, out string o) { Deletes++; o = ""; return S.Remove(n); }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CreateHardLinkW(string newName, string existing, IntPtr sec);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint GetShortPathNameW(string longPath, StringBuilder buf, uint len);

        /// <summary>A directory junction made with Windows' own mklink (no administrator rights needed).</summary>
        static bool MakeJunction(string link, string target)
        {
            using (var p = Process.Start(new ProcessStartInfo(Sys.SystemExe("cmd.exe"), "/c mklink /J \"" + link + "\" \"" + target + "\"")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true }))
            {
                p.StandardOutput.ReadToEnd();
                p.WaitForExit(10000);
            }
            return Directory.Exists(link) && (File.GetAttributes(link) & FileAttributes.ReparsePoint) != 0;
        }

        static void RemoveJunction(string link)
        {
            try { if (Directory.Exists(link) && (File.GetAttributes(link) & FileAttributes.ReparsePoint) != 0) Directory.Delete(link, false); } catch { }
        }

        static string Own6(EngineKind k, string args) => "\"" + Engines.Get(k).ExePath + "\" " + args;

        /// <summary>A stream that sends one byte every <see cref="Gap"/> ms forever (a "slow drip" server).</summary>
        sealed class DripStream : Stream
        {
            public int Gap = 200;
            public override bool CanRead => true; public override bool CanSeek => false; public override bool CanWrite => true;
            public override long Length => 0; public override long Position { get; set; }
            public override void Flush() { }
            public override int Read(byte[] b, int o, int c) { Thread.Sleep(Gap); b[o] = (byte)'X'; return 1; }
            public override async Task<int> ReadAsync(byte[] b, int o, int c, CancellationToken ct) { await Task.Delay(Gap).ConfigureAwait(false); b[o] = (byte)'X'; return 1; }
            public override long Seek(long off, SeekOrigin so) => 0;
            public override void SetLength(long v) { }
            public override void Write(byte[] b, int o, int c) { }
            public override Task WriteAsync(byte[] b, int o, int c, CancellationToken ct) => Task.CompletedTask;
        }

        /// <summary>A conflict source whose first step takes a while (two callers meet during it).</summary>
        sealed class SlowSource6 : IConflictSource
        {
            public IConflictSource Inner;
            public int Calls;
            public ConflictContext Context() { Interlocked.Increment(ref Calls); Thread.Sleep(300); return Inner.Context(); }
            public List<ProcEntry> Processes(IEnumerable<string> names) => Inner.Processes(names);
            public ScmEntry Service(string name) => Inner.Service(name);
            public List<AdapterInfo> Adapters() => Inner.Adapters();
            public int? BestRouteIndex() => Inner.BestRouteIndex();
        }

        static void Stage6Tests(Action<string, bool, string> Check)
        {
            var oldSettings = App.Settings;
            if (App.Engine == null) App.Engine = new Engine();
            string root = Path.Combine(Path.GetTempPath(), "nsf stage6 " + Guid.NewGuid().ToString("N").Substring(0, 6));
            Directory.CreateDirectory(root);
            var ctx = SynchronizationContext.Current;
            try
            {
                SynchronizationContext.SetSynchronizationContext(null);
                App.Settings = new AppSettings();
                App.Settings.Normalize();
                Updater6(Check, root);
                Paths6(Check, root);
                Proxy6(Check);
                Owners6(Check, root);
                Service6(Check);
                Dns6(Check);
                ByeDpi6(Check);
                Lists6(Check, root);
                Support6(Check);
                Race6(Check);
                Settings6(Check, root);
                Probe6(Check);
                Bridge6(Check);
                Misc6(Check);
                SynchronizationContext.SetSynchronizationContext(ctx);
                Window6(Check);
                SynchronizationContext.SetSynchronizationContext(null);
            }
            catch (Exception ex) { Check("stage 6 tests ran without an exception", false, ex.GetType().Name + ": " + ex.Message + " @ " + (ex.StackTrace ?? "").Split('\n').FirstOrDefault()?.Trim()); }
            finally
            {
                SynchronizationContext.SetSynchronizationContext(ctx);
                App.Settings = oldSettings;
                try { Directory.Delete(root, true); } catch { }
            }
        }

        // ============================================================================ B1, B12, M3, M8: updater and installer switch

        static void Updater6(Action<string, bool, string> Check, string root)
        {
            string repo = Repo;
            // B1: a rejected --apply-update never touches the target: no data folder, no log, nothing started from it
            string dst = Path.Combine(root, "b1 target");
            Directory.CreateDirectory(Path.Combine(dst, "notes"));
            File.WriteAllText(Path.Combine(dst, "NSFShield.exe"), "not a program");
            string fake = Path.Combine(root, "b1 elsewhere");
            Directory.CreateDirectory(fake);
            int rc = Updater.Apply(fake, dst, 999999, "1.0.0", false);
            Check("B1 apply: rejected arguments leave the target untouched (no data folder, no update.log) and return 2",
                  rc == 2 && !Directory.Exists(Path.Combine(dst, "data")) && Directory.GetFileSystemEntries(dst).Length == 2, "rc " + rc);
            string updSrc = File.ReadAllText(Path.Combine(repo, @"src\Core\Updater.cs"));
            int ap = updSrc.IndexOf("public static int Apply(string src, string dst, int pid, string oldVer, bool resume)", StringComparison.Ordinal);
            string apBody = updSrc.Substring(ap, updSrc.IndexOf("internal static int Apply(", ap, StringComparison.Ordinal) - ap);
            Check("B1 apply: on rejection only the setup package's protected location may be reopened (fresh guard check), nothing is written",
                  apBody.Contains("InnoInstallLocation()") && apBody.Contains("InstallGuard.Check(inst") && !apBody.Contains("AppendAllText") && !apBody.Contains("CreateDirectory"), "");

            // B1: no always-true publisher check; the honest identity check really compares product and version
            string selfExe = Process.GetCurrentProcess().MainModule.FileName;
            string notepad = Path.Combine(Environment.SystemDirectory, "notepad.exe");
            Check("B1 identity: the always-true publisher check is gone; product + version are really compared (the SHA-256 comes from GitHub)",
                  !updSrc.Contains("CheckPublisher") && !File.ReadAllText(Path.Combine(repo, @"src\Core\InstallerSwitch.cs")).Contains("CheckPublisher") &&
                  Updater.VerifyIdentity(selfExe, Updater.Current, false, out _) && !Updater.VerifyIdentity(selfExe, new Version(9, 9, 9), false, out _) &&
                  !Updater.VerifyIdentity(selfExe, Updater.Current, true, out _) && (!File.Exists(notepad) || !Updater.VerifyIdentity(notepad, null, false, out _)), "");

            // B1: the local setup package hook exists in the preview build only
            string isw = File.ReadAllText(Path.Combine(repo, @"src\Core\InstallerSwitch.cs")), prg = File.ReadAllText(Path.Combine(repo, @"src\Program.cs"));
            bool Guarded(string src, string needle)
            {
                int i = src.IndexOf(needle, StringComparison.Ordinal);
                if (i < 0) return true;
                int ifp = src.LastIndexOf("#if PREVIEW", i, StringComparison.Ordinal), end = src.LastIndexOf("#endif", i, StringComparison.Ordinal);
                return ifp >= 0 && ifp > end;
            }
            Check("B1 switch: --switch-to-installer <path> <hash> (local setup package) is compiled into the preview build only",
                  Guarded(isw, "public const string LocalArg") && Guarded(isw, "public static Updater.Prepared PrepareLocal") &&
                  Guarded(prg, "InstallerSwitch.LocalArg") && Guarded(File.ReadAllText(Path.Combine(repo, @"src\UI\SwitchDialog.cs")), "InstallerSwitch.PrepareLocal"), "");
            string relExe = Path.Combine(App.BaseDir, @"package\NSF Shield\NSFShield.exe");
            // the release exe of the build in this folder (build.ps1 gives it the fixed source time, so its date says nothing)
            if (File.Exists(relExe))
            {
                var bin = File.ReadAllBytes(relExe);
                var needle = Encoding.Unicode.GetBytes("--switch-to-installer");
                bool found = false;
                for (int i = 0; i + needle.Length <= bin.Length && !found; i++)
                {
                    int j = 0;
                    while (j < needle.Length && bin[i + j] == needle[j]) j++;
                    found = j == needle.Length;
                }
                Check("B1 switch: the release NSFShield.exe of this build has no --switch-to-installer argument", !found, "");
            }
            // B1: setup runs the program already in {app} only from the verified protected folder; no name-based taskkill
            string iss = File.ReadAllText(Path.Combine(repo, @"installer\NSFShield.iss"));
            // stage 7: the folder is verified by the new program of the package (owner, write permissions, physical path), not by a prefix
            int pti = iss.IndexOf("function PrepareToInstall", StringComparison.Ordinal);
            Check("B1 setup: --prepare-upgrade of the installed program runs only after the folder was verified as protected; otherwise nothing runs; setup's own steps always follow",
                  pti > 0 && iss.IndexOf("DirState := CheckAppDir;", pti, StringComparison.Ordinal) > pti &&
                  iss.IndexOf("DirState := CheckAppDir;", pti, StringComparison.Ordinal) < iss.IndexOf("if Exec(Exe, '--prepare-upgrade'", pti, StringComparison.Ordinal) &&
                  iss.Contains("State := StopOwnService;") && iss.Contains("if not StopFolderProcesses(True) then") && iss.Contains("FILE_ATTRIBUTE_REPARSE_POINT") &&
                  iss.Contains("if FileExists(Exe) and AppDirTrusted then"), "");

            // B12: a failed copy removes what the update added, restores the old files (verified) and only then reopens
            string s12 = Path.Combine(root, "b12 src"), d12 = Path.Combine(root, "b12 dst");
            Directory.CreateDirectory(Path.Combine(s12, "newdir"));
            File.WriteAllText(Path.Combine(s12, "NSFShield.exe"), "new");
            File.WriteAllText(Path.Combine(s12, @"newdir\new.txt"), "added");
            File.WriteAllText(Path.Combine(s12, "zzz.txt"), "blocked");
            Directory.CreateDirectory(Path.Combine(d12, "zzz.txt"));     // a folder where the update wants a file: the copy fails
            File.WriteAllText(Path.Combine(d12, "NSFShield.exe"), "old");
            Updater.WriteManifest(Updater.ManifestPath(s12), Updater.HashTree(s12));   // stage 7: the current protocol has a manifest
            int rc12 = Updater.Apply(s12, d12, 999999, "1.0.0", false, false);
            string log12 = File.Exists(Path.Combine(d12, @"data\update.log")) ? File.ReadAllText(Path.Combine(d12, @"data\update.log")) : "";
            Check("B12 rollback: files and folders the failed update added are removed, the old exe is back (verified)",
                  rc12 == 1 && !Directory.Exists(Path.Combine(d12, "newdir")) && File.ReadAllText(Path.Combine(d12, "NSFShield.exe")) == "old" &&
                  log12.Contains("restored files verified"), "rc " + rc12);
            string bak = Path.Combine(root, "b12 bak"), tgt = Path.Combine(root, "b12 tgt");
            Directory.CreateDirectory(bak); Directory.CreateDirectory(tgt);
            File.WriteAllText(Path.Combine(bak, "NSFShield.exe"), "old");
            bool j12 = MakeJunction(Path.Combine(bak, "linked"), root);
            var lines = new List<string>();
            bool restored = Updater.RestoreBackup(bak, tgt, new List<string>(), l => lines.Add(l));
            RemoveJunction(Path.Combine(bak, "linked"));
            int ia = updSrc.IndexOf("if (!intact)", StringComparison.Ordinal);
            Check("B12 rollback: a rollback that cannot be completed reports a recovery error and the exe is not started (exit code 3)",
                  j12 && !restored && ia > 0 && updSrc.IndexOf("return 3;", ia, StringComparison.Ordinal) > ia &&
                  updSrc.IndexOf("return 3;", ia, StringComparison.Ordinal) < updSrc.IndexOf("Process.Start(new ProcessStartInfo(dstExe, \"--tray --update-failed\"", ia, StringComparison.Ordinal), string.Join(" | ", lines));

            // M3: the bytes really written are counted; the package folder must match its manifest before it is installed
            bool tooBig = Throws<InvalidDataException>(() => Updater.CopyLimited(new MemoryStream(new byte[100]), new MemoryStream(), 0, 50));
            long fine = Updater.CopyLimited(new MemoryStream(new byte[100]), new MemoryStream(), 10, 500);
            Check("M3 extract: the limit counts the bytes actually written (not the size in the zip header)",
                  tooBig && fine == 110 && updSrc.Contains("totalBytes = CopyLimited(es, cs, totalBytes, MaxExtractBytes);") && !updSrc.Contains("totalBytes += e.Length"), "");
            string pkg = Path.Combine(root, "m3 pkg");
            Directory.CreateDirectory(Path.Combine(pkg, "bin"));
            File.WriteAllText(Path.Combine(pkg, "NSFShield.exe"), "exe");
            File.WriteAllText(Path.Combine(pkg, @"bin\a.dll"), "dll");
            var man = Updater.HashTree(pkg);
            Updater.WriteManifest(Updater.ManifestPath(pkg), man);
            var back = Updater.ReadManifest(Updater.ManifestPath(pkg), out bool bad0);
            bool same = Updater.MatchesManifest(pkg, back, out _);
            File.WriteAllText(Path.Combine(pkg, "extra.dll"), "planted");
            bool extra = !Updater.MatchesManifest(pkg, back, out string w1);
            File.Delete(Path.Combine(pkg, "extra.dll"));
            File.WriteAllText(Path.Combine(pkg, @"bin\a.dll"), "changed");
            bool changed = !Updater.MatchesManifest(pkg, back, out string w2);
            File.WriteAllText(Updater.ManifestPath(pkg), "zz  ..\\x\r\n");
            Updater.ReadManifest(Updater.ManifestPath(pkg), out bool bad1);
            Check("M3 package: the extracted set and hashes are checked again before installing (extra, changed, invalid manifest refused)",
                  same && !bad0 && extra && w1.Contains("extra.dll") && changed && w2.Contains("a.dll") && bad1 &&
                  updSrc.Contains("MatchesManifest(prep.Root, prep.Manifest") && updSrc.Contains("MatchesManifest(src, manifest"), w1 + " / " + w2);

            // M8: one decision for the automatic check, the manual check and the window
            UpdateInfo Rel(bool zip, bool zipHash, bool setup) => new UpdateInfo
            {
                Version = new Version(Updater.Current.Major + 1, 0, 0),
                AssetUrl = zip ? "https://github.com/x/y/releases/download/v9/NSF-Shield-9.0.0.zip" : "", Sha256 = zipHash ? new string('a', 64) : "",
                SetupUrl = setup ? "https://github.com/x/y/releases/download/v9/NSF-Shield-9.0.0-Setup.exe" : "", SetupSha256 = setup ? new string('b', 64) : "",
            };
            var old = new UpdateInfo { Version = Updater.Current };
            Check("M8 update: the same fit decision everywhere (a portable copy with a Setup-only release is offered the switch, never an empty zip download)",
                  Updater.FitFor(Rel(false, false, true), false) == Updater.Fit.NeedsInstalledVersion && Updater.FitFor(Rel(false, false, true), true) == Updater.Fit.Ready &&
                  Updater.FitFor(Rel(true, true, false), false) == Updater.Fit.Ready && Updater.FitFor(Rel(true, false, false), false) == Updater.Fit.NoPackage &&
                  Updater.FitFor(old, false) == Updater.Fit.UpToDate, "");
            string ud = File.ReadAllText(Path.Combine(repo, @"src\UI\UpdateDialog.cs"));
            int dl = ud.IndexOf("await Task.Delay(600, token);", StringComparison.Ordinal);
            Check("M8 update: the pause before installing can be cancelled and the cancel is checked again right before the start",
                  dl > 0 && ud.IndexOf("token.ThrowIfCancellationRequested();", dl, StringComparison.Ordinal) > dl &&
                  ud.IndexOf("token.ThrowIfCancellationRequested();", dl, StringComparison.Ordinal) < ud.IndexOf("Updater.StartSetup(prep)", dl, StringComparison.Ordinal) &&
                  ud.Contains("var fit = Updater.LastFit;") && ud.Contains("Updater.FitFor(info, installed) != Updater.Fit.Ready"), "");
        }

        // ============================================================================ B2, M4, M10: links, final paths, short names

        static void Paths6(Action<string, bool, string> Check, string root)
        {
            string repo = Repo;
            string real = Path.Combine(root, "real dir");
            Directory.CreateDirectory(Path.Combine(real, "sub"));
            string link = Path.Combine(root, "link dir");
            bool made = MakeJunction(link, real);
            try
            {
                Check("B2 paths: a junction is a redirect, a normal folder is not; the chain check finds it above a sub folder",
                      made && PathSafety.Reparse(link) == PathSafety.Kind.Redirect && PathSafety.Reparse(real) == PathSafety.Kind.None &&
                      PathSafety.UnsafeInChain(Path.Combine(link, "sub")) == link && PathSafety.UnsafeInChain(Path.Combine(real, "sub")) == null &&
                      PathSafety.ResolvesToItself(real) && !PathSafety.ResolvesToItself(Path.Combine(link, "sub")), "");
                bool guardLink = InstallGuard.Check(Path.Combine(link, "sub"), out string why);
                Check("B2 guard: a folder reached through a junction is never protected (reason names the link)", made && !guardLink && why.Contains(link), why);
                string esrc = File.ReadAllText(Path.Combine(repo, @"src\Core\Engine.cs")), stsrc = File.ReadAllText(Path.Combine(repo, @"src\Core\Startup.cs"));
                int ss = esrc.IndexOf("bool StartService(", StringComparison.Ordinal);
                Check("B2 guard: the service start and the elevated startup task check the folder again right before (no cached result)",
                      ss > 0 && esrc.Contains("FreshGuard = () => (InstallGuard.CheckFresh(out string why), why);") && esrc.IndexOf("FreshGuard();", ss, StringComparison.Ordinal) > ss &&
                      esrc.IndexOf("FreshGuard();", ss, StringComparison.Ordinal) < esrc.IndexOf("ServiceStart.Run(", ss, StringComparison.Ordinal) &&
                      stsrc.Contains("InstallGuard.CheckFresh(out string why)") && !stsrc.Contains("if (!InstallGuard.IsProtected)"), "");

                // M4: a driver file must be a single hard link that resolves to its own path
                string sys1 = Path.Combine(root, "m4.sys"), hl = Path.Combine(root, "m4 second link.sys");
                File.WriteAllText(sys1, "driver");
                bool plain;
                using (var fs = new FileStream(sys1, FileMode.Open, FileAccess.Read, FileShare.Read)) plain = Integrity.PlainFileAt(fs, sys1);
                bool hard = CreateHardLinkW(hl, sys1, IntPtr.Zero);
                bool afterLink;
                using (var fs = new FileStream(sys1, FileMode.Open, FileAccess.Read, FileShare.Read)) afterLink = Integrity.PlainFileAt(fs, sys1);
                File.WriteAllText(Path.Combine(real, "drv.sys"), "driver");
                bool viaJunction;
                using (var fs = new FileStream(Path.Combine(link, "drv.sys"), FileMode.Open, FileAccess.Read, FileShare.Read)) viaJunction = Integrity.PlainFileAt(fs, Path.Combine(link, "drv.sys"));
                Check("M4 driver: checked at the load boundary – a plain file passes, a second hard link or a path through a junction does not",
                      plain && hard && !afterLink && made && !viaJunction, "");
                // M4: a hash mismatch closes the handle (the file can be deleted right after)
                string bogus = Path.Combine(root, "m4 ciadpi.exe");
                File.WriteAllText(bogus, "not ciadpi");
                var hold = Integrity.VerifyAndLock(new[] { (@"byedpi\ciadpi.exe", bogus) }, out string ierr);
                bool deletable;
                try { File.Delete(bogus); deletable = !File.Exists(bogus); } catch { deletable = false; }
                Check("M4 integrity: a failed check leaves no open handle behind", hold == null && ierr.Length > 0 && deletable, ierr);
            }
            finally { RemoveJunction(link); }

            // M10: owners and driver folders are compared in their long form (an 8.3 short name still matches)
            string longDir = Path.Combine(root, "a rather long folder name for short names");
            Directory.CreateDirectory(longDir);
            string longFile = Path.Combine(longDir, "WinDivert64.sys");
            File.WriteAllText(longFile, "x");
            var sb = new StringBuilder(1024);
            uint n = GetShortPathNameW(longFile, sb, (uint)sb.Capacity);
            string shortFile = n > 0 && n < sb.Capacity ? sb.ToString(0, (int)n) : longFile;
            if (!string.Equals(shortFile, longFile, StringComparison.OrdinalIgnoreCase))
                Check("M10 paths: an 8.3 short path matches its long form (driver folder and owner checks)",
                      PathSafety.Same(shortFile, longFile) && DriverControl.DriverInFolder(@"\??\" + shortFile, longDir) && PathSafety.Inside(shortFile, longDir), shortFile);
            string issText = File.ReadAllText(Path.Combine(repo, @"installer\NSFShield.iss"));
            Check("M10 setup: service states come from the SCM API as numbers (not found / access denied / query error / stopped told apart); no 'sc query' text parsing",
                  issText.Contains("external 'QueryServiceStatus@advapi32.dll stdcall'") && issText.Contains("SVC_ACCESS_DENIED") && issText.Contains("SVC_QUERY_ERROR") &&
                  issText.Contains("ERROR_SERVICE_DOES_NOT_EXIST") && !issText.Contains("'query \"'") && issText.Contains("function PhysicalInFolder(P, Dir: String): Boolean;"), "");
        }

        // ============================================================================ B3, M7: proxies

        static void Proxy6(Action<string, bool, string> Check)
        {
            bool h1 = ProxyTools.TryParse("https://user:pw@10.1.2.3:8443", ProxyKind.Http, out var ph, out string eh);
            bool h2 = ProxyTools.TryParse("socks4://10.1.2.3:1080", ProxyKind.Http, out _, out _);
            bool ok1 = ProxyTools.TryParse("http://10.1.2.3:8080", ProxyKind.Socks5, out var p1, out _);
            bool ok2 = ProxyTools.TryParse("socks5://u:p@10.1.2.3:1080", ProxyKind.Http, out var p2, out _);
            Check("B3 proxy: an https:// proxy is refused with its own message (never stored as plain HTTP); http:// and socks5:// work",
                  !h1 && ph == null && eh == Loc.T("proxy.parse.httpsUnsupported") && !h2 && ok1 && p1.Kind == ProxyKind.Http && ok2 && p2.Kind == ProxyKind.Socks5, eh);
            var s = new AppSettings();
            s.Proxies.Add(new ProxyEntry { Host = "https://10.1.2.3", Port = 8443 });
            s.Proxies.Add(new ProxyEntry { Host = "10.1.2.3", Port = 8080 });
            s.Proxies.Add(new ProxyEntry { Host = "10.1.2.4", Port = 8080, Kind = (ProxyKind)7 });
            s.Normalize();
            var bad = new ProxyEntry { Host = "https://10.1.2.3", Port = 8443, User = "u", Password = "secret" };
            var r = ProxyTools.Test(bad, "discord.com", 2000, false, false);
            Check("B3 proxy: an invalid entry is dropped when the settings are read and refused before any connection (no credentials sent)",
                  s.Proxies.Count == 1 && s.Proxies[0].Host == "10.1.2.3" && !r.Ok && !r.Reach && r.Code == "NSF-805" && !ProxyBridge.Ensure(bad, out _), r.Message);

            // M7: the one SOCKS5 encoder: IPv6 as ATYP 4 (16 bytes), IPv4 as ATYP 1, names as ATYP 3
            var v6 = ProxyTools.Socks5Connect("2001:db8::1", 443);
            var v6b = ProxyTools.Socks5Connect("[2001:db8::1]", 443);
            var v4 = ProxyTools.Socks5Connect("192.0.2.1", 80);
            var nm = ProxyTools.Socks5Connect("discord.com", 443);
            string bridgeSrc = File.ReadAllText(Path.Combine(Repo, @"src\Core\ProxyBridge.cs")), probeSrc = File.ReadAllText(Path.Combine(Repo, @"src\Core\NetProbe.cs"));
            Check("M7 socks: numeric IPv6 is sent as ATYP 4 with 16 bytes; one encoder for the test, the bridge and the scanner",
                  v6.Length == 22 && v6[3] == 4 && v6b.SequenceEqual(v6) && v4.Length == 10 && v4[3] == 1 && nm[3] == 3 && nm[4] == 11 &&
                  probeSrc.Contains("ProxyTools.Socks5Connect(ip.ToString(), port)") && !File.ReadAllText(Path.Combine(Repo, @"src\Core\Proxy.cs")).Contains("conn.Add(3); conn.Add((byte)hb.Length)"), "");
            var info = new ProxyTestResult();
            ProxyTools.ParseExitInfo("ip=203.0.113.9\nloc=TR\nip=<script>\nloc=toolong\n", info);
            bool big = Throws<InvalidDataException>(() => ProxyTools.ReadLimited(new MemoryStream(new byte[ProxyTools.MaxExitInfoBytes + 1]), ProxyTools.MaxExitInfoBytes));
            string pxSrc = File.ReadAllText(Path.Combine(Repo, @"src\Core\Proxy.cs"));
            Check("M7 exit info: normal TLS validation (no accept-all callback), a small answer limit, only an IP and a two-letter country are taken",
                  !pxSrc.Contains("(a, b, c, e) => true") && pxSrc.Contains("TlsPolicy.Accept(e)") && big && info.ExitIp == "203.0.113.9" && info.Country == "TR", info.ExitIp + " " + info.Country);
        }

        static void Bridge6(Action<string, bool, string> Check)
        {
            // M7: the bridge's stop closes every accepted tunnel; a client that sends nothing is cut after the head time limit
            var up = new TcpListener(IPAddress.Loopback, 0);
            up.Start();
            int upPort = ((IPEndPoint)up.LocalEndpoint).Port;
            var held = new List<TcpClient>();
            var upTask = Task.Run(async () =>
            {
                try
                {
                    for (int i = 0; i < 2; i++)
                    {
                        var c = await up.AcceptTcpClientAsync().ConfigureAwait(false);
                        lock (held) held.Add(c);
                        var st = c.GetStream();
                        var b = new byte[64];
                        await st.ReadAsync(b, 0, 64).ConfigureAwait(false);          // greeting
                        await st.WriteAsync(new byte[] { 5, 0 }, 0, 2).ConfigureAwait(false);
                        await st.ReadAsync(b, 0, 64).ConfigureAwait(false);          // CONNECT
                        await st.WriteAsync(new byte[] { 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 }, 0, 10).ConfigureAwait(false);
                    }
                }
                catch { }
            });
            int FreePort() { var f = new TcpListener(IPAddress.Loopback, 0); f.Start(); int n = ((IPEndPoint)f.LocalEndpoint).Port; f.Stop(); return n; }
            int local = FreePort(), local2 = FreePort();
            var p = new ProxyEntry { Id = "stage6-bridge", Kind = ProxyKind.Socks5, Host = "127.0.0.1", Port = upPort, LocalPort = local };
            var p2 = new ProxyEntry { Id = "stage6-bridge-idle", Kind = ProxyKind.Socks5, Host = "127.0.0.1", Port = upPort, LocalPort = local2 };
            int oldTimeout = ProxyBridge.HeaderTimeoutMs;
            bool started = ProxyBridge.Ensure(p, out string err);
            int closed = 0;
            bool tunnelCut = false, idleCut = false;
            try
            {
                if (started)
                {
                    using (var cl = new TcpClient())
                    {
                        cl.Connect(IPAddress.Loopback, local);
                        var cs = cl.GetStream();
                        cs.ReadTimeout = 4000;
                        var req = Encoding.ASCII.GetBytes("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
                        cs.Write(req, 0, req.Length);
                        var buf = new byte[256];
                        int got = cs.Read(buf, 0, buf.Length);   // "200 Connection established"
                        Thread.Sleep(200);
                        closed = ProxyBridge.Stop(p.Id);
                        try { tunnelCut = got > 0 && cs.Read(buf, 0, buf.Length) == 0; } catch (IOException) { tunnelCut = true; }
                    }
                    ProxyBridge.HeaderTimeoutMs = 400;
                    ProxyBridge.Ensure(p2, out _);
                    using (var idle = new TcpClient())
                    {
                        idle.Connect(IPAddress.Loopback, local2);
                        var st = idle.GetStream();
                        st.ReadTimeout = 4000;
                        var sw = Stopwatch.StartNew();
                        try { idleCut = st.Read(new byte[8], 0, 8) == 0 && sw.ElapsedMilliseconds < 3500; } catch (IOException) { idleCut = sw.ElapsedMilliseconds < 3500; }
                    }
                }
            }
            finally
            {
                ProxyBridge.HeaderTimeoutMs = oldTimeout;
                ProxyBridge.Stop(p.Id);
                ProxyBridge.Stop(p2.Id);
                try { up.Stop(); } catch { }
                lock (held) foreach (var c in held) try { c.Close(); } catch { }
            }
            Check("M7 bridge: stopping a bridge closes its open tunnels; a client without a request is cut after the head time limit",
                  started && closed >= 1 && tunnelCut && idleCut, err + " closed " + closed);
        }

        // ============================================================================ B4: owners of processes and SCM entries

        static void Owners6(Action<string, bool, string> Check, string root)
        {
            string ownExe = Path.Combine(root, @"apps\Tool\tool.exe"), otherExe = Path.Combine(root, @"apps\Other\tool.exe");
            Directory.CreateDirectory(Path.GetDirectoryName(ownExe)); Directory.CreateDirectory(Path.GetDirectoryName(otherExe));
            File.WriteAllText(ownExe, ""); File.WriteAllText(otherExe, "");
            var rule = new ProxyApp { ExePath = ownExe, Mode = AppProxyMode.Chromium };
            string discordRoot = Path.Combine(root, @"Local\Discord");
            Directory.CreateDirectory(Path.Combine(discordRoot, "app-1.0.9"));
            var drule = new ProxyApp { ExePath = Path.Combine(discordRoot, "Update.exe"), Mode = AppProxyMode.Discord };
            Check("B4 programs: 'close running copies' matches the full path only (same name elsewhere, unreadable path or another Discord install are kept)",
                  AppProxy.IsCopyOf(rule, ownExe) && !AppProxy.IsCopyOf(rule, otherExe) && !AppProxy.IsCopyOf(rule, null) &&
                  AppProxy.IsCopyOf(drule, Path.Combine(discordRoot, @"app-1.0.9\Discord.exe")) && !AppProxy.IsCopyOf(drule, Path.Combine(root, @"Local\DiscordPTB\app-1.0.9\Discord.exe")) &&
                  !AppProxy.IsCopyOf(drule, Path.Combine(discordRoot, @"other\Discord.exe")), "");

            // B4: uninstall removes only SCM entries proven to be this installation's
            var scm = new Scm6();
            scm.S[Engine.ServiceName] = new ServiceInfo { Exists = true, Status = ServiceControllerStatus.Running, ImagePath = "\"C:\\Other\\bin\\zapret\\winws.exe\" x" };
            scm.S["WinDivert"] = new ServiceInfo { Exists = true, Status = ServiceControllerStatus.Running, ImagePath = @"\??\C:\Other\bin\zapret\WinDivert64.sys" };
            var rep = new UninstallReport();
            Engine.RemoveOwnedEntries(scm, rep, false, ip => false, ip => false);
            bool keptForeign = scm.S.ContainsKey(Engine.ServiceName) && scm.S.ContainsKey("WinDivert") && scm.Deletes == 0 && scm.Stops == 0;
            scm.S[Engine.ServiceName].ImagePath = Own6(EngineKind.Zapret, "x");
            scm.S["WinDivert"].ImagePath = @"\??\" + Path.Combine(Engines.BinRoot, @"zapret\WinDivert64.sys");
            var rep2 = new UninstallReport();
            Engine.RemoveOwnedEntries(scm, rep2, true, ip => true, ip => true);
            bool ownRemovedDriverKept = !scm.S.ContainsKey(Engine.ServiceName) && scm.S.ContainsKey("WinDivert");
            string esrc = File.ReadAllText(Path.Combine(Repo, @"src\Core\Engine.cs"));
            Check("B4 uninstall: another installation's service and driver entries (or unreadable owners) are kept; this installation's are removed",
                  keptForeign && rep.English.Contains("kept") && ownRemovedDriverKept && rep2.English.Contains("removed") &&
                  esrc.Contains("ServiceOwnership.OwnedEngineVerified(ip) != null") && esrc.Contains("DriverControl.DriverInFolderVerified(ip, App.BaseDir)"), rep.English.Replace("\n", " "));
            string iss = File.ReadAllText(Path.Combine(Repo, @"installer\NSFShield.iss"));
            Check("B4 setup: no name-based taskkill; processes of the folder are matched by the physical path of the allowed executables (Win32 API, no script host)",
                  !iss.Contains("taskkill.exe") && iss.Contains("QueryFullProcessImageNameW(H, 0, Buf, Size)") && iss.Contains("if not IsAllowedExe(Path, IncludeApp) then") &&
                  iss.IndexOf("power" + "shell", StringComparison.OrdinalIgnoreCase) < 0, "");
        }

        // ============================================================================ B5, B6: the service

        static void Service6(Action<string, bool, string> Check)
        {
            string own = Own6(EngineKind.Zapret, "--wf-tcp=443 --dpi-desync=fake"), foreign = "\"C:\\Other DPI\\bin\\zapret\\winws.exe\" --wf-tcp=443";
            var oldScm = Engine.Scm;
            try
            {
                // B5: StopInternal stops the NSFShield service only when it is this installation's (or on an explicit take-over)
                var scm = new Scm6();
                scm.S[Engine.ServiceName] = new ServiceInfo { Exists = true, Status = ServiceControllerStatus.Running, ImagePath = foreign };
                Engine.Scm = scm;
                var stopInternal = typeof(Engine).GetMethod("StopInternal", BindingFlags.Instance | BindingFlags.NonPublic);
                var e = new Engine();
                stopInternal.Invoke(e, new object[] { false });
                bool foreignKept = scm.Stops == 0 && scm.S[Engine.ServiceName].Status == ServiceControllerStatus.Running;
                stopInternal.Invoke(e, new object[] { true });
                bool takeOverStops = scm.Stops == 1;
                scm.S[Engine.ServiceName] = new ServiceInfo { Exists = true, Status = ServiceControllerStatus.Running, ImagePath = own, Owned = EngineKind.Zapret };
                stopInternal.Invoke(e, new object[] { false });
                bool ownStops = scm.Stops == 2;
                string shSrc = File.ReadAllText(Path.Combine(Repo, @"src\Core\ScanHost.cs"));
                Check("B5 scan apply: the apply never takes over (takeOver: false) and a foreign NSFShield service is not stopped by it",
                      shSrc.Contains("App.Engine.Start(p, false, token, takeOver: false)") && foreignKept && takeOverStops && ownStops, "");
                var scmF = new Scm6();
                scmF.S[Engine.ServiceName] = new ServiceInfo { Exists = true, Status = ServiceControllerStatus.Stopped, ImagePath = foreign, StartType = ServiceStartMode.Manual };
                var rf = ServiceStart.Run(scmF, Engine.ServiceName, own, false, null);
                Check("B5 service: without take-over another installation's service is not changed", !rf.Ok && rf.Error.Key == "engine.serviceForeign" && scmF.Configs == 0 && scmF.S[Engine.ServiceName].ImagePath == foreign, "");

                // B6: a failed start undoes the change and checks it in the SCM
                var scmN = new Scm6 { StartWorks = false };
                var rn = ServiceStart.Run(scmN, Engine.ServiceName, own, false, null);
                Check("B6 service: a service created by a failed start is removed again", !rn.Ok && rn.RolledBack == true && !scmN.S.ContainsKey(Engine.ServiceName) && scmN.Creates == 1, rn.RollbackDetail);
                string oldCmd = Own6(EngineKind.Zapret, "--wf-tcp=80,443 --dpi-desync=split");
                var scmE = new Scm6 { StartWorks = false };
                scmE.S[Engine.ServiceName] = new ServiceInfo { Exists = true, Status = ServiceControllerStatus.Stopped, ImagePath = oldCmd, StartType = ServiceStartMode.Manual, Owned = EngineKind.Zapret };
                var re = ServiceStart.Run(scmE, Engine.ServiceName, own, false, null);
                var after = scmE.Query(Engine.ServiceName);
                Check("B6 service: an existing service gets its old command line, start type and state back after a failed start (read back)",
                      !re.Ok && re.RolledBack == true && after.ImagePath == oldCmd && after.StartType == ServiceStartMode.Manual && !after.Running, re.RollbackDetail);
                var scmV = new Scm6 { ConfigWrites = false };
                scmV.S[Engine.ServiceName] = new ServiceInfo { Exists = true, Status = ServiceControllerStatus.Running, ImagePath = oldCmd, StartType = ServiceStartMode.Automatic, Owned = EngineKind.Zapret };
                var rv = ServiceStart.Run(scmV, Engine.ServiceName, own, false, null);
                Check("B6 service: a command line that does not read back as written counts as a failure and is undone",
                      !rv.Ok && rv.Error.Key == "engine.serviceNotVerified" && scmV.Query(Engine.ServiceName).Running && scmV.Query(Engine.ServiceName).ImagePath == oldCmd, "");
                // B6: after a scan the service must be as before it (created → removed, changed → old command back)
                var scmC = new Scm6();
                scmC.S[Engine.ServiceName] = new ServiceInfo { Exists = true, Status = ServiceControllerStatus.Stopped, ImagePath = own, Owned = EngineKind.Zapret, StartType = ServiceStartMode.Automatic };
                var p1 = LiveScanHost.RestoreServiceConfig(scmC, new EnvSnapshot { Service = new ServiceInfo() });
                var scmR = new Scm6();
                scmR.S[Engine.ServiceName] = new ServiceInfo { Exists = true, Status = ServiceControllerStatus.Stopped, ImagePath = own, Owned = EngineKind.Zapret, StartType = ServiceStartMode.Automatic };
                var envR = new EnvSnapshot { Service = new ServiceInfo { Exists = true, Status = ServiceControllerStatus.Running, ImagePath = oldCmd, Owned = EngineKind.Zapret, StartType = ServiceStartMode.Automatic } };
                var p2 = LiveScanHost.RestoreServiceConfig(scmR, envR);
                Check("B6 restore: a service the scan created is removed; a changed command line of this installation goes back to the one before the scan",
                      p1.Count == 0 && !scmC.S.ContainsKey(Engine.ServiceName) && p2.Count == 0 && scmR.S[Engine.ServiceName].ImagePath == oldCmd && scmR.S[Engine.ServiceName].Status == ServiceControllerStatus.Running, "");
            }
            finally { Engine.Scm = oldScm; }
        }

        // ============================================================================ B7: DNS / DoH restore

        static void Dns6(Action<string, bool, string> Check)
        {
            var oldNetsh = SystemDns.Netsh; var oldRead = SystemDns.ReadServers; var oldId = SystemDns.AdapterId; var oldFlush = SystemDns.Flush;
            var state = new Dictionary<string, List<string>>();   // "<id>|4" / "<id>|6" → manual servers
            var cmds = new List<string>();
            try
            {
                SystemDns.AdapterId = name => name == "Ethernet A" ? "{A}" : name == "Wi-Fi B" ? "{B}" : null;
                SystemDns.ReadServers = (id, v6) => state.TryGetValue(id + "|" + (v6 ? "6" : "4"), out var l) ? l.ToList() : new List<string>();
                SystemDns.Flush = () => { };
                var dohShow = "DNS-over-HTTPS template   : https://cloudflare-dns.com/dns-query\r\nAuto-upgrade              : yes\r\nUDP-fallback              : yes\r\n";
                SystemDns.Netsh = (exe, args) =>
                {
                    lock (cmds) cmds.Add(args);
                    var m = System.Text.RegularExpressions.Regex.Match(args, "^interface (ipv4|ipv6) (set|add) dnsservers name=\"([^\"]+)\" (?:source=(dhcp|static)\\s*)?(?:address=(\\S+))?");
                    if (m.Success)
                    {
                        string id = SystemDns.AdapterId(m.Groups[3].Value), key = id + "|" + (m.Groups[1].Value == "ipv6" ? "6" : "4");
                        if (m.Groups[2].Value == "add" && id == "{B}") return (1, "The requested operation failed.");
                        if (m.Groups[4].Value == "dhcp") state[key] = new List<string>();
                        else if (m.Groups[2].Value == "set") state[key] = new List<string> { m.Groups[5].Value };
                        else state[key].Add(m.Groups[5].Value);
                        return (0, "");
                    }
                    if (args.StartsWith("dns show encryption")) return (0, dohShow);
                    return (0, "");
                };
                state["{A}|4"] = new List<string> { "1.1.1.1", "1.0.0.1" }; state["{B}|4"] = new List<string> { "1.1.1.1", "1.0.0.1" };
                App.Settings.DnsBackups = new List<DnsBackup>
                {
                    new DnsBackup { Adapter = "Ethernet A", V4Dhcp = false, V4 = new List<string> { "9.9.9.9", "149.112.112.112" }, V6Dhcp = true },
                    new DnsBackup { Adapter = "Wi-Fi B", V4Dhcp = false, V4 = new List<string> { "9.9.9.9", "149.112.112.112" }, V6Dhcp = true },
                };
                App.Settings.DohBackups = new List<DohBackup> { new DohBackup { Server = "1.1.1.1", Existed = true, Template = "https://cloudflare-dns.com/dns-query", AutoUpgrade = true, UdpFallback = false } };
                bool ok = SystemDns.Restore(out string report, onlyBackups: true);
                Check("B7 dns: a failed secondary server keeps that adapter's backup (A restored and freed, B kept); the result is partial, never 'restored'",
                      !ok && App.Settings.DnsBackups.Count == 1 && App.Settings.DnsBackups[0].Adapter == "Wi-Fi B" &&
                      state["{A}|4"].SequenceEqual(new[] { "9.9.9.9", "149.112.112.112" }) && report.Contains("Wi-Fi B"), report.Replace("\r\n", " | "));
                Check("B7 doh: an entry whose UDP fallback did not come back keeps its backup (template + auto upgrade + fallback checked together)",
                      App.Settings.DohBackups.Count == 1, "");
                dohShow = "DNS-over-HTTPS template   : https://cloudflare-dns.com/dns-query\r\nAuto-upgrade              : yes\r\nUDP-fallback              : no\r\n";
                var log = new StringBuilder();
                bool dohOk = SystemDns.RestoreDoh(log);
                Check("B7 doh: once the entry reads back exactly as before, only then its backup is removed", dohOk && App.Settings.DohBackups.Count == 0, log.ToString());
            }
            finally
            {
                SystemDns.Netsh = oldNetsh; SystemDns.ReadServers = oldRead; SystemDns.AdapterId = oldId; SystemDns.Flush = oldFlush;
                App.Settings.DnsBackups = new List<DnsBackup>(); App.Settings.DohBackups = new List<DohBackup>();
            }
        }

        // ============================================================================ B8: the Windows proxy of ByeDPI

        static void ByeDpi6(Action<string, bool, string> Check)
        {
            var oldPersist = ByeDpiNet.Persist;
            var reg = MemRegistry.Inet;
            MemRegistry.Reset();
            try
            {
                // the user's own state: proxy off, a server value present, no bypass list, a PAC script
                reg["ProxyEnable"] = ProxyValue.Number(0); reg["ProxyServer"] = ProxyValue.Text("10.0.0.5:3128"); reg["AutoConfigURL"] = ProxyValue.Text("http://wpad.local/p.pac");
                var live = ProxyRecovery.Live();
                Check("B8 proxy: all four values are read with whether each exists",
                      live != null && live[0].Exists && live[0].Dword && live[0].Data == "0" && live[1].Data == "10.0.0.5:3128" && !live[2].Exists && live[3].Data == "http://wpad.local/p.pac", "");
                var s = App.Settings;
                var apply = typeof(ByeDpiNet).GetMethod("ApplySystem", BindingFlags.Static | BindingFlags.NonPublic);
                void Arm() { apply.Invoke(null, null); }
                Arm();
                bool armed = MemRegistry.HasRecord && MemRegistry.RunOnce(ProxyRecovery.RunOnceName) != null && reg["ProxyServer"].Data == ByeDpiNet.BridgeAddress && !reg.ContainsKey("AutoConfigURL");
                var r1 = ByeDpiNet.RestoreOwned("test");
                Check("B8 proxy: while the setting is still the bridge, the exact old state comes back (absent values deleted, PAC back) and the record goes",
                      armed && r1 == ByeDpiNet.RestoreResult.Restored && reg["ProxyEnable"].Data == "0" && reg["ProxyServer"].Data == "10.0.0.5:3128" && !reg.ContainsKey("ProxyOverride") &&
                      reg["AutoConfigURL"].Data == "http://wpad.local/p.pac" && !MemRegistry.HasRecord && MemRegistry.RunOnce(ProxyRecovery.RunOnceName) == null && s.SystemProxyId == "", "");
                Arm();
                reg["ProxyServer"] = ProxyValue.Text("192.0.2.50:8080");   // the user set an own proxy in Windows meanwhile
                ByeDpiNet.CheckOwnership();
                Check("B8 proxy: a proxy the user set meanwhile is never overwritten (the whole setting is the user's; the periodic check drops only NSF Shield's record)",
                      reg["ProxyServer"].Data == "192.0.2.50:8080" && reg["ProxyEnable"].Data == "1" && reg["ProxyOverride"].Data == ProxyTools.LocalBypass &&
                      !reg.ContainsKey("AutoConfigURL") && !MemRegistry.HasRecord && MemRegistry.RunOnce(ProxyRecovery.RunOnceName) == null && s.SystemProxyId == "", "");
                reg["ProxyEnable"] = ProxyValue.Number(0); reg["ProxyServer"] = ProxyValue.Text("10.0.0.5:3128");
                Arm();
                MemRegistry.FailWrite = n => n == "ProxyServer";
                bool rec = ByeDpiNet.RecoverStale("test");
                MemRegistry.FailWrite = n => false;
                Check("B8 proxy: a restore that fails keeps the record (marker, record, sign-in entry) for the next attempt",
                      !rec && s.SystemProxyId == ByeDpiNet.ProxyMarker && MemRegistry.HasRecord && MemRegistry.RunOnce(ProxyRecovery.RunOnceName) != null, "");
                ByeDpiNet.RestoreOwned("cleanup");
                // the record must be saved before Windows is changed: a failed settings save leaves the Windows proxy as it was
                MemRegistry.Reset(); reg["ProxyEnable"] = ProxyValue.Number(0);
                s.SystemProxyId = "";
                ByeDpiNet.Persist = () => false;
                bool threw = false;
                try { Arm(); } catch (TargetInvocationException ex) when (ex.InnerException is IOException) { threw = true; }
                Check("B8 proxy: if the settings cannot be saved the Windows proxy is not changed at all (and no record stays)",
                      threw && reg["ProxyEnable"].Data == "0" && !reg.ContainsKey("ProxyServer") && s.SystemProxyId == "" && !MemRegistry.HasRecord &&
                      MemRegistry.RunOnce(ProxyRecovery.RunOnceName) == null && MemRegistry.Writes == 0, "");
                string bsrc = File.ReadAllText(Path.Combine(Repo, @"src\Core\ByeDpiNet.cs"));
                int gm = bsrc.IndexOf("public static int GuardMain", StringComparison.Ordinal);
                Check("B8 proxy: every restore path (stop, guard, start, upgrade, uninstall) goes through the per-value ownership check",
                      bsrc.Contains("if (SystemProxyActive || RecordIsOurs()) RestoreOwned(\"stop\");") && bsrc.IndexOf("RecoverStale(", gm, StringComparison.Ordinal) > gm &&
                      bsrc.Contains("var r = RestoreOwned(reason);") && bsrc.Contains("var res = ProxyRecovery.Restore(rec);") &&
                      File.ReadAllText(Path.Combine(Repo, @"src\Core\Engine.cs")).Contains("ByeDpiNet.CheckOwnership();"), "");
            }
            finally
            {
                ByeDpiNet.Persist = oldPersist;
                MemRegistry.Reset();
                App.Settings.SystemProxyId = "";
            }
        }

        // ============================================================================ B9: domain lists

        static void Lists6(Action<string, bool, string> Check, string root)
        {
            var lb = new ListBinding { Include = @"C:\l\include.txt", Exclude = @"C:\l\exclude.txt" };
            var zp = new Profile { Engine = EngineKind.Zapret, EngineArgs = "--wf-tcp=443 --filter-tcp=443 --hostlist=include.txt --dpi-desync=fake" };
            string za = Engines.Zapret.BuildArgs(zp, lb);
            var bp = new Profile { Engine = EngineKind.ByeDpi, EngineArgs = "--hosts include.txt --split 1+s" };
            string ba = Engines.ByeDpi.BuildArgs(bp, lb);
            var bp2 = new Profile { Engine = EngineKind.ByeDpi, EngineArgs = "--hosts exclude.txt --auto=none --split 1+s" };
            string ba2 = Engines.ByeDpi.BuildArgs(bp2, lb);
            Check("B9 lists: a profile that places its include list itself still gets the exclude list (Zapret rules, ByeDPI first group)",
                  za.Contains("--hostlist=C:\\l\\include.txt") && za.Contains("--hostlist-exclude=C:\\l\\exclude.txt") &&
                  ba.Contains("--hosts C:\\l\\exclude.txt --auto none") && ba.IndexOf("C:\\l\\exclude.txt", StringComparison.Ordinal) < ba.IndexOf("C:\\l\\include.txt", StringComparison.Ordinal) &&
                  ba2.Contains("--hosts C:\\l\\include.txt") && ba2.StartsWith("--ip 127.0.0.1 --port " + ByeDpiNet.SocksPort + " --hosts C:\\l\\exclude.txt --auto none"), za + " || " + ba + " || " + ba2);
            var s = new AppSettings { TargetedMode = true, TargetDomains = new List<string> { "discord.com" }, ExcludeEnabled = true, ExcludeDomains = new List<string> { "bank.example" } };
            s.Normalize();
            string ld = Path.Combine(root, "b9 lists");
            var planned = Hostlists.Resolve(Engines.Zapret, s, ld).Binding;
            ListBinding bound;
            using (Hostlists.Prepare(Engines.Zapret, s, ld, out bound, out _)) { }
            Check("B9 lists: the start and the command preview use one resolved plan (same files)",
                  planned.SameFiles(bound) && bound.Include != null && bound.Exclude != null && Hostlists.Plan(Engines.Zapret, s).SameFiles(Hostlists.Resolve(Engines.Zapret, s).Binding), "");
            string blocked = Path.Combine(root, "b9 blocked");
            File.WriteAllText(blocked, "a file where the list folder should be");
            bool failsClosed = Throws<Exception>(() => { using (Hostlists.Prepare(Engines.Zapret, s, blocked, out _, out _)) { } });
            string esrc = File.ReadAllText(Path.Combine(Repo, @"src\Core\Engine.cs"));
            int ls = esrc.IndexOf("listHold = Hostlists.Prepare(", StringComparison.Ordinal);
            Check("B9 lists: a list the user turned on that cannot be written and locked stops the start (no 'all traffic' fallback)",
                  failsClosed && ls > 0 && esrc.IndexOf("Fail(new LocText(\"lists.writeFailedStop\"", ls, StringComparison.Ordinal) > ls && !esrc.Contains("lists = ListBinding.None;"), "");
        }

        // ============================================================================ B10: support package

        static void Support6(Action<string, bool, string> Check)
        {
            var s = new AppSettings();
            s.Proxies.Add(new ProxyEntry { Name = "Ankara office 10.9.8.7", Host = "10.9.8.7", Port = 3128, User = "alice", Password = "pw-secret", LastResult = "Working · TR 10.9.8.7" });
            s.ProxyApps.Add(new ProxyApp { Name = "Bob's browser", ExePath = @"C:\Users\bob\AppData\Local\app.exe", ExtraArgs = "--token=SECRET123", ProxyId = s.Proxies[0].Id });
            s.CustomProfiles.Add(new Profile { Name = "My secret method", Engine = EngineKind.Zapret, EngineArgs = "--wf-tcp=443 --dpi-desync=fake" });
            s.TargetDomains = new List<string> { "private-site.example" };
            s.Normalize();
            s.SelectedProfileId = s.CustomProfiles[0].Id;
            var oldS = App.Settings;
            string xml;
            App.Settings = s;
            try { xml = Support.SettingsSummary(s).ToString(); }
            finally { App.Settings = oldS; }
            string[] leaks = { "10.9.8.7", "Ankara", "alice", "pw-secret", "SECRET123", "bob", "Bob's", "My secret", "private-site", "Working" };
            var found = leaks.Where(l => xml.IndexOf(l, StringComparison.OrdinalIgnoreCase) >= 0).ToList();
            Check("B10 support: the settings part is built from an allow list (no proxy names/addresses/users, no paths, no extra arguments, no site lists)",
                  found.Count == 0 && xml.Contains("name=\"Proxy #1\"") && xml.Contains("name=\"App #1\"") && xml.Contains("extraArgs=\"yes\"") && xml.Contains("<IncludeListSize>1</IncludeListSize>"),
                  string.Join(", ", found));
            string sup = File.ReadAllText(Path.Combine(Repo, @"src\Core\Support.cs"));
            Check("B10 support: the package writes exactly what its README describes (settings-summary.xml, no settings copy) and custom profiles are not named",
                  sup.Contains("SettingsSummary(App.Settings).Save(Path.Combine(tmp, SettingsFileName));") && !sup.Contains("SettingsStore.Clone(App.Settings)") &&
                  Support.ReadmeText.Contains(Support.SettingsFileName) && Support.ReadmeText.Contains("extra arguments") &&
                  !Support.ProfileLabel(new Profile { Name = "My secret method", Engine = EngineKind.Zapret }).Contains("secret"), "");
        }

        // ============================================================================ B13: user start/stop against a scan

        static void Race6(Action<string, bool, string> Check)
        {
            bool a = ScanGate.TryBeginUser();
            object t1 = ScanGate.TryAcquire();
            var acq = ScanGate.AcquireAsync(5000);
            Thread.Sleep(200);
            bool waiting = !acq.IsCompleted;
            var ended = DateTime.UtcNow;
            ScanGate.EndUser();
            object t2 = acq.Wait(3000) ? acq.Result.Token : null;
            bool refusedDuringScan = t2 != null && !ScanGate.TryBeginUser();
            if (t2 != null) ScanGate.Release(t2);
            Check("B13 race: an accepted stop/start finishes before a scan can take the engine; while a scan owns it, a user request is refused",
                  a && t1 == null && waiting && t2 != null && refusedDuringScan && ScanGate.UserOps == 0, "");

            // through a whole scan: the state is recorded only after the user's stop has finished
            var h = new FakeHost();
            int stopFinished = 0, capturedAfter = -1;
            h.Env = new EnvSnapshot { State = EngineState.Stopped };
            ScanGate.TryBeginUser();
            var req = ScanRequest.Create(ScanScope.AllEngines, ScanMode.StopOnFirstMatch, false, new[] { "tr-recommended" }, T3);
            var run = Task.Run(() => new Scanner(req, new CaptureHost { H = h, OnCapture = () => capturedAfter = Volatile.Read(ref stopFinished) }).RunAsync(CancellationToken.None));
            Thread.Sleep(300);
            bool notYet = capturedAfter == -1;
            Volatile.Write(ref stopFinished, 1);
            ScanGate.EndUser();
            var o = run.Wait(20000) ? run.Result : null;
            string act = File.ReadAllText(Path.Combine(Repo, @"src\Core\Actions.cs"));
            Check("B13 race: a scan started during an accepted stop records the state only after it (Actions use the gate's user requests)",
                  o != null && !o.Busy && notYet && capturedAfter == 1 && act.Contains("ScanGate.TryBeginUser()") && act.Contains("UserEngineOp(\"Stop\"") &&
                  File.ReadAllText(Path.Combine(Repo, @"src\Core\Scanner.cs")).Contains("await ScanGate.AcquireAsync(30000, ct)"),
                  "outcome " + (o == null ? "none" : o.Busy ? "busy" : "ran") + ", captured after the stop: " + capturedAfter);
        }

        /// <summary>A scan host that records when the scan captured the state (everything else from <see cref="FakeHost"/>).</summary>
        sealed class CaptureHost : IScanHost
        {
            public FakeHost H;
            public Action OnCapture;
            public EnvSnapshot Capture() { OnCapture?.Invoke(); return H.Capture(); }
            public SuspendResult Suspend(EnvSnapshot env, object token) => H.Suspend(env, token);
            public Task<bool> PretestAsync(CancellationToken ct) => H.PretestAsync(ct);
            public Task<DnsComparison> CompareDnsAsync(string host, bool skipDoh, CancellationToken ct) => H.CompareDnsAsync(host, skipDoh, ct);
            public Task<TargetProbe> ProbeAsync(string host, ProbeTransport via, CancellationToken ct) => H.ProbeAsync(host, via, ct);
            public Task<StunResult> StunAsync(CancellationToken ct) => H.StunAsync(ct);
            public bool Available(Profile p, out LocText why) => H.Available(p, out why);
            public ListPlan PlanLists(Profile p, IReadOnlyList<string> targets, bool widen) => H.PlanLists(p, targets, widen);
            public void FlushDns() => H.FlushDns();
            public Task<TrialStart> StartTrialAsync(Profile p, ListPlan lists, CancellationToken ct) => H.StartTrialAsync(p, lists, ct);
            public bool Apply(Profile p, EnvSnapshot env, object token, out LocText error) => H.Apply(p, env, token, out error);
            public RestoreReport Restore(EnvSnapshot env, object token) => H.Restore(env, token);
        }

        // ============================================================================ M1: settings files

        static void Settings6(Action<string, bool, string> Check, string root)
        {
            string dtd = Path.Combine(root, "m1 dtd.xml");
            File.WriteAllText(dtd, "<?xml version=\"1.0\"?><!DOCTYPE a [<!ENTITY x \"y\">]><AppSettings><Language>&x;</Language></AppSettings>");
            string big = Path.Combine(root, "m1 big.xml");
            using (var fs = new FileStream(big, FileMode.Create)) fs.SetLength(SettingsStore.MaxFileBytes + 1);
            bool dtdRefused = Throws<System.Xml.XmlException>(() => SettingsStore.LoadXml(dtd));
            bool bigRefused = Throws<InvalidDataException>(() => SettingsStore.LoadXml(big));
            string isw = File.ReadAllText(Path.Combine(Repo, @"src\Core\InstallerSwitch.cs"));
            Check("M1 settings: every settings read (load, import, installer switch) uses the bounded reader – DTD prohibited, size limited",
                  dtdRefused && bigRefused && isw.Contains("SettingsStore.Import(tmp)") &&
                  File.ReadAllText(Path.Combine(Repo, @"src\Core\Models.cs")).Contains("var doc = LoadXml(path);"), "");
            var w = new AppSettings { WatchMinutes = int.MaxValue };
            w.Normalize();
            Check("M1 settings: the watchdog minutes are clamped before they become milliseconds (no overflow)",
                  w.WatchMinutes == AppSettings.MaxWatchMinutes && MainForm.WatchIntervalMs(int.MaxValue) == AppSettings.MaxWatchMinutes * 60000 && MainForm.WatchIntervalMs(-5) == 0, "");
            string target = Path.Combine(root, "m1 settings.xml");
            var all = Enumerable.Range(0, 12).Select(i => Task.Run(() => SettingsStore.SaveTo(new AppSettings { ThemeId = "t" + i }, target))).ToArray();
            Task.WaitAll(all);
            bool readable;
            try { SettingsStore.ReadFile(target); readable = true; } catch { readable = false; }
            Check("M1 settings: saves are serialized with a unique temporary file and report their result (no lost or half-written file)",
                  all.All(t => t.Result) && readable && Directory.GetFiles(root, "m1 settings.xml.*.tmp").Length == 0, "");
            string ln = File.ReadAllText(Path.Combine(Repo, @"src\Core\Models.cs"));
            int lo = ln.IndexOf("public static AppSettings Load()", StringComparison.Ordinal);
            Check("M1 settings: Normalize runs inside the load error handling (a file that cannot be normalized counts as corrupt)",
                  lo > 0 && ln.IndexOf("s.Normalize();   // a file that reads but cannot be normalized counts as corrupt too", lo, StringComparison.Ordinal) > lo, "");
        }

        // ============================================================================ M5, M6, L3: measurements

        static void Probe6(Action<string, bool, string> Check)
        {
            // M5: a candidate that exits during its measurement never counts
            var h = new FakeHost { Verdict = (pid, host, rd, st) => TargetVerdict.Pass };
            int calls = 0;
            h.TrialAlive = () => Interlocked.Increment(ref calls) < 2;
            int oldAlive = Scanner.AliveCheckMs;
            Scanner.AliveCheckMs = 50;
            ScanOutcome o;
            try { o = RunScan(ScanRequest.Create(ScanScope.AllEngines, ScanMode.FullBenchmark, false, new[] { "tr-recommended" }, T3), h); }
            finally { Scanner.AliveCheckMs = oldAlive; }
            var row = o.Rows.FirstOrDefault();
            Check("M5 scan: a candidate that exits (or loses its port) during the measurement is not a success (NSF-602, never applied)",
                  row != null && row.Lost != null && row.Status == ScanRow.Failed && row.Code == "NSF-602" && o.Suggested == null, row?.Status + " " + row?.Code);
            var h2 = new FakeHost { Verdict = (pid, host, rd, st) => TargetVerdict.Pass };
            var o2 = RunScan(ScanRequest.Create(ScanScope.AllEngines, ScanMode.FullBenchmark, false, new[] { "tr-recommended" }, T3), h2);
            Check("M5 scan: a candidate that keeps running is measured as before", o2.Rows.FirstOrDefault()?.IsFull == true, "");
            var oldOwner = ProbeTransport.OwnerCheck;
            bool connected = false;
            try
            {
                ProbeTransport.OwnerCheck = (port, pid) => false;
                var env = new ProbeEnv
                {
                    Resolve = (n, t, c) => Task.FromResult(new DnsAnswer { Status = DnsStatus.Ok, Addresses = { IPAddress.Parse("104.16.1.1") } }),
                    Connect = (ep, t, c) => { connected = true; return Task.FromResult<Stream>(new MemoryStream()); },
                };
                var pr = NetProbe.HttpsAsync("discord.com", ProbeTransport.Socks5(18999, 4321), env, CancellationToken.None).GetAwaiter().GetResult();
                Check("M5 probe: the transport carries the candidate's PID; a SOCKS port it no longer owns is never measured (no connection)",
                      !connected && pr.Stage == ProbeStage.Tunnel && pr.Code == "NSF-808" && pr.Detail?.Key == "scan.probe.socksOwner", pr.Code);
            }
            finally { ProbeTransport.OwnerCheck = oldOwner; }

            // M6: one deadline per stage (a slow-drip server cannot stretch it), one pending STUN receive, A/AAAA kept apart
            var drip = new DripStream { Gap = 150 };
            var envH = new ProbeEnv { HttpTimeoutMs = 900, MaxHeaderBytes = 64 * 1024 };
            var sw = Stopwatch.StartNew();
            bool timedOut = false;
            try { NetProbe.HttpGetAsync(drip, "example.com", "/", null, false, envH, CancellationToken.None).GetAwaiter().GetResult(); }
            catch (System.TimeoutException) { timedOut = true; }
            Check("M6 http: a server sending one byte at a time hits the stage deadline (not 6 s per read)", timedOut && sw.ElapsedMilliseconds < 2500, sw.ElapsedMilliseconds + " ms");
            using (var quiet = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)))
            {
                int before = Stun.Receives;
                var r = Stun.BindAsync((IPEndPoint)quiet.Client.LocalEndPoint, 150, 3, CancellationToken.None).GetAwaiter().GetResult();
                Check("M6 stun: retransmissions share one pending receive per socket", r.Status == StunStatus.Timeout && Stun.Receives - before == 1, (Stun.Receives - before) + " receives");
            }
            Check("M6 doh: an empty A answer next to a missing AAAA answer is unclear, not 'no data'; two empty answers are 'no data'",
                  Doh.Combine(DohStatus.NoData, DohStatus.Unreachable, 0) == DohStatus.Unreachable && Doh.Combine(DohStatus.NoData, DohStatus.NoData, 0) == DohStatus.NoData &&
                  Doh.Combine(DohStatus.Ok, DohStatus.Unreachable, 1) == DohStatus.Ok, "");

            // L3: HTTP/1.1 for the Gateway 101; custom redirects only to the very same host (or with/without www.)
            string key = WsHandshake.NewKey();
            HttpHead Head(string v)
            {
                var t = v + " 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + WsHandshake.Accept(key) + "\r\n\r\n";
                var b = Encoding.ASCII.GetBytes(t);
                return HttpHead.Parse(b, b.Length, b.Length);
            }
            Check("L3 gateway: a 101 is accepted only as HTTP/1.1", WsHandshake.Judge(Head("HTTP/1.1"), key).Verdict == TargetVerdict.Pass && WsHandshake.Judge(Head("HTTP/1.0"), key).Verdict == TargetVerdict.Fail, "");
            Check("L3 redirect: a custom target's redirect must stay on the same host (shared domains such as github.io never match a sibling)",
                  !Redirects.SameSite("foo.github.io", "evil.github.io") && Redirects.SameSite("example.com", "www.example.com") && Redirects.SameSite("www.example.com", "example.com") &&
                  !Redirects.SameSite("example.com", "login.example.com") && !Redirects.SameSite("shop.example.co.uk", "other.example.co.uk"), "");
        }

        // ============================================================================ M9, M11, L2, L4

        static void Misc6(Action<string, bool, string> Check)
        {
            // M9: callers during a running diagnosis share it
            var oldSource = Conflicts.Source;
            try
            {
                var slow = new SlowSource6 { Inner = BaseSource() };
                Conflicts.Source = slow;
                Conflicts.DebugSet(null);
                var t1 = Conflicts.RefreshAsync();
                var t2 = Conflicts.RefreshAsync();
                bool sameTask = ReferenceEquals(t1, t2);
                var r2 = t2.GetAwaiter().GetResult();
                Check("M9 diagnosis: a second caller during the first diagnosis gets the same task and a real result (never null)",
                      sameTask && r2 != null && slow.Calls == 1, "calls " + slow.Calls);
            }
            finally { Conflicts.Source = oldSource; Conflicts.DebugSet(null); }

            // M11: an existing release is checked, never a blind success
            string yml = File.ReadAllText(Path.Combine(Repo, @".github\workflows\build.yml"));
            // stage 7: the check lives in .github/scripts/release-check.ps1 (tested offline with a fake gh by build.ps1)
            string rcs = File.ReadAllText(Path.Combine(Repo, @".github\scripts\release-check.ps1"));
            Check("M11 workflow: an existing release must have the three files with this build's hashes, otherwise the job fails",
                  System.Text.RegularExpressions.Regex.Matches(yml, "release-check\\.ps1").Count >= 2 && rcs.Contains("'release', 'download'") &&
                  rcs.Contains("throw \"The published release has no $f\"") && rcs.Contains("throw \"The published $f differs from this build") &&
                  !yml.Contains("Write-Host 'This release is already published; not published again.'; exit 0"), "");

            // L2: nothing may follow the profile element of a profile code
            string body = "<profile version=\"1\" engine=\"zapret\"><args>--wf-tcp=443 --dpi-desync=fake</args></profile>";
            bool good = ProfileCode.TryFromCode(ProfileCode.PackRaw(1, Encoding.UTF8.GetBytes(body + "\n  ")), out _, out _);
            bool second = ProfileCode.TryFromCode(ProfileCode.PackRaw(1, Encoding.UTF8.GetBytes(body + body)), out _, out string e2);
            bool trailing = ProfileCode.TryFromCode(ProfileCode.PackRaw(1, Encoding.UTF8.GetBytes(body + "tail")), out _, out string e3);
            Check("L2 nsf1: the document must end after </profile> (a second root or trailing data is refused)", good && !second && !trailing, e2 + " / " + e3);

            // L4: the user's folder is masked in the log, in a crash record and in a copied/saved log
            string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string masked = Privacy.MaskUser("file at " + home + "\\Desktop\\x.txt and " + home.ToUpperInvariant() + "\\y");
            App.Log("stage 6 privacy check: " + home + "\\Desktop\\NSF Shield");
            var last = App.LogSnapshot().LastOrDefault(l => l.Text.StartsWith("stage 6 privacy check"));
            string crash = File.ReadAllText(Path.Combine(Repo, @"src\Core\Crash.cs")), pages = File.ReadAllText(Path.Combine(Repo, @"src\UI\OtherPages.cs"));
            Check("L4 privacy: the log, a crash record and the copied/saved log use the shared mask (%USERPROFILE%)",
                  !masked.Contains(home) && masked.Contains("%USERPROFILE%\\Desktop\\x.txt") && last != null && !last.Text.Contains(home) && last.Text.Contains("%USERPROFILE%\\Desktop") &&
                  crash.Contains("Privacy.MaskUser(") && pages.Contains("Clipboard.SetText(Privacy.MaskUser(box.Text))") && pages.Contains("Privacy.MaskUser(box.Text), Encoding.UTF8"), "");
        }

        // ============================================================================ L1: the main window lets go of everything when it closes

        static void Window6(Action<string, bool, string> Check)
        {
            var oldInstance = MainForm.Instance;
            MainForm.NetEventsOverride = new RecordingNetEvents();
            var form = new MainForm();
            try
            {
                var h = form.Handle;
                var appEvent = typeof(App).GetField("StatusChanged", BindingFlags.Static | BindingFlags.NonPublic);
                var engEvent = typeof(Engine).GetField("StateChanged", BindingFlags.Instance | BindingFlags.NonPublic);
                bool Holds(Delegate d) => d != null && d.GetInvocationList().Any(x => ReferenceEquals(x.Target, form));
                bool before = Holds((Delegate)appEvent.GetValue(null)) && Holds((Delegate)engEvent.GetValue(App.Engine));
                var icons = (System.Collections.IDictionary)typeof(MainForm).GetField("trayIcons", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(form);
                form.Dispose();
                bool after = !Holds((Delegate)appEvent.GetValue(null)) && !Holds((Delegate)engEvent.GetValue(App.Engine));
                Check("L1 window: closing removes the app and engine subscriptions, disposes the cached tray icons and clears Instance",
                      before && after && icons.Count == 0 && !ReferenceEquals(MainForm.Instance, form), "");
            }
            finally
            {
                if (!form.IsDisposed) form.Dispose();
                MainForm.NetEventsOverride = null;
                MainForm.Instance = oldInstance;
            }
        }
    }
}
#endif
