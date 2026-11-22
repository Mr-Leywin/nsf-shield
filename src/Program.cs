using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;

// Exe version information (Windows: Properties → Details). The publisher is this project only; the GoodbyeDPI (ValdikSS)
// and WinDivert (basil00) attributions are in the licenses folder, on the About page and in the README.
// The version comes from one place: the three values must be equal (build.ps1 checks them and sets app.manifest to match).
[assembly: AssemblyTitle("NSF Shield")]                                     // FileDescription
[assembly: AssemblyDescription("NSF Shield by Nightshift: GoodbyeDPI, Zapret and ByeDPI control panel")]   // Comments
[assembly: AssemblyCompany(NSFShield.App.Publisher)]                       // CompanyName
[assembly: AssemblyProduct("NSF Shield")]                                   // ProductName
[assembly: AssemblyCopyright(NSFShield.App.Copyright)]                     // LegalCopyright
[assembly: AssemblyTrademark("")]
[assembly: System.Resources.NeutralResourcesLanguage("en")]
[assembly: AssemblyVersion("1.0.1.0")]
[assembly: AssemblyFileVersion("1.0.1.0")]
[assembly: AssemblyInformationalVersion("1.0.1")]                          // ProductVersion
[assembly: TargetFramework(".NETFramework,Version=v4.8", FrameworkDisplayName = ".NET Framework 4.8")]
// every DLL called through P/Invoke (kernel32, user32, dnsapi, dwmapi, uxtheme, wininet) is loaded from System32 only
[assembly: System.Runtime.InteropServices.DefaultDllImportSearchPaths(System.Runtime.InteropServices.DllImportSearchPath.System32)]

namespace NSFShield
{
    static class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
            Native.HardenDllSearch();
            // update installation: run by the new version's exe, before the single-instance lock and the administrator check
            int ui = Array.IndexOf(args, "--apply-update");
            // the setup package checks its target folder with this (new, verified) program from its own temporary folder before
            // it runs anything there or writes to it: 0 protected, 1 not there yet, 2 unsafe, 3 not readable (nothing is changed)
            int cdi = Array.IndexOf(args, "--check-install-dir");
            if (cdi >= 0) return InstallGuard.SetupCheckCli(args, cdi);
            if (ui >= 0)
            {
                if (args.Length >= ui + 5 && int.TryParse(args[ui + 3], out int oldPid))
                    return Updater.Apply(args[ui + 1], args[ui + 2], oldPid, args[ui + 4], args.Length > ui + 5 && args[ui + 5] == "1");
                return 2;
            }
#if PREVIEW
            App.Preview = true;
            // the preview (screenshots, UI check, self-test) never touches the real Windows proxy, its record or RunOnce
            MemRegistry.Install();
            int mi = Array.IndexOf(args, "--make-icon");
            if (mi >= 0) { IconArt.WriteIco(args[mi + 1], new[] { 16, 20, 24, 32, 40, 48, 64, 256 }); return 0; }
            // the package files are produced in a fixed language: English scripts (file names too); the guide has both languages
            // build helpers: a failure gives a non-zero exit code (build.ps1 never takes an old output for a new one)
            int ei = Array.IndexOf(args, "--export-scripts");
            if (ei >= 0) return SelfTest.Helper(() => { Loc.Init("en"); Scripts.ExportAll(args[ei + 1]); });
            int gi = Array.IndexOf(args, "--export-guide");
            if (gi >= 0) return SelfTest.Helper(() => { Loc.Init("en"); Guide.Build(args[gi + 1], args[gi + 2]); });
            int rni = Array.IndexOf(args, "--release-notes");
            if (rni >= 0) return ReleaseNotes.Cli(args, rni);
            // self-test: exit code 0 only for a complete, non-empty report without failures (see SelfTest.RunToFile)
            int pi = Array.IndexOf(args, "--selftest-probe");
            if (pi >= 0) return SelfTest.Probe(args, pi);
            int ti = Array.IndexOf(args, "--selftest");
            if (ti >= 0)
            {
                string outPath = args.Length > ti + 1 ? args[ti + 1] : null;
                if (string.IsNullOrWhiteSpace(outPath) || outPath.StartsWith("--")) return SelfTest.ExitUsage;
                return SelfTest.RunToFile(outPath, () => SelfTest.Run(args.Skip(ti + 2).ToArray()));
            }
            App.DataDir = Path.Combine(Path.GetTempPath(), "nsfshield_preview");
            try { Directory.Delete(App.DataDir, true); } catch { }
#endif
            // clean uninstall (the setup package's uninstaller calls this too): closes the running copy, undoes system changes
            if (args.Contains("--uninstall") && !App.Preview)
                return Uninstaller.RunCli(quiet: args.Contains("--quiet"));
            // before the setup package replaces files: stops the app, the engines and the service of this folder (settings are kept)
            if (args.Contains("--prepare-upgrade") && !App.Preview)
                return Uninstaller.PrepareUpgrade();
            // started by the app while ByeDPI sets the Windows proxy: restores the proxy if the app ends without doing it
            if (args.Contains("--proxy-guard") && !App.Preview)
                return ByeDpiNet.GuardMain(args);

            // started by a portable copy that switched to this installed copy: let it exit first (single instance)
            int swi = Array.IndexOf(args, InstallerSwitch.SwitchedArg);
            bool switched = swi >= 0 && !App.Preview;
            if (switched && args.Length > swi + 1) InstallerSwitch.WaitForPortable(args[swi + 1]);

            bool createdNew;
            var mutex = new Mutex(true, @"Local\NSFShield_SingleInstance", out createdNew);
            var showEvent = new EventWaitHandle(false, EventResetMode.AutoReset, @"Local\NSFShield_Show");
            if (!createdNew && !App.Preview)
            {
                showEvent.Set();   // bring the running copy to the front
                return 0;
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            using (var g = Graphics.FromHwnd(IntPtr.Zero)) Theme.Scale = g.DpiX / 96f;

            try { ServicePointManager.SecurityProtocol = SecurityProtocolType.SystemDefault; } catch { }
            ServicePointManager.DefaultConnectionLimit = 32;
            ServicePointManager.Expect100Continue = false;
            ServicePointManager.DnsRefreshTimeout = 0;   // .NET DNS cache off: every test uses the current DNS answer

            Application.ThreadException += (s, e) => { App.Log("Unexpected error: " + e.Exception, LogLevel.Error); CrashMarker.Record(e.Exception, fatal: false); };
            AppDomain.CurrentDomain.UnhandledException += (s, e) => { App.Log("Fatal error: " + e.ExceptionObject, LogLevel.Error); CrashMarker.Record(e.ExceptionObject as Exception, fatal: true); };

            App.Init();
            Theme.Apply(Palettes.Resolve(App.Settings));

            if (!App.Preview && !App.IsAdmin())
            {
                MessageBox.Show(Loc.T("main.needAdmin"), App.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return 1;
            }

            CrashMarker.Begin();   // AfterStartup reports it if the previous run did not close properly
            bool tray = args.Any(a => a.Equals("--tray", StringComparison.OrdinalIgnoreCase));
            bool scanAll = args.Any(a => a.Equals("--scan-all", StringComparison.OrdinalIgnoreCase));
            bool scan = scanAll || args.Any(a => a.Equals("--scan", StringComparison.OrdinalIgnoreCase));
            int ufi = Array.IndexOf(args, "--updated");
            string updatedFrom = ufi >= 0 && args.Length > ufi + 1 ? args[ufi + 1] : null;
            bool updateFailed = args.Contains("--update-failed");
            bool resume = args.Contains("--resume");
            string localSetup = null, localSha = null;
#if PREVIEW
            // test hook of the preview build only: --switch-to-installer "<local Setup.exe>" <SHA-256> (the release exe has none)
            int lsi = Array.IndexOf(args, InstallerSwitch.LocalArg);
            if (lsi >= 0 && args.Length > lsi + 2) { localSetup = args[lsi + 1]; localSha = args[lsi + 2]; }
#endif
            var form = new MainForm();
            App.UI = SynchronizationContext.Current;

#if PREVIEW
            int si = Array.IndexOf(args, "--screenshot");
            if (si >= 0) { Preview.Run(form, args[si + 1]); return 0; }
            // visual and behaviour checks with real windows (exit code 0 only without failures; report uicheck.txt in that folder)
            int uci = Array.IndexOf(args, "--uicheck");
            if (uci >= 0) return args.Length > uci + 1 ? Preview.UiCheck(form, args[uci + 1]) : SelfTest.ExitUsage;
#endif

            var waiter = new Thread(() =>
            {
                while (showEvent.WaitOne())
                    try { form.BeginInvoke(new Action(form.ShowFromTray)); } catch { }
            }) { IsBackground = true };
            waiter.Start();

            if (tray && !scan) { var h = form.Handle; } else form.Show();
            form.BeginInvoke(new Action(() => form.AfterStartup(tray, scan, scanAll, updatedFrom, updateFailed, resume, switched)));
            if (localSetup != null) form.BeginInvoke(new Action(() => SwitchDialog.Run(form, localSetup, localSha)));
            Application.Run(new ApplicationContext());
            CrashMarker.End();
            GC.KeepAlive(mutex);
            return 0;
        }
    }

#if PREVIEW
    /// <summary>Unit tests that need no administrator rights (run by hand after a build: NSFShield.preview.exe --selftest out.txt).</summary>
    static partial class SelfTest
    {


        static string Repo => Path.GetFullPath(Path.Combine(App.BaseDir, ".."));

        /// <summary>Keeps the Windows account name out of the report (user folders become %USERPROFILE%).</summary>
        internal static string Redact(string s)
        {
            string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (!string.IsNullOrEmpty(home)) s = System.Text.RegularExpressions.Regex.Replace(s, System.Text.RegularExpressions.Regex.Escape(home), "%USERPROFILE%", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            string user = Environment.UserName;
            if (!string.IsNullOrEmpty(user) && user.Length > 2) s = System.Text.RegularExpressions.Regex.Replace(s, @"(?<=[\\/])" + System.Text.RegularExpressions.Regex.Escape(user) + @"(?=[\\/])", "<user>", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            return s;
        }

        // ------------------------------------------------------------------ structured result and exit codes
        public const int ExitOk = 0, ExitFailed = 1, ExitException = 3, ExitWrite = 4, ExitEmpty = 5, ExitIncomplete = 6, ExitUsage = 64;
        static int okCount, failCount;
        static bool completed;
        internal static int OkCount => okCount;
        internal static int FailCount => failCount;

        /// <summary>One check: counted (not read back from the text) and written as an "OK"/"FAIL" line.</summary>
        static void Record(System.Text.StringBuilder sb, string name, bool ok, string detail)
        {
            if (ok) okCount++; else failCount++;
            sb.AppendLine((ok ? "OK   " : "FAIL ") + name + (detail.Length > 0 ? "  → " + detail : ""));
        }

        /// <summary>
        /// Runs a test body and writes its report. 0 only when the body finished, at least one check ran, nothing failed and
        /// the report was written (and is not empty); otherwise a non-zero code (failed checks, exception, write error, empty or
        /// incomplete run). The report text keeps its OK/FAIL lines and the account name filter.
        /// </summary>
        internal static int RunToFile(string outPath, Func<string> body)
        {
            okCount = failCount = 0;
            completed = false;
            string report;
            int code;
            try { report = body(); code = !completed ? ExitIncomplete : okCount + failCount == 0 ? ExitEmpty : failCount > 0 ? ExitFailed : ExitOk; }
            catch (Exception ex)
            {
                failCount++;
                report = "FAIL unexpected exception: " + ex.GetType().Name + ": " + ex.Message + "\r\n";
                code = ExitException;
            }
            try
            {
                File.WriteAllText(outPath, Redact(report), System.Text.Encoding.UTF8);
                if (new FileInfo(outPath).Length == 0) return ExitEmpty;
            }
            catch (Exception) { return ExitWrite; }
            return code;
        }

        /// <summary>A build helper (guide, scripts): 0 when it finished, 1 on any exception.</summary>
        internal static int Helper(Action a)
        {
            try { a(); return 0; }
            catch (Exception ex) { try { Console.Error.WriteLine(ex.GetType().Name + ": " + ex.Message); } catch { } return 1; }
        }

        /// <summary>
        /// --selftest-probe &lt;ok|fail|throw|empty|incomplete&gt; &lt;out&gt;: a tiny controlled run through the same exit-code path
        /// (the self-test checks its own exit codes with it; the full self-test is never started again from inside itself).
        /// </summary>
        internal static int Probe(string[] args, int i)
        {
            if (args.Length < i + 3) return ExitUsage;
            string kind = args[i + 1], outPath = args[i + 2];
            return RunToFile(outPath, () =>
            {
                var sb = new System.Text.StringBuilder();
                if (kind == "throw") throw new InvalidOperationException("probe");
                if (kind == "ok" || kind == "fail" || kind == "incomplete") Record(sb, "probe check", true, "");
                if (kind == "fail") Record(sb, "probe failure", false, "on purpose");
                if (kind != "incomplete") completed = true;
                return sb.ToString();
            });
        }

        public static string Run(string[] proxies)
        {
            var sb = new System.Text.StringBuilder();
            void Check(string name, bool ok, string detail = "") => Record(sb, name, ok, detail);

            // the tests read the English texts from the repository's locales folder
            Loc.Dir = Path.Combine(Repo, "locales");
            Loc.Init("en");

            // proxy parsing
            foreach (var (text, kind, host, port, user) in new[]
            {
                ("185.12.34.56:8080", ProxyKind.Http, "185.12.34.56", 8080, ""),
                ("socks5://alice:secret@1.2.3.4:1080", ProxyKind.Socks5, "1.2.3.4", 1080, "alice"),
                ("http://proxy.example.com:3128/", ProxyKind.Http, "proxy.example.com", 3128, ""),
                ("5.6.7.8:9000:bob:password", ProxyKind.Http, "5.6.7.8", 9000, "bob"),
                ("socks5h://[2001:db8::1]:1080", ProxyKind.Socks5, "2001:db8::1", 1080, ""),
            })
            {
                bool ok = ProxyTools.TryParse(text, ProxyKind.Http, out var p, out var err);
                Check("parse " + text, ok && p.Kind == kind && p.Host == host && p.Port == port && p.User == user,
                      ok ? p.Kind + " " + p.Host + " " + p.Port + " " + p.User + (p.HasAuth ? " pass=" + p.Password : "") : err);
            }
            Check("parse: invalid port rejected", !ProxyTools.TryParse("1.2.3.4:99999", ProxyKind.Http, out _, out _));
            Check("parse: empty rejected", !ProxyTools.TryParse("  ", ProxyKind.Http, out _, out _));

            // profile code
            var src = Profiles.BuiltIns.First(x => x.Id == "tr-alt").CloneAsCustom();
            string code = ProfileCode.ToCode(src);
            bool back = ProfileCode.TryFromCode("My friend sent this: " + code + " try it", out var dst, out var perr);
            Check("profile code round trip", back && dst.BuildArgs(null) == src.BuildArgs(null) && dst.Id != src.Id, code.Length + " characters " + perr);
            Check("corrupt profile code rejected", !ProfileCode.TryFromCode("NSF1:abc", out _, out _));

            // DPI signature: -9 with another DNS is the same, -5 is different
            string s9a = Scanner.DpiSignature(Profiles.BuiltIns.First(x => x.Id == "tr-recommended"));
            string s9b = Scanner.DpiSignature(Profiles.BuiltIns.First(x => x.Id == "tr-quad9"));
            string s5 = Scanner.DpiSignature(Profiles.BuiltIns.First(x => x.Id == "tr-autottl"));
            Check("DPI signature: -9 Yandex == -9 Quad9", s9a == s9b, "'" + s9a + "'");
            Check("DPI signature: -9 != -5", s9a != s5, "'" + s5 + "'");

            // per-program proxy plans
            foreach (var (name, path) in AppProxy.Installed())
                sb.AppendLine("     found: " + name + " → " + AppProxy.Detect(path) + "  (" + path + ")");
            var auth = new ProxyEntry { Kind = ProxyKind.Socks5, Host = "1.2.3.4", Port = 1080, User = "u", Password = "p", LocalPort = 18950 };
            var open = new ProxyEntry { Kind = ProxyKind.Http, Host = "5.6.7.8", Port = 3128 };
            var chrome = new ProxyApp { Name = "Chrome", ExePath = @"C:\X\chrome.exe", Mode = AppProxyMode.Chromium };
            var plan1 = AppProxy.Plan(chrome, open);
            Check("plan Chromium direct", plan1.Args.Contains("--proxy-server=\"http://5.6.7.8:3128\"") && plan1.Args.Contains("--user-data-dir"), plan1.Args);
            var plan2 = AppProxy.Plan(chrome, auth);
            Check("plan Chromium with password → bridge", plan2.Args.Contains("http://127.0.0.1:18950"), plan2.Args);
            var env = new ProxyApp { Name = "Tool", ExePath = @"C:\X\tool.exe", Mode = AppProxyMode.Env };
            var plan3 = AppProxy.Plan(env, open);
            Check("plan environment variables", plan3.Target.EndsWith("cmd.exe") && plan3.Args.Contains("HTTPS_PROXY=http://5.6.7.8:3128") && plan3.WindowStyle == 7, plan3.Args.Substring(0, Math.Min(90, plan3.Args.Length)) + "…");
            var dc = new ProxyApp { Name = "Discord", ExePath = @"C:\Users\x\AppData\Local\Discord\Update.exe", Mode = AppProxyMode.Discord };
            var plan4 = AppProxy.Plan(dc, open);
            Check("plan Discord", plan4.Args == "--processStart Discord.exe --process-start-args \"--proxy-server=http://5.6.7.8:3128\"", plan4.Args);
            Check("bridge requirement", AppProxy.NeedsBridge(chrome, auth) && !AppProxy.NeedsBridge(chrome, open) &&
                                        AppProxy.NeedsBridge(env, new ProxyEntry { Kind = ProxyKind.Socks5, Host = "h", Port = 1 }));
            Check("proxy list parsing", ProxyTools.ParseList("# comment\n1.1.1.1:80\n\nbroken\nsocks5://2.2.2.2:1080\n1.1.1.1:80", ProxyKind.Http, out int bad).Count == 2 && bad == 1);

            // update: parsing the GitHub answer
            string relJson = "{\"tag_name\":\"v9.8.7\",\"name\":\"NSF Shield 9.8.7\",\"draft\":false,\"prerelease\":false,\"body\":\"## What's new\\n- a\",\"html_url\":\"https://github.com/x/y\"," +
                             "\"published_at\":\"2026-11-20T10:00:00Z\",\"assets\":[{\"name\":\"NSF-Shield-9.8.7.zip.sha256\",\"browser_download_url\":\"https://github.com/a\",\"size\":80,\"digest\":null}," +
                             "{\"name\":\"NSF-Shield-9.8.7.zip\",\"browser_download_url\":\"https://github.com/x/y/releases/download/v9.8.7/NSF-Shield-9.8.7.zip\",\"size\":564400," +
                             "\"digest\":\"sha256:086556D50BFC1DD3D1B03DF0CADFDE01FA172343BBFAE6224D66A756CA93DB51\"}]}";
            var ui1 = Updater.Parse(relJson);
            Check("update: version and package parsed", ui1 != null && ui1.Version == new Version(9, 8, 7) && ui1.AssetName == "NSF-Shield-9.8.7.zip" &&
                  ui1.Sha256 == "086556d50bfc1dd3d1b03df0cadfde01fa172343bbfae6224d66a756ca93db51" && Updater.IsNewer(ui1), ui1?.Version + " " + ui1?.AssetName);
            var ui2 = Updater.Parse(relJson.Replace("\"digest\":\"sha256:086556D50BFC1DD3D1B03DF0CADFDE01FA172343BBFAE6224D66A756CA93DB51\"", "\"digest\":null")
                                           .Replace("- a", "**SHA-256** (NSF-Shield-9.8.7.zip): `" + new string('a', 64) + "`"));
            Check("update: hash read from the release notes", ui2 != null && ui2.Sha256 == new string('a', 64));
            Check("update: pre-release ignored", Updater.Parse(relJson.Replace("\"prerelease\":false", "\"prerelease\":true")) == null);
            Check("update: older version is not newer", !Updater.IsNewer(Updater.Parse(relJson.Replace("9.8.7", "1.0.0"))));

            // support package: hiding personal details
            string raw = @"C:\Users\testuser\AppData\Local\Discord\Update.exe exit IP 203.0.113.45 TR · DNS 77.88.8.8:1253 · discord 162.159.135.232 · modem 192.168.1.1 · v6 2a00:1d34:abcd::5 fe80::1 · someone@example.com · 17:46:13";
            string red = Support.Redact(raw);
            Check("redact: user folder", red.Contains(@"C:\Users\<user>\AppData") && !red.Contains("testuser"), red);
            Check("redact: public IP hidden, DNS/Discord kept", red.Contains("<ip>") && !red.Contains("203.0.113") && red.Contains("77.88.8.8") && red.Contains("162.159.135.232"));
            Check("redact: local IP, IPv6, e-mail", red.Contains("<local-ip>") && red.Contains("<ipv6>") && red.Contains("fe80::1") && red.Contains("<email>") && red.Contains("17:46:13"));
            string legacyUser = Support.Redact(@"C:\Kullan" + "\u0131c\u0131" + @"lar\testuser\Desktop");   // tr-literal: Turkish name of the Users folder
            Check("redact: user folder with the Turkish folder name", !legacyUser.Contains("testuser") && legacyUser.Contains("<user>"), legacyUser);

            // "Report a problem": explorer.exe passes at most 259 characters on, so the issue address never gets longer; the
            // title is shortened by whole characters (no cut escape sequence or surrogate pair), the summary is not in it
            string shortIssue = Support.IssueUrl("NSF-601 – GoodbyeDPI closed", "1.0.1", "26300", "NSF-601");
            Check("issue: short address with the repository, form and fields",
                  shortIssue == "https://github.com/" + Updater.Owner + "/" + Updater.Repo + "/issues/new?template=hata.yml&title=NSF-601%20%E2%80%93%20GoodbyeDPI%20closed&surum=1.0.1&windows=Build%2026300&kod=NSF-601" &&
                  !shortIssue.Contains("ozet="), shortIssue);
            var longIssues = new[]
            {
                Support.IssueUrl("NSF-601 – " + string.Concat(Enumerable.Repeat("çığüşö ", 60)), "1.0.1", "26300", "NSF-601"),   // tr-literal: Turkish letters in a test title
                Support.IssueUrl(string.Concat(Enumerable.Repeat("x\U0001F6E1", 200)), "1.0.1", "26300", "NSF-601"),
                Support.IssueUrl(new string('a', 2000), "10.20.30", "26300", "NSF-999"),
            };
            bool EscapesWhole(string u)
            {
                for (int i = 0; i < u.Length; i++)
                    if (u[i] == '%' && (i + 2 >= u.Length || !Uri.IsHexDigit(u[i + 1]) || !Uri.IsHexDigit(u[i + 2]))) return false;
                try { Uri.UnescapeDataString(u); return true; } catch { return false; }
            }
            Check("issue: a long title is shortened; the address never exceeds the explorer limit and no escape sequence is cut",
                  longIssues.All(u => u.Length <= Sys.MaxShellArgument && EscapesWhole(u) && u.Contains("&kod=NSF-") && u.Contains("&surum=")) &&
                  longIssues[0].Contains("%E2%80%A6&surum") && !longIssues[1].Contains("%ED"),
                  string.Join(" ", longIssues.Select(u => u.Length)));
            Check("issue: the elevated opener refuses an address explorer.exe would cut",
                  !Sys.OpenAsUser("https://example.invalid/" + new string('a', Sys.MaxShellArgument)), "");

            // update installation (file operations only; does not touch the service); the user's data folder is never touched
            {
                string t = Path.Combine(Path.GetTempPath(), "nsf-apply-test-" + Guid.NewGuid().ToString("N").Substring(0, 6));
                string srcDir = Path.Combine(t, "new"), dstDir = Path.Combine(t, "installed");
                Directory.CreateDirectory(Path.Combine(srcDir, "bin", "x86_64"));
                Directory.CreateDirectory(Path.Combine(dstDir, "data"));
                Directory.CreateDirectory(Path.Combine(dstDir, "bin", "x86_64"));
                File.WriteAllText(Path.Combine(srcDir, "NSFShield.exe"), "new");
                File.WriteAllText(Path.Combine(srcDir, "bin", "x86_64", "goodbyedpi.exe"), "new-gdpi");
                File.WriteAllText(Path.Combine(dstDir, "NSFShield.exe"), "old");
                File.WriteAllText(Path.Combine(dstDir, "bin", "x86_64", "goodbyedpi.exe"), "old-gdpi");
                const string settingsXml = "<AppSettings><ThemeId>dracula</ThemeId></AppSettings>";
                File.WriteAllText(Path.Combine(dstDir, "data", "settings.xml"), settingsXml);
                // stage 7: the current protocol – the package folder comes with the manifest the old app wrote after extracting
                Updater.WriteManifest(Updater.ManifestPath(srcDir), Updater.HashTree(srcDir));
                int rc = Updater.Apply(srcDir, dstDir, 999999, "1.0.0", false, false);
                bool okCopy = File.ReadAllText(Path.Combine(dstDir, "NSFShield.exe")) == "new" && File.ReadAllText(Path.Combine(dstDir, "bin", "x86_64", "goodbyedpi.exe")) == "new-gdpi";
                bool okKeep = File.ReadAllText(Path.Combine(dstDir, "data", "settings.xml")) == settingsXml;
                bool okBak = File.ReadAllText(Path.Combine(dstDir, "data", "previous-version", "NSFShield.exe")) == "old" &&
                             !Directory.Exists(Path.Combine(dstDir, "data", "previous-version", "data"));
                bool okLog = File.Exists(Path.Combine(dstDir, "data", "update.log"));
                Check("update installation: copy, settings kept, backup in data\\previous-version (without the data folder), log",
                      rc == 0 && okCopy && okKeep && okBak && okLog, "rc=" + rc + " copy=" + okCopy + " keep=" + okKeep + " backup=" + okBak + " log=" + okLog);
                int rc2 = Updater.Apply(dstDir, dstDir, 999999, "1.0.0", false, false);
                Check("update installation: same folder rejected", rc2 == 1);
                try { Directory.Delete(t, true); } catch { }
            }

            SecurityTests(Check);
            Phase2Tests(Check);
            Stage2Tests(Check);
            Stage3Tests(Check);
            Stage4Tests(Check);
            Stage5Tests(Check);
            Stage6Tests(Check);
            Stage7Tests(Check);
            ReleaseAssetTests(Check);
            LocalizationTests(Check);

            if (proxies.Contains("--update-live"))
            {
                string err;
                var li = Updater.Check(out err);
                Check("version info from GitHub", li != null && li.AssetUrl.Length > 0 && li.Sha256.Length == 64, li != null ? li.Tag + " " + li.AssetName + " sha " + li.Sha256.Substring(0, 12) : err);
                if (li != null)
                {
                    try
                    {
                        var prep = Updater.DownloadAndExtract(li, null, System.Threading.CancellationToken.None);
                        string exe = Path.Combine(prep.Root, "NSFShield.exe");
                        Check("download from GitHub + SHA-256 + opened from the same handle", File.Exists(exe) && Integrity.Sha256File(exe) == prep.ExeSha256 &&
                              prep.Root.StartsWith(Updater.UpdateRoot, StringComparison.OrdinalIgnoreCase), prep.Root);
                        Check("update: the downloaded zip is deleted after extraction", !Directory.GetFiles(Updater.UpdateRoot, "*.zip").Any());
                        File.AppendAllText(exe, "x");   // as if changed after extraction
                        try { Updater.StartApply(prep); Check("update: an exe changed after extraction is not started", false); }
                        catch (InvalidDataException) { Check("update: an exe changed after extraction is not started", true); }
                    }
                    catch (Exception ex) { Check("download from GitHub + SHA-256 + opened from the same handle", false, ex.Message); }
                    var badInfo = new UpdateInfo { Version = li.Version, AssetName = li.AssetName, AssetUrl = li.AssetUrl, Sha256 = new string('0', 64) };
                    try { Updater.DownloadAndExtract(badInfo, null, System.Threading.CancellationToken.None); Check("wrong hash rejected", false); }
                    catch (InvalidDataException) { Check("wrong hash rejected (file and folder deleted)", !Directory.GetFiles(Updater.UpdateRoot).Any() && !Directory.Exists(Path.Combine(Updater.UpdateRoot, "v" + li.Version))); }
                    var evil = new UpdateInfo { Version = li.Version, AssetName = "x.zip", AssetUrl = "https://example.com/x.zip", Sha256 = new string('0', 64) };
                    try { Updater.DownloadAndExtract(evil, null, System.Threading.CancellationToken.None); Check("non-GitHub address rejected", false); }
                    catch (InvalidOperationException) { Check("non-GitHub address rejected", true); }
                    Updater.Cleanup();
                }
            }

            if (proxies.Contains("--speed"))
            {
                var sr = SpeedTest.Run(null, System.Threading.CancellationToken.None);
                Check("speed test", sr.Error.Length == 0 && sr.PingMs > 0 && sr.DownMbps > 0 && sr.UpMbps > 0,
                      "latency " + sr.PingMs + " ms (jitter " + sr.JitterMs + "), download " + sr.DownMbps.ToString("0.0") + " Mbit/s (" + sr.DownBytes / 1048576 + " MB), upload " +
                      sr.UpMbps.ToString("0.0") + " Mbit/s " + sr.Error);
            }
            int bport = 18960;
            foreach (var u in proxies.Where(x => !x.StartsWith("--")))
            {
                if (!ProxyTools.TryParse(u, ProxyKind.Http, out var p, out var err)) { Check("proxy " + u, false, err); continue; }
                var r = ProxyTools.Test(p);
                Check("proxy test " + u, r.Ok, r.Ok ? r.TotalMs + " ms, exit " + r.ExitIp + " " + r.Country + (r.KindFixed ? " (type corrected → " + p.KindLabel + ")" : "") : r.Code + " " + r.Message);
                if (!r.Ok) continue;
                p.LocalPort = bport++;
                if (!ProxyBridge.Ensure(p, out var berr)) { Check("open bridge " + u, false, berr); continue; }
                var viaHttp = new ProxyEntry { Kind = ProxyKind.Http, Host = "127.0.0.1", Port = p.LocalPort };
                var viaSocks = new ProxyEntry { Kind = ProxyKind.Socks5, Host = "127.0.0.1", Port = p.LocalPort };
                var r1 = ProxyTools.Test(viaHttp, exitInfo: false, log: false);
                var r2 = ProxyTools.Test(viaSocks, exitInfo: false, log: false);
                Check("bridge HTTP CONNECT → " + u, r1.Ok, r1.Ok ? r1.TotalMs + " ms" : r1.Code + " " + r1.Message);
                Check("bridge SOCKS5 → " + u, r2.Ok, r2.Ok ? r2.TotalMs + " ms" : r2.Code + " " + r2.Message);
                try
                {
                    var req = (HttpWebRequest)WebRequest.Create("http://example.com/");
                    req.Proxy = new WebProxy("http://127.0.0.1:" + p.LocalPort);
                    req.Timeout = 10000;
                    using (var resp = (HttpWebResponse)req.GetResponse())
                    using (var rd = new StreamReader(resp.GetResponseStream()))
                        Check("bridge plain HTTP (example.com) → " + u, rd.ReadToEnd().Contains("Example Domain"), "HTTP " + (int)resp.StatusCode);
                }
                catch (Exception ex) { Check("bridge plain HTTP (example.com) → " + u, false, ex.Message); }
                ProxyBridge.Stop(p.Id);
            }
            completed = true;
            return sb.ToString();
        }

        /// <summary>Runs goodbyedpi.exe without elevation (RunAsInvoker): only to see how it parses its arguments.</summary>
        static string RunUnelevated(string exe, string args)
        {
            var psi = new System.Diagnostics.ProcessStartInfo(exe, args)
            {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
                WorkingDirectory = Path.GetDirectoryName(exe),
            };
            psi.EnvironmentVariables["__COMPAT_LAYER"] = "RunAsInvoker";
            using (var p = System.Diagnostics.Process.Start(psi))
            {
                var o = p.StandardOutput.ReadToEndAsync();
                var e = p.StandardError.ReadToEndAsync();
                if (!p.WaitForExit(10000)) { try { p.Kill(); } catch { } return "timeout"; }
                return o.Result + e.Result;
            }
        }

        // ==================================================================== helpers

        /// <summary>Runs a program with arguments (unelevated: "RunAsInvoker"), returns the exit code and the output.</summary>
        static (int Code, string Output) RunCapture(string exe, string args, int timeoutMs = 15000)
        {
            var psi = new System.Diagnostics.ProcessStartInfo(exe, args)
            {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
                WorkingDirectory = Path.GetDirectoryName(exe),
            };
            psi.EnvironmentVariables["__COMPAT_LAYER"] = "RunAsInvoker";
            using (var p = System.Diagnostics.Process.Start(psi))
            {
                var o = p.StandardOutput.ReadToEndAsync();
                var e = p.StandardError.ReadToEndAsync();
                if (!p.WaitForExit(timeoutMs)) { try { p.Kill(); } catch { } return (-1, "timeout"); }
                return (p.ExitCode, o.Result + e.Result);
            }
        }

        static int FreePort()
        {
            var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            l.Start();
            int port = ((IPEndPoint)l.LocalEndpoint).Port;
            l.Stop();
            return port;
        }

        /// <summary>stage 3: three engines (GoodbyeDPI, Zapret, ByeDPI), allow lists, integrity, domain lists, ByeDPI proxy safety.</summary>
        static void Stage3Tests(Action<string, bool, string> Check)
        {
            var oldSettings = App.Settings;
            var oldEngine = App.Engine;
            string oldBase = App.BaseDir, oldData = App.DataDir;
            App.Settings = new AppSettings();
            App.Settings.Normalize();
            if (App.Engine == null) App.Engine = new Engine();
            string repo = Repo;
            string tz = Path.Combine(repo, @"third_party\zapret"), tb = Path.Combine(repo, @"third_party\byedpi");
            // a package-like folder with a space in its name: bin\zapret, bin\zapret\payloads, bin\byedpi, data\lists
            string root = Path.Combine(Path.GetTempPath(), "nsf stage3 " + Guid.NewGuid().ToString("N").Substring(0, 6));
            try
            {
                // ------------------------------------------------------------ engines
                Check("engines: three engines with their own process and folder",
                      Engines.All.Count == 3 && Engines.All.Select(e => e.ProcessName).Distinct().Count() == 3 && Engines.All.Select(e => e.BinDir).Distinct().Count() == 3,
                      string.Join(", ", Engines.All.Select(e => e.DisplayName)));
                Check("engines: GoodbyeDPI and Zapret load their own WinDivert driver, ByeDPI none",
                      Engines.GoodbyeDpi.UsesDriver && Engines.Zapret.UsesDriver && !Engines.ByeDpi.UsesDriver &&
                      !string.Equals(Engines.GoodbyeDpi.DriverPath, Engines.Zapret.DriverPath, StringComparison.OrdinalIgnoreCase) && Engines.ByeDpi.DriverPath == null, "");
                Check("engines: service mode for GoodbyeDPI and Zapret, ByeDPI runs with the app (per-user Windows proxy)",
                      Engines.GoodbyeDpi.SupportsService && Engines.Zapret.SupportsService && !Engines.ByeDpi.SupportsService, "");
                Check("engines: list support (GoodbyeDPI include only; Zapret and ByeDPI include + exclude)",
                      Engines.GoodbyeDpi.SupportsInclude && !Engines.GoodbyeDpi.SupportsExclude && Engines.Zapret.SupportsExclude && Engines.ByeDpi.SupportsExclude, "");
                Check("engines: every engine has a recommended built-in profile first",
                      Engines.All.All(e => Profiles.ForEngine(Profiles.BuiltIns, e.Kind).FirstOrDefault()?.Group == Profiles.GroupRecommended), "");
                Check("engines: profile of 2.x (no Engine element) is GoodbyeDPI", new Profile().Engine == EngineKind.GoodbyeDpi && Engines.Of(null) == Engines.GoodbyeDpi, "");
                Check("engines: Zapret/ByeDPI profiles never redirect DNS", Profiles.BuiltIns.Where(p => !p.IsGoodbyeDpi).All(p => !p.UsesDnsRedirect && p.DnsTarget == null), "");
                Check("engines: WinDivert engines and all engine process names",
                      Engines.DriverProcessNames.SequenceEqual(new[] { "goodbyedpi", "winws" }) && Engines.AllProcessNames.SequenceEqual(new[] { "goodbyedpi", "winws", "ciadpi" }), "");

                // ------------------------------------------------------------ winws allow list
                foreach (var p in Profiles.ForEngine(Profiles.BuiltIns, EngineKind.Zapret))
                    Check("winws allow list accepts built-in: " + p.Id, WinwsPolicy.Validate(p.EngineArgs, out var ze), ze);
                string cap = "--wf-tcp=443 ";
                foreach (var (args, why) in new[]
                {
                    (cap + "--dry", "abbreviation (winws: --dry-run)"), (cap + "--hostlist-auto-d=x.txt", "abbreviation of the file-writing --hostlist-auto-debug"),
                    (cap + "--hostl=include.txt", "abbreviation of --hostlist"), ("-wf-tcp=443 -new", "single-dash form"),
                    (cap + "--hostlist-auto=auto.txt", "writes a file"), (cap + "--hostlist-auto-debug=log.txt", "writes a file"),
                    (cap + "--debug", "debug output"), (cap + "--debug=@C:\\log.txt", "debug to a file"), (cap + "--pidfile=x.pid", "writes a file"),
                    (cap + "--wf-save=filter.txt", "writes a file"), (cap + "--wf-raw=outbound", "raw filter"), (cap + "--ipset=ips.txt", "free path"),
                    (cap + "--hostlist=C:\\Windows\\win.ini", "absolute path"), (cap + "--hostlist=..\\..\\x.txt", "relative path"),
                    (cap + "--hostlist=\\\\server\\share\\x.txt", "UNC path"), (cap + "--hostlist=other.txt", "unmanaged list name"),
                    (cap + "--dpi-desync=fake --dpi-desync-fake-tls=C:\\evil.bin", "payload path"), (cap + "--dpi-desync-fake-tls=../evil.bin", "payload path with /"),
                    (cap + "--dpi-desync-fake-tls=\\\\srv\\x.bin", "UNC payload"), (cap + "--dpi-desync-fake-tls=evil.bin", "unknown payload name"),
                    ("@config.txt", "config file"), (cap + "--dpi-desync=fake&calc", "&"), (cap + "--dpi-desync=fake|calc", "|"), (cap + "--dpi-desync=%PATH%", "%"),
                    (cap + "--dpi-desync=fake;calc", ";"), (cap + "--dpi-desync=fake>x", ">"), (cap + "--dpi-desync=fake<x", "<"), (cap + "--dpi-desync=fake\r\n--debug", "CR LF"),
                    (cap + "--dpi-desync=\"fake\"", "quote"), (cap + "--dpi-desync=$x", "$"), (cap + "--dpi-desync=fa*ke", "glob"), ("--filter-tcp=443 --dpi-desync=fake", "no capture filter"),
                    (cap + "--wf-tcp=0", "port 0"), (cap + "--wf-tcp=443-80", "descending range"), (cap + "--dpi-desync=fake,bogus", "unknown method"), (cap + "--new=1", "flag with a value"),
                })
                    Check("winws allow list rejects (" + why + "): " + args.Replace("\r\n", "⏎"), !WinwsPolicy.Validate(args, out _), "");
                foreach (var args in new[] { cap + "--hostlist=include.txt --hostlist-exclude=exclude.txt", cap + "--dpi-desync=fake --dpi-desync-fake-tls=0x160301",
                                             cap + "--hostlist-domains=discord.com,discord.gg --dpi-desync=multisplit --dpi-desync-split-pos=1,midsld" })
                    Check("winws allow list accepts: " + args, WinwsPolicy.Validate(args, out var ae), ae);
                WinwsPolicy.Validate(cap + "--dry", out var abbrErr);
                Check("winws allow list names the full option of an abbreviation", abbrErr.Contains("--dry-run"), abbrErr);

                // ------------------------------------------------------------ ciadpi allow list
                foreach (var p in Profiles.ForEngine(Profiles.BuiltIns, EngineKind.ByeDpi))
                    Check("ciadpi allow list accepts built-in: " + p.Id, CiadpiPolicy.Validate(p.EngineArgs, out var be), be);
                foreach (var (args, why) in new[]
                {
                    ("--ip 0.0.0.0 --split 1", "listen address"), ("--port 1080 --split 1", "listen port"), ("--conn-ip :: --split 1", "outgoing bind address"),
                    ("--transparent --split 1", "transparent mode"), ("--hel", "abbreviation of --help"), ("--spl 1", "abbreviation of --split"), ("-s 1", "short option"),
                    ("-i 0.0.0.0 --split 1", "short listen address"), ("--split 1 --cache-dump cache.txt", "writes a file"), ("--split 1 --fake-data C:\\x.bin", "free path"),
                    ("--split 1 --hosts C:\\x.txt", "path"), ("--split 1 --hosts ..\\x.txt", "relative path"), ("--split 1 --hosts other.txt", "unmanaged list"),
                    ("--split 1 --ipset ips.txt", "free path"), ("--split 1 --md5sig", "Linux only"), ("--split", "missing value"), ("--auto=torst", "no method"),
                    ("--split 1&calc", "&"), ("--split 1|x", "|"), ("--split %x%", "%"), ("--split 1;x", ";"), ("--split 1>x", ">"), ("--split 1\nx", "LF"), ("--split @x", "@"),
                    ("--split 1+sz", "bad position"), ("--ttl 300 --split 1", "TTL range"),
                })
                    Check("ciadpi allow list rejects (" + why + "): " + args.Replace("\n", "⏎"), !CiadpiPolicy.Validate(args, out _), "");
                Check("ciadpi allow list accepts negative positions and --name=value", CiadpiPolicy.Validate("--fake -1 --ttl 8 --auto=torst,ssl_err --split=1+s --hosts include.txt", out var ne), ne);

                // ------------------------------------------------------------ package-like folder for building and running the engines
                Directory.CreateDirectory(Path.Combine(root, @"bin\zapret\payloads"));
                Directory.CreateDirectory(Path.Combine(root, @"bin\byedpi"));
                foreach (var f in Directory.GetFiles(Path.Combine(tz, "x86_64"))) File.Copy(f, Path.Combine(root, @"bin\zapret", Path.GetFileName(f)));
                foreach (var f in Directory.GetFiles(Path.Combine(tz, "payloads"))) File.Copy(f, Path.Combine(root, @"bin\zapret\payloads", Path.GetFileName(f)));
                File.Copy(Path.Combine(tb, @"x86_64\ciadpi.exe"), Path.Combine(root, @"bin\byedpi\ciadpi.exe"));
                App.BaseDir = root;
                App.DataDir = Path.Combine(root, "data");

                // ------------------------------------------------------------ integrity of the new engines
                Check("integrity: every file an engine verifies has an embedded hash", Engines.All.All(e => e.VerifiedFiles.All(Integrity.Known.ContainsKey)), "");
                using (var h = Integrity.VerifyAndLock(Engines.BinRoot, Engines.Zapret.VerifiedFiles.Concat(Engines.ByeDpi.VerifiedFiles), out var ie))
                {
                    Check("integrity: winws, cygwin1.dll, WinDivert 2.2.2, payloads and ciadpi match the official releases", h != null, ie);
                    bool locked;
                    try { using (new FileStream(Path.Combine(root, @"bin\zapret\payloads\stun.bin"), FileMode.Open, FileAccess.Write, FileShare.ReadWrite)) { } locked = false; }
                    catch (IOException) { locked = true; }
                    Check("integrity: payload files stay closed for writing while held (TOCTOU)", locked, "");
                }
                File.AppendAllText(Path.Combine(root, @"bin\zapret\payloads\stun.bin"), "x");
                using (var h2 = Integrity.VerifyAndLock(Engines.BinRoot, Engines.Zapret.VerifiedFiles, out var ce))
                    Check("integrity: a changed payload is rejected", h2 == null && ce.Contains("stun.bin"), ce);
                File.Copy(Path.Combine(tz, @"payloads\stun.bin"), Path.Combine(root, @"bin\zapret\payloads\stun.bin"), true);
                foreach (var readme in new[] { Path.Combine(tz, "README.md"), Path.Combine(tb, "README.md") })
                {
                    var lines = File.ReadAllLines(readme).Where(l => System.Text.RegularExpressions.Regex.IsMatch(l, "^[0-9a-f]{64}  ")).ToList();
                    string folder = Path.GetFileName(Path.GetDirectoryName(readme));
                    bool same = lines.Count > 0 && lines.All(l =>
                    {
                        string rel = l.Substring(66).Replace('/', '\\');
                        string key = folder + "\\" + (rel.StartsWith(@"x86_64\") ? rel.Substring(7) : rel);
                        return Integrity.Known.TryGetValue(key, out var hv) && hv == l.Substring(0, 64);
                    });
                    Check("integrity: third_party\\" + folder + "\\README.md lists the embedded hashes", same, lines.Count + " lines");
                }

                // ------------------------------------------------------------ domain lists
                foreach (var (input, want) in new[]
                {
                    ("discord.com", "discord.com"), ("https://www.Discord.com/app?x=1", "www.discord.com"), ("*.discordapp.net", "discordapp.net"),
                    ("cdn.discordapp.com:443", "cdn.discordapp.com"), ("m\u00fc\u015fteri.com.tr", "xn--mteri-kva70e.com.tr"), ("A-B.example.org.", "a-b.example.org"),
                })
                    Check("lists: accepted " + input, Hostlists.Normalize(input) == want, Hostlists.Normalize(input) ?? "null");
                foreach (var bad in new[] { "-bad.com", "--hostlist=x", "..\\x.com", "C:\\x.txt", "\\\\server\\share", "foo bar.com", "1.2.3.4", "com", "a..b.com",
                                            "x@y.com", "exa\tmple.com", "ex\u0001ample.com", new string('a', 64) + ".com", "localhost", "*.", "[::1]", "bad_.com" })
                    Check("lists: rejected " + bad.Replace("\t", "\\t").Replace("\u0001", "\\x01"), Hostlists.Normalize(bad) == null, Hostlists.Normalize(bad) ?? "");
                Check("lists: every template entry is a valid name",
                      Hostlists.IncludeTemplates.Concat(Hostlists.ExcludeTemplates).All(t => t.Domains.All(Hostlists.IsValidDomain) && Loc.Has("lists.template." + t.Key)), "");
                var (okL, badL) = Hostlists.ParseMany("discord.com\r\nhttps://x.example.org/a, bad_name.com;; -x.com #comment\n");
                Check("lists: pasted text is split; invalid parts are reported", okL.SequenceEqual(new[] { "discord.com", "x.example.org" }) && badL.Count == 2, string.Join("|", badL));
                string ld = Path.Combine(root, @"data\lists");
                bool onlyManaged;
                try { Hostlists.WriteAtomic("evil.txt", new[] { "a.com" }, ld); onlyManaged = false; } catch (ArgumentException) { onlyManaged = true; }
                try { Hostlists.WriteAtomic(@"..\include.txt", new[] { "a.com" }, ld); onlyManaged = false; } catch (ArgumentException) { }
                Check("lists: only the fixed names include.txt / exclude.txt can be written", onlyManaged, "");
                bool badRejected;
                try { Hostlists.WriteAtomic(Hostlists.IncludeName, new[] { "ok.com", "--debug" }, ld); badRejected = false; } catch (InvalidDataException) { badRejected = true; }
                Check("lists: an invalid line is never written", badRejected && !File.Exists(Path.Combine(ld, Hostlists.IncludeName)), "");
                Hostlists.WriteAtomic(Hostlists.IncludeName, new[] { "old.com" }, ld);
                string inc = Hostlists.WriteAtomic(Hostlists.IncludeName, new[] { "discord.com", "discord.gg" }, ld);
                Check("lists: atomic replace, LF lines, no temporary file left",
                      File.ReadAllText(inc) == "discord.com\ndiscord.gg\n" && Directory.GetFiles(ld).Length == 1, string.Join(", ", Directory.GetFiles(ld).Select(Path.GetFileName)));
                App.Settings.TargetedMode = true;
                App.Settings.TargetDomains = new List<string> { "discord.com", "discord.gg" };
                App.Settings.ExcludeEnabled = true;
                App.Settings.ExcludeDomains = new List<string> { "turkiye.gov.tr" };
                using (var hold = Hostlists.Prepare(Engines.GoodbyeDpi, App.Settings, out var gb, out var gw))
                    Check("lists: GoodbyeDPI gets the include list, the exclude list is reported as unsupported (NSF-606)",
                          gb.Include != null && gb.Exclude == null && gw.Count == 1 && gw[0].Key == "lists.excludeUnsupported", "");
                ListBinding zb;
                using (var hold = Hostlists.Prepare(Engines.Zapret, App.Settings, out zb, out var zw))
                {
                    bool wl;
                    try { using (new FileStream(zb.Include, FileMode.Open, FileAccess.Write, FileShare.ReadWrite)) { } wl = false; }
                    catch (IOException) { wl = true; }
                    Check("lists: Zapret gets both lists; they stay closed for writing while the engine runs", zb.Include != null && zb.Exclude != null && zw.Count == 0 && wl, "");
                }
                bool released;
                try { using (new FileStream(zb.Include, FileMode.Open, FileAccess.Write, FileShare.ReadWrite)) { } released = true; } catch (IOException) { released = false; }
                Check("lists: the files are released after the run", released, "");
                var sNorm = new AppSettings { TargetDomains = new List<string> { "discord.com", "C:\\x", "--x" }, ExcludeDomains = new List<string> { "bad name", "ok.org" } };
                sNorm.Normalize();
                Check("lists: settings keep only valid names", sNorm.TargetDomains.SequenceEqual(new[] { "discord.com" }) && sNorm.ExcludeDomains.SequenceEqual(new[] { "ok.org" }), "");
                string imp = Path.Combine(root, "import.xml");
                SettingsStore.Export(new AppSettings { ExcludeDomains = new List<string> { "..\\evil" } }, imp);
                bool impRejected;
                try { SettingsStore.Import(imp); impRejected = false; } catch (InvalidDataException) { impRejected = true; }
                Check("lists: importing settings with an invalid domain is refused", impRejected, "");

                // ------------------------------------------------------------ command lines
                var zp = Profiles.BuiltIns.First(p => p.Id == "zapret-discord");
                string zargs = Engines.Zapret.BuildArgs(zp, zb);
                var zsec = zargs.Split(new[] { " --new " }, StringSplitOptions.None);
                // stage 7: in targeted mode the Discord voice rule (no host name) is left out instead of running for all traffic
                Check("zapret: lists bound to the TCP and QUIC rules; the Discord voice rule is left out in targeted mode",
                      zsec.Length == 3 && zsec.All(x => x.Contains("--hostlist=") && x.Contains("--hostlist-exclude=")) && !zargs.Contains("--filter-l7=discord,stun"), zargs);
                Check("zapret: payload names become the verified files, paths with spaces are quoted",
                      zargs.Contains("\"--dpi-desync-fake-tls=" + Path.Combine(root, @"bin\zapret\payloads\tls_clienthello_www_google_com.bin") + "\"") &&
                      zargs.Contains("\"--hostlist=" + zb.Include + "\""), "");
                string znone = Engines.Zapret.BuildArgs(zp, ListBinding.None);
                Check("zapret: no list options when the lists are off", !znone.Contains("--hostlist"), "");
                var zexp = new Profile { Engine = EngineKind.Zapret, EngineArgs = cap + "--filter-tcp=443 --hostlist=include.txt --dpi-desync=fake" };
                Check("zapret: an explicit list is kept only while that list is on",
                      Engines.Zapret.BuildArgs(zexp, new ListBinding { Include = zb.Include }).Contains("--hostlist=") && !Engines.Zapret.BuildArgs(zexp, ListBinding.None).Contains("--hostlist"), "");
                int bport = FreePort();
                App.Settings.ByeDpiPort = bport;
                var bp = Profiles.BuiltIns.First(p => p.Id == "byedpi-recommended");
                string bargs = Engines.ByeDpi.BuildArgs(bp, zb);
                Check("byedpi: always listens on 127.0.0.1 with the port from the settings",
                      bargs.StartsWith("--ip 127.0.0.1 --port " + bport + " ") && !bargs.Contains("0.0.0.0"), bargs);
                Check("byedpi: exclude = first group without a method; include = every group limited, then an empty group",
                      bargs.Contains("--hosts \"" + zb.Exclude + "\" --auto none --hosts \"" + zb.Include + "\" --split 1+s") &&
                      bargs.Contains("--auto torst --hosts \"" + zb.Include + "\" --tlsrec 1+s") && bargs.EndsWith("--auto none"), bargs);
                Check("goodbyedpi: the include list is --blacklist",
                      Engines.GoodbyeDpi.BuildArgs(Profiles.BuiltIns[0], new ListBinding { Include = @"C:\a b\include.txt" }).Contains("--blacklist \"C:\\a b\\include.txt\""), "");

                // ------------------------------------------------------------ live: winws (zapret) parses with getopt_long_only
                string winws = Path.Combine(root, @"bin\zapret\winws.exe");
                var w0 = RunCapture(winws, "--dry-run --wf-tcp=443");
                Check("winws live: --dry-run checks parameters without the driver", w0.Code == 0 && w0.Output.Contains("command line parameters verified"), w0.Code + " " + Last(w0.Output));
                var w1 = RunCapture(winws, "--dry --wf-tcp=443");
                Check("winws live: the abbreviation --dry is accepted by winws → the allow list refuses it",
                      w1.Code == 0 && w1.Output.Contains("verified") && !WinwsPolicy.Validate("--wf-tcp=443 --dry", out _), w1.Code + " " + Last(w1.Output));
                var w2 = RunCapture(winws, "-dry-run -wf-tcp=443");
                Check("winws live: the single-dash form -dry-run is accepted by winws → the allow list refuses it",
                      w2.Code == 0 && w2.Output.Contains("verified") && !WinwsPolicy.Validate("-wf-tcp=443", out _), w2.Code + " " + Last(w2.Output));
                string dbg = Path.Combine(root, "abbrev-debug.txt");
                var w3 = RunCapture(winws, "--dry-run --wf-tcp=443 " + Engines.Quote("--hostlist-auto-d=" + dbg));
                Check("winws live: --hostlist-auto-d=<file> becomes the file-writing --hostlist-auto-debug → refused",
                      w3.Code == 0 && File.Exists(dbg) && !WinwsPolicy.Validate("--wf-tcp=443 --hostlist-auto-d=x.txt", out _), w3.Code + " file=" + File.Exists(dbg));
                var w4 = RunCapture(winws, "--dry-run --bogus-option=1");
                Check("winws live: an unknown option fails", w4.Code != 0 && w4.Output.Contains("unknown option"), w4.Code + " " + Last(w4.Output));
                foreach (var p in Profiles.ForEngine(Profiles.BuiltIns, EngineKind.Zapret))
                    foreach (var lists in new[] { ListBinding.None, zb })
                    {
                        var r = RunCapture(winws, "--dry-run " + Engines.Zapret.BuildArgs(p, lists));
                        Check("winws live: built-in " + p.Id + (lists == ListBinding.None ? "" : " + lists") + " passes --dry-run",
                              r.Code == 0 && r.Output.Contains("command line parameters verified"), r.Code + " " + Last(r.Output));
                    }

                // ------------------------------------------------------------ live: ciadpi (ByeDPI) parses with getopt_long
                string ciadpi = Path.Combine(root, @"bin\byedpi\ciadpi.exe");
                var c1 = RunCapture(ciadpi, "--hel");
                Check("ciadpi live: the abbreviation --hel is accepted (prints help) → the allow list refuses it",
                      c1.Output.Contains("--port") && !CiadpiPolicy.Validate("--hel", out _), Last(c1.Output));
                Check("ciadpi live: its own default address is 0.0.0.0, so the app always passes --ip 127.0.0.1",
                      c1.Output.Contains("default 0.0.0.0") && bargs.StartsWith("--ip 127.0.0.1"), "");
                var c2 = RunCapture(ciadpi, "--bogus-option");
                Check("ciadpi live: an unknown option fails", c2.Output.Contains("unknown option"), Last(c2.Output));
                foreach (var p in Profiles.ForEngine(Profiles.BuiltIns, EngineKind.ByeDpi))
                {
                    App.Settings.ByeDpiPort = FreePort();
                    var psi = new System.Diagnostics.ProcessStartInfo(ciadpi, Engines.ByeDpi.BuildArgs(p, zb)) { UseShellExecute = false, CreateNoWindow = true };
                    using (var proc = System.Diagnostics.Process.Start(psi))
                    {
                        bool listens = ByeDpiNet.WaitListening(ByeDpiNet.SocksPort, proc, 5000);
                        bool loop = listens && ByeDpiNet.LoopbackOnly(ByeDpiNet.SocksPort, out string bound);
                        ByeDpiNet.LoopbackOnly(ByeDpiNet.SocksPort, out bound);
                        bool alive = !proc.HasExited;
                        try { proc.Kill(); proc.WaitForExit(3000); } catch { }
                        Check("ciadpi live: built-in " + p.Id + " starts and listens on 127.0.0.1 only", listens && loop && alive, bound);
                    }
                }
                Check("ciadpi live: port check sees a busy port", !ByeDpiNet.PortFree(UsePort(out var busy)), "");
                busy.Stop();

                // ------------------------------------------------------------ mutual exclusion, switching, upgrade and uninstall
                string engSrc = File.ReadAllText(Path.Combine(repo, @"src\Core\Engine.cs"));
                int st0 = engSrc.IndexOf("public bool Start(Profile p", StringComparison.Ordinal);
                string startBody = engSrc.Substring(st0, engSrc.IndexOf("void ReleaseLists()", st0, StringComparison.Ordinal) - st0);
                Check("switch: a start first stops every engine (process, service, ByeDPI proxy), then frees the WinDivert driver the new engine does not use",
                      startBody.IndexOf("StopInternal(foreignService: takeOver);", StringComparison.Ordinal) > 0 &&
                      startBody.IndexOf("StopInternal(foreignService: takeOver);", StringComparison.Ordinal) < startBody.IndexOf("DriverControl.Release(App.BaseDir, dlog, eng.UsesDriver ? eng.DriverPath : null)", StringComparison.Ordinal) &&
                      startBody.IndexOf("DriverControl.Release(", StringComparison.Ordinal) < startBody.IndexOf("StartProcess(eng, args)", StringComparison.Ordinal), "");
                int si0 = engSrc.IndexOf("void StopInternal(bool foreignService = false)", StringComparison.Ordinal);
                Check("switch: stopping restores the ByeDPI proxy and releases the list files",
                      engSrc.IndexOf("ByeDpiNet.Detach();", si0, StringComparison.Ordinal) > si0 && engSrc.IndexOf("ReleaseLists();", si0, StringComparison.Ordinal) > si0, "");
                string dcSrc = File.ReadAllText(Path.Combine(repo, @"src\Core\DriverControl.cs"));
                int r0 = dcSrc.IndexOf("public static void Release(", StringComparison.Ordinal), r1 = dcSrc.IndexOf("public static bool WaitStopped", StringComparison.Ordinal);
                string relBody = r0 > 0 && r1 > r0 ? dcSrc.Substring(r0, r1 - r0) : "";
                Check("switch: the driver is only stopped (never deleted), skipped while another WinDivert program runs",
                      relBody.Contains(".Stop()") && relBody.Contains("WaitStopped(") && relBody.Contains("DriverUserRunning()") && !relBody.Contains("Delete") && !relBody.Contains("delete"), "");
                string unSrc = File.ReadAllText(Path.Combine(repo, @"src\Core\Uninstall.cs"));
                int pu = unSrc.IndexOf("public static int PrepareUpgrade", StringComparison.Ordinal);
                Check("upgrade: --prepare-upgrade closes goodbyedpi, winws and ciadpi of the folder (exact exe paths), frees the drivers and restores the ByeDPI proxy",
                      unSrc.IndexOf("PathSafety.Same(pe.Path, exe)", pu, StringComparison.Ordinal) > pu && unSrc.IndexOf("ProcReader.TerminateIf(pe.Pid, path => ProcReader.IsFile(path, exe)", pu, StringComparison.Ordinal) > pu &&
                      unSrc.IndexOf("ReleaseDrivers(dir, log);", pu, StringComparison.Ordinal) > pu &&
                      unSrc.IndexOf("ByeDpiNet.RecoverStale(", pu, StringComparison.Ordinal) > pu, "");
                int ru = engSrc.IndexOf("public void RemoveForUninstall", StringComparison.Ordinal);
                Check("uninstall: the engine processes of the folder (exact exe paths) and the ByeDPI proxy are removed",
                      engSrc.IndexOf("PathSafety.Same(pe.Path, e.ExePath)", ru, StringComparison.Ordinal) > ru && unSrc.Contains("ByeDpiNet.RecoverStale(\"clean uninstall\")"), "");
                string iss = File.ReadAllText(Path.Combine(repo, @"installer\NSFShield.iss"));
                Check("setup script: winws and ciadpi are closed too, another winws keeps its driver, data\\ is never in the package",
                      iss.Contains("winws.exe") && iss.Contains("ciadpi.exe") && iss.Contains("OtherDriverUserRunning") && !iss.Contains("{app}\\data\"; Flags") &&
                      !System.Text.RegularExpressions.Regex.IsMatch(iss, @"\[InstallDelete\][^\[]*\{app\}\\data"), "");

                // ------------------------------------------------------------ quick engine switch and remembered profiles
                App.Settings.SelectedProfileId = "tr-recommended";
                var z2 = Profiles.BuiltIns.First(p => p.Id == "zapret-aggressive");
                App.Settings.RememberProfile(z2);
                Check("switch: the last profile of every engine is remembered",
                      App.Settings.LastProfileId(EngineKind.Zapret) == "zapret-aggressive" && App.Settings.LastProfileId(EngineKind.ByeDpi) == "", "");
                var tray = new EngineTrayChoices().Items().ToList();
                Check("tray: the engine menu lists the three engines and checks the active one",
                      tray.Count == 3 && tray.Count(c => c.Checked) == 1 && tray.First(c => c.Checked).Id == "GoodbyeDpi", string.Join(",", tray.Select(c => c.Label)));
                Check("tray: the method menu lists only the profiles of the active engine",
                      new ProfileTrayChoices().Items().All(c => App.FindProfile(c.Id).IsGoodbyeDpi), "");
                Check("tray: the engine tips exist in the language files", Engines.All.All(e => Loc.Has("engines." + e.Id + ".tip") && Loc.Has("profilesPage.engineInfo." + e.Id)) &&
                      Loc.Has("engineEdit.help.zapret") && Loc.Has("engineEdit.help.byedpi") &&
                      Profiles.BuiltIns.All(p => Loc.Has("profiles.builtin." + p.Id + ".name") && Loc.Has("profiles.builtin." + p.Id + ".description")), "");

                // ------------------------------------------------------------ profile codes of the new engines (NSF1)
                var zcode = ProfileCode.ToCode(z2.CloneAsCustom());
                bool zback = ProfileCode.TryFromCode(zcode, out var zi, out var zerr);
                Check("profile code: a Zapret profile keeps its engine and parameters (NSF1)",
                      zcode.StartsWith(ProfileCode.Prefix) && zback && zi.Engine == EngineKind.Zapret && zi.EngineArgs == z2.EngineArgs, zerr);
                foreach (var (engine, args) in new[] { (EngineKind.Zapret, cap + "--hostlist-auto=x.txt"), (EngineKind.ByeDpi, "--ip 0.0.0.0 --split 1"), (EngineKind.Zapret, cap + "--debug=@x") })
                {
                    var evil = new Profile { Name = "x", Engine = engine, EngineArgs = args };
                    Check("profile code: an unsafe " + engine + " code is refused (reader and writer): " + args,
                          !ProfileCode.TryFromCode(ProfileCode.ToCodeUnchecked(evil), out _, out _) && !ProfileCode.TryToCode(evil, out _, out _), "");
                }
                Check("scripts: .cmd scripts are only made for GoodbyeDPI profiles",
                      Throws<InvalidDataException>(() => Scripts.Build(z2, "..\\bin")), "");

                // ------------------------------------------------------------ ByeDPI proxy safety (no system change in the test)
                // stage 7: the sign-in restore is one entry for the recovery helper (quoted full path, one fixed argument; no reg.exe,
                // cmd or script host); the record keeps every value with its existence, also a long configuration script address
                string helperCmd = ProxyRecovery.HelperCommand(@"C:\Program Files\NSF Shield\bin\" + ProxyRecovery.HelperFile);
                var longPac = "http://pac.example.test/" + new string('p', 3000) + ".pac";
                var recT = new ProxyRecord { Owner = ByeDpiNet.ProxyMarker, AtSignIn = true,
                    Backup = new[] { ProxyValue.Absent, ProxyValue.Text("10.0.0.1:3128"), ProxyValue.Absent, ProxyValue.Text(longPac) },
                    Written = ProxyRecovery.For(ByeDpiNet.BridgeAddress, ProxyTools.LocalBypass) };
                var recBack = ProxyRecord.Parse(recT.Serialize());
                string torn = recT.Serialize();
                Check("byedpi proxy: the sign-in entry starts the recovery helper only (no reg.exe, cmd or script host); the record keeps all four values, a 3000-character PAC too, and a torn or edited record is never used",
                      helperCmd == "\"C:\\Program Files\\NSF Shield\\bin\\NSFShieldProxyRecovery.exe\" --restore" &&
                      !new[] { "reg.exe", "cmd", "power" + "shell", "w" + "script", "c" + "script", "ms" + "hta" }.Any(x => helperCmd.IndexOf(x, StringComparison.OrdinalIgnoreCase) >= 0) &&
                      recBack != null && recBack.Owner == recT.Owner && recBack.AtSignIn && !recBack.Backup[0].Exists && recBack.Backup[3].Data == longPac &&
                      recBack.Written[2].Data == ProxyTools.LocalBypass && !recBack.Written[3].Exists &&
                      ProxyRecord.Parse(torn.Substring(0, torn.Length / 2)) == null && ProxyRecord.Parse(torn.Replace("NSFR1", "NSFR2")) == null &&
                      ProxyRecord.Parse(torn.Substring(0, torn.Length - 1) + (torn.EndsWith("0") ? "1" : "0")) == null, helperCmd);
                Check("byedpi proxy: the engine entry is local only and never saved",
                      ByeDpiNet.Entry.Host == "127.0.0.1" && ByeDpiNet.Entry.LocalPort == ByeDpiNet.SocksPort + 1 &&
                      new Func<bool>(() => { var s = new AppSettings(); s.Proxies.Add(ByeDpiNet.Entry); s.Normalize(); return s.Proxies.Count == 0; })(), "");
                App.Settings.SystemProxyId = "";
                Check("byedpi proxy: recovery does nothing when the proxy is not ours", !ByeDpiNet.RecoverStale("test"), "");
                string bnSrc = File.ReadAllText(Path.Combine(repo, @"src\Core\ByeDpiNet.cs"));
                int armAt = bnSrc.IndexOf("ProxyRecovery.Arm(rec, helper", StringComparison.Ordinal), persistAt = bnSrc.IndexOf("if (!Persist())", StringComparison.Ordinal),
                    liveAt = bnSrc.IndexOf("ProxyRecovery.WriteLive(rec.Written", StringComparison.Ordinal);
                Check("byedpi proxy: the record, the sign-in entry and the marker are saved before Windows is changed; the guard acts only on a ByeDPI record",
                      armAt > 0 && persistAt > armAt && liveAt > persistAt && bnSrc.Contains("if (!RecordIsOurs()) return 0;") &&
                      engSrc.Contains("if (eng.Kind == EngineKind.ByeDpi) ByeDpiNet.Detach();"), "");
                Check("byedpi proxy: the bridge only listens on the loopback address",
                      File.ReadAllText(Path.Combine(repo, @"src\Core\ProxyBridge.cs")).Contains("new TcpListener(IPAddress.Loopback, p.LocalPort)"), "");
            }
            catch (Exception ex) { Check("stage 3 tests ran without an exception", false, ex.GetType().Name + ": " + ex.Message); }
            finally
            {
                App.BaseDir = oldBase;
                App.DataDir = oldData;
                App.Settings = oldSettings;
                App.Engine = oldEngine;
                try { Directory.Delete(root, true); } catch { }
            }
        }

        static string Last(string output) =>
            string.Join(" | ", (output ?? "").Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0).Reverse().Take(1)).Replace(Path.GetTempPath().TrimEnd('\\'), "%TEMP%");

        static bool Throws<T>(Action a) where T : Exception
        {
            try { a(); return false; } catch (T) { return true; }
        }

        static int UsePort(out System.Net.Sockets.TcpListener l)
        {
            l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            l.Start();
            return ((IPEndPoint)l.LocalEndpoint).Port;
        }

        /// <summary>stage 2: theme draft and contrast, presets and "follow Windows", tray status, switch to the installed version.</summary>
        static void Stage2Tests(Action<string, bool, string> Check)
        {
            // ---------------------------------------------------------------- WCAG contrast
            Color Hx(string h) { Palettes.TryParseColor(h, out var c); return c; }
            double bw = Wcag.Ratio(Color.Black, Color.White);
            Check("WCAG: black on white is 21:1", Math.Abs(bw - 21) < 0.001, bw.ToString("0.000"));
            double r777 = Wcag.Ratio(Hx("#777777"), Color.White), r767 = Wcag.Ratio(Hx("#767676"), Color.White);
            Check("WCAG: #777777 on white is below AA, #767676 meets it", r777 < Wcag.AA && r767 >= Wcag.AA && Math.Abs(Wcag.Ratio(Color.White, Hx("#767676")) - r767) < 1e-9,
                  r777.ToString("0.00") + " / " + r767.ToString("0.00"));
            var lowP = Palettes.Base("clean-light");
            lowP.Muted = Hx("#CBD5E1");
            var low = Wcag.Low(lowP);
            Check("WCAG: a pale secondary text on the card is reported, the other pairs are not",
                  low.Count == 1 && low[0].Pair == "appearancePage.pair.mutedCard" && low[0].Ratio < Wcag.AA, string.Join(", ", low.Select(l => l.Pair + " " + l.Ratio.ToString("0.00"))));
            Check("WCAG: every pair has a text in en.json", Wcag.Pairs(lowP).All(p => Loc.Has(p.Pair)), "");

            // ---------------------------------------------------------------- presets
            var featured = Palettes.FeaturedIds.Select(Palettes.Base).ToList();
            Check("presets: Slate Dark, AMOLED Black, Nord and Clean Light exist",
                  Palettes.FeaturedIds.SequenceEqual(new[] { "slate-dark", "amoled", "nord", "clean-light" }) && Palettes.FeaturedIds.All(Palettes.IsKnown) &&
                  featured.Select(p => p.Group).SequenceEqual(new[] { "dark", "dark", "dark", "light" }) &&
                  featured.Take(3).All(p => p.IsDark) && !featured[3].IsDark && Palettes.Presets.Select(p => p.Id).Distinct().Count() == Palettes.Presets.Count,
                  string.Join(", ", featured.Select(p => p.Id + "/" + p.Group)));
            var featuredLow = featured.SelectMany(p => Wcag.Low(p).Select(l => p.Id + ":" + l.Pair)).ToList();
            Check("presets: the recommended themes meet WCAG AA for every text pair", featuredLow.Count == 0, string.Join(", ", featuredLow));
            Check("presets: defaults for follow Windows", Palettes.DefaultDarkId == "slate-dark" && Palettes.DefaultLightId == "clean-light" &&
                  new AppSettings().DarkThemeId == "slate-dark" && new AppSettings().LightThemeId == "clean-light" && !new AppSettings().FollowSystem, "");

            // ---------------------------------------------------------------- follow Windows light/dark
            var fs = new AppSettings { ThemeId = "dracula", FollowSystem = false, LightThemeId = "clean-light", DarkThemeId = "amoled" };
            bool offOk = Palettes.EffectiveBaseId(fs, true) == "dracula" && Palettes.EffectiveBaseId(fs, false) == "dracula";
            fs.FollowSystem = true;
            bool onOk = Palettes.EffectiveBaseId(fs, true) == "amoled" && Palettes.EffectiveBaseId(fs, false) == "clean-light" &&
                        Palettes.Resolve(fs, true).Id == "amoled" && Palettes.Resolve(fs, false).Id == "clean-light";
            fs.DarkThemeId = "no-such-theme"; fs.LightThemeId = "";
            bool fbOk = Palettes.EffectiveBaseId(fs, true) == Palettes.DefaultDarkId && Palettes.EffectiveBaseId(fs, false) == Palettes.DefaultLightId;
            var norm = new AppSettings { LightThemeId = "", DarkThemeId = null };
            norm.Normalize();
            Check("follow Windows: off uses the selected theme, on picks the light/dark theme, unknown ids fall back",
                  offOk && onOk && fbOk && norm.LightThemeId == Palettes.DefaultLightId && norm.DarkThemeId == Palettes.DefaultDarkId, offOk + " " + onOk + " " + fbOk);
            bool sys = Palettes.SystemDark();
            object reg = null;
            try { using (var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")) reg = k?.GetValue("AppsUseLightTheme"); }
            catch (Exception ex) { App.Ignored("Theme registry value could not be read", ex); }
            Check("follow Windows: the Windows mode is read from AppsUseLightTheme", reg is int v ? sys == (v == 0) : !sys, "dark=" + sys + " value=" + (reg ?? "none"));

            // a saved settings file with only a theme gives the same theme (no follow Windows, no custom colors)
            string fixture = Path.Combine(Path.GetTempPath(), "nsf-theme-" + Guid.NewGuid().ToString("N").Substring(0, 6) + ".xml");
            try
            {
                File.WriteAllText(fixture, "<?xml version=\"1.0\" encoding=\"utf-8\"?><AppSettings><ThemeId>dracula</ThemeId></AppSettings>");
                var old = SettingsStore.ReadFile(fixture);
                old.Normalize();
                Check("themes: saved settings resolve to the same theme",
                      !old.FollowSystem && old.ThemeId == "dracula" && Palettes.Resolve(old, true).ToCode() == Palettes.Base("dracula").ToCode() &&
                      Palettes.Resolve(old, false).ToCode() == Palettes.Base("dracula").ToCode(), old.ThemeId);
                var withColors = SettingsStore.ReadFile(fixture);
                withColors.ThemeOverrides.Add(new ThemeColor { Key = "Accent", Hex = "#FF0000" });
                withColors.ThemeOverrides.Add(new ThemeColor { Key = "Nope", Hex = "#00FF00" });
                var wc = Palettes.Resolve(withColors, false);
                Check("themes: custom colors apply on top of the theme (unknown keys ignored)", wc.Id == "dracula" && wc.Custom && wc.Accent.ToArgb() == Color.Red.ToArgb() &&
                      wc.Bg.ToArgb() == Palettes.Base("dracula").Bg.ToArgb(), wc.ToCode());
            }
            catch (Exception ex) { Check("themes: saved settings tests", false, ex.Message); }
            finally { try { File.Delete(fixture); } catch { } }

            // ---------------------------------------------------------------- theme draft
            var ds = new AppSettings { ThemeId = "nord" };
            var before = Theme.Current?.ToCode();
            var draft = new ThemeDraft(ds, true);
            bool cleanStart = !draft.Dirty && draft.Current && draft.Overrides().Count == 0;
            draft.Set("Accent", Hx("#FF00AA"));
            draft.Set("Muted", Hx("#3B4252"));
            bool untouched = ds.ThemeOverrides.Count == 0 && Theme.Current?.ToCode() == before && Palettes.Resolve(ds, true).ToCode() == Palettes.Base("nord").ToCode();
            Check("draft: editing does not change the theme in use or the settings", cleanStart && draft.Dirty && untouched && draft.Overrides().Count == 2, cleanStart + " " + untouched);
            Check("draft: the low contrast of the draft is reported", draft.LowContrast().Any(l => l.Pair == "appearancePage.pair.mutedCard"), "");
            draft.Cancel();
            Check("draft: Cancel goes back to the colors in use", !draft.Dirty && draft.Colors.ToCode() == Palettes.Base("nord").ToCode() && ds.ThemeOverrides.Count == 0, "");
            draft.Set("Accent", Hx("#FF00AA"));
            draft.Apply();
            bool applied = ds.ThemeOverrides.Count == 1 && ds.ThemeOverrides[0].Key == "Accent" && ds.ThemeOverrides[0].Hex == "#FF00AA" && !draft.Dirty &&
                           Palettes.Resolve(ds, true).Accent.ToArgb() == Hx("#FF00AA").ToArgb() && Palettes.Resolve(ds, true).Custom;
            draft.ResetToBase();
            bool resetDirty = draft.Dirty && draft.Overrides().Count == 0;
            draft.Apply();
            Check("draft: Apply writes only the changed colors, Reset removes them", applied && resetDirty && ds.ThemeOverrides.Count == 0 && !Palettes.Resolve(ds, true).Custom,
                  applied + " " + resetDirty);
            Check("draft: Apply does not change the theme in use by itself", Theme.Current?.ToCode() == before, "");

            // ---------------------------------------------------------------- tray status
            var none = new Severity[0];
            Check("tray: status from engine state and problems",
                  TrayLook.From(EngineState.Running, none) == TrayStatus.Active &&
                  TrayLook.From(EngineState.Running, new[] { Severity.Info }) == TrayStatus.Active &&
                  TrayLook.From(EngineState.Running, new[] { Severity.Info, Severity.Warning }) == TrayStatus.Warning &&
                  TrayLook.From(EngineState.Running, new[] { Severity.Error }) == TrayStatus.Warning &&
                  TrayLook.From(EngineState.Stopped, new[] { Severity.Error }) == TrayStatus.Off &&
                  TrayLook.From(EngineState.Starting, none) == TrayStatus.Busy && TrayLook.From(EngineState.Stopping, none) == TrayStatus.Busy &&
                  TrayLook.From(EngineState.Error, none) == TrayStatus.Error, "");
            var px = new List<string>();
            foreach (TrayStatus t in Enum.GetValues(typeof(TrayStatus)))
                using (var ic = TrayLook.MakeIcon(t, 32)) using (var bmp = ic.ToBitmap()) px.Add(bmp.GetPixel(16, 6).ToArgb().ToString("X8"));
            Check("tray: every status has its own icon", px.Distinct().Count() == px.Count, string.Join(" ", px));
            Check("tray: the menu is built from choice sources (engine switch can be added)", TrayMenus.Choices.Count >= 1 && TrayMenus.Choices.All(c => Loc.Has(c.TitleKey)), "");

            // ---------------------------------------------------------------- upgrade: the loaded WinDivert driver is unloaded, never deleted
            string pf = @"C:\Program Files\NSF Shield\";
            Check("upgrade: only a WinDivert driver loaded from the installation folder is unloaded",
                  Uninstaller.DriverInFolder(@"\??\C:\Program Files\NSF Shield\bin\x86_64\WinDivert64.sys", pf) &&
                  Uninstaller.DriverInFolder(@"\??\c:\program files\nsf shield\BIN\x86\WinDivert32.sys", pf.TrimEnd('\\')) &&
                  Uninstaller.DriverInFolder(@"""C:\Program Files\NSF Shield\bin\x86_64\WinDivert64.sys""", pf) &&
                  !Uninstaller.DriverInFolder(@"\??\C:\Program Files\NSF Shield2\bin\x86_64\WinDivert64.sys", pf) &&
                  !Uninstaller.DriverInFolder(@"\??\C:\Program Files\NSF Shield\..\Other\WinDivert64.sys", pf) &&
                  !Uninstaller.DriverInFolder(@"\SystemRoot\System32\drivers\WinDivert64.sys", pf) &&
                  !Uninstaller.DriverInFolder(@"System32\drivers\WinDivert64.sys", pf) &&
                  !Uninstaller.DriverInFolder(@"\??\UNC\server\share\NSF Shield\WinDivert64.sys", @"\\server\share\NSF Shield") &&
                  !Uninstaller.DriverInFolder(null, pf) && !Uninstaller.DriverInFolder("", pf) &&
                  !Uninstaller.DriverInFolder(@"\??\C:\Program Files\NSF Shield\bin\x86_64\WinDivert64.sys", null), "");
            string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            Check("upgrade: \\SystemRoot and relative driver paths resolve to the Windows folder",
                  Uninstaller.DriverFile(@"\SystemRoot\System32\drivers\x.sys") == Path.Combine(win, @"System32\drivers\x.sys") &&
                  Uninstaller.DriverFile(@"System32\drivers\x.sys") == Path.Combine(win, @"System32\drivers\x.sys"), "");
            Check("upgrade: WinDivert 2.x and 1.4 driver service names", Uninstaller.DriverServices.Contains("WinDivert") && Uninstaller.DriverServices.Contains("WinDivert1.4"), "");
            string unSrc = File.ReadAllText(Path.Combine(Repo, @"src\Core\Uninstall.cs"));
            string dcSrc0 = File.ReadAllText(Path.Combine(Repo, @"src\Core\DriverControl.cs"));
            int rd0 = dcSrc0.IndexOf("public static void Release(", StringComparison.Ordinal), rd1 = dcSrc0.IndexOf("public static bool WaitStopped", StringComparison.Ordinal);
            string rdBody = rd0 > 0 && rd1 > rd0 ? dcSrc0.Substring(rd0, rd1 - rd0) : "";
            int pu0 = unSrc.IndexOf("public static int PrepareUpgrade", StringComparison.Ordinal);
            Check("upgrade: --prepare-upgrade unloads the driver with Stop and waits, never deletes it",
                  rdBody.Contains(".Stop()") && rdBody.Contains("WaitStopped(") && !rdBody.Contains("Delete") && !rdBody.Contains("delete") &&
                  unSrc.Contains("static void ReleaseDrivers(string dir, StringBuilder log) => DriverControl.Release(dir, log);") &&
                  unSrc.IndexOf("ReleaseDrivers(dir, log);", pu0, StringComparison.Ordinal) > pu0, "");
            try
            {
                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\WinDivert"))
                    if (key != null)
                        using (var sc = new System.ServiceProcess.ServiceController("WinDivert"))
                            Check("upgrade: the state of the WinDivert driver can be read (read only)", true, sc.Status.ToString());
            }
            catch (InvalidOperationException) { /* removed in the meantime */ }
            catch (Exception ex) { Check("upgrade: the state of the WinDivert driver can be read (read only)", false, ex.Message); }
            string issText = File.ReadAllText(Path.Combine(Repo, @"installer\NSFShield.iss"));
            var issLines = issText.Split('\n').Select(l => l.Trim()).ToList();
            var sysLine = issLines.FirstOrDefault(l => l.StartsWith("Source:") && l.Contains("\\*.sys\""));
            var mainLine = issLines.FirstOrDefault(l => l.StartsWith("Source:") && l.Contains("\\*\";"));
            Check("setup script: drivers are unloaded before copying, a locked newer .sys is replaced at restart, silent updates never reboot",
                  mainLine != null && mainLine.Contains("Excludes: \"*.sys\"") && sysLine != null && sysLine.Contains("restartreplace") && !sysLine.Contains("ignoreversion") &&
                  issText.Contains("ReleaseDrivers;") && issText.Contains("'stop \"'") && !issText.Contains("'delete \"'") && issText.Contains("ReleaseDriver('WinDivert1.4')") &&
                  File.ReadAllText(Path.Combine(Repo, @"src\Core\Updater.cs")).Contains("/VERYSILENT /SUPPRESSMSGBOXES /NORESTART") &&
                  File.ReadAllText(Path.Combine(Repo, @"src\Core\InstallerSwitch.cs")).Contains("/NORESTART"), sysLine ?? "no .sys line");

            // ---------------------------------------------------------------- switch to the installed version
            string t0 =Path.Combine(Path.GetTempPath(), "nsf-switch-" + Guid.NewGuid().ToString("N").Substring(0, 6));
            string selfExe = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
            try
            {
                string good = Path.Combine(t0, "Program Files", "NSF Shield"), empty = Path.Combine(t0, "empty"), self = Path.Combine(t0, "self");
                Directory.CreateDirectory(good); Directory.CreateDirectory(empty); Directory.CreateDirectory(self);
                File.Copy(selfExe, Path.Combine(good, "NSFShield.exe"));
                File.Copy(selfExe, Path.Combine(self, "NSFShield.exe"));
                File.WriteAllText(Path.Combine(empty, "NSFShield.exe"), "not an exe");
                Func<string, bool> yes = d => true, no = d => false;
                var rejected = new List<string>();
                foreach (var (dir, selfDir, prot, name) in new[]
                {
                    ((string)null, "", yes, "null"), ("", "", yes, "empty"), (@"relative\NSF Shield", "", yes, "relative"), (@"\\server\share\NSF Shield", "", yes, "UNC"),
                    ("//server/share", "", yes, "UNC/"), (good + @"\..\NSF Shield", "", yes, ".."), (self, self + "\\", yes, "own folder"), (empty, "", yes, "not NSF Shield"),
                    (Path.Combine(t0, "missing"), "", yes, "missing"), (good, "", no, "unprotected"),
                })
                    if (InstallerSwitch.ValidateTarget(dir, selfDir, prot, out _)) rejected.Add(name);
                bool unprotMsg = !InstallerSwitch.ValidateTarget(good, "", no, out string uerr) && uerr.Contains(good);
                Check("switch: unsafe installation folders are rejected", rejected.Count == 0 && unprotMsg, "accepted: " + string.Join(", ", rejected));
                Check("switch: a protected folder with NSF Shield is accepted", InstallerSwitch.ValidateTarget(good, self, yes, out string gerr), gerr);

                string tsp = InstallerSwitch.TargetSettingsPath(good + "\\");
                Check("switch: settings go only to <installation>\\data\\settings.xml", tsp == Path.Combine(good, "data", "settings.xml"), tsp.Substring(t0.Length));

                // settings pass the import checks; service and start with Windows are offered again in the installed copy
                var src = new AppSettings
                {
                    ServiceMode = true, StartWithWindows = true, LastUpdateCheck = DateTime.Now, SkipVersion = "9.9.9", Language = "tr", ThemeId = "nord",
                    FollowSystem = true, DarkThemeId = "amoled", SelectedProfileId = "tr-alt",
                };
                src.ThemeOverrides.Add(new ThemeColor { Key = "Accent", Hex = "#123456" });
                src.DnsBackups.Add(new DnsBackup { Adapter = "Ethernet", V4Dhcp = false, V4 = new List<string> { "192.0.2.53" } });
                var cust = Profiles.BuiltIns.First(x => x.Id == "tr-alt").CloneAsCustom();
                cust.Name = "My profile";
                src.CustomProfiles.Add(cust);
                var work = Path.Combine(t0, "work");
                var clean = InstallerSwitch.Prepare(src, work);
                Check("switch: settings carried over, service/startup reset, hint hidden",
                      !clean.ServiceMode && !clean.StartWithWindows && clean.LastUpdateCheck == null && clean.SkipVersion == "" && clean.InstallerHintDismissed &&
                      clean.Language == "tr" && clean.ThemeId == "nord" && clean.FollowSystem && clean.DarkThemeId == "amoled" && clean.ThemeOverrides.Count == 1 &&
                      clean.SelectedProfileId == "tr-alt" && clean.CustomProfiles.Count == 1 && clean.DnsBackups.Count == 1 && clean.DnsBackups[0].V4[0] == "192.0.2.53" &&
                      src.ServiceMode && !Directory.EnumerateFiles(work).Any(), "");
                var evil = new AppSettings();
                var ep = Profiles.BuiltIns.First(x => x.Id == "tr-alt").CloneAsCustom();
                ep.UseRaw = true; ep.RawArgs = "-9 & calc";
                evil.CustomProfiles.Add(ep);
                bool blocked;
                try { InstallerSwitch.Prepare(evil, work); blocked = false; } catch (InvalidDataException) { blocked = true; }
                var evilDns = new AppSettings();
                evilDns.DnsBackups.Add(new DnsBackup { Adapter = "x", V4 = new List<string> { "1.1.1.1 & calc" } });
                bool blockedDns;
                try { InstallerSwitch.Prepare(evilDns, work); blockedDns = false; } catch (InvalidDataException) { blockedDns = true; }
                Check("switch: an unsafe profile or DNS backup is not carried over", blocked && blockedDns, blocked + " " + blockedDns);

                // transfer: an existing settings file is kept, the history is copied once
                string srcData = Path.Combine(t0, "portable-data");
                Directory.CreateDirectory(srcData);
                File.WriteAllText(Path.Combine(srcData, "history.csv"), "time;kind\r\n");
                Directory.CreateDirectory(Path.Combine(good, "data"));
                File.WriteAllText(tsp, "<old/>");
                string written = InstallerSwitch.Transfer(src, good, srcData);
                var back = SettingsStore.ReadFile(written);
                Check("switch: transfer writes the settings and keeps the old file as .before-switch",
                      written == tsp && File.ReadAllText(tsp + ".before-switch") == "<old/>" && back.ThemeId == "nord" && back.Language == "tr" && !back.ServiceMode &&
                      File.Exists(Path.Combine(good, "data", "history.csv")) && !File.Exists(tsp + ".tmp"), written.Substring(Math.Min(t0.Length, written.Length)));

                // local setup package (test hook)
                var badLocal = new List<string>();
                foreach (var p in new[] { null, "", @"relative\Setup.exe", @"\\server\share\Setup.exe", Path.Combine(t0, "setup.txt"), Path.Combine(t0, "missing.exe") })
                    if (InstallerSwitch.ValidateLocalPath(p, out _)) badLocal.Add(p ?? "null");
                File.WriteAllText(Path.Combine(t0, "setup.txt"), "x");
                if (InstallerSwitch.ValidateLocalPath(Path.Combine(t0, "setup.txt"), out _)) badLocal.Add("setup.txt");
                Check("switch: local setup path must be a full local .exe", badLocal.Count == 0 && InstallerSwitch.ValidateLocalPath(selfExe, out _), string.Join(", ", badLocal));
                Check("switch: NSF Shield itself is not accepted as a setup package", !InstallerSwitch.VerifySetupInfo(selfExe, new Version(1, 0), out string nerr) && nerr.Length > 0, nerr);
                string distSetup = Path.Combine(Repo, "dist", "NSF-Shield-" + App.Version + "-Setup.exe");
                if (File.Exists(distSetup))
                    Check("switch: the built setup package is accepted, an older minimum too, a newer one not",
                          InstallerSwitch.VerifySetupInfo(distSetup, Updater.Current, out string serr) && !InstallerSwitch.VerifySetupInfo(distSetup, new Version(99, 0), out _), serr);
                bool Throws(Action a) { try { a(); return false; } catch (InvalidDataException) { return true; } }
                Check("switch: local setup package with a missing or wrong SHA-256 is rejected",
                      Throws(() => InstallerSwitch.PrepareLocal(selfExe, "")) && Throws(() => InstallerSwitch.PrepareLocal(selfExe, new string('z', 64))) &&
                      Throws(() => InstallerSwitch.PrepareLocal(selfExe, new string('0', 64))) &&
                      (!Directory.Exists(Updater.UpdateRoot) || !Directory.EnumerateFiles(Updater.UpdateRoot, "*.exe", SearchOption.AllDirectories).Any()), "");

                // release check
                var ok = new UpdateInfo { Version = Updater.Current, SetupUrl = "https://github.com/x", SetupSha256 = new string('a', 64) };
                var older = new UpdateInfo { Version = new Version(0, 9, 0), SetupUrl = "https://github.com/x", SetupSha256 = new string('a', 64) };
                var noSetup = new UpdateInfo { Version = Updater.Current, AssetUrl = "https://github.com/x.zip", Sha256 = new string('a', 64) };
                Check("switch: only a verified setup release of this version or newer is used",
                      InstallerSwitch.Usable(ok, out _) && !InstallerSwitch.Usable(older, out _) && !InstallerSwitch.Usable(noSetup, out _) && !InstallerSwitch.Usable(null, out _), "");
            }
            catch (Exception ex) { Check("switch tests", false, ex.ToString()); }
            finally { try { Directory.Delete(t0, true); } catch { } }
        }

        static void ReleaseAssetTests(Action<string, bool, string> Check)
        {
            // updating without a zip: the installed version only needs Setup.exe and its hash
            string setupOnly = "{\"tag_name\":\"v9.9.0\",\"draft\":false,\"prerelease\":false,\"body\":\"**SHA-256**: `" + new string('c', 64) + "`\",\"assets\":[" +
                "{\"name\":\"NSF-Shield-9.9.0-Setup.exe\",\"browser_download_url\":\"https://github.com/x/y/releases/download/v9.9.0/NSF-Shield-9.9.0-Setup.exe\",\"size\":2,\"digest\":\"sha256:" + new string('b', 64) + "\"}]}";
            var so = Updater.Parse(setupOnly);
            Check("update without zip: release with only Setup.exe is parsed", so != null && so.AssetUrl.Length == 0 && so.Sha256.Length == 0 &&
                  so.SetupSha256 == new string('b', 64), so == null ? "null" : "zip='" + so.AssetName + "' sha='" + so.Sha256 + "'");
            Check("update without zip: installed version can install it, portable version cannot",
                  Updater.Installable(so, true) && Updater.UseSetup(so, true) && !Updater.Installable(so, false), "");
            var noHash = Updater.Parse(setupOnly.Replace("\"digest\":\"sha256:" + new string('b', 64) + "\"", "\"digest\":null"));
            Check("update without zip: Setup.exe without a hash is not installed", noHash == null || !Updater.Installable(noHash, true), "");
            string both = "{\"tag_name\":\"v9.9.1\",\"draft\":false,\"prerelease\":false,\"body\":\"x\",\"assets\":[" +
                "{\"name\":\"NSF-Shield-9.9.1.zip\",\"browser_download_url\":\"https://github.com/x/y/releases/download/v9.9.1/NSF-Shield-9.9.1.zip\",\"size\":1,\"digest\":\"sha256:" + new string('a', 64) + "\"}]}";
            var zo = Updater.Parse(both);
            Check("update with only a zip: both modes can install it (zip flow)", zo != null && Updater.Installable(zo, true) && Updater.Installable(zo, false) && !Updater.UseSetup(zo, true), "");
        }

        // ==================================================================== localisation

        static readonly Regex Placeholder = new Regex(@"\{(\d+)(,[^}:]*)?(:[^}]*)?\}");

        static string Placeholders(object v)
        {
            string text = v is string[] a ? string.Join("\n", a) : v as string ?? "";
            return string.Join(",", Placeholder.Matches(text).Cast<Match>().Select(m => m.Groups[1].Value).Distinct().OrderBy(x => x));
        }

        static void LocalizationTests(Action<string, bool, string> Check)
        {
            string dir = Path.Combine(Repo, "locales");
            Dictionary<string, object> en, tr;
            try
            {
                en = Loc.Parse(File.ReadAllText(Path.Combine(dir, "en.json"), System.Text.Encoding.UTF8));
                tr = Loc.Parse(File.ReadAllText(Path.Combine(dir, "tr.json"), System.Text.Encoding.UTF8));
            }
            catch (Exception ex) { Check("locales: en.json and tr.json parse", false, ex.Message); return; }
            Check("locales: _meta blocks", (string)en["_meta.code"] == "en" && (string)tr["_meta.code"] == "tr" &&
                  en.ContainsKey("_meta.name") && en.ContainsKey("_meta.nativeName") && tr.ContainsKey("_meta.name") && tr.ContainsKey("_meta.nativeName"), "");

            var ek = new HashSet<string>(Loc.Keys(en)); var tk = new HashSet<string>(Loc.Keys(tr));
            var onlyEn = ek.Except(tk).ToList(); var onlyTr = tk.Except(ek).ToList();
            Check("locales: en and tr have the same keys", onlyEn.Count == 0 && onlyTr.Count == 0, ek.Count + " keys; only en: " + string.Join(", ", onlyEn.Take(5)) + "; only tr: " + string.Join(", ", onlyTr.Take(5)));
            var badPh = ek.Intersect(tk).Where(k => Placeholders(en[k]) != Placeholders(tr[k])).ToList();
            Check("locales: same {n} placeholders in en and tr", badPh.Count == 0, string.Join(", ", badPh.Take(5)));
            var badType = ek.Intersect(tk).Where(k => (en[k] is string[]) != (tr[k] is string[]) ||
                                                      (en[k] is string[] ea && tr[k] is string[] ta && ea.Length != ta.Length)).ToList();
            Check("locales: lists have the same length in en and tr", badType.Count == 0, string.Join(", ", badType.Take(5)));
            var badFormat = ek.Concat(tk).Distinct().SelectMany(k => new[] { (k, en.TryGetValue(k, out var a) ? a : null), (k, tr.TryGetValue(k, out var b) ? b : null) })
                .Where(x => x.Item2 is string s && Placeholder.IsMatch(s) && !FormatsOk(s)).Select(x => x.k).Distinct().ToList();
            Check("locales: every template is a valid format string", badFormat.Count == 0, string.Join(", ", badFormat.Take(5)));
            var turkishInEn = Loc.Keys(en).Where(k => (en[k] is string[] arr ? string.Join(" ", arr) : (string)en[k]).IndexOfAny(TurkishChars) >= 0).ToList();
            Check("locales: en.json contains no Turkish text", turkishInEn.Count == 0, string.Join(", ", turkishInEn.Take(5)));

            // every key the code asks for by its full name exists (a missing key would show up as "profilesPage.x" in the window)
            var usedMissing = new List<string>();
            foreach (var file in Directory.GetFiles(Path.Combine(Repo, "src"), "*.cs", SearchOption.AllDirectories).Where(f => Path.GetFileName(f) != "Program.cs"))
                foreach (Match m in Regex.Matches(File.ReadAllText(file), "(?:Loc\\.(?:T|En|List|Has)|new LocText|CmdText)\\(\"([A-Za-z][\\w-]*(?:\\.[\\w-]+)+)\"\\s*[,)]"))
                    if (!ek.Contains(m.Groups[1].Value)) usedMissing.Add(Path.GetFileName(file) + ": " + m.Groups[1].Value);
            Check("locales: every key used in the code exists in en.json", usedMissing.Count == 0, string.Join(", ", usedMissing.Distinct().Take(8)));

            // every error code has a title, summary and steps in every language
            var missingErr = ErrorCatalog.All.Where(e => !ek.Contains("errors." + e.Code + ".title") || !ek.Contains("errors." + e.Code + ".summary")).Select(e => e.Code).ToList();
            Check("error catalog: every code has English texts", missingErr.Count == 0 && ErrorCatalog.All.All(e => e.Steps.Length > 0), string.Join(", ", missingErr));

            // discovery and language choice
            Loc.Dir = dir;
            Loc.Discover();
            var langs = Loc.Languages;
            Check("languages discovered from the folder", langs.Any(l => l.Code == "en") && langs.Any(l => l.Code == "tr" && l.NativeName.Length > 0), string.Join(", ", langs.Select(l => l.Code)));
            var avail = new[] { "en", "tr" };
            Check("language: auto follows Windows, otherwise English",
                  Loc.Resolve("auto", avail, new System.Globalization.CultureInfo("tr-TR")) == "tr" &&
                  Loc.Resolve("auto", avail, new System.Globalization.CultureInfo("de-DE")) == "en" &&
                  Loc.Resolve("tr", avail, new System.Globalization.CultureInfo("en-US")) == "tr" &&
                  Loc.Resolve("xx", avail, new System.Globalization.CultureInfo("en-US")) == "en" &&
                  Loc.Resolve(null, avail, System.Globalization.CultureInfo.InvariantCulture) == "en", "");

            // live switch: event, texts and no effect on command lines
            int changed = 0;
            Action onChange = () => changed++;
            Loc.Changed += onChange;
            try
            {
                Loc.SetLanguage("en");
                string enHome = Loc.T("nav.home");
                var argsEn = Profiles.BuiltIns.Select(b => b.BuildArgs(@"C:\x\target-sites.txt")).ToList();
                var scriptEn = Scripts.Build(Profiles.BuiltIns[0], "..\\bin");
                Loc.SetLanguage("tr");
                string trHome = Loc.T("nav.home");
                var argsTr = Profiles.BuiltIns.Select(b => b.BuildArgs(@"C:\x\target-sites.txt")).ToList();
                string trName = Profiles.BuiltIns[0].Name;
                Check("language switch: event raised and texts change", changed == 2 && Loc.Current == "tr" && enHome == (string)en["nav.home"] && trHome == (string)tr["nav.home"] &&
                      trName == (string)tr["profiles.builtin.tr-recommended.name"], enHome + " → " + trHome);
                Check("language switch: command lines do not depend on the language", argsEn.SequenceEqual(argsTr), "");
                string scriptArgs(string sc) => string.Join("\n", sc.Split('\n').Where(l => l.Contains("goodbyedpi.exe")));
                Check("language switch: script command line does not depend on the language", scriptArgs(scriptEn) == scriptArgs(Scripts.Build(Profiles.BuiltIns[0], "..\\bin")), "");
                Check("scripts: export file names come from the English profile names", Scripts.Slug((string)en["profiles.builtin.tr-recommended.name"]) == "turkey_recommended", "");
            }
            finally { Loc.Changed -= onChange; Loc.SetLanguage("en"); }

            // missing keys fall back to English per key; broken templates never throw
            var act = new Dictionary<string, object> { { "a", "Merhaba {0}" }, { "bad", "Bozuk {1" }, { "worse", "{5} only" }, { "list", new[] { "x" } } };   // tr-literal: Turkish test text
            var fb = new Dictionary<string, object> { { "a", "Hello {0}" }, { "b", "English only {0}" }, { "bad", "Broken {0}" }, { "worse", "Fine {0}" }, { "list", new[] { "y" } }, { "list2", new[] { "z" } } };
            Loc.DebugUse("xx", act, fb);
            try
            {
                bool ok1 = Loc.T("a", "x") == "Merhaba x";   // tr-literal
                bool ok2 = Loc.T("b", 7) == "English only 7";
                bool ok3 = Loc.T("does.not.exist") == "does.not.exist";
                bool ok4 = Loc.T("bad", 5) == "Broken 5";
                bool ok5 = Loc.T("worse", 1) == "Fine 1";
                string s6; bool ok6;
                try { s6 = Loc.T("a"); ok6 = s6 == "Merhaba {0}"; } catch { s6 = "threw"; ok6 = false; }   // tr-literal
                bool ok7; try { ok7 = Loc.SafeFormat("{0} {9}", null, System.Globalization.CultureInfo.InvariantCulture, new object[] { 1 }).Length > 0; } catch { ok7 = false; }
                bool ok8 = Loc.List("list")[0] == "x" && Loc.List("list2")[0] == "z" && Loc.List("none").Length == 0;
                Check("missing key: falls back to English, then to the key", ok1 && ok2 && ok3, "");
                Check("broken template: never throws, uses English", ok4 && ok5 && ok6 && ok7, s6);
                Check("lists fall back per key", ok8, "");
                var nested = new LocText("a", new LocText("b", 3));
                Check("LocText: nested texts render in each language", nested.Text == "Merhaba English only 3" && nested.English == "Hello English only 3", nested.Text + " | " + nested.English);   // tr-literal
            }
            finally { Loc.Init("en"); }

            // a broken or foreign language file is skipped, the rest keep working
            string tmp = Path.Combine(Path.GetTempPath(), "nsf-loc-" + Guid.NewGuid().ToString("N").Substring(0, 6));
            try
            {
                Directory.CreateDirectory(tmp);
                File.Copy(Path.Combine(dir, "en.json"), Path.Combine(tmp, "en.json"));
                File.WriteAllText(Path.Combine(tmp, "broken.json"), "{ not json");
                File.WriteAllText(Path.Combine(tmp, "nometa.json"), "{\"nav\":{\"home\":\"X\"}}");
                File.WriteAllText(Path.Combine(tmp, "de.json"), "{\"_meta\":{\"code\":\"de\",\"name\":\"German\",\"nativeName\":\"Deutsch\"},\"nav\":{\"home\":\"Start {0\"}}");
                Loc.Dir = tmp;
                Loc.SetLanguage("de");
                Check("language files: broken files skipped, partial language falls back per key",
                      Loc.Languages.Select(l => l.Code).OrderBy(c => c).SequenceEqual(new[] { "de", "en" }) && Loc.Current == "de" &&
                      Loc.T("nav.home") == "Start {0" && Loc.T("nav.settings") == (string)en["nav.settings"], string.Join(",", Loc.Languages.Select(l => l.Code)) + " " + Loc.T("nav.home"));
            }
            finally { Loc.Dir = dir; Loc.Init("en"); try { Directory.Delete(tmp, true); } catch { } }

            // no Turkish text hard-coded in the code: the UI and the error catalog read everything from locales/
            var hits = new List<string>();
            foreach (var file in Directory.GetFiles(Path.Combine(Repo, "src"), "*.cs", SearchOption.AllDirectories).OrderBy(f => f, StringComparer.Ordinal))
            {
                int n = 0;
                foreach (var line in File.ReadAllLines(file, System.Text.Encoding.UTF8))
                {
                    n++;
                    if (line.Contains("tr-literal")) continue;
                    string l = line.Replace(App.Publisher, "");
                    if (l.IndexOfAny(TurkishChars) >= 0) hits.Add(Path.GetFileName(file) + ":" + n);
                }
            }
            Check("code: no hard-coded Turkish text (UI, error catalog, logs, comments)", hits.Count == 0, hits.Count + " " + string.Join(", ", hits.Take(8)));
            var errSrc = File.ReadAllText(Path.Combine(Repo, @"src\Core\Errors.cs"));
            Check("error catalog: texts come from locales only", !Regex.IsMatch(errSrc, "Title\\s*=\\s*\"|Summary\\s*=\\s*\"|Steps\\s*=\\s*new"), "");
        }

        static readonly char[] TurkishChars = "çğıöşüÇĞİÖŞÜ".ToCharArray();   // tr-literal: the characters the scan looks for

        static bool FormatsOk(string s)
        {
            try { string.Format(System.Globalization.CultureInfo.InvariantCulture, s, Enumerable.Range(0, 10).Select(i => (object)i).ToArray()); return true; }
            catch (FormatException) { return false; }
        }

        static void Phase2Tests(Action<string, bool, string> Check)
        {
            string repo = Repo;
            string ver = App.Version, ver4 = ver + ".0";

            // ---------------------------------------------------------------- exe version info and manifest
            var self = System.Diagnostics.FileVersionInfo.GetVersionInfo(System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName);
            Check("metadata: publisher, product, description, copyright", self.CompanyName == App.Publisher && self.ProductName == "NSF Shield" && self.FileDescription == "NSF Shield" &&
                  self.LegalCopyright == "Copyright (c) 2026 " + App.Publisher && App.Copyright == self.LegalCopyright, self.CompanyName + " | " + self.ProductName + " | " + self.FileDescription + " | " + self.LegalCopyright);
            Check("metadata: versions consistent", self.FileVersion == ver4 && self.ProductVersion == ver && ver == "1.0.1", self.FileVersion + " / " + self.ProductVersion);
            string pkgExe = Path.Combine(App.BaseDir, @"package\NSF Shield\NSFShield.exe");
            if (File.Exists(pkgExe))
            {
                var pv = System.Diagnostics.FileVersionInfo.GetVersionInfo(pkgExe);
                string text = System.Text.Encoding.UTF8.GetString(File.ReadAllBytes(pkgExe));
                var m = Regex.Match(text, "<assemblyIdentity\\s+version=\"([\\d.]+)\"\\s+name=\"NSFShield.app\"");
                Check("metadata: package exe version equals the embedded manifest version", pv.FileVersion == ver4 && m.Success && m.Groups[1].Value == ver4 &&
                      text.Contains("requireAdministrator"), pv.FileVersion + " / manifest " + (m.Success ? m.Groups[1].Value : "none"));
            }
            else Check("metadata: package exe (build.ps1 not run)", false, pkgExe);

            // ---------------------------------------------------------------- package layout: English names, locales next to the exe
            string pkg = Path.Combine(App.BaseDir, @"package\NSF Shield");
            if (Directory.Exists(pkg))
            {
                var top = Directory.GetFileSystemEntries(pkg).Select(Path.GetFileName).OrderBy(x => x, StringComparer.Ordinal).ToList();
                Check("package: English folder and file names (guide entry pages in guide\\)", top.SequenceEqual(new[] { "Guide.html", "NSFShield.exe", "README.txt", "bin", "guide", "licenses", "locales", "scripts" }), string.Join(", ", top));
                Check("package: locales and English scripts", File.Exists(Path.Combine(pkg, @"locales\en.json")) && File.Exists(Path.Combine(pkg, @"locales\tr.json")) &&
                      File.Exists(Path.Combine(pkg, @"scripts\01_turkey_recommended.cmd")) && File.Exists(Path.Combine(pkg, @"scripts\README.txt")), "");
                string guide = File.ReadAllText(Path.Combine(pkg, "Guide.html"), System.Text.Encoding.UTF8);
                Check("package: guide filled in (no placeholders left)", !Regex.IsMatch(guide, "<!--(VERSION|ERROR_COUNT|PROFILE_COUNT|ERROR_CODES(:[a-z]+)?|PROFILES(:[a-z]+)?)-->") &&
                      guide.Contains("id=\"en-NSF-101\"") && guide.Contains("id=\"tr-NSF-101\""), "");
            }

            // ---------------------------------------------------------------- no script interpreter (PS) anywhere
            // (the app and its sign-in recovery helper; no other script host is started either)
            string needle = "power" + "shell";
            var hostExes = new[] { "w" + "script.exe", "c" + "script.exe", "ms" + "hta.exe" };
            var codeFiles = Directory.GetFiles(Path.Combine(repo, "src"), "*.cs", SearchOption.AllDirectories)
                .Concat(Directory.Exists(Path.Combine(repo, "recovery")) ? Directory.GetFiles(Path.Combine(repo, "recovery"), "*.cs") : new string[0]).ToList();
            var hits = codeFiles.Where(f => { string t = File.ReadAllText(f); return t.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0 || hostExes.Any(h => t.IndexOf(h, StringComparison.OrdinalIgnoreCase) >= 0); })
                .Select(Path.GetFileName).ToList();
            string scripts = Path.Combine(pkg, "scripts");
            if (Directory.Exists(scripts))
                hits.AddRange(Directory.GetFiles(scripts).Where(f => File.ReadAllText(f).IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0).Select(Path.GetFileName));
            Check("no " + "Power" + "Shell in the source code and the scripts", hits.Count == 0, hits.Count == 0 ? "" : string.Join(", ", hits));

            // ---------------------------------------------------------------- encrypted DNS: netsh and Windows 10 behaviour
            Check("DoH: not supported on Windows 10 (19045), supported on Windows 11 (22000+)",
                  !SystemDns.DohSupportedOn(19045) && SystemDns.DohSupportedOn(22000) && SystemDns.DohSupportedOn(26100), "this computer: " + SystemDns.WindowsBuild);
            string msg10 = SystemDns.DohUnsupportedMessage(19045);
            Check("DoH: clear warning on Windows 10", msg10.Contains("Windows 11") && msg10.Contains("19045") && msg10.Contains("without encryption"), msg10);
            var cf = SystemDns.Choices.First(c => c.Id == "cloudflare");
            var cmds = SystemDns.DohCommands(cf);
            Check("DoH: netsh commands (4 addresses, add + set)", cmds.Count == 4 &&
                  cmds.All(c => c.Add.StartsWith("dns add encryption server=") && c.Set.StartsWith("dns set encryption server=") &&
                                c.Add.EndsWith(" dohtemplate=https://cloudflare-dns.com/dns-query autoupgrade=yes udpfallback=no")), cmds.Count > 0 ? cmds[0].Add : "");
            Check("DoH: commands for every DNS choice", SystemDns.Choices.Where(c => !c.IsAuto).All(c => SystemDns.DohCommands(c).Count == 4), "");
            var evilChoice = new SystemDnsChoice { Id = "x", V4a = "1.1.1.1", Doh = "https://x.example/dns-query & calc" };
            Check("DoH: an unsafe template never reaches a command", SystemDns.DohCommands(evilChoice).Count == 0, "");
            // real 'netsh dns show encryption server=…' output of a Windows 11 26300 machine
            string shownNo = "\r\nEncryption settings for 1.1.1.1 \r\n----------------------------------------------------------------------\r\n" +
                             "DNS-over-HTTPS template     : https://cloudflare-dns.com/dns-query\r\nAuto-upgrade                : no\r\nUDP-fallback                : no\r\n";
            var pNo = SystemDns.ParseEncryption(shownNo);
            var pYes = SystemDns.ParseEncryption(shownNo.Replace("Auto-upgrade                : no", "Auto-upgrade                : yes"));
            var pV6 = SystemDns.ParseEncryption(shownNo.Replace("1.1.1.1", "2606:4700:4700::1111"));
            var pNone = SystemDns.ParseEncryption("\r\n");
            Check("DoH: netsh output parsed (built-in entry Auto-upgrade: no → yes, no entry, IPv6 header)",
                  pNo.Exists && pNo.AutoUpgrade == false && pNo.UdpFallback == false && pNo.Template == "https://cloudflare-dns.com/dns-query" &&
                  pYes.AutoUpgrade == true && pV6.Exists && pV6.Template.Length > 0 && !pNone.Exists && pNone.AutoUpgrade == null, "");
            Check("DoH: global setting read", SystemDns.ParseGlobalDoh("\r\nDoH settings                : enabled\r\n\r\nDoT settings                : enabled\r\n") == "enabled" &&
                  SystemDns.ParseGlobalDoh("") == null, "");
            Check("DoH: server address kept separately in the commands (for read-back and backup)", cmds.All(c => c.Add.Contains("server=" + c.Ip + " ")) && cmds[0].Ip == cf.V4a, "");

            // ---------------------------------------------------------------- updating with the setup package
            string relJson = "{\"tag_name\":\"v9.8.7\",\"draft\":false,\"prerelease\":false,\"body\":\"x\",\"assets\":[" +
                "{\"name\":\"NSF-Shield-9.8.7.zip\",\"browser_download_url\":\"https://github.com/x/y/releases/download/v9.8.7/NSF-Shield-9.8.7.zip\",\"size\":1,\"digest\":\"sha256:" + new string('a', 64) + "\"}," +
                "{\"name\":\"NSF-Shield-9.8.7-Setup.exe\",\"browser_download_url\":\"https://github.com/x/y/releases/download/v9.8.7/NSF-Shield-9.8.7-Setup.exe\",\"size\":2,\"digest\":\"sha256:" + new string('b', 64) + "\"}," +
                "{\"name\":\"SHA256SUMS.txt\",\"browser_download_url\":\"https://github.com/x/y/s\",\"size\":3,\"digest\":null}]}";
            var ri = Updater.Parse(relJson);
            Check("update: zip and Setup.exe parsed separately", ri.AssetName == "NSF-Shield-9.8.7.zip" && ri.Sha256 == new string('a', 64) &&
                  ri.SetupName == "NSF-Shield-9.8.7-Setup.exe" && ri.SetupSha256 == new string('b', 64), ri.SetupName);
            string notes = "**SHA-256** (NSF-Shield-9.8.7.zip): `" + new string('c', 64) + "`\\n\\n**SHA-256** (NSF-Shield-9.8.7-Setup.exe): `" + new string('d', 64) + "`";
            var rn = Updater.Parse(relJson.Replace("\"digest\":\"sha256:" + new string('a', 64) + "\"", "\"digest\":null")
                                          .Replace("\"digest\":\"sha256:" + new string('b', 64) + "\"", "\"digest\":null").Replace("\"body\":\"x\"", "\"body\":\"" + notes + "\""));
            Check("update: hashes read from the release notes by file name", rn.Sha256 == new string('c', 64) && rn.SetupSha256 == new string('d', 64), rn.Sha256.Substring(0, 4) + " " + rn.SetupSha256.Substring(0, 4));
            Check("update: installed version uses Setup.exe, portable uses the zip", Updater.UseSetup(ri, true) && !Updater.UseSetup(ri, false) &&
                  !Updater.UseSetup(Updater.Parse(relJson.Replace("-Setup.exe", "-Installer.exe")), true), "");
            Check("update: the setup registration only counts in the same, protected folder",
                  Updater.IsInnoInstall(@"C:\Program Files\NSF Shield\", @"C:\Program Files\NSF Shield\", true) &&
                  !Updater.IsInnoInstall(@"C:\Program Files\NSF Shield", @"C:\Program Files\NSF Shield\", false) &&
                  !Updater.IsInnoInstall(@"C:\Users\x\Desktop\NSF Shield", @"C:\Program Files\NSF Shield\", true) &&
                  !Updater.IsInnoInstall(@"C:\Program Files\NSF Shield", null, true), "");

            string iss = Path.Combine(repo, @"installer\NSFShield.iss");
            if (File.Exists(iss))
            {
                string s = File.ReadAllText(iss);
                Check("setup script: same AppId as the app, upgrade/uninstall hooks present",
                      s.Contains("AppId={" + Updater.InnoAppId) && s.Contains("--prepare-upgrade") && s.Contains("--uninstall --quiet") &&
                      s.Contains("PrivilegesRequired=admin") && s.Contains("ArchitecturesAllowed=x64compatible") && s.Contains("{param:NSFUPDATED|}") && s.Contains("{param:NSFRESUME|"), "");
                // an exe with a requireAdministrator manifest started without rights gives CreateProcess error 740: every start is elevated
                var codeLines = s.Split('\n').Select(l => l.Trim()).Where(l => !l.StartsWith(";") && !l.StartsWith("{") && !l.StartsWith("//")).ToList();
                var launches = codeLines.Where(l => l.StartsWith("Filename:") && l.Contains("{#AppExe}")).ToList();
                // stage 7: the uninstall clean-up is started from [Code] (elevated, only after it was verified), not from [UninstallRun]
                Check("setup script: NSFShield.exe is always started with runascurrentuser (no error 740)",
                      launches.Count == 2 && launches.All(l => l.Contains("runascurrentuser")) && s.Contains("if Exec(Exe, '--uninstall --quiet', '', SW_HIDE, ewWaitUntilTerminated, RC) then") &&
                      !codeLines.Any(l => l.Contains("runasoriginaluser") || l.Contains("ExecAsOriginalUser")), launches.Count + " starts");
                var icons = codeLines.Where(l => l.StartsWith("Name:") && l.Contains("Filename:")).ToList();
                Check("setup script: English package names; the data folder is handled",
                      icons.Any(l => l.Contains("{app}\\guide\\en.html") && l.EndsWith("Languages: en")) && icons.Any(l => l.Contains("{app}\\guide\\tr.html") && l.EndsWith("Languages: tr")) &&
                      icons.Count >= 4 && s.Contains("{app}\\data"), icons.Count + " shortcuts");
            }
            string setup = Path.Combine(repo, "dist", "NSF-Shield-" + ver + "-Setup.exe");
            if (File.Exists(setup))
            {
                var sv = System.Diagnostics.FileVersionInfo.GetVersionInfo(setup);
                string spn = (sv.ProductName ?? "").Trim(), sfv = (sv.FileVersion ?? "").Trim(), sco = (sv.CompanyName ?? "").Trim();
                // Inno Setup pads the version strings with spaces; the updater compares them trimmed
                Check("setup package: version info as the updater expects", spn == "NSF Shield" && sfv == ver4 && sco == App.Publisher && (sv.LegalCopyright ?? "").Trim() == App.Copyright,
                      spn + " " + sfv + " " + sco + " (padded: " + (sv.ProductName != spn) + ")");
            }

            // ---------------------------------------------------------------- SHA256SUMS list matches the real files
            string sumsFile = Path.Combine(repo, "dist", "NSF-Shield-" + ver + ".SHA256SUMS.txt");
            if (File.Exists(sumsFile))
            {
                var bad = new List<string>();
                int n = 0;
                foreach (var line in File.ReadAllLines(sumsFile).Where(l => l.Length > 66))
                {
                    string h = line.Substring(0, 64), name = line.Substring(66);
                    string path = name.StartsWith("NSF Shield/") ? Path.Combine(App.BaseDir, "package", name.Replace('/', '\\')) : Path.Combine(repo, "dist", name);
                    n++;
                    if (!File.Exists(path) || Integrity.Sha256File(path) != h) bad.Add(name);
                }
                Check("SHA256SUMS: every line matches its file", bad.Count == 0 && n >= 9, n + " lines " + string.Join(", ", bad));
            }
            else Check("SHA256SUMS file (build.ps1 not run)", false, sumsFile);

            // ---------------------------------------------------------------- unexpected shutdown marker
            {
                bool oldPreview = App.Preview;
                string oldData = App.DataDir;
                string t = Path.Combine(Path.GetTempPath(), "nsf-crash-" + Guid.NewGuid().ToString("N").Substring(0, 6));
                try
                {
                    App.Preview = false;
                    App.DataDir = t;
                    CrashMarker.Begin();
                    bool clean = CrashMarker.PreviousUnexpected == null;
                    CrashMarker.End();
                    CrashMarker.Begin();
                    bool stillClean = CrashMarker.PreviousUnexpected == null;     // no warning after a clean exit
                    CrashMarker.Record(new InvalidOperationException("test crash"), fatal: true);
                    CrashMarker.Begin();                                             // reopened without End = crash
                    string prev = CrashMarker.PreviousUnexpected;
                    CrashMarker.Clear(t);
                    CrashMarker.Begin();
                    bool clearedOk = CrashMarker.PreviousUnexpected == null;        // no warning if our own tools closed it on purpose
                    CrashMarker.End();
                    Check("crash marker: no warning after a clean exit, NSF-106 and the last error after a crash", clean && stillClean && prev != null && prev.Contains("test crash") && clearedOk, prev ?? "");
                }
                finally
                {
                    App.Preview = oldPreview;
                    App.DataDir = oldData;
                    try { Directory.Delete(t, true); } catch { }
                }
            }

            // ---------------------------------------------------------------- antivirus texts
            var avSteps = ErrorCatalog.All.SelectMany(e => e.Steps).Where(s => s.IndexOf("exclusion", StringComparison.OrdinalIgnoreCase) >= 0).ToList();
            Check("antivirus: an exclusion is only suggested as a 'last resort'", avSteps.Count > 0 && avSteps.All(s => s.Contains("Last resort")), avSteps.Count + " steps");
            var fp = new[] { "NSF-102", "NSF-202", "NSF-204" }.Select(ErrorCatalog.Get).ToList();
            Check("antivirus: reporting the false positive and the SHA-256 check come first", fp.All(e => e.Fix == FixKind.ReportFalsePositive || e.Fix2 == FixKind.ReportFalsePositive) &&
                  fp.All(e => e.Steps.Any(s => s.Contains("wdsi")) && e.Steps.Any(s => s.Contains("SHA-256"))) &&
                  ErrorInfo.FixLabel(FixKind.ReportFalsePositive).Length > 0 && ErrorCatalog.Get("NSF-106") != null, "");
        }

        static void SecurityTests(Action<string, bool, string> Check)
        {
            // ---------------------------------------------------------------- argument allow-list
            var bad = Profiles.BuiltIns.Where(x => !ArgPolicy.ValidateProfile(x, out _)).Select(x => x.Id).ToList();
            Check("allow-list: every built-in profile passes", bad.Count == 0, bad.Count == 0 ? Profiles.BuiltIns.Count + " profiles" : string.Join(", ", bad));
            foreach (var a in new[] { "--blacklist x.txt", "--black x.txt", "--bl x", "--blacklist=x", "-5 & calc", "-9 --dns-addr 1.1.1.1&calc",
                                      "--dns-ad 1.1.1.1", "--set-ttl 999", "--set-ttl -5", "--zzz", "-e", "-9 \"x\"", "-9 %PATH%", "-9\r\nstart calc",
                                      "--dns-addr 1.1.1", "--dnsv6-addr 1.1.1.1", "-pqr", "-f2", "--wrong-seq=1", "--fake-from-hex 12z4", "-9 x", "-9 \\\\host\\share" })
                Check("allow-list rejects: " + a.Replace("\r\n", "⏎"), !ArgPolicy.Validate(a, out _), "");
            foreach (var a in new[] { "-9", "-5 --set-ttl 5 --dns-addr 77.88.8.8 --dns-port 1253 --dnsv6-addr 2a02:6b8::feed:0ff --dnsv6-port 1253",
                                      "--auto-ttl=1-4-10 --max-payload=1200 --auto-ttl --max-payload", "-e 2 --fake-from-hex 1234abcd --fake-gen 5 --fake-resend 2 -q" })
                Check("allow-list accepts: " + a, ArgPolicy.Validate(a, out var ge), ge);

            // ---------------------------------------------------------------- GoodbyeDPI's getopt_long behaviour (the reason for the allow-list)
            string tp = Path.GetFullPath(Path.Combine(App.BaseDir, @"..\third_party\goodbyedpi"));
            string gdpi = Path.Combine(tp, "x86_64", "goodbyedpi.exe");
            if (File.Exists(gdpi))
            {
                string nofile = @"C:\nsf-missing\missing.txt";
                string full = RunUnelevated(gdpi, "--blacklist " + nofile), abbr = RunUnelevated(gdpi, "--black " + nofile), unk = RunUnelevated(gdpi, "--zzz");
                Check("getopt_long: GoodbyeDPI takes the abbreviation '--black' as --blacklist (an old Contains check could be bypassed)",
                      full.Contains("Can't load blacklist") && abbr.Contains("Can't load blacklist") && unk.Contains("Usage"), abbr.Trim().Split('\n').Last().Trim());
            }
            else Check("getopt_long test (third_party not found)", false, tp);

            // ---------------------------------------------------------------- profile code and script safety
            var basep = Profiles.BuiltIns.First(x => x.Id == "tr-alt").CloneAsCustom();
            var ev = basep.CloneAsCustom();
            ev.UseRaw = true; ev.RawArgs = "-9 --black C:\\x.txt";
            Check("profile code: abbreviated --blacklist rejected", !ProfileCode.TryFromCode(ProfileCode.ToCodeUnchecked(ev), out _, out _) && !ProfileCode.TryToCode(ev, out _, out _), "");
            ev.RawArgs = "-9 & calc";
            Check("profile code: command character rejected", !ProfileCode.TryFromCode(ProfileCode.ToCodeUnchecked(ev), out _, out _) && !ProfileCode.TryToCode(ev, out _, out _), "");
            ev.RawArgs = "-9"; ev.Name = "Name\r\nstart calc"; ev.Description = "a\nb";
            bool okc = ProfileCode.TryFromCode(ProfileCode.ToCodeUnchecked(ev), out var cleaned, out var cerr) && ProfileCode.TryFromCode(ProfileCode.ToCode(ev), out var cleaned2, out _) &&
                       !cleaned2.Name.Contains("\n") && !cleaned2.Description.Contains("\n");
            Check("profile code: line breaks in name/description removed", okc && !cleaned.Name.Contains("\n") && !cleaned.Description.Contains("\n"), cerr);
            var raw = basep.CloneAsCustom(); raw.UseRaw = true; raw.RawArgs = "-9"; raw.Name = "x\r\nstart calc ^"; raw.Description = "%PATH% & del\r\nstart y";
            string script = Scripts.Build(raw, "..\\bin");
            Check("script: no command leaks from the REM lines", script.Split('\n').Count(l => l.TrimStart().StartsWith("start ")) == 1 && !script.Contains("%PATH%") && !script.Contains("^"), "");
            raw.RawArgs = "-9 & calc";
            try { Scripts.Build(raw, "..\\bin"); Check("script: an unsafe profile does not become a script", false, ""); }
            catch (InvalidDataException) { Check("script: an unsafe profile does not become a script", true, ""); }

            // ---------------------------------------------------------------- per-program proxy: cmd line
            var openP = new ProxyEntry { Kind = ProxyKind.Http, Host = "5.6.7.8", Port = 3128 };
            bool Throws(Action a) { try { a(); return false; } catch (ArgumentException) { return true; } }
            Check("environment mode: extra argument '& calc' rejected", Throws(() => AppProxy.Plan(new ProxyApp { Name = "A", ExePath = @"C:\X\t.exe", Mode = AppProxyMode.Env, ExtraArgs = "& calc" }, openP)), "");
            Check("environment mode: % in the path rejected", Throws(() => AppProxy.Plan(new ProxyApp { Name = "A", ExePath = @"C:\X\%PATH%\t.exe", Mode = AppProxyMode.Env }, openP)), "");
            Check("environment mode: quote in the address rejected", Throws(() => AppProxy.Plan(new ProxyApp { Name = "A", ExePath = @"C:\X\t.exe", Mode = AppProxyMode.Env },
                                                                     new ProxyEntry { Kind = ProxyKind.Http, Host = "1.2.3.4\"&calc&\"", Port = 80 })), "");
            Check("environment mode: normal path with parentheses accepted", !Throws(() => AppProxy.Plan(new ProxyApp { Name = "A", ExePath = @"C:\Program Files (x86)\X\t.exe", Mode = AppProxyMode.Env, ExtraArgs = "--verbose" }, openP)), "");

            // ---------------------------------------------------------------- file integrity and lock
            // third_party\goodbyedpi holds only GoodbyeDPI (x86, x86_64); the package bin folder holds every engine
            if (Directory.Exists(tp)) Check("embedded SHA-256 hashes match: third_party\\goodbyedpi", Integrity.VerifyTree(tp, out var ie0, k => k.StartsWith("x86")), ie0);
            string pkgBin = Path.Combine(App.BaseDir, @"package\NSF Shield\bin");
            if (Directory.Exists(pkgBin)) Check("embedded SHA-256 hashes match: package bin (GoodbyeDPI, zapret, ByeDPI)", Integrity.VerifyTree(pkgBin, out var ie), ie);
            if (File.Exists(gdpi))
            {
                string t = Path.Combine(Path.GetTempPath(), "nsf-int-" + Guid.NewGuid().ToString("N").Substring(0, 6));
                Directory.CreateDirectory(t);
                foreach (var f in new[] { "goodbyedpi.exe", "WinDivert.dll", "WinDivert64.sys" }) File.Copy(Path.Combine(tp, "x86_64", f), Path.Combine(t, f));
                var files = new[] { "goodbyedpi.exe", "WinDivert.dll", "WinDivert64.sys" };
                using (var h = Integrity.VerifyAndLock(t, "x86_64", files, out var e1))
                {
                    Check("integrity: official files verified", h != null, e1);
                    bool writeBlocked;
                    try { using (new FileStream(Path.Combine(t, "goodbyedpi.exe"), FileMode.Open, FileAccess.Write, FileShare.ReadWrite)) { } writeBlocked = false; }
                    catch (IOException) { writeBlocked = true; }
                    Check("integrity: exe closed for writing after the check", writeBlocked, "");
                    string outp = RunUnelevated(Path.Combine(t, "goodbyedpi.exe"), "--zzz");
                    Check("integrity: GoodbyeDPI and WinDivert.dll can load while locked", outp.Contains("Usage"), outp.Length > 0 ? "" : "no output");
                }
                File.AppendAllText(Path.Combine(t, "WinDivert.dll"), "x");
                using (var h2 = Integrity.VerifyAndLock(t, "x86_64", files, out var e2))
                    Check("integrity: a changed WinDivert.dll is rejected", h2 == null && e2.Contains("WinDivert.dll"), e2);
                try { Directory.Delete(t, true); } catch { }
            }

            // ---------------------------------------------------------------- protected folder check
            Check("protected folder: Program Files", InstallGuard.Check(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), out var r1), r1);
            Check("protected folder: System32", InstallGuard.Check(Environment.SystemDirectory, out var r2), r2);
            Check("unprotected folder: Temp", !InstallGuard.Check(Path.GetTempPath(), out var r3), r3);
            {
                string ud = Path.Combine(Path.GetTempPath(), "nsf-portable-" + Guid.NewGuid().ToString("N").Substring(0, 6));
                Directory.CreateDirectory(Path.Combine(ud, "bin", "x86_64"));
                Check("unprotected folder: new folder the user can write to", !InstallGuard.Check(ud, out var r4), r4);
                try { Directory.Delete(ud, true); } catch { }
            }
            Check("unprotected folder: folder that does not exist", !InstallGuard.Check(@"C:\nsf-missing-" + Guid.NewGuid().ToString("N"), out var r5), r5);

            // ---------------------------------------------------------------- safe process helper
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var pr = Sys.Run(Sys.SystemExe("ping.exe"), "-n 30 127.0.0.1", 1500);
            Check("process helper: killed when the time is up", pr.Code == -2 && sw.ElapsedMilliseconds < 7000, sw.ElapsedMilliseconds + " ms");
            var pr2 = Sys.Run(Sys.SystemExe("cmd.exe"), "/c for /l %i in (1,1,1500) do @(echo out%i & echo err%i 1>&2)", 30000);
            Check("process helper: large stdout+stderr read without a deadlock", pr2.Code == 0 && pr2.Output.Contains("out1500") && pr2.Output.Contains("err1500"), pr2.Output.Length + " characters");

            // ---------------------------------------------------------------- Task Scheduler (COM) and the DLL search restriction
            Check("Task Scheduler COM connection", Startup.Probe(out var se), se + (Startup.IsEnabled() ? " (task: " + Startup.CommandPath() + ")" : " (no task)"));
            Check("WMI works with the DLL restriction", Engine.ServicePath("Winmgmt") != null, "");
            bool zipOk;
            try
            {
                using (var ms = new MemoryStream())
                {
                    using (var za = new System.IO.Compression.ZipArchive(ms, System.IO.Compression.ZipArchiveMode.Create, true))
                    using (var w = new StreamWriter(za.CreateEntry("a.txt").Open())) w.Write(new string('x', 5000));
                    ms.Position = 0;
                    using (var za = new System.IO.Compression.ZipArchive(ms, System.IO.Compression.ZipArchiveMode.Read))
                    using (var rd = new StreamReader(za.Entries[0].Open())) zipOk = rd.ReadToEnd().Length == 5000;
                }
            }
            catch { zipOk = false; }
            Check("zip (clrcompression) works with the DLL restriction", zipOk, "");

            // ---------------------------------------------------------------- update paths
            Check("update: trusted addresses", Updater.TrustedUrl("https://github.com/x") && Updater.TrustedUrl("https://objects.githubusercontent.com/x") &&
                  !Updater.TrustedUrl("http://github.com/x") && !Updater.TrustedUrl("https://github.com.evil.example/x") && !Updater.TrustedUrl("https://evilgithubusercontent.com/x"), "");
            {
                string t = Path.Combine(Path.GetTempPath(), "nsf-val-" + Guid.NewGuid().ToString("N").Substring(0, 6));
                string dst = Path.Combine(t, "installed");
                Directory.CreateDirectory(dst);
                File.Copy(System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName, Path.Combine(dst, "NSFShield.exe"));
                string src = Path.Combine(dst, "data", "update", "v9.9.9", "NSF Shield");
                Check("update path: data\\update accepted", Updater.ValidateApplyArgs(src, dst, Path.Combine(src, "NSFShield.exe"), out var v0), v0);
                string veriDir = Path.Combine(dst, "veri", "guncelleme", "v9.9.9", "NSF Shield");
                Check("update path: an old download folder outside data\\update is rejected", !Updater.ValidateApplyArgs(veriDir, dst, Path.Combine(veriDir, "NSFShield.exe"), out _), "");
                Check("update path: another folder rejected", !Updater.ValidateApplyArgs(Path.Combine(t, "other"), dst, Path.Combine(t, "other", "NSFShield.exe"), out _), "");
                Check("update path: escape with ..\\ rejected", !Updater.ValidateApplyArgs(Path.Combine(dst, @"data\update\..\..\x"), dst, Path.Combine(dst, @"x\NSFShield.exe"), out _), "");
                Check("update path: updater running outside the source rejected", !Updater.ValidateApplyArgs(src, dst, Path.Combine(t, "NSFShield.exe"), out _), "");
                Check("update path: target that is not NSF Shield rejected", !Updater.ValidateApplyArgs(src, t, Path.Combine(src, "NSFShield.exe"), out _), "");
                try { Directory.Delete(t, true); } catch { }
            }
        }
    }

    static partial class Preview
    {
        [System.Runtime.InteropServices.DllImport("user32.dll")]
        static extern bool PrintWindow(IntPtr hwnd, IntPtr hdc, uint flags);

        static void Pump()
        {
            for (int i = 0; i < 8; i++) { Application.DoEvents(); Thread.Sleep(30); }
        }

        static void Shot(Form f, string path)
        {
            Pump();
            using (var bmp = new Bitmap(f.Width, f.Height))
            {
                using (var g = Graphics.FromImage(bmp))
                {
                    IntPtr hdc = g.GetHdc();
                    PrintWindow(f.Handle, hdc, 2);
                    g.ReleaseHdc(hdc);
                }
                bmp.Save(path);
            }
        }

        static void Theme(MainForm form, string id, UiLevel level)
        {
            App.Settings.ThemeId = id;
            App.Settings.UiLevel = level;
            NSFShield.Theme.Apply(Palettes.Resolve(App.Settings));
            form.Rebuild();
            Pump();
        }

        static void Fake()
        {
            App.LastTest = AppSettings.DefaultTestHosts.Select((h, i) => new HostResult
            { Host = h, Ok = true, Ms = 180 + i * 37, Ip = "162.159.13" + i + ".23" + i, DetailValue = new LocText("net.reachable", 200) }).ToList();
            App.LastTestTime = DateTime.Now;
            App.LastDnsOk = true;
        }

        public static void Run(MainForm form, string dir)
        {
            Directory.CreateDirectory(dir);
            form.StartPosition = FormStartPosition.Manual;
            form.Location = new Point(-5000, 0);
            form.Show();
            Pump();

            var p = App.SelectedProfile;
            Fake();
            SystemDns.Publish(SampleNet());
            App.Log("NSF Shield " + App.Version + " started.", LogLevel.Info);
            App.Log("Command: goodbyedpi.exe " + p.BuildArgs(null), LogLevel.Debug);
            App.Log("GoodbyeDPI v0.2.3rc3: Passive DPI blocker and Active DPI circumvention utility", LogLevel.Output);
            App.Log("Filter activated, GoodbyeDPI is now running!", LogLevel.Output);
            App.Log("Protection active: " + p.Name, LogLevel.Success);
            App.Log("Connection test: 6/6 sites reachable, DNS correct.", LogLevel.Success);
            App.Log("[NSF-402] DNS server does not answer: 77.88.8.8:1253", LogLevel.Warn);
            App.Engine.DebugSet(EngineState.Running, p);

            // --- both languages: the main pages
            foreach (var lang in new[] { "en", "tr" })
            {
                Loc.SetLanguage(lang);
                Theme(form, "system", UiLevel.Standard);
                foreach (var key in new[] { "home", "profiles", "settings", "about" })
                {
                    form.Navigate(key);
                    Shot(form, Path.Combine(dir, "0_" + lang + "_" + key + ".png"));
                }
            }
            Loc.SetLanguage(App.Settings.Language);

            // --- stage 2 in both languages: status chips, switch strip, appearance (draft + contrast), settings, switch windows
            foreach (var lang in new[] { "en", "tr" })
            {
                Loc.SetLanguage(lang);
                foreach (var (themeId, level) in new[] { ("slate-dark", UiLevel.Standard), ("clean-light", UiLevel.Simple), ("amoled", UiLevel.Advanced) })
                {
                    Theme(form, themeId, level);
                    App.RaiseStatus();
                    form.Navigate("home");
                    Shot(form, Path.Combine(dir, "g_" + lang + "_home_" + themeId + ".png"));
                }
                foreach (var tid in new[] { "clean-light", "nord", "amoled", "slate-dark" })
                {
                    Theme(form, tid, UiLevel.Standard);
                    form.Go<AppearancePage>("appearance");
                    Shot(form, Path.Combine(dir, "g_" + lang + "_combo_" + tid + ".png"));
                }
                var ap = form.Go<AppearancePage>("appearance");
                Shot(form, Path.Combine(dir, "g_" + lang + "_appearance.png"));
                ap.DebugEdit("Muted", Color.FromArgb(0x47, 0x55, 0x69));
                ap.DebugEdit("Accent", Color.FromArgb(0xF4, 0x72, 0xB6));
                Shot(form, Path.Combine(dir, "g_" + lang + "_appearance_draft.png"));
                form.Navigate("settings");
                Shot(form, Path.Combine(dir, "g_" + lang + "_settings_draftdot.png"));
                form.Go<AppearancePage>("appearance").DebugEdit(null, Color.Empty);
                Theme(form, "clean-light", UiLevel.Standard);
                form.Go<AppearancePage>("appearance").DebugEdit("Text", Color.FromArgb(0x94, 0xA3, 0xB8));
                Shot(form, Path.Combine(dir, "g_" + lang + "_appearance_light_draft.png"));
                form.Go<AppearancePage>("appearance").DebugEdit(null, Color.Empty);
                var setp = form.Navigate("settings");
                var sarea = setp.Controls.OfType<ScrollArea>().FirstOrDefault();
                foreach (int yy in new[] { 0, 380 })
                {
                    if (sarea != null) sarea.AutoScrollPosition = new Point(0, NSFShield.Theme.D(yy));
                    Shot(form, Path.Combine(dir, "g_" + lang + "_settings_" + yy + ".png"));
                }
                foreach (bool done in new[] { false, true })
                    using (var w = SwitchDialog.DebugCreate(done))
                    {
                        w.StartPosition = FormStartPosition.Manual;
                        w.Location = new Point(-5000, 0);
                        w.Show();
                        Shot(w, Path.Combine(dir, "g_" + lang + "_switch_" + (done ? "done" : "dialog") + ".png"));
                        w.Close();
                    }
            }
            // --- stage 3 in both languages: engines (home chip, profile tabs, editor), site lists, ByeDPI settings
            string selBefore = App.Settings.SelectedProfileId;
            foreach (var lang in new[] { "en", "tr" })
            {
                Loc.SetLanguage(lang);
                Theme(form, "slate-dark", UiLevel.Advanced);
                foreach (var id in new[] { "zapret-discord", "byedpi-recommended" })
                {
                    var prof = Profiles.BuiltIns.First(x => x.Id == id);
                    App.Settings.SelectedProfileId = id;
                    App.Engine.DebugSet(EngineState.Running, prof);
                    App.RaiseStatus();
                    form.Navigate("home");
                    Shot(form, Path.Combine(dir, "h_" + lang + "_home_" + id + ".png"));
                    form.Navigate("profiles");
                    Shot(form, Path.Combine(dir, "h_" + lang + "_profiles_" + id + ".png"));
                }
                foreach (var (tag, prof) in new[]
                {
                    ("zapret", Profiles.BuiltIns.First(x => x.Id == "zapret-discord").CloneAsCustom()),
                    ("byedpi_rejected", new Profile { Name = "ByeDPI test", Engine = EngineKind.ByeDpi, EngineArgs = "--ip 0.0.0.0 --split 1+s" }),
                })
                    using (var ed3 = new EngineProfileEditor(prof))
                    {
                        ed3.StartPosition = FormStartPosition.Manual;
                        ed3.Location = new Point(-5000, 0);
                        ed3.Show();
                        Shot(ed3, Path.Combine(dir, "h_" + lang + "_editor_" + tag + ".png"));
                        ed3.Close();
                    }
                App.Settings.TargetedMode = true;
                App.Settings.ExcludeEnabled = true;
                App.Settings.ExcludeDomains = Hostlists.ExcludeTemplates[0].Domains.Take(9).ToList();
                var sp3 = form.Go<SitesPage>("sites");
                sp3.ShowList(false);
                Shot(form, Path.Combine(dir, "h_" + lang + "_sites_include.png"));
                sp3.ShowList(true);
                Shot(form, Path.Combine(dir, "h_" + lang + "_sites_exclude.png"));
                // GoodbyeDPI has no exclude list: the page says so in amber
                App.Settings.SelectedProfileId = "tr-recommended";
                App.Engine.DebugSet(EngineState.Running, App.SelectedProfile);
                App.RaiseStatus();
                sp3 = form.Go<SitesPage>("sites");
                sp3.ShowList(true);
                Shot(form, Path.Combine(dir, "h_" + lang + "_sites_exclude_goodbyedpi.png"));
                var stp = form.Navigate("settings");
                var sarea3 = stp.Controls.OfType<ScrollArea>().FirstOrDefault();
                if (sarea3 != null) sarea3.AutoScrollPosition = new Point(0, NSFShield.Theme.D(1060));
                Shot(form, Path.Combine(dir, "h_" + lang + "_settings_byedpi.png"));
                App.Settings.TargetedMode = false;
                App.Settings.ExcludeEnabled = false;
                App.Settings.ExcludeDomains = new List<string>();
            }
            App.Settings.SelectedProfileId = selBefore;
            App.Engine.DebugSet(EngineState.Running, App.SelectedProfile);
            // --- stage 4: catalog layers, three UI levels, smart scanner (fixed example results)
            Stage4Shots(form, dir);
            // --- stage 5: conflict diagnosis, the home card, access denied, network change, NSF1 profile codes
            Stage5Shots(form, dir);
            // --- security audit: refused https:// proxy, Setup-only release on a portable copy
            Stage6Shots(form, dir);
            Loc.SetLanguage(App.Settings.Language);
            using (var bmp = new Bitmap(560, 70))
            using (var g = Graphics.FromImage(bmp))
            {
                g.Clear(Color.FromArgb(32, 32, 32));
                int x = 10;
                foreach (TrayStatus t in Enum.GetValues(typeof(TrayStatus)))
                {
                    foreach (int sz in new[] { 16, 32, 48 })
                    {
                        using (var ic = TrayLook.MakeIcon(t, sz)) g.DrawIcon(ic, new Rectangle(x, 10, sz, sz));
                        x += sz + 4;
                    }
                    x += 6;
                }
                bmp.Save(Path.Combine(dir, "g_tray_icons.png"));
            }

            // --- Simple UI, system theme
            foreach (var (themeId, tag) in new[] { ("system", "system"), ("light", "light"), ("dracula", "dracula"), ("solarized-light", "solarized"), ("contrast", "contrast") })
            {
                Theme(form, themeId, UiLevel.Simple);
                App.RaiseStatus();
                form.Navigate("home");
                Shot(form, Path.Combine(dir, "a_simple_home_" + tag + ".png"));
            }
            Theme(form, "system", UiLevel.Simple);
            App.Problems.Report("NSF-901");
            App.RaiseStatus();
            form.Navigate("home"); Shot(form, Path.Combine(dir, "a_simple_home_banner.png"));
            App.Problems.Clear("NSF-901");

            App.Engine.DebugSet(EngineState.Error, p, "GoodbyeDPI could not be started. The WinDivert driver was blocked by an antivirus program.");
            App.Problems.Report("NSF-204", "test");
            App.RaiseStatus();
            form.Navigate("home"); Shot(form, Path.Combine(dir, "a_simple_home_error.png"));
            var tp = form.Go<TroublePage>("trouble");
            Shot(form, Path.Combine(dir, "a_simple_trouble.png"));
            tp.ShowCode("NSF-204");
            Shot(form, Path.Combine(dir, "a_simple_trouble_codes.png"));
            App.Problems.Clear("NSF-204");
            App.Engine.DebugSet(EngineState.Running, p);
            App.RaiseStatus();
            foreach (var key in new[] { "appearance", "settings", "about" })
            {
                form.Navigate(key);
                Shot(form, Path.Combine(dir, "a_simple_" + key + ".png"));
            }

            // --- Standard UI
            Theme(form, "system", UiLevel.Standard);
            App.RaiseStatus();
            App.Settings.Proxies.Add(new ProxyEntry { Name = "Germany SOCKS5", Kind = ProxyKind.Socks5, Host = "203.0.113.10", Port = 1080, LastOk = true, LastTest = DateTime.Now, LastResult = "Working · 84 ms · DE" });
            App.Settings.Proxies.Add(new ProxyEntry { Name = "Office HTTP", Kind = ProxyKind.Http, Host = "198.51.100.7", Port = 3128, User = "user", LastOk = false, LastTest = DateTime.Now, LastResult = "NSF-805 The proxy server did not answer." });
            ProxyBridge.AssignPorts(App.Settings.Proxies);
            foreach (var (nm, path) in AppProxy.Installed().Take(3))
                App.Settings.ProxyApps.Add(new ProxyApp { Name = nm, ExePath = path, Mode = AppProxy.Detect(path), ProxyId = App.Settings.Proxies[App.Settings.ProxyApps.Count % 2].Id });
            var rnd = new Random(7);
            for (int i = 0; i < 46; i++)
            {
                bool ok = i != 30 && i != 31;
                History.Add(new HistoryEntry { Time = DateTime.Now.AddMinutes(-15 * (46 - i)), Kind = "test", Profile = i < 31 ? "Turkey – Recommended" : "Automatic TTL (-5)",
                    Ok = ok ? 6 : i == 30 ? 1 : 0, Total = 6, Ms = ok ? 120 + rnd.Next(0, 160) : 0, DnsOk = true, Running = i != 12, Note = ok ? "" : "discord.com NSF-501" });
                if (i == 31) History.Add(new HistoryEntry { Time = DateTime.Now.AddMinutes(-15 * (46 - i) + 1), Kind = "repair", Profile = "Automatic TTL (-5)", Ok = 1, Total = 1, Running = true, Note = "New method: Automatic TTL (-5)" });
            }
            foreach (var key in new[] { "home", "profiles", "net", "dns", "sites", "proxy", "settings" })
            {
                form.Navigate(key);
                Shot(form, Path.Combine(dir, "b_standard_" + key + ".png"));
            }
            var np = form.Go<NetPage>("net");
            np.ShowTab(1, false); Shot(form, Path.Combine(dir, "b_standard_net_site.png"));
            np.ShowTab(2, false); Shot(form, Path.Combine(dir, "b_standard_net_dns.png"));
            np.ShowTab(3, false); Shot(form, Path.Combine(dir, "b_standard_net_speed.png"));
            np.ShowTab(4, false); Shot(form, Path.Combine(dir, "b_standard_net_history.png"));
            form.Go<ProxyPage>("proxy").ShowApps(); Shot(form, Path.Combine(dir, "b_standard_proxy_apps.png"));

            // --- Advanced UI, light theme
            Theme(form, "light", UiLevel.Advanced);
            App.RaiseStatus();
            foreach (var key in new[] { "home", "profiles", "log", "settings", "net" })
            {
                form.Navigate(key);
                Shot(form, Path.Combine(dir, "c_advanced_" + key + ".png"));
            }

            // --- update banner and the lower sections of Settings
            Theme(form, "system", UiLevel.Standard);
            Updater.DebugSetAvailable(new UpdateInfo { Version = new Version(1, 0, 1), Notes = "## What's new\n- Example" });
            App.RaiseStatus();
            form.Navigate("home"); Shot(form, Path.Combine(dir, "f_home_update.png"));
            var sp = form.Navigate("settings");
            var area = sp.Controls.OfType<ScrollArea>().FirstOrDefault();
            if (area != null)
                foreach (int yy in new[] { 900, 1500 })
                {
                    area.AutoScrollPosition = new Point(0, NSFShield.Theme.D(yy));
                    Shot(form, Path.Combine(dir, "f_settings_" + yy + ".png"));
                }
            Updater.DebugSetAvailable(null);
            form.Go<TroublePage>("trouble"); Shot(form, Path.Combine(dir, "f_trouble.png"));

            // --- windows
            Theme(form, "system", UiLevel.Standard);
            var ed = new ProfileEditor(Profiles.BuiltIns[4].CloneAsCustom());
            ed.StartPosition = FormStartPosition.Manual;
            ed.Location = new Point(-5000, 0);
            ed.Show();
            Shot(ed, Path.Combine(dir, "d_editor.png"));
            ed.Close();

            // icons + glyph table
            var glyphs = typeof(NSFShield.Theme).GetFields(BindingFlags.Public | BindingFlags.Static)
                .Where(f => f.IsLiteral && f.Name.StartsWith("G")).ToList();
            using (var bmp = new Bitmap(900, 460))
            using (var g = Graphics.FromImage(bmp))
            {
                g.Clear(Color.White);
                int x = 10;
                foreach (EngineState s in Enum.GetValues(typeof(EngineState)))
                {
                    foreach (int sz in new[] { 16, 24, 32, 64 })
                    {
                        using (var ic = IconArt.StateIcon(s, sz)) g.DrawIcon(ic, new Rectangle(x, 10, sz, sz));
                        x += sz + 8;
                    }
                    x += 10;
                }
                int gx = 10, gy = 110;
                using (var f = new Font(NSFShield.Theme.IconFontName, 16f))
                    foreach (var fi in glyphs)
                    {
                        TextRenderer.DrawText(g, (string)fi.GetValue(null), f, new Point(gx, gy), Color.Black);
                        TextRenderer.DrawText(g, fi.Name, new Font("Segoe UI", 8f), new Point(gx + 30, gy + 6), Color.DimGray);
                        gx += 125;
                        if (gx > 800) { gx = 10; gy += 40; }
                    }
                bmp.Save(Path.Combine(dir, "e_icons.png"));
            }
            form.Dispose();
        }
    }
#endif
}
