using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace NSFShield
{
    /// <summary>
    /// Clean uninstall: reverts every change NSF Shield made to Windows (service, startup task, WinDivert
    /// driver entry, Windows proxy setting, changed DNS servers, local bridge, temporary files).
    /// Does not delete the program folder or the settings. Command line: NSFShield.exe --uninstall [--quiet]
    /// </summary>
    /// <summary>Bullet list of uninstall results in the UI language, with an English copy for the log.</summary>
    public sealed class UninstallReport
    {
        readonly StringBuilder ui = new StringBuilder(), en = new StringBuilder();

        public void Add(string key, params object[] args)
        {
            ui.AppendLine("• " + Loc.T(key, args));
            en.AppendLine("• " + Loc.En(key, args));
        }

        public bool Empty => ui.Length == 0;
        public string Text => ui.ToString().TrimEnd();
        public string English => en.ToString().TrimEnd();
    }

    public static class Uninstaller
    {
        public static string Run()
        {
            var r = new UninstallReport();
            App.Log("Clean uninstall started.", LogLevel.Info);

            // 1) protection, service and driver entry
            try { App.Engine.RemoveForUninstall(r); }
            catch (Exception ex) { r.Add("uninstall.serviceCleanupFailed", ex.Message); }

            // 2) startup task (only if it belongs to this installation or to a folder that no longer exists)
            try
            {
                string cmd = Startup.CommandPath();
                if (cmd != null)
                {
                    bool ours = string.Equals(Path.GetFullPath(cmd), Path.GetFullPath(Application.ExecutablePath), StringComparison.OrdinalIgnoreCase) || !File.Exists(cmd);
                    if (ours) { Startup.Disable(); r.Add("uninstall.taskRemoved"); }
                    else r.Add("uninstall.taskKept", cmd);
                }
            }
            catch (Exception ex) { r.Add("uninstall.taskRemoveFailed", ex.Message); }

            // 3) local proxy bridge and Windows proxy setting (also the ByeDPI bridge and its restore entry for the next sign-in)
            try { ProxyBridge.StopAll(); } catch (Exception ign) { App.Ignored("Local bridge could not be stopped", ign); }
            try { if (ByeDpiNet.RecoverStale("clean uninstall")) r.Add("uninstall.proxyRestored"); }
            catch (Exception ex) { r.Add("uninstall.proxyRestoreFailed", ex.Message); }
            try
            {
                if (ProxyTools.HasRecord)
                {
                    if (ProxyTools.RestoreSystem()) r.Add("uninstall.proxyRestored");
                    else r.Add("uninstall.proxyRestoreFailed", Loc.T("uninstall.proxyNotVerified"));
                }
            }
            catch (Exception ex) { r.Add("uninstall.proxyRestoreFailed", ex.Message); }
            // the recovery helper goes with the app: no record or sign-in entry of it stays behind (the live setting is not touched)
            try { ProxyRecovery.Drop(); } catch (Exception ign) { App.Ignored("Proxy recovery record could not be removed", ign); }

            // 4) DNS servers changed by NSF Shield
            try
            {
                if (App.Settings.DnsBackups.Count > 0 || App.Settings.DohBackups.Count > 0 || App.Settings.GlobalDohBackup != null)
                {
                    bool ok = SystemDns.Restore(out string rep, onlyBackups: true);
                    if (ok) r.Add("uninstall.dnsRestored"); else r.Add("uninstall.dnsPartial", rep);
                }
            }
            catch (Exception ex) { r.Add("uninstall.dnsRestoreFailed", ex.Message); }

            // 5) temporary files
            try
            {
                Updater.Cleanup();
                foreach (var f in Directory.GetFiles(Path.GetTempPath(), "NSFShield-*-proxy.lnk")) try { File.Delete(f); } catch (Exception ign) { App.Ignored("Temporary shortcut could not be deleted", ign); }
                string prev = Path.Combine(Path.GetTempPath(), "nsfshield_preview");
                if (Directory.Exists(prev)) try { Directory.Delete(prev, true); } catch (Exception ign) { App.Ignored("Preview folder could not be deleted", ign); }
            }
            catch (Exception ign) { App.Ignored("Temporary files could not be cleaned up", ign); }

            // 6) settings: record that no permanent system change is left
            App.Settings.ServiceMode = false;
            App.Settings.StartWithWindows = false;
            App.Save();
            Native.FlushDns();

            if (r.Empty) r.Add("uninstall.nothingToRevert");
            string profiles = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NSF Shield");
            if (Directory.Exists(profiles))
                r.Add("uninstall.browserProfilesKept", profiles);
            App.Log("Clean uninstall finished:\n" + r.English, LogLevel.Success);
            return r.Text;
        }

        /// <summary>
        /// Called at startup. A NSF Shield service or startup task pointing to an unprotected (writable by everyone) folder
        /// is removed; if this installation is protected and the user enabled the feature, it is pointed back to this folder later.
        /// Returns: whether the removed service was running (protection should continue in app mode).
        /// </summary>
        public static bool EnforceLocationRules(bool thisProtected, out string removed)
        {
            var sb = new StringBuilder();
            bool wasRunning = false;
            try
            {
                if (Engine.ServiceExists(Engine.ServiceName))
                {
                    string exe = Engine.ServiceExe(Engine.ServiceName);
                    string inst = exe == null ? null : Path.GetDirectoryName(Path.GetDirectoryName(Path.GetDirectoryName(exe)));
                    bool safe = inst != null && InstallGuard.Check(inst, out _);
                    bool repointLater = thisProtected && App.Settings.ServiceMode;
                    if (!safe && !repointLater)
                    {
                        try
                        {
                            using (var sc = new System.ServiceProcess.ServiceController(Engine.ServiceName))
                                wasRunning = sc.Status == System.ServiceProcess.ServiceControllerStatus.Running;
                        }
                        catch (Exception ign) { App.Ignored("Service status could not be read", ign); }
                        App.Engine.UninstallService();
                        sb.Append(Loc.T("uninstall.removed.service"));
                        App.Log("[NSF-705] Removed the background service pointing to an unprotected folder: " + exe, LogLevel.Warn);
                    }
                }
            }
            catch (Exception ex) { App.Log("Service could not be checked: " + ex.Message, LogLevel.Warn); }
            try
            {
                string cmd = Startup.CommandPath();
                if (cmd != null)
                {
                    bool safe = File.Exists(cmd) && InstallGuard.Check(Path.GetDirectoryName(cmd), out _);
                    bool reRegisterLater = thisProtected && App.Settings.StartWithWindows;
                    if (!safe && !reRegisterLater)
                    {
                        Startup.Disable();
                        sb.Append(sb.Length > 0 ? " " + Loc.T("common.and") + " " : "").Append(Loc.T("uninstall.removed.task"));
                        App.Log("[NSF-705] Removed the startup task pointing to an unprotected folder: " + cmd, LogLevel.Warn);
                    }
                }
            }
            catch (Exception ex) { App.Log("Startup task could not be checked: " + ex.Message, LogLevel.Warn); }
            if (!thisProtected && (App.Settings.ServiceMode || App.Settings.StartWithWindows))
            {
                App.Settings.ServiceMode = false;
                App.Settings.StartWithWindows = false;
                App.Save();
            }
            removed = sb.ToString();
            return wasRunning;
        }

        /// <summary>
        /// --prepare-upgrade: called by the setup package before it replaces the files in this folder. Closes NSF Shield and the
        /// engines (goodbyedpi, winws, ciadpi) running from this folder, stops the service if it points here and unloads the
        /// WinDivert drivers of this folder. Does not touch settings, DNS or the task; a Windows proxy left pointed at the
        /// ByeDPI bridge by the closed app is restored.
        /// Returns: 10 the service was running (must be restarted after setup), 0 it was not, 1 no administrator rights.
        /// </summary>
        public static int PrepareUpgrade()
        {
            if (!App.IsAdmin()) return 1;
            string self = Process.GetCurrentProcess().MainModule.FileName;
            string dir = Path.GetDirectoryName(self).TrimEnd('\\') + "\\";
            int me = Process.GetCurrentProcess().Id;
            var log = new StringBuilder();
            // the app of this folder: its exact path (never the name alone)
            foreach (var pe in ProcReader.ByNames(new[] { "NSFShield" }))
            {
                if (pe.Pid == me || pe.Path == null || !PathSafety.Same(pe.Path, self)) continue;
                try
                {
                    bool gone;
                    using (var p = Process.GetProcessById(pe.Pid)) gone = p.WaitForExit(3000);
                    if (gone || ProcReader.TerminateIf(pe.Pid, path => ProcReader.IsFile(path, self), out string why, 5000)) log.AppendLine("App closed (PID " + pe.Pid + ").");
                    else log.AppendLine("App was not closed (PID " + pe.Pid + "): " + why);
                }
                catch (ArgumentException) { log.AppendLine("App closed (PID " + pe.Pid + ")."); }
                catch (Exception ex) { log.AppendLine("App could not be closed: " + ex.Message); }
            }
            bool wasRunning = false;
            // the service of this installation only (the strict owner rule: its exe is an engine of this folder by the physical
            // path, read right before it is stopped); a service of another installation or an unreadable one is left alone
            var svc = Engine.Scm.Query(Engine.ServiceName);
            if (svc.Exists && svc.Owned != null && svc.Running)
            {
                wasRunning = true;
                if (Engine.Scm.Stop(Engine.ServiceName, TimeSpan.FromSeconds(30))) log.AppendLine("Background service stopped.");
                else log.AppendLine("Service could not be stopped in time.");
            }
            else if (svc.Exists && svc.Owned == null) log.AppendLine("The NSFShield service is not this installation's; it was left running.");
            else if (svc.Unknown) log.AppendLine("The service state could not be read (" + svc.Read + "); nothing was changed.");
            // the engines of this folder (GoodbyeDPI, Zapret winws, ByeDPI ciadpi) and the proxy recovery helper: by their exact
            // exe, checked again through the handle that closes them
            var exes = Engines.All.Select(e => (Name: e.ProcessName, Exe: e.ExePath)).ToList();
            exes.Add((Path.GetFileNameWithoutExtension(ProxyRecovery.HelperFile), Path.Combine(dir, "bin", ProxyRecovery.HelperFile)));
            foreach (var (name, exe) in exes)
                foreach (var pe in ProcReader.ByNames(new[] { name }))
                {
                    if (pe.Path == null || !PathSafety.Same(pe.Path, exe)) continue;
                    if (ProcReader.TerminateIf(pe.Pid, path => ProcReader.IsFile(path, exe), out string why)) log.AppendLine(name + " closed.");
                    else log.AppendLine(name + " was not closed: " + why);
                }
            ReleaseDrivers(dir, log);
            // ByeDPI: the app was closed above, so the Windows proxy must not stay pointed at its bridge
            try
            {
                App.Settings = SettingsStore.Load();
                if (ByeDpiNet.RecoverStale("before the setup package")) log.AppendLine("Windows proxy of ByeDPI restored.");
            }
            catch (Exception ex) { log.AppendLine("Windows proxy could not be checked: " + ex.Message); }
            string data = Path.Combine(dir, "data");
            CrashMarker.Clear(data);
            try
            {
                Directory.CreateDirectory(data);
                File.AppendAllText(Path.Combine(data, "update.log"), DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  Preparing for the setup package: " +
                                   (log.Length > 0 ? log.ToString().Replace(Environment.NewLine, " ") : "nothing was running.") + Environment.NewLine, Encoding.UTF8);
            }
            catch (Exception ign) { App.Ignored("Preparation log could not be written", ign); }
            return wasRunning ? 10 : 0;
        }

        /// <summary>Service names of the WinDivert driver (see <see cref="DriverControl"/>).</summary>
        internal static string[] DriverServices => DriverControl.DriverServices;
        internal static string DriverFile(string imagePath) => DriverControl.DriverFile(imagePath);
        internal static bool DriverInFolder(string imagePath, string dir) => DriverControl.DriverInFolder(imagePath, dir);

        /// <summary>
        /// The WinDivert driver stays loaded after the engine exits and keeps its .sys file locked, so the setup package cannot
        /// replace it: unload every WinDivert driver loaded from this folder (GoodbyeDPI's and Zapret's; stop only, never delete).
        /// </summary>
        static void ReleaseDrivers(string dir, StringBuilder log) => DriverControl.Release(dir, log);

        /// <summary>
        /// The setup package could not start the background service again after an upgrade (it wrote data\setup-result.txt):
        /// the problem is shown once at the next start (never a silent success). A link in its place is ignored.
        /// </summary>
        public static void ReportSetupResult()
        {
            string f = Path.Combine(App.DataDir, "setup-result.txt");
            if (PathSafety.Reparse(f) != PathSafety.Kind.None || !File.Exists(f) || new FileInfo(f).Length > 4096) return;
            string t = File.ReadAllText(f);
            if (t.Contains("service-not-restored"))
            {
                App.Log("[NSF-702] The setup package installed the files, but the background service could not be started again.", LogLevel.Warn);
                App.Problems.Report("NSF-702", new LocText("setup.serviceNotRestored"));
            }
            File.Delete(f);
        }

        /// <summary>--uninstall: closes the running copy and cleans up. 0 success, 1 no administrator rights.</summary>
        public static int RunCli(bool quiet)
        {
            if (!App.IsAdmin()) return 1;
            string self = Process.GetCurrentProcess().MainModule.FileName;
            int me = Process.GetCurrentProcess().Id;
            foreach (var pe in ProcReader.ByNames(new[] { "NSFShield" }))
            {
                if (pe.Pid == me) continue;
                if (!ProcReader.TerminateIf(pe.Pid, path => ProcReader.IsFile(path, self), out string why, 5000) && pe.Path != null && PathSafety.Same(pe.Path, self))
                    App.Log("Running copy was not closed (PID " + pe.Pid + "): " + why, LogLevel.Warn);
            }
            CrashMarker.Clear(App.DataDir);   // no "unexpected shutdown" warning for the copy that was closed
            App.Init();
            string report = Run();
            if (!quiet)
                MessageBox.Show(Loc.T("uninstall.done", report), App.Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
            return 0;
        }
    }
}
