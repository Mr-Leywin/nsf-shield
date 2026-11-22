using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;

namespace NSFShield
{
    /// <summary>
    /// Moves a portable copy to the installed version: the setup package (verified like an update) installs NSF Shield to
    /// Program Files, the settings are carried over through the same checks as a settings import, then the installed copy
    /// opens and this one closes. The portable folder is not deleted.
    /// </summary>
    public static class InstallerSwitch
    {
        /// <summary>Started by the portable copy: "--switched-from-portable &lt;pid&gt;" (waits for that process to exit).</summary>
        public const string SwitchedArg = "--switched-from-portable";
#if PREVIEW
        /// <summary>
        /// Test hook of the preview build only: "--switch-to-installer &lt;local Setup.exe&gt; &lt;SHA-256&gt;". The release exe has no
        /// way to start an elevated setup package from a local path with a hash given by the caller; it only installs the
        /// verified setup package of the GitHub release.
        /// </summary>
        public const string LocalArg = "--switch-to-installer";
#endif
        public const string SetupDescription = "NSF Shield Setup";
        const long MaxSetupBytes = 100L * 1024 * 1024;

        /// <summary>The switch is offered to portable copies only.</summary>
        public static bool Offered => InstallGuard.IsPortable && !Updater.InstalledMode;

        // ================================================================ setup package

        /// <summary>Can this release be used for the switch? It must not be older than this copy and must have Setup.exe with SHA-256.</summary>
        public static bool Usable(UpdateInfo i, out string error)
        {
            error = "";
            if (i == null) { error = Loc.T("switch.noRelease"); return false; }
            if (i.Version < Updater.Current) { error = Loc.T("switch.olderRelease", i.Version, Updater.Current); return false; }
            if (i.SetupUrl.Length == 0 || i.SetupSha256.Length != 64) { error = Loc.T("switch.noSetup", i.Version); return false; }
            return true;
        }

        /// <summary>Downloads the setup package of a release (HTTPS, GitHub address after redirects, SHA-256, product name, version).</summary>
        public static Updater.Prepared Download(UpdateInfo i, Action<long, long> progress, CancellationToken ct)
        {
            if (!Usable(i, out string err)) throw new InvalidOperationException(err);
            var prep = Updater.DownloadSetup(i, progress, ct);
            if (!VerifySetupInfo(prep.SetupPath, Updater.Current, out err))
            {
                try { File.Delete(prep.SetupPath); } catch (Exception ex) { App.Ignored("Setup package could not be deleted", ex); }
                throw new InvalidDataException(err);
            }
            return prep;
        }

        /// <summary>Is the file a NSF Shield setup package of at least the given version?</summary>
        internal static bool VerifySetupInfo(string path, Version min, out string error)
        {
            error = "";
            var fv = FileVersionInfo.GetVersionInfo(path);
            string product = (fv.ProductName ?? "").Trim(), desc = (fv.FileDescription ?? "").Trim(), ver = (fv.FileVersion ?? "").Trim();
            if (product != "NSF Shield" || desc != SetupDescription || !Version.TryParse(ver, out var v) || new Version(v.Major, v.Minor, Math.Max(0, v.Build)) < min)
            {
                error = Loc.T("switch.notSetup", (product + " · " + desc + " · " + ver).Trim(' ', '·'));
                return false;
            }
            return true;
        }

#if PREVIEW
        /// <summary>A local path for the test hook: an existing .exe on a local drive.</summary>
        internal static bool ValidateLocalPath(string path, out string error)
        {
            error = "";
            try
            {
                if (string.IsNullOrWhiteSpace(path) || !Path.IsPathRooted(path) || path.StartsWith(@"\\") || path.StartsWith("//"))
                { error = Loc.T("switch.localPath"); return false; }
                string full = Path.GetFullPath(path);
                if (!string.Equals(Path.GetExtension(full), ".exe", StringComparison.OrdinalIgnoreCase)) { error = Loc.T("switch.localPath"); return false; }
                var fi = new FileInfo(full);
                if (!fi.Exists || fi.Length == 0 || fi.Length > MaxSetupBytes) { error = Loc.T("switch.localMissing", full); return false; }
                return true;
            }
            catch (Exception ex) { error = Loc.T("switch.localPath") + " " + ex.Message; return false; }
        }

        /// <summary>
        /// Test hook: copies a local setup package to data\update and verifies the copy (SHA-256 from the same handle, product
        /// name, description, version). Nothing is started from the original path.
        /// </summary>
        public static Updater.Prepared PrepareLocal(string path, string sha256)
        {
            if (!ValidateLocalPath(path, out string err)) throw new InvalidDataException(err);
            sha256 = (sha256 ?? "").Trim().ToLowerInvariant();
            if (sha256.Length != 64 || !sha256.All(Uri.IsHexDigit)) throw new InvalidDataException(Loc.T("switch.localHash"));
            Directory.CreateDirectory(Updater.UpdateRoot);
            string copy = Path.Combine(Updater.UpdateRoot, Path.GetFileNameWithoutExtension(path) + "-" + Guid.NewGuid().ToString("N").Substring(0, 8) + ".exe");
            using (var src = new FileStream(Path.GetFullPath(path), FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var dst = new FileStream(copy, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
            {
                src.CopyTo(dst);
                dst.Position = 0;
                if (Integrity.Sha256(dst) != sha256) { dst.Close(); File.Delete(copy); throw new InvalidDataException(Loc.T("switch.localHashMismatch")); }
            }
            if (!VerifySetupInfo(copy, Updater.Current, out err)) { File.Delete(copy); throw new InvalidDataException(err); }
            App.Log("Local setup package verified for the switch: " + Path.GetFileName(copy) + " (SHA-256 " + sha256.Substring(0, 16) + "…)", LogLevel.Info);
            return new Updater.Prepared { SetupPath = copy, ExeSha256 = sha256 };
        }
#endif

        /// <summary>
        /// Runs the setup package with a progress window (no wizard pages) and waits for it. The hash and the version information
        /// are checked again from a handle that denies writing until the process has started (there is no publisher signature
        /// to check yet; see <see cref="Updater.VerifyIdentity"/>). Returns the setup's exit code.
        /// </summary>
        public static int RunSetup(Updater.Prepared prep, CancellationToken ct)
        {
            Process p;
            using (var hold = new FileStream(prep.SetupPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (Integrity.Sha256(hold) != prep.ExeSha256) throw new InvalidDataException(Loc.T("update.setupChanged"));
                if (!VerifySetupInfo(prep.SetupPath, Updater.Current, out string why)) throw new InvalidDataException(why);
                string log = Path.Combine(App.DataDir, "setup-switch.log");
                p = Process.Start(new ProcessStartInfo(prep.SetupPath, "/SILENT /SUPPRESSMSGBOXES /NORESTART /SP- /LOG=\"" + log + "\"")
                { UseShellExecute = false, WorkingDirectory = Path.GetDirectoryName(prep.SetupPath) });
            }
            using (p)
            {
                App.Log("Setup package started to switch to the installed version.", LogLevel.Info);
                var until = DateTime.Now.AddMinutes(15);
                while (!p.WaitForExit(500))
                    if (DateTime.Now > until) throw new TimeoutException(Loc.T("switch.setupTimeout"));
                App.Log("Setup package finished with exit code " + p.ExitCode + ".", p.ExitCode == 0 ? LogLevel.Info : LogLevel.Warn);
                return p.ExitCode;
            }
        }

        // ================================================================ target folder

        /// <summary>
        /// The installed folder must be an absolute local path, not this folder, contain NSFShield.exe of NSF Shield and be
        /// protected (only administrators can write to it).
        /// </summary>
        internal static bool ValidateTarget(string dir, string selfDir, Func<string, bool> isProtected, out string error)
        {
            error = Loc.T("switch.badTarget", dir ?? "");
            try
            {
                if (string.IsNullOrWhiteSpace(dir) || !Path.IsPathRooted(dir) || dir.StartsWith(@"\\") || dir.StartsWith("//") || dir.Contains("..")) return false;
                string full = Path.GetFullPath(dir).TrimEnd('\\');
                if (!string.IsNullOrEmpty(selfDir) && string.Equals(full, Path.GetFullPath(selfDir).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) return false;
                string exe = Path.Combine(full, "NSFShield.exe");
                if (!Directory.Exists(full) || !File.Exists(exe)) return false;
                if ((FileVersionInfo.GetVersionInfo(exe).ProductName ?? "").Trim() != "NSF Shield") return false;
                if (!isProtected(full)) { error = Loc.T("switch.unprotectedTarget", full); return false; }
                error = "";
                return true;
            }
            catch { return false; }
        }

        /// <summary>The folder the setup package installed to (read from its uninstall entry) after validation; null on error.</summary>
        public static string InstalledDir(out string error)
        {
            string loc = Updater.InnoInstallLocation();
            if (!ValidateTarget(loc, App.BaseDir, d => InstallGuard.Check(d, out _), out error)) return null;
            return Path.GetFullPath(loc).TrimEnd('\\');
        }

        // ================================================================ settings

        /// <summary>data\settings.xml of the installed folder (only fixed names are appended to the validated folder).</summary>
        internal static string TargetSettingsPath(string installDir)
        {
            string root = Path.GetFullPath(installDir).TrimEnd('\\') + "\\";
            string path = Path.GetFullPath(Path.Combine(root, App.DataDirName, "settings.xml"));
            if (!path.StartsWith(root + App.DataDirName + "\\", StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException(Loc.T("switch.badTarget", installDir));
            return path;
        }

        /// <summary>
        /// The settings for the installed copy, passed through the checks of a settings import (allow-listed GoodbyeDPI
        /// arguments, proxy rules, DNS backup addresses). The background service and start with Windows start off: they
        /// are offered after the switch.
        /// </summary>
        internal static AppSettings Prepare(AppSettings s, string workDir)
        {
            Directory.CreateDirectory(workDir);
            string tmp = Path.Combine(workDir, "switch-settings-" + Guid.NewGuid().ToString("N").Substring(0, 8) + ".xml");
            try
            {
                // a new file with a unique name (CreateNew never opens an existing file or a link planted under that name)
                using (var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None)) SettingsStore.Serialize(s, fs);
                var clean = SettingsStore.Import(tmp);
                clean.ServiceMode = false;
                clean.StartWithWindows = false;
                clean.LastUpdateCheck = null;
                clean.SkipVersion = "";
                clean.InstallerHintDismissed = true;
                return clean;
            }
            finally { try { File.Delete(tmp); } catch (Exception ex) { App.Ignored("Temporary settings file could not be deleted", ex); } }
        }

        /// <summary>
        /// Opens a plain file of a folder for reading (writing denied while it is open): no link in its path, exactly one hard
        /// link, its physical path inside the physical folder, at most <paramref name="maxBytes"/>.
        /// </summary>
        internal static FileStream OpenPlain(string path, string dir, long maxBytes)
        {
            string link = PathSafety.UnsafeInChain(path);
            if (link != null) throw new InvalidDataException(Loc.T("guard.reparse", link));
            var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            try
            {
                string fin = PathSafety.FinalPathOf(fs), d = PathSafety.FinalPath(dir);
                if (fin == null || d == null || !fin.StartsWith(d.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException(Loc.T("guard.finalPath", path));
                if (PathSafety.LinkCount(fs) != 1) throw new InvalidDataException(Loc.T("integrity.notPlain", path));
                if (fs.Length > maxBytes) throw new InvalidDataException(Loc.T("switch.fileTooLarge", Path.GetFileName(path)));
                return fs;
            }
            catch { fs.Dispose(); throw; }
        }

        /// <summary>
        /// Writes a file of a folder: a new temporary file with a unique name (CreateNew) is written, flushed and moved into
        /// place. An existing destination must be a plain file of that folder (<paramref name="replace"/>), or must not exist.
        /// </summary>
        internal static void WriteNew(string dst, string dir, Action<Stream> write, bool replace)
        {
            string tmp = Path.Combine(dir, Path.GetFileName(dst) + "." + Guid.NewGuid().ToString("N").Substring(0, 8) + ".tmp");
            using (var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { write(fs); fs.Flush(true); }
            try
            {
                if (File.Exists(dst) || PathSafety.Reparse(dst) != PathSafety.Kind.None)
                {
                    if (!replace) throw new IOException(Loc.T("switch.targetExists", Path.GetFileName(dst)));
                    using (OpenPlain(dst, dir, long.MaxValue)) { }
                    File.Replace(tmp, dst, null);
                }
                else File.Move(tmp, dst);
            }
            catch { try { if (File.Exists(tmp)) File.Delete(tmp); } catch { } throw; }
        }

        /// <summary>
        /// Writes the settings into the installed folder. Settings already there are kept as settings.xml.before-switch.
        /// The history is copied too if the installed copy has none. Every source and target is a plain file (no link, one hard
        /// link) at the physical path of its folder; every new file is created under a unique name first. Returns the settings file.
        /// </summary>
        public static string Transfer(AppSettings s, string installDir, string sourceDataDir)
        {
            var clean = Prepare(s, Path.Combine(sourceDataDir, Updater.UpdateDirName));
            string target = TargetSettingsPath(installDir);
            string dataDir = Path.GetDirectoryName(target);
            // the protected folder was checked a moment ago; its data folder and settings file must not be links either
            string link = PathSafety.UnsafeInChain(target);
            if (link != null) throw new InvalidDataException(Loc.T("guard.reparse", link));
            Directory.CreateDirectory(dataDir);
            string pd = PathSafety.FinalPath(dataDir), pi = PathSafety.FinalPath(installDir);
            if (pd == null || pi == null || !pd.StartsWith(pi.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException(Loc.T("guard.finalPath", dataDir));
            if (File.Exists(target))
                using (var cur = OpenPlain(target, dataDir, SettingsStore.MaxFileBytes))
                    WriteNew(target + ".before-switch", dataDir, dst => cur.CopyTo(dst), replace: true);
            WriteNew(target, dataDir, dst => SettingsStore.Serialize(clean, dst), replace: true);

            string hist = Path.Combine(sourceDataDir, "history.csv"), histDst = Path.Combine(dataDir, "history.csv");
            try
            {
                // the history of the portable copy (a folder its user can write) is read as a plain file of that folder only
                if (File.Exists(hist) && !File.Exists(histDst))
                    using (var src = OpenPlain(hist, sourceDataDir, 5L * 1024 * 1024))
                        WriteNew(histDst, dataDir, dst => src.CopyTo(dst), replace: false);
            }
            catch (Exception ex) { App.Log("History could not be copied: " + ex.Message, LogLevel.Warn); }
            App.Log("Settings carried over to the installed version: " + target, LogLevel.Success);
            return target;
        }

        /// <summary>Starts the installed copy; it waits for this process to exit before it opens (single instance).</summary>
        public static void StartInstalled(string installDir)
        {
            string exe = Path.Combine(installDir, "NSFShield.exe");
            Process.Start(new ProcessStartInfo(exe, SwitchedArg + " " + Process.GetCurrentProcess().Id) { UseShellExecute = false, WorkingDirectory = installDir });
        }

        /// <summary>In the installed copy: waits (at most 30 s) until the portable copy that started it has exited.</summary>
        public static void WaitForPortable(string pidText)
        {
            if (!int.TryParse(pidText, out int pid) || pid <= 0) return;
            try
            {
                using (var p = Process.GetProcessById(pid))
                    if (p.ProcessName.Equals("NSFShield", StringComparison.OrdinalIgnoreCase)) p.WaitForExit(30000);
            }
            catch (ArgumentException) { /* already exited */ }
            catch (Exception ex) { App.Ignored("Waiting for the portable copy failed", ex); }
        }
    }
}
