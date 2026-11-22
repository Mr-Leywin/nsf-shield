using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;

namespace NSFShield
{
    public sealed class UpdateInfo
    {
        public Version Version;
        public string Tag = "", Name = "", Notes = "", HtmlUrl = "", AssetName = "", AssetUrl = "", Sha256 = "";
        public long Size;
        /// <summary>Setup package (NSF-Shield-x.y.z-Setup.exe); the installed version is updated with it.</summary>
        public string SetupName = "", SetupUrl = "", SetupSha256 = "";
        public long SetupSize;
        public DateTime Published;
    }

    /// <summary>
    /// Automatic update from GitHub releases. The SHA-256 hash of the downloaded package is compared with the hash
    /// published by GitHub; if they differ nothing is installed. The portable version is installed by the new version's
    /// own exe (--apply-update) after the old app has exited and rolls back on errors; the installed version runs the
    /// setup package silently.
    /// </summary>
    public static class Updater
    {
        public const string Owner = "Mr-Leywin", Repo = "nsf-shield";
        public static UpdateInfo Available { get; private set; }
#if PREVIEW
        internal static void DebugSetAvailable(UpdateInfo i) => Available = i;
#endif
        public static bool Checking { get; private set; }
        /// <summary>The decision of the last check (see <see cref="FitFor"/>).</summary>
        public static Fit LastFit { get; private set; } = Fit.UpToDate;

        public static Version Current => Norm(Assembly.GetExecutingAssembly().GetName().Version);
        static Version Norm(Version v) => new Version(v.Major, v.Minor, Math.Max(0, v.Build));

        /// <summary>Name of the download folder inside the data folder.</summary>
        public const string UpdateDirName = "update";

        /// <summary>
        /// Download and extraction folder: inside the app's own data folder. In the installed version only administrators
        /// can write to it; in the portable version it has the same trust level as the app folder (%TEMP%, writable by
        /// everyone, is not used).
        /// </summary>
        public static string UpdateRoot => Path.Combine(App.DataDir, UpdateDirName);


        static HttpWebRequest Req(string url, int timeout)
        {
            var r = (HttpWebRequest)WebRequest.Create(url);
            r.UserAgent = "NSFShield/" + App.Version + " (+https://github.com/" + Owner + "/" + Repo + ")";
            r.Timeout = timeout;
            r.ReadWriteTimeout = timeout;
            r.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
            return r;
        }

        /// <summary>Reads the latest release on GitHub (returns the information even if it is not newer).</summary>
        public static UpdateInfo Check(out string error)
        {
            error = "";
            Checking = true;
            try
            {
                var r = Req("https://api.github.com/repos/" + Owner + "/" + Repo + "/releases/latest", 15000);
                r.Accept = "application/vnd.github+json";
                r.Headers["X-GitHub-Api-Version"] = "2022-11-28";
                string json;
                using (var resp = r.GetResponse())
                {
                    var u = resp.ResponseUri;
                    if (u == null || u.Scheme != "https" || u.Host != "api.github.com")
                        throw new InvalidOperationException(Loc.T("update.unexpectedRedirect", u?.Host));
                    using (var sr = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
                        json = sr.ReadToEnd();
                }
                var info = Parse(json);
                if (info == null) { error = Loc.T("update.unreadable"); return null; }
                if (App.Settings != null) { App.Settings.LastUpdateCheck = DateTime.Now; App.Post(App.Save); }
                LastFit = FitFor(info, InstalledMode);
                Available = LastFit == Fit.Ready ? info : null;
                App.Log("Update check: latest version " + info.Version + (Available != null ? " – a new version is available." : " – up to date."), LogLevel.Info);
                App.RaiseStatus();
                return info;
            }
            catch (WebException ex) when (ex.Response is HttpWebResponse hr && (int)hr.StatusCode == 404)
            {
                error = Loc.T("update.noRelease");
                return null;
            }
            catch (Exception ex)
            {
                error = Loc.T("update.githubUnreachable", ex.Message);
                App.Log("Update check failed: " + ex.Message, LogLevel.Debug);
                return null;
            }
            finally { Checking = false; }
        }

        /// <summary>Parses the GitHub API response.</summary>
        public static UpdateInfo Parse(string json)
        {
            var d = new JavaScriptSerializer { MaxJsonLength = 8 * 1024 * 1024 }.Deserialize<Dictionary<string, object>>(json);
            string S(Dictionary<string, object> o, string k) => o != null && o.TryGetValue(k, out var v) && v != null ? v.ToString() : "";
            string tag = S(d, "tag_name");
            if (!Version.TryParse(tag.TrimStart('v', 'V'), out var ver)) return null;
            if (d.TryGetValue("draft", out var dr) && dr is bool b1 && b1) return null;
            if (d.TryGetValue("prerelease", out var pr) && pr is bool b2 && b2) return null;
            var info = new UpdateInfo
            {
                Version = Norm(ver), Tag = tag, Name = S(d, "name"), Notes = S(d, "body"), HtmlUrl = S(d, "html_url"),
            };
            DateTime.TryParse(S(d, "published_at"), null, System.Globalization.DateTimeStyles.AdjustToUniversal, out info.Published);
            if (d.TryGetValue("assets", out var a) && a is System.Collections.ArrayList list)
            {
                foreach (Dictionary<string, object> asset in list.OfType<Dictionary<string, object>>())
                {
                    string name = S(asset, "name");
                    bool isZip = Regex.IsMatch(name, @"^NSF-Shield-[\d.]+\.zip$", RegexOptions.IgnoreCase);
                    bool isSetup = Regex.IsMatch(name, @"^NSF-Shield-[\d.]+-Setup\.exe$", RegexOptions.IgnoreCase);
                    if (!isZip && !isSetup) continue;
                    string digest = S(asset, "digest");
                    string sha = digest.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase) ? digest.Substring(7).ToLowerInvariant() : "";
                    long.TryParse(S(asset, "size"), out long size);
                    if (isZip && info.AssetName.Length == 0)
                    { info.AssetName = name; info.AssetUrl = S(asset, "browser_download_url"); info.Size = size; info.Sha256 = sha; }
                    if (isSetup && info.SetupName.Length == 0)
                    { info.SetupName = name; info.SetupUrl = S(asset, "browser_download_url"); info.SetupSize = size; info.SetupSha256 = sha; }
                }
            }
            // without a GitHub digest: "SHA-256 (file name): `hash`" lines in the release notes
            string FromNotes(string asset)
            {
                if (asset.Length == 0) return "";
                var m = Regex.Match(info.Notes, Regex.Escape(asset) + @"\)?\W{0,6}`([0-9a-fA-F]{64})`");
                return m.Success ? m.Groups[1].Value.ToLowerInvariant() : "";
            }
            if (info.Sha256.Length == 0) info.Sha256 = FromNotes(info.AssetName);
            if (info.SetupSha256.Length == 0) info.SetupSha256 = FromNotes(info.SetupName);
            return info;
        }

        public static bool IsNewer(UpdateInfo i) => i != null && i.Version > Current;

        /// <summary>
        /// Can this release be installed by this copy? The installed version only needs the setup package (with its
        /// SHA-256); the portable version needs the zip package (with its SHA-256).
        /// </summary>
        public static bool Installable(UpdateInfo i, bool installedMode) =>
            i != null && (UseSetup(i, installedMode) || (i.AssetUrl.Length > 0 && i.Sha256.Length == 64));

        public enum Fit { UpToDate, Ready, NeedsInstalledVersion, NoPackage }

        /// <summary>
        /// The one decision used by the automatic check, the manual check and the update window: is the release newer, and can
        /// this copy install it? A portable copy and a release with only a setup package: the switch to the installed version.
        /// </summary>
        public static Fit FitFor(UpdateInfo i, bool installedMode)
        {
            if (!IsNewer(i)) return Fit.UpToDate;
            if (Installable(i, installedMode)) return Fit.Ready;
            if (!installedMode && i.SetupUrl.Length > 0 && i.SetupSha256.Length == 64) return Fit.NeedsInstalledVersion;
            return Fit.NoPackage;
        }

        /// <summary>Checks once a day if automatic checking is on.</summary>
        public static bool DueForCheck =>
            App.Settings.AutoUpdate && (!App.Settings.LastUpdateCheck.HasValue || (DateTime.Now - App.Settings.LastUpdateCheck.Value).TotalHours >= 20);

        public static bool Skipped(UpdateInfo i) => i != null && App.Settings.SkipVersion == i.Version.ToString();

        internal static bool TrustedUrl(string url) =>
            Uri.TryCreate(url, UriKind.Absolute, out var u) && u.Scheme == "https" &&
            (u.Host == "github.com" || u.Host.EndsWith(".githubusercontent.com"));

        /// <summary>A downloaded (and extracted) package ready to be installed.</summary>
        public sealed class Prepared
        {
            public string Root;       // zip: the folder that contains NSFShield.exe
            public string SetupPath;  // setup package: the downloaded Setup.exe
            public string ExeSha256;  // hash of the file to start (verified again right before starting)
            public Version Version;   // the release version (the file's version information must match it)
            /// <summary>zip: every file of the package folder (relative path → SHA-256), from the verified extraction.</summary>
            public Dictionary<string, string> Manifest;
        }

        /// <summary>Where the extraction manifest of a package folder is written (next to it, never inside it).</summary>
        internal static string ManifestPath(string root) => Path.GetFullPath(root).TrimEnd('\\') + ".manifest";

        /// <summary>
        /// Every file of a folder (relative path → SHA-256); a link anywhere inside makes it invalid (null). With
        /// <paramref name="skipTop"/>, top-level entries it names are left out (the data folders of an app folder).
        /// </summary>
        internal static Dictionary<string, string> HashTree(string root, Func<string, bool> skipTop = null)
        {
            string full = Path.GetFullPath(root).TrimEnd('\\') + "\\";
            var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var e in Directory.GetFileSystemEntries(full))
            {
                string name = Path.GetFileName(e);
                if (skipTop != null && skipTop(name)) continue;
                if (PathSafety.UnsafeInTree(e) != null) return null;
                if (File.Exists(e)) d[name] = Integrity.Sha256File(e);
                else foreach (var f in Directory.GetFiles(e, "*", SearchOption.AllDirectories)) d[f.Substring(full.Length)] = Integrity.Sha256File(f);
            }
            if (PathSafety.Reparse(full) != PathSafety.Kind.None) return null;
            return d;
        }

        /// <summary>Is the folder exactly the manifest (the same set of files, every hash equal)? <paramref name="why"/> names the first difference.</summary>
        internal static bool MatchesManifest(string root, IDictionary<string, string> manifest, out string why)
        {
            why = "";
            var now = HashTree(root);
            if (now == null) { why = "link inside the package folder"; return false; }
            foreach (var kv in manifest)
            {
                if (!now.TryGetValue(kv.Key, out var h)) { why = "missing " + kv.Key; return false; }
                if (!string.Equals(h, kv.Value, StringComparison.OrdinalIgnoreCase)) { why = "changed " + kv.Key; return false; }
            }
            var extra = now.Keys.FirstOrDefault(k => !manifest.ContainsKey(k));
            if (extra != null) { why = "unexpected " + extra; return false; }
            return true;
        }

        internal static void WriteManifest(string path, IDictionary<string, string> manifest) =>
            File.WriteAllLines(path, manifest.OrderBy(k => k.Key, StringComparer.Ordinal).Select(k => k.Value + "  " + k.Key), new UTF8Encoding(false));

        /// <summary>Reads a manifest written by <see cref="WriteManifest"/> (null if missing; an invalid line makes it invalid).</summary>
        internal static Dictionary<string, string> ReadManifest(string path, out bool invalid)
        {
            invalid = false;
            if (!File.Exists(path)) return null;
            var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var fi = new FileInfo(path);
            if (fi.Length > 4 * 1024 * 1024) { invalid = true; return null; }
            foreach (var line in File.ReadAllLines(path, Encoding.UTF8))
            {
                var m = Regex.Match(line, @"^([0-9a-f]{64})  (.+)$");
                string rel = m.Success ? m.Groups[2].Value : null;
                if (rel == null || Path.IsPathRooted(rel) || rel.Contains("..") || rel.IndexOfAny(Path.GetInvalidPathChars()) >= 0 || d.ContainsKey(rel)) { invalid = true; return null; }
                d[rel] = m.Groups[1].Value;
            }
            return d;
        }

        /// <summary>
        /// Downloads the package, verifies its SHA-256 hash and extracts it from the SAME file handle (writing denied), so
        /// the package cannot be changed between verification and extraction. The address after redirects must be GitHub too.
        /// </summary>
        public static Prepared DownloadAndExtract(UpdateInfo i, Action<long, long> progress, CancellationToken ct)
        {
            if (!TrustedUrl(i.AssetUrl)) throw new InvalidOperationException(Loc.T("update.notGithub", i.AssetUrl));
            if (i.Sha256.Length != 64) throw new InvalidOperationException(Loc.T("update.noHash"));
            Directory.CreateDirectory(UpdateRoot);
            string zipPath = Path.Combine(UpdateRoot, Path.GetFileName(i.AssetName));
            string dir = Path.Combine(UpdateRoot, "v" + i.Version);
            if (Directory.Exists(dir)) Directory.Delete(dir, true);
            Dictionary<string, string> hashes;
            try
            {
                using (var fs = new FileStream(zipPath, FileMode.Create, FileAccess.ReadWrite, FileShare.None))
                {
                    DownloadTo(i.AssetUrl, fs, i.Sha256, i.Size, progress, ct);
                    App.Log("Update downloaded and verified: " + i.AssetName + " (SHA-256 " + i.Sha256.Substring(0, 16) + "…)", LogLevel.Success);
                    fs.Flush();
                    fs.Position = 0;
                    using (var za = new ZipArchive(fs, ZipArchiveMode.Read, true))
                        hashes = ExtractSafe(za, dir);
                }
            }
            catch
            {
                try { File.Delete(zipPath); } catch (Exception ign) { App.Ignored("Temporary update file could not be deleted", ign); }
                try { if (Directory.Exists(dir)) Directory.Delete(dir, true); } catch (Exception ign) { App.Ignored("Temporary update folder could not be deleted", ign); }
                throw;
            }
            try { File.Delete(zipPath); } catch (Exception ign) { App.Ignored("Downloaded zip could not be deleted", ign); }

            string exe = Directory.GetFiles(dir, "NSFShield.exe", SearchOption.AllDirectories).OrderBy(f => f.Length).FirstOrDefault();
            if (exe == null) throw new InvalidDataException(Loc.T("update.noExe"));
            string root = Path.GetDirectoryName(exe);
            foreach (var req in new[] { @"bin\x86_64\goodbyedpi.exe", @"bin\x86_64\WinDivert.dll", @"bin\x86\goodbyedpi.exe", @"bin\zapret\winws.exe", @"bin\byedpi\ciadpi.exe" })
                if (!File.Exists(Path.Combine(root, req))) throw new InvalidDataException(Loc.T("update.incomplete", req));
            var fv = FileVersionInfo.GetVersionInfo(exe);
            if (!Version.TryParse(fv.FileVersion, out var exeVer) || Norm(exeVer) != i.Version)
                throw new InvalidDataException(Loc.T("update.versionMismatch", fv.FileVersion, i.Version));
            // the package folder as extracted (relative path → hash): checked again right before it is installed
            string rootFull = Path.GetFullPath(root).TrimEnd('\\') + "\\";
            var manifest = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var kv in hashes)
                if (kv.Key.StartsWith(rootFull, StringComparison.OrdinalIgnoreCase)) manifest[kv.Key.Substring(rootFull.Length)] = kv.Value;
            return new Prepared { Root = root, ExeSha256 = hashes[Path.GetFullPath(exe)], Version = i.Version, Manifest = manifest };
        }

        /// <summary>
        /// Downloads the address and computes SHA-256 while writing to the given stream; fails if the address after
        /// redirects is not GitHub or the hash does not match (the caller deletes the file).
        /// </summary>
        static void DownloadTo(string url, Stream dst, string expectedSha, long size, Action<long, long> progress, CancellationToken ct)
        {
            var r = Req(url, 30000);
            using (var resp = r.GetResponse())
            {
                if (!TrustedUrl(resp.ResponseUri?.AbsoluteUri))
                    throw new InvalidOperationException(Loc.T("update.redirectedOutside", resp.ResponseUri?.Host));
                using (var src = resp.GetResponseStream())
                using (var sha = SHA256.Create())
                {
                    long total = resp.ContentLength > 0 ? resp.ContentLength : size, got = 0;
                    var buf = new byte[81920];
                    int n;
                    while ((n = src.Read(buf, 0, buf.Length)) > 0)
                    {
                        ct.ThrowIfCancellationRequested();
                        dst.Write(buf, 0, n);
                        sha.TransformBlock(buf, 0, n, null, 0);
                        got += n;
                        progress?.Invoke(got, total);
                        if (got > 200L * 1024 * 1024) throw new InvalidOperationException(Loc.T("update.tooBig"));
                    }
                    sha.TransformFinalBlock(new byte[0], 0, 0);
                    string hash = Integrity.Hex(sha.Hash);
                    if (hash != expectedSha)
                        throw new InvalidDataException(Loc.T("update.hashMismatch", expectedSha.Substring(0, 12), hash.Substring(0, 12)));
                }
            }
            dst.Flush();
        }

        // ================================================================ installed version (Inno Setup)

        /// <summary>Application id of the setup package (same as AppId in installer\NSFShield.iss).</summary>
        public const string InnoAppId = "{1B0AAA19-BCF0-40C5-9E22-77192CC33415}";

        /// <summary>Installation folder in Inno Setup's uninstall entry (null if not installed).</summary>
        internal static string InnoInstallLocation()
        {
            try
            {
                using (var hk = Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry64))
                using (var k = hk.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + InnoAppId + "_is1"))
                    return k?.GetValue("InstallLocation") as string;
            }
            catch (Exception ex) { App.Ignored("Setup registry entry could not be read", ex); return null; }
        }

        /// <summary>Was the given folder installed with the setup package and is it protected?</summary>
        internal static bool IsInnoInstall(string dir, string installLocation, bool protectedDir)
        {
            if (string.IsNullOrEmpty(installLocation) || string.IsNullOrEmpty(dir) || !protectedDir) return false;
            try
            {
                return string.Equals(Path.GetFullPath(installLocation).TrimEnd('\\'), Path.GetFullPath(dir).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        /// <summary>Was this copy installed with the setup package? (Then it is also updated with the setup package.)</summary>
        public static bool InstalledMode => IsInnoInstall(App.BaseDir, InnoInstallLocation(), InstallGuard.IsProtected);

        /// <summary>Which update path to use for this release: Setup.exe in the installed version (if present), the zip otherwise.</summary>
        public static bool UseSetup(UpdateInfo i, bool installedMode) =>
            installedMode && i != null && i.SetupUrl.Length > 0 && i.SetupSha256.Length == 64;

        /// <summary>
        /// Downloads the setup package to data\update and verifies it (SHA-256, product name and version). In the
        /// installed version only administrators can write to this folder.
        /// </summary>
        public static Prepared DownloadSetup(UpdateInfo i, Action<long, long> progress, CancellationToken ct)
        {
            if (!TrustedUrl(i.SetupUrl)) throw new InvalidOperationException(Loc.T("update.setupNotGithub", i.SetupUrl));
            if (i.SetupSha256.Length != 64) throw new InvalidOperationException(Loc.T("update.setupNoHash"));
            Directory.CreateDirectory(UpdateRoot);
            string path = Path.Combine(UpdateRoot, Path.GetFileName(i.SetupName));
            try
            {
                using (var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None))
                    DownloadTo(i.SetupUrl, fs, i.SetupSha256, i.SetupSize, progress, ct);
                var fv = FileVersionInfo.GetVersionInfo(path);
                if ((fv.ProductName ?? "").Trim() != "NSF Shield" || !Version.TryParse((fv.FileVersion ?? "").Trim(), out var sv) || Norm(sv) != i.Version)
                    throw new InvalidDataException(Loc.T("update.setupInfoMismatch", ((fv.ProductName ?? "").Trim() + " " + (fv.FileVersion ?? "").Trim()).Trim()));
            }
            catch
            {
                try { File.Delete(path); } catch (Exception ex) { App.Ignored("Downloaded setup package could not be deleted", ex); }
                throw;
            }
            App.Log("Setup package downloaded and verified: " + i.SetupName + " (SHA-256 " + i.SetupSha256.Substring(0, 16) + "…)", LogLevel.Success);
            return new Prepared { SetupPath = path, ExeSha256 = i.SetupSha256, Version = i.Version };
        }

        /// <summary>
        /// What is checked before a downloaded file is started – honestly: the packages are not code-signed yet, so there is no
        /// publisher (Authenticode) check. The file must have the SHA-256 published with the GitHub release (checked from the
        /// same handle that keeps it closed for writing until it has started) and the expected version information
        /// (product "NSF Shield", the release version; a setup package also "NSF Shield Setup"). The version information
        /// alone proves nothing (anyone can write it); it only catches a wrong file next to a matching hash.
        /// </summary>
        internal static bool VerifyIdentity(string path, Version expected, bool setup, out string why)
        {
            why = "";
            var fv = FileVersionInfo.GetVersionInfo(path);
            string product = (fv.ProductName ?? "").Trim(), desc = (fv.FileDescription ?? "").Trim(), ver = (fv.FileVersion ?? "").Trim();
            bool okVer = Version.TryParse(ver, out var v) && (expected == null || Norm(v) == expected);
            if (product != "NSF Shield" || !okVer || (setup && desc != InstallerSwitch.SetupDescription))
            {
                why = (product + " · " + desc + " · " + ver).Trim(' ', '·');
                return false;
            }
            return true;
        }

        /// <summary>Starts the setup package as a silent upgrade; this app must exit afterwards.</summary>
        public static void StartSetup(Prepared prep)
        {
            using (var hold = new FileStream(prep.SetupPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (Integrity.Sha256(hold) != prep.ExeSha256)
                    throw new InvalidDataException(Loc.T("update.setupChanged"));
                if (!VerifyIdentity(prep.SetupPath, prep.Version, true, out string why))
                    throw new InvalidDataException(Loc.T("update.setupInfoMismatch", why));
                string log = Path.Combine(App.DataDir, "setup.log");
                // /NSFUPDATED and /NSFRESUME are read by the setup script: after the upgrade the app is reopened with the "updated" notice
                var psi = new ProcessStartInfo(prep.SetupPath,
                    "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /NOCANCEL /LOG=\"" + log + "\" /NSFUPDATED=" + App.Version +
                    " /NSFRESUME=" + (App.Engine != null && App.Engine.IsActive ? "1" : "0"))
                { UseShellExecute = false, WorkingDirectory = UpdateRoot };
                Process.Start(psi);
            }
            App.Log("Setup package started for a silent upgrade; the app will reopen.", LogLevel.Info);
        }

        /// <summary>Extracts zip entries without leaving the folder; returns the SHA-256 hash of every file.</summary>
        static Dictionary<string, string> ExtractSafe(ZipArchive za, string dir)
        {
            string full = Path.GetFullPath(dir).TrimEnd('\\') + "\\";
            Directory.CreateDirectory(full);
            var hashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            long totalBytes = 0;
            foreach (var e in za.Entries)
            {
                string name = e.FullName.Replace('/', '\\');
                string target = Path.GetFullPath(Path.Combine(full, name));
                if (!target.StartsWith(full, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException(Loc.T("update.zipSlip", e.FullName));
                if (name.EndsWith("\\")) { Directory.CreateDirectory(target); continue; }
                Directory.CreateDirectory(Path.GetDirectoryName(target));
                using (var es = e.Open())
                using (var outF = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                using (var sha = SHA256.Create())
                using (var cs = new CryptoStream(outF, sha, CryptoStreamMode.Write))
                {
                    // the bytes really written are counted (the size in the entry header is not trusted)
                    totalBytes = CopyLimited(es, cs, totalBytes, MaxExtractBytes);
                    cs.FlushFinalBlock();
                    hashes[target] = Integrity.Hex(sha.Hash);
                }
            }
            return hashes;
        }

        internal const long MaxExtractBytes = 300L * 1024 * 1024;

        /// <summary>Copies a stream and adds the copied bytes to <paramref name="total"/>; past <paramref name="limit"/> it stops with an error.</summary>
        internal static long CopyLimited(Stream from, Stream to, long total, long limit)
        {
            var buf = new byte[81920];
            int n;
            while ((n = from.Read(buf, 0, buf.Length)) > 0)
            {
                total += n;
                if (total > limit) throw new InvalidDataException(Loc.T("update.extractTooBig"));
                to.Write(buf, 0, n);
            }
            return total;
        }

        /// <summary>Starts the new version's exe to install it; this app must exit afterwards.</summary>
        public static void StartApply(Prepared prep)
        {
            string dst = App.BaseDir.TrimEnd('\\');
            string exe = Path.Combine(prep.Root, "NSFShield.exe");
            // the whole package folder must still be exactly what was extracted and verified
            if (prep.Manifest == null) throw new InvalidDataException(Loc.T("update.packageChanged", "-"));
            if (!MatchesManifest(prep.Root, prep.Manifest, out string diff)) throw new InvalidDataException(Loc.T("update.packageChanged", diff));
            WriteManifest(ManifestPath(prep.Root), prep.Manifest);
            // the exe is kept open with writing denied: it cannot be changed between hash verification and start
            using (var hold = new FileStream(exe, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (Integrity.Sha256(hold) != prep.ExeSha256)
                    throw new InvalidDataException(Loc.T("update.exeChanged"));
                if (!VerifyIdentity(exe, prep.Version, false, out string why))
                    throw new InvalidDataException(Loc.T("update.versionMismatch", why, prep.Version));
                var psi = new ProcessStartInfo(exe,
                    "--apply-update \"" + prep.Root.TrimEnd('\\') + "\" \"" + dst + "\" " + Process.GetCurrentProcess().Id + " " + App.Version + " " + (App.Engine.IsActive ? "1" : "0"))
                { UseShellExecute = false, WorkingDirectory = prep.Root };
                Process.Start(psi);
            }
            App.Log("Update installation started; the app will reopen.", LogLevel.Info);
        }

        /// <summary>
        /// Validates the --apply-update paths: the target must be a NSF Shield folder; the source must be in the target's
        /// update folder (data\update) and the updater
        /// must run from the source folder.
        /// </summary>
        internal static bool ValidateApplyArgs(string src, string dst, string selfExe, out string error)
        {
            error = "";
            try
            {
                string N(string p) => Path.GetFullPath(p).TrimEnd('\\');
                src = N(src);
                dst = N(dst);
                string dstExe = Path.Combine(dst, "NSFShield.exe");
                if (!File.Exists(dstExe)) { error = "NSF Shield not found in the target folder: " + dst; return false; }
                if (FileVersionInfo.GetVersionInfo(dstExe).ProductName != "NSF Shield") { error = "The program in the target is not NSF Shield."; return false; }
                var roots = new[] { N(Path.Combine(dst, App.DataDirName, UpdateDirName)) + "\\" };
                if (!roots.Any(r => (src + "\\").StartsWith(r, StringComparison.OrdinalIgnoreCase) && src.Length + 1 > r.Length))
                { error = "The source folder is not inside an update folder: " + src; return false; }
                if (!N(selfExe).StartsWith(src + "\\", StringComparison.OrdinalIgnoreCase))
                { error = "The updater is not running from the source folder."; return false; }
                return true;
            }
            catch (Exception ex) { error = ex.Message; return false; }
        }

        // ================================================================ installation (runs inside the new exe)

        /// <summary>The top-level entry of an app folder that an update never copies or backs up (the user's data).</summary>
        internal static bool IsDataEntry(string name) => name.Equals(App.DataDirName, StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// Copies a folder. Every file is read through one handle (writing denied), its hash checked against
        /// <paramref name="expected"/> (relative path → SHA-256; a file that is not listed is refused), written to a new
        /// temporary file of the target folder and moved into place (an existing hard link is never written through), then the
        /// target is read back and compared with the expected hash. With <paramref name="added"/> every file and folder that did
        /// not exist in the target before is recorded (a rollback removes them). Links are never followed.
        /// </summary>
        static void CopyDir(string src, string dst, Func<string, bool> skipTop, Action<string> log, List<string> added, IDictionary<string, string> expected, string rel = "")
        {
            if (PathSafety.Reparse(src) != PathSafety.Kind.None || PathSafety.Reparse(dst) != PathSafety.Kind.None)
                throw new IOException("link in the update path: " + src + " → " + dst);
            if (!Directory.Exists(dst)) { Directory.CreateDirectory(dst); added?.Add(dst + "\\"); }
            foreach (var d in Directory.GetDirectories(src))
            {
                string name = Path.GetFileName(d);
                if (skipTop != null && skipTop(name)) continue;
                CopyDir(d, Path.Combine(dst, name), null, log, added, expected, rel.Length == 0 ? name : rel + "\\" + name);
            }
            foreach (var f in Directory.GetFiles(src))
            {
                string name = Path.GetFileName(f);
                if (skipTop != null && skipTop(name)) continue;
                string key = rel.Length == 0 ? name : rel + "\\" + name;
                if (expected == null || !expected.TryGetValue(key, out string want)) throw new IOException("not in the verified file list: " + key);
                string target = Path.Combine(dst, name);
                if (PathSafety.Reparse(f) != PathSafety.Kind.None || PathSafety.Reparse(target) != PathSafety.Kind.None)
                    throw new IOException("link in the update path: " + name);
                bool existed = File.Exists(target);
                string tmp = target + ".dkupd-" + Guid.NewGuid().ToString("N").Substring(0, 8);
                using (var from = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    if (!string.Equals(Integrity.Sha256(from), want, StringComparison.OrdinalIgnoreCase)) throw new IOException("changed after it was verified: " + key);
                    from.Position = 0;
                    using (var to = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { from.CopyTo(to); to.Flush(true); }
                }
                try
                {
                    if (!string.Equals(Integrity.Sha256File(tmp), want, StringComparison.OrdinalIgnoreCase)) throw new IOException("copy could not be verified: " + key);
                    for (int attempt = 1; ; attempt++)
                    {
                        try
                        {
                            if (File.Exists(target)) File.Replace(tmp, target, null);
                            else File.Move(tmp, target);
                            break;
                        }
                        catch (IOException) when (attempt < 10) { Thread.Sleep(500); }
                        catch (UnauthorizedAccessException) when (attempt < 10) { Thread.Sleep(500); }
                    }
                }
                finally { try { if (File.Exists(tmp)) File.Delete(tmp); } catch { } }
                if (!existed) added?.Add(target);
                if (!string.Equals(Integrity.Sha256File(target), want, StringComparison.OrdinalIgnoreCase)) throw new IOException("copy could not be verified: " + key);
            }
        }

        /// <summary>
        /// Rollback after a failed update: the files the update added are removed, the backup is copied back (each file checked
        /// against the hash recorded when it was backed up) and the managed files of the folder (everything but the data
        /// folders) must then be exactly the recorded previous set. A folder the update added that still holds other files is
        /// kept (nothing that was not the update's is deleted). False if anything of that failed or could not be verified: the
        /// app must not be started then.
        /// </summary>
        internal static bool RestoreBackup(string bak, string dst, List<string> added, Action<string> log, IDictionary<string, string> before = null)
        {
            bool ok = true;
            foreach (var f in added.Where(a => !a.EndsWith("\\")))
                try { if (File.Exists(f)) File.Delete(f); }
                catch (Exception ex) { ok = false; log("Added file could not be removed: " + Path.GetFileName(f) + " (" + ex.Message + ")"); }
            foreach (var d in added.Where(a => a.EndsWith("\\")).OrderByDescending(a => a.Length))
            {
                string dd = d.TrimEnd('\\');
                try
                {
                    if (!Directory.Exists(dd)) continue;
                    if (Directory.EnumerateFileSystemEntries(dd).Any()) { ok = false; log("Added folder still holds other files; it is kept: " + d); continue; }
                    Directory.Delete(dd);
                }
                catch (Exception ex) { ok = false; log("Added folder could not be removed: " + d + " (" + ex.Message + ")"); }
            }
            var expected = before ?? HashTree(bak);
            if (expected == null) { log("The backup could not be read (link inside)."); return false; }
            try { CopyDir(bak, dst, null, log, null, expected); }
            catch (Exception ex) { ok = false; log("Backup could not be copied back: " + ex.Message); }
            // the managed file set is verified as a whole: the same files with the same hashes as before the update
            var now = HashTree(dst, IsDataEntry);
            if (now == null) { log("The app folder could not be verified after the rollback (link inside)."); return false; }
            var missing = expected.Keys.FirstOrDefault(k => !now.TryGetValue(k, out var h) || !string.Equals(h, expected[k], StringComparison.OrdinalIgnoreCase));
            var extra = now.Keys.FirstOrDefault(k => !expected.ContainsKey(k));
            if (missing != null || extra != null)
            {
                ok = false;
                log("The previous file set could not be verified: " + (missing != null ? "differs " + missing : "") + (extra != null ? " extra " + extra + " (kept)" : ""));
            }
            return ok;
        }

        /// <summary>
        /// --apply-update source target pid oldVersion: waits for the old app to exit, stops the service,
        /// backs up the target, copies the files (except the data folder) and starts the new version.
        /// </summary>
        public static int Apply(string src, string dst, int pid, string oldVer, bool resume)
        {
            string self = Process.GetCurrentProcess().MainModule.FileName;
            if (!ValidateApplyArgs(src, dst, self, out string err))
            {
                // rejected: the target is not touched at all (no data folder, no log, nothing started from it). Only the
                // installed copy at the setup package's protected location may be reopened, after a fresh check.
                try
                {
                    string inst = InnoInstallLocation();
                    if (inst != null && PathSafety.Same(inst, dst) && InstallGuard.Check(inst, out _))
                    {
                        string old = Path.Combine(Path.GetFullPath(inst), "NSFShield.exe");
                        if (File.Exists(old) && VerifyIdentity(old, null, false, out _))
                            Process.Start(new ProcessStartInfo(old, "--tray --update-failed" + (resume ? " --resume" : "")) { UseShellExecute = false, WorkingDirectory = Path.GetDirectoryName(old) });
                    }
                }
                catch { /* rejected anyway; nothing else is done */ }
                return 2;
            }
            return Apply(src, dst, pid, oldVer, resume, true);
        }

        /// <param name="live">false: file operations only (for tests) – does not touch the service and does not start the app.</param>
        internal static int Apply(string src, string dst, int pid, string oldVer, bool resume, bool live)
        {
            string dataDir = Path.Combine(dst, App.DataDirName);
            string log = Path.Combine(dataDir, "update.log");
            // until the 2.x data folder has been migrated, log lines are kept in memory (writing them would create "data" too early)
            var pending = new StringBuilder();
            bool logReady = false;
            void L(string m)
            {
                string line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + m + Environment.NewLine;
                if (!logReady) { pending.Append(line); return; }
                try { Directory.CreateDirectory(dataDir); File.AppendAllText(log, line, Encoding.UTF8); }
                catch { /* the installation continues even if the update log cannot be written */ }
            }
            void FlushLog()
            {
                logReady = true;
                if (pending.Length == 0) return;
                try { Directory.CreateDirectory(dataDir); File.AppendAllText(log, pending.ToString(), Encoding.UTF8); }
                catch { /* see above */ }
                pending.Clear();
            }
            string bak = Path.Combine(dataDir, "previous-version");
            string dstExe = Path.Combine(dst, "NSFShield.exe");
            bool backedUp = false;
            var added = new List<string>();
            Dictionary<string, string> before = null;
            try
            {
                L("Update started: " + oldVer + " → " + Current + "  (" + src + " → " + dst + ")");
                if (string.Equals(Path.GetFullPath(src).TrimEnd('\\'), Path.GetFullPath(dst).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Source and target are the same folder.");
                // the package folder must still be exactly what the old app extracted and verified (its manifest, always required)
                var manifest = ReadManifest(ManifestPath(src), out bool badManifest);
                if (badManifest) throw new InvalidDataException("The package manifest is not valid.");
                if (manifest == null) throw new InvalidDataException("No trusted package manifest.");
                if (!MatchesManifest(src, manifest, out string diff)) throw new InvalidDataException("The package folder changed after it was verified: " + diff);
                IDictionary<string, string> expected = manifest;

                // 1) wait for the old app to exit; it is closed only when that process id still runs this installation's exe
                //    (read through the handle that closes it): a process id that now belongs to another program is never hit
                try
                {
                    bool exited;
                    using (var p = Process.GetProcessById(pid)) exited = p.WaitForExit(20000);
                    if (!exited)
                    {
                        if (ProcReader.TerminateIf(pid, path => ProcReader.IsFile(path, dstExe), out string why, 5000))
                        {
                            L("The old app did not exit; it was closed.");
                            CrashMarker.Clear(dataDir);   // closed on purpose: must not count as an "unexpected shutdown"
                        }
                        else L("The old app did not exit and was not closed: " + why);
                    }
                }
                catch (ArgumentException) { /* already exited */ }

                FlushLog();

                // 3) stop the service of this installation and close the engines of this folder (the same owner rule as the setup
                //    package and the uninstaller: the exe's physical path is in this folder, read right before; anything else stays)
                if (live)
                {
                    var svc = Engine.Scm.Query(Engine.ServiceName);
                    string svcExe = ServiceOwnership.ExeOf(svc.ImagePath);
                    if (svc.Exists && !svc.Unknown && svcExe != null && ProcReader.IsUnder(svcExe, dst) && svc.Running)
                    {
                        if (Engine.Scm.Stop(Engine.ServiceName, TimeSpan.FromSeconds(15))) L("Background service stopped.");
                        else L("Background service did not stop in time.");
                    }
                    else if (svc.Exists && svc.Running) L("The NSFShield service does not run from this folder (or cannot be read); it was left running.");
                    foreach (var pe in ProcReader.ByNames(Engines.AllProcessNames.Concat(new[] { Path.GetFileNameWithoutExtension(ProxyRecovery.HelperFile) })))
                    {
                        if (pe.Path == null || !ProcReader.IsUnder(pe.Path, dst)) continue;
                        if (ProcReader.TerminateIf(pe.Pid, path => ProcReader.IsUnder(path, dst), out string why)) L(pe.Name + " closed (PID " + pe.Pid + ").");
                        else L(pe.Name + " was not closed: " + why);
                    }
                }
                Thread.Sleep(800);

                // 4) backup (without data); the managed files of the previous version are recorded with their hashes
                if (File.Exists(dstExe))
                {
                    if (Directory.Exists(bak)) Directory.Delete(bak, true);
                    before = HashTree(dst, IsDataEntry) ?? throw new IOException("link in the app folder");
                    CopyDir(dst, bak, IsDataEntry, L, null, before);
                    backedUp = true;
                    L("Previous version backed up: " + bak);
                }

                // 5) copy the new files (without data); every copy is checked against the expected (manifest) hash, new files
                //    and folders are recorded for a rollback
                CopyDir(src, dst, IsDataEntry, L, added, expected);
                L("Files copied.");

                // 6) start the new version
                if (live) Process.Start(new ProcessStartInfo(dstExe, "--tray --updated " + oldVer + (resume ? " --resume" : "")) { UseShellExecute = false, WorkingDirectory = dst });
                L("New version started. Update finished.");
                return 0;
            }
            catch (Exception ex)
            {
                FlushLog();
                L("ERROR: " + ex.Message);
                bool intact = true;
                if (backedUp)
                {
                    intact = RestoreBackup(bak, dst, added, L, before);
                    L(intact ? "Rolled back to the previous version (restored files verified)." : "RECOVERY ERROR: the rollback could not be completed or verified.");
                }
                if (!intact)
                {
                    // a half-restored folder is never started: the previous files stay in data\previous-version
                    L("The app was not started. Copy the files from " + bak + " back by hand or reinstall NSF Shield.");
                    return 3;
                }
                try { if (live && File.Exists(dstExe)) Process.Start(new ProcessStartInfo(dstExe, "--tray --update-failed" + (resume ? " --resume" : "")) { UseShellExecute = false, WorkingDirectory = dst }); }
                catch (Exception ign) { L("The old version could not be reopened: " + ign.Message); }
                return 1;
            }
        }

        /// <summary>Removes the download folder after a successful update.</summary>
        public static void Cleanup()
        {
            try { if (Directory.Exists(UpdateRoot)) Directory.Delete(UpdateRoot, true); } catch (Exception ign) { App.Ignored("Update folder could not be deleted", ign); }
        }
    }
}
