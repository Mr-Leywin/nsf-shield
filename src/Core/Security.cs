using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

namespace NSFShield
{
    /// <summary>
    /// Is the installation folder protected? (Can only Administrators, SYSTEM and TrustedInstaller write to it?)
    /// The background service running as SYSTEM and the elevated startup task can only be used in a protected installation
    /// (e.g. installed to Program Files with the setup package). The portable (zip) version runs in app mode.
    /// This class only reads; it never changes any permission.
    /// </summary>
    public static class InstallGuard
    {
        static readonly SecurityIdentifier[] Trusted =
        {
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            new SecurityIdentifier("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"),   // NT SERVICE\TrustedInstaller (the same on every Windows)
        };

        // The folder and the files in it: write, append, delete, change attributes and permissions
        // (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_DELETE_CHILD | FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL | GENERIC_WRITE)
        const int StrictMask = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000;
        // Parent folders: renaming/deleting and changing permissions are forbidden; creating a new folder is allowed (e.g. C:\)
        const int AncestorMask = 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000;

        public static string NeedInstall => Loc.T("guard.installedOnly");

        static readonly object Gate = new object();
        static bool? cached;
        static string cachedReason = "";

        /// <summary>Is the app's own folder protected (cached).</summary>
        public static bool IsProtected => Evaluate(false);
        public static bool IsPortable => !IsProtected;

        /// <summary>The reason if it is not protected (shown to the user).</summary>
        public static string Reason { get { Evaluate(false); return cachedReason; } }

        public static bool Evaluate(bool refresh)
        {
            lock (Gate)
            {
                if (cached == null || refresh)
                {
                    cached = Check(App.BaseDir, out cachedReason);
                    App.Log("Installation folder: " + (cached.Value ? "protected (installed version)" : "portable – " + cachedReason), LogLevel.Debug);
                }
                return cached.Value;
            }
        }

        /// <summary>
        /// A fresh check (never the cached result) right before a privileged operation (service, elevated task, installer
        /// switch); the cached state is updated with it.
        /// </summary>
        public static bool CheckFresh(out string reason)
        {
            bool ok = Check(App.BaseDir, out reason);
            lock (Gate) { cached = ok; cachedReason = reason; }
            return ok;
        }

        /// <summary>
        /// The folder, its subfolders, the app/GoodbyeDPI files, the data folder and every parent folder are checked. A junction,
        /// symbolic link or mount point anywhere on the way (or a folder that does not resolve to itself) is never protected:
        /// the owner and ACL checks below must apply to the physical folders.
        /// </summary>
        public static bool Check(string baseDir, out string reason)
        {
            reason = "";
            try
            {
                string b = Path.GetFullPath(baseDir).TrimEnd('\\');
                if (b.StartsWith(@"\\")) { reason = Loc.T("guard.networkFolder"); return false; }
                string link = PathSafety.UnsafeInChain(b);
                if (link != null) { reason = Loc.T("guard.reparse", link); return false; }
                if (!Directory.Exists(b) || !PathSafety.ResolvesToItself(b)) { reason = Loc.T("guard.finalPath", b); return false; }
                if (!CheckObject(b, true, StrictMask, out reason)) return false;
                string exe = Path.Combine(b, "NSFShield.exe");
                if (File.Exists(exe) && PathSafety.Reparse(exe) != PathSafety.Kind.None) { reason = Loc.T("guard.reparse", exe); return false; }
                if (File.Exists(exe) && !CheckObject(exe, false, StrictMask, out reason)) return false;
                foreach (var sub in new[] { "bin", @"bin\x86", @"bin\x86_64", @"bin\zapret", @"bin\zapret\payloads", @"bin\byedpi",
                                            App.DataDirName, App.DataDirName + @"\lists" })
                {
                    string d = Path.Combine(b, sub);
                    if (PathSafety.Reparse(d) != PathSafety.Kind.None) { reason = Loc.T("guard.reparse", d); return false; }
                    if (!Directory.Exists(d)) continue;
                    if (!CheckObject(d, true, StrictMask, out reason)) return false;
                    if (sub == "bin") continue;
                    foreach (var f in Directory.GetFiles(d))
                    {
                        if (PathSafety.Reparse(f) != PathSafety.Kind.None) { reason = Loc.T("guard.reparse", f); return false; }
                        if (!CheckObject(f, false, StrictMask, out reason)) return false;
                    }
                }
                for (var p = Directory.GetParent(b); p != null; p = p.Parent)
                    if (!CheckObject(p.FullName, true, AncestorMask, out reason)) return false;
                return true;
            }
            catch (Exception ex)
            {
                reason = Loc.T("guard.aclUnreadable") + " " + ex.Message;
                return false;
            }
        }

        /// <summary>Results of the setup package's folder check (exit codes of NSFShield.exe --check-install-dir).</summary>
        public const int SetupProtected = 0, SetupAbsent = 1, SetupUnsafe = 2, SetupUnreadable = 3;

        /// <summary>
        /// The setup package's check of its target folder, run by the NEW program from the setup's own temporary folder (never
        /// by a program in the target): Protected – the folder exists and passes every rule of <see cref="Check"/> (physical
        /// path, no link, owner and write permissions of the folder, its program, the used subfolders and every parent);
        /// Absent – it does not exist yet and its nearest existing parent is safe (a first installation); Unsafe – a link, a
        /// foreign owner, a write permission of other accounts or a network path; Unreadable – an existing path that cannot be
        /// read (access denied is never taken for "not there").
        /// </summary>
        public static int SetupCheck(string dir, out string reason)
        {
            reason = "";
            try
            {
                string b = Path.GetFullPath(dir).TrimEnd('\\');
                if (b.StartsWith(@"\\")) { reason = "network path"; return SetupUnsafe; }
                FileAttributes attrs;
                try { attrs = File.GetAttributes(b); }
                catch (FileNotFoundException) { attrs = (FileAttributes)(-1); }
                catch (DirectoryNotFoundException) { attrs = (FileAttributes)(-1); }
                catch (UnauthorizedAccessException ex) { reason = "access denied: " + ex.Message; return SetupUnreadable; }
                if ((int)attrs == -1)
                {
                    // not there yet: the nearest existing parent and everything above it must be safe
                    var p = Directory.GetParent(b);
                    while (p != null && !p.Exists) p = p.Parent;
                    if (p == null) { reason = "no existing parent"; return SetupUnsafe; }
                    string link = PathSafety.UnsafeInChain(p.FullName);
                    if (link != null) { reason = "link: " + link; return SetupUnsafe; }
                    for (var a = p; a != null; a = a.Parent)
                        if (!CheckObject(a.FullName, true, AncestorMask, out reason)) return SetupUnsafe;
                    return SetupAbsent;
                }
                if ((attrs & FileAttributes.Directory) == 0) { reason = "not a folder"; return SetupUnsafe; }
                if ((attrs & FileAttributes.ReparsePoint) != 0) { reason = "link: " + b; return SetupUnsafe; }
                if (Check(b, out reason)) return SetupProtected;
                return reason.StartsWith(Loc.T("guard.aclUnreadable"), StringComparison.Ordinal) ? SetupUnreadable : SetupUnsafe;
            }
            catch (UnauthorizedAccessException ex) { reason = "access denied: " + ex.Message; return SetupUnreadable; }
            catch (Exception ex) { reason = ex.GetType().Name + ": " + ex.Message; return SetupUnreadable; }
        }

        /// <summary>--check-install-dir &lt;dir&gt; [report]: the exit code of <see cref="SetupCheck"/>; the reason goes to the report file.</summary>
        public static int SetupCheckCli(string[] args, int i)
        {
            if (args.Length <= i + 1) return SetupUnsafe;
            try { Loc.Init("en"); } catch { }   // the reasons go to the setup log in English (the embedded language file)
            int r = SetupCheck(args[i + 1], out string reason);
            if (args.Length > i + 2)
                try { File.WriteAllText(args[i + 2], r + " " + reason, new UTF8Encoding(false)); } catch { }
            return r;
        }

        static bool CheckObject(string path, bool dir, int mask, out string reason)
        {
            reason = "";
            const AccessControlSections s = AccessControlSections.Access | AccessControlSections.Owner;
            FileSystemSecurity sec = dir ? (FileSystemSecurity)Directory.GetAccessControl(path, s) : File.GetAccessControl(path, s);
            var owner = sec.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            if (owner == null || !Trusted.Contains(owner))
            {
                reason = Loc.T("guard.owner", path, Name(owner));
                return false;
            }
            foreach (FileSystemAccessRule r in sec.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (r.AccessControlType != AccessControlType.Allow) continue;
                if ((r.PropagationFlags & PropagationFlags.InheritOnly) != 0) continue;   // only applies to new child items
                var sid = r.IdentityReference as SecurityIdentifier;
                if (sid != null && Trusted.Contains(sid)) continue;
                if (((int)r.FileSystemRights & mask) != 0)
                {
                    reason = Name(sid) + " " + Loc.T("guard.canModify") + " " + path;
                    return false;
                }
            }
            return true;
        }

        /// <summary>Account name: only general groups are written by name; personal account names are hidden so they do not end up in the log/support package.</summary>
        static string Name(SecurityIdentifier sid)
        {
            if (sid == null) return "?";
            foreach (var t in new[] { WellKnownSidType.BuiltinUsersSid, WellKnownSidType.AuthenticatedUserSid, WellKnownSidType.WorldSid,
                                      WellKnownSidType.InteractiveSid, WellKnownSidType.CreatorOwnerSid, WellKnownSidType.BuiltinGuestsSid,
                                      WellKnownSidType.LocalServiceSid, WellKnownSidType.NetworkServiceSid })
                if (sid.IsWellKnown(t))
                {
                    try { return sid.Translate(typeof(NTAccount)).Value; } catch { return sid.Value; }
                }
            return Loc.T("guard.userAccount");
        }
    }

    /// <summary>
    /// Verifies that the engine files are identical to the official releases (SHA-256, embedded in the program): GoodbyeDPI
    /// 0.2.3rc3 + WinDivert 2.2.0, zapret v72.13 (winws, Cygwin DLL, WinDivert 2.2.2, fake payloads) and ByeDPI 0.17.3 (ciadpi).
    /// The files are kept open with writing denied so they cannot be changed between verification and start.
    /// </summary>
    public static class Integrity
    {
        /// <summary>
        /// Keys are relative to the bin folder. Same as third_party\goodbyedpi\README.md (ValdikSS's goodbyedpi-0.2.3rc3-2.zip),
        /// third_party\zapret\README.md (bol-van's zapret-v72.13.zip) and third_party\byedpi\README.md (hufrea's byedpi-17.3-x86_64-w64.zip).
        /// </summary>
        public static readonly Dictionary<string, string> Known = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [@"x86_64\goodbyedpi.exe"] = "8d412b094bb9c137ff25ba9a794d1122ecc84bb776debff6c249723a13cc31cd",
            [@"x86_64\WinDivert.dll"] = "6110bfa44667405179c3e15e12af1b62037e447ed59b054b19042032995e6c7e",
            [@"x86_64\WinDivert64.sys"] = "e69b5ba3f0cd6cfb2983e442636e7f0b342b61b15264b0328317d4559c82cf50",
            [@"x86\goodbyedpi.exe"] = "66e202c9fce9e769e2bc791b7fd6f56f21eab59f607f4ed0724e0c68c430dd1f",
            [@"x86\WinDivert.dll"] = "625ffdd95bfabff32d0e8a95beabcd303c01c8bba73b90402d4e84d6e15dd8e5",
            [@"x86\WinDivert32.sys"] = "29ca5ceb59c9c6993a349e82b1fd46078e6f8a302764153ab84fa22e382fcdca",
            [@"x86\WinDivert64.sys"] = "e69b5ba3f0cd6cfb2983e442636e7f0b342b61b15264b0328317d4559c82cf50",
            // zapret v72.13 (binaries/windows-x86_64 and files/fake)
            [@"zapret\winws.exe"] = "a14bff1df6234ea555d2e0c61b589f0707c0b12d6c9b7eeccda76012154996e8",
            [@"zapret\cygwin1.dll"] = "103104a52e5293ce418944725df19e2bf81ad9269b9a120d71d39028e821499b",
            [@"zapret\WinDivert.dll"] = "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2",
            [@"zapret\WinDivert64.sys"] = "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2",
            [@"zapret\payloads\discord-ip-discovery-with-port.bin"] = "073e84935196ec6a9701e6ad0df21de2b5fbfb7e3fd3ce6c5d9bba8e8654eb14",
            [@"zapret\payloads\discord-ip-discovery-without-port.bin"] = "3f63c3a0cc63b90a6a8c50ffc61a32cc7d1f1b60457a96b90719256744df0e96",
            [@"zapret\payloads\dtls_clienthello_w3_org.bin"] = "5bacd8cb6bd451f2374e55bc066b632e3c88fb852e3a44f19e6246c04d127be5",
            [@"zapret\payloads\http_iana_org.bin"] = "3e4fb49b1323ddf2f8e691b1cbe804207b4e849711d76f79ebf2b54247a9285e",
            [@"zapret\payloads\quic_initial_facebook_com.bin"] = "d6504305e15e6f63930d24ced9045001e345d3c1aeb56b1b4c329d51c7dea274",
            [@"zapret\payloads\quic_initial_www_google_com.bin"] = "f4589c57749f956bb30538197a521d7005f8b0a8723b4707e72405e51ddac50a",
            [@"zapret\payloads\stun.bin"] = "9cd5469309780ca56c0bd97266524a48c7ee529d02c3179cfecb20b260a59641",
            [@"zapret\payloads\tls_clienthello_iana_org.bin"] = "9db8772636bb332f1970e8767bc7d628bfa640714bd0b7e699fbe92d559e666e",
            [@"zapret\payloads\tls_clienthello_www_google_com.bin"] = "936c2bee4cfb80aa3c426b2dcbcc834b3fbcd1adb17172959dc569c73a14275c",
            [@"zapret\payloads\zero_256.bin"] = "5341e6b2646979a70e57653007a1f310169421ec9bdd9f1a5648f75ade005af1",
            [@"zapret\payloads\zero_512.bin"] = "076a27c79e5ace2a3d47f9dd2e83e4ff6ea8872b3c2218f66c92b89b55f36560",
            // ByeDPI 0.17.3 (byedpi-17.3-x86_64-w64.zip)
            [@"byedpi\ciadpi.exe"] = "eb53ceeeb981cc6735ac24bb1e51e725280b86630e80fdf19ddc4ee4a5b54ef4",
            // NSF Shield's own sign-in proxy recovery helper of this build (built first by build.ps1, its hash generated)
            [ProxyRecovery.HelperFile] = BuildInfo.RecoveryHelperSha256,
        };

        public static string Hex(byte[] b) => BitConverter.ToString(b).Replace("-", "").ToLowerInvariant();

        public static string Sha256(Stream s)
        {
            s.Position = 0;
            using (var h = SHA256.Create()) return Hex(h.ComputeHash(s));
        }

        public static string Sha256File(string path)
        {
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)) return Sha256(fs);
        }

        public sealed class Hold : IDisposable
        {
            internal readonly List<FileStream> Streams = new List<FileStream>();
            public void Dispose() { foreach (var s in Streams) try { s.Dispose(); } catch { } Streams.Clear(); }
        }

        /// <summary>Verifies the GoodbyeDPI files in a folder (their embedded hashes are those of bin\&lt;arch&gt;).</summary>
        public static Hold VerifyAndLock(string binDir, string arch, IEnumerable<string> files, out string error) =>
            VerifyAndLock(files.Select(f => (arch + "\\" + f, Path.Combine(binDir, f))), out error);

        /// <summary>Verifies files given relative to the bin folder (e.g. zapret\winws.exe).</summary>
        public static Hold VerifyAndLock(string binRoot, IEnumerable<string> relPaths, out string error) =>
            VerifyAndLock(relPaths.Select(r => (r, Path.Combine(binRoot, r))), out error);

        /// <summary>
        /// Verifies files against the embedded hash of their key. On success the exe, dll and payload files are kept open with
        /// writing denied (until disposed); on failure null is returned and every handle opened so far is closed. A .sys file is
        /// checked strictly right before the driver is loaded – its hash, that it is a plain file (no link, no second hard link)
        /// and that the open handle resolves to the expected path – and then closed, so the Windows loader is never blocked.
        /// </summary>
        public static Hold VerifyAndLock(IEnumerable<(string Key, string Path)> files, out string error)
        {
            error = "";
            var hold = new Hold();
            try
            {
                foreach (var (rel, path) in files)
                {
                    string name = Path.GetFileName(rel);
                    if (!Known.TryGetValue(rel, out var expected)) { error = Loc.T("integrity.noHash", rel); hold.Dispose(); return null; }
                    bool sys = name.EndsWith(".sys", StringComparison.OrdinalIgnoreCase);
                    if (PathSafety.Reparse(path) != PathSafety.Kind.None) { error = Loc.T("integrity.notPlain", name); hold.Dispose(); return null; }
                    var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                    bool keep = false;
                    try
                    {
                        string got = Sha256(fs);
                        if (got != expected)
                        {
                            error = Loc.T("integrity.mismatch", name, got.Substring(0, 12), expected.Substring(0, 12));
                            hold.Dispose();
                            return null;
                        }
                        if (sys && !PlainFileAt(fs, path))
                        {
                            error = Loc.T("integrity.notPlain", name);
                            hold.Dispose();
                            return null;
                        }
                        if (!sys) { hold.Streams.Add(fs); keep = true; }
                    }
                    finally { if (!keep) fs.Dispose(); }
                }
                return hold;
            }
            catch (Exception ex)
            {
                hold.Dispose();
                error = ex is FileNotFoundException f ? Loc.T("integrity.notFound", Path.GetFileName(f.FileName)) : ex is DirectoryNotFoundException ? Loc.T("integrity.notFound", ex.Message) : ex.Message;
                return null;
            }
        }

        /// <summary>An open file is a single hard link that resolves to the expected path (a driver file is never loaded through an alias).</summary>
        internal static bool PlainFileAt(FileStream fs, string path)
        {
            if (PathSafety.LinkCount(fs) != 1) return false;
            string fin = PathSafety.FinalPathOf(fs);
            return fin != null && PathSafety.Same(fin, path);
        }

        /// <summary>Verifies every known file in a bin root (GoodbyeDPI x86/x86_64, zapret, byedpi) (for tests and package checks).</summary>
        public static bool VerifyTree(string binRoot, out string error, Func<string, bool> filter = null)
        {
            error = "";
            foreach (var kv in Known)
            {
                if (filter != null && !filter(kv.Key)) continue;
                string f = Path.Combine(binRoot, kv.Key);
                if (!File.Exists(f)) { error = kv.Key + " missing"; return false; }
                if (Sha256File(f) != kv.Value) { error = kv.Key + " hash mismatch"; return false; }
            }
            return true;
        }
    }

    /// <summary>
    /// Allow list for GoodbyeDPI parameters. Only the known options of 0.2.3rc3 are accepted, with their full names
    /// (abbreviations are rejected because GoodbyeDPI's getopt_long parser also accepts abbreviations like "--black").
    /// Values are checked as number ranges, IP addresses or hex text; command line special characters cannot pass.
    /// </summary>
    public static class ArgPolicy
    {
        enum K { Flag, Int, Ip4, Ip6, Hex, OptAutoTtl, OptInt }

        sealed class Spec
        {
            public K Kind;
            public int Min, Max;
        }

        static Spec F() => new Spec { Kind = K.Flag };
        static Spec I(int min, int max) => new Spec { Kind = K.Int, Min = min, Max = max };

        static readonly Dictionary<string, Spec> Opts = new Dictionary<string, Spec>(StringComparer.Ordinal)
        {
            ["-p"] = F(), ["-q"] = F(), ["-r"] = F(), ["-s"] = F(), ["-a"] = F(), ["-m"] = F(), ["-n"] = F(), ["-w"] = F(),
            ["-1"] = F(), ["-2"] = F(), ["-3"] = F(), ["-4"] = F(), ["-5"] = F(), ["-6"] = F(), ["-7"] = F(), ["-8"] = F(), ["-9"] = F(),
            ["-f"] = I(1, 65535), ["-k"] = I(1, 65535), ["-e"] = I(1, 65535),
            ["--port"] = I(1, 65535), ["--ip-id"] = I(0, 65535),
            ["--dns-addr"] = new Spec { Kind = K.Ip4 }, ["--dns-port"] = I(1, 65535),
            ["--dnsv6-addr"] = new Spec { Kind = K.Ip6 }, ["--dnsv6-port"] = I(1, 65535),
            ["--dns-verb"] = F(), ["--allow-no-sni"] = F(), ["--frag-by-sni"] = F(),
            ["--set-ttl"] = I(1, 255), ["--auto-ttl"] = new Spec { Kind = K.OptAutoTtl }, ["--min-ttl"] = I(1, 255),
            ["--wrong-chksum"] = F(), ["--wrong-seq"] = F(), ["--native-frag"] = F(), ["--reverse-frag"] = F(),
            ["--fake-from-hex"] = new Spec { Kind = K.Hex }, ["--fake-gen"] = I(1, 30), ["--fake-resend"] = I(1, 100),
            ["--max-payload"] = new Spec { Kind = K.OptInt, Min = 0, Max = 65535 },
        };

        static bool AllowedChar(char c) =>
            c == ' ' || c == '-' || c == '.' || c == ':' || c == '=' ||
            (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');

        /// <summary>Checks parameters coming from the user/code (output of BuildArgs(null), without --blacklist).</summary>
        public static bool Validate(string args, out string error)
        {
            error = "";
            args = args ?? "";
            if (args.Length > 4000) { error = Loc.T("args.tooLong"); return false; }
            foreach (char c in args)
                if (!AllowedChar(c))
                {
                    error = Loc.T("args.badChar", c < 32 ? Loc.T("args.controlChar") : "'" + c + "'");
                    return false;
                }
            var t = args.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < t.Length; i++)
            {
                string tok = t[i], name = tok, val = null;
                if (!tok.StartsWith("-")) { error = Loc.T("args.unexpectedValue") + " " + tok; return false; }
                int eq = tok.IndexOf('=');
                if (eq > 0)
                {
                    if (!tok.StartsWith("--")) { error = Loc.T("args.shortWithEquals") + " " + tok; return false; }
                    name = tok.Substring(0, eq);
                    val = tok.Substring(eq + 1);
                }
                if (name.Length >= 3 && "--blacklist".StartsWith(name, StringComparison.Ordinal))
                {
                    error = Loc.T("args.noBlacklist");
                    return false;
                }
                if (!Opts.TryGetValue(name, out var s))
                {
                    error = Loc.T("args.unknown", name);
                    return false;
                }
                switch (s.Kind)
                {
                    case K.Flag:
                        if (val != null) { error = name + " " + Loc.T("args.noValue"); return false; }
                        break;
                    case K.OptAutoTtl:
                        if (val != null && !Regex.IsMatch(val, @"^\d{1,3}-\d{1,3}-\d{1,3}$")) { error = name + " " + Loc.T("args.fragFormat"); return false; }
                        break;
                    case K.OptInt:
                        if (val != null && !IntOk(val, s.Min, s.Max)) { error = name + " " + Loc.T("args.range", s.Min, s.Max); return false; }
                        break;
                    default:
                        if (val == null)
                        {
                            if (i + 1 >= t.Length) { error = name + " " + Loc.T("args.missingValue"); return false; }
                            val = t[++i];
                        }
                        if (!ValueOk(s, val)) { error = name + " " + Loc.T("args.invalidValue") + " " + val; return false; }
                        break;
                }
            }
            return true;
        }

        static bool IntOk(string v, int min, int max) =>
            v.Length > 0 && v.Length <= 6 && v.All(char.IsDigit) && int.TryParse(v, out int n) && n >= min && n <= max;

        static bool ValueOk(Spec s, string v)
        {
            switch (s.Kind)
            {
                case K.Int: return IntOk(v, s.Min, s.Max);
                case K.Ip4: return Regex.IsMatch(v, @"^\d{1,3}(\.\d{1,3}){3}$") && IPAddress.TryParse(v, out var a4) && a4.AddressFamily == AddressFamily.InterNetwork;
                case K.Ip6: return v.Contains(":") && IPAddress.TryParse(v, out var a6) && a6.AddressFamily == AddressFamily.InterNetworkV6;
                case K.Hex: return v.Length >= 2 && v.Length <= 4096 && v.Length % 2 == 0 && Regex.IsMatch(v, "^[0-9a-fA-F]+$");
                default: return false;
            }
        }

        /// <summary>Checks the parameters of a profile with the allow list of its engine (GoodbyeDPI, Zapret or ByeDPI).</summary>
        public static bool ValidateProfile(Profile p, out string error)
        {
            if (p == null) { error = Loc.T("args.noProfile"); return false; }
            return Engines.Of(p).Validate(p, out error);
        }

        /// <summary>Removes control characters from names/descriptions coming from outside and limits the length.</summary>
        public static string CleanText(string s, int max)
        {
            var sb = new StringBuilder();
            foreach (char c in s ?? "")
                sb.Append(char.IsControl(c) ? ' ' : c);
            string r = Regex.Replace(sb.ToString(), @"\s{2,}", " ").Trim();
            return r.Length > max ? r.Substring(0, max) : r;
        }
    }

    /// <summary>Security checks for values that go on a cmd.exe command line.</summary>
    public static class CmdLine
    {
        static bool HasControl(string s) => (s ?? "").Any(char.IsControl);

        /// <summary>Value used inside quotes: no quote, percent (variable expansion), exclamation mark or control character.</summary>
        public static bool QuotedSafe(string s) => s != null && s.IndexOfAny(new[] { '"', '%', '!' }) < 0 && !HasControl(s);

        /// <summary>Value used without quotes: no command separators or redirections.</summary>
        public static bool BareSafe(string s) => s != null && s.IndexOfAny(new[] { '&', '|', '<', '>', '^', '%', '!' }) < 0 && !HasControl(s);

        /// <summary>For REM lines in .cmd scripts: only safe printable characters remain.</summary>
        public static string RemText(string s)
        {
            var sb = new StringBuilder();
            foreach (char c in s ?? "")
                sb.Append(char.IsLetterOrDigit(c) || " -_.,:;()'/+[]#".IndexOf(c) >= 0 ? c : ' ');
            return Regex.Replace(sb.ToString(), @" {2,}", " ").Trim();
        }

        public static bool HasControlChars(string s) => HasControl(s);
    }
}
