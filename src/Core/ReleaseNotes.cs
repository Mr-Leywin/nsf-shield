#if PREVIEW
using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace NSFShield
{
    /// <summary>
    /// The text of a GitHub release (made by the build job: NSFShield.preview.exe --release-notes). The SHA-256 lines come
    /// first, each next to its file name: the updater looks for the hash next to the file name when GitHub gives no digest,
    /// so a hash anywhere in the changelog text is never taken.
    /// The user-facing part (Turkish) comes from .github\release-notes.md ({ZIP}, {SETUP}, {REPO}).
    /// </summary>
    public static class ReleaseNotes
    {
        /// <summary>The changelog section of a version ("## [1.0.0] …" up to the next "## "); empty if there is none.</summary>
        public static string ChangelogSection(string changelog, string version)
        {
            var m = Regex.Match((changelog ?? "").Replace("\r\n", "\n"), @"(?ms)^## \[?" + Regex.Escape(version) + @"\]?[^\n]*\n(.*?)(?=^## |\z)");
            return m.Success ? m.Groups[1].Value.Trim() : "";
        }

        public static string Build(string version, string zipSha, string setupSha, string changelogSection, string repository, string template)
        {
            if (!Regex.IsMatch(zipSha ?? "", "^[0-9a-f]{64}$") || !Regex.IsMatch(setupSha ?? "", "^[0-9a-f]{64}$")) throw new ArgumentException("SHA-256 values are required");
            if (!Regex.IsMatch(version ?? "", @"^\d+\.\d+\.\d+$")) throw new ArgumentException("bad version");
            if (!Regex.IsMatch(repository ?? "", @"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")) throw new ArgumentException("bad repository");
            string zip = "NSF-Shield-" + version + ".zip", setup = "NSF-Shield-" + version + "-Setup.exe", sums = "NSF-Shield-" + version + ".SHA256SUMS.txt";
            var sb = new StringBuilder();
            sb.Append("**SHA-256** (" + zip + "): `" + zipSha + "`\n\n");
            sb.Append("**SHA-256** (" + setup + "): `" + setupSha + "`\n\n");
            sb.Append((string.IsNullOrWhiteSpace(changelogSection) ? "NSF Shield " + version : changelogSection.Trim()) + "\n\n");
            sb.Append((template ?? "").Replace("\r\n", "\n").Trim().Replace("{ZIP}", zip).Replace("{SETUP}", setup).Replace("{SUMS}", sums).Replace("{REPO}", repository) + "\n");
            return sb.ToString();
        }

        /// <summary>
        /// --release-notes &lt;version&gt; &lt;zip&gt; &lt;setup&gt; &lt;CHANGELOG.md&gt; &lt;template&gt; &lt;owner/repo&gt; &lt;out&gt;; exit code 0 only when written.
        /// </summary>
        public static int Cli(string[] a, int i)
        {
            try
            {
                if (a.Length < i + 8) return 64;
                string Sha(string f) { using (var s = File.OpenRead(f)) using (var h = System.Security.Cryptography.SHA256.Create()) return BitConverter.ToString(h.ComputeHash(s)).Replace("-", "").ToLowerInvariant(); }
                string version = a[i + 1];
                string text = Build(version, Sha(a[i + 2]), Sha(a[i + 3]), ChangelogSection(File.ReadAllText(a[i + 4], Encoding.UTF8), version), a[i + 6],
                                    File.ReadAllText(a[i + 5], Encoding.UTF8));
                File.WriteAllText(a[i + 7], text, new UTF8Encoding(false));
                return 0;
            }
            catch (Exception) { return 1; }
        }
    }
}
#endif
