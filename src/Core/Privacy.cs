using System;
using System.Text.RegularExpressions;

namespace NSFShield
{
    /// <summary>
    /// The shared privacy mask for text that leaves the program or is kept on disk (the log, a crash record, the log copied to
    /// the clipboard or saved, the support package): the user's own folder becomes %USERPROFILE%, so the Windows account name
    /// does not end up in it. The support package additionally hides addresses (see <see cref="Support.Redact"/>).
    /// </summary>
    public static class Privacy
    {
        static Regex mask;
        static string maskFor;

        static Regex Mask()
        {
            string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) ?? "";
            if (home == maskFor) return mask;
            Regex r = null;
            if (home.Length > 3)
            {
                string longHome = PathSafety.LongPath(home);
                string pattern = Regex.Escape(home.TrimEnd('\\'));
                if (!string.Equals(longHome, home, StringComparison.OrdinalIgnoreCase)) pattern += "|" + Regex.Escape(longHome.TrimEnd('\\'));
                // the folder itself, followed by a separator, the end or anything that is not part of a longer name
                r = new Regex("(?:" + pattern + @")(?=[\\/""'\s:;,)\]]|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            }
            mask = r;
            maskFor = home;
            return r;
        }

        /// <summary>The text with the user's folder replaced by %USERPROFILE%.</summary>
        public static string MaskUser(string text)
        {
            if (string.IsNullOrEmpty(text)) return text;
            try
            {
                var r = Mask();
                return r == null ? text : r.Replace(text, "%USERPROFILE%");
            }
            catch { return text; }
        }
    }
}
