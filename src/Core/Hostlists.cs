using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace NSFShield
{
    /// <summary>
    /// Domain lists: Include (apply the bypass only to these sites) and Exclude (never touch these sites). The lists live
    /// in the settings and are written before every start to data\lists\include.txt and exclude.txt (fixed names, atomic
    /// replace, one valid ASCII/punycode host name per line). While an engine runs, the files it reads are kept open with
    /// writing denied, so they cannot be changed under it (winws reloads a hostlist when the file changes).
    /// </summary>
    public static class Hostlists
    {
        public const string IncludeName = "include.txt", ExcludeName = "exclude.txt";
        public const int MaxEntries = 5000;

        public static string Dir => Path.Combine(App.DataDir, "lists");
        public static string IncludePath => Path.Combine(Dir, IncludeName);
        public static string ExcludePath => Path.Combine(Dir, ExcludeName);

        static readonly Regex Label = new Regex("^(?!-)[a-z0-9-]{1,63}(?<!-)$");

        /// <summary>
        /// A host name as the engines read it: lower-case ASCII (punycode for IDN), 2+ labels of 1–63 letters/digits/hyphens,
        /// at most 253 characters, a top-level domain that is not only digits (no IP addresses), no spaces, control
        /// characters, leading '-' (option), '/' or '\' (path), ':' (port) or '*'.
        /// </summary>
        public static bool IsValidDomain(string d)
        {
            if (string.IsNullOrEmpty(d) || d.Length > 253) return false;
            var labels = d.Split('.');
            if (labels.Length < 2) return false;
            foreach (var l in labels) if (!Label.IsMatch(l)) return false;
            return !labels[labels.Length - 1].All(char.IsDigit);
        }

        /// <summary>
        /// Turns user input into a valid host name or null. An address copied from the browser is accepted
        /// (https://www.example.com/path → www.example.com); "*." in front is dropped; IDN names become punycode.
        /// </summary>
        public static string Normalize(string input)
        {
            if (input == null) return null;
            string s = input.Trim();
            if (s.Length == 0 || s.Length > 300 || s.Any(char.IsControl) || s.StartsWith("-")) return null;
            s = s.ToLowerInvariant();
            int i = s.IndexOf("://", StringComparison.Ordinal);
            if (i >= 0) s = s.Substring(i + 3);
            i = s.IndexOfAny(new[] { '/', '?', '#' });
            if (i >= 0) s = s.Substring(0, i);
            if (s.Contains("@") || s.Contains("\\")) return null;
            i = s.LastIndexOf(':');
            if (i >= 0)
            {
                // a port after the name is dropped; anything else with ':' (IPv6, garbage) is refused
                if (!Regex.IsMatch(s.Substring(i + 1), @"^\d{1,5}$")) return null;
                s = s.Substring(0, i);
            }
            if (s.StartsWith("*.")) s = s.Substring(2);
            s = s.Trim('.');
            if (s.Length == 0) return null;
            try { s = new IdnMapping().GetAscii(s).ToLowerInvariant(); } catch { return null; }
            return IsValidDomain(s) ? s : null;
        }

        /// <summary>Splits pasted text (lines, spaces, commas, semicolons) into valid names and the rejected parts.</summary>
        public static (List<string> Ok, List<string> Bad) ParseMany(string text)
        {
            var ok = new List<string>();
            var bad = new List<string>();
            foreach (var part in (text ?? "").Split(new[] { ' ', ',', ';', '\n', '\r', '\t' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (part.StartsWith("#")) continue;
                var d = Normalize(part);
                if (d == null) bad.Add(part.Length > 60 ? part.Substring(0, 60) + "…" : part);
                else if (!ok.Contains(d)) ok.Add(d);
            }
            return (ok, bad);
        }

        /// <summary>Keeps only valid, unique names (settings from older versions or edited by hand).</summary>
        public static List<string> Clean(IEnumerable<string> list) =>
            (list ?? Enumerable.Empty<string>()).Select(Normalize).Where(d => d != null).Distinct().Take(MaxEntries).ToList();

        /// <summary>File content: the names one per line (LF; both engines read it, ByeDPI also splits on spaces).</summary>
        public static string Content(IEnumerable<string> domains) =>
            string.Concat(domains.Select(d => d + "\n"));

        /// <summary>
        /// Writes a managed list atomically: only the two fixed names are allowed and every line is validated again; the text
        /// goes to a temporary file in the same folder that then replaces the list in one step.
        /// </summary>
        public static string WriteAtomic(string name, IEnumerable<string> domains, string dir = null)
        {
            if (name != IncludeName && name != ExcludeName) throw new ArgumentException("not a managed list: " + name);
            var list = domains.ToList();
            if (list.Count > MaxEntries) throw new InvalidDataException(Loc.T("lists.tooMany", MaxEntries));
            foreach (var d in list) if (!IsValidDomain(d)) throw new InvalidDataException(Loc.T("lists.badEntry", d));
            dir = dir ?? Dir;
            Directory.CreateDirectory(dir);
            string target = Path.Combine(dir, name);
            string tmp = Path.Combine(dir, "." + name + "." + Guid.NewGuid().ToString("N").Substring(0, 8) + ".tmp");
            try
            {
                using (var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    var b = Encoding.ASCII.GetBytes(Content(list));
                    fs.Write(b, 0, b.Length);
                    fs.Flush(true);
                }
                if (File.Exists(target)) File.Replace(tmp, target, null);
                else File.Move(tmp, target);
            }
            finally { try { if (File.Exists(tmp)) File.Delete(tmp); } catch (Exception ign) { App.Ignored("Temporary list file could not be deleted", ign); } }
            return target;
        }

        /// <summary>Files kept open with writing denied while the engine runs.</summary>
        public sealed class Hold : IDisposable
        {
            internal readonly List<FileStream> Streams = new List<FileStream>();
            public void Dispose() { foreach (var s in Streams) try { s.Dispose(); } catch { } Streams.Clear(); }
        }

        /// <summary>Is the include list (targeted mode) in effect?</summary>
        public static bool IncludeOn(AppSettings s) => s.TargetedMode && s.TargetDomains.Count > 0;
        /// <summary>Is the exclude list in effect?</summary>
        public static bool ExcludeOn(AppSettings s) => s.ExcludeEnabled && s.ExcludeDomains.Count > 0;

        /// <summary>
        /// Writes the lists the engine will use and locks them for the run. A list the engine cannot use is reported in
        /// <paramref name="warnings"/> (e.g. GoodbyeDPI has no exclude list) and left out.
        /// </summary>
        public static Hold Prepare(IDpiEngine eng, AppSettings s, out ListBinding binding, out List<LocText> warnings) =>
            Prepare(eng, s, Dir, out binding, out warnings);

        /// <summary>
        /// Writes and locks the lists of <see cref="Resolve"/> (the plan the command preview shows). Any list of the plan that
        /// cannot be written, read back and locked throws: the caller stops the start (fail-closed) instead of running
        /// without the user's limit.
        /// </summary>
        internal static Hold Prepare(IDpiEngine eng, AppSettings s, string dir, out ListBinding binding, out List<LocText> warnings)
        {
            var plan = Resolve(eng, s, dir);
            warnings = plan.Warnings;
            binding = new ListBinding();
            var hold = new Hold();
            try
            {
                if (plan.Binding.Include != null) binding.Include = WriteAtomic(IncludeName, plan.Include, dir);
                if (plan.Binding.Exclude != null) binding.Exclude = WriteAtomic(ExcludeName, plan.Exclude, dir);
                foreach (var f in new[] { binding.Include, binding.Exclude }.Where(f => f != null))
                {
                    var fs = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.Read);
                    hold.Streams.Add(fs);
                    // the locked file must hold exactly the plan's names (nothing changed it between writing and locking)
                    var want = f == binding.Include ? plan.Include : plan.Exclude;
                    fs.Position = 0;
                    var got = new StreamReader(fs, Encoding.ASCII, false, 4096, true).ReadToEnd();
                    if (got != Content(want)) throw new InvalidDataException(Loc.T("lists.changed", Path.GetFileName(f)));
                    fs.Position = 0;
                }
                if (!binding.SameFiles(plan.Binding)) throw new InvalidDataException(Loc.T("lists.changed", "plan"));
                return hold;
            }
            catch
            {
                hold.Dispose();
                throw;
            }
        }

        /// <summary>The resolved list plan of a start: the names, the file paths and the warnings (lists an engine cannot use).</summary>
        public sealed class ListPlanResult
        {
            public List<string> Include, Exclude;
            public ListBinding Binding = new ListBinding();
            public List<LocText> Warnings = new List<LocText>();
        }

        /// <summary>
        /// The one list plan used by a start (<see cref="Prepare"/>) and by the command preview (<see cref="Plan"/>): which list
        /// is on, which file path it gets and what the engine cannot honour.
        /// </summary>
        public static ListPlanResult Resolve(IDpiEngine eng, AppSettings s, string dir = null)
        {
            dir = dir ?? Dir;
            var r = new ListPlanResult();
            if (IncludeOn(s))
            {
                if (eng.SupportsInclude) { r.Include = Clean(s.TargetDomains); r.Binding.Include = Path.Combine(dir, IncludeName); }
                else r.Warnings.Add(new LocText("lists.includeUnsupported", eng.DisplayName));
            }
            if (ExcludeOn(s))
            {
                if (eng.SupportsExclude) { r.Exclude = Clean(s.ExcludeDomains); r.Binding.Exclude = Path.Combine(dir, ExcludeName); }
                else r.Warnings.Add(new LocText("lists.excludeUnsupported", eng.DisplayName));
            }
            return r;
        }

        /// <summary>
        /// The list files a start would bind (the same full paths <see cref="Prepare"/> returns), worked out without writing or
        /// locking anything: for the command preview.
        /// </summary>
        public static ListBinding Plan(IDpiEngine eng, AppSettings s) => Resolve(eng, s).Binding;

        /// <summary>
        /// Writes the given lists into <paramref name="dir"/> (a scan trial's own folder, never the live lists) and keeps them
        /// closed for writing until the hold is disposed. null = that list is not used.
        /// </summary>
        public static Hold WriteAndHold(IList<string> include, IList<string> exclude, string dir, out ListBinding binding)
        {
            binding = new ListBinding();
            var hold = new Hold();
            try
            {
                if (include != null) binding.Include = WriteAtomic(IncludeName, include, dir);
                if (exclude != null) binding.Exclude = WriteAtomic(ExcludeName, exclude, dir);
                foreach (var f in new[] { binding.Include, binding.Exclude }.Where(f => f != null))
                    hold.Streams.Add(new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.Read));
                return hold;
            }
            catch
            {
                hold.Dispose();
                throw;
            }
        }

        // ------------------------------------------------------------------ ready-made lists

        public sealed class Template
        {
            public string Key;
            public string[] Domains;
            public string Name => Loc.T("lists.template." + Key);
        }

        public static readonly Template[] IncludeTemplates =
        {
            new Template { Key = "discordVoice", Domains = AppSettings.DiscordDomains.Concat(new[] { "discord-attachments-uploads-prd.storage.googleapis.com" }).ToArray() },
            new Template { Key = "roblox", Domains = new[] { "roblox.com", "rbxcdn.com", "rbx.com", "robloxlabs.com" } },
            new Template { Key = "wattpad", Domains = new[] { "wattpad.com" } },
        };

        public static readonly Template[] ExcludeTemplates =
        {
            new Template
            {
                Key = "banksGov",
                Domains = new[]
                {
                    "gov.tr", "turkiye.gov.tr", "edevlet.gov.tr", "gib.gov.tr", "sgk.gov.tr", "mhrs.gov.tr", "e-okul.meb.gov.tr", "ptt.gov.tr",
                    "ziraatbank.com.tr", "isbank.com.tr", "garantibbva.com.tr", "akbank.com", "yapikredi.com.tr", "halkbank.com.tr",
                    "vakifbank.com.tr", "qnb.com.tr", "denizbank.com", "teb.com.tr", "kuveytturk.com.tr", "enpara.com", "ing.com.tr",
                    "hsbc.com.tr", "sekerbank.com.tr", "albaraka.com.tr", "fibabanka.com.tr", "odeabank.com.tr", "papara.com",
                },
            },
            new Template
            {
                Key = "antiCheat",
                Domains = new[]
                {
                    "riotgames.com", "riotcdn.net", "leagueoflegends.com", "playvalorant.com", "faceit.com", "faceit-cdn.net",
                    "battleye.com", "easy.ac", "easyanticheat.net", "eac-cdn.com", "steampowered.com", "steamcommunity.com",
                    "steamcontent.com", "valvesoftware.com", "ea.com", "epicgames.com", "ubisoft.com", "xboxlive.com",
                },
            },
        };
    }
}
