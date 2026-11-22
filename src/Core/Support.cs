using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace NSFShield
{
    /// <summary>Support package (with personal data removed) and reporting issues on GitHub.</summary>
    public static class Support
    {
        /// <summary>Well-known public addresses that may be shared (DNS servers, Discord/Cloudflare, block page).</summary>
        static readonly string[] KeepIp =
        {
            "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "9.9.9.10", "149.112.112.112", "149.112.112.10",
            "77.88.8.8", "77.88.8.1", "77.88.8.88", "94.140.14.14", "94.140.15.15", "94.140.14.140", "94.140.14.141",
            "208.67.222.222", "208.67.220.220", "208.67.222.123", "195.175.254.2", "127.0.0.1", "0.0.0.0",
        };

        /// <summary>Hides personal data in a text: IP addresses, user folder name, e-mail.</summary>
        public static string Redact(string text)
        {
            if (string.IsNullOrEmpty(text)) return text;
            // C:\Users\<name>\  →  C:\Users\<user>\
            text = Regex.Replace(text, @"(?i)([a-z]:\\(?:Users|Kullan\u0131c\u0131lar)\\)[^\\/""\r\n]+", "$1<user>");
            // e-mail
            text = Regex.Replace(text, @"[\w.+-]+@[\w-]+\.[\w.-]+", "<email>");
            // IPv4 (Discord/Cloudflare 162.159.x.x and known DNS servers are kept)
            text = Regex.Replace(text, @"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b", m =>
            {
                string ip = m.Value;
                if (KeepIp.Contains(ip) || ip.StartsWith("162.159.") || ip.StartsWith("104.16.")) return ip;
                if (!m.Groups.Cast<Group>().Skip(1).All(g => int.TryParse(g.Value, out int v) && v <= 255)) return ip;   // version numbers etc.
                if (ip.StartsWith("192.168.") || ip.StartsWith("10.") || Regex.IsMatch(ip, @"^172\.(1[6-9]|2\d|3[01])\.")) return "<local-ip>";
                return "<ip>";
            });
            // public IPv6 addresses (fe80 local and known DNS servers are kept)
            text = Regex.Replace(text, @"(?<![\w:.])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])", m =>
            {
                string v = m.Value.ToLowerInvariant();
                if (v.StartsWith("fe80") || v.StartsWith("2a02:6b8::") || v.StartsWith("2a10:50c0::") || v.StartsWith("2620:fe::") ||
                    v.StartsWith("2620:119:") || v.StartsWith("2606:4700:") || v.StartsWith("2001:4860:")) return m.Value;
                return IPAddress.TryParse(m.Value, out _) ? "<ipv6>" : m.Value;
            });
            return text;
        }

        /// <summary>
        /// Replaces what names the user's saved proxies and program rules in a text: a proxy's address (host:port), host (a DNS
        /// name or an IP), name and user name become "Proxy #n"; a rule's name and program path become "App #n". Longer texts
        /// are replaced first, case-insensitively; very short texts (under 3 characters) are left alone.
        /// </summary>
        public static string MaskSaved(string text, AppSettings s)
        {
            if (string.IsNullOrEmpty(text) || s == null) return text;
            var map = new List<(string Find, string Label)>();
            for (int i = 0; i < s.Proxies.Count; i++)
            {
                var p = s.Proxies[i];
                string label = "Proxy #" + (i + 1);
                foreach (var v in new[] { p.Address, p.Host, p.Name, p.User })
                    if (!string.IsNullOrWhiteSpace(v) && v.Trim().Length >= 3 && v.Trim() != "127.0.0.1") map.Add((v.Trim(), label));
            }
            for (int i = 0; i < s.ProxyApps.Count; i++)
            {
                var a = s.ProxyApps[i];
                string label = "App #" + (i + 1);
                foreach (var v in new[] { a.ExePath, a.Name })
                    if (!string.IsNullOrWhiteSpace(v) && v.Trim().Length >= 3) map.Add((v.Trim(), label));
            }
            foreach (var (find, label) in map.OrderByDescending(x => x.Find.Length))
                text = Regex.Replace(text, Regex.Escape(find), label, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            return text;
        }

        /// <summary>Every text that goes into the support package: the saved names masked first, then addresses, user folder, e-mail.</summary>
        public static string ForPackage(string text) => Redact(MaskSaved(Privacy.MaskUser(text), App.Settings));

        public static string SystemSummary()
        {
            var sb = new StringBuilder();
            sb.AppendLine("NSF Shield " + App.Version + " · Windows build " + SystemDns.WindowsBuild + (Environment.Is64BitOperatingSystem ? " (64 bit)" : " (32 bit)"));
            sb.AppendLine("UI: " + App.Settings.UiLevel + " · Theme: " + App.Settings.ThemeId + " · Service mode: " + (App.Settings.ServiceMode ? "on" : "off") +
                          " · Include list: " + (Hostlists.IncludeOn(App.Settings) ? App.Settings.TargetDomains.Count.ToString() : "off") +
                          " · Exclude list: " + (Hostlists.ExcludeOn(App.Settings) ? App.Settings.ExcludeDomains.Count.ToString() : "off"));
            var eng = App.Engine;
            sb.AppendLine("Protection: " + eng.State + (eng.LastErrorCode.Length > 0 ? " [" + eng.LastErrorCode + "]" : "") + " · Method: " + ProfileLabel(eng.ActiveProfile ?? App.SelectedProfile));
            var prof = eng.ActiveProfile ?? App.SelectedProfile;
            var en = Engines.Of(prof);
            sb.AppendLine("Engine: " + en.DisplayName + (en.Kind == EngineKind.ByeDpi ? " · SOCKS 127.0.0.1:" + ByeDpiNet.SocksPort + " · Windows proxy: " + (ByeDpiNet.SystemProxyActive ? "set" : "not set") : ""));
            sb.AppendLine("Command: " + en.ExeName + " " + en.BuildArgs(prof, ListBinding.Display(Hostlists.IncludeOn(App.Settings), Hostlists.ExcludeOn(App.Settings)), true));
            var t = App.LastTest;
            if (t != null) sb.AppendLine("Last test: " + t.Count(x => x.Ok) + "/" + t.Count + (App.LastDnsOk == false ? ", DNS wrong" : "") +
                                         (t.Any(x => !x.Ok) ? " · failing: " + string.Join(", ", t.Where(x => !x.Ok).Select(x => x.Host + " " + x.Code)) : ""));
            var probs = App.Problems.Snapshot();
            sb.AppendLine("Detected problems: " + (probs.Count == 0 ? "none" : string.Join(", ", probs.Select(p => p.Code + " " + p.Info?.Title))));
            return ForPackage(sb.ToString());
        }

        /// <summary>Saves the log, history, settings (passwords and proxy addresses removed) and a system summary as a zip.</summary>
        public static void CreatePackage(string zipPath)
        {
            string tmp = Path.Combine(Path.GetTempPath(), "NSFShield-support-" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(tmp);
            try
            {
                File.WriteAllText(Path.Combine(tmp, "summary.txt"), SystemSummary(), Encoding.UTF8);
                if (File.Exists(App.LogFile))
                {
                    var lines = File.ReadAllLines(App.LogFile, Encoding.UTF8);
                    File.WriteAllText(Path.Combine(tmp, "app-log.txt"), ForPackage(string.Join(Environment.NewLine, lines.Skip(Math.Max(0, lines.Length - 3000)))), Encoding.UTF8);
                }
                string hist = Path.Combine(App.DataDir, "history.csv");
                if (File.Exists(hist)) File.WriteAllText(Path.Combine(tmp, "history.csv"), ForPackage(File.ReadAllText(hist, Encoding.UTF8)), Encoding.UTF8);
                string upd = Path.Combine(App.DataDir, "update.log");
                if (File.Exists(upd)) File.WriteAllText(Path.Combine(tmp, "update.txt"), ForPackage(File.ReadAllText(upd, Encoding.UTF8)), Encoding.UTF8);

                // settings: built from an allow list of diagnostic fields (never a copy of the settings with fields removed)
                SettingsSummary(App.Settings).Save(Path.Combine(tmp, SettingsFileName));
                File.WriteAllText(Path.Combine(tmp, "README.txt"), ReadmeText, Encoding.UTF8);
                if (File.Exists(zipPath)) File.Delete(zipPath);
                ZipFile.CreateFromDirectory(tmp, zipPath);
                App.Log("Support package created: " + zipPath, LogLevel.Success);
            }
            finally { try { Directory.Delete(tmp, true); } catch { } }
        }

        public const string SettingsFileName = "settings-summary.xml";

        /// <summary>What the package contains – the same as what <see cref="CreatePackage"/> writes (checked by the self-test).</summary>
        public const string ReadmeText =
            "This package was created by NSF Shield for a support request. You can open and check every file before sharing it.\r\n" +
            "\r\n" +
            "summary.txt          version, Windows build, UI/engine state, the method (custom profiles are not named) and its command line.\r\n" +
            "app-log.txt          the last 3000 log lines.\r\n" +
            "history.csv          tests, scans and repairs.\r\n" +
            "update.txt           the update log (if there is one).\r\n" +
            "settings-summary.xml switches and counts only: no proxy addresses, proxy or program names, user names or passwords,\r\n" +
            "                     no program paths or extra arguments (only whether there are any), no site lists (only their size),\r\n" +
            "                     no DNS or proxy backups.\r\n" +
            "\r\n" +
            "In every text file the saved proxies (address, host name, name, user name) are shown as \"Proxy #n\" and per-program\r\n" +
            "rules as \"App #n\"; IP addresses (except well-known public DNS and Discord/Cloudflare addresses), the user folder\r\n" +
            "name and e-mail addresses are hidden.\r\n";

        /// <summary>A profile as it may appear in a support package: built-in profiles by their name, custom ones only by their engine.</summary>
        public static string ProfileLabel(Profile p) =>
            p == null ? "-" : p.BuiltIn ? p.Name : "custom profile (" + Engines.Of(p).DisplayName + ")";

        /// <summary>
        /// The settings part of the support package, from an allow list: every field is chosen here on purpose (switches, counts,
        /// built-in ids). Proxies and per-program rules get neutral names ("Proxy #1", "App #1"); extra arguments only as yes/no.
        /// </summary>
        public static System.Xml.Linq.XDocument SettingsSummary(AppSettings s)
        {
            XElement E(string n, object v) => new XElement(n, v);
            var proxyNo = new Dictionary<string, int>();
            for (int i = 0; i < s.Proxies.Count; i++) proxyNo[s.Proxies[i].Id ?? ""] = i + 1;
            string ProxyRef(string id) => id == ByeDpiNet.ProxyMarker ? "ByeDPI (127.0.0.1)" : proxyNo.TryGetValue(id ?? "", out int n) ? "Proxy #" + n : (string.IsNullOrEmpty(id) ? "none" : "unknown");
            var sel = App.FindProfile(s.SelectedProfileId);
            var root = new XElement("SupportSettings", new XAttribute("app", App.Version), new XAttribute("schema", s.Version),
                E("Language", s.Language), E("UiLevel", s.UiLevel), E("ThemeId", s.ThemeId == "system" || Palettes.Presets.Any(x => x.Id == s.ThemeId) ? s.ThemeId : "custom"),
                E("SelectedProfile", sel != null && sel.BuiltIn ? sel.Id : sel != null ? "custom (" + Engines.Of(sel).DisplayName + ")" : "unknown"),
                E("CustomProfiles", s.CustomProfiles.Count),
                E("ServiceMode", s.ServiceMode), E("StartWithWindows", s.StartWithWindows), E("AutoStartProtection", s.AutoStartProtection),
                E("AutoRestart", s.AutoRestart), E("AutoHeal", s.AutoHeal), E("WatchMinutes", s.WatchMinutes), E("AutoUpdate", s.AutoUpdate),
                E("FlushDns", s.FlushDns), E("TestAfterStart", s.TestAfterStart), E("CheckDnsOnStart", s.CheckDnsOnStart),
                E("TargetedMode", s.TargetedMode), E("IncludeListSize", s.TargetDomains.Count),
                E("ExcludeEnabled", s.ExcludeEnabled), E("ExcludeListSize", s.ExcludeDomains.Count),
                E("ScanTargets", s.TestTargets?.Count ?? 0), E("TestHosts", s.TestHosts.Count),
                E("ByeDpiPort", s.ByeDpiPort), E("ByeDpiSystemProxy", s.ByeDpiSystemProxy),
                E("WindowsProxySetByApp", ProxyRef(s.SystemProxyId)),
                E("DnsChangedAdapters", s.DnsBackups.Count), E("DohChangedEntries", s.DohBackups.Count), E("GlobalDohChanged", s.GlobalDohBackup != null));
            var px = new XElement("Proxies");
            for (int i = 0; i < s.Proxies.Count; i++)
            {
                var p = s.Proxies[i];
                px.Add(new XElement("Proxy", new XAttribute("name", "Proxy #" + (i + 1)), new XAttribute("kind", p.KindLabel),
                    new XAttribute("auth", p.HasAuth ? "yes" : "no"), new XAttribute("lastOk", p.LastOk ? "yes" : "no")));
            }
            root.Add(px);
            var apps = new XElement("ProxyApps");
            for (int i = 0; i < s.ProxyApps.Count; i++)
            {
                var a = s.ProxyApps[i];
                apps.Add(new XElement("App", new XAttribute("name", "App #" + (i + 1)), new XAttribute("mode", a.Mode), new XAttribute("proxy", ProxyRef(a.ProxyId)),
                    new XAttribute("extraArgs", string.IsNullOrWhiteSpace(a.ExtraArgs) ? "no" : "yes"),
                    new XAttribute("separateProfile", a.SeparateProfile), new XAttribute("closeRunning", a.CloseRunning)));
            }
            root.Add(apps);
            return new System.Xml.Linq.XDocument(root);
        }

        /// <summary>
        /// Address of the pre-filled "new issue" page (the user sees and edits it before submitting). The elevated app opens it
        /// through explorer.exe (<see cref="Sys.OpenAsUser"/>), which passes at most <see cref="Sys.MaxShellArgument"/>
        /// characters on: the address carries only the short fields (version, Windows build, error code, title); the system
        /// summary goes to the clipboard instead (<see cref="SystemSummary"/>).
        /// </summary>
        public static string IssueUrl()
        {
            var eng = App.Engine;
            var top = App.Problems.Top;
            string title = top != null ? top.Code + " – " + top.Info?.Title : eng.State == EngineState.Error ? Loc.T("support.protectionNotWorking") : "";
            return IssueUrl(title, App.Version, SystemDns.WindowsBuild.ToString(), top?.Code ?? eng.LastErrorCode);
        }

        /// <summary>
        /// The "new issue" address from its fields, never longer than <see cref="Sys.MaxShellArgument"/>: the title is shortened
        /// (whole characters before escaping, so no escape sequence or surrogate pair is ever cut) and dropped last.
        /// </summary>
        public static string IssueUrl(string title, string version, string build, string code)
        {
            string Q(string s) => Uri.EscapeDataString(s ?? "");
            string head = "https://github.com/" + Updater.Owner + "/" + Updater.Repo + "/issues/new?template=hata.yml";
            string tail = "&surum=" + Q(version) + "&windows=" + Q("Build " + build) + "&kod=" + Q(code);
            string Make(string t) => head + (string.IsNullOrEmpty(t) ? "" : "&title=" + Q(t)) + tail;
            if (head.Length + tail.Length > Sys.MaxShellArgument) tail = "";   // never: the fields are short
            title = (title ?? "").Trim();
            string url = Make(title);
            if (url.Length <= Sys.MaxShellArgument) return url;
            var si = new System.Globalization.StringInfo(title);
            for (int n = si.LengthInTextElements - 1; n > 0; n--)
            {
                url = Make(si.SubstringByTextElements(0, n).TrimEnd() + "…");
                if (url.Length <= Sys.MaxShellArgument) return url;
            }
            return Make("");
        }
    }
}
