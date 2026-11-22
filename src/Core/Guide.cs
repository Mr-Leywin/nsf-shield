using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace NSFShield
{
    /// <summary>
    /// Builds the bilingual Guide.html from docs\Guide.html at build time: the error code and profile tables of each language
    /// are made from that language's own texts; every id carries the language prefix ("en-NSF-101", "tr-NSF-101"), so no id
    /// repeats and no link crosses languages. Two fixed entry pages (guide\en.html, guide\tr.html) open the main file at the
    /// language's part: a file path with "#en" or "?lang=" is never handed to Windows.
    /// </summary>
    public static class Guide
    {
        public static readonly string[] Languages = { "en", "tr" };
        public const string FileName = "Guide.html", EntryDir = "guide";

        static string H(string s) => WebUtility.HtmlEncode(s ?? "");

        public static string ErrorsHtml(string lang)
        {
            var sb = new StringBuilder();
            foreach (var cat in ErrorCatalog.Categories)
            {
                sb.AppendLine("<h3>" + H(ErrorCatalog.CategoryName(cat)) + "</h3>");
                foreach (var e in ErrorCatalog.All.Where(x => x.Category == cat))
                {
                    string sev = e.Severity == Severity.Error ? "err" : e.Severity == Severity.Warning ? "warn" : "info";
                    sb.AppendLine("<details class=\"code " + sev + "\" id=\"" + lang + "-" + H(e.Code) + "\"><summary><span class=\"badge\">" + H(e.Code) + "</span> " + H(e.Title) + "</summary>");
                    sb.AppendLine("<p>" + H(e.Summary) + "</p>");
                    if (e.Causes.Length > 0)
                        sb.AppendLine("<p class=\"lbl\">" + H(Loc.T("guide.causes")) + "</p><ul>" + string.Concat(e.Causes.Select(c => "<li>" + H(c) + "</li>")) + "</ul>");
                    if (e.Steps.Length > 0)
                        sb.AppendLine("<p class=\"lbl\">" + H(Loc.T("guide.solution")) + "</p><ol>" + string.Concat(e.Steps.Select(c => "<li>" + H(c) + "</li>")) + "</ol>");
                    if (e.Fix != FixKind.None)
                        sb.AppendLine("<p class=\"fix\">" + H(Loc.T("guide.oneClick")) + " <b>" + H(ErrorInfo.FixLabel(e.Fix)) + "</b>" +
                                      (e.Fix2 != FixKind.None ? " · <b>" + H(ErrorInfo.FixLabel(e.Fix2)) + "</b>" : "") + "</p>");
                    sb.AppendLine("</details>");
                }
            }
            return sb.ToString();
        }

        /// <summary>
        /// The built-in profiles of each engine with the validated command of that engine's own builder (short names, default
        /// settings: no user lists, paths or ports of this computer) – the same preview the app shows.
        /// </summary>
        public static string ProfilesHtml(string lang)
        {
            var s = new AppSettings();
            var sb = new StringBuilder();
            foreach (var eng in Engines.All)
            {
                sb.AppendLine("<h3 id=\"" + lang + "-engine-" + eng.Id + "\">" + H(eng.DisplayName) + "</h3>");
                sb.AppendLine("<table><thead><tr><th>#</th><th>" + H(Loc.T("guide.method")) + "</th><th>DNS</th><th>" + H(Loc.T("guide.description")) + "</th></tr></thead><tbody>");
                int i = 0;
                foreach (var p in ProfileCatalog.Order(Profiles.BuiltIns.Where(x => x.Engine == eng.Kind)))
                {
                    i++;
                    string tier = p.Tier == ProfileTier.Recommended ? "<span class=\"tier\">" + H(Loc.T("profiles.tier.Recommended")) + "</span>" : "";
                    string cmd = CommandPreview.TryBuild(p, s, false, out string c, out string err) ? c : "✗ " + err;
                    string tags = p.Tags.Length > 0 ? "<br><small>" + H(string.Join(" · ", ProfileCatalog.ScenarioTags(p))) + "</small>" : "";
                    sb.AppendLine("<tr" + (p.UsesDnsRedirect ? "" : " class=\"nodns\"") + "><td>" + i.ToString("00") + "</td><td><b>" + H(p.Name) + "</b>" + tier +
                                  "<br><code>" + H(cmd) + "</code></td><td>" + H(p.DnsLabel) + "</td><td>" + H(p.Description) + tags + "</td></tr>");
                }
                sb.AppendLine("</tbody></table>");
            }
            return sb.ToString();
        }

        /// <summary>A fixed entry page that opens the main guide at one language (no user input, no network request).</summary>
        public static string EntryHtml(string lang)
        {
            string title = lang == "tr" ? "NSF Shield Rehberi" : "NSF Shield Guide";
            string link = "../" + FileName + "#" + lang;
            return "<!doctype html>\r\n<html lang=\"" + lang + "\">\r\n<head>\r\n<meta charset=\"utf-8\">\r\n<title>" + title + "</title>\r\n" +
                   "<meta http-equiv=\"refresh\" content=\"0; url=" + link + "\">\r\n</head>\r\n<body>\r\n<p><a href=\"" + link + "\">" + title + "</a></p>\r\n" +
                   "<script>location.replace(\"" + link + "\");</script>\r\n</body>\r\n</html>\r\n";
        }

        /// <summary>The entry page for the UI language (other languages: English); null if it is missing.</summary>
        public static string EntryFor(string baseDir, string uiLang)
        {
            string lang = uiLang == "tr" ? "tr" : "en";
            string entry = Path.Combine(baseDir, EntryDir, lang + ".html");
            if (File.Exists(entry)) return entry;
            string main = Path.Combine(baseDir, FileName);
            return File.Exists(main) ? main : null;
        }

        public static void Build(string template, string output)
        {
            string html = File.ReadAllText(template, Encoding.UTF8)
                .Replace("<!--VERSION-->", App.Version)
                .Replace("<!--ERROR_COUNT-->", ErrorCatalog.All.Count.ToString())
                .Replace("<!--PROFILE_COUNT-->", Profiles.BuiltIns.Count.ToString());
            string start = Loc.Current;
            try
            {
                foreach (var lang in Languages)
                {
                    Loc.Init(lang);
                    html = html.Replace("<!--ERROR_CODES:" + lang + "-->", ErrorsHtml(lang)).Replace("<!--PROFILES:" + lang + "-->", ProfilesHtml(lang));
                }
            }
            finally { Loc.Init(start); }
            var left = Regex.Match(html, "<!--(VERSION|ERROR_COUNT|PROFILE_COUNT|ERROR_CODES:[a-z]+|PROFILES:[a-z]+)-->");
            if (left.Success) throw new InvalidDataException("Guide template placeholder not filled: " + left.Value);
            File.WriteAllText(output, html, new UTF8Encoding(true));
            string dir = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(output)), EntryDir);
            Directory.CreateDirectory(dir);
            foreach (var lang in Languages) File.WriteAllText(Path.Combine(dir, lang + ".html"), EntryHtml(lang), new UTF8Encoding(false));
        }
    }
}
