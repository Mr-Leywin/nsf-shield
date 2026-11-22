using System;
using System.Collections.Generic;
using System.Drawing;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using Microsoft.Win32;

namespace NSFShield
{
    /// <summary>A color theme: the 12 base colors the user can change.</summary>
    sealed class Palette
    {
        public string Id, Group = "";
        /// <summary>Locale key of the theme name, or a proper name that is shown as it is (e.g. "Nord").</summary>
        public string NameKey = "";
        /// <summary>True when the user's own colors are applied on top of the theme.</summary>
        public bool Custom;
        public string Name => (Loc.Has(NameKey) ? Loc.T(NameKey) : NameKey) + (Custom ? " " + Loc.T("theme.customSuffix") : "");
        public Color Accent, Bg, Card, Border, Text, Muted, Sidebar, SidebarText, Green, Amber, Red, LogBg;

        public static readonly string[] Keys =
            { "Accent", "Bg", "Card", "Border", "Text", "Muted", "Sidebar", "SidebarText", "Green", "Amber", "Red", "LogBg" };

        public static readonly string[] Labels =
        {
            "theme.color.Accent", "theme.color.Bg", "theme.color.Card", "theme.color.Border", "theme.color.Text", "theme.color.Muted", "theme.color.Sidebar", "theme.color.SidebarText", "theme.color.Green", "theme.color.Amber", "theme.color.Red", "theme.color.LogBg"
        };

        public Color Get(string key)
        {
            switch (key)
            {
                case "Accent": return Accent; case "Bg": return Bg; case "Card": return Card; case "Border": return Border;
                case "Text": return Text; case "Muted": return Muted; case "Sidebar": return Sidebar; case "SidebarText": return SidebarText;
                case "Green": return Green; case "Amber": return Amber; case "Red": return Red; case "LogBg": return LogBg;
            }
            return Color.Empty;
        }

        public void Set(string key, Color c)
        {
            switch (key)
            {
                case "Accent": Accent = c; break; case "Bg": Bg = c; break; case "Card": Card = c; break; case "Border": Border = c; break;
                case "Text": Text = c; break; case "Muted": Muted = c; break; case "Sidebar": Sidebar = c; break; case "SidebarText": SidebarText = c; break;
                case "Green": Green = c; break; case "Amber": Amber = c; break; case "Red": Red = c; break; case "LogBg": LogBg = c; break;
            }
        }

        public Palette Clone() => (Palette)MemberwiseClone();

        public bool IsDark => Theme.Lum(Card) < 0.35;

        /// <summary>Shareable theme code: DKT1:Accent=2563EB;Bg=…</summary>
        public string ToCode() => "DKT1:" + string.Join(";", Keys.Select(k => k + "=" + Palettes.Hex(Get(k)).TrimStart('#')));

        public static bool TryParseCode(string code, Palette basePalette, out Palette p)
        {
            p = basePalette.Clone();
            code = (code ?? "").Trim();
            if (!code.StartsWith("DKT1:", StringComparison.OrdinalIgnoreCase)) return false;
            int n = 0;
            foreach (var part in code.Substring(5).Split(';'))
            {
                var kv = part.Split('=');
                if (kv.Length != 2) continue;
                string key = Keys.FirstOrDefault(k => k.Equals(kv[0].Trim(), StringComparison.OrdinalIgnoreCase));
                if (key != null && Palettes.TryParseColor(kv[1], out var c)) { p.Set(key, c); n++; }
            }
            return n > 0;
        }
    }

    static class Palettes
    {
        static Color H(string hex) { TryParseColor(hex, out var c); return c; }

        static Palette P(string id, string name, string group, string accent, string bg, string card, string border, string text, string muted,
                         string sidebar, string sideText, string green, string amber, string red, string log = null)
        {
            var p = new Palette
            {
                Id = id, NameKey = name, Group = group,
                Accent = H(accent), Bg = H(bg), Card = H(card), Border = H(border), Text = H(text), Muted = H(muted),
                Sidebar = H(sidebar), SidebarText = H(sideText), Green = H(green), Amber = H(amber), Red = H(red),
            };
            p.LogBg = log != null ? H(log) : p.IsDark ? Theme.Mix(p.Bg, Color.Black, 0.35f) : Color.FromArgb(15, 22, 38);
            return p;
        }

        /// <summary>Themes used when "follow Windows" is turned on for the first time.</summary>
        public const string DefaultLightId = "clean-light", DefaultDarkId = "slate-dark";

        /// <summary>The carefully tuned themes shown first (every text color meets WCAG AA on its background).</summary>
        public static readonly string[] FeaturedIds = { "slate-dark", "amoled", "nord", "clean-light" };

        public static readonly List<Palette> Presets = new List<Palette>
        {
            P("slate-dark", "Slate Dark", "dark", "#38BDF8", "#0F172A", "#1E293B", "#334155", "#F1F5F9", "#94A3B8", "#0B1120", "#CBD5E1", "#22C55E", "#F59E0B", "#F87171"),
            P("amoled", "AMOLED Black", "dark", "#22D3EE", "#000000", "#0A0A0A", "#262626", "#F5F5F5", "#A3A3A3", "#000000", "#E5E5E5", "#4ADE80", "#FBBF24", "#F87171", "#000000"),
            P("clean-light", "Clean Light", "light", "#2563EB", "#F8FAFC", "#FFFFFF", "#E2E8F0", "#0F172A", "#475569", "#F1F5F9", "#1E293B", "#16A34A", "#B45309", "#DC2626"),
            P("light", "theme.name.light", "light", "#2563EB", "#F2F5FA", "#FFFFFF", "#E1E6EF", "#141C2D", "#647188", "#0D1424", "#C4CDDC", "#16A34A", "#D97706", "#DC2626"),
            P("emerald", "theme.name.emerald", "light", "#059669", "#F0F7F5", "#FFFFFF", "#D5E7E1", "#0F2A24", "#5B746D", "#063B33", "#C6E6DE", "#16A34A", "#D97706", "#DC2626"),
            P("ocean", "theme.name.ocean", "light", "#0891B2", "#EEF6FB", "#FFFFFF", "#D3E5F0", "#0B2534", "#5B7586", "#0B3A53", "#CFE6F2", "#059669", "#D97706", "#DC2626"),
            P("lavender", "theme.name.lavender", "light", "#7C3AED", "#F6F3FF", "#FFFFFF", "#E4DCF7", "#1E1433", "#6B5E86", "#2A1650", "#E2D8FA", "#16A34A", "#D97706", "#DC2626"),
            P("sakura", "Sakura", "light", "#DB2777", "#FFF5F8", "#FFFFFF", "#F5D5E0", "#3B1F2B", "#8A6070", "#4A1D33", "#F9DCE6", "#16A34A", "#D97706", "#DC2626"),
            P("solarized-light", "theme.name.solarizedLight", "light", "#268BD2", "#EEE8D5", "#FDF6E3", "#DDD6C1", "#073642", "#657B83", "#002B36", "#93A1A1", "#859900", "#B58900", "#DC322F"),
            P("latte", "Catppuccin Latte", "light", "#1E66F5", "#EFF1F5", "#FFFFFF", "#CCD0DA", "#4C4F69", "#6C6F85", "#DCE0E8", "#4C4F69", "#40A02B", "#DF8E1D", "#D20F39"),
            P("github-light", "theme.name.githubLight", "light", "#0969DA", "#F6F8FA", "#FFFFFF", "#D0D7DE", "#1F2328", "#656D76", "#24292F", "#E6EDF3", "#1A7F37", "#BF8700", "#CF222E"),

            P("dark", "theme.name.dark", "dark", "#3B82F6", "#111318", "#1B1E25", "#2C313B", "#E6E9F0", "#969EAC", "#0B0D11", "#C9D0DC", "#22C55E", "#F59E0B", "#EF4444"),
            P("github-dark", "theme.name.githubDark", "dark", "#2F81F7", "#0D1117", "#161B22", "#30363D", "#E6EDF3", "#8D96A0", "#010409", "#C9D1D9", "#3FB950", "#D29922", "#F85149"),
            P("nord", "Nord", "dark", "#88C0D0", "#2E3440", "#3B4252", "#4C566A", "#ECEFF4", "#AEB7C6", "#242933", "#D8DEE9", "#A3BE8C", "#EBCB8B", "#BF616A"),
            P("dracula", "Dracula", "dark", "#BD93F9", "#282A36", "#313342", "#44475A", "#F8F8F2", "#A9ADC9", "#21222C", "#E2E2DC", "#50FA7B", "#FFB86C", "#FF5555"),
            P("onedark", "One Dark", "dark", "#61AFEF", "#282C34", "#2F343E", "#3E4451", "#DCDFE4", "#9DA5B4", "#21252B", "#C8CCD4", "#98C379", "#E5C07B", "#E06C75"),
            P("monokai", "Monokai", "dark", "#66D9EF", "#272822", "#31322C", "#49483E", "#F8F8F2", "#B5B19C", "#1E1F1A", "#E0E0D8", "#A6E22E", "#FD971F", "#F92672"),
            P("tokyo", "Tokyo Night", "dark", "#7AA2F7", "#1A1B26", "#24283B", "#343A55", "#C0CAF5", "#9AA5CE", "#16161E", "#A9B1D6", "#9ECE6A", "#E0AF68", "#F7768E"),
            P("mocha", "Catppuccin Mocha", "dark", "#89B4FA", "#1E1E2E", "#282839", "#45475A", "#CDD6F4", "#A6ADC8", "#181825", "#BAC2DE", "#A6E3A1", "#F9E2AF", "#F38BA8"),
            P("gruvbox", "Gruvbox", "dark", "#FE8019", "#282828", "#32302F", "#504945", "#EBDBB2", "#A89984", "#1D2021", "#D5C4A1", "#B8BB26", "#FABD2F", "#FB4934"),
            P("solarized-dark", "theme.name.solarizedDark", "dark", "#268BD2", "#002B36", "#073642", "#0E4A5A", "#EEE8D5", "#93A1A1", "#00212B", "#A9B7B7", "#859900", "#B58900", "#DC322F"),
            P("sunset", "theme.name.sunset", "dark", "#FF7A59", "#1F1A24", "#2A2230", "#3D3245", "#F4E9E1", "#B9A8B5", "#17121B", "#E8D9E0", "#6BCB77", "#FFC75F", "#FF5C7A"),
            P("contrast", "theme.name.contrast", "dark", "#FFD60A", "#000000", "#0B0B0B", "#FFFFFF", "#FFFFFF", "#E0E0E0", "#000000", "#FFFFFF", "#3DFF7A", "#FFB000", "#FF4D4D", "#000000"),
        };

        // ------------------------------------------------------------ system theme

        public static bool SystemDark()
        {
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"))
                    return k != null && Convert.ToInt32(k.GetValue("AppsUseLightTheme", 1)) == 0;
            }
            catch { return false; }
        }

        /// <summary>Windows accent color (a light shade in the dark theme, a dark shade in the light theme).</summary>
        public static Color SystemAccent(bool dark)
        {
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\Accent"))
                {
                    if (k?.GetValue("AccentPalette") is byte[] b && b.Length >= 32)
                    {
                        int i = dark ? 2 : 4;   // AccentLight1 / AccentDark1
                        return Color.FromArgb(b[i * 4], b[i * 4 + 1], b[i * 4 + 2]);
                    }
                }
                using (var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\DWM"))
                {
                    if (k?.GetValue("AccentColor") is int abgr)
                    {
                        var c = Color.FromArgb(abgr & 0xFF, (abgr >> 8) & 0xFF, (abgr >> 16) & 0xFF);
                        return dark ? Theme.Mix(c, Color.White, 0.25f) : c;
                    }
                }
            }
            catch (Exception ign) { App.Ignored("System color could not be read", ign); }
            return dark ? H("#60A5FA") : H("#2563EB");
        }

        public static Palette System()
        {
            if (SystemInformation.HighContrast)
            {
                var hc = new Palette
                {
                    Id = "system", NameKey = "theme.name.systemHc",
                    Accent = SystemColors.Highlight, Bg = SystemColors.Window, Card = SystemColors.Window, Border = SystemColors.WindowText,
                    Text = SystemColors.WindowText, Muted = SystemColors.WindowText, Sidebar = SystemColors.Window, SidebarText = SystemColors.WindowText,
                    Green = H("#3DFF7A"), Amber = H("#FFB000"), Red = H("#FF4D4D"), LogBg = SystemColors.Window,
                };
                return hc;
            }
            bool dark = SystemDark();
            var p = dark
                ? P("system", "theme.name.system", "", "#60A5FA", "#202020", "#2B2B2B", "#3A3A3A", "#FFFFFF", "#ABABAB", "#1B1B1B", "#F0F0F0", "#6CCB5F", "#FCE100", "#FF99A4")
                : P("system", "theme.name.system", "", "#2563EB", "#F3F3F3", "#FFFFFF", "#E5E5E5", "#1A1A1A", "#616161", "#EBEBEB", "#1A1A1A", "#0F7B0F", "#9D5D00", "#C42B1C");
            if (dark) { p.Green = H("#4CC35A"); p.Amber = H("#F2B02F"); p.Red = H("#F1707B"); }
            p.Accent = SystemAccent(dark);
            p.NameKey = dark ? "theme.name.systemDark" : "theme.name.systemLight";
            return p;
        }

        public static Palette Base(string id)
        {
            if (id == "system" || string.IsNullOrEmpty(id)) return System();
            return (Presets.FirstOrDefault(p => p.Id == id) ?? System()).Clone();
        }

        public static bool IsKnown(string id) => id == "system" || Presets.Any(p => p.Id == id);

        /// <summary>The theme in use: the selected one, or with "follow Windows" the light or dark one for the current Windows mode.</summary>
        public static string EffectiveBaseId(AppSettings s, bool systemDark)
        {
            if (!s.FollowSystem) return s.ThemeId;
            string id = systemDark ? s.DarkThemeId : s.LightThemeId;
            return IsKnown(id) ? id : systemDark ? DefaultDarkId : DefaultLightId;
        }

        /// <summary>The theme from the settings + the colors the user changed.</summary>
        public static Palette Resolve(AppSettings s) => Resolve(s, SystemDark());

        public static Palette Resolve(AppSettings s, bool systemDark)
        {
            var p = Base(EffectiveBaseId(s, systemDark));
            foreach (var o in s.ThemeOverrides)
                if (Palette.Keys.Contains(o.Key) && TryParseColor(o.Hex, out var c)) p.Set(o.Key, c);
            if (s.ThemeOverrides.Count > 0) p.Custom = true;
            return p;
        }

        // ------------------------------------------------------------ color code

        public static string Hex(Color c) => "#" + c.R.ToString("X2") + c.G.ToString("X2") + c.B.ToString("X2");

        /// <summary>Accepts #RGB, #RRGGBB, RRGGBB, rgb(r,g,b) or "r,g,b".</summary>
        public static bool TryParseColor(string text, out Color c)
        {
            c = Color.Empty;
            if (string.IsNullOrWhiteSpace(text)) return false;
            string s = text.Trim().ToLowerInvariant();
            if (s.StartsWith("rgb")) s = s.Substring(3).Trim('(', ')', ' ', 'a');
            if (s.Contains(","))
            {
                var parts = s.Split(',').Select(x => x.Trim()).ToArray();
                if (parts.Length < 3) return false;
                if (int.TryParse(parts[0], out int r) && int.TryParse(parts[1], out int g) && int.TryParse(parts[2], out int b) &&
                    r >= 0 && r < 256 && g >= 0 && g < 256 && b >= 0 && b < 256)
                { c = Color.FromArgb(r, g, b); return true; }
                return false;
            }
            s = s.TrimStart('#');
            if (s.Length == 3) s = new string(new[] { s[0], s[0], s[1], s[1], s[2], s[2] });
            if (s.Length == 8) s = s.Substring(2);
            if (s.Length != 6) return false;
            if (!int.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int v)) return false;
            c = Color.FromArgb((v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF);
            return true;
        }
    }

    /// <summary>WCAG 2 contrast check of the color pairs that carry text.</summary>
    static class Wcag
    {
        /// <summary>Level AA for normal text.</summary>
        public const double AA = 4.5;

        public static double Ratio(Color a, Color b) => Theme.Contrast(a, b);

        /// <summary>Text color pairs of a palette (locale key of the pair, foreground, background).</summary>
        public static IEnumerable<(string Pair, Color Fore, Color Back)> Pairs(Palette p)
        {
            yield return ("appearancePage.pair.textBg", p.Text, p.Bg);
            yield return ("appearancePage.pair.textCard", p.Text, p.Card);
            yield return ("appearancePage.pair.mutedCard", p.Muted, p.Card);
            yield return ("appearancePage.pair.button", Theme.On(p.Accent), p.Accent);
            yield return ("appearancePage.pair.sidebar", p.SidebarText, p.Sidebar);
        }

        /// <summary>The pairs below level AA, with their ratio.</summary>
        public static List<(string Pair, double Ratio)> Low(Palette p) =>
            Pairs(p).Select(x => (x.Pair, Ratio(x.Fore, x.Back))).Where(x => x.Item2 < AA).ToList();
    }

    /// <summary>
    /// Custom colors being edited. Changes stay in the draft (the app's theme does not change and nothing is saved)
    /// until Apply; Cancel goes back to the colors in use.
    /// </summary>
    sealed class ThemeDraft
    {
        readonly AppSettings settings;
        readonly bool systemDark;

        /// <summary>The theme the colors are based on (without the user's colors).</summary>
        public Palette Base { get; private set; }
        /// <summary>The draft colors.</summary>
        public Palette Colors { get; private set; }

        public ThemeDraft(AppSettings s, bool systemDark)
        {
            settings = s;
            this.systemDark = systemDark;
            Cancel();
        }

        Palette InUse() => Palettes.Resolve(settings, systemDark);

        public bool Dirty => Colors.ToCode() != InUse().ToCode();

        /// <summary>True if the draft is based on the theme that is selected now.</summary>
        public bool Current => Base.Id == Palettes.EffectiveBaseId(settings, systemDark);

        public void Set(string key, Color c) => Colors.Set(key, c);

        /// <summary>Back to the colors of the theme (the user's colors are removed when applied).</summary>
        public void ResetToBase()
        {
            var b = Base.Clone();
            b.Custom = false;
            Colors = b;
        }

        /// <summary>Drops the changes: the draft is the colors in use again.</summary>
        public void Cancel()
        {
            Base = Palettes.Base(Palettes.EffectiveBaseId(settings, systemDark));
            Colors = InUse();
        }

        /// <summary>The colors that differ from the theme.</summary>
        public List<ThemeColor> Overrides() =>
            Palette.Keys.Where(k => Colors.Get(k).ToArgb() != Base.Get(k).ToArgb())
                        .Select(k => new ThemeColor { Key = k, Hex = Palettes.Hex(Colors.Get(k)) }).ToList();

        /// <summary>Writes the draft into the settings (the caller saves them and applies the theme).</summary>
        public void Apply()
        {
            settings.ThemeOverrides = Overrides();
            Colors = InUse();
        }

        public List<(string Pair, double Ratio)> LowContrast() => Wcag.Low(Colors);
    }
}
