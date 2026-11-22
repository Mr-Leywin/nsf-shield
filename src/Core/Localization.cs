using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Web.Script.Serialization;

namespace NSFShield
{
    /// <summary>
    /// UI localisation backed by UTF-8 JSON files in the "locales" folder (en.json is the reference and fallback).
    /// Nested objects are flattened to dotted keys ("home.start"); arrays of strings are allowed for list values.
    /// Translations are display text only: they must never be used to build command lines or service arguments.
    /// </summary>
    public static class Loc
    {
        public const string Auto = "auto";
        public const string FallbackCode = "en";
        const long MaxFileBytes = 4 * 1024 * 1024;
        const string EmbeddedFallback = "NSFShield.locales.en.json";

        public sealed class Language
        {
            public string Code, Name, NativeName, Path;
            public string Label => string.IsNullOrEmpty(NativeName) || NativeName == Name ? Name : NativeName + " (" + Name + ")";
            public override string ToString() => Label;
        }

        static readonly object gate = new object();
        static Dictionary<string, object> active = new Dictionary<string, object>(StringComparer.Ordinal);
        static Dictionary<string, object> fallback = new Dictionary<string, object>(StringComparer.Ordinal);
        static List<Language> languages = new List<Language>();
        static CultureInfo culture = CultureInfo.InvariantCulture;

        /// <summary>Folder scanned for *.json language files (defaults to "locales" next to the executable).</summary>
        public static string Dir { get; set; } = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "locales");

        /// <summary>Code of the language currently in use ("en", "tr", …).</summary>
        public static string Current { get; private set; } = FallbackCode;

        /// <summary>Raised after the active language changed (on the thread that called <see cref="SetLanguage"/>).</summary>
        public static event Action Changed;

        /// <summary>Languages found in the locales folder, ordered by English name.</summary>
        public static IReadOnlyList<Language> Languages { get { lock (gate) return languages.ToList(); } }

        /// <summary>Formatting culture of the active language (numbers and dates in translated text).</summary>
        public static CultureInfo Culture => culture;

        // ------------------------------------------------------------------ loading

        /// <summary>Discovers the available languages and activates the one chosen by <paramref name="setting"/>.</summary>
        public static void Init(string setting)
        {
            Discover();
            Activate(Resolve(setting, Languages.Select(l => l.Code).ToList(), CultureInfo.CurrentUICulture));
        }

        /// <summary>Scans the locales folder. Files that are unreadable, too large or lack a valid "_meta" block are skipped.</summary>
        public static void Discover()
        {
            var found = new List<Language>();
            try
            {
                if (Directory.Exists(Dir))
                {
                    foreach (var file in Directory.GetFiles(Dir, "*.json").OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
                    {
                        var map = TryLoadFile(file);
                        if (map == null) continue;
                        string code = Str(map, "_meta.code").Trim().ToLowerInvariant();
                        if (!ValidCode(code) || found.Any(l => l.Code == code)) continue;
                        found.Add(new Language
                        {
                            Code = code, Path = file,
                            Name = Str(map, "_meta.name").Trim().Length > 0 ? Str(map, "_meta.name").Trim() : code,
                            NativeName = Str(map, "_meta.nativeName").Trim(),
                        });
                    }
                }
            }
            catch (Exception ex) { App.Ignored("Locales folder could not be scanned", ex); }
            if (!found.Any(l => l.Code == FallbackCode))
                found.Add(new Language { Code = FallbackCode, Name = "English", NativeName = "English", Path = null });
            lock (gate) languages = found.OrderBy(l => l.Name, StringComparer.OrdinalIgnoreCase).ToList();
        }

        static bool ValidCode(string code) =>
            code.Length >= 2 && code.Length <= 12 && code.All(c => (c >= 'a' && c <= 'z') || c == '-');

        /// <summary>
        /// Picks the language for a setting: an explicit available code, otherwise ("auto" or unknown) the Windows UI
        /// language when it is available, otherwise English.
        /// </summary>
        public static string Resolve(string setting, ICollection<string> available, CultureInfo uiCulture)
        {
            string s = (setting ?? "").Trim().ToLowerInvariant();
            if (s.Length > 0 && s != Auto && available.Contains(s)) return s;
            string sys = "";
            try { sys = (uiCulture ?? CultureInfo.CurrentUICulture).TwoLetterISOLanguageName.ToLowerInvariant(); } catch { }
            if (sys.Length > 0 && available.Contains(sys)) return sys;
            return FallbackCode;
        }

        /// <summary>Changes the language at run time ("auto" or a code) and notifies the UI.</summary>
        public static void SetLanguage(string setting)
        {
            Discover();
            Activate(Resolve(setting, Languages.Select(l => l.Code).ToList(), CultureInfo.CurrentUICulture));
            Changed?.Invoke();
        }

        static void Activate(string code)
        {
            var fb = LoadFallback();
            Dictionary<string, object> act = fb;
            if (code != FallbackCode)
            {
                var lang = Languages.FirstOrDefault(l => l.Code == code);
                act = lang?.Path != null ? TryLoadFile(lang.Path) : null;
                if (act == null) { code = FallbackCode; act = fb; }
            }
            CultureInfo ci;
            try { ci = CultureInfo.GetCultureInfo(code); } catch { ci = CultureInfo.InvariantCulture; }
            lock (gate)
            {
                fallback = fb;
                active = act;
                culture = ci;
                Current = code;
            }
        }

        static Dictionary<string, object> LoadFallback()
        {
            var lang = Languages.FirstOrDefault(l => l.Code == FallbackCode);
            var map = lang?.Path != null ? TryLoadFile(lang.Path) : null;
            if (map != null) return map;
            // the English reference is also embedded in the executable, so the UI stays readable without the folder
            try
            {
                using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream(EmbeddedFallback))
                    if (s != null)
                        using (var r = new StreamReader(s, Encoding.UTF8))
                            return Parse(r.ReadToEnd());
            }
            catch (Exception ex) { App.Ignored("Embedded English strings could not be read", ex); }
            return new Dictionary<string, object>(StringComparer.Ordinal);
        }

        static Dictionary<string, object> TryLoadFile(string path)
        {
            try
            {
                var fi = new FileInfo(path);
                if (!fi.Exists || fi.Length > MaxFileBytes) return null;
                return Parse(File.ReadAllText(path, Encoding.UTF8));
            }
            catch (Exception ex) { App.Ignored("Language file skipped (" + System.IO.Path.GetFileName(path) + ")", ex); return null; }
        }

        /// <summary>Parses a language file and flattens it: {"a":{"b":"x"}} becomes "a.b" → "x"; string arrays become string[].</summary>
        public static Dictionary<string, object> Parse(string json)
        {
            var root = new JavaScriptSerializer { MaxJsonLength = (int)MaxFileBytes }.DeserializeObject(json) as Dictionary<string, object>;
            if (root == null) throw new FormatException("A language file must contain a JSON object.");
            var flat = new Dictionary<string, object>(StringComparer.Ordinal);
            Flatten(root, "", flat, 0);
            return flat;
        }

        static void Flatten(Dictionary<string, object> obj, string prefix, Dictionary<string, object> into, int depth)
        {
            if (depth > 16) return;
            foreach (var kv in obj)
            {
                string key = prefix.Length == 0 ? kv.Key : prefix + "." + kv.Key;
                switch (kv.Value)
                {
                    case string s: into[key] = s; break;
                    case Dictionary<string, object> d: Flatten(d, key, into, depth + 1); break;
                    case IEnumerable list when !(kv.Value is string):
                        into[key] = list.Cast<object>().Select(o => o as string ?? "").ToArray();
                        break;
                }
            }
        }

        static string Str(Dictionary<string, object> map, string key) =>
            map.TryGetValue(key, out var v) && v is string s ? s : "";

        // ------------------------------------------------------------------ lookup

        /// <summary>Translated text for <paramref name="key"/> (active language, then English, then the key itself).</summary>
        public static string T(string key, params object[] args)
        {
            Dictionary<string, object> act, fb;
            CultureInfo ci;
            lock (gate) { act = active; fb = fallback; ci = culture; }
            string text = act.TryGetValue(key, out var v) && v is string s ? s : null;
            string fbText = fb.TryGetValue(key, out var f) && f is string fs ? fs : null;
            if (text == null) { text = fbText ?? key; ci = CultureInfo.InvariantCulture; }
            if (args == null || args.Length == 0) return text;
            return SafeFormat(text, fbText, ci, args);
        }

        /// <summary>English text for <paramref name="key"/> (used where the same message also goes to the log).</summary>
        public static string En(string key, params object[] args)
        {
            Dictionary<string, object> fb;
            lock (gate) fb = fallback;
            string text = fb.TryGetValue(key, out var f) && f is string fs ? fs : key;
            return args == null || args.Length == 0 ? text : SafeFormat(text, null, CultureInfo.InvariantCulture, args);
        }

        /// <summary>List value (e.g. the steps of an error code); falls back to English per key.</summary>
        public static string[] List(string key)
        {
            Dictionary<string, object> act, fb;
            lock (gate) { act = active; fb = fallback; }
            if (act.TryGetValue(key, out var v) && v is string[] a) return a;
            if (fb.TryGetValue(key, out var f) && f is string[] b) return b;
            return new string[0];
        }

        public static bool Has(string key)
        {
            lock (gate) return active.ContainsKey(key) || fallback.ContainsKey(key);
        }

        /// <summary>string.Format that never throws: a broken translation falls back to English, then to the raw text.</summary>
        public static string SafeFormat(string text, string fallbackText, CultureInfo ci, object[] args)
        {
            try { return string.Format(ci, text, args); }
            catch (FormatException)
            {
                if (fallbackText != null && !ReferenceEquals(fallbackText, text))
                    try { return string.Format(CultureInfo.InvariantCulture, fallbackText, args); } catch (FormatException) { }
                return text + " (" + string.Join(", ", args.Select(a => Convert.ToString(a, CultureInfo.InvariantCulture))) + ")";
            }
        }

        /// <summary>All keys of a parsed language file (tests and tooling).</summary>
        internal static IEnumerable<string> Keys(Dictionary<string, object> map) => map.Keys.Where(k => !k.StartsWith("_meta.", StringComparison.Ordinal));

#if PREVIEW
        /// <summary>Test hook: activates in-memory language data without touching the disk.</summary>
        internal static void DebugUse(string code, Dictionary<string, object> act, Dictionary<string, object> fb)
        {
            lock (gate) { active = act; fallback = fb; Current = code; culture = CultureInfo.InvariantCulture; }
        }
#endif
    }

    /// <summary>A message that is rendered in the current UI language when shown (so it follows live language changes).</summary>
    public sealed class LocText
    {
        public readonly string Key;
        public readonly object[] Args;
        public LocText(string key, params object[] args) { Key = key; Args = args ?? new object[0]; }
        public string Text => Loc.T(Key, Args.Select(a => a is LocText l ? (object)l.Text : a).ToArray());
        public string English => Loc.En(Key, Args.Select(a => a is LocText l ? (object)l.English : a).ToArray());
        public override string ToString() => Text;
    }
}
