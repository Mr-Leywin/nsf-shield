using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Xml;

namespace NSFShield
{
    /// <summary>
    /// Profile codes for sharing a method with friends.
    /// <para><b>NSF1</b> (the only format): <c>NSF1:</c> + Base64(raw Deflate(UTF-8 XML)). The XML document is
    /// <c>&lt;profile version="1" engine="goodbyedpi|zapret|byedpi"&gt;</c> with at most one of each child element, no
    /// attributes besides these two, no DTD, no other content:</para>
    /// <list type="bullet">
    /// <item><c>name</c>, <c>description</c> (text; cleaned on import, default: "Imported profile" / empty)</item>
    /// <item>Zapret / ByeDPI: <c>args</c> (required) – the logical method arguments as stored by the app (payload and list
    /// names such as <c>tls_clienthello_www_google_com.bin</c> or <c>include.txt</c>, never a local path)</item>
    /// <item>GoodbyeDPI raw mode: <c>raw</c> (required, alone); structured mode: <c>mode</c> ("" or -1…-9, default ""),
    /// <c>dns</c> (None, Yandex, AdGuard, AdGuardFree, Quad9, OpenDns, Cloudflare, Google, Custom; default None),
    /// <c>dns4</c>/<c>dns6</c> (default ""), <c>dns4port</c>/<c>dns6port</c> (1–65535, default 53), <c>ttl</c> ("", "auto" or
    /// 1–255, default ""), <c>httpfrag</c>/<c>httpsfrag</c>/<c>fakegen</c>/<c>fakeresend</c> (0–65535, default 0),
    /// <c>flags</c> (space separated, each once: passive hostreplace hostremovespace hostmixcase wrongchksum wrongseq
    /// nativefrag reversefrag blockquic fragbysni maxpayload allownosni; default none), <c>extra</c> (extra arguments, default "").</item>
    /// </list>
    /// <para>Never shared: settings, the selected profile, the catalog layer, the local id, the real command line, executable
    /// paths, proxy secrets, the listen port or the content of the site lists.</para>
    /// <para>A code of another version (<c>NSF2:</c>…) is refused as unsupported.</para>
    /// <para>Limits (checked before any copy, decoding or decompression): pasted text 128 Ki characters,
    /// compressed data 64 KiB, decompressed XML 64 KiB (read incrementally).</para>
    /// </summary>
    public static class ProfileCode
    {
        public const int MaxInputChars = 128 * 1024;
        public const int MaxCompressedBytes = 64 * 1024;
        public const int MaxXmlBytes = 64 * 1024;
        /// <summary>The longest Base64 text that can hold <see cref="MaxCompressedBytes"/>.</summary>
        public const int MaxBase64Chars = (MaxCompressedBytes + 2) / 3 * 4;
        public const string Tag = "NSF";
        public const int Version = 1;
        public const string Prefix = "NSF1:";

        static readonly string[] FlagNames =
            { "passive", "hostreplace", "hostremovespace", "hostmixcase", "wrongchksum", "wrongseq", "nativefrag", "reversefrag", "blockquic", "fragbysni", "maxpayload", "allownosni" };

        static string EngineName(EngineKind k) => k == EngineKind.Zapret ? "zapret" : k == EngineKind.ByeDpi ? "byedpi" : "goodbyedpi";

        // ------------------------------------------------------------------ writing

        /// <summary>The NSF1 code of a profile; throws <see cref="InvalidDataException"/> (with a translated message) if it cannot be shared.</summary>
        public static string ToCode(Profile p)
        {
            if (!TryToCode(p, out string code, out string err)) throw new InvalidDataException(err);
            return code;
        }

        /// <summary>
        /// Writes an NSF1 code. The profile must pass its engine's allow list; the code must stay within every limit and is read
        /// back with the same reader before it is returned (the writer never produces a code its own reader refuses).
        /// </summary>
        public static bool TryToCode(Profile p, out string code, out string error)
        {
            code = null;
            if (!ArgPolicy.ValidateProfile(p, out string argErr)) { error = Loc.T("profiles.code.unsafe", argErr); return false; }
            byte[] xml = WriteXml(p, true);
            if (xml.Length > MaxXmlBytes) { error = Loc.T("profiles.code.tooLarge"); return false; }
            byte[] packed = Deflate(xml);
            if (packed.Length > MaxCompressedBytes) { error = Loc.T("profiles.code.tooLarge"); return false; }
            string c = Prefix + Convert.ToBase64String(packed);
            if (!TryFromCode(c, out var back, out string rerr)) { error = rerr; return false; }
            if (!SameMethod(p, back)) { error = Loc.T("profiles.code.roundTrip"); return false; }
            code = c;
            error = "";
            return true;
        }

        /// <summary>Same engine and the same validated engine arguments (the profile id and name do not matter).</summary>
        public static bool SameMethod(Profile a, Profile b) =>
            a != null && b != null && a.Engine == b.Engine && MethodArgs(a) == MethodArgs(b);

        /// <summary>The method as the engine would run it, without lists, port or paths.</summary>
        public static string MethodArgs(Profile p) => Engines.Of(p).BuildArgs(p, new ListBinding(), true);

        static byte[] Deflate(byte[] data)
        {
            using (var ms = new MemoryStream())
            {
                using (var z = new DeflateStream(ms, CompressionLevel.Optimal, true)) z.Write(data, 0, data.Length);
                return ms.ToArray();
            }
        }

        static string XmlText(string s, int max, bool clean = true)
        {
            s = clean ? ArgPolicy.CleanText(s, max) : s ?? "";
            var sb = new StringBuilder(s.Length);
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (char.IsHighSurrogate(c) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { sb.Append(c).Append(s[++i]); continue; }
                sb.Append(char.IsSurrogate(c) || !XmlConvert.IsXmlChar(c) ? '?' : c);
            }
            return sb.ToString();
        }

        static byte[] WriteXml(Profile p, bool clean)
        {
            var ws = new XmlWriterSettings { Encoding = new UTF8Encoding(false), OmitXmlDeclaration = true, Indent = false, NewLineHandling = NewLineHandling.Entitize };
            using (var ms = new MemoryStream())
            {
                using (var w = XmlWriter.Create(ms, ws))
                {
                    w.WriteStartElement("profile");
                    w.WriteAttributeString("version", Version.ToString(CultureInfo.InvariantCulture));
                    w.WriteAttributeString("engine", EngineName(p.Engine));
                    w.WriteElementString("name", XmlText(p.Name, 80, clean));
                    string d = XmlText(p.Description, 600, clean);
                    if (d.Length > 0) w.WriteElementString("description", d);
                    if (!p.IsGoodbyeDpi) w.WriteElementString("args", XmlText(p.EngineArgs, 8000));
                    else if (p.UseRaw) w.WriteElementString("raw", XmlText(p.RawArgs, 8000));
                    else
                    {
                        w.WriteElementString("mode", p.Mode ?? "");
                        w.WriteElementString("dns", p.Dns.ToString());
                        if (p.Dns == DnsChoice.Custom)
                        {
                            if (!string.IsNullOrWhiteSpace(p.CustomDns4)) { w.WriteElementString("dns4", p.CustomDns4.Trim()); w.WriteElementString("dns4port", p.CustomDns4Port.ToString(CultureInfo.InvariantCulture)); }
                            if (!string.IsNullOrWhiteSpace(p.CustomDns6)) { w.WriteElementString("dns6", p.CustomDns6.Trim()); w.WriteElementString("dns6port", p.CustomDns6Port.ToString(CultureInfo.InvariantCulture)); }
                        }
                        if (!string.IsNullOrEmpty(p.Ttl)) w.WriteElementString("ttl", p.Ttl);
                        void N(string n, int v) { if (v != 0) w.WriteElementString(n, v.ToString(CultureInfo.InvariantCulture)); }
                        N("httpfrag", p.HttpFrag); N("httpsfrag", p.HttpsFrag); N("fakegen", p.FakeGen); N("fakeresend", p.FakeResend);
                        var flags = new List<string>();
                        bool[] on = { p.PassiveDpi, p.HostReplace, p.HostRemoveSpace, p.HostMixCase, p.WrongChksum, p.WrongSeq, p.NativeFrag, p.ReverseFrag, p.BlockQuic, p.FragBySni, p.MaxPayload, p.AllowNoSni };
                        for (int i = 0; i < FlagNames.Length; i++) if (on[i]) flags.Add(FlagNames[i]);
                        if (flags.Count > 0) w.WriteElementString("flags", string.Join(" ", flags));
                        if (!string.IsNullOrWhiteSpace(p.ExtraArgs)) w.WriteElementString("extra", XmlText(p.ExtraArgs, 8000));
                    }
                    w.WriteEndElement();
                }
                return ms.ToArray();
            }
        }

        // ------------------------------------------------------------------ reading

        static bool IsB64(char c) => (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';

        /// <summary>Finds the codes in a pasted text (version, Base64 text); null when a code is longer than any valid one.</summary>
        static List<(int Version, string B64)> Find(string text, out bool tooLarge)
        {
            tooLarge = false;
            var found = new List<(int, string)>();
            int i = 0;
            while (i <= text.Length - 5)
            {
                int a = text.IndexOf(Tag, i, StringComparison.OrdinalIgnoreCase);
                if (a < 0 || a > text.Length - 5) break;
                char v = text[a + 3];
                if (v >= '0' && v <= '9' && text[a + 4] == ':')
                {
                    int s = a + 5, e = s;
                    while (e < text.Length && IsB64(text[e]))
                    {
                        e++;
                        if (e - s > MaxBase64Chars) { tooLarge = true; return found; }
                    }
                    found.Add((v - '0', text.Substring(s, e - s)));
                    i = e;
                }
                else i = a + 3;
            }
            return found;
        }

        /// <summary>Inflates at most <see cref="MaxXmlBytes"/> bytes (incrementally; a larger result is refused without being read).</summary>
        static byte[] Inflate(byte[] packed, out bool tooLarge)
        {
            tooLarge = false;
            using (var src = new MemoryStream(packed))
            using (var z = new DeflateStream(src, CompressionMode.Decompress))
            using (var o = new MemoryStream())
            {
                var buf = new byte[4096];
                int n;
                while ((n = z.Read(buf, 0, buf.Length)) > 0)
                {
                    if (o.Length + n > MaxXmlBytes) { tooLarge = true; return null; }
                    o.Write(buf, 0, n);
                }
                return o.ToArray();
            }
        }

        /// <summary>A document type declaration anywhere in the text (UTF-8 or UTF-16) is refused before parsing.</summary>
        static bool HasDoctype(byte[] xml)
        {
            foreach (var enc in new Encoding[] { new UTF8Encoding(false), Encoding.Unicode, Encoding.BigEndianUnicode })
            {
                string t;
                try { t = enc.GetString(xml); } catch { continue; }
                if (t.IndexOf("<!DOCTYPE", StringComparison.OrdinalIgnoreCase) >= 0 || t.IndexOf("<!ENTITY", StringComparison.OrdinalIgnoreCase) >= 0) return true;
            }
            return false;
        }

        static XmlReaderSettings ReaderSettings() => new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = MaxXmlBytes,
            MaxCharactersFromEntities = 0,
            IgnoreComments = true,
            IgnoreWhitespace = true,
            IgnoreProcessingInstructions = true,
            CloseInput = true,
        };

        /// <summary>
        /// Reads one profile code from a pasted text (the code may be inside a share message). The profile
        /// gets a new custom id, a cleaned name and description, and must pass its engine's allow list; nothing is saved here.
        /// </summary>
        public static bool TryFromCode(string text, out Profile p, out string error)
        {
            p = null;
            error = "";
            if (text == null || text.Length == 0) { error = Loc.T("profiles.code.noCode"); return false; }
            if (text.Length > MaxInputChars) { error = Loc.T("profiles.code.tooLong", MaxInputChars / 1024); return false; }
            var codes = Find(text, out bool big);
            if (big) { error = Loc.T("profiles.code.tooLarge"); return false; }
            if (codes.Count == 0) { error = Loc.T("profiles.code.noCode"); return false; }
            if (codes.Any(c => c.Version != codes[0].Version || c.B64 != codes[0].B64)) { error = Loc.T("profiles.code.multiple"); return false; }
            var (ver, b64) = codes[0];
            if (ver != Version) { error = Loc.T("profiles.code.unsupportedVersion", ver.ToString(CultureInfo.InvariantCulture)); return false; }
            if (b64.Length == 0) { error = Loc.T("profiles.code.empty"); return false; }

            byte[] packed, xml;
            try { packed = Convert.FromBase64String(b64); }
            catch (FormatException) { error = Loc.T("profiles.code.corrupt"); return false; }
            if (packed.Length > MaxCompressedBytes) { error = Loc.T("profiles.code.tooLarge"); return false; }
            try { xml = Inflate(packed, out big); }
            catch (Exception) { error = Loc.T("profiles.code.corrupt"); return false; }
            if (big) { error = Loc.T("profiles.code.tooLarge"); return false; }
            if (xml.Length == 0) { error = Loc.T("profiles.code.empty"); return false; }
            if (HasDoctype(xml)) { error = Loc.T("profiles.code.dtd"); return false; }

            try
            {
                using (var r = XmlReader.Create(new MemoryStream(xml), ReaderSettings()))
                    p = ReadDocument(r, out error);
            }
            catch (XmlException ex) when (ex.Message.IndexOf("DTD", StringComparison.OrdinalIgnoreCase) >= 0) { error = Loc.T("profiles.code.dtd"); return false; }
            catch (InvalidOperationException ex) when (ex.InnerException is XmlException xe && xe.Message.IndexOf("DTD", StringComparison.OrdinalIgnoreCase) >= 0) { error = Loc.T("profiles.code.dtd"); return false; }
            catch (Exception) { error = Loc.T("profiles.code.corrupt"); return false; }
            if (p == null) { if (error.Length == 0) error = Loc.T("profiles.code.empty"); return false; }

            if (!ArgPolicy.ValidateProfile(p, out string argErr)) { error = Loc.T("profiles.code.unsafe", argErr); p = null; return false; }
            p.Id = Guid.NewGuid().ToString("N");
            p.BuiltIn = false;
            p.Group = Profiles.GroupCustom;
            p.Priority = 1000;
            p.Tags = new string[0];
            p.NameKey = p.DescriptionKey = null;
            p.Name = ArgPolicy.CleanText(p.Name, 80);
            p.Description = ArgPolicy.CleanText(p.Description, 600);
            if (string.IsNullOrWhiteSpace(p.Name)) p.Name = Loc.T("profiles.importedName");
            return true;
        }

        /// <summary>Reads past the root's end: true only if nothing but whitespace follows up to the end of the document.</summary>
        static bool AtDocumentEnd(XmlReader r)
        {
            while (r.Read())
            {
                if (r.NodeType == XmlNodeType.Whitespace || r.NodeType == XmlNodeType.SignificantWhitespace) continue;
                if (r.NodeType == XmlNodeType.Text && string.IsNullOrWhiteSpace(r.Value)) continue;
                return false;
            }
            return r.EOF;
        }

        /// <summary>The strict reader: known elements only, each at most once, no attributes besides version/engine.</summary>
        static Profile ReadDocument(XmlReader r, out string error)
        {
            error = "";
            r.MoveToContent();
            if (r.NodeType != XmlNodeType.Element || r.Name != "profile") { error = Loc.T("profiles.code.corrupt"); return null; }
            string version = null, engine = null;
            if (r.HasAttributes)
                while (r.MoveToNextAttribute())
                {
                    if (r.Name == "version" && version == null) version = r.Value;
                    else if (r.Name == "engine" && engine == null) engine = r.Value;
                    else { error = Loc.T("profiles.code.unknownField", r.Name); return null; }
                }
            r.MoveToElement();
            if (version != "1") { error = Loc.T("profiles.code.unsupportedVersion", version ?? "?"); return null; }
            if (engine == null) { error = Loc.T("profiles.code.noEngine"); return null; }
            EngineKind kind;
            if (engine == "goodbyedpi") kind = EngineKind.GoodbyeDpi;
            else if (engine == "zapret") kind = EngineKind.Zapret;
            else if (engine == "byedpi") kind = EngineKind.ByeDpi;
            else { error = Loc.T("profiles.code.unknownEngine", engine); return null; }

            var f = new Dictionary<string, string>(StringComparer.Ordinal);
            if (!r.IsEmptyElement)
            {
                r.Read();
                while (r.NodeType != XmlNodeType.EndElement)
                {
                    // whitespace between the fields (a long run can come as a text node even with IgnoreWhitespace)
                    if ((r.NodeType == XmlNodeType.Text || r.NodeType == XmlNodeType.Whitespace || r.NodeType == XmlNodeType.SignificantWhitespace) && string.IsNullOrWhiteSpace(r.Value))
                    {
                        if (!r.Read()) { error = Loc.T("profiles.code.corrupt"); return null; }
                        continue;
                    }
                    if (r.NodeType != XmlNodeType.Element) { error = Loc.T("profiles.code.corrupt"); return null; }
                    string n = r.Name;
                    if (r.HasAttributes) { error = Loc.T("profiles.code.unknownField", n + "@"); return null; }
                    if (f.ContainsKey(n)) { error = Loc.T("profiles.code.duplicateField", n); return null; }
                    f[n] = r.ReadElementContentAsString();   // nested elements throw: refused as corrupt
                }
            }
            // after </profile> only whitespace may follow up to the end of the document: a second root or any trailing data is refused
            if (!AtDocumentEnd(r)) { error = Loc.T("profiles.code.trailing"); return null; }

            var gd = new[] { "mode", "dns", "dns4", "dns4port", "dns6", "dns6port", "ttl", "httpfrag", "httpsfrag", "fakegen", "fakeresend", "flags", "extra" };
            string[] allowed = kind != EngineKind.GoodbyeDpi ? new[] { "name", "description", "args" }
                             : f.ContainsKey("raw") ? new[] { "name", "description", "raw" } : new[] { "name", "description" }.Concat(gd).ToArray();
            foreach (var k in f.Keys)
                if (!allowed.Contains(k))
                {
                    bool known = k == "raw" || k == "args" || gd.Contains(k);
                    error = known ? Loc.T("profiles.code.conflicting", k) : Loc.T("profiles.code.unknownField", k);
                    return null;
                }

            // code defaults (not the defaults of a new profile in the editor)
            var p = new Profile { Engine = kind, Mode = "", Dns = DnsChoice.None, EngineArgs = "", CustomDns4Port = 53, CustomDns6Port = 53 };
            p.Name = f.TryGetValue("name", out var nm) ? nm : "";
            p.Description = f.TryGetValue("description", out var ds) ? ds : "";
            if (kind != EngineKind.GoodbyeDpi)
            {
                if (!f.TryGetValue("args", out var a) || string.IsNullOrWhiteSpace(a)) { error = Loc.T("profiles.code.missingField", "args"); return null; }
                p.EngineArgs = a;
                return p;
            }
            if (f.TryGetValue("raw", out var raw))
            {
                if (string.IsNullOrWhiteSpace(raw)) { error = Loc.T("profiles.code.missingField", "raw"); return null; }
                p.UseRaw = true;
                p.RawArgs = raw;
                return p;
            }
            bool Num(string key, int min, int max, int def, out int v)
            {
                v = def;
                if (!f.TryGetValue(key, out var s)) return true;
                return int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out v) && v >= min && v <= max;
            }
            if (f.TryGetValue("mode", out var mode))
            {
                if (!(mode.Length == 0 || (mode.Length == 2 && mode[0] == '-' && mode[1] >= '1' && mode[1] <= '9'))) { error = Loc.T("profiles.code.badValue", "mode", mode); return null; }
                p.Mode = mode;
            }
            if (f.TryGetValue("dns", out var dns))
            {
                if (!Enum.GetNames(typeof(DnsChoice)).Contains(dns)) { error = Loc.T("profiles.code.badValue", "dns", dns); return null; }
                p.Dns = (DnsChoice)Enum.Parse(typeof(DnsChoice), dns);
            }
            p.CustomDns4 = f.TryGetValue("dns4", out var d4) ? d4 : "";
            p.CustomDns6 = f.TryGetValue("dns6", out var d6) ? d6 : "";
            if ((p.CustomDns4.Length > 0 || p.CustomDns6.Length > 0) && p.Dns != DnsChoice.Custom) { error = Loc.T("profiles.code.conflicting", "dns4/dns6"); return null; }
            if (!Num("dns4port", 1, 65535, 53, out int p4)) { error = Loc.T("profiles.code.badValue", "dns4port", f["dns4port"]); return null; }
            if (!Num("dns6port", 1, 65535, 53, out int p6)) { error = Loc.T("profiles.code.badValue", "dns6port", f["dns6port"]); return null; }
            p.CustomDns4Port = p4;
            p.CustomDns6Port = p6;
            if (f.TryGetValue("ttl", out var ttl))
            {
                bool okTtl = ttl == "auto" || (int.TryParse(ttl, NumberStyles.None, CultureInfo.InvariantCulture, out int tv) && tv >= 1 && tv <= 255 && tv.ToString(CultureInfo.InvariantCulture) == ttl);
                if (!okTtl) { error = Loc.T("profiles.code.badValue", "ttl", ttl); return null; }
                p.Ttl = ttl;
            }
            foreach (var key in new[] { "httpfrag", "httpsfrag", "fakegen", "fakeresend" })
                if (!Num(key, 0, 65535, 0, out _)) { error = Loc.T("profiles.code.badValue", key, f[key]); return null; }
            Num("httpfrag", 0, 65535, 0, out int hf); p.HttpFrag = hf;
            Num("httpsfrag", 0, 65535, 0, out int sf); p.HttpsFrag = sf;
            Num("fakegen", 0, 65535, 0, out int fg); p.FakeGen = fg;
            Num("fakeresend", 0, 65535, 0, out int fr); p.FakeResend = fr;
            if (f.TryGetValue("flags", out var flags))
            {
                var seen = new HashSet<string>();
                foreach (var fl in flags.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    int idx = Array.IndexOf(FlagNames, fl);
                    if (idx < 0) { error = Loc.T("profiles.code.badFlag", fl); return null; }
                    if (!seen.Add(fl)) { error = Loc.T("profiles.code.duplicateField", fl); return null; }
                    switch (idx)
                    {
                        case 0: p.PassiveDpi = true; break;
                        case 1: p.HostReplace = true; break;
                        case 2: p.HostRemoveSpace = true; break;
                        case 3: p.HostMixCase = true; break;
                        case 4: p.WrongChksum = true; break;
                        case 5: p.WrongSeq = true; break;
                        case 6: p.NativeFrag = true; break;
                        case 7: p.ReverseFrag = true; break;
                        case 8: p.BlockQuic = true; break;
                        case 9: p.FragBySni = true; break;
                        case 10: p.MaxPayload = true; break;
                        case 11: p.AllowNoSni = true; break;
                    }
                }
            }
            p.ExtraArgs = f.TryGetValue("extra", out var ex) ? ex : "";
            return p;
        }

#if PREVIEW
        /// <summary>Self-test only: an NSF1 code written without the allow list or text cleaning – to test the reader's refusals.</summary>
        public static string ToCodeUnchecked(Profile p) => Prefix + Convert.ToBase64String(Deflate(WriteXml(p, false)));

        /// <summary>Self-test only: packs any XML text as a code of the given version (raw Deflate; optionally stored blocks only).</summary>
        public static string PackRaw(int version, byte[] xml, bool stored = false)
        {
            byte[] packed;
            if (stored)
            {
                var o = new MemoryStream();
                for (int i = 0; i < xml.Length || i == 0; i += 65535)
                {
                    int n = Math.Min(65535, xml.Length - i);
                    bool last = i + n >= xml.Length;
                    o.WriteByte((byte)(last ? 1 : 0));
                    o.WriteByte((byte)n); o.WriteByte((byte)(n >> 8));
                    o.WriteByte((byte)~n); o.WriteByte((byte)(~n >> 8));
                    o.Write(xml, i, n);
                    if (last) break;
                }
                packed = o.ToArray();
            }
            else packed = Deflate(xml);
            return Tag + version + ":" + Convert.ToBase64String(packed);
        }
#endif
    }
}
