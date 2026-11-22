using System;
using System.Collections.Generic;
using System.Linq;

namespace NSFShield
{
    /// <summary>Detailed, plain-language explanations of the profile options (texts: locales, keys profileHelp.*).</summary>
    static class ProfileHelp
    {
        public sealed class Topic
        {
            public string Title, Text, Flag = "";
        }

        /// <summary>Help topic key used by the editor → (GoodbyeDPI flag shown under the title, locale id).</summary>
        static readonly Dictionary<string, (string Flag, string Id)> Topics = new Dictionary<string, (string, string)>
        {
            ["intro"] = ("", "intro"),
            ["name"] = ("", "name"),
            ["mode"] = ("-1 … -9", "mode"),
            ["mode:"] = ("", "modeNone"),
            ["mode:-1"] = ("-1", "mode1"),
            ["mode:-2"] = ("-2", "mode2"),
            ["mode:-3"] = ("-3", "mode3"),
            ["mode:-4"] = ("-4", "mode4"),
            ["mode:-5"] = ("-5", "mode5"),
            ["mode:-6"] = ("-6", "mode6"),
            ["mode:-7"] = ("-7", "mode7"),
            ["mode:-8"] = ("-8", "mode8"),
            ["mode:-9"] = ("-9", "mode9"),
            ["ttl"] = ("--set-ttl / --auto-ttl", "ttl"),
            ["fakegen"] = ("--fake-gen", "fakegen"),
            ["fakeresend"] = ("--fake-resend", "fakeresend"),
            ["dns"] = ("--dns-addr / --dns-port", "dns"),
            ["dns:custom"] = ("--dns-addr / --dnsv6-addr", "dnsCustom"),
            ["httpsfrag"] = ("-e", "httpsfrag"),
            ["httpfrag"] = ("-f", "httpfrag"),
            ["wrongchk"] = ("--wrong-chksum", "wrongchk"),
            ["wrongseq"] = ("--wrong-seq", "wrongseq"),
            ["native"] = ("--native-frag", "native"),
            ["reverse"] = ("--reverse-frag", "reverse"),
            ["quic"] = ("-q", "quic"),
            ["sni"] = ("--frag-by-sni", "sni"),
            ["payload"] = ("--max-payload", "payload"),
            ["nosni"] = ("--allow-no-sni", "nosni"),
            ["passive"] = ("-p", "passive"),
            ["hostr"] = ("-r", "hostr"),
            ["hosts"] = ("-s", "hosts"),
            ["hostm"] = ("-m", "hostm"),
            ["extra"] = ("", "extra"),
            ["raw"] = ("", "raw"),
            ["preview"] = ("", "preview"),
        };

        /// <summary>The GoodbyeDPI arguments each base mode stands for (first line of the mode help).</summary>
        static readonly Dictionary<string, string> ModeArgs = new Dictionary<string, string>
        {
            ["-1"] = "-p -r -s -f 2 -k 2 -n -e 2",
            ["-2"] = "-p -r -s -f 2 -k 2 -n -e 40",
            ["-3"] = "-p -r -s -e 40",
            ["-4"] = "-p -r -s",
            ["-5"] = "-f 2 -e 2 --auto-ttl --reverse-frag --max-payload",
            ["-6"] = "-f 2 -e 2 --wrong-seq --reverse-frag --max-payload",
            ["-7"] = "-f 2 -e 2 --wrong-chksum --reverse-frag --max-payload",
            ["-8"] = "-f 2 -e 2 --wrong-seq --wrong-chksum --reverse-frag --max-payload",
            ["-9"] = "-f 2 -e 2 --wrong-seq --wrong-chksum --reverse-frag --max-payload -q",
        };

        public static IEnumerable<string> TopicKeys => Topics.Keys;

        static string Text(string id) => Loc.T("profileHelp." + id + ".text");

        public static Topic Get(string key)
        {
            if (key == null || !Topics.TryGetValue(key, out var t)) { key = "intro"; t = Topics[key]; }
            string text = Text(t.Id);
            if (key.StartsWith("mode:-") && ModeArgs.TryGetValue(key.Substring(5), out var args)) text = "= " + args + "\n" + text;
            return new Topic { Flag = t.Flag, Title = Loc.T("profileHelp." + t.Id + ".title"), Text = text };
        }

        static readonly Dictionary<string, string[]> ModeFlags = new Dictionary<string, string[]>
        {
            ["-1"] = new[] { "passive", "hostr", "hosts", "httpfrag2", "httpsfrag2" },
            ["-2"] = new[] { "passive", "hostr", "hosts", "httpfrag2", "httpsfrag40" },
            ["-3"] = new[] { "passive", "hostr", "hosts", "httpsfrag40" },
            ["-4"] = new[] { "passive", "hostr", "hosts" },
            ["-5"] = new[] { "httpfrag2", "httpsfrag2", "autottl", "reverse", "payload" },
            ["-6"] = new[] { "httpfrag2", "httpsfrag2", "wrongseq", "reverse", "payload" },
            ["-7"] = new[] { "httpfrag2", "httpsfrag2", "wrongchk", "reverse", "payload" },
            ["-8"] = new[] { "httpfrag2", "httpsfrag2", "wrongseq", "wrongchk", "reverse", "payload" },
            ["-9"] = new[] { "httpfrag2", "httpsfrag2", "wrongseq", "wrongchk", "reverse", "payload", "quic" },
        };

        static string E(string key, params object[] args) => Loc.T("profileHelp.explain." + key, args);

        /// <summary>Explains everything the profile does, point by point; Warn marks a missing DNS redirection.</summary>
        public static List<(string Title, string Text, bool Warn)> Explain(Profile p)
        {
            if (!p.IsGoodbyeDpi) return EngineHelp.Explain(p).ToList();
            var list = new List<(string, string, bool)>();
            if (p.UseRaw)
            {
                list.Add((E("raw"), E("rawText", p.RawArgs), false));
                list.Add(p.UsesDnsRedirect ? (E("dnsYes"), E("rawDnsYes"), false) : (E("dnsNo"), E("rawDnsNo"), true));
                return list;
            }
            var flags = new HashSet<string>();
            if (!string.IsNullOrEmpty(p.Mode) && ModeFlags.TryGetValue(p.Mode, out var mf)) foreach (var f in mf) flags.Add(f);
            if (p.WrongChksum) flags.Add("wrongchk");
            if (p.WrongSeq) flags.Add("wrongseq");
            if (p.NativeFrag) flags.Add("native");
            if (p.ReverseFrag) flags.Add("reverse");
            if (p.BlockQuic) flags.Add("quic");
            if (p.FragBySni) flags.Add("sni");
            if (p.MaxPayload) flags.Add("payload");
            if (p.PassiveDpi) flags.Add("passive");
            if (p.HostReplace) flags.Add("hostr");
            if (p.HostRemoveSpace) flags.Add("hosts");
            if (p.HostMixCase) flags.Add("hostm");

            // DNS
            if (p.UsesDnsRedirect)
            {
                var prov = DnsProviders.Get(p.Dns);
                list.Add((E("dnsTo", p.DnsLabel),
                    prov != null ? E("dnsToProvider", prov.Name, prov.V4, prov.V4Port) + " " + prov.Note : E("dnsToCustom"), false));
            }
            else
                list.Add((E("dnsNo"), E("dnsNoText"), true));

            if (!string.IsNullOrEmpty(p.Mode) && ModeFlags.ContainsKey(p.Mode))
                list.Add((E("mode", p.Mode), Text(Topics["mode:" + p.Mode].Id), false));

            // fragmentation
            int https = p.HttpsFrag > 0 ? p.HttpsFrag : flags.Contains("httpsfrag2") ? 2 : flags.Contains("httpsfrag40") ? 40 : 0;
            if (https > 0)
                list.Add((E("httpsFrag", https), E(https <= 2 ? "httpsFragSmallText" : "httpsFragText"), false));
            if (flags.Contains("sni")) list.Add((E("sni"), Text("sni"), false));
            if (flags.Contains("reverse")) list.Add((E("reverse"), E("reverseText"), false));
            else if (flags.Contains("native")) list.Add((E("native"), Text("native"), false));

            // fake packets
            bool fake = flags.Contains("wrongseq") || flags.Contains("wrongchk") || flags.Contains("autottl") || p.Ttl.Length > 0 || p.FakeGen > 0;
            if (fake)
            {
                var how = new List<string>();
                if (flags.Contains("autottl") || p.Ttl == "auto") how.Add(E("howAutoTtl"));
                else if (int.TryParse(p.Ttl, out int ttl)) how.Add(E("howTtl", ttl));
                if (flags.Contains("wrongseq")) how.Add(E("howSeq"));
                if (flags.Contains("wrongchk")) how.Add(E("howChk"));
                string count = p.FakeGen > 0 ? E("fakeCount", p.FakeGen) : E("fakeSent");
                list.Add((count + (p.FakeResend > 1 ? E("fakeResend", p.FakeResend) : ""),
                    how.Count > 0 ? E("fakeTextHow", string.Join(", ", how)) : E("fakeText"), false));
            }
            if (flags.Contains("quic")) list.Add((E("quic"), E("quicText"), false));
            if (flags.Contains("passive")) list.Add((E("passive"), Text("passive"), false));
            if (flags.Contains("hostr") || flags.Contains("hosts") || flags.Contains("hostm"))
                list.Add((E("headers"), E("headersText"), false));
            if (flags.Contains("payload")) list.Add((E("payload"), E("payloadText"), false));
            if (!string.IsNullOrWhiteSpace(p.ExtraArgs)) list.Add((Loc.T("profileHelp.extra.title"), p.ExtraArgs, false));
            if (!fake && https == 0 && !flags.Contains("sni") && !flags.Contains("hostr"))
                list.Add((E("noDpi"), E("noDpiText"), false));
            return list;
        }

        public static string WhenToUse(Profile p)
        {
            string W(string key) => Loc.T("profileHelp.when." + key);
            switch (p.Id)
            {
                case "tr-recommended": return W("first");
                case "tr-adguard": case "tr-quad9": case "tr-opendns": return W("dnsAlt");
                case "tr-autottl": return W("autoTtl");
                case "tr-legacy1-dns": case "tr-legacy2-dns": return W("legacy");
                case "tr-e1": case "tr-sni": case "tr-alt": return W("connectionCut");
                case "tr-fakegen": case "tr-resend": return W("unstable");
                case "tr-wrongchk": case "tr-wrongseq": case "tr-mode8": case "tr-native": return W("fakeAlt");
                case "tr-compatible": case "tr-classic2": return W("lastResort");
                case "dns-only": return W("dnsOnly");
                case "legacy-1": case "legacy-2": case "plain": return W("compare");
                case "zapret-discord": return W("zapretFirst");
                case "zapret-aggressive": return W("zapretAggressive");
                case "zapret-tls": return W("zapretTls");
                case "zapret-split": return W("zapretSplit");
                case "byedpi-recommended": return W("byedpiFirst");
                case "byedpi-fake": return W("byedpiFake");
                case "byedpi-tlsrec": case "byedpi-oob": return W("byedpiAlt");
            }
            return p.BuiltIn ? "" : W("custom");
        }
    }
}
