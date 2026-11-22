using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml.Serialization;

namespace NSFShield
{
    public enum DnsChoice { None, Yandex, AdGuard, Custom, AdGuardFree, Quad9, OpenDns, Cloudflare, Google }

    /// <summary>UI detail level. Settings files of version 2 stored the Turkish names (Basit/Orta/Detayli); see <see cref="SettingsSchema"/>.</summary>
    public enum UiLevel { Simple, Standard, Advanced }

    /// <summary>
    /// Catalog layer of a profile: Recommended (built-ins of the "recommended" group: Simple shows them, the scanner tries them
    /// first) or Specialized (the other built-ins and every custom profile: Standard shows them on request, Advanced always).
    /// </summary>
    public enum ProfileTier { Recommended, Specialized }

    /// <summary>A server that GoodbyeDPI's DNS redirection can use.</summary>
    public sealed class DnsProvider
    {
        public DnsChoice Id;
        /// <summary>Brand name (shown as is unless the language file has "dns.provider.&lt;Id&gt;.name").</summary>
        public string Brand;
        public string V4, V6;
        public int V4Port, V6Port;
        string K(string field) => "dns.provider." + Id + "." + field;
        public string Name => Loc.Has(K("name")) ? Loc.T(K("name")) : Brand;
        public string Short => Loc.Has(K("short")) ? Loc.T(K("short")) : Brand + " (" + V4Port + ")";
        public string Note => Loc.T(K("note"));
        public bool StandardPort => V4Port == 53;
        public string Label => Name + " – " + V4 + ":" + V4Port;
    }

    public static class DnsProviders
    {
        public static readonly List<DnsProvider> All = new List<DnsProvider>
        {
            new DnsProvider { Id = DnsChoice.Yandex, Brand = "Yandex", V4 = "77.88.8.8", V4Port = 1253, V6 = "2a02:6b8::feed:0ff", V6Port = 1253 },
            new DnsProvider { Id = DnsChoice.AdGuard, Brand = "AdGuard", V4 = "94.140.14.14", V4Port = 5353, V6 = "2a10:50c0::ad1:ff", V6Port = 5353 },
            new DnsProvider { Id = DnsChoice.AdGuardFree, Brand = "AdGuard", V4 = "94.140.14.140", V4Port = 5353, V6 = "2a10:50c0::1:ff", V6Port = 5353 },
            new DnsProvider { Id = DnsChoice.Quad9, Brand = "Quad9", V4 = "9.9.9.9", V4Port = 9953, V6 = "2620:fe::fe", V6Port = 9953 },
            new DnsProvider { Id = DnsChoice.OpenDns, Brand = "OpenDNS", V4 = "208.67.222.222", V4Port = 5353, V6 = "2620:119:35::35", V6Port = 5353 },
            new DnsProvider { Id = DnsChoice.Cloudflare, Brand = "Cloudflare", V4 = "1.1.1.1", V4Port = 53, V6 = "2606:4700:4700::1111", V6Port = 53 },
            new DnsProvider { Id = DnsChoice.Google, Brand = "Google", V4 = "8.8.8.8", V4Port = 53, V6 = "2001:4860:4860::8888", V6Port = 53 },
        };

        public static DnsProvider Get(DnsChoice c) => All.FirstOrDefault(p => p.Id == c);
    }

    /// <summary>A working method (parameter set) of one engine: GoodbyeDPI (the fields below), Zapret or ByeDPI (<see cref="EngineArgs"/>).</summary>
    public class Profile
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        string name = Loc.T("profiles.newProfile"), description = "";
        /// <summary>Built-in profiles take their name/description from the language file (they follow the UI language).</summary>
        [XmlIgnore] public string NameKey { get; set; }
        [XmlIgnore] public string DescriptionKey { get; set; }
        public string Name { get => NameKey != null ? Loc.T(NameKey) : name; set { name = value; NameKey = null; } }
        public string Description { get => DescriptionKey != null ? Loc.T(DescriptionKey) : description; set { description = value; DescriptionKey = null; } }
        [XmlIgnore] public bool BuiltIn { get; set; }
        [XmlIgnore] public string Group { get; set; } = Profiles.GroupCustom;
        [XmlIgnore] public int Priority { get; set; } = 1000;
        /// <summary>Catalog layer (derived, never saved: never part of settings files or profile codes).</summary>
        [XmlIgnore] public ProfileTier Tier => BuiltIn && Group == Profiles.GroupRecommended ? ProfileTier.Recommended : ProfileTier.Specialized;
        /// <summary>Scenario tags of a built-in profile (texts: "profiles.tag.&lt;tag&gt;"); never saved.</summary>
        [XmlIgnore] public string[] Tags { get; set; } = new string[0];

        /// <summary>"" (none) or "-1" … "-9"</summary>
        public string Mode { get; set; } = "-9";
        public DnsChoice Dns { get; set; } = DnsChoice.Yandex;
        public string CustomDns4 { get; set; } = "";
        public int CustomDns4Port { get; set; } = 53;
        public string CustomDns6 { get; set; } = "";
        public int CustomDns6Port { get; set; } = 53;
        /// <summary>"" off, "auto" automatic, otherwise a number.</summary>
        public string Ttl { get; set; } = "";
        public int HttpFrag { get; set; }
        public int HttpsFrag { get; set; }
        public bool PassiveDpi { get; set; }
        public bool HostReplace { get; set; }
        public bool HostRemoveSpace { get; set; }
        public bool HostMixCase { get; set; }
        public bool WrongChksum { get; set; }
        public bool WrongSeq { get; set; }
        public bool NativeFrag { get; set; }
        public bool ReverseFrag { get; set; }
        public bool BlockQuic { get; set; }
        public bool FragBySni { get; set; }
        public bool MaxPayload { get; set; }
        public bool AllowNoSni { get; set; }
        public int FakeGen { get; set; }
        public int FakeResend { get; set; }
        public string ExtraArgs { get; set; } = "";
        public bool UseRaw { get; set; }
        public string RawArgs { get; set; } = "";
        /// <summary>Engine the profile belongs to. A settings file without this element means GoodbyeDPI.</summary>
        public EngineKind Engine { get; set; } = EngineKind.GoodbyeDpi;
        /// <summary>Parameters of a Zapret / ByeDPI profile (checked against that engine's allow list); not used by GoodbyeDPI.</summary>
        public string EngineArgs { get; set; } = "";

        [XmlIgnore] public bool IsGoodbyeDpi => Engine == EngineKind.GoodbyeDpi;

        /// <summary>Only GoodbyeDPI can redirect DNS; Zapret and ByeDPI use the system DNS (see the DNS page).</summary>
        public bool UsesDnsRedirect =>
            !IsGoodbyeDpi ? false :
            UseRaw ? (RawArgs ?? "").Contains("--dns-addr")
                   : Dns == DnsChoice.Custom ? !string.IsNullOrWhiteSpace(CustomDns4) || !string.IsNullOrWhiteSpace(CustomDns6)
                   : Dns != DnsChoice.None;

        /// <summary>Redirected IPv4 DNS server (null if none).</summary>
        public (string Addr, int Port)? DnsTarget
        {
            get
            {
                if (!IsGoodbyeDpi) return null;
                if (UseRaw)
                {
                    var t = Tokens(RawArgs);
                    int i = t.IndexOf("--dns-addr");
                    if (i < 0 || i + 1 >= t.Count) return null;
                    int port = 53;
                    int j = t.IndexOf("--dns-port");
                    if (j >= 0 && j + 1 < t.Count) int.TryParse(t[j + 1], out port);
                    return (t[i + 1], port);
                }
                if (Dns == DnsChoice.Custom)
                    return string.IsNullOrWhiteSpace(CustomDns4) ? ((string, int)?)null : (CustomDns4.Trim(), CustomDns4Port);
                var p = DnsProviders.Get(Dns);
                return p == null ? ((string, int)?)null : (p.V4, p.V4Port);
            }
        }

        static List<string> Tokens(string s) =>
            (s ?? "").Split(new[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).ToList();

        public string DnsLabel
        {
            get
            {
                if (!IsGoodbyeDpi) return Loc.T("profiles.dnsSystem");
                if (UseRaw) return UsesDnsRedirect ? Loc.T("profiles.dnsManual") : Loc.T("common.off");
                if (Dns == DnsChoice.Custom) return UsesDnsRedirect ? CustomDns4 + ":" + CustomDns4Port : Loc.T("common.off");
                return DnsProviders.Get(Dns)?.Short ?? Loc.T("common.off");
            }
        }

        public string BuildArgs(string blacklistPath)
        {
            var a = new List<string>();
            if (UseRaw)
            {
                if (!string.IsNullOrWhiteSpace(RawArgs)) a.Add(RawArgs.Trim());
            }
            else
            {
                if (!string.IsNullOrEmpty(Mode)) a.Add(Mode);
                if (HttpFrag > 0) a.Add("-f " + HttpFrag);
                if (HttpsFrag > 0) a.Add("-e " + HttpsFrag);
                if (PassiveDpi) a.Add("-p");
                if (HostReplace) a.Add("-r");
                if (HostRemoveSpace) a.Add("-s");
                if (HostMixCase) a.Add("-m");
                if (Ttl == "auto") a.Add("--auto-ttl");
                else if (int.TryParse(Ttl, out int ttl) && ttl > 0) a.Add("--set-ttl " + ttl);
                if (WrongChksum) a.Add("--wrong-chksum");
                if (WrongSeq) a.Add("--wrong-seq");
                if (NativeFrag) a.Add("--native-frag");
                if (ReverseFrag) a.Add("--reverse-frag");
                if (FragBySni) a.Add("--frag-by-sni");
                if (MaxPayload) a.Add("--max-payload");
                if (BlockQuic) a.Add("-q");
                if (FakeGen > 0) a.Add("--fake-gen " + Math.Min(30, FakeGen));
                if (FakeResend > 1) a.Add("--fake-resend " + Math.Min(20, FakeResend));
                if (Dns == DnsChoice.Custom)
                {
                    if (!string.IsNullOrWhiteSpace(CustomDns4))
                        a.Add("--dns-addr " + CustomDns4.Trim() + " --dns-port " + CustomDns4Port);
                    if (!string.IsNullOrWhiteSpace(CustomDns6))
                        a.Add("--dnsv6-addr " + CustomDns6.Trim() + " --dnsv6-port " + CustomDns6Port);
                }
                else
                {
                    var d = DnsProviders.Get(Dns);
                    if (d != null)
                        a.Add("--dns-addr " + d.V4 + " --dns-port " + d.V4Port + " --dnsv6-addr " + d.V6 + " --dnsv6-port " + d.V6Port);
                }
                if (!string.IsNullOrWhiteSpace(ExtraArgs)) a.Add(ExtraArgs.Trim());
            }
            if (blacklistPath != null)
            {
                a.Add("--blacklist \"" + blacklistPath + "\"");
                if (AllowNoSni && !UseRaw) a.Add("--allow-no-sni");
            }
            return string.Join(" ", a);
        }

        public Profile CloneAsCustom()
        {
            var p = (Profile)MemberwiseClone();
            p.Id = Guid.NewGuid().ToString("N");
            p.BuiltIn = false;
            p.Group = Profiles.GroupCustom;
            p.Priority = 1000;
            p.Name = Name + Loc.T("profiles.copySuffix");
            p.Description = Description;
            p.Tags = new string[0];
            return p;
        }

        /// <summary>A frozen copy with the same id (a scan request keeps its candidates even if a profile is edited meanwhile).</summary>
        public Profile Snapshot() => (Profile)MemberwiseClone();

        public override string ToString() => Name;
    }

    public static class Profiles
    {
        /// <summary>Profile group ids (display names: "profiles.group.&lt;id&gt;").</summary>
        public const string GroupCustom = "custom";
        public const string GroupRecommended = "recommended";
        public const string GroupAlt = "alternative";
        public const string GroupNoDns = "nodns";

        public static string GroupName(string group) => Loc.T("profiles.group." + group);

        static int order;
        static Profile B(string id, string group, string nameKey, string descKey, Action<Profile> cfg)
        {
            var p = new Profile { Id = id, BuiltIn = true, Mode = "", Dns = DnsChoice.None, Group = group, Priority = ++order };
            p.NameKey = nameKey;
            p.DescriptionKey = descKey;
            cfg(p);
            return p;
        }

        /// <summary>A built-in Zapret / ByeDPI profile (name and description from "profiles.builtin.&lt;id&gt;.*").</summary>
        static Profile E(EngineKind engine, string id, string group, string args, params string[] tags) =>
            B(id, group, "profiles.builtin." + id + ".name", "profiles.builtin." + id + ".description",
              p => { p.Engine = engine; p.EngineArgs = args; p.Mode = ""; p.Dns = DnsChoice.None; p.Tags = tags; });

        /// <summary>Adds scenario tags to a built-in GoodbyeDPI profile.</summary>
        static Profile T(Profile p, params string[] tags) { p.Tags = tags; return p; }

        /// <summary>Profiles of one engine, in list order.</summary>
        public static IEnumerable<Profile> ForEngine(IEnumerable<Profile> all, EngineKind k) => all.Where(p => p.Engine == k).OrderBy(p => p.Priority);

        // Zapret (winws) for Turkish ISPs: Discord text/voice (UDP 50000-50100: Discord RTC with STUN/IP discovery), QUIC on 443,
        // HTTPS with fake ClientHello + split/disorder. Every preset is checked with "winws --dry-run" by the self-test.
        internal const string ZapretDiscord =
            "--wf-tcp=80,443 --wf-udp=443,50000-50100 " +
            "--filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=quic_initial_www_google_com.bin --new " +
            "--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new " +
            "--filter-tcp=80 --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new " +
            "--filter-tcp=443 --dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,midsld --dpi-desync-repeats=6 " +
            "--dpi-desync-fooling=badseq,md5sig --dpi-desync-fake-tls=tls_clienthello_www_google_com.bin";
        internal const string ZapretAggressive =
            "--wf-tcp=80,443 --wf-udp=443,50000-50100 " +
            "--filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=11 --dpi-desync-fake-quic=quic_initial_www_google_com.bin --new " +
            "--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=11 " +
            "--dpi-desync-fake-discord=discord-ip-discovery-with-port.bin --dpi-desync-fake-stun=stun.bin --new " +
            "--filter-tcp=80 --dpi-desync=fake,fakedsplit --dpi-desync-autottl=2 --dpi-desync-fooling=badseq,md5sig --new " +
            "--filter-tcp=443 --dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,sniext+1,host+1,midsld-2,midsld,midsld+2,endhost-1 " +
            "--dpi-desync-repeats=11 --dpi-desync-fooling=badseq,md5sig --dpi-desync-fake-tls=tls_clienthello_www_google_com.bin " +
            "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com";
        internal const string ZapretTlsOnly =
            "--wf-tcp=443 --filter-tcp=443 --dpi-desync=fake,multisplit --dpi-desync-split-pos=1,midsld --dpi-desync-repeats=6 " +
            "--dpi-desync-fooling=badseq --dpi-desync-fake-tls=tls_clienthello_www_google_com.bin";
        internal const string ZapretSplitOnly =
            "--wf-tcp=80,443 --filter-tcp=80,443 --dpi-desync=multisplit --dpi-desync-split-pos=2,sniext+1";
        // general web (TLS + QUIC) with fake + fakedsplit and an automatic TTL (no Discord voice capture)
        internal const string ZapretGeneral =
            "--wf-tcp=80,443 --wf-udp=443 " +
            "--filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=quic_initial_www_google_com.bin --new " +
            "--filter-tcp=80 --dpi-desync=fake,fakedsplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new " +
            "--filter-tcp=443 --dpi-desync=fake,fakedsplit --dpi-desync-split-pos=1,midsld --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig " +
            "--dpi-desync-fake-tls=tls_clienthello_www_google_com.bin";
        // fake packets with a fixed TTL of 4 (they expire before the server), multisplit at the SNI
        internal const string ZapretFixedTtl =
            "--wf-tcp=80,443 --wf-udp=443 " +
            "--filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-ttl=4 --dpi-desync-fake-quic=quic_initial_www_google_com.bin --new " +
            "--filter-tcp=80,443 --dpi-desync=fake,multisplit --dpi-desync-split-pos=1,sniext+1 --dpi-desync-ttl=4 --dpi-desync-repeats=4 " +
            "--dpi-desync-fake-tls=tls_clienthello_iana_org.bin --dpi-desync-fake-http=http_iana_org.bin";
        // Discord voice first: IP discovery / STUN fakes on the RTC ports, light TCP 443 and QUIC rules
        internal const string ZapretVoice =
            "--wf-tcp=443 --wf-udp=443,50000-50100 " +
            "--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=8 " +
            "--dpi-desync-fake-discord=discord-ip-discovery-without-port.bin --dpi-desync-fake-stun=stun.bin --new " +
            "--filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=quic_initial_facebook_com.bin --new " +
            "--filter-tcp=443 --dpi-desync=fake,multisplit --dpi-desync-split-pos=1,midsld --dpi-desync-fooling=badseq " +
            "--dpi-desync-fake-tls=tls_clienthello_iana_org.bin";
        // the least intervention: only TCP 443, the first segment reordered, no fake packets
        internal const string ZapretLight = "--wf-tcp=443 --filter-tcp=443 --dpi-desync=multidisorder --dpi-desync-split-pos=1";
        // last resort: many fakes with bad sequence/checksum, fakeddisorder on HTTP and TLS, QUIC and Discord voice too
        internal const string ZapretLastResort =
            "--wf-tcp=80,443 --wf-udp=443,50000-50100 " +
            "--filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=20 --dpi-desync-fake-quic=quic_initial_facebook_com.bin --new " +
            "--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=20 " +
            "--dpi-desync-fake-discord=discord-ip-discovery-with-port.bin --dpi-desync-fake-stun=stun.bin --new " +
            "--filter-tcp=80 --dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=method+2 --dpi-desync-repeats=20 " +
            "--dpi-desync-fooling=badseq,badsum --dpi-desync-fake-http=http_iana_org.bin --new " +
            "--filter-tcp=443 --dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=midsld --dpi-desync-repeats=20 " +
            "--dpi-desync-fooling=badseq,badsum --dpi-desync-fake-tls=tls_clienthello_iana_org.bin --dpi-desync-fake-tls-mod=rnd,dupsid";

        // ByeDPI (ciadpi): the Windows settings recommended by its README (split + disorder; disorder + fake), with the
        // automatic fallback (--auto=torst): the next group is tried only when the connection is reset or times out.
        internal const string ByeDpiRecommended = "--split 1+s --disorder 3+s --mod-http=h,d --auto=torst --tlsrec 1+s";
        internal const string ByeDpiFake = "--disorder 1 --fake -1 --ttl 8";
        internal const string ByeDpiTlsrec = "--split 1+s --tlsrec 3+s --auto=torst --timeout 3 --disorder 1 --tlsrec 1+s";
        internal const string ByeDpiOob = "--split 1+s --oob 3+s --auto=torst --disorder 3+s";
        // TLS record splitting only (first at SNI+1, the fallback group at SNI+3)
        internal const string ByeDpiTlsrecOnly = "--tlsrec 1+s --auto=torst --tlsrec 3+s";
        // hybrid OOB: disorder + out-of-band byte with a TLS record split; fallback: OOB at SNI+3 with a record split
        internal const string ByeDpiHybridOob = "--disoob 1 --tlsrec 1+s --auto=torst --oob 3+s --tlsrec 3+s";
        // HTTP and HTTPS separately: the first group only for HTTP (Host header tricks), the second for TLS ("--auto=none":
        // used when the first group was skipped by its protocol filter)
        internal const string ByeDpiHttpHttps = "--proto=http --split 1+h --mod-http=h,d,r --auto=none --proto=tls --split 1+s --disorder 3+s --tlsrec 1+s";

        public static readonly List<Profile> BuiltIns = new List<Profile>
        {
            T(B("tr-recommended", GroupRecommended, "profiles.builtin.tr-recommended.name",
              "profiles.builtin.tr-recommended.description",
              p => { p.Mode = "-9"; p.Dns = DnsChoice.Yandex; }), "discord", "web", "dns"),
            T(B("tr-adguard", GroupRecommended, "profiles.builtin.tr-adguard.name",
              "profiles.builtin.tr-adguard.description",
              p => { p.Mode = "-9"; p.Dns = DnsChoice.AdGuard; }), "discord", "web", "dns"),
            T(B("tr-quad9", GroupRecommended, "profiles.builtin.tr-quad9.name",
              "profiles.builtin.tr-quad9.description",
              p => { p.Mode = "-9"; p.Dns = DnsChoice.Quad9; }), "discord", "web", "dns"),
            T(B("tr-opendns", GroupRecommended, "profiles.builtin.tr-opendns.name",
              "profiles.builtin.tr-opendns.description",
              p => { p.Mode = "-9"; p.Dns = DnsChoice.OpenDns; }), "discord", "web", "dns"),

            B("tr-autottl", GroupAlt, "profiles.builtin.tr-autottl.name",
              "profiles.builtin.tr-autottl.description",
              p => { p.Mode = "-5"; p.Dns = DnsChoice.Yandex; }),
            B("tr-legacy1-dns", GroupAlt, "profiles.builtin.tr-legacy1-dns.name",
              "profiles.builtin.tr-legacy1-dns.description",
              p => { p.Ttl = "3"; p.Dns = DnsChoice.Yandex; }),
            B("tr-legacy2-dns", GroupAlt, "profiles.builtin.tr-legacy2-dns.name",
              "profiles.builtin.tr-legacy2-dns.description",
              p => { p.Mode = "-4"; p.Ttl = "5"; p.Dns = DnsChoice.Yandex; }),
            B("tr-wrongseq", GroupAlt, "profiles.builtin.tr-wrongseq.name",
              "profiles.builtin.tr-wrongseq.description",
              p => { p.Mode = "-6"; p.Dns = DnsChoice.Yandex; }),
            B("tr-wrongchk", GroupAlt, "profiles.builtin.tr-wrongchk.name",
              "profiles.builtin.tr-wrongchk.description",
              p => { p.Mode = "-7"; p.Dns = DnsChoice.Yandex; }),
            B("tr-mode8", GroupAlt, "profiles.builtin.tr-mode8.name",
              "profiles.builtin.tr-mode8.description",
              p => { p.Mode = "-8"; p.Dns = DnsChoice.Yandex; }),
            B("tr-fakegen", GroupAlt, "profiles.builtin.tr-fakegen.name",
              "profiles.builtin.tr-fakegen.description",
              p => { p.Mode = "-9"; p.FakeGen = 5; p.Dns = DnsChoice.Yandex; }),
            B("tr-resend", GroupAlt, "profiles.builtin.tr-resend.name",
              "profiles.builtin.tr-resend.description",
              p => { p.Mode = "-9"; p.FakeGen = 3; p.FakeResend = 3; p.Dns = DnsChoice.Yandex; }),
            B("tr-e1", GroupAlt, "profiles.builtin.tr-e1.name",
              "profiles.builtin.tr-e1.description",
              p => { p.Mode = "-9"; p.HttpsFrag = 1; p.Dns = DnsChoice.Yandex; }),
            B("tr-sni", GroupAlt, "profiles.builtin.tr-sni.name",
              "profiles.builtin.tr-sni.description",
              p => { p.Mode = "-9"; p.FragBySni = true; p.Dns = DnsChoice.Yandex; }),
            B("tr-native", GroupAlt, "profiles.builtin.tr-native.name",
              "profiles.builtin.tr-native.description",
              p => { p.HttpFrag = 2; p.HttpsFrag = 2; p.NativeFrag = true; p.WrongSeq = true; p.WrongChksum = true; p.MaxPayload = true; p.BlockQuic = true; p.Dns = DnsChoice.Yandex; }),
            B("tr-alt", GroupAlt, "profiles.builtin.tr-alt.name",
              "profiles.builtin.tr-alt.description",
              p => { p.Mode = "-5"; p.HttpsFrag = 1; p.BlockQuic = true; p.FakeGen = 5; p.Dns = DnsChoice.Yandex; }),
            B("tr-compatible", GroupAlt, "profiles.builtin.tr-compatible.name",
              "profiles.builtin.tr-compatible.description",
              p => { p.Mode = "-1"; p.Dns = DnsChoice.Yandex; }),
            B("tr-classic2", GroupAlt, "profiles.builtin.tr-classic2.name",
              "profiles.builtin.tr-classic2.description",
              p => { p.Mode = "-2"; p.Dns = DnsChoice.Yandex; }),
            B("dns-only", GroupAlt, "profiles.builtin.dns-only.name",
              "profiles.builtin.dns-only.description",
              p => { p.Dns = DnsChoice.Yandex; }),

            B("legacy-1", GroupNoDns, "profiles.builtin.legacy-1.name",
              "profiles.builtin.legacy-1.description",
              p => { p.Ttl = "3"; }),
            B("legacy-2", GroupNoDns, "profiles.builtin.legacy-2.name",
              "profiles.builtin.legacy-2.description",
              p => { p.Mode = "-4"; p.Ttl = "5"; }),
            B("plain", GroupNoDns, "profiles.builtin.plain.name",
              "profiles.builtin.plain.description",
              p => { p.Mode = "-9"; }),

            E(EngineKind.Zapret, "zapret-discord", GroupRecommended, ZapretDiscord, "discord", "voice", "web", "quic"),
            E(EngineKind.Zapret, "zapret-aggressive", GroupAlt, ZapretAggressive, "aggressive", "try-tt"),
            E(EngineKind.Zapret, "zapret-tls", GroupAlt, ZapretTlsOnly, "tls"),
            E(EngineKind.Zapret, "zapret-split", GroupAlt, ZapretSplitOnly, "nofake", "try-mobile"),

            E(EngineKind.ByeDpi, "byedpi-recommended", GroupRecommended, ByeDpiRecommended, "balanced", "driverless"),
            E(EngineKind.ByeDpi, "byedpi-fake", GroupAlt, ByeDpiFake, "ttl", "driverless"),
            E(EngineKind.ByeDpi, "byedpi-tlsrec", GroupAlt, ByeDpiTlsrec, "nottl", "try-mobile", "driverless"),
            E(EngineKind.ByeDpi, "byedpi-oob", GroupAlt, ByeDpiOob, "oob", "driverless"),

            // appended: the order and ids of the profiles above stay as they were
            E(EngineKind.Zapret, "zapret-general", GroupRecommended, ZapretGeneral, "web", "quic", "try-tt", "try-superonline"),
            E(EngineKind.Zapret, "zapret-ttl", GroupAlt, ZapretFixedTtl, "ttl", "try-vodafone"),
            E(EngineKind.Zapret, "zapret-voice", GroupAlt, ZapretVoice, "voice", "discord"),
            E(EngineKind.Zapret, "zapret-light", GroupAlt, ZapretLight, "light", "nofake", "try-mobile"),
            E(EngineKind.Zapret, "zapret-lastresort", GroupAlt, ZapretLastResort, "lastresort"),
            E(EngineKind.ByeDpi, "byedpi-tlsrec-only", GroupAlt, ByeDpiTlsrecOnly, "tlsrec", "driverless"),
            E(EngineKind.ByeDpi, "byedpi-hybrid-oob", GroupAlt, ByeDpiHybridOob, "oob", "try-superonline", "driverless"),
            E(EngineKind.ByeDpi, "byedpi-http-https", GroupAlt, ByeDpiHttpHttps, "http", "driverless"),
        };
    }

    public class ThemeColor
    {
        public string Key { get; set; }
        public string Hex { get; set; }
    }

    public class DnsBackup
    {
        public string Adapter { get; set; }
        public bool V4Dhcp { get; set; }
        public List<string> V4 { get; set; } = new List<string>();
        public bool V6Dhcp { get; set; }
        public List<string> V6 { get; set; } = new List<string>();
    }

    /// <summary>State of an encrypted DNS entry before NSF Shield changed it (for undo).</summary>
    public class DohBackup
    {
        public string Server { get; set; } = "";
        public bool Existed { get; set; }
        public string Template { get; set; } = "";
        public bool AutoUpgrade { get; set; }
        public bool UdpFallback { get; set; }
    }

    public class AppSettings
    {
        /// <summary>Schema version of the settings file (1 since NSF Shield 1.0.0).</summary>
        public const int SettingsSchemaVersion = 1;
        public int Version { get; set; } = SettingsSchemaVersion;
        /// <summary>UI language: "auto" (Windows language, English if unavailable) or a code from the locales folder.</summary>
        public string Language { get; set; } = Loc.Auto;
        public string SelectedProfileId { get; set; } = "tr-recommended";
        public List<Profile> CustomProfiles { get; set; } = new List<Profile>();
        public bool ServiceMode { get; set; }
        public bool StartWithWindows { get; set; }
        public bool AutoStartProtection { get; set; } = true;
        public bool CloseToTray { get; set; } = true;
        public bool HideFromTaskbar { get; set; } = true;
        public bool AutoRestart { get; set; } = true;
        public bool Notifications { get; set; } = true;
        public bool FlushDns { get; set; } = true;
        public bool TestAfterStart { get; set; } = true;
        public bool SuggestDiscordRestart { get; set; } = true;
        public bool CheckDnsOnStart { get; set; } = true;
        public bool ScanAll { get; set; }
        public bool TargetedMode { get; set; }
        public bool TrayHintShown { get; set; }
        public UiLevel UiLevel { get; set; } = UiLevel.Simple;
        public string ThemeId { get; set; } = "system";
        public List<ThemeColor> ThemeOverrides { get; set; } = new List<ThemeColor>();
        /// <summary>Follow the Windows light/dark mode: LightThemeId in light mode, DarkThemeId in dark mode (ThemeId is not used then).</summary>
        public bool FollowSystem { get; set; }
        public string LightThemeId { get; set; } = Palettes.DefaultLightId;
        public string DarkThemeId { get; set; } = Palettes.DefaultDarkId;
        /// <summary>The one-time "switch to the installed version" notice on the home page was closed.</summary>
        public bool InstallerHintDismissed { get; set; }
        public DateTime? LastScanTime { get; set; }
        public string LastScanResult { get; set; } = "";
        public List<DnsBackup> DnsBackups { get; set; } = new List<DnsBackup>();
        public List<DohBackup> DohBackups { get; set; } = new List<DohBackup>();
        /// <summary>Previous value of the global DoH setting if it was off/automatic before NSF Shield changed it (null if unchanged).</summary>
        public string GlobalDohBackup { get; set; }
        /// <summary>Find a working method by itself when access is lost.</summary>
        public bool AutoHeal { get; set; } = true;
        /// <summary>Connection watchdog interval (minutes, 0 = off, at most <see cref="MaxWatchMinutes"/>).</summary>
        public int WatchMinutes { get; set; } = 15;
        public const int MaxWatchMinutes = 1440;
        public bool Hotkey { get; set; }
        public bool AutoUpdate { get; set; } = true;
        public DateTime? LastUpdateCheck { get; set; }
        public string SkipVersion { get; set; } = "";
        public List<ProxyEntry> Proxies { get; set; } = new List<ProxyEntry>();
        public List<ProxyApp> ProxyApps { get; set; } = new List<ProxyApp>();
        public string SystemProxyId { get; set; } = "";
        public List<string> TargetDomains { get; set; } = new List<string>();
        public List<string> TestHosts { get; set; } = new List<string>();
        /// <summary>Exclude list: these sites are never touched (written to data\lists\exclude.txt while it is on).</summary>
        public bool ExcludeEnabled { get; set; }
        public List<string> ExcludeDomains { get; set; } = new List<string>();
        /// <summary>SOCKS port of ByeDPI on 127.0.0.1 (its HTTP bridge uses the next port).</summary>
        public int ByeDpiPort { get; set; } = ByeDpiNet.DefaultPort;
        /// <summary>Point the Windows proxy setting at ByeDPI while it runs (off: only the programs set on the Proxy page use it).</summary>
        public bool ByeDpiSystemProxy { get; set; } = true;
        /// <summary>The profile last used with each engine (the quick engine switch returns to it).</summary>
        public string LastGoodbyeDpiProfileId { get; set; } = "";
        public string LastZapretProfileId { get; set; } = "";
        public string LastByeDpiProfileId { get; set; } = "";
        /// <summary>
        /// Targets of the smart scanner (host names only, see <see cref="ScanTargets"/>); TestHosts stays the list of the
        /// quick/network test. Empty = not created yet: built once from the valid host names of TestHosts (TestHosts is not changed).
        /// </summary>
        public List<string> TestTargets { get; set; }
        /// <summary>Standard UI: also list the specialized and custom profiles (Advanced always lists them).</summary>
        public bool ShowExpertProfiles { get; set; }
        /// <summary>Candidate scope last chosen in the scan window (Standard / Advanced).</summary>
        public ScanScope ScanScope { get; set; } = ScanScope.Recommended;

        public string LastProfileId(EngineKind k) =>
            k == EngineKind.Zapret ? LastZapretProfileId : k == EngineKind.ByeDpi ? LastByeDpiProfileId : LastGoodbyeDpiProfileId;

        public void RememberProfile(Profile p)
        {
            if (p == null) return;
            if (p.Engine == EngineKind.Zapret) LastZapretProfileId = p.Id;
            else if (p.Engine == EngineKind.ByeDpi) LastByeDpiProfileId = p.Id;
            else LastGoodbyeDpiProfileId = p.Id;
        }

        public static readonly string[] DiscordDomains =
        {
            "discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media",
            "discordcdn.com", "discord.dev", "discord.new", "discord.gift", "discordstatus.com",
            "dis.gd", "discord.co"
        };

        public static readonly string[] DefaultTestHosts =
        {
            "discord.com", "gateway.discord.gg", "cdn.discordapp.com", "media.discordapp.net", "updates.discord.com", "discordapp.com"
        };

        static readonly string[] OldDefaultTestHosts =
        {
            "discord.com", "gateway.discord.gg", "cdn.discordapp.com", "media.discordapp.net"
        };

        public void Normalize()
        {
            if (CustomProfiles == null) CustomProfiles = new List<Profile>();
            if (ThemeOverrides == null) ThemeOverrides = new List<ThemeColor>();
            if (DnsBackups == null) DnsBackups = new List<DnsBackup>();
            if (DohBackups == null) DohBackups = new List<DohBackup>();
            if (Proxies == null) Proxies = new List<ProxyEntry>();
            if (ProxyApps == null) ProxyApps = new List<ProxyApp>();
            if (ExcludeDomains == null) ExcludeDomains = new List<string>();
            Proxies.RemoveAll(p => p == null || (p.Id ?? "").StartsWith("engine:"));   // engine entries are never saved
            ProxyBridge.AssignPorts(Proxies);
            ProxyApps.RemoveAll(a => a == null || string.IsNullOrEmpty(a.ExePath));
            if (SystemProxyId == null) SystemProxyId = "";
            // the watchdog interval becomes milliseconds later: kept to 0 (off) … 24 h
            if (WatchMinutes < 0) WatchMinutes = 0;
            if (WatchMinutes > MaxWatchMinutes) WatchMinutes = MaxWatchMinutes;
            // a proxy entry from a file edited by hand: a usable host/port and a defined type, otherwise it is left out
            Proxies.RemoveAll(p => !ProxyTools.ValidEntry(p, out _));
            if (string.IsNullOrEmpty(ThemeId)) ThemeId = "system";
            if (string.IsNullOrEmpty(LightThemeId)) LightThemeId = Palettes.DefaultLightId;
            if (string.IsNullOrEmpty(DarkThemeId)) DarkThemeId = Palettes.DefaultDarkId;
            if (string.IsNullOrWhiteSpace(Language)) Language = Loc.Auto;
            if (TargetDomains == null || TargetDomains.Count == 0) TargetDomains = DiscordDomains.ToList();
            if (TestHosts == null || TestHosts.Count == 0 || TestHosts.SequenceEqual(OldDefaultTestHosts)) TestHosts = DefaultTestHosts.ToList();
            TargetDomains = Hostlists.Clean(TargetDomains);
            if (TargetDomains.Count == 0) TargetDomains = DiscordDomains.ToList();
            ExcludeDomains = Hostlists.Clean(ExcludeDomains);
            if (ByeDpiPort < 1024 || ByeDpiPort > 65000) ByeDpiPort = ByeDpiNet.DefaultPort;
            if (LastGoodbyeDpiProfileId == null) LastGoodbyeDpiProfileId = "";
            if (LastZapretProfileId == null) LastZapretProfileId = "";
            if (LastByeDpiProfileId == null) LastByeDpiProfileId = "";
            TestHosts = TestHosts.Select(d => d.Trim()).Where(d => d.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            TestTargets = ScanTargets.Init(TestTargets, TestHosts);
            if (!Enum.IsDefined(typeof(ScanScope), ScanScope)) ScanScope = ScanScope.Recommended;
            ThemeOverrides = ThemeOverrides.Where(o => o != null && !string.IsNullOrEmpty(o.Key) && !string.IsNullOrEmpty(o.Hex))
                                           .GroupBy(o => o.Key).Select(g => g.Last()).ToList();
            foreach (var p in CustomProfiles) { p.BuiltIn = false; p.Group = Profiles.GroupCustom; p.Priority = 1000; if (p.EngineArgs == null) p.EngineArgs = ""; }
            if (Version < SettingsSchemaVersion) Version = SettingsSchemaVersion;
        }
    }

    public static class SettingsStore
    {
        static readonly XmlSerializer Ser = new XmlSerializer(typeof(AppSettings));

        public static string FilePath => Path.Combine(App.DataDir, "settings.xml");
        public static bool LastSaveFailed { get; private set; }

        public static AppSettings Load()
        {
            AppSettings s = null;
            try
            {
                if (File.Exists(FilePath))
                {
                    s = ReadFile(FilePath);
                    s.Normalize();   // a file that reads but cannot be normalized counts as corrupt too
                }
            }
            catch (Exception ex)
            {
                s = null;
                try { File.Copy(FilePath, FilePath + ".corrupt", true); } catch (Exception ign) { App.Ignored("Corrupt settings file could not be backed up", ign); }
                App.Log("Settings file could not be read, using defaults: " + ex.Message, LogLevel.Warn);
            }
            if (s == null) { s = new AppSettings(); s.Normalize(); }
            return s;
        }

        /// <summary>Largest settings file that is read (the lists are limited to 5000 names each).</summary>
        public const long MaxFileBytes = 16L * 1024 * 1024;

        /// <summary>
        /// Reads a settings XML file with the bounded reader used for every settings file (load, 2.x migration, import, the
        /// installer switch): size limit before reading, no DTD, no external resolver.
        /// </summary>
        public static System.Xml.Linq.XDocument LoadXml(string path)
        {
            var fi = new FileInfo(path);
            if (fi.Length > MaxFileBytes) throw new InvalidDataException(Loc.T("settings.tooLarge", MaxFileBytes / (1024 * 1024)));
            var rs = new System.Xml.XmlReaderSettings
            {
                DtdProcessing = System.Xml.DtdProcessing.Prohibit, XmlResolver = null,
                MaxCharactersInDocument = MaxFileBytes, MaxCharactersFromEntities = 1024, IgnoreComments = true, IgnoreProcessingInstructions = true,
            };
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var r = System.Xml.XmlReader.Create(fs, rs))
                return System.Xml.Linq.XDocument.Load(r);
        }

        /// <summary>Reads a settings file with the bounded reader.</summary>
        public static AppSettings ReadFile(string path)
        {
            var doc = LoadXml(path);
            using (var r = doc.CreateReader()) return (AppSettings)Ser.Deserialize(r);
        }

        /// <summary>An independent copy of the settings.</summary>
        public static AppSettings Clone(AppSettings s)
        {
            using (var ms = new MemoryStream())
            {
                Ser.Serialize(ms, s);
                ms.Position = 0;
                var c = (AppSettings)Ser.Deserialize(ms);
                c.Normalize();
                return c;
            }
        }

        /// <summary>Backs up the settings to another file (to move them to another computer or to share them).</summary>
        public static void Export(AppSettings s, string path)
        {
            using (var fs = File.Create(path)) Ser.Serialize(fs, s);
        }

        /// <summary>Writes the settings XML to an open stream (the caller chose how the file was created).</summary>
        internal static void Serialize(AppSettings s, Stream to) => Ser.Serialize(to, s);

        /// <summary>Reads and validates a backup file.</summary>
        public static AppSettings Import(string path)
        {
            AppSettings s;
            s = ReadFile(path);
            foreach (var d in (s.TargetDomains ?? new List<string>()).Concat(s.ExcludeDomains ?? new List<string>()))
                if (Hostlists.Normalize(d) == null)
                    throw new InvalidDataException(Loc.T("settings.import.badDomain", ArgPolicy.CleanText(d, 80)));
            // scan targets: the same strict check as a new entry (no URL, port, path, IP, local name)
            foreach (var t in s.TestTargets ?? new List<string>())
                if (!ScanTargets.IsValid(t))
                    throw new InvalidDataException(Loc.T("settings.import.badTarget", ArgPolicy.CleanText(t, 80)));
            if (s.TestTargets != null && s.TestTargets.Count > ScanTargets.MaxTargets)
                throw new InvalidDataException(Loc.T("settings.import.tooManyTargets", ScanTargets.MaxTargets));
            s.Normalize();
            foreach (var p in s.CustomProfiles)
            {
                if (!ArgPolicy.ValidateProfile(p, out string argErr))
                    throw new InvalidDataException(Loc.T("settings.import.unsafeProfile", ArgPolicy.CleanText(p.Name, 80), argErr));
                p.Name = ArgPolicy.CleanText(p.Name, 80);
                p.Description = ArgPolicy.CleanText(p.Description, 600);
            }
            foreach (var a in s.ProxyApps)
                if (CmdLine.HasControlChars(a.ExtraArgs) || CmdLine.HasControlChars(a.ExePath))
                    throw new InvalidDataException(Loc.T("settings.import.badAppRule", ArgPolicy.CleanText(a.Name, 80)));
            foreach (var b in s.DnsBackups)
                foreach (var ip in (b.V4 ?? new List<string>()).Concat(b.V6 ?? new List<string>()))
                    if (!System.Net.IPAddress.TryParse(ip ?? "", out _))
                        throw new InvalidDataException(Loc.T("settings.import.badDns", ArgPolicy.CleanText(ip, 60)));
            return s;
        }

        /// <summary>Save requests (counted in the preview too: the self-test checks that rebuilding a page writes nothing).</summary>
        internal static int SaveRequests;

        static readonly object saveGate = new object();

        /// <summary>
        /// Saves the settings: one writer at a time (a lock), a unique temporary file in the same folder that then replaces the
        /// file in one step. Returns false (and reports NSF-104) when it failed, so a caller that must not go on without the saved
        /// state (e.g. the Windows proxy backup of ByeDPI) can stop.
        /// </summary>
        public static bool Save(AppSettings s) => SaveTo(s, FilePath);

        internal static bool SaveTo(AppSettings s, string path)
        {
            SaveRequests++;
            if (App.Preview && path == FilePath) return true;
            lock (saveGate)
            {
                string tmp = path + "." + Guid.NewGuid().ToString("N").Substring(0, 8) + ".tmp";
                try
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(path));
                    using (var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    {
                        Ser.Serialize(fs, s);
                        fs.Flush(true);
                    }
                    // the new file must be one the next start can read: within the size limit of LoadXml and readable by the
                    // same bounded reader; otherwise the previous (valid) settings file stays and the caller gets false
                    long len = new FileInfo(tmp).Length;
                    if (len > MaxFileBytes) throw new InvalidDataException(Loc.T("settings.tooLarge", MaxFileBytes / (1024 * 1024)));
                    ReadFile(tmp);
                    if (File.Exists(path)) File.Replace(tmp, path, null);
                    else File.Move(tmp, path);
                    if (LastSaveFailed && path == FilePath) App.Problems.Clear("NSF-104");
                    if (path == FilePath) LastSaveFailed = false;
                    return true;
                }
                catch (Exception ex)
                {
                    try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
                    if (path == FilePath)
                    {
                        LastSaveFailed = true;
                        App.Log("Settings could not be saved: " + ex.Message, LogLevel.Error);
                        App.Problems.Report("NSF-104", ex.Message);
                    }
                    return false;
                }
            }
        }
    }

    public static class Domains
    {
        public static string Clean(string input)
        {
            if (input == null) return null;
            string s = input.Trim().ToLowerInvariant();
            int i = s.IndexOf("://", StringComparison.Ordinal);
            if (i >= 0) s = s.Substring(i + 3);
            i = s.IndexOfAny(new[] { '/', '?', '#', ':' });
            if (i >= 0) s = s.Substring(0, i);
            if (s.StartsWith("*.")) s = s.Substring(2);
            s = s.Trim('.');
            if (s.Length < 3 || !s.Contains(".")) return null;
            foreach (char c in s)
                if (!(char.IsLetterOrDigit(c) || c == '-' || c == '.')) return null;
            try { s = new IdnMapping().GetAscii(s); } catch { return null; }
            return s;
        }

        public static string HostOf(string hostOrUrl)
        {
            if (string.IsNullOrEmpty(hostOrUrl)) return hostOrUrl;
            if (hostOrUrl.Contains("://")) { try { return new Uri(hostOrUrl).Host; } catch { } }
            return hostOrUrl;
        }

        /// <summary>Is the host one of the domains in the target list, or a subdomain of one?</summary>
        public static bool Covered(string host, IEnumerable<string> list)
        {
            host = (HostOf(host) ?? "").ToLowerInvariant();
            return list.Any(d => host == d || host.EndsWith("." + d));
        }
    }
}
