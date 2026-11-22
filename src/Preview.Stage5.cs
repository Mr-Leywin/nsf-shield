#if PREVIEW
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;

namespace NSFShield
{
    /// <summary>
    /// stage 5 screenshots (EN/TR, fixed example data): the Find Problems rows of the conflict diagnosis, the home page
    /// information card, the access-denied case, the network change note, the NSF1 share message and the import confirmation.
    /// </summary>
    static partial class Preview
    {
        /// <summary>A fixed system view for the screenshots (nothing is read from this computer).</summary>
        sealed class SampleSource : IConflictSource
        {
            public ConflictContext Ctx = new ConflictContext();
            public List<ProcEntry> Procs = new List<ProcEntry>();
            public Dictionary<string, ScmEntry> Services = new Dictionary<string, ScmEntry>(StringComparer.OrdinalIgnoreCase);
            public List<AdapterInfo> Ads = new List<AdapterInfo>();
            public int? Best;
            public ConflictContext Context() => Ctx;
            public List<ProcEntry> Processes(IEnumerable<string> names) { var n = names.ToList(); return Procs.Where(p => n.Contains(p.Name, StringComparer.OrdinalIgnoreCase)).ToList(); }
            public ScmEntry Service(string name) => Services.TryGetValue(name, out var e) ? e : new ScmEntry { Name = name, Read = ScmRead.NotFound };
            public List<AdapterInfo> Adapters() => Ads;
            public int? BestRouteIndex() => Best;
        }

        const string SampleDir = @"C:\Program Files\NSF Shield";

        static SampleSource BaseSample()
        {
            var s = new SampleSource();
            s.Ctx.BaseDir = SampleDir;
            foreach (var f in new[] { @"\bin\x86_64\goodbyedpi.exe", @"\bin\zapret\winws.exe", @"\bin\byedpi\ciadpi.exe" }) s.Ctx.OwnExes.Add(SampleDir + f);
            s.Ctx.OwnPids.Add(4120);
            s.Ctx.Running = Engines.Zapret;
            s.Ctx.ByeDpiAvailable = true;
            return s;
        }

        static ScmEntry Entry(string name, uint type, uint state, string image = "") => new ScmEntry { Name = name, Read = ScmRead.Ok, Type = type, State = state, ImagePath = image };

        /// <summary>Find Problems: own engine, another copy, WinDivert entries, an active anti-cheat driver with the card, VPN route.</summary>
        static ConflictReport DiagSample()
        {
            var s = BaseSample();
            s.Procs.Add(new ProcEntry { Name = "winws", Pid = 4120, Path = SampleDir + @"\bin\zapret\winws.exe" });
            s.Procs.Add(new ProcEntry { Name = "goodbyedpi", Pid = 7344, Path = @"D:\Tools\GoodbyeDPI\x86_64\goodbyedpi.exe" });
            s.Services["WinDivert"] = Entry("WinDivert", 1, 4, @"\??\" + SampleDir + @"\bin\zapret\WinDivert64.sys");
            s.Services["WinDivert14"] = Entry("WinDivert14", 1, 1, @"\??\D:\Tools\GoodbyeDPI\x86_64\WinDivert64.sys");
            s.Services["vgk"] = Entry("vgk", 1, 4, @"system32\drivers\vgk.sys");
            s.Services["EasyAntiCheat"] = Entry("EasyAntiCheat", 0x10, 1);
            s.Ads.Add(new AdapterInfo { Name = "Ethernet", Description = "Realtek PCIe GbE", IfIndex = 6, V4 = { "192.168.1.20" }, Gateways = { "192.168.1.1" } });
            s.Ads.Add(new AdapterInfo { Name = "CloudflareWARP", Description = "Cloudflare WARP Interface Tunnel", IfIndex = 21, IsVpn = true, V4 = { "172.16.0.2" } });
            s.Best = 21;
            s.Services["CloudflareWARP"] = Entry("CloudflareWARP", 0x10, 4);
            return Conflicts.Evaluate(s);
        }

        /// <summary>The access-denied case: entries and processes that could not be read are shown as such, never as "not found".</summary>
        static ConflictReport AccessSample()
        {
            var s = BaseSample();
            s.Ctx.Running = Engines.GoodbyeDpi;
            s.Procs.Add(new ProcEntry { Name = "winws", Pid = 9032, Path = null, AccessDenied = true });
            s.Services["WinDivert"] = new ScmEntry { Name = "WinDivert", Read = ScmRead.AccessDenied, Win32Error = 5 };
            s.Services["vgk"] = new ScmEntry { Name = "vgk", Read = ScmRead.AccessDenied, Win32Error = 5 };
            s.Services["BEDaisy"] = new ScmEntry { Name = "BEDaisy", Read = ScmRead.AccessDenied, Win32Error = 5 };
            s.Services["FACEIT"] = Entry("FACEIT", 1, 1, @"system32\drivers\FACEIT.sys");
            s.Ads.Add(new AdapterInfo { Name = "Wi-Fi", Description = "Intel Wi-Fi 6E AX211", IfIndex = 9, V4 = { "192.168.0.14" }, Gateways = { "192.168.0.1" } });
            return Conflicts.Evaluate(s);
        }

        static List<CheckItem> Items(ConflictReport r) =>
            new List<CheckItem> { new CheckItem { TitleValue = new LocText("diag.admin.title"), Status = CheckStatus.Ok, DetailValue = new LocText("diag.admin.ok"), Code = "NSF-101" } }
            .Concat(Diagnostics.ConflictItems(r, false).Select(x => new CheckItem { TitleValue = x.Title, Status = x.Status, DetailValue = x.Detail, Code = x.Code })).ToList();

        [DllImport("user32.dll")] static extern bool EnumThreadWindows(int threadId, EnumWindowsProc cb, IntPtr l);
        delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassName(IntPtr h, StringBuilder sb, int n);
        [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
        [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out RECT r);
        [DllImport("user32.dll")] static extern bool PostMessage(IntPtr h, int msg, IntPtr w, IntPtr l);
        [DllImport("user32.dll")] static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
        [DllImport("user32.dll")] static extern int GetWindowThreadProcessId(IntPtr h, out int pid);
        [DllImport("kernel32.dll")] static extern int GetCurrentThreadId();
        [StructLayout(LayoutKind.Sequential)] struct RECT { public int Left, Top, Right, Bottom; }

        /// <summary>
        /// Shows the app's real message box (the existing confirmation window), captures it and answers it with No / OK – so an
        /// import confirmation shown here changes nothing.
        /// </summary>
        static DialogResult ShotMessageBox(IWin32Window owner, string text, MessageBoxButtons buttons, MessageBoxIcon icon, string path)
        {
            // a background watcher finds the box of this process, captures it and always answers it (No / OK): it never hangs
            int me = System.Diagnostics.Process.GetCurrentProcess().Id;
            bool done = false;
            var watcher = new System.Threading.Thread(() =>
            {
                var sw = System.Diagnostics.Stopwatch.StartNew();
                while (!done && sw.ElapsedMilliseconds < 20000)
                {
                    System.Threading.Thread.Sleep(300);
                    IntPtr dlg = IntPtr.Zero;
                    EnumWindows((h, l) =>
                    {
                        GetWindowThreadProcessId(h, out int pid);
                        if (pid != me || !IsWindowVisible(h)) return true;
                        var sb = new StringBuilder(64);
                        GetClassName(h, sb, 64);
                        if (sb.ToString() == "#32770") { dlg = h; return false; }
                        return true;
                    }, IntPtr.Zero);
                    if (dlg == IntPtr.Zero) continue;
                    System.Threading.Thread.Sleep(400);   // fully painted
                    try
                    {
                        GetWindowRect(dlg, out var r);
                        using (var bmp = new Bitmap(Math.Max(1, r.Right - r.Left), Math.Max(1, r.Bottom - r.Top)))
                        {
                            using (var g = Graphics.FromImage(bmp))
                            {
                                IntPtr hdc = g.GetHdc();
                                PrintWindow(dlg, hdc, 2);
                                g.ReleaseHdc(hdc);
                            }
                            bmp.Save(path);
                        }
                    }
                    catch (Exception ex) { File.WriteAllText(path + ".error.txt", ex.ToString()); }
                    finally
                    {
                        const int WM_COMMAND = 0x0111, IDOK = 1, IDNO = 7;
                        PostMessage(dlg, WM_COMMAND, (IntPtr)(buttons == MessageBoxButtons.YesNo ? IDNO : IDOK), IntPtr.Zero);
                    }
                    return;
                }
            }) { IsBackground = true };
            watcher.Start();
            var res = MessageBox.Show(owner, text, App.Name, buttons, icon);
            done = true;
            return res;
        }

        /// <summary>The network change note as the tray shows it (the live Windows notification itself cannot be captured here).</summary>
        static void ShotNetNotice(NetState s, string path)
        {
            var (title, text) = MainForm.NetNotice(s);
            int w = NSFShield.Theme.D(380), h = NSFShield.Theme.D(104);
            using (var bmp = new Bitmap(w, h))
            using (var g = Graphics.FromImage(bmp))
            {
                g.Clear(NSFShield.Theme.Card);
                using (var pen = new Pen(NSFShield.Theme.Border)) g.DrawRectangle(pen, 0, 0, w - 1, h - 1);
                using (var ic = IconArt.AppIcon(32)) g.DrawIcon(ic, new Rectangle(NSFShield.Theme.D(14), NSFShield.Theme.D(16), NSFShield.Theme.D(24), NSFShield.Theme.D(24)));
                TextRenderer.DrawText(g, App.Name, NSFShield.Theme.Small, new Point(NSFShield.Theme.D(48), NSFShield.Theme.D(14)), NSFShield.Theme.Muted);
                TextRenderer.DrawText(g, title, NSFShield.Theme.Bold, new Point(NSFShield.Theme.D(48), NSFShield.Theme.D(36)), NSFShield.Theme.Text);
                TextRenderer.DrawText(g, text, NSFShield.Theme.Body, new Rectangle(NSFShield.Theme.D(48), NSFShield.Theme.D(58), w - NSFShield.Theme.D(60), NSFShield.Theme.D(40)),
                                      NSFShield.Theme.Text, TextFormatFlags.WordBreak | TextFormatFlags.NoPrefix);
                bmp.Save(path);
            }
        }

        public static void Stage5Shots(MainForm form, string dir)
        {
            string sel = App.Settings.SelectedProfileId;
            bool hint = App.Settings.InstallerHintDismissed;
            App.Settings.InstallerHintDismissed = true;
            App.Problems.ClearWhere(e => true);
            foreach (var lang in new[] { "en", "tr" })
            {
                Loc.SetLanguage(lang);
                string tag = "s5_" + lang;
                SystemDns.Publish(SampleNet());

                // Find Problems: the conflict diagnosis rows (Standard)
                App.Settings.SelectedProfileId = "zapret-discord";
                App.Engine.DebugSet(EngineState.Running, BI("zapret-discord"));
                var diag = DiagSample();
                Conflicts.DebugSet(diag);
                Theme(form, "system", UiLevel.Standard);
                form.Go<TroublePage>("trouble")?.DebugShow(Items(diag));
                Shot(form, Path.Combine(dir, tag + "_trouble_diag.png"));
                // the home page card (an active anti-cheat driver next to Zapret: ByeDPI explained, the profile page can be opened)
                foreach (var lvl in new[] { UiLevel.Simple, UiLevel.Standard })
                {
                    Theme(form, "system", lvl);
                    form.Navigate("home");
                    Shot(form, Path.Combine(dir, tag + "_" + lvl.ToString().ToLowerInvariant() + "_home_card.png"));
                }

                // access denied: "could not be checked", never "not found"; the card without the ByeDPI switch (32-bit example)
                var acc = AccessSample();
                Conflicts.DebugSet(acc);
                App.Engine.DebugSet(EngineState.Running, BI("tr-recommended"));
                Theme(form, "system", UiLevel.Standard);
                form.Go<TroublePage>("trouble")?.DebugShow(Items(acc));
                Shot(form, Path.Combine(dir, tag + "_trouble_access.png"));
                var s32 = BaseSample();
                s32.Ctx.Running = Engines.GoodbyeDpi;
                s32.Ctx.ByeDpiAvailable = false;
                s32.Ctx.ByeDpiWhy = Engines.Unavailable64(Engines.ByeDpi);
                s32.Services["vgk"] = Entry("vgk", 1, 4);
                Conflicts.DebugSet(Conflicts.Evaluate(s32));
                Theme(form, "system", UiLevel.Simple);
                form.Navigate("home");
                Shot(form, Path.Combine(dir, tag + "_simple_home_card_nobyedpi.png"));
                Conflicts.DebugSet(null);

                // network change: the note and the home page with the new DNS chip
                var now = new NetState { Online = true, AdapterId = "{eth}", AdapterName = "Ethernet", AdapterType = Loc.T("net.adapter.wired"), RouteKnown = true, Candidates = 2, DnsChoice = "cloudflare", Doh = DohState.Configured };
                SystemDns.Publish(now);
                ShotNetNotice(now, Path.Combine(dir, tag + "_net_notice.png"));
                ShotNetNotice(new NetState { Online = false, DnsChoice = "auto" }, Path.Combine(dir, tag + "_net_notice_offline.png"));
                // a Zapret profile uses the Windows DNS, so the DNS chip shows the new network's setting
                App.Settings.SelectedProfileId = "zapret-general";
                App.Engine.DebugSet(EngineState.Running, BI("zapret-general"));
                Theme(form, "system", UiLevel.Standard);
                form.Navigate("home");
                Shot(form, Path.Combine(dir, tag + "_standard_home_netchanged.png"));

                // NSF1: the share message and the import confirmation (answered "No": nothing is added)
                var share = BI("byedpi-hybrid-oob").CloneAsCustom();
                string code = ProfileCode.ToCode(share);
                ShotMessageBox(form, ProfilesPage.CopiedText(share, code), MessageBoxButtons.OK, MessageBoxIcon.Information, Path.Combine(dir, tag + "_nsf1_copied.png"));
                int before = App.Settings.CustomProfiles.Count;
                if (ProfileCode.TryFromCode(code, out var imp, out _))
                {
                    var r = ShotMessageBox(form, ProfilesPage.ImportConfirmText(imp), MessageBoxButtons.YesNo, MessageBoxIcon.Question, Path.Combine(dir, tag + "_nsf1_import_confirm.png"));
                    if (r == DialogResult.Yes) App.Settings.CustomProfiles.Add(imp);   // never reached: the capture answers "No"
                }
                if (App.Settings.CustomProfiles.Count != before) throw new InvalidOperationException("the import preview changed the profile list");
            }
            SystemDns.Publish(SampleNet());
            App.Settings.InstallerHintDismissed = hint;
            App.Settings.SelectedProfileId = sel;
            App.Engine.DebugSet(EngineState.Running, App.SelectedProfile);
            Loc.SetLanguage(App.Settings.Language);
        }

        /// <summary>The network picture of every other screenshot (deterministic: nothing is read in PREVIEW).</summary>
        static NetState SampleNet() => new NetState { Online = true, AdapterId = "{eth}", AdapterName = "Ethernet", RouteKnown = true, Candidates = 1, DnsChoice = "auto", Doh = DohState.Unknown };
    }
}
#endif
