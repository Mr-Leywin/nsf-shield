#if PREVIEW
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace NSFShield
{
    /// <summary>
    /// --uicheck &lt;dir&gt;: visual and behaviour checks with real WinForms windows (offline, nothing on the system changes):
    /// the profile box of the Home page (running, selected, old id, engine split, Rebuild), the closed text of every themed box
    /// compared between PrintWindow and the normal screen painting, scrolling in a short work area at 100 % and 150 % (wheel and
    /// scroll bar), and the reachability of every control on every page and dialog. The report is &lt;dir&gt;\uicheck.txt; the exit
    /// code is 0 only for a complete, non-empty run without failures.
    /// </summary>
    static partial class Preview
    {
        [DllImport("user32.dll")] static extern IntPtr SendMessage(IntPtr h, int msg, IntPtr w, IntPtr l);
        [DllImport("user32.dll")] static extern IntPtr WindowFromPoint(Point p);
        [DllImport("user32.dll")] static extern IntPtr GetAncestor(IntPtr h, uint flags);
        [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr h);
        [DllImport("user32.dll")] static extern IntPtr GetDC(IntPtr h);
        [DllImport("user32.dll")] static extern int ReleaseDC(IntPtr h, IntPtr dc);
        [DllImport("gdi32.dll")] static extern bool BitBlt(IntPtr dst, int x, int y, int w, int h, IntPtr src, int sx, int sy, int rop);

        const int WM_MOUSEWHEEL = 0x020A, WM_VSCROLL = 0x0115, SB_PAGEDOWN = 3, SB_BOTTOM = 7;

        static readonly List<string> uiReport = new List<string>();
        static int uiOk, uiFail;
        static string uiDir;

        static void UiCheckResult(string name, bool pass, string detail = "")
        {
            if (pass) uiOk++; else uiFail++;
            uiReport.Add((pass ? "OK   " : "FAIL ") + name + (string.IsNullOrEmpty(detail) ? "" : " – " + detail));
        }

        static readonly Rectangle NormalWork = new Rectangle(0, 0, 1920, 1032);
        /// <summary>A short work area with the full design width (Home must scroll vertically only).</summary>
        static Rectangle ShortWork(float scale) => scale > 1.2f ? new Rectangle(0, 0, 1920, 816) : new Rectangle(0, 0, 1366, 560);
        /// <summary>A short and narrow work area (the worst case for reaching every control).</summary>
        static Rectangle SmallWork(float scale) => scale > 1.2f ? new Rectangle(0, 0, 1366, 728) : new Rectangle(0, 0, 1024, 560);

        public static int UiCheck(MainForm first, string dir)
        {
            uiDir = dir;
            Directory.CreateDirectory(dir);
            foreach (var old in Directory.GetFiles(dir, "u7_*.png")) File.Delete(old);
            var keepLang = App.Settings.Language;
            bool keepHint = App.Settings.InstallerHintDismissed;
            try
            {
                first.Dispose();
                // the preview runs as a portable copy: its one-time "switch to the installed version" banner is closed here, so the
                // checks decide when a banner is shown (NSF-104)
                App.Settings.InstallerHintDismissed = true;
                Fake();
                SystemDns.Publish(SampleNet());
                foreach (var scale in new[] { 1f, 1.5f })
                {
                    SetScale(scale);
                    foreach (var lang in new[] { "en", "tr" })
                    {
                        HomeBox(lang, scale);
                        ThemedBoxes(lang, scale);
                        Scrolling(lang, scale);
                        Reachability(lang, scale);
                    }
                }
            }
            catch (Exception ex)
            {
                UiCheckResult("the UI check ran to the end", false, ex.GetType().Name + ": " + ex.Message + " | " + ex.StackTrace);
            }
            finally
            {
                SetScale(1f);
                App.Settings.InstallerHintDismissed = keepHint;
                MainForm.WorkAreaOverride = null;
                Loc.SetLanguage(keepLang);
            }
            var head = new List<string>
            {
                "NSF Shield " + App.Version + " UI check (real WinForms handles, offline)",
                "Screen " + Screen.PrimaryScreen.Bounds.Size + ", system DPI " + SystemDpi() + "; 150 % = Theme.Scale 1.5 with 1.5x fonts (the system DPI is not changed)",
                "",
            };
            uiReport.Add("");
            uiReport.Add(uiOk + " OK / " + uiFail + " FAIL");
            File.WriteAllLines(Path.Combine(dir, "uicheck.txt"), head.Concat(uiReport), new UTF8Encoding(false));
            return uiFail == 0 && uiOk > 0 ? 0 : 1;
        }

        static void Pump(int n) { for (int i = 0; i < n; i++) { Application.DoEvents(); Thread.Sleep(25); } }

        static int SystemDpi() { using (var g = Graphics.FromHwnd(IntPtr.Zero)) return (int)g.DpiX; }

        static void SetScale(float s)
        {
            NSFShield.Theme.Scale = s;
            NSFShield.Theme.ScaleFonts(s);
        }

        static string Tag(string lang, float scale) => lang + "_" + (scale > 1.2f ? "150" : "100");

        // ------------------------------------------------------------------ windows

        static MainForm OpenMain(Rectangle work, UiLevel level, string theme, string lang)
        {
            Loc.SetLanguage(lang);
            App.Settings.UiLevel = level;
            App.Settings.ThemeId = theme;
            App.Settings.FollowSystem = false;
            NSFShield.Theme.Apply(Palettes.Resolve(App.Settings));
            MainForm.WorkAreaOverride = () => work;
            var f = new MainForm { StartPosition = FormStartPosition.Manual, Location = work.Location };
            f.Show();
            f.TopMost = true;
            f.Activate();
            SetForegroundWindow(f.Handle);
            Pump();
            return f;
        }

        static void Close(Form f)
        {
            if (f == null || f.IsDisposed) return;
            f.TopMost = false;
            f.Hide();
            f.Dispose();
            Pump(2);
        }

        static Bitmap PrintOf(Form f)
        {
            var bmp = new Bitmap(f.Width, f.Height, PixelFormat.Format32bppArgb);
            using (var g = Graphics.FromImage(bmp))
            {
                IntPtr hdc = g.GetHdc();
                try { PrintWindow(f.Handle, hdc, 2); } finally { g.ReleaseHdc(hdc); }
            }
            return bmp;
        }

        /// <summary>The control as PrintWindow draws it (cropped from the window).</summary>
        static Bitmap PrintCrop(Form f, Control c)
        {
            using (var whole = PrintOf(f))
            {
                var p = c.PointToScreen(Point.Empty);
                var r = new Rectangle(p.X - f.Left, p.Y - f.Top, c.Width, c.Height);
                r.Intersect(new Rectangle(Point.Empty, whole.Size));
                return whole.Clone(r, PixelFormat.Format32bppArgb);
            }
        }

        /// <summary>
        /// The control as the normal WM_PAINT path drew it: read from the screen; when another program's window covers it there,
        /// from the window's own surface (the composited picture of the same WM_PAINT, which DWM keeps for covered windows).
        /// Null when neither can be read.
        /// </summary>
        static Bitmap ScreenCrop(Control c, out string why, out string source)
        {
            why = null;
            source = "screen";
            var f = c.FindForm();
            f.TopMost = true;
            f.Activate();
            SetForegroundWindow(f.Handle);
            c.Invalidate();
            c.Update();
            Pump(4);
            var r = c.RectangleToScreen(c.ClientRectangle);
            var mid = new Point(r.Left + r.Width / 2, r.Top + r.Height / 2);
            var top = GetAncestor(WindowFromPoint(mid), 2 /* GA_ROOT */);
            var bmp = new Bitmap(r.Width, r.Height, PixelFormat.Format32bppArgb);
            if (top != f.Handle)
            {
                // covered by another program's window (its title is never read): the control's own window surface
                source = "window surface (covered on the screen)";
                using (var g = Graphics.FromImage(bmp))
                {
                    IntPtr dst = g.GetHdc(), src = GetDC(c.Handle);
                    try { if (src == IntPtr.Zero || !BitBlt(dst, 0, 0, r.Width, r.Height, src, 0, 0, 0x00CC0020 /* SRCCOPY */)) why = "the window surface cannot be read"; }
                    finally { if (src != IntPtr.Zero) ReleaseDC(c.Handle, src); g.ReleaseHdc(dst); }
                }
                if (why != null) { bmp.Dispose(); return null; }
                return bmp;
            }
            try
            {
                using (var g = Graphics.FromImage(bmp)) g.CopyFromScreen(r.Location, Point.Empty, r.Size);
            }
            catch (Exception ex) { bmp.Dispose(); why = "the screen cannot be read (" + ex.Message + ")"; return null; }
            return bmp;
        }

        // ------------------------------------------------------------------ text of a closed box

        const TextFormatFlags BoxFlags = TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPadding;

        static bool[,] InkMask(Bitmap b, Rectangle r, Color bg)
        {
            var m = new bool[r.Width, r.Height];
            for (int x = 0; x < r.Width; x++)
                for (int y = 0; y < r.Height; y++)
                {
                    int px = r.X + x, py = r.Y + y;
                    if (px < 0 || py < 0 || px >= b.Width || py >= b.Height) continue;
                    var c = b.GetPixel(px, py);
                    m[x, y] = Math.Abs(c.R - bg.R) + Math.Abs(c.G - bg.G) + Math.Abs(c.B - bg.B) > 120;
                }
            return m;
        }

        static int Count(bool[,] m) { int n = 0; foreach (var v in m) if (v) n++; return n; }

        /// <summary>Share of the ink of <paramref name="a"/> that has ink of <paramref name="b"/> within one pixel.</summary>
        static double Covered(bool[,] a, bool[,] b)
        {
            int w = a.GetLength(0), h = a.GetLength(1), n = 0, hit = 0;
            for (int x = 0; x < w; x++)
                for (int y = 0; y < h; y++)
                {
                    if (!a[x, y]) continue;
                    n++;
                    bool near = false;
                    for (int dx = -1; dx <= 1 && !near; dx++)
                        for (int dy = -1; dy <= 1 && !near; dy++)
                        {
                            int u = x + dx, v = y + dy;
                            near = u >= 0 && v >= 0 && u < w && v < h && b[u, v];
                        }
                    if (near) hit++;
                }
            return n == 0 ? 1 : hit / (double)n;
        }

        /// <summary>
        /// Checks that the closed box shows exactly its selected text (or nothing for a real empty selection), in the PrintWindow
        /// picture and in the normal screen painting; both are compared with the text drawn the way the box draws it.
        /// </summary>
        static void BoxText(string name, ThemedCombo box, string shotName)
        {
            var f = box.FindForm();
            BringIntoView(box);
            box.Invalidate();
            box.Update();
            Pump(3);
            string expected = box.SelectedIndex >= 0 ? box.GetItemText(box.SelectedItem) : "";
            var edit = box.LastEditBounds;
            if (edit.Width <= 0 || box.EditPaints == 0)
            {
                UiCheckResult(name + ": the closed box painted its text area", false, "no WM_DRAWITEM for the edit area");
                return;
            }
            int bw = Math.Max(NSFShield.Theme.D(18), SystemInformation.VerticalScrollBarWidth);
            var text = Rectangle.Inflate(edit, -NSFShield.Theme.D(4), 0);
            text.Intersect(new Rectangle(3, 3, box.Width - bw - 6, box.Height - 6));
            Color bg = NSFShield.Theme.Input, fg = NSFShield.Theme.Text;
            using (var pw = PrintCrop(f, box))
            using (var reference = new Bitmap(box.Width, box.Height, PixelFormat.Format32bppArgb))
            {
                using (var g = Graphics.FromImage(reference))
                {
                    g.Clear(bg);
                    TextRenderer.DrawText(g, expected, box.Font, Rectangle.Inflate(edit, -NSFShield.Theme.D(4), 0), fg, bg, BoxFlags);
                }
                var R = InkMask(reference, text, bg);
                var A = InkMask(pw, text, bg);
                var scr = ScreenCrop(box, out string why, out string source);
                var S = scr == null ? null : InkMask(scr, text, bg);
                SaveTriple(shotName, pw, scr, reference);
                scr?.Dispose();
                string Detail(bool[,] m) => m == null ? why : "ink " + Count(m) + "/" + Count(R) + ", precision " + Covered(m, R).ToString("0.00") + ", recall " + Covered(R, m).ToString("0.00");
                bool Matches(bool[,] m) => m != null && (expected.Length == 0 ? Count(m) <= 2 : Count(m) >= 8 && Covered(m, R) >= 0.85 && Covered(R, m) >= 0.85);
                string what = expected.Length == 0 ? "stays empty (no selection)" : "shows \"" + expected + "\"";
                UiCheckResult(name + ": PrintWindow " + what, Matches(A), Detail(A));
                UiCheckResult(name + ": normal WM_PAINT painting " + what, Matches(S), Detail(S) + (S != null ? " (" + source + ")" : ""));
                if (A != null && S != null && expected.Length > 0)
                    UiCheckResult(name + ": PrintWindow and screen show the same text", Covered(A, S) >= 0.85 && Covered(S, A) >= 0.85,
                                  Covered(A, S).ToString("0.00") + " / " + Covered(S, A).ToString("0.00"));
            }
        }

        static void SaveTriple(string name, Bitmap pw, Bitmap scr, Bitmap reference)
        {
            int w = pw.Width, h = pw.Height, z = 2;
            using (var sheet = new Bitmap((w * 3 + 16) * z, h * z))
            using (var g = Graphics.FromImage(sheet))
            {
                g.Clear(Color.Magenta);
                g.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.NearestNeighbor;
                g.PixelOffsetMode = System.Drawing.Drawing2D.PixelOffsetMode.Half;
                g.DrawImage(pw, 0, 0, w * z, h * z);
                if (scr != null) g.DrawImage(scr, (w + 8) * z, 0, w * z, h * z);
                g.DrawImage(reference, (w * 2 + 16) * z, 0, w * z, h * z);
                sheet.Save(Path.Combine(uiDir, "u7_" + name + "_box.png"), ImageFormat.Png);
            }
        }

        // ------------------------------------------------------------------ scrolling helpers

        static IEnumerable<Control> Descend(Control root)
        {
            foreach (Control c in root.Controls)
            {
                yield return c;
                foreach (var d in Descend(c)) yield return d;
            }
        }

        static bool ShownUnder(Control c, Control root)
        {
            for (var x = c; x != null && x != root; x = x.Parent) if (!UIx.OwnVisible(x)) return false;
            return true;
        }

        /// <summary>Scrolls every scrolled ancestor (innermost first) so that the control comes into view.</summary>
        static void BringIntoView(Control c)
        {
            for (var a = c.Parent; a != null; a = a.Parent)
            {
                if (!(a is ScrollableControl sc) || !sc.AutoScroll) continue;
                var r = sc.RectangleToClient(c.Parent.RectangleToScreen(c.Bounds));
                var cs = sc.ClientRectangle;
                int dy = 0, dx = 0;
                if (r.Bottom > cs.Bottom) dy = r.Bottom - cs.Bottom;
                if (r.Top - dy < cs.Top) dy = r.Top - cs.Top;
                if (r.Right > cs.Right) dx = r.Right - cs.Right;
                if (r.Left - dx < cs.Left) dx = r.Left - cs.Left;
                if (dx != 0 || dy != 0) sc.AutoScrollPosition = new Point(-sc.AutoScrollPosition.X + dx, -sc.AutoScrollPosition.Y + dy);
            }
            Pump(1);
        }

        /// <summary>
        /// Is the control visible after scrolling (inside every parent, the window and the work area)? A control taller or wider
        /// than its viewport must fill the viewport.
        /// </summary>
        static bool Reachable(Control c, Rectangle work, out string why)
        {
            BringIntoView(c);
            var r = c.Parent.RectangleToScreen(c.Bounds);
            var clip = work;
            for (var a = c.Parent; a != null; a = a.Parent) clip.Intersect(a.RectangleToScreen(a.ClientRectangle));
            var vis = Rectangle.Intersect(r, clip);
            bool ok = vis.Height >= Math.Min(r.Height, clip.Height) - 2 && vis.Width >= Math.Min(r.Width, clip.Width) - 2 && clip.Height > 0;
            why = ok ? null : Describe(c) + " shows " + vis.Size + " of " + r.Size + " (viewport " + clip.Size + ")";
            return ok;
        }

        static string Describe(Control c)
        {
            string t = (c.Text ?? "").Replace("\n", " ");
            if (t.Length > 32) t = t.Substring(0, 32) + "…";
            return c.GetType().Name + (t.Length > 0 ? " \"" + t + "\"" : "");
        }

        static bool IsInteractive(Control c) =>
            c is FlatBtn || c is ComboBox || c is TextBoxBase || c is CheckX || c is Toggle || c is Segmented || c is ListView ||
            c is ListBox || c is NumericUpDown || c is NavItem;

        static void Wheel(Control target, int clicks)
        {
            var p = target.PointToScreen(new Point(Math.Min(target.Width / 2, NSFShield.Theme.D(30)), target.Height / 2));
            for (int i = 0; i < Math.Abs(clicks); i++)
            {
                int delta = clicks < 0 ? -120 : 120;
                SendMessage(target.Handle, WM_MOUSEWHEEL, (IntPtr)(delta << 16), (IntPtr)((p.Y << 16) | (p.X & 0xFFFF)));
                Pump(1);
            }
            Pump(2);
        }

        static void Snap(Form f, string name) { Pump(); using (var b = PrintOf(f)) b.Save(Path.Combine(uiDir, "u7_" + name + ".png"), ImageFormat.Png); }

        // ------------------------------------------------------------------ 1. the Home profile box

        static Profile CopyOf(Profile p, string id, string name)
        {
            var c = p.CloneAsCustom();
            c.Id = id;
            c.Name = name;
            return c;
        }

        static void HomeBox(string lang, float scale)
        {
            string tag = Tag(lang, scale);
            var all = App.AllProfiles.ToList();
            var gdpi = all.First(p => p.Engine == EngineKind.GoodbyeDpi && p.Tier == ProfileTier.Recommended);
            var zap = all.First(p => p.Engine == EngineKind.Zapret && p.Tier == ProfileTier.Recommended);
            var longName = all.Where(p => p.Engine == EngineKind.GoodbyeDpi).OrderByDescending(p => p.Name.Length).First();
            var snapshot = CopyOf(zap, "removed-running-snapshot", lang == "tr" ? "\u00c7al\u0131\u015fan anl\u0131k g\u00f6r\u00fcnt\u00fc \u2013 \u015f\u0131k a\u011f ayar\u0131 (\u011e\u00dc\u015e\u0130\u00d6\u00c7)" : "Running snapshot \u2013 removed profile");
            var scenarios = new (string Key, string Selected, EngineState State, Profile Active, Profile Expect)[]
            {
                ("selected", gdpi.Id, EngineState.Stopped, null, gdpi),
                ("oldid", "removed-old-profile-id", EngineState.Stopped, null, Profiles.BuiltIns[0]),
                ("running", gdpi.Id, EngineState.Running, zap, zap),
                ("snapshot", gdpi.Id, EngineState.Running, snapshot, snapshot),
                ("starting", gdpi.Id, EngineState.Starting, zap, zap),
                ("longname", longName.Id, EngineState.Stopped, null, longName),
            };
            foreach (var level in new[] { UiLevel.Standard, UiLevel.Advanced })
                foreach (var theme in new[] { "clean-light", "slate-dark" })
                {
                    var f = OpenMain(NormalWork, level, theme, lang);
                    try
                    {
                        foreach (var sc in scenarios)
                        {
                            App.Settings.SelectedProfileId = sc.Selected;
                            App.Engine.DebugSet(sc.State, sc.Active);
                            App.RaiseStatus();
                            Pump();
                            var home = (HomePage)f.Navigate("home");
                            Pump();
                            string n = "home " + tag + " " + level + " " + theme + " " + sc.Key;
                            var box = home.ProfileBox;
                            var items = box.Items.Cast<Profile>().ToList();
                            UiCheckResult(n + ": card, box and chip show the same profile",
                                ReferenceEquals(home.ShownProfile, sc.Expect) && home.CardProfileName == sc.Expect.Name &&
                                ReferenceEquals(box.SelectedItem, sc.Expect) && box.SelectedIndex >= 0,
                                "card \"" + home.CardProfileName + "\", box \"" + (box.SelectedItem as Profile)?.Name + "\", expected \"" + sc.Expect.Name + "\"");
                            UiCheckResult(n + ": the box lists only the shown profile's engine", items.Count > 0 && items.All(p => p.Engine == sc.Expect.Engine),
                                string.Join(", ", items.Select(p => p.Engine).Distinct()));
                            if (sc.Key == "starting")
                                UiCheckResult(n + ": the box is disabled while the engine starts", !box.Enabled, "");
                            BoxText(n, box, tag + "_" + level.ToString().ToLowerInvariant() + "_" + theme + "_home_" + sc.Key);
                            if (sc.Key == "snapshot" && theme == "slate-dark") Snap(f, tag + "_" + level.ToString().ToLowerInvariant() + "_home_snapshot");
                        }
                        // the status notices of a running app: no rebuild of an unchanged list, no save, no start, no selection
                        App.Settings.SelectedProfileId = gdpi.Id;
                        App.Engine.DebugSet(EngineState.Running, snapshot);
                        App.RaiseStatus();
                        Pump();
                        var h2 = (HomePage)f.Navigate("home");
                        int refills = h2.ComboRefills, saves = SettingsStore.SaveRequests, selects = Actions.SelectRequests;
                        var state = App.Engine.State;
                        for (int i = 0; i < 5; i++) { App.RaiseStatus(); Pump(1); }
                        h2.OnActivated();
                        Pump();
                        UiCheckResult("home " + tag + " " + level + " " + theme + ": five status notices rebuild nothing and save, start or select nothing",
                            h2.ComboRefills == refills && SettingsStore.SaveRequests == saves && Actions.SelectRequests == selects && App.Engine.State == state &&
                            ReferenceEquals(h2.ProfileBox.SelectedItem, snapshot),
                            "refills " + refills + "→" + h2.ComboRefills + ", saves " + saves + "→" + SettingsStore.SaveRequests + ", selects " + selects + "→" + Actions.SelectRequests);
                        // the normal list behaviour: it opens with every item and closes again
                        h2.ProfileBox.Focus();
                        h2.ProfileBox.DroppedDown = true;
                        Pump();
                        bool opened = h2.ProfileBox.DroppedDown;
                        h2.ProfileBox.DroppedDown = false;
                        Pump();
                        UiCheckResult("home " + tag + " " + level + " " + theme + ": the list opens and closes normally, the selection stays",
                            opened && !h2.ProfileBox.DroppedDown && ReferenceEquals(h2.ProfileBox.SelectedItem, snapshot) && Actions.SelectRequests == selects, "");
                        // focused box: its text stays visible
                        BoxText("home " + tag + " " + level + " " + theme + " focused", h2.ProfileBox, tag + "_" + level.ToString().ToLowerInvariant() + "_" + theme + "_home_focused");
                        // Rebuild (language or theme change): the new page shows the same profile, in the box too
                        f.Rebuild();
                        Pump();
                        var h3 = (HomePage)f.CurrentPage;
                        UiCheckResult("home " + tag + " " + level + " " + theme + ": after Rebuild the card and the box show the same running snapshot",
                            ReferenceEquals(h3.ShownProfile, snapshot) && ReferenceEquals(h3.ProfileBox.SelectedItem, snapshot) && h3.CardProfileName == snapshot.Name, "");
                        BoxText("home " + tag + " " + level + " " + theme + " after Rebuild", h3.ProfileBox, tag + "_" + level.ToString().ToLowerInvariant() + "_" + theme + "_home_rebuild");
                    }
                    finally
                    {
                        App.Engine.DebugSet(EngineState.Stopped, null);
                        Close(f);
                    }
                }
        }

        // ------------------------------------------------------------------ 2. every themed box

        static Segmented TabsOf(PageBase p) =>
            (p.GetType().GetField("tabs", BindingFlags.Instance | BindingFlags.NonPublic) ??
             p.GetType().GetField("engineTabs", BindingFlags.Instance | BindingFlags.NonPublic))?.GetValue(p) as Segmented;

        static void ThemedBoxes(string lang, float scale)
        {
            string tag = Tag(lang, scale);
            foreach (var theme in new[] { "clean-light", "slate-dark" })
            {
                var f = OpenMain(NormalWork, UiLevel.Advanced, theme, lang);
                try
                {
                    foreach (var key in new[] { "appearance", "settings", "proxy", "trouble" })
                    {
                        var page = f.Navigate(key);
                        Pump();
                        var tabs = TabsOf(page);
                        int tabCount = tabs?.Items.Count ?? 1;
                        int seen = 0;
                        for (int t = 0; t < tabCount; t++)
                        {
                            if (tabs != null) { tabs.SelectedIndex = t; Pump(); }
                            int i = 0;
                            foreach (var box in Descend(page).OfType<ThemedCombo>().Where(b => ShownUnder(b, page)).ToList())
                            {
                                seen++;
                                BoxText(key + " " + tag + " " + theme + " box " + (++i) + (tabs != null ? " (tab " + (t + 1) + ")" : ""), box,
                                        tag + "_" + theme + "_" + key + "_" + t + "_" + i);
                            }
                        }
                        if (tabs != null) { tabs.SelectedIndex = 0; Pump(); }
                        UiCheckResult(key + " " + tag + " " + theme + ": themed boxes found", seen > 0, seen + " box(es)");
                        if (key == "proxy")
                        {
                            // no proxy yet: the rule box has no item and stays empty (no "select the first item")
                            tabs.SelectedIndex = 1;
                            Pump();
                            var ap = page.GetType().GetField("aProxy", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(page) as ThemedCombo;
                            UiCheckResult("proxy " + tag + " " + theme + ": without an app rule the proxy box keeps its real empty selection",
                                App.Settings.ProxyApps.Count == 0 && ap.SelectedIndex == -1, ap.Items.Count + " choice(s), index " + ap.SelectedIndex);
                            tabs.SelectedIndex = 0;
                        }
                    }
                    // the GoodbyeDPI profile editor: mode, TTL and DNS boxes
                    var prof = Profiles.BuiltIns.First(p => p.Engine == EngineKind.GoodbyeDpi).CloneAsCustom();
                    using (var ed = new ProfileEditor(prof))
                    {
                        ed.StartPosition = FormStartPosition.Manual;
                        ed.Location = new Point(40, 40);
                        ed.Show(f);
                        ed.TopMost = true;
                        Pump();
                        int i = 0;
                        foreach (var box in Descend(ed).OfType<ThemedCombo>().ToList())
                            BoxText("profile editor " + tag + " " + theme + " box " + (++i), box, tag + "_" + theme + "_editor_" + i);
                        UiCheckResult("profile editor " + tag + " " + theme + ": three themed boxes", i == 3, i + " box(es)");
                        ed.Close();
                    }
                }
                finally { Close(f); }
            }
        }

        // ------------------------------------------------------------------ 3. scrolling in a short work area

        static void Scrolling(string lang, float scale)
        {
            string tag = Tag(lang, scale);
            var work = ShortWork(scale);
            foreach (var level in new[] { UiLevel.Simple, UiLevel.Standard, UiLevel.Advanced })
            {
                // the normal work area: everything fits, no scroll bar on Home (with and without a banner)
                var big = OpenMain(NormalWork, level, "slate-dark", lang);
                try
                {
                    var home = (HomePage)big.Navigate("home");
                    Pump();
                    UiCheckResult("scroll " + tag + " " + level + ": design size in a large work area, no scroll bar on Home",
                        big.ClientSize == new Size(NSFShield.Theme.D(1040), NSFShield.Theme.D(680)) && !home.Area.VerticalScroll.Visible && !home.Area.HorizontalScroll.Visible,
                        big.ClientSize + ", content " + home.Content.Size + ", area " + home.Area.ClientSize);
                    App.Problems.Report("NSF-104", "ui check");
                    App.RaiseStatus();
                    Pump();
                    UiCheckResult("scroll " + tag + " " + level + ": with a banner Home still fits without a scroll bar",
                        home.BannerTitle != null && !home.Area.VerticalScroll.Visible, "content " + home.Content.Size);
                    App.Problems.Clear("NSF-104");
                    App.RaiseStatus();
                    Pump();
                }
                finally { Close(big); }

                var f = OpenMain(work, level, level == UiLevel.Standard ? "clean-light" : "slate-dark", lang);
                try
                {
                    string n = "scroll " + tag + " " + level;
                    UiCheckResult(n + ": the window fits the work area " + work.Size, f.Width <= work.Width && f.Height <= work.Height &&
                        f.Bounds.Bottom <= work.Bottom, f.Bounds.ToString());
                    var host = f.Host;
                    UiCheckResult(n + ": the page host follows the real client size",
                        host.Width == f.ClientSize.Width - NSFShield.Theme.D(220) && host.Height == f.ClientSize.Height - NSFShield.Theme.D(40), host.Size + " in " + f.ClientSize);
                    var home = (HomePage)f.Navigate("home");
                    Pump();
                    var area = home.Area;
                    UiCheckResult(n + ": the Home area takes the host size", area.Size == host.Size, area.Size + " / " + host.Size);
                    var last = home.LastCard;
                    UiCheckResult(n + ": Home is taller than the area: vertical bar only",
                        home.Content.Height > area.ClientSize.Height && area.VerticalScroll.Visible && !area.HorizontalScroll.Visible,
                        "content " + home.Content.Size + ", area " + area.ClientSize);
                    int contentBottom = home.Content.NaturalHeight;
                    UiCheckResult(n + ": the content height is the last visible card's bottom plus the margin",
                        contentBottom == last.Bottom + home.Content.BottomMargin && home.Content.Height == contentBottom, contentBottom + " / " + last.Bottom);
                    string why;
                    bool before = FullyInside(last, area);
                    Snap(f, tag + "_" + level.ToString().ToLowerInvariant() + "_home_short_before");
                    // the wheel over a label of the status card scrolls the page
                    var label = Descend(home).OfType<Label>().First(l => ShownUnder(l, home) && l.Width > 40 && l.Parent is Card);
                    int y0 = area.Offset.Y;
                    Wheel(label, -1);
                    int y1 = area.Offset.Y;
                    Wheel(label, -20);
                    bool after = FullyInside(last, area);
                    Snap(f, tag + "_" + level.ToString().ToLowerInvariant() + "_home_short_wheel");
                    UiCheckResult(n + ": the wheel scrolls Home down until the last card is fully visible",
                        !before && y1 > y0 && after, "offset " + y0 + " → " + y1 + " → " + area.Offset.Y + ", last card visible before " + before + ", after " + after);
                    Wheel(label, 20);
                    UiCheckResult(n + ": the wheel scrolls back to the top", area.Offset.Y == 0, "offset " + area.Offset.Y);
                    // the scroll bar (page down, bottom)
                    SendMessage(area.Handle, WM_VSCROLL, (IntPtr)SB_PAGEDOWN, IntPtr.Zero);
                    Pump();
                    int yPage = area.Offset.Y;
                    SendMessage(area.Handle, WM_VSCROLL, (IntPtr)SB_BOTTOM, IntPtr.Zero);
                    Pump();
                    UiCheckResult(n + ": the scroll bar moves the page and reaches the last card", yPage > 0 && FullyInside(last, area),
                        "page down " + yPage + ", bottom " + area.Offset.Y);
                    Snap(f, tag + "_" + level.ToString().ToLowerInvariant() + "_home_short_bar");
                    if (home.ProfileBox != null)
                    {
                        // the wheel over the closed, unfocused profile box scrolls the page and never changes the profile
                        area.Offset = Point.Empty;
                        Pump();
                        f.ActiveControl = null;
                        int sel = home.ProfileBox.SelectedIndex, selects = Actions.SelectRequests, yb = area.Offset.Y;
                        BringIntoView(home.ProfileBox);
                        yb = area.Offset.Y;
                        Wheel(home.ProfileBox, -2);
                        UiCheckResult(n + ": the wheel over the closed profile box scrolls the page, the profile stays",
                            area.Offset.Y > yb && home.ProfileBox.SelectedIndex == sel && Actions.SelectRequests == selects,
                            "offset " + yb + " → " + area.Offset.Y + ", index " + sel + " → " + home.ProfileBox.SelectedIndex);
                        // an open list keeps its own wheel: the page does not move
                        home.ProfileBox.Focus();
                        home.ProfileBox.DroppedDown = true;
                        Pump();
                        int yo = area.Offset.Y;
                        Wheel(home.ProfileBox, -1);
                        bool still = area.Offset.Y == yo;
                        home.ProfileBox.DroppedDown = false;
                        Pump();
                        UiCheckResult(n + ": the wheel over an open list is not taken by the page", still, "offset " + yo + " → " + area.Offset.Y);
                        f.ActiveControl = null;
                    }
                    // a banner while scrolled: the cards move by the banner height once (logical positions, no second offset)
                    area.Offset = new Point(0, NSFShield.Theme.D(60));
                    Pump();
                    int scrolled = area.Offset.Y;
                    App.Problems.Report("NSF-104", "ui check");
                    App.RaiseStatus();
                    Pump();
                    int expected = NSFShield.Theme.D(272 + (int)Math.Round(home.BannerCard.Height / NSFShield.Theme.Scale) + 14);
                    UiCheckResult(n + ": a banner while scrolled moves the cards once (logical positions), hides the tip, grows the content",
                        UIx.OwnVisible(home.BannerCard) && home.BannerCard.Top == NSFShield.Theme.D(272) && home.ProfileCard.Top == expected &&
                        !UIx.OwnVisible(home.TipCard) && home.Content.Height == home.Content.NaturalHeight && home.Content.Top == -area.Offset.Y,
                        "banner " + home.BannerCard.Top + ", card " + home.ProfileCard.Top + " (expected " + expected + "), content top " + home.Content.Top + ", offset " + scrolled + "→" + area.Offset.Y);
                    App.Problems.Clear("NSF-104");
                    App.RaiseStatus();
                    Pump();
                    UiCheckResult(n + ": without the banner the cards go back and the tip comes back",
                        !UIx.OwnVisible(home.BannerCard) && home.ProfileCard.Top == NSFShield.Theme.D(272) && UIx.OwnVisible(home.TipCard) &&
                        home.Content.Height == home.Content.NaturalHeight, "card " + home.ProfileCard.Top);
                    // Rebuild (the language changes) keeps the scroll position as far as the new page allows
                    area.Offset = new Point(0, NSFShield.Theme.D(90));
                    Pump();
                    int kept = area.Offset.Y;
                    Loc.SetLanguage(lang == "en" ? "tr" : "en");
                    Pump();
                    var h2 = (HomePage)f.CurrentPage;
                    UiCheckResult(n + ": after a language Rebuild the scroll position comes back", kept > 0 && h2.Area.Offset.Y == Math.Min(kept, h2.Content.Height - h2.Area.ClientSize.Height),
                        kept + " → " + h2.Area.Offset.Y);
                    Loc.SetLanguage(lang);
                    Pump();
                    // the menu: every page entry reachable; the status box only when it fits
                    foreach (var nav in f.NavItems)
                        UiCheckResult(n + ": menu entry " + nav.Key + " reachable", Reachable(nav, work, out why), why);
                }
                finally { Close(f); }
            }
        }

        static bool FullyInside(Control c, ScrollArea area)
        {
            var r = area.RectangleToClient(c.Parent.RectangleToScreen(c.Bounds));
            return area.ClientRectangle.Contains(r);
        }

        // ------------------------------------------------------------------ 4. every control of every page and dialog

        static void Reachability(string lang, float scale)
        {
            string tag = Tag(lang, scale);
            var work = SmallWork(scale);
            var f = OpenMain(work, UiLevel.Advanced, "slate-dark", lang);
            try
            {
                foreach (var nav in f.NavItems.ToList())
                {
                    var page = f.Navigate(nav.Key);
                    Pump();
                    var tabs = TabsOf(page);
                    int tabCount = tabs?.Items.Count ?? 1;
                    var bad = new List<string>();
                    int n = 0;
                    for (int t = 0; t < tabCount; t++)
                    {
                        if (tabs != null) { tabs.SelectedIndex = t; Pump(); }
                        foreach (var c in Descend(page).Where(c => IsInteractive(c) && c.Width > 0 && c.Height > 0 && ShownUnder(c, page)).ToList())
                        {
                            n++;
                            if (!Reachable(c, work, out string why)) bad.Add(why);
                        }
                    }
                    if (tabs != null) { tabs.SelectedIndex = 0; Pump(); }
                    UiCheckResult("reach " + tag + " " + nav.Key + ": every control can be scrolled into view (" + n + ")", n > 0 && bad.Count == 0, string.Join("; ", bad.Take(6)));
                    if (nav.Key == "profiles" || nav.Key == "proxy" || nav.Key == "settings" || nav.Key == "appearance")
                    {
                        var area = page.Controls.OfType<ScrollArea>().FirstOrDefault();
                        if (area != null) { area.Offset = new Point(0, 100000); Pump(); }
                        Snap(f, tag + "_reach_" + nav.Key + "_bottom");
                    }
                }
                // the dialogs: never larger than the work area, every control reachable
                var prof = Profiles.BuiltIns.First(p => p.Engine == EngineKind.GoodbyeDpi).CloneAsCustom();
                var zprof = Profiles.BuiltIns.First(p => p.Engine == EngineKind.Zapret).CloneAsCustom();
                var dialogs = new List<(string, Func<Form>)>
                {
                    ("profile editor", () => new ProfileEditor(prof)),
                    ("engine profile editor", () => new EngineProfileEditor(zprof)),
                    ("scan", () => ScanDialog.DebugCreate(UiLevel.Advanced, Sample(UiLevel.Advanced))),
                    ("update", () => (Form)Activator.CreateInstance(typeof(UpdateDialog), BindingFlags.Instance | BindingFlags.NonPublic, null,
                        new object[] { new UpdateInfo { Version = new Version(9, 9, 9), SetupUrl = "https://github.com/x", SetupSha256 = new string('a', 64), Notes = "-" } }, null)),
                    ("switch", () => SwitchDialog.DebugCreate(false)),
                    ("bulk proxies", () => (Form)Activator.CreateInstance(typeof(BulkProxyDialog), true)),
                };
                foreach (var (name, make) in dialogs)
                {
                    Form d = null;
                    try
                    {
                        d = make();
                        d.StartPosition = FormStartPosition.Manual;
                        d.Location = work.Location;
                        d.Show(f);
                        d.TopMost = true;
                        Pump();
                        var bad = new List<string>();
                        int n = 0;
                        foreach (var c in Descend(d).Where(c => IsInteractive(c) && c.Width > 0 && c.Height > 0 && ShownUnder(c, d)).ToList())
                        {
                            n++;
                            if (!Reachable(c, work, out string why)) bad.Add(why);
                        }
                        UiCheckResult("reach " + tag + " dialog " + name + ": fits the work area, every control reachable (" + n + ")",
                            d.Width <= work.Width && d.Height <= work.Height && n > 0 && bad.Count == 0, d.Size + "; " + string.Join("; ", bad.Take(6)));
                        if (name == "scan" || name == "profile editor") Snap(d, tag + "_reach_dialog_" + name.Replace(' ', '_'));
                    }
                    finally { if (d != null) { d.Hide(); d.Dispose(); } }
                }
            }
            finally { Close(f); }
        }
    }
}
#endif
