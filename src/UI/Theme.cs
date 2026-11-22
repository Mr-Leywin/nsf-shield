using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Drawing.Text;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace NSFShield
{
    /// <summary>Active color theme and fonts. The colors are updated with Apply() when the theme changes.</summary>
    static class Theme
    {
        public static float Scale = 1f;
        public static int D(float v) => (int)Math.Round(v * Scale);
        public static Rectangle R(int x, int y, int w, int h) => new Rectangle(D(x), D(y), D(w), D(h));

        public static Palette Current;
        public static bool IsDark, SidebarIsDark;

        // base colors
        public static Color Accent, Bg, Card, Border, Text, Muted, Sidebar, SidebarText, Green, Amber, Red, LogBg;
        // derived colors
        public static Color AccentText, AccentSoft, AccentBorder, AccentInk, Input, Hover, Pressed, Divider,
            SidebarMuted, SidebarHover, SidebarSel, SidebarBox, GreenSoft, AmberSoft, RedSoft, GreenText, AmberText, RedText,
            GreenBorder, AmberBorder, RedBorder, Gray, GraySoft, ToggleOff, LogText, LogMuted, LogGreen, LogAmber, LogRed, LogBlue;

        // old names
        public static Color Blue => Accent;
        public static Color BlueSoft => AccentSoft;

        public static void Apply(Palette p)
        {
            Current = p;
            Accent = p.Accent; Bg = p.Bg; Card = p.Card; Border = p.Border; Text = p.Text; Muted = p.Muted;
            Sidebar = p.Sidebar; SidebarText = p.SidebarText; Green = p.Green; Amber = p.Amber; Red = p.Red; LogBg = p.LogBg;

            IsDark = Lum(Card) < 0.35;
            SidebarIsDark = Lum(Sidebar) < 0.35;
            float k = IsDark ? 1.6f : 1f;

            AccentText = On(Accent);
            AccentSoft = Mix(Card, Accent, 0.12f * k);
            AccentBorder = Mix(Card, Accent, 0.35f * (IsDark ? 1.3f : 1f));
            AccentInk = Readable(Accent, Card, 3.2);
            Input = IsDark ? Mix(Card, Color.Black, 0.18f) : Mix(Card, Color.White, 0.7f);
            Hover = Mix(Card, Text, IsDark ? 0.08f : 0.045f);
            Pressed = Mix(Card, Text, IsDark ? 0.15f : 0.10f);
            Divider = Mix(Border, Card, 0.35f);

            SidebarHover = Mix(Sidebar, SidebarText, 0.07f);
            SidebarSel = Mix(Sidebar, SidebarText, 0.13f);
            SidebarBox = Mix(Sidebar, SidebarText, 0.055f);
            SidebarMuted = Mix(SidebarText, Sidebar, 0.40f);

            GreenSoft = Mix(Card, Green, 0.13f * k);
            AmberSoft = Mix(Card, Amber, 0.14f * k);
            RedSoft = Mix(Card, Red, 0.12f * k);
            GreenBorder = Mix(Card, Green, 0.38f);
            AmberBorder = Mix(Card, Amber, 0.42f);
            RedBorder = Mix(Card, Red, 0.38f);
            GreenText = Readable(Green, GreenSoft, 4.0);
            AmberText = Readable(Amber, AmberSoft, 4.0);
            RedText = Readable(Red, RedSoft, 4.0);

            Gray = Mix(Muted, Card, 0.35f);
            GraySoft = Mix(Card, Text, IsDark ? 0.07f : 0.06f);
            ToggleOff = Mix(Card, Text, IsDark ? 0.30f : 0.22f);

            bool logDark = Lum(LogBg) < 0.4;
            LogText = logDark ? Color.FromArgb(214, 222, 235) : Color.FromArgb(30, 36, 48);
            LogMuted = logDark ? Color.FromArgb(110, 124, 150) : Color.FromArgb(120, 128, 140);
            LogGreen = logDark ? Color.FromArgb(74, 222, 128) : Color.FromArgb(21, 128, 61);
            LogAmber = logDark ? Color.FromArgb(251, 191, 36) : Color.FromArgb(161, 98, 7);
            LogRed = logDark ? Color.FromArgb(248, 113, 113) : Color.FromArgb(185, 28, 28);
            LogBlue = logDark ? Color.FromArgb(125, 211, 252) : Color.FromArgb(3, 105, 161);
        }

        // ------------------------------------------------------------ color helpers

        static double Lin(int v) { double c = v / 255.0; return c <= 0.03928 ? c / 12.92 : Math.Pow((c + 0.055) / 1.055, 2.4); }
        public static double Lum(Color c) => 0.2126 * Lin(c.R) + 0.7152 * Lin(c.G) + 0.0722 * Lin(c.B);
        public static double Contrast(Color a, Color b)
        {
            double x = Lum(a), y = Lum(b);
            return (Math.Max(x, y) + 0.05) / (Math.Min(x, y) + 0.05);
        }

        /// <summary>Readable text color (white or dark) on the given background.</summary>
        public static Color On(Color bg) => Contrast(Color.White, bg) >= 3.0 ? Color.White : Color.FromArgb(17, 17, 17);

        /// <summary>Darkens/lightens the color until it has at least the min contrast on the background.</summary>
        public static Color Readable(Color c, Color bg, double min)
        {
            Color target = Lum(bg) < 0.4 ? Color.White : Color.Black;
            for (float t = 0; t <= 1.001f; t += 0.08f)
            {
                var m = Mix(c, target, t);
                if (Contrast(m, bg) >= min) return m;
            }
            return target;
        }

        public static Color Mix(Color a, Color b, float t)
        {
            t = Math.Max(0, Math.Min(1, t));
            return Color.FromArgb(
                (int)Math.Round(a.R + (b.R - a.R) * t),
                (int)Math.Round(a.G + (b.G - a.G) * t),
                (int)Math.Round(a.B + (b.B - a.B) * t));
        }

        // ------------------------------------------------------------ fonts

        public static Font Body { get; private set; } = new Font("Segoe UI", 9.75f);
        public static Font Small { get; private set; } = new Font("Segoe UI", 8.75f);
        public static Font Bold { get; private set; } = new Font("Segoe UI Semibold", 9.75f);
        public static Font Caption { get; private set; } = new Font("Segoe UI Semibold", 8f);
        public static Font H1 { get; private set; } = new Font("Segoe UI Semibold", 17f);
        public static Font H2 { get; private set; } = new Font("Segoe UI Semibold", 12.5f);
        public static Font Big { get; private set; } = new Font("Segoe UI Semibold", 11f);
        public static Font Hero { get; private set; } = new Font("Segoe UI Semibold", 22f);
        public static Font Mono { get; private set; } = new Font("Consolas", 9f);
        public static Font MonoSmall { get; private set; } = new Font("Consolas", 8.25f);

#if PREVIEW
        /// <summary>
        /// UI check only: the fonts at <paramref name="f"/> times their size, so that a 96 DPI test machine draws a 150 % layout
        /// (Scale = 1.5) with 150 % text (the system DPI itself is never changed). 1 = the normal fonts.
        /// </summary>
        internal static void ScaleFonts(float f)
        {
            Font S(string n, float pt) => new Font(n, pt * f);
            Body = S("Segoe UI", 9.75f); Small = S("Segoe UI", 8.75f); Bold = S("Segoe UI Semibold", 9.75f);
            Caption = S("Segoe UI Semibold", 8f); H1 = S("Segoe UI Semibold", 17f); H2 = S("Segoe UI Semibold", 12.5f);
            Big = S("Segoe UI Semibold", 11f); Hero = S("Segoe UI Semibold", 22f); Mono = S("Consolas", 9f); MonoSmall = S("Consolas", 8.25f);
            iconS = new Font(IconFontName, 10f * f); iconM = new Font(IconFontName, 12f * f); iconL = new Font(IconFontName, 20f * f);
        }
#endif

        static string iconFontName;
        public static string IconFontName
        {
            get
            {
                if (iconFontName == null)
                {
                    using (var fc = new InstalledFontCollection())
                        iconFontName = fc.Families.Any(f => f.Name == "Segoe Fluent Icons") ? "Segoe Fluent Icons" : "Segoe MDL2 Assets";
                }
                return iconFontName;
            }
        }

        static Font iconS, iconM, iconL;
        public static Font IconS => iconS ?? (iconS = new Font(IconFontName, 10f));
        public static Font IconM => iconM ?? (iconM = new Font(IconFontName, 12f));
        public static Font IconL => iconL ?? (iconL = new Font(IconFontName, 20f));

        // Segoe MDL2 / Fluent icons
        public const string GHome = "", GProfiles = "", GGlobe = "", GDiag = "",
            GLog = "", GSettings = "", GInfo = "", GPlay = "", GStop = "",
            GRefresh = "", GSearch = "", GAdd = "", GDelete = "", GEdit = "",
            GCopy = "", GCheck = "", GCancel = "", GWarn = "", GMin = "",
            GClose = "", GSave = "", GFolder = "", GSpeed = "", GShield = "",
            GClock = "", GWrench = "", GArrow = "", GColor = "", GHelp = "",
            GNetwork = "", GBug = "", GChat = "", GLink = "", GPaste = "",
            GUndo = "", GChevron = "", GList = "", GServer = "";

        public static GraphicsPath Round(RectangleF r, float rad)
        {
            var p = new GraphicsPath();
            float d = Math.Min(rad * 2, Math.Min(r.Width, r.Height));
            if (d <= 0.5f) { p.AddRectangle(r); return p; }
            p.AddArc(r.X, r.Y, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }

        public static void HQ(Graphics g)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.PixelOffsetMode = PixelOffsetMode.HighQuality;
            g.InterpolationMode = InterpolationMode.HighQualityBicubic;
        }

        public static Color StateColor(EngineState s)
        {
            switch (s)
            {
                case EngineState.Running: return GreenText;
                case EngineState.Starting:
                case EngineState.Stopping: return AmberText;
                case EngineState.Error: return RedText;
                default: return Muted;
            }
        }

        public static Color SevColor(Severity s) => s == Severity.Error ? Red : s == Severity.Warning ? Amber : Accent;

        // ------------------------------------------------------------ fit standard controls to the theme

        /// <summary>Fits controls such as TextBox, ListBox, ListView, RichTextBox, NumericUpDown and ComboBox to the theme.</summary>
        public static T Style<T>(T c) where T : Control
        {
            if (c is TextBoxBase || c is ListBox || c is ListView || c is NumericUpDown || c is ComboBox)
            {
                c.BackColor = Input;
                c.ForeColor = Text;
            }
            if (c is TextBox tb && tb.BorderStyle == BorderStyle.Fixed3D) tb.BorderStyle = BorderStyle.FixedSingle;
            if (c is NumericUpDown nu) nu.BorderStyle = BorderStyle.FixedSingle;
            if (c is ComboBox cb) cb.FlatStyle = FlatStyle.Flat;
            if (IsDark)
            {
                string th = c is ComboBox || c is TextBox || c is NumericUpDown ? "DarkMode_CFD" : "DarkMode_Explorer";
                if (c.IsHandleCreated) Native.ThemeWindow(c.Handle, th);
                c.HandleCreated += (s, e) => Native.ThemeWindow(((Control)s).Handle, th);
            }
            return c;
        }

        /// <summary>Fits the scroll bar of a scrollable panel to the theme.</summary>
        public static void StyleScroll(Control c)
        {
            if (!IsDark) return;
            if (c.IsHandleCreated) Native.ThemeWindow(c.Handle, "DarkMode_Explorer");
            c.HandleCreated += (s, e) => Native.ThemeWindow(((Control)s).Handle, "DarkMode_Explorer");
        }
    }

    /// <summary>Shield logo and icons (drawn without needing files).</summary>
    static class IconArt
    {
        public enum Glyph { None, Check, Pause, Exclaim, Dots }

        public static GraphicsPath ShieldPath(RectangleF r)
        {
            float x = r.X, y = r.Y, w = r.Width, h = r.Height;
            PointF P(float u, float v) => new PointF(x + u * w, y + v * h);
            var p = new GraphicsPath();
            p.AddBezier(P(.5f, .02f), P(.63f, .10f), P(.78f, .14f), P(.93f, .15f));
            p.AddBezier(P(.93f, .15f), P(.94f, .56f), P(.79f, .82f), P(.5f, .98f));
            p.AddBezier(P(.5f, .98f), P(.21f, .82f), P(.06f, .56f), P(.07f, .15f));
            p.AddBezier(P(.07f, .15f), P(.22f, .14f), P(.37f, .10f), P(.5f, .02f));
            p.CloseFigure();
            return p;
        }

        public static void DrawShield(Graphics g, RectangleF r, Color top, Color bottom, Glyph glyph)
        {
            Theme.HQ(g);
            using (var path = ShieldPath(r))
            using (var br = new LinearGradientBrush(new PointF(r.X, r.Y), new PointF(r.X, r.Bottom), top, bottom))
            {
                g.FillPath(br, path);
                // a slight shine on the left half
                var st = g.Save();
                g.SetClip(path);
                using (var hi = new SolidBrush(Color.FromArgb(34, 255, 255, 255)))
                    g.FillRectangle(hi, r.X, r.Y, r.Width / 2f, r.Height);
                g.Restore(st);
            }

            float w = r.Width, h = r.Height;
            PointF P(float u, float v) => new PointF(r.X + u * w, r.Y + v * h);
            float pw = Math.Max(1.4f, w * 0.095f);
            using (var pen = new Pen(Color.White, pw) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round })
            using (var wb = new SolidBrush(Color.White))
            {
                switch (glyph)
                {
                    case Glyph.Check:
                        g.DrawLines(pen, new[] { P(.31f, .50f), P(.45f, .64f), P(.70f, .37f) });
                        break;
                    case Glyph.Pause:
                        g.DrawLine(pen, P(.40f, .36f), P(.40f, .63f));
                        g.DrawLine(pen, P(.60f, .36f), P(.60f, .63f));
                        break;
                    case Glyph.Exclaim:
                        g.DrawLine(pen, P(.5f, .30f), P(.5f, .54f));
                        float d = pw * 1.15f;
                        var c = P(.5f, .68f);
                        g.FillEllipse(wb, c.X - d / 2, c.Y - d / 2, d, d);
                        break;
                    case Glyph.Dots:
                        float dd = pw * 1.1f;
                        foreach (var u in new[] { .32f, .5f, .68f })
                        {
                            var cc = P(u, .5f);
                            g.FillEllipse(wb, cc.X - dd / 2, cc.Y - dd / 2, dd, dd);
                        }
                        break;
                }
            }
        }

        public static (Color, Color, Glyph) StateLook(EngineState s)
        {
            switch (s)
            {
                case EngineState.Running: return (Color.FromArgb(52, 211, 113), Color.FromArgb(21, 128, 61), Glyph.Check);
                case EngineState.Starting:
                case EngineState.Stopping: return (Color.FromArgb(252, 196, 60), Color.FromArgb(217, 119, 6), Glyph.Dots);
                case EngineState.Error: return (Color.FromArgb(248, 113, 113), Color.FromArgb(200, 30, 30), Glyph.Exclaim);
                default: return (Color.FromArgb(160, 172, 192), Color.FromArgb(96, 110, 134), Glyph.Pause);
            }
        }

        public static Bitmap ShieldBitmap(int size, Color top, Color bottom, Glyph glyph)
        {
            var bmp = new Bitmap(size, size, PixelFormat.Format32bppArgb);
            using (var g = Graphics.FromImage(bmp))
            {
                g.Clear(Color.Transparent);
                float pad = size * 0.03f;
                DrawShield(g, new RectangleF(pad + size * 0.04f, pad, size - 2 * pad - size * 0.08f, size - 2 * pad), top, bottom, glyph);
            }
            return bmp;
        }

        public static Bitmap AppBitmap(int size) =>
            ShieldBitmap(size, Color.FromArgb(56, 189, 248), Color.FromArgb(29, 78, 216), Glyph.Check);

        public static Icon MakeIcon(Bitmap bmp)
        {
            IntPtr h = bmp.GetHicon();
            var tmp = Icon.FromHandle(h);
            var ico = (Icon)tmp.Clone();
            tmp.Dispose();
            Native.DestroyIcon(h);
            return ico;
        }

        public static Icon StateIcon(EngineState s, int size)
        {
            var (a, b, gl) = StateLook(s);
            using (var bmp = ShieldBitmap(size, a, b, gl)) return MakeIcon(bmp);
        }

        public static Icon AppIcon(int size)
        {
            using (var bmp = AppBitmap(size)) return MakeIcon(bmp);
        }

        /// <summary>Writes a multi-size .ico file (used during the build).</summary>
        public static void WriteIco(string path, int[] sizes)
        {
            var blobs = sizes.Select(s =>
            {
                using (var bmp = AppBitmap(s))
                {
                    if (s >= 256)
                    {
                        using (var ms = new MemoryStream()) { bmp.Save(ms, ImageFormat.Png); return ms.ToArray(); }
                    }
                    return Dib(bmp);
                }
            }).ToList();
            using (var fs = File.Create(path))
            using (var w = new BinaryWriter(fs))
            {
                w.Write((short)0); w.Write((short)1); w.Write((short)sizes.Length);
                int offset = 6 + 16 * sizes.Length;
                for (int i = 0; i < sizes.Length; i++)
                {
                    int s = sizes[i];
                    w.Write((byte)(s >= 256 ? 0 : s)); w.Write((byte)(s >= 256 ? 0 : s));
                    w.Write((byte)0); w.Write((byte)0);
                    w.Write((short)1); w.Write((short)32);
                    w.Write(blobs[i].Length); w.Write(offset);
                    offset += blobs[i].Length;
                }
                foreach (var b in blobs) w.Write(b);
            }
        }

        static byte[] Dib(Bitmap bmp)
        {
            int s = bmp.Width;
            using (var ms = new MemoryStream())
            using (var w = new BinaryWriter(ms))
            {
                w.Write(40); w.Write(s); w.Write(s * 2); w.Write((short)1); w.Write((short)32);
                w.Write(0); w.Write(0); w.Write(0); w.Write(0); w.Write(0); w.Write(0);
                for (int y = s - 1; y >= 0; y--)
                    for (int x = 0; x < s; x++)
                    {
                        var c = bmp.GetPixel(x, y);
                        w.Write(c.B); w.Write(c.G); w.Write(c.R); w.Write(c.A);
                    }
                int maskRow = ((s + 31) / 32) * 4;
                w.Write(new byte[maskRow * s]);
                w.Flush();
                return ms.ToArray();
            }
        }
    }
}
