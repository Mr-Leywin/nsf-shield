#if PREVIEW
using System;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace NSFShield
{
    /// <summary>
    /// Screenshots of the user-visible texts changed by the pre-release security audit (EN/TR): the refused https:// proxy,
    /// the portable copy offered the switch for a Setup-only release (window and tray note) and the support package README.
    /// </summary>
    static partial class Preview
    {
        /// <summary>A tray note rendered the way the balloon shows it (the live Windows notification cannot be captured).</summary>
        static void ShotNotice(string title, string text, string path)
        {
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

        public static void Stage6Shots(MainForm form, string dir)
        {
            foreach (var lang in new[] { "en", "tr" })
            {
                Loc.SetLanguage(lang);
                string tag = "s6_" + lang;
                // an https:// proxy address: the parser's own message (the real warning box of the Proxy page)
                ProxyTools.TryParse("https://user:pass@203.0.113.10:8443", ProxyKind.Http, out _, out string err);
                Theme(form, "system", UiLevel.Standard);
                form.Navigate("proxy");
                ShotMessageBox(form, err, MessageBoxButtons.OK, MessageBoxIcon.Warning, Path.Combine(dir, tag + "_proxy_https_refused.png"));
                // a portable copy and a release with only the setup package: the manual check offers the switch (answered "No")
                ShotMessageBox(form, Loc.T("updateDialog.needsSetup", "3.1.0"), MessageBoxButtons.YesNo, MessageBoxIcon.Information, Path.Combine(dir, tag + "_update_needs_setup.png"));
                ShotNotice(Loc.T("updateDialog.newVersion", "3.1.0"), Loc.T("updateDialog.needsSetupShort", "3.1.0"), Path.Combine(dir, tag + "_update_needs_setup_tray.png"));
            }
            Loc.SetLanguage(App.Settings.Language);
        }
    }
}
#endif
