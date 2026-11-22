using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using static NSFShield.Theme;

namespace NSFShield
{
    /// <summary>Page for changing the Windows DNS server (and encrypted DNS).</summary>
    sealed class DnsPage : PageBase
    {
        public override string Key => "dns";

        readonly ReportBox current;
        readonly ListBox choices;
        readonly CheckX chkDoh;
        readonly FlatBtn bApply, bRestore, bCheck;
        readonly Label result;

        public DnsPage()
        {
            Header(Loc.T("dnsPage.title"), Loc.T("dnsPage.subtitle"));

            // --- current state
            var c1 = AddCard(28, 76, 764, 168);
            c1.Add(UIx.L(Loc.T("dnsPage.current"), Caption, Muted, 20, 14, 300, 18));
            current = c1.Add(new ReportBox { Bounds = R(20, 36, 520, 120) });
            current.BackColor = Theme.Card;
            bCheck = c1.Add(new FlatBtn { Text = Loc.T("dnsPage.check"), Glyph = GSearch, Kind = FlatBtn.Kinds.Secondary, Bounds = R(556, 36, 190, 36) });
            bCheck.Click += async (s, e) => await CheckBlock();
            result = c1.Add(UIx.L("", Small, Muted, 556, 78, 190, 80));

            // --- choices
            var c2 = AddCard(28, 256, 764, 316);
            c2.Add(UIx.L(Loc.T("dnsPage.newServer"), Caption, Muted, 20, 14, 300, 18));
            choices = new ListBox
            {
                Bounds = R(16, 36, 470, 266), DrawMode = DrawMode.OwnerDrawFixed, ItemHeight = D(44),
                BorderStyle = BorderStyle.None, IntegralHeight = false, Font = Body,
            };
            c2.Add(choices);
            choices.BackColor = Theme.Card;
            foreach (var ch in SystemDns.Choices) choices.Items.Add(ch);
            choices.DrawItem += DrawChoice;
            choices.SelectedIndexChanged += (s, e) => { if (bRestore != null) Sync(); };

            chkDoh = c2.Add(new CheckX { Text = Loc.T("dnsPage.useDoh"), Bounds = R(504, 36, 244, 26), Checked = SystemDns.DohSupported });
            c2.Add(UIx.L(SystemDns.DohSupported
                    ? Loc.T("dnsPage.dohInfo")
                    : Loc.T("dnsPage.dohUnsupported"),
                Small, Muted, 530, 62, 218, 62));
            chkDoh.Enabled = SystemDns.DohSupported;
            bApply = c2.Add(new FlatBtn { Text = Loc.T("dnsPage.apply"), Glyph = GCheck, Kind = FlatBtn.Kinds.Primary, Bounds = R(504, 160, 244, 40) });
            bRestore = c2.Add(new FlatBtn { Text = Loc.T("dnsPage.restore"), Glyph = GUndo, Kind = FlatBtn.Kinds.Secondary, Bounds = R(504, 208, 244, 36) });
            c2.Add(UIx.L(Loc.T("dnsPage.allAdapters"), Small, Muted, 504, 252, 244, 44));
            bApply.Click += async (s, e) => await Apply();
            bRestore.Click += async (s, e) => await Restore();

            Controls.Add(UIx.L(Loc.T("dnsPage.note"), Small, Muted, 29, 580, 764, 40));
            choices.SelectedIndex = 1;
        }

        public override void OnActivated() => _ = ShowCurrent();

        void Sync()
        {
            var c = choices.SelectedItem as SystemDnsChoice;
            chkDoh.Visible = c != null && !c.IsAuto;
            bRestore.Enabled = App.Settings.DnsBackups.Count > 0 || App.Settings.DohBackups.Count > 0;
        }

        void DrawChoice(object sender, DrawItemEventArgs e)
        {
            if (e.Index < 0) return;
            var c = (SystemDnsChoice)choices.Items[e.Index];
            var g = e.Graphics;
            HQ(g);
            bool sel = (e.State & DrawItemState.Selected) != 0;
            var r = e.Bounds;
            using (var b = new SolidBrush(Theme.Card)) g.FillRectangle(b, r);
            Color bg = sel ? AccentSoft : Theme.Card;
            using (var p = Round(new RectangleF(r.X + 2, r.Y + 2, r.Width - 5, r.Height - 4), D(8)))
            {
                using (var b = new SolidBrush(bg)) g.FillPath(b, p);
                if (sel) using (var pen = new Pen(AccentBorder)) g.DrawPath(pen, p);
            }
            // radio button
            var dot = new RectangleF(r.X + D(12), r.Y + D(14), D(16), D(16));
            using (var pen = new Pen(sel ? Accent : Mix(Border, Theme.Text, 0.3f), 1.5f)) g.DrawEllipse(pen, dot);
            if (sel) using (var b = new SolidBrush(Accent)) g.FillEllipse(b, RectangleF.Inflate(dot, -D(4), -D(4)));
            string addr = c.IsAuto ? Loc.T("dnsPage.dhcp") : c.V4a + ", " + c.V4b;
            TextRenderer.DrawText(g, c.Name, Bold, new Rectangle(r.X + D(38), r.Y + D(5), r.Width - D(44), D(20)), Theme.Text, bg, TextFormatFlags.NoPadding | TextFormatFlags.EndEllipsis);
            TextRenderer.DrawText(g, addr + "  ·  " + c.Note, Small, new Rectangle(r.X + D(38), r.Y + D(24), r.Width - D(44), D(18)), Muted, bg, TextFormatFlags.NoPadding | TextFormatFlags.EndEllipsis);
        }

        async Task ShowCurrent()
        {
            Sync();
            current.Clear();
            var adapters = await Task.Run(() => SystemDns.TargetAdapters());
            if (IsDisposed) return;
            current.Clear();
            if (adapters.Count == 0) { current.Muted(Loc.T("dnsPage.noAdapter")); return; }
            foreach (var a in adapters)
            {
                string id = SystemDns.CurrentChoiceId(a);
                var ch = SystemDns.Choices.FirstOrDefault(x => x.Id == id);
                current.Out(a.Name + "  ·  " + a.Type, Theme.Text, Bold);
                current.Kv("   " + Loc.T("dnsPage.setting"), ch != null ? ch.Name : Loc.T("dnsPage.manualServer"));
                current.Kv("   " + Loc.T("dnsPage.dnsInUse"), a.Dns.Count > 0 ? string.Join(", ", a.Dns.Take(3)) : "—");
            }
            if (App.Settings.DnsBackups.Count > 0) current.Muted(Loc.T("dnsPage.backedUp"));
        }

        async Task CheckBlock()
        {
            bCheck.Enabled = false;
            result.Text = Loc.T("dnsPage.checking");
            result.ForeColor = Muted;
            var rep = await Task.Run(() => { Native.FlushDns(); return NetTest.CheckDns("discord.com"); });
            if (IsDisposed) return;
            bool redirect = App.Engine.State == EngineState.Running && (App.Engine.ActiveProfile?.UsesDnsRedirect ?? false);
            result.Text = (rep.Blocked ? "✗ " : rep.Reference.Count == 0 ? "? " : "✓ ") + rep.Verdict +
                          (redirect ? "\n" + Loc.T("dnsPage.redirecting") : "");
            result.ForeColor = rep.Blocked ? RedText : rep.Reference.Count == 0 ? AmberText : GreenText;
            bCheck.Enabled = true;
        }

        async Task Apply()
        {
            if (!(choices.SelectedItem is SystemDnsChoice c)) return;
            var adapters = SystemDns.TargetAdapters();
            if (adapters.Count == 0) { MessageBox.Show(FindForm(), Loc.T("dnsPage.noAdapter"), App.Name); return; }
            bool doh = chkDoh.Checked && chkDoh.Enabled && !c.IsAuto;
            string what = c.IsAuto ? Loc.T("dnsPage.autoProvider") : c.Name + " (" + c.V4a + ")" + (doh ? " + " + Loc.T("dnsPage.encryptedDns") : "");
            if (MessageBox.Show(FindForm(),
                    Loc.T("dnsPage.applyConfirm", string.Join("\n  ", adapters.Select(a => a.Name)), what),
                    App.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            bApply.Enabled = bRestore.Enabled = false;
            string report = null;
            bool ok = await Task.Run(() => SystemDns.Apply(c, doh, adapters, out report));
            if (IsDisposed) return;
            bApply.Enabled = true;
            await ShowCurrent();
            current.Blank();
            current.Out(ok ? Loc.T("dnsPage.applied") : Loc.T("dnsPage.someFailed"), ok ? GreenText : AmberText, Bold);
            foreach (var line in (report ?? "").Split('\n')) current.Muted(line.TrimEnd());
            await CheckBlock();
        }

        async Task Restore()
        {
            bApply.Enabled = bRestore.Enabled = false;
            string report = null;
            bool ok = await Task.Run(() => SystemDns.Restore(out report));
            if (IsDisposed) return;
            bApply.Enabled = true;
            await ShowCurrent();
            current.Blank();
            current.Out(ok ? Loc.T("dnsPage.restored") : Loc.T("dnsPage.someFailedEnd"), ok ? GreenText : AmberText, Bold);
            foreach (var line in (report ?? "").Split('\n')) current.Muted(line.TrimEnd());
        }
    }
}
