using System;
using System.Drawing;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using static NSFShield.Theme;

namespace NSFShield
{
    /// <summary>New version window: notes, download (SHA-256 verified) and installation.</summary>
    sealed class UpdateDialog : Form
    {
        readonly UpdateInfo info;
        readonly ReportBox notes;
        readonly ProgressLine bar;
        readonly Label status;
        readonly FlatBtn bUpdate, bSkip, bLater;
        CancellationTokenSource cts;
        bool busy;

        /// <summary>Checks for updates; opens the window if there is a new version, otherwise (manual check) shows a message.</summary>
        public static async Task CheckAndShow(IWin32Window owner, bool manual)
        {
            if (Updater.Checking) return;
            string err = null;
            var i = await Task.Run(() => Updater.Check(out err));
            if (i == null)
            {
                if (manual) MessageBox.Show(owner, Loc.T("updateDialog.checkFailed") + "\n\n" + err, App.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            // the same decision as the automatic check (Updater.FitFor): newer, and installable by this copy?
            var fit = Updater.LastFit;
            if (fit == Updater.Fit.UpToDate)
            {
                if (manual) MessageBox.Show(owner, Loc.T("updateDialog.upToDate", App.Version), App.Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            if (!manual && Updater.Skipped(i)) return;
            if (fit == Updater.Fit.NeedsInstalledVersion)
            {
                // a portable copy and a release with only the setup package: no empty zip download, the switch is offered
                if (!manual) { MainForm.Instance?.ShowBalloon(Loc.T("updateDialog.newVersion", i.Version), Loc.T("updateDialog.needsSetupShort", i.Version), ToolTipIcon.Info); return; }
                if (MessageBox.Show(owner, Loc.T("updateDialog.needsSetup", i.Version), App.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Information) == DialogResult.Yes)
                    SwitchDialog.Run(owner);
                return;
            }
            if (fit == Updater.Fit.NoPackage)
            {
                if (manual) MessageBox.Show(owner, Loc.T("updateDialog.noPackage", i.Version), App.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            if (!manual)
            {
                MainForm.Instance?.ShowBalloon(Loc.T("updateDialog.newVersion", i.Version), Loc.T("updateDialog.released", i.Version), ToolTipIcon.Info);
                return;
            }
            ShowFor(owner, i);
        }

        public static void ShowFor(IWin32Window owner, UpdateInfo i)
        {
            using (var d = new UpdateDialog(i)) d.ShowDialog(owner);
        }

        UpdateDialog(UpdateInfo i)
        {
            info = i;
            Text = Loc.T("updateDialog.title") + " – " + App.Name;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterParent;
            MaximizeBox = MinimizeBox = false;
            ShowInTaskbar = false;
            AutoScaleMode = AutoScaleMode.None;
            BackColor = Bg;
            Font = Body;
            ClientSize = new Size(D(600), D(520));
            UIx.FitDialog(this);
            Icon = IconArt.AppIcon(32);

            Controls.Add(UIx.L(Loc.T("updateDialog.heading", i.Version), H2, Theme.Text, 24, 16, 550, 30));
            Controls.Add(UIx.L(Loc.T("updateDialog.current", App.Version) + (i.Published > DateTime.MinValue ? "  ·  " + Loc.T("updateDialog.publishedOn") + " " + i.Published.ToLocalTime().ToString("dd.MM.yyyy") : "") +
                               (i.Size > 0 ? "  ·  " + (i.Size / 1024) + " KB" : "") + "  ·  " + Loc.T("updateDialog.verifiedSha"), Small, Muted, 25, 48, 550, 20));
            var card = new Card { Bounds = R(24, 78, 552, 330) };
            Controls.Add(card);
            notes = card.Add(new ReportBox { Bounds = R(16, 12, 520, 306) });
            notes.BackColor = Theme.Card;
            notes.Out(Loc.T("updateDialog.whatsNew"), Muted, Caption);
            foreach (var raw in (i.Notes ?? "").Replace("\r", "").Split('\n'))
            {
                string line = raw.Trim();
                if (line.StartsWith("**SHA-256") || line.StartsWith("SHA-256")) continue;
                bool head = line.StartsWith("#");
                line = Regex.Replace(line, @"^#+\s*", "");
                line = line.Replace("**", "").Replace("`", "");
                line = Regex.Replace(line, @"^[-*]\s+", "•  ");
                line = Regex.Replace(line, @"\[([^\]]+)\]\([^)]+\)", "$1");
                if (head) notes.Out(line, Theme.Text, Bold); else notes.Out(line, Theme.Text, Small);
            }
            notes.SelectionStart = 0;

            status = UIx.L(Loc.T("updateDialog.info"),
                Small, Muted, 24, 414, 552, 34);
            Controls.Add(status);
            bar = new ProgressLine { Bounds = R(24, 450, 552, 6), BackColor = Bg, Visible = false };
            Controls.Add(bar);

            bUpdate = new FlatBtn { Text = Loc.T("updateDialog.updateNow"), Glyph = GRefresh, Kind = FlatBtn.Kinds.Primary, Bounds = R(24, 466, 190, 40) };
            bSkip = new FlatBtn { Text = Loc.T("updateDialog.skip"), Kind = FlatBtn.Kinds.Secondary, Bounds = R(222, 466, 160, 40) };
            bLater = new FlatBtn { Text = Loc.T("updateDialog.later"), Kind = FlatBtn.Kinds.Secondary, Bounds = R(456, 466, 120, 40) };
            Controls.AddRange(new Control[] { bUpdate, bSkip, bLater });
            bUpdate.Click += async (s, e) => await DoUpdate();
            bSkip.Click += (s, e) =>
            {
                App.Settings.SkipVersion = i.Version.ToString();
                App.Save();
                App.Log("Update skipped: " + i.Version, LogLevel.Info);
                Close();
            };
            bLater.Click += (s, e) => Close();
        }

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            Native.DarkTitle(Handle, IsDark);
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (busy) { cts?.Cancel(); e.Cancel = true; return; }
            base.OnFormClosing(e);
        }

        async Task DoUpdate()
        {
            busy = true;
            bUpdate.Enabled = bSkip.Enabled = false;
            bLater.Text = Loc.T("common.cancel");
            bar.Visible = true;
            status.ForeColor = Muted;
            cts = new CancellationTokenSource();
            try
            {
                status.Text = Loc.T("updateDialog.downloading");
                Action<long, long> progress = (got, total) =>
                {
                    try
                    {
                        BeginInvoke(new Action(() =>
                        {
                            if (IsDisposed) return;
                            bar.Value = total > 0 ? got / (float)total : 0;
                            status.Text = Loc.T("updateDialog.downloadingKb", got / 1024, total / 1024);
                        }));
                    }
                    catch (Exception ex) { App.Ignored("Progress could not be shown", ex); }
                };
                // The installed version is updated with the setup package (the Add/Remove Programs entry stays current); the portable version with the zip
                bool installed = await Task.Run(() => Updater.InstalledMode);
                if (Updater.FitFor(info, installed) != Updater.Fit.Ready) throw new InvalidOperationException(Loc.T("updateDialog.noPackage", info.Version));
                bool viaSetup = Updater.UseSetup(info, installed);
                var token = cts.Token;
                var prep = viaSetup ? await Task.Run(() => Updater.DownloadSetup(info, progress, token))
                                    : await Task.Run(() => Updater.DownloadAndExtract(info, progress, token));
                status.Text = Loc.T("updateDialog.installing");
                status.ForeColor = GreenText;
                await Task.Delay(600, token);
                // a cancel during the short pause still wins: nothing is started after it
                token.ThrowIfCancellationRequested();
                if (viaSetup) Updater.StartSetup(prep); else Updater.StartApply(prep);
                busy = false;
                MainForm.Instance.ExitApp(false);
            }
            catch (OperationCanceledException)
            {
                busy = false;
                status.Text = Loc.T("updateDialog.cancelled");
                Reset();
            }
            catch (Exception ex)
            {
                busy = false;
                App.Log("Update failed: " + ex.Message, LogLevel.Error);
                status.Text = Loc.T("updateDialog.failed", ex.Message);
                status.ForeColor = RedText;
                Reset();
            }
        }

        void Reset()
        {
            if (IsDisposed) return;
            bUpdate.Enabled = bSkip.Enabled = true;
            bLater.Text = Loc.T("common.close");
            bar.Visible = false;
        }
    }
}
