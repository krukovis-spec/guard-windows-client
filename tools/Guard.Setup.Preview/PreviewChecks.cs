using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;

namespace Guard.Setup;

internal static class PreviewChecks
{
    internal static async Task RunAsync()
    {
        var peer = new PreviewBackend();
        var window = PreviewProgram.CreateWindow(peer);
        try
        {
            window.Show(); window.Activate();
            await Until(() => window.IsActive, "preview window must be active");
            Click(window.Refresh);
            await Until(() => window.BeginEnrollment.IsEnabled, "inspection did not complete");
            Click(window.BeginEnrollment);
            await Until(() => window.EnrollmentQrImage.Source != null && window.CancelEnrollment.IsEnabled, "QR missing");
            var image = window.EnrollmentQrImage.Source;
            var transitions = 0;
            window.Refresh.IsEnabledChanged += (_, _) => transitions++;
            window.Cancel.IsEnabledChanged += (_, _) => transitions++;
            window.RefreshEnrollment.IsEnabledChanged += (_, _) => transitions++;
            window.CancelEnrollment.IsEnabledChanged += (_, _) => transitions++;
            var before = peer.AdvanceCalls;
            await Until(() => peer.AdvanceCalls >= before + 2 && peer.ActiveCalls == 0, "background polls missing");
            Check(transitions == 0, "Background polling toggled buttons: " + transitions);
            Check(ReferenceEquals(image, window.EnrollmentQrImage.Source), "unchanged poll rebuilt QR");
            Check(peer.ConfirmCalls == 0 && peer.CancelCalls == 0, "poll changed authority");
            foreach (var width in new[] { 760.0, 420.0 })
            {
                window.Width = width; window.Height = 660; window.UpdateLayout();
                window.EnrollmentQrFrame.BringIntoView(); await Task.Delay(80);
                var rect = window.EnrollmentQrFrame.TransformToAncestor(window.SetupScroll)
                    .TransformBounds(new Rect(window.EnrollmentQrFrame.RenderSize));
                Check(rect.Width <= 320.5 && rect.Height <= window.SetupScroll.ViewportHeight + 0.5 &&
                    rect.Top >= -0.5 && rect.Bottom <= window.SetupScroll.ViewportHeight + 0.5, "QR clipped in viewport");
            }
            Console.WriteLine("PASS: unchanged polling has zero button transitions; QR remains visible at 760/420 DIP");

            peer.Phase = "compare-phone"; peer.Version++;
            await Until(() => window.ComparisonPanel.Visibility == Visibility.Visible, "comparison missing");
            Check(window.ComparisonCode.Text.Replace("\n", "").Replace("\r", "") == PreviewBackend.Hash &&
                !window.ConfirmEnrollment.IsEnabled, "full comparison/explicit consent lost");
            Click(window.ConfirmEnrollment);
            Check(peer.ConfirmCalls == 0, "confirmation without checkbox");
            window.Compared.IsChecked = true;
            var other = new Window { Title = "ДЕМО — проверка потери фокуса", Width = 260, Height = 100 };
            try
            {
                other.Show(); other.Activate(); await Until(() => !window.IsActive, "focus did not leave preview");
                Check(window.ComparisonCode.Text.Length == 0 && window.Compared.IsChecked == false, "focus loss retained comparison");
                window.Activate(); await Until(() => window.IsActive && window.ComparisonCode.Text.Length > 0, "comparison did not return");
                Check(!window.ConfirmEnrollment.IsEnabled, "focus return retained consent");
            }
            finally { other.Close(); }
            window.Activate(); window.Compared.IsChecked = true; peer.LoseConfirmation = true;
            Click(window.ConfirmEnrollment);
            await Until(() => peer.ConfirmCalls == 1 && peer.ActiveCalls == 0 && window.RefreshEnrollment.IsEnabled, "lost confirmation not recoverable");
            Check(window.ComparisonCode.Text.Length == 0, "lost response retained comparison evidence");
            Click(window.RefreshEnrollment);
            await Until(() => window.EnrollmentStatus.Text.StartsWith("Привязка сохранена") && peer.ActiveCalls == 0, "result read failed");
            Check(peer.ConfirmCalls == 1 && !window.ConfirmEnrollment.IsEnabled, "result query repeated confirmation");
            Console.WriteLine("PASS: full comparison, focus reset, explicit confirmation and lost-reply read-only recovery");
        }
        finally { window.Close(); }

        peer = new PreviewBackend(); window = await StartAsync(peer);
        try
        {
            peer.Fail = true;
            await Until(() => window.EnrollmentQrImage.Source == null && window.EnrollmentStatus.Text.StartsWith("Не удалось получить"), "offline evidence not cleared");
            Check(window.RefreshEnrollment.IsEnabled && !window.CancelEnrollment.IsEnabled, "offline controls unsafe");
            peer.Fail = false; Click(window.RefreshEnrollment);
            await Until(() => window.EnrollmentQrImage.Source != null && window.CancelEnrollment.IsEnabled, "manual retry did not restore QR");
            var release = Hold(peer);
            await peer.AdvanceEntered!.Task.WaitAsync(TimeSpan.FromSeconds(12));
            Click(window.CancelEnrollment); Click(window.CancelEnrollment);
            Check(peer.CancelCalls == 0, "cancel overlapped background poll");
            release.SetResult();
            await Until(() => peer.CancelCalls == 1 && window.EnrollmentStatus.Text.StartsWith("Попытка привязки отменена"), "queued cancel was lost");
            Check(peer.MaxActiveCalls == 1 && peer.ConfirmCalls == 0, "overlapping or duplicated command");
            Console.WriteLine("PASS: offline/retry clears evidence; queued double-click cancels exactly once without overlap");
        }
        finally { window.Close(); }

        peer = new PreviewBackend(); window = await StartAsync(peer);
        try
        {
            var release = Hold(peer);
            await peer.AdvanceEntered!.Task.WaitAsync(TimeSpan.FromSeconds(12));
            Click(window.CancelEnrollment);
            peer.Phase = "compare-phone"; peer.Version++;
            release.SetResult();
            await Until(() => peer.ActiveCalls == 0 && window.ComparisonPanel.Visibility == Visibility.Visible, "changed state not rendered");
            Check(peer.CancelCalls == 0 && peer.ConfirmCalls == 0, "queued stale action used newer screen");
            Console.WriteLine("PASS: queued action refuses changed comparison/version");
        }
        finally { window.Close(); }

        peer = new PreviewBackend { Lifetime = TimeSpan.FromSeconds(3) }; window = await StartAsync(peer);
        try
        {
            await Until(() => window.EnrollmentStatus.Text.StartsWith("Срок попытки закончился"), "expired screen not shown");
            Check(window.EnrollmentQrImage.Source == null && !window.ConfirmEnrollment.IsEnabled &&
                !window.CancelEnrollment.IsEnabled, "expired evidence/action retained");
            Console.WriteLine("PASS: expiry hides QR and refuses confirmation/cancel");
        }
        finally { window.Close(); }

        peer = new PreviewBackend(); window = await StartAsync(peer);
        Hold(peer);
        await peer.AdvanceEntered!.Task.WaitAsync(TimeSpan.FromSeconds(12));
        window.Close();
        await Until(() => peer.ActiveCalls == 0, "close did not drain pending poll");
        Check(peer.CancelCalls == 0 && peer.ConfirmCalls == 0 && window.EnrollmentQrImage.Source == null, "close changed owner or retained evidence");
        Console.WriteLine("PASS: close cancels local read only; no remote command");
    }

    private static TaskCompletionSource Hold(PreviewBackend peer)
    {
        peer.HoldNextAdvance = new(TaskCreationOptions.RunContinuationsAsynchronously);
        peer.AdvanceEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        return peer.HoldNextAdvance;
    }

    private static async Task<SetupWindow> StartAsync(PreviewBackend peer)
    {
        var window = PreviewProgram.CreateWindow(peer);
        try
        {
            window.Show(); window.Activate(); await Until(() => window.IsActive, "preview inactive");
            Click(window.Refresh); await Until(() => window.BeginEnrollment.IsEnabled, "inspection failed");
            Click(window.BeginEnrollment);
            await Until(() => window.EnrollmentQrImage.Source != null && window.CancelEnrollment.IsEnabled, "initial QR missing");
            return window;
        }
        catch { window.Close(); throw; }
    }

    internal static void Click(Button button) => button.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
    internal static void Check(bool value, string message) { if (!value) throw new InvalidOperationException(message); }
    internal static async Task Until(Func<bool> predicate, string message)
    {
        var clock = Stopwatch.StartNew();
        while (!predicate())
        {
            if (clock.Elapsed > TimeSpan.FromSeconds(12)) throw new InvalidOperationException(message);
            await Task.Delay(25);
        }
    }
}
