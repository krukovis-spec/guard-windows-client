using System;
using System.Buffers.Binary;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Xml.Linq;
using Guard.Contracts.Relay;
using Guard.Protocol.Relay;
using Guard.Setup;
using Guard.Windows.Ipc;

namespace Guard.Windows.Ipc.Tests;

internal static class EnrollmentViewChecks
{
    internal static void Run()
    {
        CheckCompactLayout();
        var now = DateTimeOffset.FromUnixTimeMilliseconds(1790812800000);
        var expiry = now.AddMinutes(5);
        const string hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        using var signing = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var encryption = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var offer = new EnrollmentOffer("https://relay.example.test", "enrollment-qr-test-0001", "device-qr-test-0001", "QR test",
            1, 1, "mailbox-qr-test-0001", "signing-qr-test-0001", signing.ExportSubjectPublicKeyInfo()[26..],
            "encryption-qr-test-0001", encryption.ExportSubjectPublicKeyInfo()[26..], now, expiry, RandomNumberGenerator.GetBytes(32));
        var qr = RelayCanonicalEncoding.EncodeEnrollmentQr(offer, RandomNumberGenerator.GetBytes(32));
        var png = EnrollmentQr.Render(qr);
        Check(png.AsSpan(0, 8).SequenceEqual(new byte[] { 137,80,78,71,13,10,26,10 }), "QR is not PNG");
        var size = BinaryPrimitives.ReadInt32BigEndian(png.AsSpan(16, 4));
        Check(size > 200 && size <= 1110 && size % 6 == 0 &&
            BinaryPrimitives.ReadInt32BigEndian(png.AsSpan(20, 4)) == size, "QR dimensions/quiet zone exceeded bound");
        CryptographicOperations.ZeroMemory(png);
        foreach (var input in new[] { "", "https://example.test", "guard-enroll://v2?offer=" + new string('x', 2200) })
        {
            try { EnrollmentQr.Render(input); throw new InvalidOperationException("bad QR accepted"); }
            catch (ArgumentException) { }
        }
        foreach (var phase in Enum.GetValues<NativeSetupPhase>())
        {
            var snapshot = new NativeSetupSnapshot(phase, 7, phase == NativeSetupPhase.ScanPhone ? qr : null,
                phase is NativeSetupPhase.ComparePhone or NativeSetupPhase.ConfirmationUnknown or NativeSetupPhase.Confirmed ? hash : null);
            var view = EnrollmentView.Create(snapshot, expiry, now);
            Check(view.Message.Length != 0 && !view.Message.Contains(qr, StringComparison.Ordinal), "missing/private state message");
            Check(view.ShowQr == (phase == NativeSetupPhase.ScanPhone), "QR visible outside scan phase");
            Check(view.CanCompare == (phase == NativeSetupPhase.ComparePhone), "confirmation available outside comparison");
            Check(view.ComparisonCode.Replace("\n", "") == (view.CanCompare ? hash : ""), "comparison truncated/retained");
            if (view.CanCompare) Check(view.ComparisonCode.Split('\n').All(line => line.Length == 8) && !view.AutoRefresh, "comparison changes during review");
            var expired = EnrollmentView.Create(snapshot, expiry, expiry);
            Check(!expired.ShowQr && !expired.CanCompare && !expired.CanCancel, "expiry retained sensitive action");
            Check(expired.CanRefresh == (phase is NativeSetupPhase.ConfirmationUnknown or NativeSetupPhase.Confirmed), "lost-result read blocked or expired mutation enabled");
            Check(view.CanCancel == (phase is NativeSetupPhase.ScanPhone or NativeSetupPhase.PhoneProof or NativeSetupPhase.ComparePhone or NativeSetupPhase.RestartRequired), "unsafe cancellation action");
        }
        var confirmed = EnrollmentView.Create(new NativeSetupSnapshot(NativeSetupPhase.Confirmed, 8,
            claimHash: hash, relayPassCompleted: true), expiry, now);
        Check(!confirmed.AutoRefresh && confirmed.Message.Contains("ещё не подтверждает", StringComparison.Ordinal), "delivery claimed enforcement");
        var recovery = EnrollmentView.Create(new NativeSetupSnapshot(NativeSetupPhase.Confirmed, 8,
            claimHash: hash, recoveryRequired: true), expiry, now);
        Check(!recovery.AutoRefresh && recovery.Message.Contains("не сбрасывайте", StringComparison.Ordinal), "recovery encouraged owner reset");
    }
    private static void CheckCompactLayout()
    {
        using var source = typeof(EnrollmentViewChecks).Assembly.GetManifestResourceStream("Guard.Setup.SetupWindow.xaml")!;
        var window = XDocument.Load(source).Root!;
        XNamespace x = "http://schemas.microsoft.com/winfx/2006/xaml";
        XElement Named(string name) => window.Descendants().Single(element => (string?)element.Attribute(x + "Name") == name);
        var qr = Named("EnrollmentQrImage");
        var frame = qr.Parent!;
        Check((string?)window.Attribute("FontSize") == "14", "setup text is oversized");
        Check(frame.Name.LocalName == "Viewbox" && (string?)frame.Attribute("MaxWidth") == "320" &&
            (string?)frame.Attribute("MaxHeight") == "{Binding ViewportHeight, ElementName=SetupScroll}" &&
            (string?)frame.Attribute("Stretch") == "Uniform" && (string?)frame.Attribute("StretchDirection") == "DownOnly",
            "QR must fit both width and visible scroll height without cropping/upscaling");
        Check((string?)qr.Attribute("Width") == "320" && (string?)qr.Attribute("Height") == "320" &&
            (string?)qr.Attribute("Stretch") == "Uniform" && (string?)qr.Attribute("Visibility") == "Collapsed",
            "QR must stay square and hidden before an authenticated session");
        Check(Named("SetupScroll").Name.LocalName == "ScrollViewer", "QR height must use the real viewport");
    }
    private static void Check(bool value, string error) { if (!value) throw new InvalidDataException(error); }
}
