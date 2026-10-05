using System;
using QRCoder;

namespace Guard.Setup;

internal static class EnrollmentQr
{
    // The caller accepts QR text only from NativeSetupSession. No URL/service renderer.
    internal static byte[] Render(string text)
    {
        if (text == null || text.Length > 2200 || !text.StartsWith("guard-enroll://v2?offer=", StringComparison.Ordinal))
            throw new ArgumentException("Invalid enrollment QR.");
        using var data = QRCodeGenerator.GenerateQrCode(text, QRCodeGenerator.ECCLevel.M);
        using var renderer = new PngByteQRCode(data);
        return renderer.GetGraphic(6); // Black/white, including the standard quiet zone.
    }
}
