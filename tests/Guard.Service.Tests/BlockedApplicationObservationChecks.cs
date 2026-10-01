using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Guard.Service;

namespace Guard.Service.Tests;

internal static class BlockedApplicationObservationChecks
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-10-01T12:00:00Z");
    private static readonly Guid Policy = new("8242ff3a-550e-4d59-aeee-ae2041dbb36d");
    private static readonly string FileHash = new('A', 64);
    private static readonly string PolicyHash = new('B', 64);
    private const string Account = "S-1-5-21-111-222-333-1001";

    internal static async Task RunAsync()
    {
        // Public synthetic event data only. No installed policies, real user logs or log writes.
        var source = new WindowsBlockedApplicationObservations("device-observation-test", Policy, PolicyHash, TimeProvider.System);
        var xml = EventXml();
        var observation = source.ParseLocalEvent(xml, Now) ?? throw new Exception("Valid block event was rejected.");
        Check(observation.Identity.FileSha256 == FileHash && observation.Identity.AuthorizationKey == "sha256:" + FileHash,
            "Authenticode hash was confused with the whole-file SHA256.");
        Check(observation.ChildAccountSid.Value == Account && observation.DisplayName == "reader.exe" &&
            observation.VerifiedSignatureSummary == null && observation.DeviceId == "device-observation-test",
            "Source account, device or display provenance changed.");
        Check(source.ParseLocalEvent(xml, Now.AddMinutes(29))!.ObservationId == observation.ObservationId &&
            source.ParseLocalEvent(xml, Now.AddMinutes(30)) == null && source.ParseLocalEvent(xml, Now.AddTicks(-1)) == null,
            "An event was renewed or accepted outside its fixed observation lifetime.");
        var renamed = source.ParseLocalEvent(xml.Replace("reader.exe", "renamed.exe"), Now)!;
        Check(renamed.Identity.Equals(observation.Identity) && renamed.ObservationId != observation.ObservationId,
            "A mutable name became the authority or event locator was reused.");
        var replaced = source.ParseLocalEvent(xml.Replace(FileHash, new string('C', 64)), Now)!;
        Check(!replaced.Identity.Equals(observation.Identity) && replaced.ObservationId != observation.ObservationId,
            "Changed content inherited a same-path identity or locator.");
        Check(new WindowsBlockedApplicationObservations("device-observation-test", Guid.NewGuid(), PolicyHash, TimeProvider.System)
            .ParseLocalEvent(xml, Now) == null, "A different policy was accepted.");
        Check(new WindowsBlockedApplicationObservations("device-observation-test", Policy, new string('D', 64), TimeProvider.System)
            .ParseLocalEvent(xml, Now) == null, "An old/different policy binary was accepted.");

        var invalid = new[]
        {
            "", "<Event>", new string('x', WindowsBlockedApplicationObservations.MaximumXmlCharacters + 1),
            "<!DOCTYPE Event [<!ENTITY file SYSTEM 'file:///must-not-be-read'>]>" + xml.Replace("reader.exe", "&file;"),
            xml.Replace("<EventID>3077", "<EventID>3076"), xml.Replace("<Version>5", "<Version>4"),
            xml.Replace("<Version>5", "<Version>6"), xml.Replace(WindowsBlockedApplicationObservations.Channel, "Application"),
            xml.Replace(WindowsBlockedApplicationObservations.ProviderId, Guid.Empty.ToString("D")),
            xml.Replace("Name=\"Microsoft-Windows-CodeIntegrity\"", "Name=\"Other\""),
            xml.Replace("<EventRecordID>42", "<EventRecordID>0"), xml.Replace("<EventRecordID>42", "<EventRecordID>042"),
            xml.Replace("<EventRecordID>42", "<EventRecordID>9223372036854775808"),
            xml.Replace("<EventRecordID>42</EventRecordID>", "<EventRecordID>42</EventRecordID><EventRecordID>43</EventRecordID>"),
            xml.Replace(Account, "S-1-5-21-0111-222-333-1001"), xml.Replace($"UserID=\"{Account}\"", ""),
            xml.Replace("2026-10-01T12:00:00Z", "invalid-date"),
            xml.Replace("2026-10-01T12:00:00Z", "2026-10-01T15:00:00+03:00"),
            xml.Replace("Name=\"PolicyHashSize\">32", "Name=\"PolicyHashSize\">20"),
            xml.Replace("Name=\"SI Signing Scenario\">1", "Name=\"SI Signing Scenario\">0"),
            xml.Replace("Name=\"PackageFamilyName\"></Data>", "Name=\"PackageFamilyName\">Example_123456789abcd</Data>"),
            xml.Replace("Name=\"SHA256 Flat Hash Size\">32", "Name=\"SHA256 Flat Hash Size\">20"),
            xml.Replace("Name=\"SHA256 Flat Hash\"", "Name=\"Absent Flat Hash\""),
            xml.Replace(FileHash, new string('G', 64)), xml.Replace(FileHash, " " + FileHash),
            xml.Replace("</EventData>", $"<Data Name=\"SHA256 Flat Hash\">{FileHash}</Data></EventData>"),
            xml.Replace("Name=\"File Name\">", "Name=\"File Name\"><Nested/>"),
            xml.Replace("reader.exe", "reader.dll"), xml.Replace("reader.exe", "reader.exe:stream"),
            xml.Replace("reader.exe", "reader\u202e.exe"), xml.Replace("reader.exe", "reader\n.exe"),
            xml.Replace(@"\Device\HarddiskVolume3", @"\\server\share"),
            xml.Replace("reader.exe", new string('x', 1024) + ".exe"),
            xml.Replace("</EventData>", string.Concat(Enumerable.Range(0, 65).Select(i => $"<Data Name=\"Extra{i}\">x</Data>")) + "</EventData>")
        };
        foreach (var item in invalid)
            Check(source.ParseLocalEvent(item, Now) == null, "Malformed/unbound event became a verified observation (case " + Array.IndexOf(invalid, item) + ").");

        // Invalid locators must be refused before querying Windows. In particular, never
        // concatenate an arbitrary child-supplied string into an EventLog XPath.
        foreach (var id in new[] { "", "ci:42'] or 1=1:" + FileHash, "ci:042:" + FileHash,
            "ci:0:" + FileHash, "ci:9223372036854775808:" + FileHash, "ci:42:" + FileHash.ToLowerInvariant(),
            "ci:42:" + FileHash + ":extra" })
            Check(await source.ResolveAsync(id, CancellationToken.None) == null, "Untrusted locator was accepted.");
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        try { await source.ResolveAsync(observation.ObservationId, cancelled.Token); throw new Exception("Cancellation was ignored."); }
        catch (OperationCanceledException) { }
    }

    private static string EventXml() => $$"""
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <Provider Name="Microsoft-Windows-CodeIntegrity" Guid="{4ee76bd8-3cf4-44a0-a0ac-3937643e37a3}"/>
            <EventID>3077</EventID><Version>5</Version><EventRecordID>42</EventRecordID>
            <Channel>Microsoft-Windows-CodeIntegrity/Operational</Channel>
            <TimeCreated SystemTime="2026-10-01T12:00:00Z"/><Security UserID="{{Account}}"/>
          </System>
          <EventData>
            <Data Name="File Name">\Device\HarddiskVolume3\unopened-fixture\reader.exe</Data>
            <Data Name="SHA256 Hash">{{new string('E', 64)}}</Data>
            <Data Name="SHA256 Flat Hash Size">32</Data><Data Name="SHA256 Flat Hash">{{FileHash}}</Data>
            <Data Name="PolicyGUID">{{Policy.ToString("B")}}</Data>
            <Data Name="PolicyID">Friendly name, not the policy GUID</Data>
            <Data Name="PolicyHashSize">32</Data><Data Name="PolicyHash">{{PolicyHash}}</Data>
            <Data Name="SI Signing Scenario">1</Data><Data Name="PackageFamilyName"></Data>
          </EventData>
        </Event>
        """;

    private static void Check(bool condition, string message) { if (!condition) throw new Exception(message); }
}
