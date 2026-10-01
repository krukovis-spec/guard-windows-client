using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using Guard.Application;
using Guard.Contracts;
using Guard.Domain;
using Guard.Domain.Policy;

namespace Guard.Service;

// Read-only historical evidence, not an enforcement/readiness probe. The service must obtain
// policyId/hash from its verified active policy, and the account from the authenticated pipe.
// Do not register this while BoundaryOnlyPolicyReconciler is the production policy boundary.
internal sealed class WindowsBlockedApplicationObservations : IBlockedApplicationObservationResolver
{
    internal const string Channel = "Microsoft-Windows-CodeIntegrity/Operational";
    internal const string ProviderId = "4ee76bd8-3cf4-44a0-a0ac-3937643e37a3";
    internal const int MaximumXmlCharacters = 64 * 1024;
    private static readonly XNamespace EventNamespace = "http://schemas.microsoft.com/win/2004/08/events/event";
    private readonly string _deviceId;
    private readonly Guid _policyId;
    private readonly string _policyHash;
    private readonly TimeProvider _clock;

    internal WindowsBlockedApplicationObservations(string deviceId, Guid policyId, string policyHash, TimeProvider clock)
    {
        if (!GuardIdentifier.IsCanonicalToken(deviceId) || policyId == Guid.Empty || !IsHash(policyHash))
            throw new ArgumentException("A device and exact locally verified policy identity are required.");
        _deviceId = deviceId;
        _policyId = policyId;
        _policyHash = policyHash.ToUpperInvariant();
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
    }

    internal IReadOnlyList<VerifiedBlockedApplicationObservation> ReadRecent(WindowsAccountSid account, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(account);
        var result = new List<VerifiedBlockedApplicationObservation>();
        // SID is canonical numeric text, never a child-supplied XPath fragment.
        var query = "*[System[EventID=3077 and Security[@UserID='" + account.Value +
            "'] and TimeCreated[timediff(@SystemTime)<=1800000]]]";
        // ponytail: bounded newest-first scan; no second durable event queue. Add paging to the
        // child listing if the VM flood test needs more than 16 results from 64 recent events.
        foreach (var xml in ReadLocalEvents(query, 64, token))
        {
            var observation = ParseLocalEvent(xml, _clock.GetUtcNow());
            if (observation == null || !observation.ChildAccountSid.Equals(account)) continue;
            result.Add(observation);
            if (result.Count == 16) break;
        }
        token.ThrowIfCancellationRequested();
        var now = _clock.GetUtcNow();
        return result.Where(item => item.IsActiveAt(now)).ToArray();
    }

    public Task<VerifiedBlockedApplicationObservation?> ResolveAsync(string observationId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!TryReadRecordId(observationId, out var recordId))
            return Task.FromResult<VerifiedBlockedApplicationObservation?>(null);
        foreach (var xml in ReadLocalEvents("*[System[EventID=3077 and EventRecordID=" +
            recordId.ToString(CultureInfo.InvariantCulture) + "]]", 1, cancellationToken))
        {
            var observation = ParseLocalEvent(xml, _clock.GetUtcNow());
            cancellationToken.ThrowIfCancellationRequested();
            if (observation?.ObservationId == observationId && observation.IsActiveAt(_clock.GetUtcNow()))
                return Task.FromResult<VerifiedBlockedApplicationObservation?>(observation);
        }
        return Task.FromResult<VerifiedBlockedApplicationObservation?>(null);
    }

    private static IEnumerable<string> ReadLocalEvents(string query, int maximum, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        using var reader = new EventLogReader(new EventLogQuery(Channel, PathType.LogName, query)
        { ReverseDirection = true, TolerateQueryErrors = false });
        for (var count = 0; count < maximum; count++)
        {
            token.ThrowIfCancellationRequested();
            using var record = reader.ReadEvent(TimeSpan.FromMilliseconds(250));
            if (record == null) yield break;
            token.ThrowIfCancellationRequested();
            yield return record.ToXml();
        }
        // Access denied, missing log, stale query and native read errors must reach the
        // coordinator as dependency failures, not silently become an empty healthy inbox.
    }

    // Only local EventLogReader output enters here in production. Internal for synthetic
    // schema checks; accepting XML from IPC/relay/files would destroy the source boundary.
    internal VerifiedBlockedApplicationObservation? ParseLocalEvent(string xml, DateTimeOffset now)
    {
        if (string.IsNullOrEmpty(xml) || xml.Length > MaximumXmlCharacters) return null;
        try
        {
            using var input = new StringReader(xml);
            using var reader = XmlReader.Create(input, new XmlReaderSettings
            { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = MaximumXmlCharacters });
            var root = XElement.Load(reader);
            if (root.Name != EventNamespace + "Event") return null;
            var system = root.Elements(EventNamespace + "System").Single();
            string Value(string name) => system.Elements(EventNamespace + name).Single().Value;
            string Attribute(string name, string attribute) => (string?)system.Elements(EventNamespace + name).Single().Attribute(attribute)
                ?? throw new InvalidDataException("Missing event field.");
            if (Value("EventID") != "3077" || Value("Version") != "5" || Value("Channel") != Channel ||
                Attribute("Provider", "Name") != "Microsoft-Windows-CodeIntegrity" ||
                !Guid.TryParse(Attribute("Provider", "Guid"), out var provider) || provider.ToString("D") != ProviderId)
                return null;
            var recordText = Value("EventRecordID");
            if (!long.TryParse(recordText, NumberStyles.None, CultureInfo.InvariantCulture, out var recordId) || recordId <= 0 ||
                recordText != recordId.ToString(CultureInfo.InvariantCulture)) return null;
            var observed = XmlConvert.ToDateTimeOffset(Attribute("TimeCreated", "SystemTime"));
            if (observed.Offset != TimeSpan.Zero || now < observed || now - observed >= VerifiedBlockedApplicationObservation.MaximumLifetime)
                return null;
            var account = new WindowsAccountSid(Attribute("Security", "UserID"));
            var fields = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var element in root.Elements(EventNamespace + "EventData").Single().Elements())
            {
                var name = (string?)element.Attribute("Name");
                if (element.Name != EventNamespace + "Data" || element.HasElements || name == null || name.Length > 64 ||
                    element.Value.Length > 2048 || fields.Count >= 64 || !fields.TryAdd(name, element.Value)) return null;
            }
            string Field(string name) => fields.TryGetValue(name, out var value) ? value : throw new InvalidDataException("Missing event data.");
            if (!Guid.TryParse(Field("PolicyGUID"), out var policy) || policy != _policyId ||
                Field("PolicyHashSize") != "32" || !IsHash(Field("PolicyHash")) ||
                !string.Equals(Field("PolicyHash"), _policyHash, StringComparison.OrdinalIgnoreCase) ||
                Field("SI Signing Scenario") != "1" || Field("PackageFamilyName") != "" ||
                Field("SHA256 Flat Hash Size") != "32" || !IsHash(Field("SHA256 Flat Hash"))) return null;
            // Hash comes from the blocked image, never from reopening a mutable path. In
            // particular, "SHA256 Hash" is Authenticode, NOT the byte-for-byte file identity.
            var identity = new ApplicationIdentity(null, null, null, Field("SHA256 Flat Hash"));
            var path = Field("File Name");
            if (path.Length > 1024 || !path.StartsWith(@"\Device\HarddiskVolume", StringComparison.Ordinal) ||
                !path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return null;
            var observationId = "ci:" + recordText + ":" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(xml)));
            // Filename is a display hint only: no publisher/product/signature claim is made.
            return new VerifiedBlockedApplicationObservation(observationId, _deviceId, account, identity,
                Path.GetFileName(path), observed, observed + VerifiedBlockedApplicationObservation.MaximumLifetime, path);
        }
        catch (Exception e) when (e is XmlException or ArgumentException or InvalidOperationException or InvalidDataException or FormatException)
        { return null; }
    }

    private static bool TryReadRecordId(string value, out long recordId)
    {
        recordId = 0;
        if (!GuardIdentifier.IsCanonicalToken(value)) return false;
        var parts = value.Split(':');
        return parts.Length == 3 && parts[0] == "ci" && IsHash(parts[2]) && parts[2] == parts[2].ToUpperInvariant() &&
            long.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out recordId) && recordId > 0 &&
            parts[1] == recordId.ToString(CultureInfo.InvariantCulture);
    }

    private static bool IsHash(string value) => value != null && value.Length == 64 && value.All(char.IsAsciiHexDigit);
}
