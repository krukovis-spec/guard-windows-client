using System;

namespace Guard.Contracts
{
    public static class GuardProtocol
    {
        public const int CurrentVersion = 1;
        public const int MaximumFrameBytes = 64 * 1024;
        public const int MaximumReasonCharacters = 280;
        public const int MaximumTargetCharacters = 2048;
        public const int MaximumParentPublicKeyBytes = 1024;
        public const int MaximumConcurrentPipeConnections = 8;
        public const int DefaultIpcReadTimeoutMilliseconds = 5000;
        public const int MaximumIpcReadTimeoutMilliseconds = 30000;
    }

    public static class GuardIdentifier
    {
        public const int MinimumCharacters = 16;
        public const int MaximumCharacters = 128;

        public static bool IsCanonicalToken(string value)
        {
            if (string.IsNullOrWhiteSpace(value) ||
                value.Length < MinimumCharacters ||
                value.Length > MaximumCharacters)
            {
                return false;
            }

            for (var index = 0; index < value.Length; index++)
            {
                var character = value[index];
                if (!((character >= 'a' && character <= 'z') ||
                      (character >= 'A' && character <= 'Z') ||
                      (character >= '0' && character <= '9') ||
                      character == '-' || character == '_' || character == '.' || character == ':'))
                {
                    return false;
                }
            }

            return true;
        }
    }

    public enum ClientRole
    {
        Unknown = 0,
        Child = 1,
        AdminSetup = 2,
        Proxy = 3,
        ParentRelay = 4,
        ServiceInternal = 5
    }

    public enum GuardVerb
    {
        Unknown = 0,
        GetStatus = 1,
        GetReadiness = 2,
        CreateApplicationRequest = 10,
        CreateWebsiteRequest = 11,
        EvaluateDomain = 20,
        BeginSetup = 30,
        CompleteSetup = 31,
        ApplyParentDecision = 40,
        ReconcilePolicy = 50
    }

    public sealed class GuardIpcRequest
    {
        private readonly byte[] _payloadUtf8;

        public GuardIpcRequest(
            int protocolVersion,
            string requestId,
            GuardVerb verb,
            byte[] payloadUtf8)
        {
            ProtocolVersion = protocolVersion;
            RequestId = requestId ?? string.Empty;
            Verb = verb;
            _payloadUtf8 = payloadUtf8 == null ? Array.Empty<byte>() : (byte[])payloadUtf8.Clone();
        }

        public int ProtocolVersion { get; }

        public string RequestId { get; }

        public GuardVerb Verb { get; }

        public int PayloadLength => _payloadUtf8.Length;

        public byte[] GetPayloadCopy()
        {
            return (byte[])_payloadUtf8.Clone();
        }
    }

    public enum ParentDecisionKind
    {
        Unknown = 0,
        AllowAlways = 1,
        AllowTemporary = 2,
        AllowDailyQuota = 3,
        Deny = 4
    }

    public enum GuardTargetKind
    {
        Unknown = 0,
        Application = 1,
        Site = 2
    }

    public sealed class ParentDecisionCommand
    {
        public ParentDecisionCommand(
            string requestId,
            GuardTargetKind targetKind,
            string targetIdentity,
            ParentDecisionKind decision,
            int? temporaryMinutes = null,
            int? dailyQuotaMinutes = null)
        {
            Guid parsedRequestId;
            if (!Guid.TryParseExact(requestId, "D", out parsedRequestId))
            {
                throw new ArgumentException("A canonical request id is required.", nameof(requestId));
            }

            if (!Enum.IsDefined(typeof(GuardTargetKind), targetKind) || targetKind == GuardTargetKind.Unknown)
            {
                throw new ArgumentOutOfRangeException(nameof(targetKind));
            }

            if (string.IsNullOrWhiteSpace(targetIdentity) || targetIdentity.Length > GuardProtocol.MaximumTargetCharacters)
            {
                throw new ArgumentException("A bounded target identity is required.", nameof(targetIdentity));
            }

            for (var index = 0; index < targetIdentity.Length; index++)
            {
                if (char.IsControl(targetIdentity[index]))
                {
                    throw new ArgumentException("Target identities cannot contain control characters.", nameof(targetIdentity));
                }
            }

            if (!Enum.IsDefined(typeof(ParentDecisionKind), decision) || decision == ParentDecisionKind.Unknown)
            {
                throw new ArgumentOutOfRangeException(nameof(decision));
            }

            if (decision == ParentDecisionKind.AllowTemporary)
            {
                if (!temporaryMinutes.HasValue || temporaryMinutes.Value < 1 || temporaryMinutes.Value > 1440 || dailyQuotaMinutes.HasValue)
                {
                    throw new ArgumentException("A temporary decision requires 1 to 1440 minutes and no quota.");
                }
            }
            else if (decision == ParentDecisionKind.AllowDailyQuota)
            {
                if (!dailyQuotaMinutes.HasValue || dailyQuotaMinutes.Value < 1 || dailyQuotaMinutes.Value > 1440 || temporaryMinutes.HasValue)
                {
                    throw new ArgumentException("A daily-quota decision requires 1 to 1440 minutes and no temporary duration.");
                }
            }
            else if (temporaryMinutes.HasValue || dailyQuotaMinutes.HasValue)
            {
                throw new ArgumentException("Always-allow and deny decisions cannot carry time values.");
            }

            RequestId = requestId;
            TargetKind = targetKind;
            TargetIdentity = targetIdentity;
            Decision = decision;
            TemporaryMinutes = temporaryMinutes;
            DailyQuotaMinutes = dailyQuotaMinutes;
        }

        public string RequestId { get; }

        public GuardTargetKind TargetKind { get; }

        public string TargetIdentity { get; }

        public ParentDecisionKind Decision { get; }

        public int? TemporaryMinutes { get; }

        public int? DailyQuotaMinutes { get; }
    }

    public sealed class SignedCommandEnvelope
    {
        private readonly byte[] _canonicalPayload;
        private readonly byte[] _signature;

        public SignedCommandEnvelope(
            string commandId,
            string deviceId,
            long sequence,
            DateTimeOffset issuedAtUtc,
            DateTimeOffset expiresAtUtc,
            string nonce,
            string keyId,
            byte[] canonicalPayload,
            byte[] signature)
        {
            CommandId = commandId ?? string.Empty;
            DeviceId = deviceId ?? string.Empty;
            Sequence = sequence;
            IssuedAtUtc = issuedAtUtc;
            ExpiresAtUtc = expiresAtUtc;
            Nonce = nonce ?? string.Empty;
            KeyId = keyId ?? string.Empty;
            _canonicalPayload = canonicalPayload == null ? Array.Empty<byte>() : (byte[])canonicalPayload.Clone();
            _signature = signature == null ? Array.Empty<byte>() : (byte[])signature.Clone();
        }

        public string CommandId { get; }

        public string DeviceId { get; }

        public long Sequence { get; }

        public DateTimeOffset IssuedAtUtc { get; }

        public DateTimeOffset ExpiresAtUtc { get; }

        public string Nonce { get; }

        public string KeyId { get; }

        public int PayloadLength => _canonicalPayload.Length;

        public int SignatureLength => _signature.Length;

        public byte[] GetCanonicalPayloadCopy()
        {
            return (byte[])_canonicalPayload.Clone();
        }

        public byte[] GetSignatureCopy()
        {
            return (byte[])_signature.Clone();
        }
    }
}
