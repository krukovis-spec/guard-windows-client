using System;
using Guard.Contracts;

namespace Guard.Domain
{
    public sealed class CommandMetadata
    {
        public CommandMetadata(
            string commandId,
            string deviceId,
            long sequence,
            DateTimeOffset issuedAtUtc,
            DateTimeOffset expiresAtUtc,
            string nonce)
        {
            CommandId = commandId ?? string.Empty;
            DeviceId = deviceId ?? string.Empty;
            Sequence = sequence;
            IssuedAtUtc = issuedAtUtc;
            ExpiresAtUtc = expiresAtUtc;
            Nonce = nonce ?? string.Empty;
        }

        public string CommandId { get; }

        public string DeviceId { get; }

        public long Sequence { get; }

        public DateTimeOffset IssuedAtUtc { get; }

        public DateTimeOffset ExpiresAtUtc { get; }

        public string Nonce { get; }
    }

    public enum CommandAcceptanceStatus
    {
        Accepted = 0,
        InvalidCommandId = 1,
        WrongDevice = 2,
        InvalidSequence = 3,
        Duplicate = 4,
        InvalidNonce = 5,
        IssuedInFuture = 6,
        Expired = 7,
        InvalidLifetime = 8
    }

    public sealed class CommandAcceptancePolicy
    {
        public CommandAcceptancePolicy(TimeSpan maximumClockSkew, TimeSpan maximumLifetime)
        {
            if (maximumClockSkew < TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(maximumClockSkew));
            }

            if (maximumLifetime <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(maximumLifetime));
            }

            MaximumClockSkew = maximumClockSkew;
            MaximumLifetime = maximumLifetime;
        }

        public TimeSpan MaximumClockSkew { get; }

        public TimeSpan MaximumLifetime { get; }
    }

    public static class CommandAcceptanceEvaluator
    {
        public static CommandAcceptanceStatus Evaluate(
            DeviceSecurityState state,
            CommandMetadata command,
            DateTimeOffset nowUtc,
            CommandAcceptancePolicy policy)
        {
            if (state == null)
            {
                throw new ArgumentNullException(nameof(state));
            }

            if (command == null)
            {
                throw new ArgumentNullException(nameof(command));
            }

            if (policy == null)
            {
                throw new ArgumentNullException(nameof(policy));
            }

            if (!IsBoundedIdentifier(command.CommandId))
            {
                return CommandAcceptanceStatus.InvalidCommandId;
            }

            if (!string.Equals(state.DeviceId, command.DeviceId, StringComparison.Ordinal))
            {
                return CommandAcceptanceStatus.WrongDevice;
            }

            if (command.Sequence <= state.HighestAcceptedSequence)
            {
                return CommandAcceptanceStatus.InvalidSequence;
            }

            if (state.HasAcceptedCommand(command.CommandId))
            {
                return CommandAcceptanceStatus.Duplicate;
            }

            if (!IsBoundedIdentifier(command.Nonce))
            {
                return CommandAcceptanceStatus.InvalidNonce;
            }

            if (command.IssuedAtUtc > nowUtc.Add(policy.MaximumClockSkew))
            {
                return CommandAcceptanceStatus.IssuedInFuture;
            }

            if (command.ExpiresAtUtc <= nowUtc)
            {
                return CommandAcceptanceStatus.Expired;
            }

            var lifetime = command.ExpiresAtUtc - command.IssuedAtUtc;
            if (lifetime <= TimeSpan.Zero || lifetime > policy.MaximumLifetime)
            {
                return CommandAcceptanceStatus.InvalidLifetime;
            }

            return CommandAcceptanceStatus.Accepted;
        }

        private static bool IsBoundedIdentifier(string value)
        {
            return GuardIdentifier.IsCanonicalToken(value);
        }
    }
}
