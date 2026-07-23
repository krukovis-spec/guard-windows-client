using System;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Guard.Contracts;
using Guard.Domain;
using Guard.Domain.Policy;

namespace Guard.Application
{
    public sealed class AuthenticatedChildContext
    {
        public AuthenticatedChildContext(string deviceId, WindowsAccountSid childAccountSid)
        {
            if (!GuardIdentifier.IsCanonicalToken(deviceId))
            {
                throw new ArgumentException("A canonical authenticated device id is required.", nameof(deviceId));
            }

            DeviceId = deviceId;
            ChildAccountSid = childAccountSid ?? throw new ArgumentNullException(nameof(childAccountSid));
        }

        public string DeviceId { get; }

        public WindowsAccountSid ChildAccountSid { get; }
    }

    public sealed class VerifiedBlockedApplicationObservation
    {
        public static readonly TimeSpan MaximumLifetime = TimeSpan.FromMinutes(30);

        public VerifiedBlockedApplicationObservation(
            string observationId,
            string deviceId,
            WindowsAccountSid childAccountSid,
            ApplicationIdentity identity,
            string displayName,
            DateTimeOffset observedAtUtc,
            DateTimeOffset expiresAtUtc,
            string? observedExecutablePath = null,
            string? verifiedSignatureSummary = null)
        {
            if (!GuardIdentifier.IsCanonicalToken(observationId))
            {
                throw new ArgumentException("A canonical observation id is required.", nameof(observationId));
            }

            if (!GuardIdentifier.IsCanonicalToken(deviceId))
            {
                throw new ArgumentException("A canonical observed device id is required.", nameof(deviceId));
            }

            if (expiresAtUtc <= observedAtUtc || expiresAtUtc - observedAtUtc > MaximumLifetime)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(expiresAtUtc),
                    "A blocked-application observation must have a short, positive lifetime.");
            }

            ObservationId = observationId;
            DeviceId = deviceId;
            ChildAccountSid = childAccountSid ?? throw new ArgumentNullException(nameof(childAccountSid));
            Identity = identity ?? throw new ArgumentNullException(nameof(identity));
            if (!Identity.IsExecutableGrantIdentity)
            {
                throw new ArgumentException(
                    "A blocked-application observation requires an exact SHA-256 or package-family identity.",
                    nameof(identity));
            }
            DisplayName = ApplicationRequestText.Require(displayName, 256, nameof(displayName));
            ObservedAtUtc = observedAtUtc;
            ExpiresAtUtc = expiresAtUtc;
            ObservedExecutablePath = ApplicationRequestText.NormalizeOptional(
                observedExecutablePath,
                1024,
                nameof(observedExecutablePath));
            VerifiedSignatureSummary = ApplicationRequestText.NormalizeOptional(
                verifiedSignatureSummary,
                512,
                nameof(verifiedSignatureSummary));
        }

        public string ObservationId { get; }

        public string DeviceId { get; }

        public WindowsAccountSid ChildAccountSid { get; }

        public ApplicationIdentity Identity { get; }

        public string DisplayName { get; }

        public DateTimeOffset ObservedAtUtc { get; }

        public DateTimeOffset ExpiresAtUtc { get; }

        public string? ObservedExecutablePath { get; }

        public string? VerifiedSignatureSummary { get; }

        public bool IsActiveAt(DateTimeOffset nowUtc)
        {
            return nowUtc >= ObservedAtUtc && nowUtc < ExpiresAtUtc;
        }
    }

    public interface IBlockedApplicationObservationResolver
    {
        Task<VerifiedBlockedApplicationObservation?> ResolveAsync(
            string observationId,
            CancellationToken cancellationToken);
    }

    public sealed class ApplicationAccessRequest
    {
        public ApplicationAccessRequest(
            string requestId,
            string deviceId,
            WindowsAccountSid childAccountSid,
            string observationId,
            ApplicationIdentity identity,
            string displayName,
            string? childReason,
            DateTimeOffset createdAtUtc,
            string? observedExecutablePath = null,
            string? verifiedSignatureSummary = null)
        {
            if (!GuardIdentifier.IsCanonicalToken(requestId))
            {
                throw new ArgumentException("A canonical request id is required.", nameof(requestId));
            }

            if (!GuardIdentifier.IsCanonicalToken(deviceId))
            {
                throw new ArgumentException("A canonical request device id is required.", nameof(deviceId));
            }

            if (!GuardIdentifier.IsCanonicalToken(observationId))
            {
                throw new ArgumentException("A canonical source observation id is required.", nameof(observationId));
            }

            RequestId = requestId;
            DeviceId = deviceId;
            ChildAccountSid = childAccountSid ?? throw new ArgumentNullException(nameof(childAccountSid));
            ObservationId = observationId;
            Identity = identity ?? throw new ArgumentNullException(nameof(identity));
            if (!Identity.IsExecutableGrantIdentity)
            {
                throw new ArgumentException(
                    "An application access request requires an exact SHA-256 or package-family identity.",
                    nameof(identity));
            }
            DisplayName = ApplicationRequestText.Require(displayName, 256, nameof(displayName));
            ChildReason = new CreateApplicationRequestPayload(
                observationId,
                childReason).ShortReason;
            CreatedAtUtc = createdAtUtc;
            ObservedExecutablePath = ApplicationRequestText.NormalizeOptional(
                observedExecutablePath,
                1024,
                nameof(observedExecutablePath));
            VerifiedSignatureSummary = ApplicationRequestText.NormalizeOptional(
                verifiedSignatureSummary,
                512,
                nameof(verifiedSignatureSummary));
            RequestKey = AccessRequestKey.ForApplication(deviceId, identity);
        }

        public string RequestId { get; }

        public string DeviceId { get; }

        public WindowsAccountSid ChildAccountSid { get; }

        public string ObservationId { get; }

        public ApplicationIdentity Identity { get; }

        public string DisplayName { get; }

        public string? ChildReason { get; }

        public DateTimeOffset CreatedAtUtc { get; }

        public string? ObservedExecutablePath { get; }

        public string? VerifiedSignatureSummary { get; }

        public AccessRequestKey RequestKey { get; }
    }

    public sealed class PendingApplicationRequestStoreResult
    {
        public PendingApplicationRequestStoreResult(ApplicationAccessRequest request, bool created)
        {
            Request = request ?? throw new ArgumentNullException(nameof(request));
            Created = created;
        }

        public ApplicationAccessRequest Request { get; }

        public bool Created { get; }
    }

    public interface IPendingApplicationAccessRequestStore
    {
        Task<PendingApplicationRequestStoreResult> CreateOrGetPendingAsync(
            ApplicationAccessRequest candidate,
            CancellationToken cancellationToken);
    }

    public enum ApplicationRequestAuditKind
    {
        Created = 1,
        Deduplicated = 2,
        RejectedObservation = 3,
        DependencyFailure = 4
    }

    public sealed class ApplicationRequestAuditEvent
    {
        public ApplicationRequestAuditEvent(
            ApplicationRequestAuditKind kind,
            DateTimeOffset occurredAtUtc,
            string deviceId,
            WindowsAccountSid childAccountSid,
            string observationId,
            string? requestId,
            AccessRequestKey? requestKey)
        {
            if (!Enum.IsDefined(typeof(ApplicationRequestAuditKind), kind))
            {
                throw new ArgumentOutOfRangeException(nameof(kind));
            }

            if (!GuardIdentifier.IsCanonicalToken(deviceId))
            {
                throw new ArgumentException("A canonical audit device id is required.", nameof(deviceId));
            }

            if (!GuardIdentifier.IsCanonicalToken(observationId))
            {
                throw new ArgumentException("A canonical audit observation id is required.", nameof(observationId));
            }

            if (requestId != null && !GuardIdentifier.IsCanonicalToken(requestId))
            {
                throw new ArgumentException("A canonical audit request id is required.", nameof(requestId));
            }

            var successful = kind == ApplicationRequestAuditKind.Created ||
                             kind == ApplicationRequestAuditKind.Deduplicated;
            if (successful != (requestId != null && requestKey != null))
            {
                throw new ArgumentException(
                    "Successful audit events require request identity; rejection events cannot carry it.");
            }

            Kind = kind;
            OccurredAtUtc = occurredAtUtc;
            DeviceId = deviceId;
            ChildAccountSid = childAccountSid ?? throw new ArgumentNullException(nameof(childAccountSid));
            ObservationId = observationId;
            RequestId = requestId;
            RequestKey = requestKey;
        }

        public ApplicationRequestAuditKind Kind { get; }

        public DateTimeOffset OccurredAtUtc { get; }

        public string DeviceId { get; }

        public WindowsAccountSid ChildAccountSid { get; }

        public string ObservationId { get; }

        public string? RequestId { get; }

        public AccessRequestKey? RequestKey { get; }
    }

    public interface IApplicationRequestAudit
    {
        Task WriteAsync(
            ApplicationRequestAuditEvent auditEvent,
            CancellationToken cancellationToken);
    }

    public enum ApplicationAccessRequestStatus
    {
        Created = 0,
        PendingAlreadyExists = 1,
        RejectedObservation = 2,
        FailedClosed = 3
    }

    public sealed class ApplicationAccessRequestResult
    {
        private ApplicationAccessRequestResult(
            ApplicationAccessRequestStatus status,
            ApplicationAccessRequest? request)
        {
            Status = status;
            Request = request;
        }

        public ApplicationAccessRequestStatus Status { get; }

        public ApplicationAccessRequest? Request { get; }

        public bool IsAccepted =>
            Status == ApplicationAccessRequestStatus.Created ||
            Status == ApplicationAccessRequestStatus.PendingAlreadyExists;

        public static ApplicationAccessRequestResult Accepted(
            ApplicationAccessRequest request,
            bool created)
        {
            return new ApplicationAccessRequestResult(
                created
                    ? ApplicationAccessRequestStatus.Created
                    : ApplicationAccessRequestStatus.PendingAlreadyExists,
                request ?? throw new ArgumentNullException(nameof(request)));
        }

        public static ApplicationAccessRequestResult Rejected(
            ApplicationAccessRequestStatus status)
        {
            if (status == ApplicationAccessRequestStatus.Created ||
                status == ApplicationAccessRequestStatus.PendingAlreadyExists)
            {
                throw new ArgumentOutOfRangeException(nameof(status));
            }

            return new ApplicationAccessRequestResult(status, null);
        }
    }

    public sealed class ApplicationAccessRequestCoordinator
    {
        private readonly IBlockedApplicationObservationResolver _resolver;
        private readonly IPendingApplicationAccessRequestStore _store;
        private readonly IApplicationRequestAudit _audit;

        public ApplicationAccessRequestCoordinator(
            IBlockedApplicationObservationResolver resolver,
            IPendingApplicationAccessRequestStore store,
            IApplicationRequestAudit audit)
        {
            _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
            _store = store ?? throw new ArgumentNullException(nameof(store));
            _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        }

        public async Task<ApplicationAccessRequestResult> CreateAsync(
            AuthenticatedChildContext context,
            CreateApplicationRequestPayload payload,
            DateTimeOffset nowUtc,
            CancellationToken cancellationToken)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }

            cancellationToken.ThrowIfCancellationRequested();

            VerifiedBlockedApplicationObservation? observation;
            try
            {
                observation = await _resolver.ResolveAsync(
                    payload.ObservationId,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception)
            {
                return await CompleteFailureAsync(
                    ApplicationRequestAuditKind.DependencyFailure,
                    ApplicationAccessRequestStatus.FailedClosed,
                    context,
                    payload.ObservationId,
                    nowUtc,
                    cancellationToken).ConfigureAwait(false);
            }

            if (!IsExactActiveObservation(context, payload, observation, nowUtc))
            {
                return await CompleteFailureAsync(
                    ApplicationRequestAuditKind.RejectedObservation,
                    ApplicationAccessRequestStatus.RejectedObservation,
                    context,
                    payload.ObservationId,
                    nowUtc,
                    cancellationToken).ConfigureAwait(false);
            }

            var candidate = new ApplicationAccessRequest(
                Guid.NewGuid().ToString("D"),
                context.DeviceId,
                context.ChildAccountSid,
                observation!.ObservationId,
                observation.Identity,
                observation.DisplayName,
                payload.ShortReason,
                nowUtc,
                observation.ObservedExecutablePath,
                observation.VerifiedSignatureSummary);

            PendingApplicationRequestStoreResult stored;
            try
            {
                stored = await _store.CreateOrGetPendingAsync(
                    candidate,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception)
            {
                return await CompleteFailureAsync(
                    ApplicationRequestAuditKind.DependencyFailure,
                    ApplicationAccessRequestStatus.FailedClosed,
                    context,
                    payload.ObservationId,
                    nowUtc,
                    cancellationToken).ConfigureAwait(false);
            }

            if (!IsExactStoredRequest(candidate, stored))
            {
                return await CompleteFailureAsync(
                    ApplicationRequestAuditKind.DependencyFailure,
                    ApplicationAccessRequestStatus.FailedClosed,
                    context,
                    payload.ObservationId,
                    nowUtc,
                    cancellationToken).ConfigureAwait(false);
            }

            var storedRequest = stored.Request;
            var auditKind = stored.Created
                ? ApplicationRequestAuditKind.Created
                : ApplicationRequestAuditKind.Deduplicated;
            var audited = await TryAuditAsync(
                new ApplicationRequestAuditEvent(
                    auditKind,
                    nowUtc,
                    context.DeviceId,
                    context.ChildAccountSid,
                    payload.ObservationId,
                    storedRequest.RequestId,
                    storedRequest.RequestKey),
                cancellationToken).ConfigureAwait(false);
            if (!audited)
            {
                return ApplicationAccessRequestResult.Rejected(
                    ApplicationAccessRequestStatus.FailedClosed);
            }

            return ApplicationAccessRequestResult.Accepted(storedRequest, stored.Created);
        }

        private static bool IsExactActiveObservation(
            AuthenticatedChildContext context,
            CreateApplicationRequestPayload payload,
            VerifiedBlockedApplicationObservation? observation,
            DateTimeOffset nowUtc)
        {
            return observation != null &&
                   string.Equals(observation.ObservationId, payload.ObservationId, StringComparison.Ordinal) &&
                   string.Equals(observation.DeviceId, context.DeviceId, StringComparison.Ordinal) &&
                   observation.ChildAccountSid.Equals(context.ChildAccountSid) &&
                   observation.IsActiveAt(nowUtc);
        }

        private static bool IsExactStoredRequest(
            ApplicationAccessRequest candidate,
            PendingApplicationRequestStoreResult? stored)
        {
            if (stored == null ||
                !stored.Request.RequestKey.Equals(candidate.RequestKey) ||
                !string.Equals(stored.Request.DeviceId, candidate.DeviceId, StringComparison.Ordinal) ||
                !stored.Request.ChildAccountSid.Equals(candidate.ChildAccountSid) ||
                !stored.Request.Identity.Equals(candidate.Identity))
            {
                return false;
            }

            if (!stored.Created)
            {
                return true;
            }

            return string.Equals(stored.Request.RequestId, candidate.RequestId, StringComparison.Ordinal) &&
                   string.Equals(stored.Request.ObservationId, candidate.ObservationId, StringComparison.Ordinal) &&
                   string.Equals(stored.Request.DisplayName, candidate.DisplayName, StringComparison.Ordinal) &&
                   string.Equals(stored.Request.ChildReason, candidate.ChildReason, StringComparison.Ordinal) &&
                   stored.Request.CreatedAtUtc == candidate.CreatedAtUtc &&
                   string.Equals(stored.Request.ObservedExecutablePath, candidate.ObservedExecutablePath, StringComparison.Ordinal) &&
                   string.Equals(stored.Request.VerifiedSignatureSummary, candidate.VerifiedSignatureSummary, StringComparison.Ordinal);
        }

        private async Task<ApplicationAccessRequestResult> CompleteFailureAsync(
            ApplicationRequestAuditKind kind,
            ApplicationAccessRequestStatus status,
            AuthenticatedChildContext context,
            string observationId,
            DateTimeOffset nowUtc,
            CancellationToken cancellationToken)
        {
            var audited = await TryAuditAsync(
                new ApplicationRequestAuditEvent(
                    kind,
                    nowUtc,
                    context.DeviceId,
                    context.ChildAccountSid,
                    observationId,
                    null,
                    null),
                cancellationToken).ConfigureAwait(false);

            return ApplicationAccessRequestResult.Rejected(
                audited ? status : ApplicationAccessRequestStatus.FailedClosed);
        }

        private async Task<bool> TryAuditAsync(
            ApplicationRequestAuditEvent auditEvent,
            CancellationToken cancellationToken)
        {
            try
            {
                await _audit.WriteAsync(auditEvent, cancellationToken).ConfigureAwait(false);
                return true;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }

    internal static class ApplicationRequestText
    {
        public static string Require(string value, int maximumCharacters, string parameterName)
        {
            var normalized = NormalizeOptional(value, maximumCharacters, parameterName);
            if (normalized == null)
            {
                throw new ArgumentException("A bounded non-blank value is required.", parameterName);
            }

            return normalized;
        }

        public static string? NormalizeOptional(
            string? value,
            int maximumCharacters,
            string parameterName)
        {
            if (value == null)
            {
                return null;
            }

            value = value.Trim();
            if (value.Length == 0)
            {
                return null;
            }

            if (value.Length > maximumCharacters)
            {
                throw new ArgumentException("Text exceeds its bounded length.", parameterName);
            }

            for (var index = 0; index < value.Length; index++)
            {
                var character = value[index];
                var category = CharUnicodeInfo.GetUnicodeCategory(value, index);
                if (category == UnicodeCategory.Control ||
                    category == UnicodeCategory.Format ||
                    category == UnicodeCategory.LineSeparator ||
                    category == UnicodeCategory.ParagraphSeparator)
                {
                    throw new ArgumentException("Control and formatting characters are not allowed.", parameterName);
                }

                if (char.IsHighSurrogate(character))
                {
                    if (index + 1 >= value.Length || !char.IsLowSurrogate(value[index + 1]))
                    {
                        throw new ArgumentException("Text must contain valid Unicode.", parameterName);
                    }

                    index++;
                }
                else if (char.IsLowSurrogate(character))
                {
                    throw new ArgumentException("Text must contain valid Unicode.", parameterName);
                }
            }

            return value;
        }
    }
}
