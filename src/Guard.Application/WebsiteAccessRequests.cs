using System;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Guard.Contracts;
using Guard.Domain;
using Guard.Domain.Policy;
using Guard.Domain.Web;

namespace Guard.Application
{
    /// <summary>
    /// Service-owned evidence for a blocked browser connection. The child
    /// request contains only ObservationId and cannot select any value here.
    /// </summary>
    public sealed class VerifiedBlockedWebsiteObservation
    {
        public static readonly TimeSpan MaximumLifetime =
            TimeSpan.FromMinutes(5);

        public VerifiedBlockedWebsiteObservation(
            string observationId,
            string deviceId,
            WindowsAccountSid childAccountSid,
            CanonicalDnsHost canonicalHost,
            RegistrableDomainEvidence registrableDomainEvidence,
            VerifiedWebServiceBundle? serviceBundleCandidate,
            string displayName,
            DateTimeOffset observedAtUtc,
            DateTimeOffset expiresAtUtc)
        {
            if (!GuardIdentifier.IsCanonicalToken(observationId))
            {
                throw new ArgumentException(
                    "A canonical observation id is required.",
                    nameof(observationId));
            }

            if (!GuardIdentifier.IsCanonicalToken(deviceId))
            {
                throw new ArgumentException(
                    "A canonical observed device id is required.",
                    nameof(deviceId));
            }

            if (expiresAtUtc <= observedAtUtc ||
                expiresAtUtc - observedAtUtc > MaximumLifetime)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(expiresAtUtc),
                    "A blocked-website observation must have a short, positive lifetime.");
            }

            CanonicalHost = canonicalHost ??
                throw new ArgumentNullException(nameof(canonicalHost));
            RegistrableDomainEvidence =
                registrableDomainEvidence ??
                throw new ArgumentNullException(
                    nameof(registrableDomainEvidence));
            if (!CanonicalHost.Equals(
                    RegistrableDomainEvidence.ObservedHost))
            {
                throw new ArgumentException(
                    "Registrable-domain evidence must be bound to the exact observed host.",
                    nameof(registrableDomainEvidence));
            }

            ServiceBundleCandidate = serviceBundleCandidate;
            if (ServiceBundleCandidate != null &&
                !BundleMatchesPrimaryHost(
                    ServiceBundleCandidate,
                    CanonicalHost))
            {
                throw new ArgumentException(
                    "The verified service-bundle candidate does not cover the observed host.",
                    nameof(serviceBundleCandidate));
            }

            ObservationId = observationId;
            DeviceId = deviceId;
            ChildAccountSid = childAccountSid ??
                throw new ArgumentNullException(nameof(childAccountSid));
            DisplayName = WebsiteRequestText.Require(
                displayName,
                256,
                nameof(displayName));
            ObservedAtUtc = observedAtUtc;
            ExpiresAtUtc = expiresAtUtc;
        }

        public string ObservationId { get; }

        public string DeviceId { get; }

        public WindowsAccountSid ChildAccountSid { get; }

        public CanonicalDnsHost CanonicalHost { get; }

        public RegistrableDomainEvidence RegistrableDomainEvidence
        {
            get;
        }

        public VerifiedWebServiceBundle? ServiceBundleCandidate
        {
            get;
        }

        public string DisplayName { get; }

        public DateTimeOffset ObservedAtUtc { get; }

        public DateTimeOffset ExpiresAtUtc { get; }

        public bool IsActiveAt(DateTimeOffset nowUtc)
        {
            return nowUtc >= ObservedAtUtc && nowUtc < ExpiresAtUtc;
        }

        internal static bool BundleMatchesPrimaryHost(
            VerifiedWebServiceBundle bundle,
            CanonicalDnsHost host)
        {
            var scopes = bundle.Bundle.Scopes;
            for (var index = 0; index < scopes.Count; index++)
            {
                if (scopes[index].Matches(host.Value))
                {
                    return true;
                }
            }

            return false;
        }
    }

    public interface IBlockedWebsiteObservationResolver
    {
        Task<VerifiedBlockedWebsiteObservation?> ResolveAsync(
            string observationId,
            CancellationToken cancellationToken);
    }

    public sealed class WebsiteAccessRequest
    {
        public WebsiteAccessRequest(
            string requestId,
            string deviceId,
            WindowsAccountSid childAccountSid,
            string observationId,
            CanonicalDnsHost canonicalHost,
            RegistrableDomainEvidence registrableDomainEvidence,
            VerifiedWebServiceBundle? serviceBundleCandidate,
            string displayName,
            string? childReason,
            DateTimeOffset createdAtUtc)
        {
            if (!GuardIdentifier.IsCanonicalToken(requestId))
            {
                throw new ArgumentException(
                    "A canonical request id is required.",
                    nameof(requestId));
            }

            if (!GuardIdentifier.IsCanonicalToken(deviceId))
            {
                throw new ArgumentException(
                    "A canonical request device id is required.",
                    nameof(deviceId));
            }

            if (!GuardIdentifier.IsCanonicalToken(observationId))
            {
                throw new ArgumentException(
                    "A canonical source observation id is required.",
                    nameof(observationId));
            }

            CanonicalHost = canonicalHost ??
                throw new ArgumentNullException(nameof(canonicalHost));
            RegistrableDomainEvidence =
                registrableDomainEvidence ??
                throw new ArgumentNullException(
                    nameof(registrableDomainEvidence));
            if (!CanonicalHost.Equals(
                    RegistrableDomainEvidence.ObservedHost))
            {
                throw new ArgumentException(
                    "Registrable-domain evidence must be bound to the exact observed host.",
                    nameof(registrableDomainEvidence));
            }

            ServiceBundleCandidate = serviceBundleCandidate;
            if (ServiceBundleCandidate != null &&
                !VerifiedBlockedWebsiteObservation
                    .BundleMatchesPrimaryHost(
                        ServiceBundleCandidate,
                        CanonicalHost))
            {
                throw new ArgumentException(
                    "The verified service-bundle candidate does not cover the observed host.",
                    nameof(serviceBundleCandidate));
            }

            RequestId = requestId;
            DeviceId = deviceId;
            ChildAccountSid = childAccountSid ??
                throw new ArgumentNullException(nameof(childAccountSid));
            ObservationId = observationId;
            DisplayName = WebsiteRequestText.Require(
                displayName,
                256,
                nameof(displayName));
            ChildReason = new CreateWebsiteRequestPayload(
                observationId,
                childReason).ShortReason;
            CreatedAtUtc = createdAtUtc;
            RequestKey = AccessRequestKey.ForSite(
                deviceId,
                RegistrableDomainEvidence.RegistrableDomain.Value);
        }

        public string RequestId { get; }

        public string DeviceId { get; }

        public WindowsAccountSid ChildAccountSid { get; }

        public string ObservationId { get; }

        public CanonicalDnsHost CanonicalHost { get; }

        public RegistrableDomainEvidence RegistrableDomainEvidence
        {
            get;
        }

        public VerifiedWebServiceBundle? ServiceBundleCandidate
        {
            get;
        }

        /// <summary>
        /// An unknown site can be queued for parent review from trusted
        /// registrable-domain evidence, but cannot become a grant until a
        /// signed catalog bundle has been resolved and bound explicitly.
        /// </summary>
        public bool RequiresCatalogResolutionBeforeGrant =>
            ServiceBundleCandidate == null;

        public string DisplayName { get; }

        public string? ChildReason { get; }

        public DateTimeOffset CreatedAtUtc { get; }

        /// <summary>
        /// Requests are deduplicated at the trusted registrable-domain
        /// service boundary. Existing records are accepted only when both
        /// sides have no bundle, or both carry the same signed bundle.
        /// </summary>
        public AccessRequestKey RequestKey { get; }
    }

    public sealed class PendingWebsiteRequestStoreResult
    {
        public PendingWebsiteRequestStoreResult(
            WebsiteAccessRequest request,
            bool created,
            WebsiteRequestAuditIntent auditIntent)
        {
            Request = request ??
                throw new ArgumentNullException(nameof(request));
            Created = created;
            AuditIntent = auditIntent ??
                throw new ArgumentNullException(nameof(auditIntent));
        }

        public WebsiteAccessRequest Request { get; }

        public bool Created { get; }

        /// <summary>
        /// A durable transactional-outbox intent written in the same commit
        /// as <see cref="Request"/>. Dispatch failures do not undo that
        /// committed request or this intent.
        /// </summary>
        public WebsiteRequestAuditIntent AuditIntent { get; }
    }

    public interface IPendingWebsiteAccessRequestStore
    {
        /// <summary>
        /// Atomically commits the request outcome and its successful audit
        /// intent to one durable transactional outbox. Implementations must
        /// return the exact outbox intent from that same commit.
        /// </summary>
        Task<PendingWebsiteRequestStoreResult>
            CommitPendingWithAuditIntentAsync(
            WebsiteAccessRequest candidate,
            DateTimeOffset auditOccurredAtUtc,
            CancellationToken cancellationToken);
    }

    public enum WebsiteRequestRateLimitOutcome
    {
        Allowed = 1,
        Exceeded = 2
    }

    /// <summary>
    /// Result of one atomic rate-limit acquisition. Implementations must
    /// consume capacity before returning Allowed and key it only by the
    /// authenticated device and child SID supplied by the coordinator.
    /// </summary>
    public sealed class WebsiteRequestRateLimitResult
    {
        public WebsiteRequestRateLimitResult(
            WebsiteRequestRateLimitOutcome outcome,
            string deviceId,
            WindowsAccountSid childAccountSid)
        {
            if (!Enum.IsDefined(
                    typeof(WebsiteRequestRateLimitOutcome),
                    outcome))
            {
                throw new ArgumentOutOfRangeException(nameof(outcome));
            }

            if (!GuardIdentifier.IsCanonicalToken(deviceId))
            {
                throw new ArgumentException(
                    "A canonical rate-limit device id is required.",
                    nameof(deviceId));
            }

            Outcome = outcome;
            DeviceId = deviceId;
            ChildAccountSid = childAccountSid ??
                throw new ArgumentNullException(nameof(childAccountSid));
        }

        public WebsiteRequestRateLimitOutcome Outcome { get; }

        public string DeviceId { get; }

        public WindowsAccountSid ChildAccountSid { get; }
    }

    public interface IWebsiteRequestRateLimiter
    {
        /// <summary>
        /// Atomically consumes one request slot for the exact authenticated
        /// device and child SID. No child payload field is a rate-limit key.
        /// </summary>
        Task<WebsiteRequestRateLimitResult> TryAcquireAsync(
            string authenticatedDeviceId,
            WindowsAccountSid authenticatedChildAccountSid,
            DateTimeOffset nowUtc,
            CancellationToken cancellationToken);
    }

    public enum WebsiteRequestAuditKind
    {
        Created = 1,
        Deduplicated = 2,
        RejectedObservation = 3,
        DependencyFailure = 4,
        RateLimited = 5
    }

    public sealed class WebsiteRequestAuditEvent
    {
        public WebsiteRequestAuditEvent(
            WebsiteRequestAuditKind kind,
            DateTimeOffset occurredAtUtc,
            string deviceId,
            WindowsAccountSid childAccountSid,
            string observationId,
            string? requestId,
            AccessRequestKey? requestKey)
        {
            if (!Enum.IsDefined(typeof(WebsiteRequestAuditKind), kind))
            {
                throw new ArgumentOutOfRangeException(nameof(kind));
            }

            if (!GuardIdentifier.IsCanonicalToken(deviceId))
            {
                throw new ArgumentException(
                    "A canonical audit device id is required.",
                    nameof(deviceId));
            }

            if (!GuardIdentifier.IsCanonicalToken(observationId))
            {
                throw new ArgumentException(
                    "A canonical audit observation id is required.",
                    nameof(observationId));
            }

            if (requestId != null &&
                !GuardIdentifier.IsCanonicalToken(requestId))
            {
                throw new ArgumentException(
                    "A canonical audit request id is required.",
                    nameof(requestId));
            }

            var successful =
                kind == WebsiteRequestAuditKind.Created ||
                kind == WebsiteRequestAuditKind.Deduplicated;
            if (successful !=
                (requestId != null && requestKey != null))
            {
                throw new ArgumentException(
                    "Successful audit events require request identity; rejection events cannot carry it.");
            }

            if (requestKey != null &&
                (requestKey.TargetKind != AccessTargetKind.Site ||
                 !string.Equals(
                     requestKey.DeviceId,
                     deviceId,
                     StringComparison.Ordinal)))
            {
                throw new ArgumentException(
                    "The audit request key must identify this device and a website target.",
                    nameof(requestKey));
            }

            Kind = kind;
            OccurredAtUtc = occurredAtUtc;
            DeviceId = deviceId;
            ChildAccountSid = childAccountSid ??
                throw new ArgumentNullException(nameof(childAccountSid));
            ObservationId = observationId;
            RequestId = requestId;
            RequestKey = requestKey;
        }

        public WebsiteRequestAuditKind Kind { get; }

        public DateTimeOffset OccurredAtUtc { get; }

        public string DeviceId { get; }

        public WindowsAccountSid ChildAccountSid { get; }

        public string ObservationId { get; }

        public string? RequestId { get; }

        public AccessRequestKey? RequestKey { get; }
    }

    /// <summary>
    /// A successful website-request audit event durably staged for delivery.
    /// It is intentionally distinct from the best-effort audit writer.
    /// </summary>
    public sealed class WebsiteRequestAuditIntent
    {
        public WebsiteRequestAuditIntent(
            string intentId,
            WebsiteRequestAuditEvent auditEvent)
        {
            if (!GuardIdentifier.IsCanonicalToken(intentId))
            {
                throw new ArgumentException(
                    "A canonical audit-intent id is required.",
                    nameof(intentId));
            }

            AuditEvent = auditEvent ??
                throw new ArgumentNullException(nameof(auditEvent));
            IntentId = intentId;
        }

        public string IntentId { get; }

        public WebsiteRequestAuditEvent AuditEvent { get; }

        public static string ForAttempt(string requestAttemptId)
        {
            if (!GuardIdentifier.IsCanonicalToken(requestAttemptId))
            {
                throw new ArgumentException(
                    "A canonical request-attempt id is required.",
                    nameof(requestAttemptId));
            }

            return "attempt-" + requestAttemptId;
        }
    }

    public interface IWebsiteRequestAudit
    {
        /// <summary>
        /// Idempotently persists an intent before a rejection/failure is
        /// returned. Successful request intents are persisted atomically by
        /// IPendingWebsiteAccessRequestStore instead.
        /// </summary>
        Task EnqueueAsync(
            WebsiteRequestAuditIntent intent,
            CancellationToken cancellationToken);

        /// <summary>
        /// Delivers idempotently by IntentId. Repeated delivery after an ack
        /// failure must not create a duplicate security event.
        /// </summary>
        Task WriteAsync(
            WebsiteRequestAuditIntent intent,
            CancellationToken cancellationToken);

        /// <summary>
        /// Idempotently acknowledges a delivered durable outbox intent.
        /// </summary>
        Task AcknowledgeAsync(
            string intentId,
            CancellationToken cancellationToken);
    }

    public enum WebsiteAccessRequestStatus
    {
        Created = 0,
        PendingAlreadyExists = 1,
        RejectedObservation = 2,
        FailedClosed = 3,
        RateLimited = 4
    }

    public sealed class WebsiteAccessRequestResult
    {
        private WebsiteAccessRequestResult(
            WebsiteAccessRequestStatus status,
            WebsiteAccessRequest? request)
        {
            Status = status;
            Request = request;
        }

        public WebsiteAccessRequestStatus Status { get; }

        public WebsiteAccessRequest? Request { get; }

        public bool IsAccepted =>
            Status == WebsiteAccessRequestStatus.Created ||
            Status ==
                WebsiteAccessRequestStatus.PendingAlreadyExists;

        public static WebsiteAccessRequestResult Accepted(
            WebsiteAccessRequest request,
            bool created)
        {
            return new WebsiteAccessRequestResult(
                created
                    ? WebsiteAccessRequestStatus.Created
                    : WebsiteAccessRequestStatus
                        .PendingAlreadyExists,
                request ??
                    throw new ArgumentNullException(nameof(request)));
        }

        public static WebsiteAccessRequestResult Rejected(
            WebsiteAccessRequestStatus status)
        {
            if (status == WebsiteAccessRequestStatus.Created ||
                status ==
                    WebsiteAccessRequestStatus.PendingAlreadyExists)
            {
                throw new ArgumentOutOfRangeException(nameof(status));
            }

            return new WebsiteAccessRequestResult(status, null);
        }
    }

    public sealed class WebsiteAccessRequestCoordinator
    {
        private readonly IBlockedWebsiteObservationResolver _resolver;
        private readonly IPendingWebsiteAccessRequestStore _store;
        private readonly IWebsiteRequestAudit _audit;
        private readonly IWebsiteRequestRateLimiter _rateLimiter;

        public WebsiteAccessRequestCoordinator(
            IWebsiteRequestRateLimiter rateLimiter,
            IBlockedWebsiteObservationResolver resolver,
            IPendingWebsiteAccessRequestStore store,
            IWebsiteRequestAudit audit)
        {
            _rateLimiter = rateLimiter ??
                throw new ArgumentNullException(nameof(rateLimiter));
            _resolver = resolver ??
                throw new ArgumentNullException(nameof(resolver));
            _store = store ??
                throw new ArgumentNullException(nameof(store));
            _audit = audit ??
                throw new ArgumentNullException(nameof(audit));
        }

        public async Task<WebsiteAccessRequestResult> CreateAsync(
            AuthenticatedChildContext context,
            CreateWebsiteRequestPayload payload,
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

            WebsiteRequestRateLimitResult? rateLimitResult;
            try
            {
                rateLimitResult =
                    await _rateLimiter.TryAcquireAsync(
                        context.DeviceId,
                        context.ChildAccountSid,
                        nowUtc,
                        cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception)
            {
                return await CompleteFailureAsync(
                    WebsiteRequestAuditKind.DependencyFailure,
                    WebsiteAccessRequestStatus.FailedClosed,
                    context,
                    payload.ObservationId,
                    nowUtc,
                    cancellationToken).ConfigureAwait(false);
            }

            if (!IsExactRateLimitResult(context, rateLimitResult))
            {
                return await CompleteFailureAsync(
                    WebsiteRequestAuditKind.DependencyFailure,
                    WebsiteAccessRequestStatus.FailedClosed,
                    context,
                    payload.ObservationId,
                    nowUtc,
                    cancellationToken).ConfigureAwait(false);
            }

            if (rateLimitResult!.Outcome ==
                WebsiteRequestRateLimitOutcome.Exceeded)
            {
                return await CompleteFailureAsync(
                    WebsiteRequestAuditKind.RateLimited,
                    WebsiteAccessRequestStatus.RateLimited,
                    context,
                    payload.ObservationId,
                    nowUtc,
                    cancellationToken).ConfigureAwait(false);
            }

            VerifiedBlockedWebsiteObservation? observation;
            try
            {
                observation = await _resolver.ResolveAsync(
                    payload.ObservationId,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception)
            {
                return await CompleteFailureAsync(
                    WebsiteRequestAuditKind.DependencyFailure,
                    WebsiteAccessRequestStatus.FailedClosed,
                    context,
                    payload.ObservationId,
                    nowUtc,
                    cancellationToken).ConfigureAwait(false);
            }

            if (!IsExactActiveObservation(
                    context,
                    payload,
                    observation,
                    nowUtc))
            {
                return await CompleteFailureAsync(
                    WebsiteRequestAuditKind.RejectedObservation,
                    WebsiteAccessRequestStatus.RejectedObservation,
                    context,
                    payload.ObservationId,
                    nowUtc,
                    cancellationToken).ConfigureAwait(false);
            }

            var candidate = new WebsiteAccessRequest(
                Guid.NewGuid().ToString("D"),
                context.DeviceId,
                context.ChildAccountSid,
                observation!.ObservationId,
                observation.CanonicalHost,
                observation.RegistrableDomainEvidence,
                observation.ServiceBundleCandidate,
                observation.DisplayName,
                payload.ShortReason,
                nowUtc);

            // Honor caller cancellation until this explicit pre-commit gate.
            // The store commit and its audit intent are irreversible together,
            // so caller cancellation must not cross that boundary.
            cancellationToken.ThrowIfCancellationRequested();

            PendingWebsiteRequestStoreResult stored;
            try
            {
                stored = await _store.CommitPendingWithAuditIntentAsync(
                    candidate,
                    nowUtc,
                    CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception)
            {
                return await CompleteFailureAsync(
                    WebsiteRequestAuditKind.DependencyFailure,
                    WebsiteAccessRequestStatus.FailedClosed,
                    context,
                    payload.ObservationId,
                    nowUtc,
                    cancellationToken).ConfigureAwait(false);
            }

            if (!IsExactStoredRequest(candidate, stored) ||
                !IsExactCommittedAuditIntent(
                    candidate,
                    stored,
                    nowUtc))
            {
                return await CompleteFailureAsync(
                    WebsiteRequestAuditKind.DependencyFailure,
                    WebsiteAccessRequestStatus.FailedClosed,
                    context,
                    payload.ObservationId,
                    nowUtc,
                    cancellationToken).ConfigureAwait(false);
            }

            var storedRequest = stored.Request;
            // Delivery is best-effort: the durable intent remains for a
            // dispatcher even if this immediate writer call fails.
            await TryDispatchAndAcknowledgeAsync(
                stored.AuditIntent).ConfigureAwait(false);

            return WebsiteAccessRequestResult.Accepted(
                storedRequest,
                stored.Created);
        }

        private static bool IsExactActiveObservation(
            AuthenticatedChildContext context,
            CreateWebsiteRequestPayload payload,
            VerifiedBlockedWebsiteObservation? observation,
            DateTimeOffset nowUtc)
        {
            return observation != null &&
                   string.Equals(
                       observation.ObservationId,
                       payload.ObservationId,
                       StringComparison.Ordinal) &&
                   string.Equals(
                       observation.DeviceId,
                       context.DeviceId,
                       StringComparison.Ordinal) &&
                   observation.ChildAccountSid.Equals(
                       context.ChildAccountSid) &&
                   observation.IsActiveAt(nowUtc);
        }

        private static bool IsExactRateLimitResult(
            AuthenticatedChildContext context,
            WebsiteRequestRateLimitResult? result)
        {
            return result != null &&
                   string.Equals(
                       result.DeviceId,
                       context.DeviceId,
                       StringComparison.Ordinal) &&
                   result.ChildAccountSid.Equals(
                       context.ChildAccountSid) &&
                   (result.Outcome ==
                        WebsiteRequestRateLimitOutcome.Allowed ||
                    result.Outcome ==
                        WebsiteRequestRateLimitOutcome.Exceeded);
        }

        private static bool IsExactStoredRequest(
            WebsiteAccessRequest candidate,
            PendingWebsiteRequestStoreResult? stored)
        {
            if (stored == null ||
                !stored.Request.RequestKey.Equals(
                    candidate.RequestKey) ||
                !string.Equals(
                    stored.Request.DeviceId,
                    candidate.DeviceId,
                    StringComparison.Ordinal) ||
                !stored.Request.ChildAccountSid.Equals(
                    candidate.ChildAccountSid) ||
                !SameRegistrableTarget(
                    stored.Request.RegistrableDomainEvidence,
                    candidate.RegistrableDomainEvidence) ||
                !SameBundleCandidate(
                    stored.Request.ServiceBundleCandidate,
                    candidate.ServiceBundleCandidate))
            {
                return false;
            }

            if (!stored.Created)
            {
                return true;
            }

            return string.Equals(
                       stored.Request.RequestId,
                       candidate.RequestId,
                       StringComparison.Ordinal) &&
                   string.Equals(
                       stored.Request.ObservationId,
                       candidate.ObservationId,
                       StringComparison.Ordinal) &&
                   stored.Request.CanonicalHost.Equals(
                       candidate.CanonicalHost) &&
                   string.Equals(
                       stored.Request.DisplayName,
                       candidate.DisplayName,
                       StringComparison.Ordinal) &&
                   string.Equals(
                       stored.Request.ChildReason,
                       candidate.ChildReason,
                       StringComparison.Ordinal) &&
                   stored.Request.CreatedAtUtc ==
                       candidate.CreatedAtUtc;
        }

        private static bool IsExactCommittedAuditIntent(
            WebsiteAccessRequest candidate,
            PendingWebsiteRequestStoreResult stored,
            DateTimeOffset occurredAtUtc)
        {
            var auditEvent = stored.AuditIntent.AuditEvent;
            return string.Equals(
                       stored.AuditIntent.IntentId,
                       WebsiteRequestAuditIntent.ForAttempt(
                           candidate.RequestId),
                       StringComparison.Ordinal) &&
                   auditEvent.Kind ==
                       (stored.Created
                           ? WebsiteRequestAuditKind.Created
                           : WebsiteRequestAuditKind.Deduplicated) &&
                   auditEvent.OccurredAtUtc == occurredAtUtc &&
                   string.Equals(
                       auditEvent.DeviceId,
                       candidate.DeviceId,
                       StringComparison.Ordinal) &&
                   auditEvent.ChildAccountSid.Equals(
                       candidate.ChildAccountSid) &&
                   string.Equals(
                       auditEvent.ObservationId,
                       candidate.ObservationId,
                       StringComparison.Ordinal) &&
                   string.Equals(
                       auditEvent.RequestId,
                       stored.Request.RequestId,
                       StringComparison.Ordinal) &&
                   auditEvent.RequestKey != null &&
                   auditEvent.RequestKey.Equals(stored.Request.RequestKey);
        }

        private static bool SameRegistrableTarget(
            RegistrableDomainEvidence left,
            RegistrableDomainEvidence right)
        {
            return left.RegistrableDomain.Equals(
                       right.RegistrableDomain) &&
                   left.PublicSuffix.Equals(right.PublicSuffix) &&
                   string.Equals(
                       left.ResolverRevision,
                       right.ResolverRevision,
                       StringComparison.Ordinal);
        }

        private static bool SameBundleCandidate(
            VerifiedWebServiceBundle? left,
            VerifiedWebServiceBundle? right)
        {
            if (left == null || right == null)
            {
                return left == null && right == null;
            }

            var leftSignature = left.Signature;
            var rightSignature = right.Signature;
            return string.Equals(
                       left.Bundle.BundleId,
                       right.Bundle.BundleId,
                       StringComparison.Ordinal) &&
                   string.Equals(
                       left.Bundle.CanonicalDigestSha256(),
                       right.Bundle.CanonicalDigestSha256(),
                       StringComparison.Ordinal) &&
                    string.Equals(
                        leftSignature.CatalogId,
                        rightSignature.CatalogId,
                        StringComparison.Ordinal) &&
                    leftSignature.CatalogSequence ==
                        rightSignature.CatalogSequence &&
                    leftSignature.BundleVersion ==
                        rightSignature.BundleVersion &&
                    leftSignature.IssuedAtUtc ==
                        rightSignature.IssuedAtUtc &&
                    leftSignature.ExpiresAtUtc ==
                        rightSignature.ExpiresAtUtc &&
                    string.Equals(
                        leftSignature.MinimumGuardVersion,
                        rightSignature.MinimumGuardVersion,
                        StringComparison.Ordinal) &&
                    string.Equals(
                        leftSignature.DigestSha256,
                       rightSignature.DigestSha256,
                       StringComparison.Ordinal) &&
                   string.Equals(
                       leftSignature.SigningKeyId,
                       rightSignature.SigningKeyId,
                       StringComparison.Ordinal) &&
                   SameBytes(
                       leftSignature.Signature,
                       rightSignature.Signature);
        }

        private static bool SameBytes(byte[] left, byte[] right)
        {
            if (left.Length != right.Length)
            {
                return false;
            }

            var difference = 0;
            for (var index = 0; index < left.Length; index++)
            {
                difference |= left[index] ^ right[index];
            }

            return difference == 0;
        }

        private async Task<WebsiteAccessRequestResult>
            CompleteFailureAsync(
                WebsiteRequestAuditKind kind,
                WebsiteAccessRequestStatus status,
                AuthenticatedChildContext context,
                string observationId,
                DateTimeOffset nowUtc,
                CancellationToken cancellationToken)
        {
            var intent = new WebsiteRequestAuditIntent(
                Guid.NewGuid().ToString("D"),
                new WebsiteRequestAuditEvent(
                    kind,
                    nowUtc,
                    context.DeviceId,
                    context.ChildAccountSid,
                    observationId,
                    null,
                    null));
            try
            {
                await _audit.EnqueueAsync(
                    intent,
                    CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception)
            {
                // The request remains fail closed. A production outbox failure
                // is surfaced through service health and cannot be repaired by
                // treating this security event as delivered.
                return WebsiteAccessRequestResult.Rejected(status);
            }

            await TryDispatchAndAcknowledgeAsync(intent)
                .ConfigureAwait(false);

            return WebsiteAccessRequestResult.Rejected(status);
        }

        private async Task<bool> TryDispatchAndAcknowledgeAsync(
            WebsiteRequestAuditIntent intent)
        {
            try
            {
                await _audit.WriteAsync(
                    intent,
                    CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception)
            {
                return false;
            }

            try
            {
                await _audit.AcknowledgeAsync(
                    intent.IntentId,
                    CancellationToken.None).ConfigureAwait(false);
                return true;
            }
            catch (Exception)
            {
                // Stable IntentId makes a later redelivery idempotent.
                return false;
            }
        }
    }

    internal static class WebsiteRequestText
    {
        public static string Require(
            string value,
            int maximumCharacters,
            string parameterName)
        {
            var normalized = NormalizeOptional(
                value,
                maximumCharacters,
                parameterName);
            if (normalized == null)
            {
                throw new ArgumentException(
                    "A bounded non-blank value is required.",
                    parameterName);
            }

            return normalized;
        }

        private static string? NormalizeOptional(
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
                throw new ArgumentException(
                    "Text exceeds its bounded length.",
                    parameterName);
            }

            for (var index = 0; index < value.Length; index++)
            {
                var character = value[index];
                var category =
                    CharUnicodeInfo.GetUnicodeCategory(value, index);
                if (category == UnicodeCategory.Control ||
                    category == UnicodeCategory.Format ||
                    category == UnicodeCategory.LineSeparator ||
                    category == UnicodeCategory.ParagraphSeparator)
                {
                    throw new ArgumentException(
                        "Control and formatting characters are not allowed.",
                        parameterName);
                }

                if (char.IsHighSurrogate(character))
                {
                    if (index + 1 >= value.Length ||
                        !char.IsLowSurrogate(value[index + 1]))
                    {
                        throw new ArgumentException(
                            "Text must contain valid Unicode.",
                            parameterName);
                    }

                    index++;
                }
                else if (char.IsLowSurrogate(character))
                {
                    throw new ArgumentException(
                        "Text must contain valid Unicode.",
                        parameterName);
                }
            }

            return value;
        }
    }
}
