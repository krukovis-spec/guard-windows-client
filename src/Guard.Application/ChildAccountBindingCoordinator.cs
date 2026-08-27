using System;
using System.Threading;
using System.Threading.Tasks;
using Guard.Contracts;
using Guard.Domain;

namespace Guard.Application
{
    public enum ChildAccountBindingStatus
    {
        Succeeded = 0,
        Forbidden = 1,
        ParentNotProvisioned = 2,
        AlreadyBound = 3,
        InvalidCandidate = 4,
        StateConflict = 5
    }

    public interface IManagedChildAccountValidator
    {
        bool TryValidate(string candidateSid, out WindowsAccountSid binding);
    }

    public sealed class ChildAccountBindingResult
    {
        public ChildAccountBindingResult(
            ChildAccountBindingStatus status,
            DeviceSecurityState state)
        {
            Status = status;
            State = state ?? throw new ArgumentNullException(nameof(state));
        }

        public ChildAccountBindingStatus Status { get; }

        public DeviceSecurityState State { get; }
    }

    public sealed class ChildAccountBindingCoordinator
    {
        private readonly IAuthoritativeStateStore _store;
        private readonly IManagedChildAccountValidator _validator;

        public ChildAccountBindingCoordinator(
            IAuthoritativeStateStore store,
            IManagedChildAccountValidator validator)
        {
            _store = store ?? throw new ArgumentNullException(nameof(store));
            _validator = validator ?? throw new ArgumentNullException(nameof(validator));
        }

        public async Task<ChildAccountBindingResult> BindAsync(
            ClientRole role,
            string candidateSid,
            DateTimeOffset nowUtc,
            CancellationToken cancellationToken)
        {
            var current = await _store.LoadAsync(cancellationToken).ConfigureAwait(false);
            if (role != ClientRole.AdminSetup)
            {
                return new ChildAccountBindingResult(ChildAccountBindingStatus.Forbidden, current);
            }

            if (!current.IsProvisioned &&
                (current.SetupChallenge == null ||
                 !current.SetupChallenge.IsActive(nowUtc)))
            {
                return new ChildAccountBindingResult(ChildAccountBindingStatus.ParentNotProvisioned, current);
            }

            if (current.ChildAccountSid != null)
            {
                return new ChildAccountBindingResult(ChildAccountBindingStatus.AlreadyBound, current);
            }

            WindowsAccountSid childAccountSid;
            bool validated;
            try
            {
                validated = _validator.TryValidate(candidateSid, out childAccountSid);
            }
            catch (ArgumentException)
            {
                validated = false;
                childAccountSid = null!;
            }
            catch (InvalidOperationException)
            {
                validated = false;
                childAccountSid = null!;
            }

            if (!validated || childAccountSid == null)
            {
                return new ChildAccountBindingResult(ChildAccountBindingStatus.InvalidCandidate, current);
            }

            var next = current.WithBoundChildAccount(
                childAccountSid,
                nowUtc);
            var committed = await _store.TryCommitAsync(current.Version, next, cancellationToken).ConfigureAwait(false);
            return committed
                ? new ChildAccountBindingResult(ChildAccountBindingStatus.Succeeded, next)
                : new ChildAccountBindingResult(ChildAccountBindingStatus.StateConflict, current);
        }
    }
}
