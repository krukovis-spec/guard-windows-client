using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Threading;
using Guard.Domain;
using Guard.Domain.Readiness;
using Guard.Windows.Readiness;

namespace Guard.Windows.Accounts
{
    public sealed class SeparateLocalAdministratorCandidateFacts
    {
        public SeparateLocalAdministratorCandidateFacts(
            WindowsAccountSid sid,
            bool isLocalUser,
            bool isEnabled,
            bool isLocked,
            bool passwordRequired,
            bool isGuest,
            bool isServiceIdentity,
            bool isEffectiveAdministrator)
        {
            Sid = sid ?? throw new ArgumentNullException(nameof(sid));
            IsLocalUser = isLocalUser;
            IsEnabled = isEnabled;
            IsLocked = isLocked;
            PasswordRequired = passwordRequired;
            IsGuest = isGuest;
            IsServiceIdentity = isServiceIdentity;
            IsEffectiveAdministrator = isEffectiveAdministrator;
        }

        public WindowsAccountSid Sid { get; }
        public bool IsLocalUser { get; }
        public bool IsEnabled { get; }
        public bool IsLocked { get; }
        public bool PasswordRequired { get; }
        public bool IsGuest { get; }
        public bool IsServiceIdentity { get; }
        public bool IsEffectiveAdministrator { get; }
    }

    public sealed class SeparateLocalAdministratorInventory
    {
        public SeparateLocalAdministratorInventory(
            WindowsAccountSid authoritativeChildSid,
            IReadOnlyCollection<SeparateLocalAdministratorCandidateFacts> candidates)
        {
            AuthoritativeChildSid = authoritativeChildSid ?? throw new ArgumentNullException(nameof(authoritativeChildSid));
            if (candidates == null)
            {
                throw new ArgumentNullException(nameof(candidates));
            }

            var copy =
                new List<SeparateLocalAdministratorCandidateFacts>(
                    candidates);
            Candidates =
                new ReadOnlyCollection<
                    SeparateLocalAdministratorCandidateFacts>(copy);
        }

        public WindowsAccountSid AuthoritativeChildSid { get; }
        public IReadOnlyList<SeparateLocalAdministratorCandidateFacts> Candidates { get; }
    }

    public interface ISeparateLocalAdministratorInventory
    {
        SeparateLocalAdministratorInventory Get(CancellationToken cancellationToken);
    }

    public sealed class SeparateLocalAdministratorReadiness : IReadinessProbe
    {
        private readonly ISeparateLocalAdministratorInventory _inventory;

        public SeparateLocalAdministratorReadiness(ISeparateLocalAdministratorInventory inventory)
        {
            _inventory = inventory ?? throw new ArgumentNullException(nameof(inventory));
        }

        public ReadinessProbeFact Probe(CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                return Unknown();
            }

            try
            {
                var inventory = _inventory.Get(cancellationToken);
                if (inventory == null ||
                    inventory.AuthoritativeChildSid == null ||
                    inventory.Candidates == null)
                {
                    return Error();
                }

                foreach (var candidate in inventory.Candidates)
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        return Unknown();
                    }

                    if (candidate == null || candidate.Sid == null)
                    {
                        return Error();
                    }

                    if (IsQualifying(candidate, inventory.AuthoritativeChildSid))
                    {
                        return Satisfied();
                    }
                }

                return Unsatisfied();
            }
            catch (OperationCanceledException)
            {
                return Unknown();
            }
            catch (Exception)
            {
                return Error();
            }
        }

        private static bool IsQualifying(
            SeparateLocalAdministratorCandidateFacts candidate,
            WindowsAccountSid childSid)
        {
            return candidate.IsLocalUser &&
                   candidate.IsEnabled &&
                   !candidate.IsLocked &&
                   candidate.PasswordRequired &&
                   !candidate.IsGuest &&
                   !candidate.IsServiceIdentity &&
                   !IsKnownServiceSid(candidate.Sid) &&
                   !HasGuestRelativeId(candidate.Sid) &&
                   candidate.IsEffectiveAdministrator &&
                   !candidate.Sid.Equals(childSid);
        }

        private static bool IsKnownServiceSid(WindowsAccountSid sid)
        {
            return string.Equals(
                       sid.Value,
                       "S-1-5-18",
                       StringComparison.Ordinal) ||
                   string.Equals(
                       sid.Value,
                       "S-1-5-19",
                       StringComparison.Ordinal) ||
                   string.Equals(
                       sid.Value,
                       "S-1-5-20",
                       StringComparison.Ordinal);
        }

        private static bool HasGuestRelativeId(WindowsAccountSid sid)
        {
            var separator = sid.Value.LastIndexOf('-');
            return separator >= 0 &&
                   string.Equals(
                       sid.Value.Substring(separator + 1),
                       "501",
                       StringComparison.Ordinal);
        }

        private static ReadinessProbeFact Satisfied() => new ReadinessProbeFact(ReadinessFactState.Satisfied);
        private static ReadinessProbeFact Unsatisfied() => new ReadinessProbeFact(ReadinessFactState.Unsatisfied);
        private static ReadinessProbeFact Unknown() => new ReadinessProbeFact(ReadinessFactState.Unknown);
        private static ReadinessProbeFact Error() => new ReadinessProbeFact(ReadinessFactState.Error);
    }
}
