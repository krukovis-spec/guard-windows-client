using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Guard.Application;
using Guard.Domain;

namespace Guard.Windows.Accounts
{
    public sealed class LocalAccountSecurityFacts
    {
        public LocalAccountSecurityFacts(
            WindowsAccountSid sid,
            bool exists,
            bool isLocalUser,
            bool isEnabled,
            bool isGuest,
            bool isServiceIdentity,
            bool isAdministrator)
        {
            Sid = sid ?? throw new ArgumentNullException(nameof(sid));
            Exists = exists;
            IsLocalUser = isLocalUser;
            IsEnabled = isEnabled;
            IsGuest = isGuest;
            IsServiceIdentity = isServiceIdentity;
            IsAdministrator = isAdministrator;
        }

        public WindowsAccountSid Sid { get; }

        public bool Exists { get; }

        public bool IsLocalUser { get; }

        public bool IsEnabled { get; }

        public bool IsGuest { get; }

        public bool IsServiceIdentity { get; }

        public bool IsAdministrator { get; }
    }

    public interface ILocalAccountSecurityFactsProvider
    {
        bool TryGet(WindowsAccountSid candidateSid, out LocalAccountSecurityFacts facts);
    }

    public sealed class ManagedChildAccountValidator : IManagedChildAccountValidator
    {
        private readonly ILocalAccountSecurityFactsProvider _factsProvider;

        public ManagedChildAccountValidator(ILocalAccountSecurityFactsProvider factsProvider)
        {
            _factsProvider = factsProvider ?? throw new ArgumentNullException(nameof(factsProvider));
        }

        public bool TryValidate(string candidateSid, out WindowsAccountSid binding)
        {
            binding = null!;
            if (!WindowsAccountSid.IsCanonical(candidateSid))
            {
                return false;
            }

            try
            {
                var candidate = new WindowsAccountSid(candidateSid);
                LocalAccountSecurityFacts facts;
                if (!_factsProvider.TryGet(candidate, out facts) ||
                    facts == null ||
                    !facts.Sid.Equals(candidate) ||
                    !facts.Exists ||
                    !facts.IsLocalUser ||
                    !facts.IsEnabled ||
                    facts.IsGuest ||
                    facts.IsServiceIdentity ||
                    facts.IsAdministrator)
                {
                    return false;
                }

                binding = facts.Sid;
                return true;
            }
            catch (Win32Exception)
            {
                return false;
            }
            catch (ExternalException)
            {
                return false;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
            catch (PlatformNotSupportedException)
            {
                return false;
            }
        }
    }
}
