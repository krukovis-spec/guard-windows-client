using System;
using Guard.Contracts;
using Guard.Domain;

namespace Guard.Windows.Ipc
{
    public enum PipeClientAuthorizationKind
    {
        BuiltinAdministrators = 1,
        ExactAccountSid = 2
    }

    public sealed class GuardPipeSecurityProfile
    {
        public GuardPipeSecurityProfile(
            string pipeName,
            ClientRole role,
            PipeClientAuthorizationKind authorizationKind,
            WindowsAccountSid authorizedSid)
        {
            if (!IsPipeNameForRole(pipeName, role))
            {
                throw new ArgumentException(
                    "The canonical Guard v2 pipe name must match its server-assigned role.",
                    nameof(pipeName));
            }

            if (role != ClientRole.AdminSetup &&
                role != ClientRole.Child &&
                role != ClientRole.Proxy)
            {
                throw new ArgumentOutOfRangeException(nameof(role));
            }

            if ((role == ClientRole.AdminSetup) !=
                (authorizationKind == PipeClientAuthorizationKind.BuiltinAdministrators))
            {
                throw new ArgumentException("The pipe role and authorization kind do not match.");
            }

            PipeName = pipeName;
            Role = role;
            AuthorizationKind = authorizationKind;
            AuthorizedSid = authorizedSid ?? throw new ArgumentNullException(nameof(authorizedSid));
        }

        public string PipeName { get; }

        public ClientRole Role { get; }

        public PipeClientAuthorizationKind AuthorizationKind { get; }

        public WindowsAccountSid AuthorizedSid { get; }

        private static bool IsPipeNameForRole(string pipeName, ClientRole role)
        {
            return role == ClientRole.AdminSetup &&
                       string.Equals(pipeName, "Guard.V2.AdminSetup.v1", StringComparison.Ordinal) ||
                   role == ClientRole.Child &&
                       string.Equals(pipeName, "Guard.V2.Child.v1", StringComparison.Ordinal) ||
                   role == ClientRole.Proxy &&
                       string.Equals(pipeName, "Guard.V2.Proxy.v1", StringComparison.Ordinal);
        }
    }
}
