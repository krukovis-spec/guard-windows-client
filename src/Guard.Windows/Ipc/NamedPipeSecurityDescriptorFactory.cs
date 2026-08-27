using System;
using System.Security.Principal;
using Guard.Contracts;

namespace Guard.Windows.Ipc
{
    public static class NamedPipeSecurityDescriptorFactory
    {
        // FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_EA |
        // FILE_WRITE_ATTRIBUTES, deliberately excluding FILE_APPEND_DATA.
        // On named pipes FILE_APPEND_DATA is FILE_CREATE_PIPE_INSTANCE, so
        // granting GENERIC_WRITE would let an authorized client create a
        // competing server instance.
        internal const int PipeClientReadWriteMaskWithoutCreateInstance = 0x0012019B;

        private const string SystemSid = "S-1-5-18";
        private const string BuiltinAdministratorsSid = "S-1-5-32-544";

        public static string CreateSddl(GuardPipeSecurityProfile profile)
        {
            if (profile == null)
            {
                throw new ArgumentNullException(nameof(profile));
            }

            var clientSid = profile.AuthorizedSid.Value;
            if (profile.Role == ClientRole.AdminSetup)
            {
                if (!string.Equals(clientSid, BuiltinAdministratorsSid, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException("The admin pipe must be bound to BUILTIN Administrators.");
                }
            }
            else
            {
                DemandDedicatedPrincipal(profile, clientSid);
            }

            return "O:SYG:SYD:P(A;;GA;;;SY)(A;;0x" +
                   PipeClientReadWriteMaskWithoutCreateInstance.ToString("X8") +
                   ";;;" + clientSid + ")";
        }

        private static void DemandDedicatedPrincipal(
            GuardPipeSecurityProfile profile,
            string clientSid)
        {
            SecurityIdentifier sid;
            try
            {
                sid = new SecurityIdentifier(clientSid);
            }
            catch (ArgumentException exception)
            {
                throw new InvalidOperationException(
                    "The pipe client SID is not a valid Windows principal.",
                    exception);
            }

            if (sid.IsWellKnown(WellKnownSidType.NullSid) ||
                sid.IsWellKnown(WellKnownSidType.WorldSid) ||
                sid.IsWellKnown(WellKnownSidType.AnonymousSid) ||
                sid.IsWellKnown(WellKnownSidType.AuthenticatedUserSid) ||
                sid.IsWellKnown(WellKnownSidType.BuiltinUsersSid) ||
                sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) ||
                sid.IsWellKnown(WellKnownSidType.LocalSystemSid) ||
                sid.IsWellKnown(WellKnownSidType.LocalServiceSid) ||
                sid.IsWellKnown(WellKnownSidType.NetworkServiceSid))
            {
                throw new InvalidOperationException(
                    "A broad or privileged SID cannot own a restricted Guard pipe.");
            }

            if (profile.Role == ClientRole.Child &&
                (!sid.IsAccountSid() ||
                 sid.AccountDomainSid == null ||
                 sid.Equals(sid.AccountDomainSid)))
            {
                throw new InvalidOperationException(
                    "The child pipe requires one concrete Windows account SID.");
            }
        }
    }
}
