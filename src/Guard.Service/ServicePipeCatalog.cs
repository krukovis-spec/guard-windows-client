using System;
using System.Collections.Generic;
using Guard.Contracts;
using Guard.Domain;

namespace Guard.Service
{
    internal static class ServicePipeNames
    {
        public const string AdminSetup = "Guard.V2.AdminSetup.v1";
        public const string Child = "Guard.V2.Child.v1";
        public const string Proxy = "Guard.V2.Proxy.v1";
    }

    internal enum PipeClientAuthorizationKind
    {
        BuiltinAdministrators = 1,
        ExactAccountSid = 2
    }

    internal sealed class ServicePipeEndpoint
    {
        public ServicePipeEndpoint(
            string pipeName,
            ClientRole role,
            PipeClientAuthorizationKind authorizationKind,
            WindowsAccountSid authorizedSid)
        {
            if (string.IsNullOrWhiteSpace(pipeName))
            {
                throw new ArgumentException("A pipe name is required.", nameof(pipeName));
            }

            if (role != ClientRole.AdminSetup &&
                role != ClientRole.Child &&
                role != ClientRole.Proxy)
            {
                throw new ArgumentOutOfRangeException(nameof(role));
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
    }

    internal static class ServicePipeCatalog
    {
        private static readonly WindowsAccountSid BuiltinAdministrators =
            new WindowsAccountSid("S-1-5-32-544");

        public static IReadOnlyList<ServicePipeEndpoint> Create(
            DeviceSecurityState state,
            WindowsAccountSid? proxyAccountSid)
        {
            if (state == null)
            {
                throw new ArgumentNullException(nameof(state));
            }

            var endpoints = new List<ServicePipeEndpoint>
            {
                new ServicePipeEndpoint(
                    ServicePipeNames.AdminSetup,
                    ClientRole.AdminSetup,
                    PipeClientAuthorizationKind.BuiltinAdministrators,
                    BuiltinAdministrators)
            };

            if (state.ChildAccountSid != null)
            {
                endpoints.Add(new ServicePipeEndpoint(
                    ServicePipeNames.Child,
                    ClientRole.Child,
                    PipeClientAuthorizationKind.ExactAccountSid,
                    state.ChildAccountSid));
            }

            if (proxyAccountSid != null)
            {
                endpoints.Add(new ServicePipeEndpoint(
                    ServicePipeNames.Proxy,
                    ClientRole.Proxy,
                    PipeClientAuthorizationKind.ExactAccountSid,
                    proxyAccountSid));
            }

            return endpoints.AsReadOnly();
        }
    }
}
