using System;
using System.Threading;
using System.Threading.Tasks;
using Guard.Application;
using Guard.Windows.Ipc;

namespace Guard.Service
{
    internal sealed class WindowsServicePipeEndpointHostFactory :
        IServicePipeEndpointHostFactory
    {
        private readonly WindowsNamedPipeFactory _pipeFactory;
        private readonly GuardPipeConnectionProcessor _connectionProcessor;

        public WindowsServicePipeEndpointHostFactory(
            WindowsNamedPipeFactory pipeFactory,
            GuardPipeConnectionProcessor connectionProcessor)
        {
            _pipeFactory = pipeFactory ?? throw new ArgumentNullException(nameof(pipeFactory));
            _connectionProcessor = connectionProcessor ?? throw new ArgumentNullException(nameof(connectionProcessor));
        }

        public IServicePipeEndpointHost Create(ServicePipeEndpoint endpoint)
        {
            if (endpoint == null)
            {
                throw new ArgumentNullException(nameof(endpoint));
            }

            var authorizationKind =
                endpoint.AuthorizationKind == PipeClientAuthorizationKind.BuiltinAdministrators
                    ? Guard.Windows.Ipc.PipeClientAuthorizationKind.BuiltinAdministrators
                    : Guard.Windows.Ipc.PipeClientAuthorizationKind.ExactAccountSid;
            var profile = new GuardPipeSecurityProfile(
                endpoint.PipeName,
                endpoint.Role,
                authorizationKind,
                endpoint.AuthorizedSid);
            return new Adapter(new GuardPipeEndpointHost(
                profile,
                _pipeFactory,
                _connectionProcessor));
        }

        private sealed class Adapter : IServicePipeEndpointHost
        {
            private readonly GuardPipeEndpointHost _host;

            public Adapter(GuardPipeEndpointHost host)
            {
                _host = host;
            }

            public Task Completion => _host.Completion;

            public Task StartAsync(CancellationToken cancellationToken)
            {
                return _host.StartAsync(cancellationToken);
            }

            public Task StopAsync(CancellationToken cancellationToken)
            {
                return _host.StopAsync(cancellationToken);
            }
        }
    }
}
