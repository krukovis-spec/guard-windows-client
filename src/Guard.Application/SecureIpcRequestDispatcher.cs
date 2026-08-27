using System;
using System.Threading;
using System.Threading.Tasks;
using Guard.Contracts;

namespace Guard.Application
{
    public interface IGuardIpcOperationHandler
    {
        Task<GuardIpcResponse> HandleAsync(
            ClientRole authenticatedRole,
            GuardIpcRequest request,
            CancellationToken cancellationToken);
    }

    public sealed class SecureIpcRequestDispatcher
    {
        private readonly IGuardIpcOperationHandler _handler;

        public SecureIpcRequestDispatcher(IGuardIpcOperationHandler handler)
        {
            _handler = handler ?? throw new ArgumentNullException(nameof(handler));
        }

        public async Task<GuardIpcResponse> DispatchAsync(
            ClientRole authenticatedRole,
            GuardIpcRequest request,
            CancellationToken cancellationToken)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (!Enum.IsDefined(typeof(ClientRole), authenticatedRole) ||
                authenticatedRole == ClientRole.Unknown ||
                IpcSecurityPolicy.Validate(request) != IpcValidationStatus.Valid)
            {
                return EmptyResponse(request.RequestId, GuardIpcResponseStatus.InvalidRequest);
            }

            if (!IpcSecurityPolicy.CanInvoke(authenticatedRole, request.Verb))
            {
                return EmptyResponse(request.RequestId, GuardIpcResponseStatus.Forbidden);
            }

            try
            {
                var response = await _handler
                    .HandleAsync(authenticatedRole, request, cancellationToken)
                    .ConfigureAwait(false);
                if (response == null ||
                    response.ProtocolVersion != GuardProtocol.CurrentVersion ||
                    !string.Equals(response.RequestId, request.RequestId, StringComparison.Ordinal) ||
                    response.PayloadLength > GuardProtocol.MaximumFrameBytes ||
                    !Enum.IsDefined(typeof(GuardIpcResponseStatus), response.Status))
                {
                    return EmptyResponse(request.RequestId, GuardIpcResponseStatus.InternalError);
                }

                return response;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                return EmptyResponse(request.RequestId, GuardIpcResponseStatus.InternalError);
            }
        }

        private static GuardIpcResponse EmptyResponse(
            string requestId,
            GuardIpcResponseStatus status)
        {
            Guid parsedRequestId;
            var safeRequestId = Guid.TryParseExact(requestId, "D", out parsedRequestId)
                ? requestId
                : Guid.Empty.ToString("D");
            return new GuardIpcResponse(
                GuardProtocol.CurrentVersion,
                safeRequestId,
                status,
                Array.Empty<byte>());
        }
    }
}
