using System;
using Guard.Contracts;

namespace Guard.Application
{
    public enum IpcValidationStatus
    {
        Valid = 0,
        UnsupportedProtocol = 1,
        InvalidRequestId = 2,
        UnknownVerb = 3,
        PayloadTooLarge = 4
    }

    public static class IpcSecurityPolicy
    {
        public static bool CanInvoke(ClientRole role, GuardVerb verb)
        {
            switch (role)
            {
                case ClientRole.Child:
                    return verb == GuardVerb.GetStatus ||
                           verb == GuardVerb.CreateApplicationRequest ||
                           verb == GuardVerb.CreateWebsiteRequest;

                case ClientRole.AdminSetup:
                    return verb == GuardVerb.GetStatus ||
                           verb == GuardVerb.GetReadiness ||
                           verb == GuardVerb.BeginSetup;

                case ClientRole.Proxy:
                    return verb == GuardVerb.EvaluateDomain;

                case ClientRole.ParentRelay:
                    return verb == GuardVerb.CompleteSetup ||
                           verb == GuardVerb.ApplyParentDecision;

                case ClientRole.ServiceInternal:
                    return verb == GuardVerb.GetStatus ||
                           verb == GuardVerb.GetReadiness ||
                           verb == GuardVerb.ReconcilePolicy;

                default:
                    return false;
            }
        }

        public static IpcValidationStatus Validate(GuardIpcRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (request.ProtocolVersion != GuardProtocol.CurrentVersion)
            {
                return IpcValidationStatus.UnsupportedProtocol;
            }

            Guid parsedRequestId;
            if (!Guid.TryParseExact(request.RequestId, "D", out parsedRequestId))
            {
                return IpcValidationStatus.InvalidRequestId;
            }

            if (!Enum.IsDefined(typeof(GuardVerb), request.Verb) || request.Verb == GuardVerb.Unknown)
            {
                return IpcValidationStatus.UnknownVerb;
            }

            if (request.PayloadLength > GuardProtocol.MaximumFrameBytes)
            {
                return IpcValidationStatus.PayloadTooLarge;
            }

            return IpcValidationStatus.Valid;
        }
    }
}
