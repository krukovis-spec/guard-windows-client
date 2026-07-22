namespace Guard
{
    public enum LegacyParentOwnershipRoute
    {
        ChildVisiblePairingCode,
        LegacyAssignApi,
        EmailCode,
        SmsCode,
        Totp,
        LegacyServerPayload
    }

    public static class GuardV2ContainmentPolicy
    {
        // P0 quarantine: the legacy control plane stays unavailable until the
        // passkey provisioning ceremony and LocalSystem boundary exist.
        public static bool CanStartParentAdminServer(GuardState? state)
        {
            return false;
        }

        public static bool CanClaimParentOwnership(GuardState? state, LegacyParentOwnershipRoute route)
        {
            return false;
        }

        public static bool CanUseLegacyRemoteServer(GuardState? state)
        {
            return false;
        }

        public static bool CanSendLegacyTelemetry(GuardState? state)
        {
            return false;
        }

        public static bool CanAuthorizeLocalPrivilegedAction(string? storedPin, string? enteredPin)
        {
            return EmergencyPinPolicy.IsAuthorized(storedPin, enteredPin);
        }

        public static bool CanAuthorizeCleaner(string? storedPin, string? enteredPin)
        {
            return EmergencyPinPolicy.IsAuthorized(storedPin, enteredPin);
        }
    }
}
