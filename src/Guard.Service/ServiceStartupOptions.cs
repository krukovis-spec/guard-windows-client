using System;
using System.Collections.Generic;

namespace Guard.Service
{
    internal sealed class ServiceStartupOptions
    {
        public const string InitializeAuthoritativeStateArgument =
            "--initialize-authoritative-state";
        public const string ImportDeviceRelayProfileArgument = "--import-device-relay-profile";

        private ServiceStartupOptions(bool initializeAuthoritativeState, bool importDeviceRelayProfile = false)
        {
            InitializeAuthoritativeState = initializeAuthoritativeState;
            ImportDeviceRelayProfile = importDeviceRelayProfile;
        }

        public bool InitializeAuthoritativeState { get; }
        public bool ImportDeviceRelayProfile { get; }

        public static ServiceStartupOptions Normal { get; } =
            new ServiceStartupOptions(initializeAuthoritativeState: false);

        public static ServiceStartupOptions Parse(
            string[]? args,
            out string[] hostArgs)
        {
            var initialize = false;
            var import = false;
            var remaining = new List<string>();
            var values = args ?? Array.Empty<string>();
            for (var index = 0; index < values.Length; index++)
            {
                var value = values[index] ?? string.Empty;
                if (string.Equals(value, ImportDeviceRelayProfileArgument, StringComparison.Ordinal))
                {
                    if (import) throw new ArgumentException("Duplicate device profile import argument.", nameof(args));
                    import = true;
                    continue;
                }
                if (string.Equals(
                    value,
                    InitializeAuthoritativeStateArgument,
                    StringComparison.Ordinal))
                {
                    if (initialize)
                    {
                        throw new ArgumentException(
                            "The authoritative-state initialization argument can be supplied only once.",
                            nameof(args));
                    }

                    initialize = true;
                    continue;
                }

                remaining.Add(value);
            }

            if (initialize && import)
                throw new ArgumentException("Device profile import requires an already initialized identity.", nameof(args));
            hostArgs = remaining.ToArray();
            return initialize || import
                ? new ServiceStartupOptions(initialize, import)
                : Normal;
        }
    }
}
