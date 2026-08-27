using System;
using System.Collections.Generic;

namespace Guard.Service
{
    internal sealed class ServiceStartupOptions
    {
        public const string InitializeAuthoritativeStateArgument =
            "--initialize-authoritative-state";

        private ServiceStartupOptions(bool initializeAuthoritativeState)
        {
            InitializeAuthoritativeState = initializeAuthoritativeState;
        }

        public bool InitializeAuthoritativeState { get; }

        public static ServiceStartupOptions Normal { get; } =
            new ServiceStartupOptions(initializeAuthoritativeState: false);

        public static ServiceStartupOptions Parse(
            string[]? args,
            out string[] hostArgs)
        {
            var initialize = false;
            var remaining = new List<string>();
            var values = args ?? Array.Empty<string>();
            for (var index = 0; index < values.Length; index++)
            {
                var value = values[index] ?? string.Empty;
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

            hostArgs = remaining.ToArray();
            return initialize
                ? new ServiceStartupOptions(initializeAuthoritativeState: true)
                : Normal;
        }
    }
}
