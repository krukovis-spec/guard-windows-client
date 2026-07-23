using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;

namespace Guard.Windows.Services
{
    public enum ServiceHealthProbeState
    {
        Found = 0,
        NotFound = 1,
        Unknown = 2,
        Error = 3
    }

    public enum GuardServiceStartMode
    {
        Unspecified = 0,
        Automatic = 1,
        AutomaticDelayed = 2,
        Manual = 3,
        Disabled = 4
    }

    public enum GuardServiceRunState
    {
        Unspecified = 0,
        Running = 1,
        Stopped = 2,
        StartPending = 3,
        StopPending = 4,
        Paused = 5
    }

    public sealed class ServiceHealthFacts
    {
        public ServiceHealthFacts(
            bool exists,
            string? accountSid,
            GuardServiceStartMode startMode,
            GuardServiceRunState runState,
            string? binaryPath)
        {
            Exists = exists;
            AccountSid = accountSid;
            StartMode = startMode;
            RunState = runState;
            BinaryPath = binaryPath;
        }

        public bool Exists { get; }

        public string? AccountSid { get; }

        public GuardServiceStartMode StartMode { get; }

        public GuardServiceRunState RunState { get; }

        public string? BinaryPath { get; }
    }

    public sealed class ServiceHealthProbeResult
    {
        public ServiceHealthProbeResult(ServiceHealthProbeState state, ServiceHealthFacts? facts)
        {
            State = state;
            Facts = facts;
        }

        public ServiceHealthProbeState State { get; }

        public ServiceHealthFacts? Facts { get; }
    }

    /// <summary>Read-only boundary for a future SCM implementation.</summary>
    public interface IServiceHealthQuery
    {
        ServiceHealthProbeResult Query(string serviceName);
    }

    public enum ServiceHealthFailure
    {
        ProbeNotFound = 1,
        ProbeUnknown = 2,
        ProbeError = 3,
        FactsMissing = 4,
        ServiceMissing = 5,
        AccountNotLocalSystem = 6,
        StartModeNotAutomatic = 7,
        ServiceNotRunning = 8,
        BinaryPathMissing = 9,
        BinaryPathInvalid = 10,
        BinaryPathAmbiguous = 11,
        BinaryPathUnexpectedArguments = 12,
        BinaryPathMismatch = 13
    }

    public sealed class ServiceHealthEvaluation
    {
        public ServiceHealthEvaluation(IReadOnlyList<ServiceHealthFailure> failures)
        {
            if (failures == null)
            {
                throw new ArgumentNullException(nameof(failures));
            }

            var copy = new List<ServiceHealthFailure>(failures);
            Failures = new ReadOnlyCollection<ServiceHealthFailure>(copy);
        }

        public IReadOnlyList<ServiceHealthFailure> Failures { get; }

        public bool IsHealthy => Failures.Count == 0;
    }

    public sealed class GuardServiceHealthInspector
    {
        private readonly IServiceHealthQuery _query;
        private readonly string _serviceName;
        private readonly string _expectedBinaryPath;

        public GuardServiceHealthInspector(
            IServiceHealthQuery query,
            string serviceName,
            string expectedBinaryPath)
        {
            _query = query ?? throw new ArgumentNullException(nameof(query));
            if (string.IsNullOrWhiteSpace(serviceName))
            {
                throw new ArgumentException("A service name is required.", nameof(serviceName));
            }

            _serviceName = serviceName;
            _expectedBinaryPath = ServiceHealthEvaluator.CanonicalizeExpectedBinaryPath(expectedBinaryPath);
        }

        public ServiceHealthEvaluation Inspect()
        {
            try
            {
                return ServiceHealthEvaluator.Evaluate(_query.Query(_serviceName), _expectedBinaryPath);
            }
            catch (Exception)
            {
                return new ServiceHealthEvaluation(new[] { ServiceHealthFailure.ProbeError });
            }
        }
    }

    public static class ServiceHealthEvaluator
    {
        public const string LocalSystemSid = "S-1-5-18";

        public static string CanonicalizeExpectedBinaryPath(string expectedBinaryPath)
        {
            if (string.IsNullOrWhiteSpace(expectedBinaryPath) ||
                !Path.IsPathFullyQualified(expectedBinaryPath) ||
                expectedBinaryPath.IndexOf('"') >= 0)
            {
                throw new ArgumentException("An absolute unquoted binary path is required.", nameof(expectedBinaryPath));
            }

            return Path.GetFullPath(expectedBinaryPath)
                .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }

        public static ServiceHealthEvaluation Evaluate(
            ServiceHealthProbeResult? probe,
            string expectedBinaryPath)
        {
            var failures = new List<ServiceHealthFailure>();
            if (probe == null)
            {
                failures.Add(ServiceHealthFailure.ProbeUnknown);
                return new ServiceHealthEvaluation(failures);
            }

            if (probe.State != ServiceHealthProbeState.Found)
            {
                failures.Add(ToProbeFailure(probe.State));
                return new ServiceHealthEvaluation(failures);
            }

            if (probe.Facts == null)
            {
                failures.Add(ServiceHealthFailure.FactsMissing);
                return new ServiceHealthEvaluation(failures);
            }

            var facts = probe.Facts;
            if (!facts.Exists)
            {
                failures.Add(ServiceHealthFailure.ServiceMissing);
            }

            if (!string.Equals(facts.AccountSid, LocalSystemSid, StringComparison.Ordinal))
            {
                failures.Add(ServiceHealthFailure.AccountNotLocalSystem);
            }

            if (facts.StartMode != GuardServiceStartMode.Automatic)
            {
                failures.Add(ServiceHealthFailure.StartModeNotAutomatic);
            }

            if (facts.RunState != GuardServiceRunState.Running)
            {
                failures.Add(ServiceHealthFailure.ServiceNotRunning);
            }

            EvaluateBinaryPath(facts.BinaryPath, expectedBinaryPath, failures);
            return new ServiceHealthEvaluation(failures);
        }

        private static ServiceHealthFailure ToProbeFailure(ServiceHealthProbeState state)
        {
            return state == ServiceHealthProbeState.NotFound
                ? ServiceHealthFailure.ProbeNotFound
                : state == ServiceHealthProbeState.Error
                    ? ServiceHealthFailure.ProbeError
                    : ServiceHealthFailure.ProbeUnknown;
        }

        private static void EvaluateBinaryPath(
            string? reportedBinaryPath,
            string expectedBinaryPath,
            ICollection<ServiceHealthFailure> failures)
        {
            if (string.IsNullOrWhiteSpace(reportedBinaryPath))
            {
                failures.Add(ServiceHealthFailure.BinaryPathMissing);
                return;
            }

            string binaryPath;
            ServiceHealthFailure parseFailure;
            if (!TryExtractBinaryPath(reportedBinaryPath, out binaryPath, out parseFailure))
            {
                failures.Add(parseFailure);
                return;
            }

            try
            {
                if (!Path.IsPathFullyQualified(binaryPath))
                {
                    failures.Add(ServiceHealthFailure.BinaryPathInvalid);
                    return;
                }

                var canonicalReported = Path.GetFullPath(binaryPath)
                    .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                if (!string.Equals(canonicalReported, expectedBinaryPath, StringComparison.OrdinalIgnoreCase))
                {
                    failures.Add(ServiceHealthFailure.BinaryPathMismatch);
                }
            }
            catch (ArgumentException)
            {
                failures.Add(ServiceHealthFailure.BinaryPathInvalid);
            }
            catch (NotSupportedException)
            {
                failures.Add(ServiceHealthFailure.BinaryPathInvalid);
            }
            catch (PathTooLongException)
            {
                failures.Add(ServiceHealthFailure.BinaryPathInvalid);
            }
        }

        private static bool TryExtractBinaryPath(
            string commandLine,
            out string binaryPath,
            out ServiceHealthFailure failure)
        {
            binaryPath = string.Empty;
            failure = ServiceHealthFailure.BinaryPathInvalid;
            var value = commandLine.Trim();
            if (value.StartsWith("\"", StringComparison.Ordinal))
            {
                var closingQuote = value.IndexOf('"', 1);
                if (closingQuote <= 1)
                {
                    return false;
                }

                if (value.Substring(closingQuote + 1).Trim().Length != 0)
                {
                    failure =
                        ServiceHealthFailure
                            .BinaryPathUnexpectedArguments;
                    return false;
                }

                binaryPath = value.Substring(1, closingQuote - 1);
                return true;
            }

            if (value.IndexOfAny(new[] { ' ', '\t' }) >= 0)
            {
                failure = ServiceHealthFailure.BinaryPathAmbiguous;
                return false;
            }

            binaryPath = value;
            return true;
        }
    }
}
