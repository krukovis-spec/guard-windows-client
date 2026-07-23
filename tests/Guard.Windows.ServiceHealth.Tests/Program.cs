using System;
using System.Collections.Generic;
using Guard.Windows.Services;

namespace Guard.Windows.ServiceHealth.Tests
{
    internal static class Program
    {
        private const string ServiceName = "GuardV2";
        private const string ExpectedPath = "C:\\Program Files\\Guard\\Guard.Service.exe";

        private static int Main()
        {
            var tests = new List<(string Name, Action Run)>
            {
                ("accepts a complete LocalSystem automatic running service", AcceptsReadyService),
                ("rejects every required service mismatch", RejectsEachMismatch),
                ("fails closed for unknown error and partial probe data", FailsClosedForUnavailableData),
                ("canonicalizes quoted binary paths and rejects ambiguous paths", HandlesPathEdges),
                ("returns immutable health outputs", ReturnsImmutableOutputs)
            };
            var failures = 0;
            foreach (var test in tests)
            {
                try
                {
                    test.Run();
                    Console.WriteLine("PASS " + test.Name);
                }
                catch (Exception exception)
                {
                    failures++;
                    Console.WriteLine("FAIL " + test.Name + ": " + exception.Message);
                }
            }

            Console.WriteLine(failures == 0
                ? "All Guard Windows service health checks passed."
                : failures + " Guard Windows service health check(s) failed.");
            return failures == 0 ? 0 : 1;
        }

        private static void AcceptsReadyService()
        {
            var query = new FixedQuery(Found(ReadyFacts()));
            var evaluation = new GuardServiceHealthInspector(query, ServiceName, ExpectedPath).Inspect();
            Assert(evaluation.IsHealthy, "Complete ready service was rejected.");
            Assert(query.CallCount == 1, "Inspector did not use its injected query exactly once.");
        }

        private static void RejectsEachMismatch()
        {
            AssertFailure(Found(new ServiceHealthFacts(false, ServiceHealthEvaluator.LocalSystemSid, GuardServiceStartMode.Automatic, GuardServiceRunState.Running, Quote(ExpectedPath))), ServiceHealthFailure.ServiceMissing);
            AssertFailure(Found(new ServiceHealthFacts(true, "S-1-5-20", GuardServiceStartMode.Automatic, GuardServiceRunState.Running, Quote(ExpectedPath))), ServiceHealthFailure.AccountNotLocalSystem);
            AssertFailure(Found(new ServiceHealthFacts(true, ServiceHealthEvaluator.LocalSystemSid, GuardServiceStartMode.AutomaticDelayed, GuardServiceRunState.Running, Quote(ExpectedPath))), ServiceHealthFailure.StartModeNotAutomatic);
            AssertFailure(Found(new ServiceHealthFacts(true, ServiceHealthEvaluator.LocalSystemSid, GuardServiceStartMode.Manual, GuardServiceRunState.Running, Quote(ExpectedPath))), ServiceHealthFailure.StartModeNotAutomatic);
            AssertFailure(Found(new ServiceHealthFacts(true, ServiceHealthEvaluator.LocalSystemSid, GuardServiceStartMode.Disabled, GuardServiceRunState.Running, Quote(ExpectedPath))), ServiceHealthFailure.StartModeNotAutomatic);
            AssertFailure(Found(new ServiceHealthFacts(true, ServiceHealthEvaluator.LocalSystemSid, GuardServiceStartMode.Automatic, GuardServiceRunState.Stopped, Quote(ExpectedPath))), ServiceHealthFailure.ServiceNotRunning);
            AssertFailure(Found(new ServiceHealthFacts(true, ServiceHealthEvaluator.LocalSystemSid, GuardServiceStartMode.Automatic, GuardServiceRunState.Running, "\"C:\\Guard\\other.exe\"")), ServiceHealthFailure.BinaryPathMismatch);
        }

        private static void FailsClosedForUnavailableData()
        {
            AssertFailure(new ServiceHealthProbeResult(ServiceHealthProbeState.NotFound, null), ServiceHealthFailure.ProbeNotFound);
            AssertFailure(new ServiceHealthProbeResult(ServiceHealthProbeState.Unknown, null), ServiceHealthFailure.ProbeUnknown);
            AssertFailure(new ServiceHealthProbeResult(ServiceHealthProbeState.Error, null), ServiceHealthFailure.ProbeError);
            AssertFailure(new ServiceHealthProbeResult(ServiceHealthProbeState.Found, null), ServiceHealthFailure.FactsMissing);
            AssertFailure(Found(new ServiceHealthFacts(true, null, GuardServiceStartMode.Unspecified, GuardServiceRunState.Unspecified, null)), ServiceHealthFailure.AccountNotLocalSystem);
            var inspector = new GuardServiceHealthInspector(new ThrowingQuery(), ServiceName, ExpectedPath);
            AssertFailure(inspector.Inspect(), ServiceHealthFailure.ProbeError);
        }

        private static void HandlesPathEdges()
        {
            AssertHealthy(Found(new ServiceHealthFacts(true, ServiceHealthEvaluator.LocalSystemSid, GuardServiceStartMode.Automatic, GuardServiceRunState.Running, "\"c:\\Program Files\\Guard\\bin\\..\\Guard.Service.exe\"")));
            AssertFailure(Found(new ServiceHealthFacts(true, ServiceHealthEvaluator.LocalSystemSid, GuardServiceStartMode.Automatic, GuardServiceRunState.Running, "\"" + ExpectedPath + "\" --initialize-authoritative-state")), ServiceHealthFailure.BinaryPathUnexpectedArguments);
            AssertFailure(Found(new ServiceHealthFacts(true, ServiceHealthEvaluator.LocalSystemSid, GuardServiceStartMode.Automatic, GuardServiceRunState.Running, ExpectedPath + " --service")), ServiceHealthFailure.BinaryPathAmbiguous);
            AssertFailure(Found(new ServiceHealthFacts(true, ServiceHealthEvaluator.LocalSystemSid, GuardServiceStartMode.Automatic, GuardServiceRunState.Running, ".\\Guard.Service.exe")), ServiceHealthFailure.BinaryPathInvalid);
            AssertHealthy(Found(new ServiceHealthFacts(true, ServiceHealthEvaluator.LocalSystemSid, GuardServiceStartMode.Automatic, GuardServiceRunState.Running, "C:\\Guard\\Guard.Service.exe")), "C:\\Guard\\Guard.Service.exe");
        }

        private static void ReturnsImmutableOutputs()
        {
            var source = new List<ServiceHealthFailure> { ServiceHealthFailure.ProbeUnknown };
            var evaluation = new ServiceHealthEvaluation(source);
            source.Clear();
            Assert(evaluation.Failures.Count == 1, "Evaluation retained mutable caller collection.");
            var mutable = evaluation.Failures as IList<ServiceHealthFailure>;
            if (mutable == null)
            {
                throw new InvalidOperationException("Evaluation did not expose a read-only list.");
            }

            var threw = false;
            try
            {
                mutable.Add(ServiceHealthFailure.ProbeError);
            }
            catch (NotSupportedException)
            {
                threw = true;
            }

            Assert(threw && evaluation.Failures.Count == 1, "Evaluation failures were mutable.");
        }

        private static ServiceHealthProbeResult Found(ServiceHealthFacts facts)
        {
            return new ServiceHealthProbeResult(ServiceHealthProbeState.Found, facts);
        }

        private static ServiceHealthFacts ReadyFacts()
        {
            return new ServiceHealthFacts(true, ServiceHealthEvaluator.LocalSystemSid, GuardServiceStartMode.Automatic, GuardServiceRunState.Running, Quote(ExpectedPath));
        }

        private static string Quote(string path)
        {
            return "\"" + path + "\"";
        }

        private static void AssertHealthy(ServiceHealthProbeResult probe, string? expectedPath = null)
        {
            var evaluation = ServiceHealthEvaluator.Evaluate(probe, ServiceHealthEvaluator.CanonicalizeExpectedBinaryPath(expectedPath ?? ExpectedPath));
            Assert(evaluation.IsHealthy, "Expected healthy result but got: " + string.Join(", ", evaluation.Failures));
        }

        private static void AssertFailure(ServiceHealthProbeResult probe, ServiceHealthFailure failure)
        {
            var evaluation = ServiceHealthEvaluator.Evaluate(probe, ServiceHealthEvaluator.CanonicalizeExpectedBinaryPath(ExpectedPath));
            AssertFailure(evaluation, failure);
        }

        private static void AssertFailure(ServiceHealthEvaluation evaluation, ServiceHealthFailure failure)
        {
            Assert(!evaluation.IsHealthy, "Unsafe result was marked healthy.");
            Assert(Contains(evaluation.Failures, failure), "Expected failure " + failure + " was missing.");
        }

        private static bool Contains(IReadOnlyList<ServiceHealthFailure> values, ServiceHealthFailure expected)
        {
            for (var index = 0; index < values.Count; index++)
            {
                if (values[index] == expected)
                {
                    return true;
                }
            }

            return false;
        }

        private static void Assert(bool condition, string message)
        {
            if (!condition)
            {
                throw new InvalidOperationException(message);
            }
        }

        private sealed class FixedQuery : IServiceHealthQuery
        {
            private readonly ServiceHealthProbeResult _result;

            public FixedQuery(ServiceHealthProbeResult result)
            {
                _result = result;
            }

            public int CallCount { get; private set; }

            public ServiceHealthProbeResult Query(string serviceName)
            {
                CallCount++;
                return _result;
            }
        }

        private sealed class ThrowingQuery : IServiceHealthQuery
        {
            public ServiceHealthProbeResult Query(string serviceName)
            {
                throw new UnauthorizedAccessException("Synthetic SCM query failure.");
            }
        }
    }
}
