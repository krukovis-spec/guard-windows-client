using System;
using System.Collections.Generic;
using Guard.Windows.Services;

namespace Guard.Windows.ScmQuery.Tests
{
    internal static class Program
    {
        private static int Main()
        {
            var tests = new List<(string Name, Action Run)>
            {
                ("maps complete service facts", MapsCompleteFacts),
                ("maps absent service", MapsNotFound),
                ("preserves delayed automatic start", MapsDelayedAutomatic),
                ("fails closed for malformed facts", FailsClosedForMalformedFacts),
                ("fails closed for native errors", FailsClosedForNativeErrors),
                ("rejects malformed service names before native access", RejectsMalformedServiceNames),
                ("uses one query and releases fake resources", UsesSingleCallAndCleansUp)
            };
            var failures = 0;
            foreach (var test in tests)
            {
                try { test.Run(); Console.WriteLine("PASS " + test.Name); }
                catch (Exception error) { failures++; Console.WriteLine("FAIL " + test.Name + ": " + error.Message); }
            }
            return failures == 0 ? 0 : 1;
        }

        private static void MapsCompleteFacts()
        {
            var native = new FakeNative(ScmServiceOpenResult.Found(new FakeSession(new ScmServiceConfiguration(2, false, "LocalSystem", "\"C:\\Guard\\Guard.Service.exe\""), 4)));
            var result = new WindowsServiceHealthQuery(native, new FakeClassifier()).Query("GuardV2");
            Assert(result.State == ServiceHealthProbeState.Found && result.Facts != null, "Complete probe was not found.");
            Assert(result.Facts!.Exists && result.Facts.AccountSid == ServiceHealthEvaluator.LocalSystemSid, "Account SID was not mapped.");
            Assert(result.Facts.StartMode == GuardServiceStartMode.Automatic && result.Facts.RunState == GuardServiceRunState.Running, "Service enums were not mapped.");
            Assert(result.Facts.BinaryPath == "\"C:\\Guard\\Guard.Service.exe\"", "Binary ImagePath was not preserved exactly.");
        }

        private static void MapsNotFound()
        {
            var result = new WindowsServiceHealthQuery(new FakeNative(ScmServiceOpenResult.NotFound()), new FakeClassifier()).Query("GuardV2");
            Assert(result.State == ServiceHealthProbeState.NotFound && result.Facts == null, "Missing service did not map to NotFound.");
        }

        private static void MapsDelayedAutomatic()
        {
            var result = Query(new ScmServiceConfiguration(2, true, "LocalSystem", "C:\\Guard\\Guard.Service.exe"), 4);
            Assert(result.State == ServiceHealthProbeState.Found && result.Facts!.StartMode == GuardServiceStartMode.AutomaticDelayed, "Delayed automatic start was flattened.");
        }

        private static void FailsClosedForMalformedFacts()
        {
            AssertError(new ScmServiceConfiguration(999, false, "LocalSystem", "C:\\Guard\\Guard.Service.exe"), 4);
            AssertError(new ScmServiceConfiguration(3, true, "LocalSystem", "C:\\Guard\\Guard.Service.exe"), 4);
            AssertError(new ScmServiceConfiguration(2, false, "bad\0account", "C:\\Guard\\Guard.Service.exe"), 4);
            AssertError(new ScmServiceConfiguration(2, false, "LocalSystem", "C:\\Guard\\bad\nservice.exe"), 4);
            AssertError(new ScmServiceConfiguration(2, false, "LocalSystem", new string('a', 32769)), 4);
            AssertError(new ScmServiceConfiguration(2, false, "LocalSystem", "C:\\Guard\\Guard.Service.exe"), 999);
        }

        private static void FailsClosedForNativeErrors()
        {
            var native = new ThrowingNative();
            var result = new WindowsServiceHealthQuery(native, new FakeClassifier()).Query("GuardV2");
            Assert(result.State == ServiceHealthProbeState.Error && result.Facts == null, "Native exception did not map to Error.");

            var session = new ThrowingSession();
            result = new WindowsServiceHealthQuery(new FakeNative(ScmServiceOpenResult.Found(session)), new FakeClassifier()).Query("GuardV2");
            Assert(result.State == ServiceHealthProbeState.Error && result.Facts == null && session.DisposeCount == 1, "Session failure did not fail closed and clean up.");
        }

        private static void RejectsMalformedServiceNames()
        {
            var native = new FakeNative(ScmServiceOpenResult.NotFound());
            var query = new WindowsServiceHealthQuery(
                native,
                new FakeClassifier());
            Assert(
                query.Query("Guard\0Other").State ==
                    ServiceHealthProbeState.Error,
                "A NUL-containing service name was accepted.");
            Assert(
                query.Query("Guard\nOther").State ==
                    ServiceHealthProbeState.Error,
                "A control-containing service name was accepted.");
            Assert(
                native.OpenCount == 0,
                "A malformed service name reached native SCM access.");
        }

        private static void UsesSingleCallAndCleansUp()
        {
            var session = new FakeSession(new ScmServiceConfiguration(2, false, "LocalSystem", "C:\\Guard\\Guard.Service.exe"), 4);
            var native = new FakeNative(ScmServiceOpenResult.Found(session));
            var result = new WindowsServiceHealthQuery(native, new FakeClassifier()).Query("GuardV2");
            Assert(result.State == ServiceHealthProbeState.Found, "Expected found result.");
            Assert(native.OpenCount == 1 && session.ConfigurationReads == 1 && session.StatusReads == 1 && session.DisposeCount == 1, "Query did not use exactly one session or release it exactly once.");
        }

        private static ServiceHealthProbeResult Query(ScmServiceConfiguration configuration, uint state)
        {
            return new WindowsServiceHealthQuery(new FakeNative(ScmServiceOpenResult.Found(new FakeSession(configuration, state))), new FakeClassifier()).Query("GuardV2");
        }

        private static void AssertError(ScmServiceConfiguration configuration, uint state)
        {
            var result = Query(configuration, state);
            Assert(result.State == ServiceHealthProbeState.Error && result.Facts == null, "Malformed input did not fail closed.");
        }

        private static void Assert(bool condition, string message)
        {
            if (!condition) throw new InvalidOperationException(message);
        }

        private sealed class FakeNative : IWindowsScmNativeApi
        {
            private readonly ScmServiceOpenResult _result;
            public FakeNative(ScmServiceOpenResult result) { _result = result; }
            public int OpenCount { get; private set; }
            public ScmServiceOpenResult OpenForQuery(string serviceName) { OpenCount++; return _result; }
        }

        private sealed class ThrowingNative : IWindowsScmNativeApi
        {
            public ScmServiceOpenResult OpenForQuery(string serviceName) { throw new InvalidOperationException("fake native failure"); }
        }

        private sealed class FakeSession : IScmQuerySession
        {
            private readonly ScmServiceConfiguration _configuration;
            private readonly uint _state;
            public FakeSession(ScmServiceConfiguration configuration, uint state) { _configuration = configuration; _state = state; }
            public int ConfigurationReads { get; private set; }
            public int StatusReads { get; private set; }
            public int DisposeCount { get; private set; }
            public ScmServiceConfiguration ReadConfiguration() { ConfigurationReads++; return _configuration; }
            public uint ReadCurrentState() { StatusReads++; return _state; }
            public void Dispose() { DisposeCount++; }
        }

        private sealed class FakeClassifier : IServiceAccountSidClassifier
        {
            public bool TryGetSid(string accountName, out string sid)
            {
                sid = accountName == "LocalSystem" ? ServiceHealthEvaluator.LocalSystemSid : string.Empty;
                return sid.Length != 0;
            }
        }

        private sealed class ThrowingSession : IScmQuerySession
        {
            public int DisposeCount { get; private set; }
            public ScmServiceConfiguration ReadConfiguration() { throw new InvalidOperationException("fake config failure"); }
            public uint ReadCurrentState() { throw new InvalidOperationException("not reached"); }
            public void Dispose() { DisposeCount++; }
        }
    }
}
