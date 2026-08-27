using System;
using System.Collections.Generic;
using Guard.Domain.Readiness;
using Guard.Domain.SelfProtection;

namespace Guard.Readiness.Tests
{
    internal static class Program
    {
        private static int Main()
        {
            var tests = new List<(string Name, Action Run)>
            {
                ("enables protection only when every required fact is satisfied", EnablesOnlyWhenReady),
                ("blocks protection when any fact is unknown or errors", BlocksUnknownAndErrorFacts),
                ("blocks protection when a required fact is unsatisfied", BlocksUnsatisfiedFact),
                ("reports stable ready, warning, and blocking codes", ReportsStableFindingCodes),
                ("keeps probe facts and evaluation findings immutable", PreservesImmutability),
                ("fails closed for incomplete, ad-hoc, or duplicate findings", FailsClosedForMalformedPublicEvaluations),
                ("accepts only the complete Guard service installation contract", AcceptsCompleteServiceInstallationContract),
                ("rejects every service self-protection weakness", RejectsServiceSelfProtectionWeaknesses),
                ("fails closed when service installation cannot be observed", FailsClosedForUnavailableServiceObservation)
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

            Console.WriteLine(failures == 0 ? "All Guard readiness checks passed." : failures + " Guard readiness check(s) failed.");
            return failures == 0 ? 0 : 1;
        }

        private static void EnablesOnlyWhenReady()
        {
            var evaluation = ReadinessEvaluator.Evaluate(CreateReadyFacts(managedBrowserCount: 2));
            Assert(evaluation.CanEnableProtection, "Fully verified readiness did not enable protection.");
            Assert(Count(evaluation, ReadinessFindingSeverity.Blocking) == 0, "Fully verified readiness returned a blocking finding.");
        }

        private static void BlocksUnknownAndErrorFacts()
        {
            var unknown = ReadinessEvaluator.Evaluate(CreateFacts(windowsEdition: new ReadinessProbeFact(ReadinessFactState.Unknown)));
            var error = ReadinessEvaluator.Evaluate(CreateFacts(secureBoot: new ReadinessProbeFact(ReadinessFactState.Error)));
            Assert(!unknown.CanEnableProtection, "Unknown fact enabled protection.");
            Assert(!error.CanEnableProtection, "Error fact enabled protection.");
            Assert(Has(unknown, ReadinessFindingCodes.WindowsEditionBlocking, ReadinessFindingSeverity.Blocking), "Unknown Windows fact lacked its stable blocking code.");
            Assert(Has(error, ReadinessFindingCodes.SecureBootBlocking, ReadinessFindingSeverity.Blocking), "Error Secure Boot fact lacked its stable blocking code.");
        }

        private static void BlocksUnsatisfiedFact()
        {
            var evaluation = ReadinessEvaluator.Evaluate(CreateFacts(childAccount: new ReadinessProbeFact(ReadinessFactState.Unsatisfied)));
            Assert(!evaluation.CanEnableProtection, "Unsatisfied child account fact enabled protection.");
            Assert(Has(evaluation, ReadinessFindingCodes.ChildAccountBlocking, ReadinessFindingSeverity.Blocking), "Unsatisfied child account did not block with the stable code.");
        }

        private static void ReportsStableFindingCodes()
        {
            var limited = ReadinessEvaluator.Evaluate(CreateReadyFacts(managedBrowserCount: 1));
            var browserMissing = ReadinessEvaluator.Evaluate(CreateFacts(browser: new SupportedManagedBrowserProbeFact(ReadinessFactState.Unsatisfied, 0)));
            Assert(Has(limited, ReadinessFindingCodes.WindowsEditionReady, ReadinessFindingSeverity.Ready), "Ready Windows code was missing.");
            Assert(Has(limited, ReadinessFindingCodes.LimitedBrowserCoverageWarning, ReadinessFindingSeverity.Warning), "Limited-browser warning was missing.");
            Assert(limited.CanEnableProtection, "A limited but supported managed browser blocked protection.");
            Assert(Has(browserMissing, ReadinessFindingCodes.SupportedManagedBrowserBlocking, ReadinessFindingSeverity.Blocking), "Missing managed browser did not block.");
        }

        private static void PreservesImmutability()
        {
            var facts = CreateReadyFacts(managedBrowserCount: 2);
            Assert(facts.WindowsEdition.State == ReadinessFactState.Satisfied, "Probe fact changed unexpectedly.");
            var evaluation = ReadinessEvaluator.Evaluate(facts);
            var first = evaluation.Findings[0];
            Assert(first.Code == ReadinessFindingCodes.WindowsEditionReady, "Evaluation did not retain its finding.");
        }

        private static void FailsClosedForMalformedPublicEvaluations()
        {
            var complete = ReadinessEvaluator.Evaluate(CreateReadyFacts(managedBrowserCount: 2)).Findings;
            Assert(!new ReadinessEvaluation(Array.Empty<ReadinessFinding>()).CanEnableProtection, "Empty findings enabled protection.");
            Assert(!new ReadinessEvaluation(new[] { complete[0] }).CanEnableProtection, "Incomplete findings enabled protection.");
            Assert(!new ReadinessEvaluation(new[]
            {
                complete[0],
                new ReadinessFinding("READINESS_AD_HOC", ReadinessFindingSeverity.Ready)
            }).CanEnableProtection, "Ad-hoc findings enabled protection.");

            var duplicated = new List<ReadinessFinding>(complete)
            {
                complete[0]
            };
            Assert(!new ReadinessEvaluation(duplicated).CanEnableProtection, "Duplicate findings enabled protection.");
        }

        private static void AcceptsCompleteServiceInstallationContract()
        {
            var evaluation =
                GuardServiceInstallationContract.Evaluate(
                    ReadyServiceInstallation());
            Assert(
                evaluation.IsSatisfied &&
                evaluation.Failures.Count == 0,
                "The complete service installation contract was rejected.");
        }

        private static void RejectsServiceSelfProtectionWeaknesses()
        {
            var observation = new ObservedGuardServiceInstallation(
                ServiceInstallationObservationState.Observed,
                serviceName: "guard",
                accountSid: "S-1-5-20",
                isOwnProcess: false,
                isInteractive: true,
                GuardServiceStartPolicy.AutomaticDelayed,
                GuardServiceSidPolicy.None,
                recoveryActionsConfigured: false,
                standardUsersCanStop: true,
                standardUsersCanChangeConfiguration: true,
                standardUsersCanDelete: true,
                binaryPathMatchesExpected: false,
                installRootProtected: false,
                installRootIsReparsePoint: true,
                legacyAuthorityDisabled: false);
            var evaluation =
                GuardServiceInstallationContract.Evaluate(observation);
            Assert(!evaluation.IsSatisfied, "A weak service installation passed.");
            Assert(
                evaluation.Failures.Count == 12,
                "The self-protection contract skipped a required failure.");
            Assert(
                Contains(
                    evaluation.Failures,
                    GuardServiceInstallationFailure.StandardUserServiceControl) &&
                Contains(
                    evaluation.Failures,
                    GuardServiceInstallationFailure.LegacyAuthorityActive),
                "Critical service-control failures were missing.");
        }

        private static void FailsClosedForUnavailableServiceObservation()
        {
            var unavailable = new[]
            {
                ServiceInstallationObservationState.NotInstalled,
                ServiceInstallationObservationState.Unknown,
                ServiceInstallationObservationState.Error
            };
            for (var index = 0; index < unavailable.Length; index++)
            {
                var observation =
                    new ObservedGuardServiceInstallation(
                        unavailable[index],
                        string.Empty,
                        string.Empty,
                        isOwnProcess: false,
                        isInteractive: false,
                        GuardServiceStartPolicy.Unspecified,
                        GuardServiceSidPolicy.None,
                        recoveryActionsConfigured: false,
                        standardUsersCanStop: false,
                        standardUsersCanChangeConfiguration: false,
                        standardUsersCanDelete: false,
                        binaryPathMatchesExpected: false,
                        installRootProtected: false,
                        installRootIsReparsePoint: false,
                        legacyAuthorityDisabled: false);
                Assert(
                    !GuardServiceInstallationContract
                        .Evaluate(observation)
                        .IsSatisfied,
                    "An unavailable service observation passed.");
            }
        }

        private static ObservedGuardServiceInstallation
            ReadyServiceInstallation()
        {
            return new ObservedGuardServiceInstallation(
                ServiceInstallationObservationState.Observed,
                GuardServiceInstallationContract.ServiceName,
                GuardServiceInstallationContract.LocalSystemSid,
                isOwnProcess: true,
                isInteractive: false,
                GuardServiceStartPolicy.Automatic,
                GuardServiceSidPolicy.Unrestricted,
                recoveryActionsConfigured: true,
                standardUsersCanStop: false,
                standardUsersCanChangeConfiguration: false,
                standardUsersCanDelete: false,
                binaryPathMatchesExpected: true,
                installRootProtected: true,
                installRootIsReparsePoint: false,
                legacyAuthorityDisabled: true);
        }

        private static ReadinessProbeFacts CreateReadyFacts(int managedBrowserCount)
        {
            return CreateFacts(browser: new SupportedManagedBrowserProbeFact(ReadinessFactState.Satisfied, managedBrowserCount));
        }

        private static ReadinessProbeFacts CreateFacts(
            ReadinessProbeFact? windowsEdition = null,
            ReadinessProbeFact? childAccount = null,
            ReadinessProbeFact? separateLocalAdministrator = null,
            ReadinessProbeFact? secureBoot = null,
            ReadinessProbeFact? bitLocker = null,
            ReadinessProbeFact? serviceBoundary = null,
            ReadinessProbeFact? programDataAcl = null,
            SupportedManagedBrowserProbeFact? browser = null)
        {
            return new ReadinessProbeFacts(
                windowsEdition ?? Satisfied(),
                childAccount ?? Satisfied(),
                separateLocalAdministrator ?? Satisfied(),
                secureBoot ?? Satisfied(),
                bitLocker ?? Satisfied(),
                serviceBoundary ?? Satisfied(),
                programDataAcl ?? Satisfied(),
                browser ?? new SupportedManagedBrowserProbeFact(ReadinessFactState.Satisfied, 2));
        }

        private static ReadinessProbeFact Satisfied()
        {
            return new ReadinessProbeFact(ReadinessFactState.Satisfied);
        }

        private static bool Has(ReadinessEvaluation evaluation, string code, ReadinessFindingSeverity severity)
        {
            foreach (var finding in evaluation.Findings)
            {
                if (string.Equals(finding.Code, code, StringComparison.Ordinal) && finding.Severity == severity)
                {
                    return true;
                }
            }

            return false;
        }

        private static int Count(ReadinessEvaluation evaluation, ReadinessFindingSeverity severity)
        {
            var count = 0;
            foreach (var finding in evaluation.Findings)
            {
                if (finding.Severity == severity)
                {
                    count++;
                }
            }

            return count;
        }

        private static bool Contains(
            IReadOnlyList<GuardServiceInstallationFailure> values,
            GuardServiceInstallationFailure expected)
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

        private static void Assert(bool value, string message)
        {
            if (!value)
            {
                throw new InvalidOperationException(message);
            }
        }
    }
}
