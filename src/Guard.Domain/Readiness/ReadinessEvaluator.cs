using System;
using System.Collections.Generic;

namespace Guard.Domain.Readiness
{
    public static class ReadinessEvaluator
    {
        public static ReadinessEvaluation Evaluate(ReadinessProbeFacts facts)
        {
            if (facts == null)
            {
                throw new ArgumentNullException(nameof(facts));
            }

            var findings = new List<ReadinessFinding>();
            AddRequiredFinding(findings, facts.WindowsEdition, ReadinessFindingCodes.WindowsEditionReady, ReadinessFindingCodes.WindowsEditionBlocking);
            AddRequiredFinding(findings, facts.ChildAccount, ReadinessFindingCodes.ChildAccountReady, ReadinessFindingCodes.ChildAccountBlocking);
            AddRequiredFinding(findings, facts.SeparateLocalAdministrator, ReadinessFindingCodes.SeparateLocalAdministratorReady, ReadinessFindingCodes.SeparateLocalAdministratorBlocking);
            AddRequiredFinding(findings, facts.SecureBoot, ReadinessFindingCodes.SecureBootReady, ReadinessFindingCodes.SecureBootBlocking);
            AddRequiredFinding(findings, facts.BitLocker, ReadinessFindingCodes.BitLockerReady, ReadinessFindingCodes.BitLockerBlocking);
            AddRequiredFinding(findings, facts.ServiceBoundary, ReadinessFindingCodes.ServiceBoundaryReady, ReadinessFindingCodes.ServiceBoundaryBlocking);
            AddRequiredFinding(findings, facts.ProgramDataAcl, ReadinessFindingCodes.ProgramDataAclReady, ReadinessFindingCodes.ProgramDataAclBlocking);
            AddBrowserFinding(findings, facts.SupportedManagedBrowser);
            return new ReadinessEvaluation(findings);
        }

        private static void AddRequiredFinding(List<ReadinessFinding> findings, ReadinessProbeFact fact, string readyCode, string blockingCode)
        {
            if (fact.State == ReadinessFactState.Satisfied)
            {
                findings.Add(new ReadinessFinding(readyCode, ReadinessFindingSeverity.Ready));
                return;
            }

            findings.Add(new ReadinessFinding(blockingCode, ReadinessFindingSeverity.Blocking));
        }

        private static void AddBrowserFinding(List<ReadinessFinding> findings, SupportedManagedBrowserProbeFact fact)
        {
            if (fact.State != ReadinessFactState.Satisfied || fact.ManagedBrowserCount == 0)
            {
                findings.Add(new ReadinessFinding(ReadinessFindingCodes.SupportedManagedBrowserBlocking, ReadinessFindingSeverity.Blocking));
                return;
            }

            findings.Add(new ReadinessFinding(ReadinessFindingCodes.SupportedManagedBrowserReady, ReadinessFindingSeverity.Ready));
            if (fact.ManagedBrowserCount == 1)
            {
                findings.Add(new ReadinessFinding(ReadinessFindingCodes.LimitedBrowserCoverageWarning, ReadinessFindingSeverity.Warning));
            }
        }
    }
}
