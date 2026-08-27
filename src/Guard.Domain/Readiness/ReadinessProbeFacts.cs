using System;

namespace Guard.Domain.Readiness
{
    public sealed class ReadinessProbeFacts
    {
        public ReadinessProbeFacts(
            ReadinessProbeFact windowsEdition,
            ReadinessProbeFact childAccount,
            ReadinessProbeFact separateLocalAdministrator,
            ReadinessProbeFact secureBoot,
            ReadinessProbeFact bitLocker,
            ReadinessProbeFact serviceBoundary,
            ReadinessProbeFact programDataAcl,
            SupportedManagedBrowserProbeFact supportedManagedBrowser)
        {
            WindowsEdition = RequireFact(windowsEdition, nameof(windowsEdition));
            ChildAccount = RequireFact(childAccount, nameof(childAccount));
            SeparateLocalAdministrator = RequireFact(separateLocalAdministrator, nameof(separateLocalAdministrator));
            SecureBoot = RequireFact(secureBoot, nameof(secureBoot));
            BitLocker = RequireFact(bitLocker, nameof(bitLocker));
            ServiceBoundary = RequireFact(serviceBoundary, nameof(serviceBoundary));
            ProgramDataAcl = RequireFact(programDataAcl, nameof(programDataAcl));
            SupportedManagedBrowser = supportedManagedBrowser ?? throw new ArgumentNullException(nameof(supportedManagedBrowser));
        }

        public ReadinessProbeFact WindowsEdition { get; }

        public ReadinessProbeFact ChildAccount { get; }

        public ReadinessProbeFact SeparateLocalAdministrator { get; }

        public ReadinessProbeFact SecureBoot { get; }

        public ReadinessProbeFact BitLocker { get; }

        public ReadinessProbeFact ServiceBoundary { get; }

        public ReadinessProbeFact ProgramDataAcl { get; }

        public SupportedManagedBrowserProbeFact SupportedManagedBrowser { get; }

        private static ReadinessProbeFact RequireFact(ReadinessProbeFact value, string parameterName)
        {
            return value ?? throw new ArgumentNullException(parameterName);
        }
    }
}
