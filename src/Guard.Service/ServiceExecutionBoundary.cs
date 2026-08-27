using System;
using System.Security;
using System.Security.Principal;
using Microsoft.Extensions.Hosting.WindowsServices;

namespace Guard.Service
{
    internal interface IServiceProcessContext
    {
        bool IsWindowsService { get; }

        bool IsLocalSystem { get; }
    }

    internal sealed class WindowsServiceProcessContext : IServiceProcessContext
    {
        public bool IsWindowsService => WindowsServiceHelpers.IsWindowsService();

        public bool IsLocalSystem
        {
            get
            {
                using (var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query))
                {
                    return identity.IsSystem;
                }
            }
        }
    }

    internal sealed class ServiceExecutionBoundary
    {
        private readonly IServiceProcessContext _context;

        public ServiceExecutionBoundary(IServiceProcessContext context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
        }

        public void DemandAuthorizedServiceProcess()
        {
            if (!_context.IsWindowsService || !_context.IsLocalSystem)
            {
                throw new SecurityException("Guard.Service requires the Windows Service Control Manager and LocalSystem identity.");
            }
        }
    }
}
