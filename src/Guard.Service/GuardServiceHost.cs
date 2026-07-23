using System;
using Guard.Application;
using Guard.Application.Readiness;
using Guard.Storage;
using Guard.Windows.Accounts;
using Guard.Windows.Cryptography;
using Guard.Windows.Ipc;
using Guard.Windows.Readiness;
using Guard.Windows.Services;
using Guard.Windows.Storage;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Guard.Service
{
    internal static class GuardServiceHost
    {
        public static IHost Build(string[] args)
        {
            string[] hostArgs;
            var startupOptions = ServiceStartupOptions.Parse(
                args,
                out hostArgs);
            var builder = Host.CreateApplicationBuilder(hostArgs);
            builder.Services.AddWindowsService(options =>
            {
                options.ServiceName = GuardServiceIdentity.ServiceName;
            });
            builder.Services.AddSingleton(startupOptions);
            builder.Services.AddSingleton<IServiceProcessContext, WindowsServiceProcessContext>();
            AddProductionBoundary(builder.Services);
            AddServiceBoundary(builder.Services);
            return builder.Build();
        }

        internal static IHost BuildForTesting(
            IServiceProcessContext processContext,
            IServiceBoundaryInitializer initializer)
        {
            var builder = Host.CreateApplicationBuilder(Array.Empty<string>());
            builder.Services.AddSingleton<IServiceProcessContext>(
                processContext ?? throw new ArgumentNullException(nameof(processContext)));
            builder.Services.AddSingleton<IServiceBoundaryInitializer>(
                initializer ?? throw new ArgumentNullException(nameof(initializer)));
            builder.Services.AddSingleton(ServiceStartupOptions.Normal);
            AddServiceBoundary(builder.Services);
            return builder.Build();
        }

        private static void AddServiceBoundary(IServiceCollection services)
        {
            services.Configure<HostOptions>(options =>
            {
                options.BackgroundServiceExceptionBehavior = BackgroundServiceExceptionBehavior.StopHost;
            });
            services.AddSingleton<ServiceExecutionBoundary>();
            services.AddSingleton<ServiceExitStatus>();
            services.AddSingleton<GuardServiceRuntime>();
            services.AddSingleton<IHostedService, GuardServiceWorker>();
        }

        private static void AddProductionBoundary(IServiceCollection services)
        {
            services.AddSingleton(_ => GuardDataPaths.ForCurrentMachine());
            services.AddSingleton<ProgramDataAclGuard>();
            services.AddSingleton<ProgramDataServiceBoundaryGuard>();
            services.AddSingleton<IServiceDataBoundaryGuard>(
                provider => provider.GetRequiredService<ProgramDataServiceBoundaryGuard>());
            services.AddSingleton<IServiceDataBoundaryBootstrapper>(
                provider => provider.GetRequiredService<ProgramDataServiceBoundaryGuard>());
            services.AddSingleton<IStateDataProtector, LocalSystemDpapiDataProtector>();
            services.AddSingleton<ServiceAuthoritativeStateBoundary>();
            services.AddSingleton<IServiceWriterLease>(
                provider => provider.GetRequiredService<ServiceAuthoritativeStateBoundary>());
            services.AddSingleton<IAuthoritativeStateStore>(
                provider => provider.GetRequiredService<ServiceAuthoritativeStateBoundary>());
            services.AddSingleton<IServiceAuthoritativeStateInitializer>(
                provider => provider.GetRequiredService<ServiceAuthoritativeStateBoundary>());
            services.AddSingleton<IPolicyReconciler, BoundaryOnlyPolicyReconciler>();
            services.AddSingleton<IServiceProxyIdentityProvider, NoProxyIdentityProvider>();

            services.AddSingleton<ISetupSecretGenerator, CryptographicSetupSecretGenerator>();
            services.AddSingleton<ISetupSecretHasher, Sha256SetupSecretHasher>();
            services.AddSingleton<EcdsaP256SignatureVerifier>();
            services.AddSingleton<IParentTrustAnchorValidator>(
                provider => provider.GetRequiredService<EcdsaP256SignatureVerifier>());
            services.AddSingleton<
                WindowsLocalAccountSecurityFactsProvider>();
            services.AddSingleton<ILocalAccountSecurityFactsProvider>(
                provider => provider.GetRequiredService<
                    WindowsLocalAccountSecurityFactsProvider>());
            services.AddSingleton<
                IWindowsEditionFactsSource,
                NativeWindowsEditionFactsSource>();
            services.AddSingleton<
                ISecureBootStateSource,
                RegistrySecureBootStateSource>();
            services.AddSingleton<
                IWindowsSeparateLocalAdministratorSource,
                NativeWindowsSeparateLocalAdministratorSource>();
            services.AddSingleton<IManagedChildAccountValidator, ManagedChildAccountValidator>();
            services.AddSingleton<SetupCeremony>();
            services.AddSingleton<SetupCoordinator>();
            services.AddSingleton<ChildAccountBindingCoordinator>();
            services.AddSingleton<IServiceUtcClock, SystemServiceUtcClock>();
            services.AddSingleton<IServiceHealthQuery, UnobservedServiceHealthQuery>();
            services.AddSingleton(provider => new GuardServiceHealthInspector(
                provider.GetRequiredService<IServiceHealthQuery>(),
                GuardServiceIdentity.ServiceName,
                GuardServiceIdentity.ExpectedBinaryPath));
            services.AddSingleton<
                IDeviceReadinessFactsProvider,
                ProductionReadinessFactsProvider>();
            services.AddSingleton<GuardReadinessCoordinator>();
            services.AddSingleton<IGuardIpcOperationHandler, GuardServiceIpcOperationHandler>();
            services.AddSingleton<SecureIpcRequestDispatcher>();
            services.AddSingleton<IpcConnectionLimiter>();
            services.AddSingleton<IPipeClientTokenFactsResolver, NamedPipeClientTokenFactsResolver>();
            services.AddSingleton<WindowsNamedPipeFactory>();
            services.AddSingleton<GuardPipeConnectionProcessor>();
            services.AddSingleton<IServicePipeEndpointHostFactory, WindowsServicePipeEndpointHostFactory>();
            services.AddSingleton<ServicePipeSupervisor>();
            services.AddSingleton<IServicePipeSupervisor>(
                provider => provider.GetRequiredService<ServicePipeSupervisor>());
            services.AddSingleton<IServiceBoundaryInitializer, ServiceBoundaryInitializer>();
        }
    }
}
