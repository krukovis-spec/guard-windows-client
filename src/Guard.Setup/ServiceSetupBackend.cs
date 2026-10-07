using Guard.Windows.Cryptography;
using Guard.Windows.Ipc;

namespace Guard.Setup;

internal sealed class ServiceSetupBackend : ISetupBackend
{
    public Task<SetupInspection> InspectAsync(CancellationToken token) => SetupInspection.ReadAsync(token);
    public Task<NativeSetupSession> BeginAsync(CancellationToken token) => NativeSetupSession.BeginAsync(token);
    public Task<DeviceProvisioningDescriptor> DescriptorAsync(CancellationToken token) => SetupInspection.ReadDescriptorAsync(token);
    public Task<NativeActivationConfirmation> ActivationAsync(CancellationToken token) => SetupInspection.ReadActivationConfirmationAsync(token);
}
