using Guard.Windows.Cryptography;
using Guard.Windows.Ipc;

namespace Guard.Setup;

// The production composition root always supplies the authenticated service backend.
// The separately compiled preview supplies only an in-memory peer; there is no runtime switch.
internal interface ISetupBackend
{
    Task<SetupInspection> InspectAsync(CancellationToken token);
    Task<NativeSetupSession> BeginAsync(CancellationToken token);
    Task<DeviceProvisioningDescriptor> DescriptorAsync(CancellationToken token);
    Task<NativeActivationConfirmation> ActivationAsync(CancellationToken token);
}
