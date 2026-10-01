using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Guard.Contracts;
using Guard.Domain;
using Guard.Provisioning;
using Guard.Windows.Cryptography;
using Guard.Windows.Ipc;

namespace Guard.Windows.Crypto.Tests;

internal static class ActivationConfirmationChecks
{
    internal static async Task RunAsync(GuardIpcResponse response, byte[] originalDescriptor, DeviceSecurityState owner, ECDsa signing, ECDiffieHellman phoneEncryption, DateTimeOffset now)
    {
        var raw = response.GetPayloadCopy();
        var descriptor = DeviceProvisioningDescriptor.Parse(originalDescriptor);
        var mailbox = owner.Enrollment!.Offer.MailboxId;
        var proof = NativeActivationConfirmation.Verify(raw, descriptor, mailbox, now);
        Check(proof.StateVersion == owner.Version && proof.Claim.ApprovalKeyId == owner.Enrollment.Candidate!.ApprovalKeyId &&
            proof.Offer.EnrollmentId == owner.Enrollment.Offer.EnrollmentId && proof.ExpiresAtUtc == now.AddMinutes(10), "wrong activation binding");
        var ui = await SetupInspection.ReadActivationConfirmationAsync((verb, _) => {
            Check(verb == GuardVerb.GetNativeActivationConfirmation, "wrong UI activation verb"); return Task.FromResult(response);
        }, new Clock(now), default);
        Check(ui.Sha256 == proof.Sha256, "UI changed signed export");
        raw[0] ^= 1; proof.GetBytesCopy()[0] ^= 1;
        Check(ui.GetBytesCopy().SequenceEqual(proof.GetBytesCopy()), "confirmation shared mutable bytes");
        raw = proof.GetBytesCopy();
        for (var size = 0; size < raw.Length; size++) Reject(() => NativeActivationConfirmation.Verify(raw[..size], descriptor, mailbox, now));
        for (var index = 0; index < raw.Length; index++)
        {
            var changed = (byte[])raw.Clone(); changed[index] ^= 1;
            Reject(() => NativeActivationConfirmation.Verify(changed, descriptor, mailbox, now));
        }
        foreach (var bad in new[] { raw.Concat(new byte[] { 0 }).ToArray(), new byte[NativeActivationConfirmation.MaximumBytes + 1] })
            Reject(() => NativeActivationConfirmation.Verify(bad, descriptor, mailbox, now));
        foreach (var time in new[] { now.AddMilliseconds(-1), proof.ExpiresAtUtc, proof.ExpiresAtUtc.AddDays(1) })
            Reject(() => NativeActivationConfirmation.Verify(raw, descriptor, mailbox, time));
        Reject(() => NativeActivationConfirmation.Verify(raw, descriptor, "different-mailbox-0001", now));
        foreach (var field in new[] { "deviceId", "relayOrigin", "signingPublicKeySpki" })
        {
            var different = JsonNode.Parse(originalDescriptor)!.AsObject();
            if (field == "signingPublicKeySpki")
            {
                using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                var anchor = new ParentTrustAnchor(ParentKeyAlgorithm.EcdsaP256Sha256, otherKey.ExportSubjectPublicKeyInfo());
                different["signingPublicKeySpki"] = Convert.ToBase64String(anchor.GetSubjectPublicKeyInfoCopy()); different["signingKeyId"] = anchor.KeyId;
            }
            else different[field] = field == "relayOrigin" ? "https://different.example.test" : "different-device-0001";
            var other = DeviceProvisioningDescriptor.Parse(JsonSerializer.SerializeToUtf8Bytes(different));
            Reject(() => NativeActivationConfirmation.Verify(raw, other, mailbox, now));
        }
        using (var wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256)) Reject(() => NativeActivationConfirmation.Create(owner, wrongKey, now));
        Reject(() => NativeActivationConfirmation.Create(new DeviceSecurityState(owner.DeviceId, 0, 0, 0), signing, now));
        Reject(() => NativeActivationConfirmation.Create(owner, signing, owner.Enrollment.Offer.CreatedAtUtc.AddMilliseconds(-1)));
        var end = owner.Enrollment.Offer.ExpiresAtUtc.AddDays(1);
        Reject(() => NativeActivationConfirmation.Create(owner, signing, end));
        Check(NativeActivationConfirmation.Create(owner, signing, end.AddSeconds(-30)).ExpiresAtUtc == end, "proof outlived enrollment retention");

        var root = Path.Combine(Path.GetTempPath(), "GuardActivationProofTests-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        try
        {
            var descriptorPath = Path.Combine(root, "device.json"); descriptor.SaveNew(descriptorPath);
            var proofPath = Path.Combine(root, "native.guard-proof"); proof.SaveNew(proofPath, now);
            Check(File.ReadAllBytes(proofPath).SequenceEqual(raw), "export did not preserve signature bytes");
            foreach (var path in new[] { proofPath, "relative.guard-proof", proofPath + ":stream", Path.Combine(root, "ambiguous. "), @"\\localhost\share\proof" })
                Reject(() => proof.SaveNew(path, now));
            Reject(() => proof.SaveNew(Path.Combine(root, "expired.guard-proof"), proof.ExpiresAtUtc));
            var job = Path.Combine(root, "computer.job");
            ProvisioningJob.Prepare(descriptor.RelayOrigin, descriptorPath, descriptor.Sha256, mailbox, now.AddDays(3), job, now);
            var savedJob = File.ReadAllBytes(job);
            var verified = ProvisioningJob.VerifyNativeConfirmation(descriptor.RelayOrigin, job, proofPath, now);
            Check(verified.Sha256 == proof.Sha256 && savedJob.SequenceEqual(File.ReadAllBytes(job)), "operator rewrote original device intent");
            Reject(() => ProvisioningJob.VerifyNativeConfirmation("https://different.example.test", job, proofPath, now));
            Reject(() => ProvisioningJob.VerifyNativeConfirmation(descriptor.RelayOrigin, job, proofPath, proof.ExpiresAtUtc));
            var otherJob = Path.Combine(root, "other-mailbox.job");
            ProvisioningJob.Prepare(descriptor.RelayOrigin, descriptorPath, descriptor.Sha256, "different-mailbox-0001", now.AddDays(3), otherJob, now);
            Reject(() => ProvisioningJob.VerifyNativeConfirmation(descriptor.RelayOrigin, otherJob, proofPath, now));
            Check(Directory.GetFiles(root).Length == 4, "refused proof export created an unexpected file");
            await NativeActivationJobChecks.RunAsync(root, descriptorPath, job, proofPath, owner, signing, phoneEncryption, now);
        }
        finally { Directory.Delete(root, recursive: true); }
    }
    private sealed class Clock(DateTimeOffset now) : TimeProvider { public override DateTimeOffset GetUtcNow() => now; }
    private static void Reject(Action action)
    {
        try { action(); }
        catch (Exception error) when (error is ArgumentException or FormatException or InvalidDataException or JsonException or CryptographicException or IOException or InvalidOperationException
            or PlatformNotSupportedException { InnerException: CryptographicException }) { return; }
        throw new InvalidOperationException("Invalid native activation proof accepted.");
    }
    private static void Check(bool value, string message) { if (!value) throw new InvalidOperationException(message); }
}
