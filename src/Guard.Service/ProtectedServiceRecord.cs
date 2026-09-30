using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Guard.Storage;

namespace Guard.Service;

// Reused by the two immutable bootstrap records. Caller holds the service's authoritative writer lease.
internal sealed class ProtectedServiceRecord(string path, string pendingPath, IStateDataProtector protector,
    IServiceDataBoundaryGuard boundary, int maximumPlaintextBytes, int maximumFileBytes)
{
    internal byte[] Read()
    {
        boundary.DemandReady();
        if (File.Exists(pendingPath)) throw new InvalidDataException("Interrupted protected record publication requires recovery.");
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length < 1 || file.Length > maximumFileBytes) throw new InvalidDataException("Protected record size.");
        var ciphertext = new byte[(int)file.Length];
        file.ReadExactly(ciphertext);
        if (file.ReadByte() != -1) throw new InvalidDataException("Protected record changed while reading.");
        var plaintext = protector.Unprotect(ciphertext);
        try
        {
            if (plaintext.Length < 1 || plaintext.Length > maximumPlaintextBytes) throw new InvalidDataException("Protected plaintext size.");
            boundary.DemandReady();
            return plaintext;
        }
        catch { CryptographicOperations.ZeroMemory(plaintext); throw; }
    }

    internal async Task PublishNewAsync(byte[] plaintext, CancellationToken cancellationToken)
    {
        if (plaintext.Length < 1 || plaintext.Length > maximumPlaintextBytes) throw new InvalidDataException("Protected plaintext size.");
        cancellationToken.ThrowIfCancellationRequested();
        boundary.DemandReady();
        if (File.Exists(path) || File.Exists(pendingPath)) throw new InvalidOperationException("Protected record already exists or needs recovery.");
        byte[] ciphertext;
        // Both callers hand over an owned buffer; do not retain plaintext across asynchronous disk I/O.
        try { ciphertext = protector.Protect(plaintext); }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
        if (ciphertext.Length < 1 || ciphertext.Length > maximumFileBytes) throw new InvalidDataException("Protected record size.");
        var ownsPending = false;
        try
        {
            await using (var pending = new FileStream(pendingPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                4096, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                ownsPending = true;
                await pending.WriteAsync(ciphertext, cancellationToken).ConfigureAwait(false);
                await pending.FlushAsync(cancellationToken).ConfigureAwait(false);
                pending.Flush(flushToDisk: true);
            }
            cancellationToken.ThrowIfCancellationRequested();
            boundary.DemandReady();
            cancellationToken.ThrowIfCancellationRequested();
            File.Move(pendingPath, path, overwrite: false);
            ownsPending = false;
        }
        finally { if (ownsPending) File.Delete(pendingPath); }
    }
}
