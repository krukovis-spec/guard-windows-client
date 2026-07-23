using System;
using System.ComponentModel;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Guard.Application;
using Guard.Contracts;
using Guard.Protocol;

namespace Guard.Windows.Ipc
{
    public interface IPipeClientTokenFactsResolver
    {
        PipeClientTokenFacts Resolve(Stream connectedPipe);
    }

    public sealed class NamedPipeClientTokenFactsResolver :
        IPipeClientTokenFactsResolver
    {
        private readonly WindowsPipeClientTokenFactsResolver _resolver =
            new WindowsPipeClientTokenFactsResolver();

        public PipeClientTokenFacts Resolve(Stream connectedPipe)
        {
            var pipe = connectedPipe as System.IO.Pipes.NamedPipeServerStream;
            if (pipe == null)
            {
                throw new ArgumentException("A connected named-pipe server stream is required.", nameof(connectedPipe));
            }

            return _resolver.Resolve(pipe);
        }
    }

    public sealed class GuardPipeConnectionProcessor
    {
        private static readonly TimeSpan ReadTimeout =
            TimeSpan.FromMilliseconds(GuardProtocol.DefaultIpcReadTimeoutMilliseconds);

        private readonly IPipeClientTokenFactsResolver _factsResolver;
        private readonly IpcConnectionLimiter _connectionLimiter;
        private readonly SecureIpcRequestDispatcher _dispatcher;

        public GuardPipeConnectionProcessor(
            IPipeClientTokenFactsResolver factsResolver,
            IpcConnectionLimiter connectionLimiter,
            SecureIpcRequestDispatcher dispatcher)
        {
            _factsResolver = factsResolver ?? throw new ArgumentNullException(nameof(factsResolver));
            _connectionLimiter = connectionLimiter ?? throw new ArgumentNullException(nameof(connectionLimiter));
            _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
        }

        public async Task<bool> ProcessOneAsync(
            GuardPipeSecurityProfile profile,
            Stream connectedPipe,
            CancellationToken cancellationToken)
        {
            if (profile == null)
            {
                throw new ArgumentNullException(nameof(profile));
            }

            if (connectedPipe == null)
            {
                throw new ArgumentNullException(nameof(connectedPipe));
            }

            PipeClientTokenFacts facts;
            try
            {
                facts = _factsResolver.Resolve(connectedPipe);
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
            catch (InvalidOperationException)
            {
                return false;
            }
            catch (Win32Exception)
            {
                return false;
            }

            if (!PipeClientAuthenticationPolicy.IsAuthorized(profile, facts))
            {
                return false;
            }

            IDisposable? lease;
            if (!_connectionLimiter.TryAcquire(out lease) || lease == null)
            {
                return false;
            }

            using (lease)
            {
                GuardIpcRequest request;
                try
                {
                    request = await IpcFrameCodec
                        .DecodeAsync(connectedPipe, ReadTimeout, cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    return false;
                }
                catch (IOException)
                {
                    return false;
                }

                var response = await _dispatcher
                    .DispatchAsync(profile.Role, request, cancellationToken)
                    .ConfigureAwait(false);
                var frame = IpcResponseFrameCodec.Encode(response);
                try
                {
                    await connectedPipe.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
                    await connectedPipe.FlushAsync(cancellationToken).ConfigureAwait(false);
                    return true;
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    return false;
                }
                catch (IOException)
                {
                    return false;
                }
                catch (ObjectDisposedException)
                {
                    return false;
                }
            }
        }
    }
}
