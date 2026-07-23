using System;
using System.ComponentModel;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Guard.Application;
using Guard.Contracts;
using Guard.Domain;
using Guard.Protocol;
using Guard.Windows.Ipc;

namespace Guard.Windows.Ipc.Tests
{
    internal static class Program
    {
        private static int Main()
        {
            var tests = new List<(string Name, Action Run)>
            {
                ("builds protected least-privilege pipe descriptors", BuildsLeastPrivilegeDescriptors),
                ("rejects broad or privileged child and proxy principals", RejectsPrivilegedEndpointSids),
                ("binds each canonical pipe name to one role", BindsPipeNameToRole),
                ("requires elevated high-integrity admin token facts", RequiresElevatedAdmin),
                ("requires exact non-elevated child and proxy identity", RequiresExactLowPrivilegeIdentity),
                ("rejects remote token facts for every endpoint", RejectsRemoteClients),
                ("authenticates the client token before reading a frame", AuthenticatesBeforeFrameRead),
                ("processes one bounded request and correlated response", ProcessesOneRequest),
                ("contains client token query failures before frame read", ContainsTokenQueryFailure),
                ("contains a client disconnect during response write", ContainsResponseDisconnect)
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

            Console.WriteLine(failures == 0
                ? "All Guard Windows IPC checks passed."
                : failures + " Guard Windows IPC check(s) failed.");
            return failures == 0 ? 0 : 1;
        }

        private static void BuildsLeastPrivilegeDescriptors()
        {
            var child = CreateChildProfile();
            var sddl = NamedPipeSecurityDescriptorFactory.CreateSddl(child);
            Assert(sddl.StartsWith("O:SYG:SYD:P", StringComparison.Ordinal), "Pipe DACL inheritance was not protected.");
            Assert(sddl.Contains("(A;;GA;;;SY)", StringComparison.Ordinal), "SYSTEM full control was missing.");
            Assert(sddl.Contains(child.AuthorizedSid.Value, StringComparison.Ordinal), "Exact child SID was missing.");
            Assert(!sddl.Contains("GRGW", StringComparison.Ordinal), "GENERIC_WRITE would allow creating a competing pipe instance.");
            Assert(!sddl.Contains(";;;WD)", StringComparison.Ordinal), "Everyone was authorized.");
            Assert(!sddl.Contains(";;;AU)", StringComparison.Ordinal), "Authenticated Users was authorized.");
            Assert(!sddl.Contains(";;;BU)", StringComparison.Ordinal), "BUILTIN Users was authorized.");

            var descriptor = new RawSecurityDescriptor(sddl);
            Assert(descriptor.DiscretionaryAcl != null, "Pipe DACL was absent.");
            var childAce = FindAce(descriptor.DiscretionaryAcl!, child.AuthorizedSid.Value);
            Assert(childAce != null, "Exact child ACE was absent.");
            Assert(
                (childAce!.AccessMask & 0x00000004) == 0,
                "Child ACE granted FILE_CREATE_PIPE_INSTANCE.");
        }

        private static void RejectsPrivilegedEndpointSids()
        {
            AssertThrows(() => NamedPipeSecurityDescriptorFactory.CreateSddl(
                new GuardPipeSecurityProfile(
                    "Guard.V2.Child.v1",
                    ClientRole.Child,
                    PipeClientAuthorizationKind.ExactAccountSid,
                    new WindowsAccountSid("S-1-5-18"))));
            AssertThrows(() => NamedPipeSecurityDescriptorFactory.CreateSddl(
                new GuardPipeSecurityProfile(
                    "Guard.V2.Proxy.v1",
                    ClientRole.Proxy,
                    PipeClientAuthorizationKind.ExactAccountSid,
                    new WindowsAccountSid("S-1-5-32-544"))));
            AssertThrows(() => NamedPipeSecurityDescriptorFactory.CreateSddl(
                new GuardPipeSecurityProfile(
                    "Guard.V2.Child.v1",
                    ClientRole.Child,
                    PipeClientAuthorizationKind.ExactAccountSid,
                    new WindowsAccountSid("S-1-1-0"))));
            AssertThrows(() => NamedPipeSecurityDescriptorFactory.CreateSddl(
                new GuardPipeSecurityProfile(
                    "Guard.V2.Child.v1",
                    ClientRole.Child,
                    PipeClientAuthorizationKind.ExactAccountSid,
                    new WindowsAccountSid("S-1-5-11"))));
        }

        private static void BindsPipeNameToRole()
        {
            AssertThrowsArgument(() => new GuardPipeSecurityProfile(
                "Guard.V2.AdminSetup.v1",
                ClientRole.Child,
                PipeClientAuthorizationKind.ExactAccountSid,
                new WindowsAccountSid("S-1-5-21-1001-2002-3003-1004")));
            AssertThrowsArgument(() => new GuardPipeSecurityProfile(
                "Guard.V2.Child.v1",
                ClientRole.AdminSetup,
                PipeClientAuthorizationKind.BuiltinAdministrators,
                new WindowsAccountSid("S-1-5-32-544")));
        }

        private static void RequiresElevatedAdmin()
        {
            var profile = CreateAdminProfile();
            Assert(!PipeClientAuthenticationPolicy.IsAuthorized(
                profile,
                Facts("S-1-5-21-1-2-3-1001", new[] { "S-1-5-32-544" }, false, 0x2000)),
                "Unelevated admin token was accepted.");
            Assert(!PipeClientAuthenticationPolicy.IsAuthorized(
                profile,
                Facts("S-1-5-21-1-2-3-1001", new[] { "S-1-5-32-544" }, true, 0x2000)),
                "Medium-integrity admin token was accepted.");
            Assert(PipeClientAuthenticationPolicy.IsAuthorized(
                profile,
                Facts("S-1-5-21-1-2-3-1001", new[] { "S-1-5-32-544" }, true, 0x3000)),
                "Elevated high-integrity admin token was rejected.");
        }

        private static void RequiresExactLowPrivilegeIdentity()
        {
            var profile = CreateChildProfile();
            Assert(PipeClientAuthenticationPolicy.IsAuthorized(
                profile,
                Facts(profile.AuthorizedSid.Value, Array.Empty<string>(), false, 0x2000)),
                "Exact standard child token was rejected.");
            Assert(!PipeClientAuthenticationPolicy.IsAuthorized(
                profile,
                Facts("S-1-5-21-1-2-3-1002", Array.Empty<string>(), false, 0x2000)),
                "Different child SID was accepted.");
            Assert(!PipeClientAuthenticationPolicy.IsAuthorized(
                profile,
                Facts(profile.AuthorizedSid.Value, new[] { "S-1-5-32-544" }, true, 0x3000)),
                "Elevated child token was accepted.");
            Assert(!PipeClientAuthenticationPolicy.IsAuthorized(
                profile,
                Facts(profile.AuthorizedSid.Value, Array.Empty<string>(), false, 0)),
                "A child token with an unknown integrity level was accepted.");
            Assert(!PipeClientAuthenticationPolicy.IsAuthorized(
                profile,
                Facts(profile.AuthorizedSid.Value, Array.Empty<string>(), false, 0x3000)),
                "A high-integrity child token was accepted.");
            Assert(!PipeClientAuthenticationPolicy.IsAuthorized(
                profile,
                Facts(profile.AuthorizedSid.Value, Array.Empty<string>(), false, 0x4000)),
                "A system-integrity child token was accepted.");
        }

        private static void RejectsRemoteClients()
        {
            var profile = CreateAdminProfile();
            Assert(!PipeClientAuthenticationPolicy.IsAuthorized(
                profile,
                new PipeClientTokenFacts(
                    "S-1-5-21-1-2-3-1001",
                    new[] { "S-1-5-32-544" },
                    isElevated: true,
                    integrityLevelRid: 0x3000,
                    isRemote: true)),
                "Remote admin token facts were accepted.");
        }

        private static void AuthenticatesBeforeFrameRead()
        {
            var stream = new TrackingMemoryStream(Array.Empty<byte>());
            var processor = CreateProcessor(
                new FixedFactsResolver(Facts(
                    "S-1-5-21-1001-2002-3003-1005",
                    Array.Empty<string>(),
                    elevated: false,
                    integrity: 0x2000)));
            var processed = processor
                .ProcessOneAsync(CreateChildProfile(), stream, CancellationToken.None)
                .GetAwaiter()
                .GetResult();
            Assert(!processed, "Unauthorized pipe client was processed.");
            Assert(stream.ReadCount == 0, "Frame bytes were read before client-token authorization.");
        }

        private static void ProcessesOneRequest()
        {
            var request = new GuardIpcRequest(
                GuardProtocol.CurrentVersion,
                Guid.NewGuid().ToString("D"),
                GuardVerb.GetStatus,
                Array.Empty<byte>());
            var input = IpcFrameCodec.Encode(request);
            var stream = new TrackingMemoryStream(input);
            var profile = CreateChildProfile();
            var processor = CreateProcessor(
                new FixedFactsResolver(Facts(
                    profile.AuthorizedSid.Value,
                    Array.Empty<string>(),
                    elevated: false,
                    integrity: 0x2000)));
            var processed = processor
                .ProcessOneAsync(profile, stream, CancellationToken.None)
                .GetAwaiter()
                .GetResult();
            Assert(processed, "Authorized request was not processed.");
            var combined = stream.ToArray();
            var responseFrame = new byte[combined.Length - input.Length];
            Array.Copy(combined, input.Length, responseFrame, 0, responseFrame.Length);
            var response = IpcResponseFrameCodec.Decode(responseFrame);
            Assert(response.RequestId == request.RequestId, "Response lost request correlation.");
            Assert(response.Status == GuardIpcResponseStatus.Success, "Authorized status request failed.");
        }

        private static void ContainsTokenQueryFailure()
        {
            var stream = new TrackingMemoryStream(Array.Empty<byte>());
            var processor = CreateProcessor(new FailingFactsResolver());
            var processed = processor
                .ProcessOneAsync(CreateChildProfile(), stream, CancellationToken.None)
                .GetAwaiter()
                .GetResult();
            Assert(!processed, "A failed token query was treated as an authorized request.");
            Assert(stream.ReadCount == 0, "Frame bytes were read after token-query failure.");
        }

        private static void ContainsResponseDisconnect()
        {
            var request = new GuardIpcRequest(
                GuardProtocol.CurrentVersion,
                Guid.NewGuid().ToString("D"),
                GuardVerb.GetStatus,
                Array.Empty<byte>());
            var stream = new FailingResponseStream(IpcFrameCodec.Encode(request));
            var profile = CreateChildProfile();
            var processor = CreateProcessor(
                new FixedFactsResolver(Facts(
                    profile.AuthorizedSid.Value,
                    Array.Empty<string>(),
                    elevated: false,
                    integrity: 0x2000)));
            var processed = processor
                .ProcessOneAsync(profile, stream, CancellationToken.None)
                .GetAwaiter()
                .GetResult();
            Assert(!processed, "A disconnected client was reported as successfully served.");
        }

        private static GuardPipeConnectionProcessor CreateProcessor(
            IPipeClientTokenFactsResolver resolver)
        {
            return new GuardPipeConnectionProcessor(
                resolver,
                new IpcConnectionLimiter(),
                new SecureIpcRequestDispatcher(new SuccessHandler()));
        }

        private static GuardPipeSecurityProfile CreateAdminProfile()
        {
            return new GuardPipeSecurityProfile(
                "Guard.V2.AdminSetup.v1",
                ClientRole.AdminSetup,
                PipeClientAuthorizationKind.BuiltinAdministrators,
                new WindowsAccountSid("S-1-5-32-544"));
        }

        private static GuardPipeSecurityProfile CreateChildProfile()
        {
            return new GuardPipeSecurityProfile(
                "Guard.V2.Child.v1",
                ClientRole.Child,
                PipeClientAuthorizationKind.ExactAccountSid,
                new WindowsAccountSid("S-1-5-21-1001-2002-3003-1004"));
        }

        private static PipeClientTokenFacts Facts(
            string userSid,
            IEnumerable<string> groups,
            bool elevated,
            int integrity)
        {
            return new PipeClientTokenFacts(userSid, groups, elevated, integrity, isRemote: false);
        }

        private static void AssertThrows(Action action)
        {
            try
            {
                action();
            }
            catch (InvalidOperationException)
            {
                return;
            }

            throw new InvalidOperationException("Expected endpoint security rejection.");
        }

        private static void AssertThrowsArgument(Action action)
        {
            try
            {
                action();
            }
            catch (ArgumentException)
            {
                return;
            }

            throw new InvalidOperationException("Expected invalid endpoint profile rejection.");
        }

        private static KnownAce? FindAce(
            RawAcl acl,
            string expectedSid)
        {
            foreach (GenericAce ace in acl)
            {
                var knownAce = ace as KnownAce;
                if (knownAce != null &&
                    string.Equals(
                        knownAce.SecurityIdentifier.Value,
                        expectedSid,
                        StringComparison.Ordinal))
                {
                    return knownAce;
                }
            }

            return null;
        }

        private static void Assert(bool condition, string message)
        {
            if (!condition)
            {
                throw new InvalidOperationException(message);
            }
        }

        private sealed class FixedFactsResolver : IPipeClientTokenFactsResolver
        {
            private readonly PipeClientTokenFacts _facts;

            public FixedFactsResolver(PipeClientTokenFacts facts)
            {
                _facts = facts;
            }

            public PipeClientTokenFacts Resolve(Stream connectedPipe)
            {
                return _facts;
            }
        }

        private sealed class FailingFactsResolver : IPipeClientTokenFactsResolver
        {
            public PipeClientTokenFacts Resolve(Stream connectedPipe)
            {
                throw new Win32Exception(5);
            }
        }

        private sealed class SuccessHandler : IGuardIpcOperationHandler
        {
            public Task<GuardIpcResponse> HandleAsync(
                ClientRole authenticatedRole,
                GuardIpcRequest request,
                CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                return Task.FromResult(new GuardIpcResponse(
                    GuardProtocol.CurrentVersion,
                    request.RequestId,
                    GuardIpcResponseStatus.Success,
                    Array.Empty<byte>()));
            }
        }

        private sealed class TrackingMemoryStream : MemoryStream
        {
            public TrackingMemoryStream(byte[] input)
            {
                Write(input, 0, input.Length);
                Position = 0;
            }

            public int ReadCount { get; private set; }

            public override Task<int> ReadAsync(
                byte[] buffer,
                int offset,
                int count,
                CancellationToken cancellationToken)
            {
                ReadCount++;
                return base.ReadAsync(buffer, offset, count, cancellationToken);
            }
        }

        private sealed class FailingResponseStream : MemoryStream
        {
            public FailingResponseStream(byte[] input)
            {
                base.Write(input, 0, input.Length);
                Position = 0;
            }

            public override Task WriteAsync(
                byte[] buffer,
                int offset,
                int count,
                CancellationToken cancellationToken)
            {
                throw new IOException("Synthetic client disconnect.");
            }

            public override ValueTask WriteAsync(
                ReadOnlyMemory<byte> buffer,
                CancellationToken cancellationToken = default)
            {
                throw new IOException("Synthetic client disconnect.");
            }
        }
    }
}
