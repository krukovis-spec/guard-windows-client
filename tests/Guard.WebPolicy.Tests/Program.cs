using System;
using System.Collections.Generic;
using System.Text;
using Guard.Domain;
using Guard.Domain.Policy;
using Guard.Domain.Web;

namespace Guard.WebPolicy.Tests
{
    internal static class Program
    {
        private const string Digest = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        private static readonly DateTimeOffset Now = new DateTimeOffset(2026, 7, 24, 12, 0, 0, TimeSpan.Zero);

        private static int Main()
        {
            var checks = new (string Name, Action Test)[]
            {
                ("canonicalizes safe IDN only", CanonicalizesIdn),
                ("rejects malformed and non-host identities", RejectsMalformedHosts),
                ("does not guess registrable domains", RequiresTrustedRegistrableEvidence),
                ("matches scopes at DNS label boundaries", MatchesOnlyAtLabelBoundaries),
                ("constrains scheme and port", ConstrainsEndpoint),
                ("requires a digest-bound signed bundle", RequiresTrustedBundle),
                ("uses a minimal YouTube-like service bundle", CompilesMinimalYoutubeLikeBundle),
                ("fails closed for expiry quota and stale usage", FailsClosedForTimeAndQuota),
                ("discovers only parent-approved candidates", CandidateDiscoveryNeverGrants)
            };
            try
            {
                foreach (var check in checks) check.Test();
                Console.WriteLine("TOTAL_PASS=" + checks.Length);
                return 0;
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine(exception);
                return 1;
            }
        }

        private static void CanonicalizesIdn()
        {
            var host = CanonicalDnsHost.Parse("BÜCHER.Example.");
            Equal("xn--bcher-kva.example", host.Value, "IDN was not canonical ASCII.");
        }

        private static void RejectsMalformedHosts()
        {
            foreach (var input in new[]
            {
                "https://example.com",
                "127.0.0.1",
                "[::1]",
                "user@example.com",
                "*.example.com",
                "example..com",
                "-bad.example",
                "example.com/path",
                "example.com:443",
                " example.com",
                "example.com ",
                "example.com..",
                new string('a', 63) + "." +
                    new string('b', 63) + "." +
                    new string('c', 63) + "." +
                    new string('d', 63)
            })
                Throws(() => CanonicalDnsHost.Parse(input), "Unsafe host was accepted: " + input);
        }

        private static void RequiresTrustedRegistrableEvidence()
        {
            Throws(() => RegistrableDomainEvidence.Resolve("a.example.co.uk", new Resolver("co.uk", "co.uk")), "Public suffix was accepted as a registrable domain.");
            Throws(() => RegistrableDomainEvidence.Resolve("evil-example.com", new Resolver("example.com", "com")), "Suffix confusion was accepted as registrable evidence.");
            var evidence = RegistrableDomainEvidence.Resolve("cdn.youtube.com", new Resolver("youtube.com", "com"));
            Equal("youtube.com", evidence.RegistrableDomain.Value, "Explicit trusted evidence changed.");
        }

        private static void MatchesOnlyAtLabelBoundaries()
        {
            var exact = WebScope.ExactHost("www.youtube.com");
            Assert(exact.Matches("www.youtube.com"), "Exact host did not match.");
            Assert(!exact.Matches("m.www.youtube.com"), "Exact scope widened to a subtree.");
            var tree = WebScope.RegistrableDomainSubtree(RegistrableDomainEvidence.Resolve("www.youtube.com", new Resolver("youtube.com", "com")));
            Assert(tree.Matches("i.youtube.com"), "Explicit subtree did not match child label.");
            Assert(!tree.Matches("notyoutube.com"), "Suffix confusion matched a subtree.");
            Assert(!tree.Matches("youtube.com.evil.example"), "Trailing lookalike matched a subtree.");
        }

        private static void ConstrainsEndpoint()
        {
            var endpoint = new WebEndpoint("HTTPS", "www.youtube.com", 443);
            Equal("https", endpoint.Scheme, "Endpoint scheme was not canonical.");
            var plainHttp = new WebEndpoint("HTTP", "example.com", 80);
            Equal("http", plainHttp.Scheme, "HTTP endpoint scheme was not canonical.");
            Throws(() => new WebEndpoint("http", "www.youtube.com", 443), "HTTP was accepted on the HTTPS port.");
            Throws(() => new WebEndpoint("https", "www.youtube.com", 80), "HTTPS was accepted on the HTTP port.");
            Throws(() => new WebEndpoint("https", "www.youtube.com", 8443), "Alternate port was accepted.");
        }

        private static void RequiresTrustedBundle()
        {
            var bundle = new WebServiceBundle("video-core", new[] { WebScope.ExactHost("www.youtube.com") });
            var valid = SignatureFor(bundle, true);
            var verifier = new CapturingVerifier(true);
            var verified = VerifyBundle(bundle, valid, verifier);
            Assert(verified.Bundle.Scopes.Count == 1, "Verified bundle changed its scope.");
            Assert(
                Encoding.UTF8.GetString(verifier.LastPayload!).StartsWith(
                    "guard.web-bundle.v2\ncatalog=catalog-1\ncatalogSequence=10\nbundleVersion=3\n",
                    StringComparison.Ordinal),
                "The catalog sequence and bundle version were not bound into the signed payload.");
            Assert(
                Encoding.UTF8.GetString(verifier.LastPayload!).Contains(
                    "\nsigningKeyId=release-key-1\n"),
                "The signing-key identifier was not bound into the signed payload.");
            var invalidDigest = SignatureFor(bundle, false);
            Throws(() => VerifyBundle(bundle, invalidDigest, new AlwaysVerifier(true)), "Incorrect digest was trusted.");
            Throws(() => VerifyBundle(bundle, valid, new AlwaysVerifier(false)), "Rejected signature was trusted.");
            Throws(
                () => VerifyBundle(
                    bundle,
                    SignatureFor(
                        bundle,
                        true,
                        signingKeyId: "replacement-key"),
                    new ExactPayloadVerifier(verifier.LastPayload!)),
                "A substituted signing-key identifier preserved signature validity.");
            Throws(() => VerifyBundle(bundle, valid, new AlwaysVerifier(true), 11), "A rolled-back catalog sequence was trusted.");
            Throws(
                () => VerifyBundle(
                    bundle,
                    SignatureFor(bundle, true, catalogId: "catalog-other"),
                    new AlwaysVerifier(true)),
                "A signed bundle from another catalog was trusted.");
            Throws(
                () => VerifyBundle(
                    bundle,
                    SignatureFor(bundle, true, bundleVersion: 2),
                    new AlwaysVerifier(true)),
                "A lower per-bundle version was replayed.");
            Throws(
                () => VerifiedWebServiceBundle.Verify(
                    bundle,
                    valid,
                    new AlwaysVerifier(true),
                    new WebBundleAcceptanceFloor(
                        valid.CatalogId,
                        bundle.BundleId,
                        valid.CatalogSequence,
                        valid.BundleVersion,
                        Digest),
                    new Version("2.0.0"),
                    Now),
                "A same-version bundle with a different accepted digest was replayed.");
            Throws(
                () => VerifiedWebServiceBundle.Verify(
                    bundle,
                    valid,
                    new AlwaysVerifier(true),
                    AcceptanceFor(bundle, valid),
                    new Version("1.9.9"),
                    Now),
                "A bundle requiring a newer Guard version was trusted.");
            Throws(
                () => VerifiedWebServiceBundle.Verify(
                    bundle,
                    valid,
                    new AlwaysVerifier(true),
                    AcceptanceFor(bundle, valid),
                    new Version("2.0.0"),
                    Now.AddDays(2)),
                "An expired bundle was trusted.");
            Throws(() => new WebServiceBundle("wide", new[] { WebScope.ExactHost("a.example.com"), WebScope.ExactHost("a.example.com") }), "Duplicate broadening scope was accepted.");
            Throws(() => new WebServiceBundle("wide\nbundle", new[] { WebScope.ExactHost("a.example.com") }), "An ambiguous bundle identifier was accepted.");
        }

        private static void CompilesMinimalYoutubeLikeBundle()
        {
            var manifest = new WebServiceBundle("youtube-essential", new[]
            {
                WebScope.ExactHost("www.youtube.com"),
                WebScope.ExactHost("accounts.google.com"),
                WebScope.ExactHost("i.ytimg.com")
            });
            var bundle = VerifyBundle(
                manifest,
                SignatureFor(manifest, true),
                new AlwaysVerifier(true));
            var plan = DefaultDenyWebPolicyCompiler.Compile(new[] { new WebAccessGrant("youtube-1", bundle, new ParentDecision(ParentDecisionKind.AlwaysAllow)) }, null, Now);
            Assert(plan.IsDefaultDeny && plan.Allows("www.youtube.com") && plan.Allows("accounts.google.com") && plan.Allows("i.ytimg.com"), "Essential bundle domains were not allowed.");
            Assert(!plan.Allows("evil.youtube.com") && !plan.Allows("google.com") && !plan.Allows("ytimg.com"), "Bundle allowed non-explicit third-party domains.");
            Assert(plan.NextReconcileAt == Now.AddDays(1), "Signed bundle expiry was not scheduled for reconciliation.");
            Assert(
                DefaultDenyWebPolicyCompiler.Compile(
                    new[] { new WebAccessGrant("youtube-1", bundle, new ParentDecision(ParentDecisionKind.AlwaysAllow)) },
                    null,
                    Now.AddDays(1)).AllowedGrants.Count == 0,
                "An expired signed bundle remained effective.");
        }

        private static void FailsClosedForTimeAndQuota()
        {
            var manifest = new WebServiceBundle("one", new[] { WebScope.ExactHost("www.youtube.com") });
            var verified = VerifyBundle(
                manifest,
                SignatureFor(manifest, true),
                new AlwaysVerifier(true));
            var temporary = new WebAccessGrant("temp", verified, new ParentDecision(ParentDecisionKind.TemporaryAllow, Now.AddMinutes(5)));
            var quota = new WebAccessGrant("quota", verified, new ParentDecision(ParentDecisionKind.DailyQuota, dailyQuotaMinutes: 10));
            var absent = DefaultDenyWebPolicyCompiler.Compile(new[] { temporary, quota }, null, Now);
            Assert(absent.AllowedGrants.Count == 1 && absent.NextReconcileAt == Now.AddMinutes(5), "Missing quota evidence did not fail closed.");
            var fresh = new TrustedDailyWebUsage("quota", 9, Now, Now.AddMinutes(1));
            var active = DefaultDenyWebPolicyCompiler.Compile(new[] { temporary, quota }, new[] { fresh }, Now);
            Assert(active.AllowedGrants.Count == 2 && active.NextReconcileAt == Now.AddMinutes(1), "Fresh quota did not schedule earliest reconciliation.");
            var exhausted = new TrustedDailyWebUsage("quota", 10, Now, Now.AddMinutes(1));
            Assert(DefaultDenyWebPolicyCompiler.Compile(new[] { quota }, new[] { exhausted }, Now).AllowedGrants.Count == 0, "Exhausted quota remained allowed.");
            var stale = new TrustedDailyWebUsage("quota", 1, Now.AddMinutes(-2), Now.AddMinutes(-1));
            Assert(DefaultDenyWebPolicyCompiler.Compile(new[] { quota }, new[] { stale }, Now).AllowedGrants.Count == 0, "Stale quota evidence remained allowed.");
            Assert(DefaultDenyWebPolicyCompiler.Compile(new[] { temporary }, null, Now.AddMinutes(5)).AllowedGrants.Count == 0, "Expired temporary grant remained allowed.");
        }

        private static void CandidateDiscoveryNeverGrants()
        {
            var untrusted = new UntrustedBrowserWebObservation("tracker.example");
            Throws(() => VerifiedWebConnection.Verify(untrusted, "binding", new AlwaysConnectionVerifier(false)), "Unverified browser host was accepted.");
            var connection = VerifiedWebConnection.Verify(untrusted, "binding", new AlwaysConnectionVerifier(true));
            var candidate = WebAccessCandidateDiscovery.Discover(connection);
            Assert(candidate.RequiresParentApproval && candidate.Host.Value == "tracker.example", "Candidate discovery produced an automatic grant.");
        }

        private static WebBundleSignature SignatureFor(
            WebServiceBundle bundle,
            bool trusted,
            string catalogId = "catalog-1",
            long bundleVersion = 3,
            string signingKeyId = "release-key-1")
        {
            var digest = bundle.CanonicalDigestSha256();
            return new WebBundleSignature(
                catalogId,
                10,
                bundleVersion,
                Now.AddDays(-1),
                Now.AddDays(1),
                "2.0.0",
                trusted ? digest : Digest,
                signingKeyId,
                new byte[] { 1, 2, 3 });
        }

        private static VerifiedWebServiceBundle VerifyBundle(
            WebServiceBundle bundle,
            WebBundleSignature signature,
            IWebBundleSignatureVerifier verifier,
            long minimumCatalogSequence = 10,
            long minimumBundleVersion = 3,
            string expectedCatalogId = "catalog-1")
        {
            return VerifiedWebServiceBundle.Verify(
                bundle,
                signature,
                verifier,
                new WebBundleAcceptanceFloor(
                    expectedCatalogId,
                    bundle.BundleId,
                    minimumCatalogSequence,
                    minimumBundleVersion,
                    bundle.CanonicalDigestSha256()),
                new Version("2.0.0"),
                Now);
        }

        private static WebBundleAcceptanceFloor AcceptanceFor(
            WebServiceBundle bundle,
            WebBundleSignature signature)
        {
            return new WebBundleAcceptanceFloor(
                signature.CatalogId,
                bundle.BundleId,
                signature.CatalogSequence,
                signature.BundleVersion,
                signature.DigestSha256);
        }

        private sealed class AlwaysVerifier : IWebBundleSignatureVerifier { private readonly bool _answer; public AlwaysVerifier(bool answer) { _answer = answer; } public bool Verify(string key, byte[] bytes, byte[] signature) => _answer; }
        private sealed class ExactPayloadVerifier : IWebBundleSignatureVerifier
        {
            private readonly byte[] _expected;

            public ExactPayloadVerifier(byte[] expected)
            {
                _expected = (byte[])expected.Clone();
            }

            public bool Verify(string key, byte[] bytes, byte[] signature)
            {
                if (bytes.Length != _expected.Length)
                {
                    return false;
                }

                var difference = 0;
                for (var index = 0; index < bytes.Length; index++)
                {
                    difference |= bytes[index] ^ _expected[index];
                }

                return difference == 0;
            }
        }

        private sealed class CapturingVerifier : IWebBundleSignatureVerifier
        {
            private readonly bool _answer;
            public CapturingVerifier(bool answer) { _answer = answer; }
            public byte[]? LastPayload { get; private set; }
            public bool Verify(string key, byte[] bytes, byte[] signature)
            {
                LastPayload = (byte[])bytes.Clone();
                return _answer;
            }
        }
        private sealed class AlwaysConnectionVerifier : IWebConnectionEvidenceVerifier { private readonly bool _answer; public AlwaysConnectionVerifier(bool answer) { _answer = answer; } public bool Verify(CanonicalDnsHost host, string binding) => _answer; }
        private sealed class Resolver : ITrustedRegistrableDomainResolver
        {
            private readonly string _registrable; private readonly string _suffix;
            public Resolver(string registrable, string suffix) { _registrable = registrable; _suffix = suffix; }
            public bool TryResolve(CanonicalDnsHost observedHost, out string registrableDomain, out string publicSuffix, out string resolverRevision)
            { registrableDomain = _registrable; publicSuffix = _suffix; resolverRevision = "psl-1"; return true; }
        }
        private static void Assert(bool value, string message) { if (!value) throw new InvalidOperationException(message); }
        private static void Equal<T>(T expected, T actual, string message) { if (!EqualityComparer<T>.Default.Equals(expected, actual)) throw new InvalidOperationException(message); }
        private static void Throws(Action action, string message) { try { action(); } catch (ArgumentException) { return; } catch (InvalidOperationException) { return; } throw new InvalidOperationException(message); }
    }
}
