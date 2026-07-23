using System;
using System.Globalization;

namespace Guard.Domain.Policy
{
    public enum SecureInstallRoot
    {
        ProgramFiles64 = 1,
        ProgramFiles32 = 2,
        WindowsApps = 3,
        WindowsSystem = 4
    }

    public enum ApplicationIdentityKind
    {
        SignedPublisherProduct = 1,
        FileSha256 = 2,
        PackageFamily = 3
    }

    public sealed class ApplicationIdentity : IEquatable<ApplicationIdentity>
    {
        private const int MaximumTextLength = 256;
        private const int MinimumPackageNameLength = 3;
        private const int MaximumPackageNameLength = 50;
        private const int PackagePublisherIdLength = 13;
        private readonly string? _publisher;
        private readonly string? _product;
        private readonly SecureInstallRoot? _secureInstallRoot;
        private readonly string? _fileSha256;
        private readonly string? _packageFamilyName;

        public ApplicationIdentity(
            string? publisher,
            string? product,
            SecureInstallRoot? secureInstallRoot,
            string? fileSha256)
            : this(publisher, product, secureInstallRoot, fileSha256, null)
        {
        }

        public ApplicationIdentity(
            string? publisher,
            string? product,
            SecureInstallRoot? secureInstallRoot,
            string? fileSha256,
            string? packageFamilyName)
        {
            _publisher = NormalizeOptionalText(publisher, nameof(publisher));
            _product = NormalizeOptionalText(product, nameof(product));
            _secureInstallRoot = secureInstallRoot;
            _fileSha256 = NormalizeOptionalSha256(fileSha256, nameof(fileSha256));
            _packageFamilyName = NormalizeOptionalPackageFamilyName(packageFamilyName, nameof(packageFamilyName));

            var signedParts = (_publisher != null ? 1 : 0) +
                              (_product != null ? 1 : 0) +
                              (_secureInstallRoot.HasValue ? 1 : 0);
            if (signedParts != 0 && signedParts != 3)
            {
                throw new ArgumentException("Signed provenance requires publisher, product, and secure root together.");
            }

            if (_secureInstallRoot.HasValue &&
                !Enum.IsDefined(typeof(SecureInstallRoot), _secureInstallRoot.Value))
            {
                throw new ArgumentOutOfRangeException(nameof(secureInstallRoot));
            }

            var modeCount = (signedParts == 3 ? 1 : 0) +
                            (_fileSha256 != null ? 1 : 0) +
                            (_packageFamilyName != null ? 1 : 0);
            if (modeCount != 1)
            {
                throw new ArgumentException("Exactly one application identity mode is required.");
            }

            Kind = signedParts == 3
                ? ApplicationIdentityKind.SignedPublisherProduct
                : _fileSha256 != null
                    ? ApplicationIdentityKind.FileSha256
                    : ApplicationIdentityKind.PackageFamily;
        }

        public string? Publisher => _publisher;

        public string? Product => _product;

        public SecureInstallRoot? SecureInstallRoot => _secureInstallRoot;

        public string? FileSha256 => _fileSha256;

        public string? PackageFamilyName => _packageFamilyName;

        public ApplicationIdentityKind Kind { get; }

        public bool HasSignedPublisherIdentity => Kind == ApplicationIdentityKind.SignedPublisherProduct;

        public bool HasFileHashFallback => Kind == ApplicationIdentityKind.FileSha256;

        public bool HasPackageFamilyIdentity => Kind == ApplicationIdentityKind.PackageFamily;

        public bool IsExecutableGrantIdentity => HasFileHashFallback || HasPackageFamilyIdentity;

        public string AuthorizationKey
        {
            get
            {
                if (HasSignedPublisherIdentity)
                {
                    return "signed:" +
                           EncodeAuthorizationPart(_publisher!) +
                           EncodeAuthorizationPart(_product!) +
                           EncodeAuthorizationPart(((int)_secureInstallRoot!.Value).ToString(CultureInfo.InvariantCulture));
                }

                if (HasFileHashFallback)
                {
                    return "sha256:" + _fileSha256;
                }

                return "package-family:" + EncodeAuthorizationPart(_packageFamilyName!);
            }
        }

        public static ApplicationIdentity ForPackageFamily(string packageFamilyName)
        {
            return new ApplicationIdentity(null, null, null, null, packageFamilyName);
        }

        public bool MatchesExactIdentity(ApplicationIdentity? candidate)
        {
            return candidate != null &&
                   string.Equals(AuthorizationKey, candidate.AuthorizationKey, StringComparison.Ordinal);
        }

        // Kept for source compatibility. This compares domain identities only; enforcement
        // grants must separately require IsExecutableGrantIdentity.
        public bool Authorizes(ApplicationIdentity candidate)
        {
            return MatchesExactIdentity(candidate);
        }

        public bool Equals(ApplicationIdentity? other)
        {
            return MatchesExactIdentity(other);
        }

        public override bool Equals(object? obj) => Equals(obj as ApplicationIdentity);

        public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(AuthorizationKey);

        internal static string NormalizeSha256(string value, string parameterName)
        {
            var normalized = NormalizeOptionalSha256(value, parameterName);
            if (normalized == null)
            {
                throw new ArgumentNullException(parameterName);
            }

            return normalized;
        }

        private static string EncodeAuthorizationPart(string value)
        {
            return value.Length.ToString(CultureInfo.InvariantCulture) + ":" + value;
        }

        private static string? NormalizeOptionalText(string? value, string parameterName)
        {
            if (value == null)
            {
                return null;
            }

            value = value.Trim();
            if (value.Length == 0 || value.Length > MaximumTextLength || ContainsControlCharacter(value))
            {
                throw new ArgumentException("Identity text must be non-blank, bounded, and free of control characters.", parameterName);
            }

            return value;
        }

        private static string? NormalizeOptionalSha256(string? value, string parameterName)
        {
            if (value == null)
            {
                return null;
            }

            value = value.Trim();
            if (value.Length != 64)
            {
                throw new ArgumentException("A SHA-256 value must contain exactly 64 hexadecimal characters.", parameterName);
            }

            for (var index = 0; index < value.Length; index++)
            {
                var character = value[index];
                if (!IsAsciiHex(character))
                {
                    throw new ArgumentException("A SHA-256 value must be hexadecimal.", parameterName);
                }
            }

            return value.ToUpperInvariant();
        }

        private static string? NormalizeOptionalPackageFamilyName(string? value, string parameterName)
        {
            if (value == null)
            {
                return null;
            }

            value = value.Trim();
            if (value.Length < MinimumPackageNameLength + 1 + PackagePublisherIdLength ||
                value.Length > MaximumPackageNameLength + 1 + PackagePublisherIdLength ||
                ContainsControlCharacter(value))
            {
                throw new ArgumentException("A package family name must be non-blank and bounded.", parameterName);
            }

            var separator = value.IndexOf('_');
            if (separator < MinimumPackageNameLength ||
                separator > MaximumPackageNameLength ||
                value.Length - separator - 1 != PackagePublisherIdLength ||
                value.IndexOf('_', separator + 1) >= 0)
            {
                throw new ArgumentException("A package family name must contain a bounded name and a 13-character publisher id.", parameterName);
            }

            if (!IsAsciiLetterOrDigit(value[0]) ||
                !IsAsciiLetterOrDigit(value[separator - 1]))
            {
                throw new ArgumentException("A package name must start and end with an alphanumeric character.", parameterName);
            }

            for (var index = 0; index < value.Length; index++)
            {
                var character = value[index];
                if (index == separator)
                {
                    continue;
                }

                var isNameCharacter = IsAsciiLetterOrDigit(character) ||
                                      (index < separator && (character == '.' || character == '-'));
                if (!isNameCharacter)
                {
                    throw new ArgumentException("The package family name contains an invalid character.", parameterName);
                }
            }

            return value.ToUpperInvariant();
        }

        private static bool ContainsControlCharacter(string value)
        {
            for (var index = 0; index < value.Length; index++)
            {
                if (char.IsControl(value[index]))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool IsAsciiHex(char character)
        {
            return (character >= '0' && character <= '9') ||
                   (character >= 'a' && character <= 'f') ||
                   (character >= 'A' && character <= 'F');
        }

        private static bool IsAsciiLetterOrDigit(char character)
        {
            return (character >= '0' && character <= '9') ||
                   (character >= 'a' && character <= 'z') ||
                   (character >= 'A' && character <= 'Z');
        }
    }
}
