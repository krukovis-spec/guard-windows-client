using System;
using System.Net;

namespace Guard.Windows.BrowserPolicy
{
    public enum ManagedBrowserKind
    {
        Unknown = 0,
        MicrosoftEdge = 1,
        GoogleChrome = 2
    }

    public sealed class TrustedLoopbackProxyEndpoint
    {
        public TrustedLoopbackProxyEndpoint(string endpoint)
        {
            if (string.IsNullOrWhiteSpace(endpoint) ||
                !Uri.TryCreate(endpoint, UriKind.Absolute, out var parsed) ||
                !string.Equals(parsed.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) ||
                !IPAddress.TryParse(parsed.Host, out var address) ||
                !IPAddress.IsLoopback(address) ||
                parsed.Port < 1 ||
                parsed.Port > 65535 ||
                !string.IsNullOrEmpty(parsed.UserInfo) ||
                !string.IsNullOrEmpty(parsed.Query) ||
                !string.IsNullOrEmpty(parsed.Fragment) ||
                !IsRootPath(parsed.AbsolutePath))
            {
                throw new ArgumentException("A canonical HTTP loopback proxy endpoint is required.", nameof(endpoint));
            }

            Endpoint = parsed.GetComponents(UriComponents.SchemeAndServer, UriFormat.UriEscaped);
        }

        public string Endpoint { get; }

        private static bool IsRootPath(string path)
        {
            return string.IsNullOrEmpty(path) || string.Equals(path, "/", StringComparison.Ordinal);
        }
    }

    public sealed class ForceInstalledExtension
    {
        public ForceInstalledExtension(string extensionId, string updateUrl)
        {
            if (!IsExtensionId(extensionId))
            {
                throw new ArgumentException("A canonical 32-character Chromium extension id is required.", nameof(extensionId));
            }

            if (string.IsNullOrWhiteSpace(updateUrl) ||
                !string.Equals(updateUrl, updateUrl.Trim(), StringComparison.Ordinal) ||
                !Uri.TryCreate(updateUrl, UriKind.Absolute, out var parsed) ||
                !string.Equals(parsed.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
                !string.IsNullOrEmpty(parsed.UserInfo) ||
                !string.IsNullOrEmpty(parsed.Query) ||
                !string.IsNullOrEmpty(parsed.Fragment) ||
                IsRootPath(parsed.AbsolutePath))
            {
                throw new ArgumentException("An exact HTTPS extension update URL with a path is required.", nameof(updateUrl));
            }

            ExtensionId = extensionId;
            UpdateUrl = parsed.GetComponents(
                UriComponents.SchemeAndServer | UriComponents.Path,
                UriFormat.UriEscaped);
        }

        public string ExtensionId { get; }

        public string UpdateUrl { get; }

        private static bool IsExtensionId(string value)
        {
            if (value == null || value.Length != 32)
            {
                return false;
            }

            for (var index = 0; index < value.Length; index++)
            {
                if (value[index] < 'a' || value[index] > 'p')
                {
                    return false;
                }
            }

            return true;
        }

        private static bool IsRootPath(string path)
        {
            return string.IsNullOrEmpty(path) || string.Equals(path, "/", StringComparison.Ordinal);
        }
    }
}
