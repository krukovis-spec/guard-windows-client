using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;

namespace Guard.Windows.BrowserPolicy
{
    public sealed class ManagedBrowserPolicyPlan
    {
        private ManagedBrowserPolicyPlan(
            ManagedBrowserKind browser,
            TrustedLoopbackProxyEndpoint proxyEndpoint,
            ForceInstalledExtension forceInstalledExtension)
        {
            Browser = browser;
            ProxyEndpoint = proxyEndpoint ?? throw new ArgumentNullException(nameof(proxyEndpoint));
            ForceInstalledExtension = forceInstalledExtension ?? throw new ArgumentNullException(nameof(forceInstalledExtension));
            MachinePolicies = BuildMachinePolicies();
            PolicyDigestSha256 = ComputeDigest();
        }

        public ManagedBrowserKind Browser { get; }

        public TrustedLoopbackProxyEndpoint ProxyEndpoint { get; }

        public ForceInstalledExtension ForceInstalledExtension { get; }

        public IReadOnlyList<ManagedBrowserPolicySetting> MachinePolicies
        {
            get;
        }

        public bool IsMachineManagedProxyOnly => true;

        public bool IsProxyAutoDetectDisabled => true;

        public bool IsProxyPacDisabled => true;

        public bool HasNoProxyBypassRules => true;

        public bool HasNoProxyOverrideRules => true;

        public bool IsQuicDisabled => true;

        public bool IsDnsOverHttpsDisabled => true;

        public bool IsIncognitoDisabled => true;

        public bool IsGuestModeDisabled => true;

        public bool IsProfileAdditionDisabled => true;

        public bool IsBrowserSigninDisabled => true;

        public bool AreDeveloperToolsRestricted => true;

        public bool IsExtensionDeveloperModeDisabled => true;

        public string PolicyDigestSha256 { get; }

        public static ManagedBrowserPolicyPlan CreateEdge(
            TrustedLoopbackProxyEndpoint proxyEndpoint,
            ForceInstalledExtension forceInstalledExtension)
        {
            return new ManagedBrowserPolicyPlan(ManagedBrowserKind.MicrosoftEdge, proxyEndpoint, forceInstalledExtension);
        }

        public static ManagedBrowserPolicyPlan CreateChrome(
            TrustedLoopbackProxyEndpoint proxyEndpoint,
            ForceInstalledExtension forceInstalledExtension)
        {
            return new ManagedBrowserPolicyPlan(ManagedBrowserKind.GoogleChrome, proxyEndpoint, forceInstalledExtension);
        }

        private string ComputeDigest()
        {
            var canonical = string.Concat(
                "browser=", Browser.ToString(), "\n",
                "proxy.mode=fixed_servers\n",
                "proxy.endpoint=", ProxyEndpoint.Endpoint, "\n",
                "proxy.machineManaged=true\n",
                "proxy.autoDetect=false\n",
                "proxy.pac=false\n",
                "proxy.bypass=\n",
                "proxy.overrideRules=\n",
                "quic.allowed=false\n",
                "dnsOverHttps.mode=off\n",
                "incognito.disabled=true\n",
                "guest.disabled=true\n",
                "profileAddition.disabled=true\n",
                "browserSignin.disabled=true\n",
                "developerTools.restricted=true\n",
                "extensionDeveloperMode.disabled=true\n",
                "extension.id=", ForceInstalledExtension.ExtensionId, "\n",
                "extension.updateUrl=", ForceInstalledExtension.UpdateUrl, "\n");
            var builder = new StringBuilder(canonical);
            for (var index = 0; index < MachinePolicies.Count; index++)
            {
                var setting = MachinePolicies[index];
                builder.Append("machinePolicy.")
                    .Append(setting.Name)
                    .Append('=')
                    .Append((int)setting.ValueKind)
                    .Append(':')
                    .Append(setting.CanonicalValue)
                    .Append('\n');
            }

            var bytes = Encoding.UTF8.GetBytes(builder.ToString());
            using (var algorithm = SHA256.Create())
            {
                var hash = algorithm.ComputeHash(bytes);
                var hashBuilder = new StringBuilder(hash.Length * 2);
                for (var index = 0; index < hash.Length; index++)
                {
                    hashBuilder.Append(hash[index].ToString("x2", System.Globalization.CultureInfo.InvariantCulture));
                }

                return hashBuilder.ToString();
            }
        }

        private IReadOnlyList<ManagedBrowserPolicySetting>
            BuildMachinePolicies()
        {
            var proxyJson =
                "{\"ProxyBypassList\":\"\",\"ProxyMode\":\"fixed_servers\",\"ProxyServer\":\"" +
                ProxyEndpoint.Endpoint +
                "\"}";
            var extensionJson =
                "{\"*\":{\"installation_mode\":\"blocked\"},\"" +
                ForceInstalledExtension.ExtensionId +
                "\":{\"installation_mode\":\"force_installed\",\"update_url\":\"" +
                ForceInstalledExtension.UpdateUrl +
                "\"}}";
            var settings = new List<ManagedBrowserPolicySetting>
            {
                StringPolicy("ProxySettings", proxyJson),
                BooleanPolicy("QuicAllowed", false),
                StringPolicy("DnsOverHttpsMode", "off"),
                BooleanPolicy("BrowserGuestModeEnabled", false),
                IntegerPolicy("BrowserSignin", 0),
                IntegerPolicy("DeveloperToolsAvailability", 2),
                StringPolicy("ExtensionSettings", extensionJson)
            };

            if (Browser == ManagedBrowserKind.MicrosoftEdge)
            {
                settings.Add(
                    IntegerPolicy("InPrivateModeAvailability", 1));
                settings.Add(
                    BooleanPolicy("BrowserAddProfileEnabled", false));
                settings.Add(
                    IntegerPolicy("ExtensionDeveloperModeSettings", 1));
            }
            else
            {
                settings.Add(
                    IntegerPolicy("IncognitoModeAvailability", 1));
                settings.Add(
                    BooleanPolicy("BrowserAddPersonEnabled", false));
            }

            settings.Sort(
                (left, right) =>
                    string.CompareOrdinal(left.Name, right.Name));
            return new ReadOnlyCollection<ManagedBrowserPolicySetting>(
                settings);
        }

        private static ManagedBrowserPolicySetting StringPolicy(
            string name,
            string value)
        {
            return new ManagedBrowserPolicySetting(
                name,
                ManagedBrowserPolicyValueKind.String,
                value);
        }

        private static ManagedBrowserPolicySetting IntegerPolicy(
            string name,
            int value)
        {
            return new ManagedBrowserPolicySetting(
                name,
                ManagedBrowserPolicyValueKind.Integer,
                value.ToString(
                    System.Globalization.CultureInfo.InvariantCulture));
        }

        private static ManagedBrowserPolicySetting BooleanPolicy(
            string name,
            bool value)
        {
            return new ManagedBrowserPolicySetting(
                name,
                ManagedBrowserPolicyValueKind.Boolean,
                value ? "true" : "false");
        }
    }
}
