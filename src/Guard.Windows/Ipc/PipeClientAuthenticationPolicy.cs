using System;
using System.Collections.Generic;
using Guard.Contracts;

namespace Guard.Windows.Ipc
{
    public sealed class PipeClientTokenFacts
    {
        private readonly string[] _groupSids;

        public PipeClientTokenFacts(
            string userSid,
            IEnumerable<string>? groupSids,
            bool isElevated,
            int integrityLevelRid,
            bool isRemote)
        {
            UserSid = userSid ?? string.Empty;
            _groupSids = groupSids == null ? Array.Empty<string>() : Copy(groupSids);
            IsElevated = isElevated;
            IntegrityLevelRid = integrityLevelRid;
            IsRemote = isRemote;
        }

        public string UserSid { get; }

        public IReadOnlyList<string> GroupSids => Array.AsReadOnly((string[])_groupSids.Clone());

        public bool IsElevated { get; }

        public int IntegrityLevelRid { get; }

        public bool IsRemote { get; }

        private static string[] Copy(IEnumerable<string> values)
        {
            var result = new List<string>();
            foreach (var value in values)
            {
                if (!string.IsNullOrWhiteSpace(value))
                {
                    result.Add(value);
                }
            }

            return result.ToArray();
        }
    }

    public static class PipeClientAuthenticationPolicy
    {
        public const int HighIntegrityRid = 0x3000;
        private const int MinimumLowPrivilegeIntegrityRid = 0x1000;
        private const string BuiltinAdministratorsSid = "S-1-5-32-544";

        public static bool IsAuthorized(
            GuardPipeSecurityProfile profile,
            PipeClientTokenFacts facts)
        {
            if (profile == null)
            {
                throw new ArgumentNullException(nameof(profile));
            }

            if (facts == null)
            {
                throw new ArgumentNullException(nameof(facts));
            }

            if (facts.IsRemote)
            {
                return false;
            }

            if (profile.Role == ClientRole.AdminSetup)
            {
                return facts.IsElevated &&
                       facts.IntegrityLevelRid >= HighIntegrityRid &&
                       ContainsSid(facts.GroupSids, BuiltinAdministratorsSid);
            }

            return !facts.IsElevated &&
                   facts.IntegrityLevelRid >= MinimumLowPrivilegeIntegrityRid &&
                   facts.IntegrityLevelRid < HighIntegrityRid &&
                   string.Equals(
                       facts.UserSid,
                       profile.AuthorizedSid.Value,
                       StringComparison.Ordinal);
        }

        private static bool ContainsSid(IReadOnlyList<string> values, string expected)
        {
            for (var index = 0; index < values.Count; index++)
            {
                if (string.Equals(values[index], expected, StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }
    }
}
