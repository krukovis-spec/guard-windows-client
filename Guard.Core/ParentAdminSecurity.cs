using System;
using System.Collections.Generic;

namespace Guard
{
    public sealed class ParentAdminSession
    {
        public string Token { get; set; } = "";
        public DateTime ExpiresAtUtc { get; set; }
    }

    public sealed class ParentAdminSessionStore
    {
        public static readonly TimeSpan SessionLifetime = TimeSpan.FromMinutes(5);

        private readonly Dictionary<string, ParentAdminSession> _sessions =
            new Dictionary<string, ParentAdminSession>(StringComparer.Ordinal);

        public void Add(string token, DateTime utcNow)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                return;
            }

            _sessions[token] = new ParentAdminSession
            {
                Token = token,
                ExpiresAtUtc = utcNow.Add(SessionLifetime)
            };
        }

        public bool IsValid(string token, DateTime utcNow)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                return false;
            }

            if (!_sessions.TryGetValue(token, out var session))
            {
                return false;
            }

            if (session.ExpiresAtUtc <= utcNow)
            {
                _sessions.Remove(token);
                return false;
            }

            return true;
        }

        public void Renew(string token, DateTime utcNow)
        {
            if (!IsValid(token, utcNow))
            {
                return;
            }

            _sessions[token].ExpiresAtUtc = utcNow.Add(SessionLifetime);
        }

        public void Remove(string token)
        {
            if (!string.IsNullOrWhiteSpace(token))
            {
                _sessions.Remove(token);
            }
        }
    }

    public static class ParentAdminSecurityPolicy
    {
        private static readonly HashSet<string> SensitiveActions = new HashSet<string>(
            new[]
            {
                "remove-domain",
                "start-maintenance",
                "sync-off",
                "set-pin",
                "set-child-user",
                "demote-child-user",
                "capture-windows-users",
                "trust-windows-user",
                "disable-windows-user",
                "remove-windows-user-admin",
                "app-control-off",
                "app-control-audit",
                "app-control-enforce",
                "add-app",
                "grant-app",
                "allow-task-manager",
                "approve-request-15",
                "approve-request-60",
                "approve-request-always",
                "set-app-category",
                "set-site-category",
                "set-daily-screen-limit",
                "set-category-limit",
                "add-self-task",
                "add-verified-task"
            },
            StringComparer.OrdinalIgnoreCase);

        public static bool RequiresParentPassword(string action)
        {
            return !string.IsNullOrWhiteSpace(action) && SensitiveActions.Contains(action.Trim());
        }
    }
}
