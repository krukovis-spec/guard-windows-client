using System;
using System.Security.Cryptography;

namespace Guard
{
    public static class ParentAdminAuth
    {
        public const int DefaultIterations = 120000;

        public static bool IsConfigured(GuardState state)
        {
            return !string.IsNullOrWhiteSpace(state.ParentAdminPasswordHash) &&
                   !string.IsNullOrWhiteSpace(state.ParentAdminPasswordSalt) &&
                   state.ParentAdminPasswordIterations > 0;
        }

        public static bool SetPassword(GuardState state, string password)
        {
            if (!IsStrongEnough(password))
            {
                return false;
            }

            var salt = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            var hash = HashPassword(password, salt, DefaultIterations);
            state.ParentAdminPasswordSalt = Convert.ToBase64String(salt);
            state.ParentAdminPasswordHash = Convert.ToBase64String(hash);
            state.ParentAdminPasswordIterations = DefaultIterations;
            return true;
        }

        public static bool VerifyPassword(GuardState state, string password)
        {
            if (!IsConfigured(state) || string.IsNullOrEmpty(password))
            {
                return false;
            }

            try
            {
                var salt = Convert.FromBase64String(state.ParentAdminPasswordSalt);
                var expected = Convert.FromBase64String(state.ParentAdminPasswordHash);
                var actual = HashPassword(password, salt, state.ParentAdminPasswordIterations);
                return FixedTimeEquals(expected, actual);
            }
            catch
            {
                return false;
            }
        }

        public static bool IsStrongEnough(string password)
        {
            return !string.IsNullOrWhiteSpace(password) && password.Length >= 12;
        }

        private static byte[] HashPassword(string password, byte[] salt, int iterations)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256))
            {
                return pbkdf2.GetBytes(32);
            }
        }

        private static bool FixedTimeEquals(byte[] left, byte[] right)
        {
            if (left.Length != right.Length)
            {
                return false;
            }

            int diff = 0;
            for (int i = 0; i < left.Length; i++)
            {
                diff |= left[i] ^ right[i];
            }

            return diff == 0;
        }
    }
}
