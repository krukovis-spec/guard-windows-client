using System;
using System.Net.Http;

namespace Guard
{
    public static class TimeHelper
    {
        /// <summary>
        /// Returns the current trusted local time by applying the stored offset.
        /// If no offset is stored, it defaults to the system's local time.
        /// </summary>
        public static DateTime GetTrustedLocalNow(GuardState state)
        {
            // If we have a trusted offset from the network, use it.
            if (state.DeviceUtcOffsetMinutes.HasValue)
            {
                // The correct calculation is to take the system's UTC time and apply our trusted offset.
                return DateTime.UtcNow.AddMinutes(state.DeviceUtcOffsetMinutes.Value);
            }

            // Fallback: If we have never successfully checked the network,
            // trust the computer's own local time setting.
            return DateTime.Now;
        }
    }
}