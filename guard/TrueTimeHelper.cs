using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.Text.Json;

namespace Guard
{
    public static class TrueTimeHelper
    {
        // We will try each of these URLs in order to get a trusted UTC time.
        private static readonly string[] UtcTimeApiUrls = {
            "https://timeapi.io/api/Time/current/zone?timeZone=UTC",
            "https://worldtimeapi.org/api/timezone/Etc/UTC",
            "https://aisenseapi.com/services/v1/datetime" // New fallback API
        };

        /// <summary>
        /// Gets a trusted UTC DateTime from network sources, with a fallback.
        /// Returns null if all sources fail.
        /// </summary>
        public static async Task<DateTime?> GetTrustedUtcNowAsync(Action<string> log)
        {
            foreach (var url in UtcTimeApiUrls)
            {
                log($"[TimeCheck] Querying for trusted UTC time: {url}");
                try
                {
                    using (var client = new HttpClient { Timeout = TimeSpan.FromSeconds(20) })
                    {
                        var json = await client.GetStringAsync(url);
                        using (var doc = JsonDocument.Parse(json))
                        {
                            // This code now handles parsing the UTC time from any of the API formats.
                            if (url.Contains("timeapi.io"))
                            {
                                return doc.RootElement.GetProperty("dateTime").GetDateTime();
                            }
                            else if (url.Contains("worldtimeapi.org"))
                            {
                                return doc.RootElement.GetProperty("utc_datetime").GetDateTime();
                            }
                            else if (url.Contains("aisenseapi.com"))
                            {
                                // Handle the new API's response format
                                return doc.RootElement.GetProperty("datetime").GetDateTime();
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    log($"[TimeCheck] FAILED to get UTC time from {url}. Error: {ex.Message}");
                    // The loop will automatically continue to the next API.
                }
            }

            log("[TimeCheck] All UTC time providers failed.");
            return null; // Return null if all services fail.
        }
    }
}