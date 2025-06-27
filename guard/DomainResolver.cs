using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace Guard
{
    public static class DomainResolver
    {
        /// <summary>
        /// Resolves a list of domains to a unique list of IP addresses (IPv4 and IPv6 if needed).
        /// Logs failures to provided log action. Use async for fast resolution of many domains.
        /// </summary>
        public static async Task<List<string>> ResolveDomainsAsync(IEnumerable<string> domains, Action<string>? diagLog = null)
        {

            var result = new HashSet<string>();
            foreach (var domain in domains.Where(d => !string.IsNullOrWhiteSpace(d)).Select(d => d.Trim().ToLowerInvariant()).Distinct())
            {

                try
                {
                    var entries = await Dns.GetHostAddressesAsync(domain);
                    foreach (var ip in entries)
                    {
                        if (IPAddress.IsLoopback(ip))
                        {
                            diagLog?.Invoke("[DomainResolver] Skipping loopback IP for: " + domain);
                            continue;
                        }
                        // You can filter here if you want only IPv4/IPv6
                        result.Add(ip.ToString());
                    }
                    if (entries.Length == 0 && diagLog != null)
                        diagLog($"[DomainResolver] No IP found for domain: {domain}");
                }
                catch (Exception ex)
                {
                    diagLog?.Invoke($"[DomainResolver] Failed to resolve {domain}: {ex.Message}");
                }
            }
            return result.ToList();
        }
    }
}