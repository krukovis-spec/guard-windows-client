using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows.Forms;
using static System.Windows.Forms.AxHost;

namespace Guard
{
    public static class DeviceUpdater
    {
        private static int _devUpdateCallCount = 0;

        public static bool ApplyRemotePinCodeIfAllowed(GuardState state, string? remotePinCode, Action<string>? log = null)
        {
            if (string.IsNullOrWhiteSpace(remotePinCode))
            {
                return false;
            }

            log?.Invoke("[SECURITY] Ignored remote PIN update. PIN can only be changed from the parent cabinet after parent password confirmation.");
            return false;
        }

        public static async Task SendDeviceUpdateAsync(GuardState state, Action<string>? log = null)

        {
            if (!GuardV2ContainmentPolicy.CanUseLegacyRemoteServer(state))
            {
                log?.Invoke("[SECURITY] Guard v2 P0 containment disabled the legacy remote control plane; remote update skipped.");
                return;
            }


            _devUpdateCallCount++;            
            if ((_devUpdateCallCount+3) % 4 == 0)
            {
                GuardStateStorage.VerifyAndRestoreStateFiles(log);

                var threeDaysAgo = DateTime.UtcNow.AddDays(-3);
                if (state.IpsRecheck < threeDaysAgo) 
                {
                    log?.Invoke("[IP updater] Last IP update is older than 3 days. Flagging for refresh.");
                    state.UpdateInfo.Ips = true;
                    state.UpdateInfo.UpdateApplied = false;
                    state.IpsRecheck = DateTime.UtcNow;
                }

                try
                {
                    if (log != null) log("[DeviceUpdater] Running periodic actual time check...");
                    await Guard.MainForm.TrueTimePeriodicCheckAsync(state,log ?? (s => System.Diagnostics.Debug.WriteLine(s)));
                }
                catch (Exception ex)
                {
                    log?.Invoke("[DeviceUpdater] Error in periodic actual time check: " + ex.Message);
                }
            }

            try
            {
                using (var client = new HttpClient())
                {
                    // FIRST STEP REQUEST:
                    var firstPost = new
                    {
                        deviceUid = state.AssignCode,
                        lastUpdate = state.LastUpdate
                    };

                    var firstJson = JsonSerializer.Serialize(firstPost);
                    var firstContent = new StringContent(firstJson, Encoding.UTF8, "application/json");
                    var firstResp = await client.PostAsync("https://guard.alexweb.app/checker/ping", firstContent);
                    log?.Invoke("[DeviceUpdater] First ping sent:\n" + firstJson);

                    if (!firstResp.IsSuccessStatusCode)
                    {
                        log?.Invoke($"[DeviceUpdater] First request failed !!!!!!!!! {firstResp.StatusCode}");
                        state.UpdateInfo.ErrorCount += 1;
                        if (state.UpdateInfo.ErrorCount >= 30)
                        {
                            log?.Invoke("[DeviceUpdater] Error threshold reached. Sending remote log.");

                            // 1. Construct the error message
                            string errorMessage = $"API check failed 30 consecutive times. Last status: {firstResp.StatusCode}";

                            // 2. Add the error to the local state log
                            state.ErrorLog.Add($"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}Z] {errorMessage}");

                            // 3. Send the log to the remote server via the function in MainForm
                            // Safely call the instance method. If Instance is null, the task will be null.
                            var logTask = MainForm.Instance?.SendInfoLogAsync(errorMessage);
                            // Await the task, or if it's null, await an already completed task.
                            await (logTask ?? Task.CompletedTask);


                            // 4. Reset the counter to avoid flooding the server with logs
                            state.UpdateInfo.ErrorCount = 0;
                        }
                    }
                    else
                    {

                        var firstRespString = await firstResp.Content.ReadAsStringAsync();
                        var firstDoc = JsonDocument.Parse(firstRespString).RootElement;
                        firstDoc.TryGetProperty("updateNeed", out JsonElement updateEl);
                        if ( !updateEl.GetBoolean())
                        {
                            log?.Invoke("No update needed.");
                        }
                        else
                        {
                            log?.Invoke("Update needed. Checking type:");
                            // SECOND STEP REQUEST:
                            
                            string lastUpdateToSend = state.LastUpdate;
                            // If Presets or RestrictedCategories are missing, request full data with last update 0
                            if (state.Presets == null || state.Presets.Count == 0 ||
                                state.RestrictedCategories == null || state.RestrictedCategories.Count == 0)
                            {
                                lastUpdateToSend = "0";
                            }


                            var secondPost = new
                            {
                                deviceUid = state.AssignCode,
                                lastUpdate = lastUpdateToSend,
                                version = state.Version,
                                pinStatus = state.PinStatus
                            };

                            var secondJson = JsonSerializer.Serialize(secondPost);
                            var secondContent = new StringContent(secondJson, Encoding.UTF8, "application/json");
                            var secondResp = await client.PostAsync("https://guard.alexweb.app/checker/ping", secondContent);
                            log?.Invoke("Second ping sent:\n" + secondJson);

                            if (!secondResp.IsSuccessStatusCode)
                            {
                                log?.Invoke($"Second request failed: {secondResp.StatusCode}");

                            }
                            else
                            {
                                var secondRespString = await secondResp.Content.ReadAsStringAsync();

                                log?.Invoke("Second response received");
                                var doc = JsonDocument.Parse(secondRespString).RootElement;

                                if (doc.TryGetProperty("pinCode", out var pinCodeEl))
                                {
                                    ApplyRemotePinCodeIfAllowed(state, pinCodeEl.GetString(), log);
                                }



                                if (doc.TryGetProperty("pinStatus", out var pinStatEl)) state.PinStatus = pinStatEl.GetInt32();

                                if (doc.TryGetProperty("syncStatus", out var syncEl))
                                {
                                    bool newSyncStatus = syncEl.GetBoolean();
                                    if (state.SyncStatus != newSyncStatus)
                                    {
                                        state.SyncStatus = newSyncStatus;
                                        state.UpdateInfo.SyncStatUpdate = true;
                                        log?.Invoke("Device turned " + (state.SyncStatus ? "ON" : "OFF") + " syncStatus changed.");
                                        state.UpdateInfo.UpdateApplied = false;
                                    }
                           
                                }

                                if (doc.TryGetProperty("lastUpdate", out var lastUpEl))
                                {
                                    // Sanitize the string to trim whitespace and limit its length.
                                    state.LastUpdate = InputSanitizer.SanitizeString(lastUpEl.GetString(), maxLength: 50);
                                    log?.Invoke("Last update set to: " + state.LastUpdate);
                                }

                                if (state.SyncStatus == true)
                                {
                                    
                                    if (doc.TryGetProperty("resetConnection", out var resetEl))
                                    {
                                        bool newResetConnection = resetEl.GetBoolean();
                                        if (state.ResetConnection != newResetConnection)
                                        {
                                            state.ResetConnection = newResetConnection;
                                            state.UpdateInfo.Parameters = true;
                                            log?.Invoke("Reset connection changed: " + (state.ResetConnection ? "ON" : "OFF"));
                                            state.UpdateInfo.UpdateApplied = false;
                                        }
                                    }
                                    if (doc.TryGetProperty("sound", out var soundEl))
                                    {
                                        int newSound = soundEl.GetInt32();
                                        if (state.Sound != newSound)
                                        {
                                            state.Sound = newSound;
                                            log?.Invoke("Sound parameter changed to: " + state.Sound);
                                        }
                                    }
                                    if (doc.TryGetProperty("version", out var versionEl))
                                    {
                                        int newVersion = versionEl.GetInt32();
                                        if (state.Version != newVersion) { 
                                        state.Version = newVersion;
                                        log?.Invoke("Version changed. Set to: " + state.Version + ". Rules Update will be made.");
                                        state.UpdateInfo.UpdateApplied = false;
                                        }

                                    }
                                    if (doc.TryGetProperty("instructions", out var instrEl))
                                    {
                                        string instructionsJson = instrEl.GetString() ?? "";
                                        var parsed = InstructionsParser.Parse(instructionsJson);
                                        if (parsed == null)
                                        {
                                            log?.Invoke("Failed to parse instructions");
                                            log?.Invoke("Previous rules and categoriesleft untouched");
                                        }
                                        else
                                        {

                                            List<int> parsedCategories = parsed.RestrictedCategoryIds
                                            .Split(new[] { '.' }, StringSplitOptions.RemoveEmptyEntries)
                                            .Select(s => int.TryParse(s, out int id) ? id : -1)
                                            .Where(id => id > 0)
                                            .OrderBy(id => id)
                                            .ToList();

                                            List<InstructionRule> parsedRules = parsed.Rules ?? new List<InstructionRule>();


                                            if (!(state.RestrictedCategoryIds.OrderBy(x => x).SequenceEqual(parsedCategories)))
                                            {
                                                state.RestrictedCategoryIds = parsedCategories;
                                                state.UpdateInfo.Cats = true;
                                                log?.Invoke("Categories cahnged to: " + parsedCategories.ToString());
                                                state.UpdateInfo.UpdateApplied = false;
                                            } else { log?.Invoke("Categories not changed"); }

                                            bool rulesChanged = !(state.Rules?.Count == parsedRules.Count &&
                        state.Rules.OrderBy(r => r.Id).Zip(parsedRules.OrderBy(r => r.Id),
                        (a, b) => a.Id == b.Id &&
                                  a.Type == b.Type &&
                                  a.Value == b.Value &&
                                  a.Schedule == b.Schedule // <-- This is the crucial addition
                        ).All(x => x));
                                            if (rulesChanged)
                                            {
                                                state.Rules = parsedRules;
                                                state.UpdateInfo.Rules = true;
                                                state.UpdateInfo.UpdateApplied = false;
                                                log?.Invoke("Rules changed to: " + parsedRules.ToString());
                                            }
                                            else { log?.Invoke("Rules not changed"); }

                                        }
                                    }

                                    if (doc.TryGetProperty("presets", out var presetsEl))
                                    {
                                        var parsedPresets = JsonSerializer.Deserialize<List<Preset>>(presetsEl.GetRawText());
                                        if (parsedPresets != null)
                                        {
                                            var sanitizedPresets = new List<Preset>();
                                            foreach (var preset in parsedPresets)
                                            {
                                                // Sanitize the Domains string
                                                if (!string.IsNullOrEmpty(preset.Domains))
                                                {
                                                    var validDomains = preset.Domains
                                                        .Split(new[] { '|' }, StringSplitOptions.RemoveEmptyEntries)
                                                        .Select(d => d.Trim())
                                                        .Where(d => InputSanitizer.IsValidDomainName(d))
                                                        .ToList();
                                                    preset.Domains = string.Join("|", validDomains);
                                                }

                                                // Sanitize the Ips string
                                                if (!string.IsNullOrEmpty(preset.Ips))
                                                {
                                                    var validIps = preset.Ips
                                                        .Split(new[] { '|' }, StringSplitOptions.RemoveEmptyEntries)
                                                        .Select(ip => ip.Trim())
                                                        .Where(ip => InputSanitizer.IsValidIpAddress(ip))
                                                        .ToList();
                                                    preset.Ips = string.Join("|", validIps);
                                                }
                                                sanitizedPresets.Add(preset);
                                            }

                                            state.Presets = sanitizedPresets;
                                            state.UpdateInfo.Presets = true;
                                            log?.Invoke($"Presets updated and sanitized, count: {state.Presets.Count}");
                                            state.UpdateInfo.UpdateApplied = false;
                                        }
                                    }

                                    if (doc.TryGetProperty("restrictedCategories", out var catsEl))
                                    {
                                        var parsedCategories = JsonSerializer.Deserialize<List<RestrictedCategory>>(catsEl.GetRawText());
                                        if (parsedCategories != null)
                                        {
                                            var sanitizedCategories = new List<RestrictedCategory>();
                                            foreach (var category in parsedCategories)
                                            {
                                                // Sanitize the Urls string
                                                if (!string.IsNullOrEmpty(category.Urls))
                                                {
                                                    var validUrls = category.Urls
                                                        .Split(new[] { '|' }, StringSplitOptions.RemoveEmptyEntries)
                                                        .Select(u => u.Trim())
                                                        .Where(u => InputSanitizer.IsValidDomainName(u))
                                                        .ToList();
                                                    category.Urls = string.Join("|", validUrls);
                                                }

                                                // Sanitize the Domains string
                                                var categoryDomains = category.Domains;
                                                if (!string.IsNullOrEmpty(categoryDomains))
                                                {
                                                    var validDomains = categoryDomains!
                                                        .Split(new[] { '|' }, StringSplitOptions.RemoveEmptyEntries)
                                                        .Select(d => d.Trim())
                                                        .Where(d => InputSanitizer.IsValidDomainName(d))
                                                        .ToList();
                                                    category.Domains = string.Join("|", validDomains);
                                                }

                                                // Sanitize the Ips string
                                                var categoryIps = category.Ips;
                                                if (!string.IsNullOrEmpty(categoryIps))
                                                {
                                                    var validIps = categoryIps!
                                                        .Split(new[] { '|' }, StringSplitOptions.RemoveEmptyEntries)
                                                        .Select(ip => ip.Trim())
                                                        .Where(ip => InputSanitizer.IsValidIpAddress(ip))
                                                        .ToList();
                                                    category.Ips = string.Join("|", validIps);
                                                }
                                                sanitizedCategories.Add(category);
                                            }

                                            state.RestrictedCategories = sanitizedCategories;
                                            state.UpdateInfo.RestrictedCats = true;
                                            log?.Invoke($"Restricted categories updated and sanitized, count: {state.RestrictedCategories.Count}");
                                            state.UpdateInfo.UpdateApplied = false;
                                        }
                                    }
                                } 




                                    GuardStateStorage.Save(state);



                            }
                        }
                    }



                }
            }
            catch (Exception ex)
            {
                log?.Invoke("Error during update: " + ex.Message);
            }

        }
    }
}

