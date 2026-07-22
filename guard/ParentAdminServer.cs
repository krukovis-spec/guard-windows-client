using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Guard
{
    public sealed class ParentAdminServer : IDisposable
    {
        private const string SessionCookieName = "GuardAdminSession";
        private readonly GuardState _state;
        private readonly Action<string> _log;
        private readonly Action _requestApply;
        private readonly ParentAdminSessionStore _sessions = new ParentAdminSessionStore();
        private HttpListener? _listener;
        private CancellationTokenSource? _stop;
        private string _prefix = "";

        public ParentAdminServer(GuardState state, Action<string> log, Action requestApply)
        {
            _state = state;
            _log = log;
            _requestApply = requestApply;
        }

        public bool IsRunning => _listener?.IsListening == true;

        private string Language => UiLanguage.Normalize(_state.UiLanguage);

        private string L(string russian, string english)
        {
            return UiLanguage.Text(Language, russian, english);
        }

        public bool Start()
        {
            if (!GuardV2ContainmentPolicy.CanStartParentAdminServer(_state))
            {
                _log("[SECURITY] Legacy parent cabinet is disabled by Guard v2 P0 containment.");
                return false;
            }

            if (IsRunning)
            {
                return true;
            }

            int port = _state.ParentAdminPort <= 0 ? 8765 : _state.ParentAdminPort;
            foreach (var prefix in new[] { $"http://+:{port}/", $"http://127.0.0.1:{port}/" })
            {
                try
                {
                    var listener = new HttpListener();
                    listener.Prefixes.Add(prefix);
                    listener.Start();

                    _listener = listener;
                    _prefix = prefix;
                    _stop = new CancellationTokenSource();
                    Task.Run(() => ListenLoop(_stop.Token));
                    _log("[ParentAdmin] Parent cabinet started on port " + port + ".");
                    return true;
                }
                catch (Exception ex)
                {
                    _log("[ParentAdmin] Failed to start listener: " + ex.Message);
                }
            }

            return false;
        }

        public string GetAccessText()
        {
            int port = _state.ParentAdminPort <= 0 ? 8765 : _state.ParentAdminPort;
            if (_prefix.StartsWith("http://127.0.0.1", StringComparison.OrdinalIgnoreCase))
            {
                return $"http://localhost:{port}/" + Environment.NewLine +
                       L("Доступ из локальной сети недоступен: кабинет смог запуститься только на localhost.",
                         "LAN access is not available because the listener could only bind to localhost.");
            }

            var urls = GetLanUrls(port);
            if (!urls.Any())
            {
                urls.Add($"http://localhost:{port}/");
            }

            return string.Join(Environment.NewLine, urls);
        }

        public void Dispose()
        {
            try { _stop?.Cancel(); } catch { }
            try { _listener?.Stop(); } catch { }
            try { _listener?.Close(); } catch { }
        }

        private void ListenLoop(CancellationToken token)
        {
            var listener = _listener;
            if (listener == null) return;

            while (!token.IsCancellationRequested && listener.IsListening)
            {
                try
                {
                    var context = listener.GetContext();
                    Task.Run(() => HandleRequest(context));
                }
                catch (HttpListenerException)
                {
                    break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _log("[ParentAdmin] Request loop error: " + ex.Message);
                }
            }
        }

        private async Task HandleRequest(HttpListenerContext context)
        {
            try
            {
                var path = context.Request.Url?.AbsolutePath ?? "/";
                if (context.Request.HttpMethod == "GET")
                {
                    WriteHtml(context, RenderPage(context, ""));
                    return;
                }

                if (context.Request.HttpMethod != "POST")
                {
                    context.Response.StatusCode = 405;
                    WriteText(context, L("Метод не поддерживается", "Method not allowed"));
                    return;
                }

                var form = await ReadForm(context.Request);
                switch (path)
                {
                    case "/setup":
                        HandleSetup(context, form);
                        break;
                    case "/login":
                        HandleLogin(context, form);
                        break;
                    case "/logout":
                        HandleLogout(context);
                        break;
                    case "/command":
                        HandleCommand(context, form);
                        break;
                    default:
                        context.Response.StatusCode = 404;
                        WriteText(context, L("Не найдено", "Not found"));
                        break;
                }
            }
            catch (Exception ex)
            {
                _log("[ParentAdmin] Request error: " + ex.Message);
                context.Response.StatusCode = 500;
                WriteText(context, L("Внутренняя ошибка", "Internal error"));
            }
        }

        private void HandleSetup(HttpListenerContext context, Dictionary<string, string> form)
        {
            context.Response.StatusCode = 403;
            WriteHtml(context, RenderPage(context,
                L("Небезопасная первичная привязка отключена до появления passkey-настройки.",
                  "Unsafe first pairing is disabled until passkey provisioning is available.")));
        }

        private void HandleLogin(HttpListenerContext context, Dictionary<string, string> form)
        {
            if (ParentAdminAuth.VerifyPassword(_state, Get(form, "password")))
            {
                SignIn(context);
                WriteHtml(context, RenderPage(context, "Signed in."));
                return;
            }

            WriteHtml(context, RenderPage(context, "Wrong password."));
        }

        private void HandleLogout(HttpListenerContext context)
        {
            var token = GetSessionToken(context);
            if (!string.IsNullOrEmpty(token))
            {
                lock (_sessions) _sessions.Remove(token!);
            }

            context.Response.Headers.Add("Set-Cookie", $"{SessionCookieName}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict");
            WriteHtml(context, RenderPage(context, "Signed out."));
        }

        private void HandleCommand(HttpListenerContext context, Dictionary<string, string> form)
        {
            if (!IsSignedIn(context))
            {
                context.Response.StatusCode = 403;
                WriteHtml(context, RenderPage(context, "Please sign in first."));
                return;
            }

            ParentCommandResult result;
            var action = Get(form, "action");
            var token = GetSessionToken(context) ?? "";
            if (ParentAdminSecurityPolicy.RequiresParentPassword(action) &&
                !ParentAdminAuth.VerifyPassword(_state, Get(form, "parentPassword")))
            {
                WriteHtml(context, RenderReauth(form, string.IsNullOrWhiteSpace(Get(form, "parentPassword"))
                    ? "Parent password is required for this action."
                    : "Wrong parent password."));
                return;
            }
            _sessions.Renew(token, DateTime.UtcNow);

            if (action == "add-domain")
            {
                result = ParentCommandApplier.Apply(_state, new ParentCommand
                {
                    Type = ParentCommandType.AddBlockedDomain,
                    Value = Get(form, "domain")
                });
            }
            else if (action == "remove-domain")
            {
                result = ParentCommandApplier.Apply(_state, new ParentCommand
                {
                    Type = ParentCommandType.RemoveBlockedDomain,
                    Value = Get(form, "domain")
                });
            }
            else if (action == "remove-site-grant")
            {
                result = ParentCommandApplier.Apply(_state, new ParentCommand
                {
                    Type = ParentCommandType.RemoveWebsiteGrant,
                    Value = Get(form, "domain")
                });
            }
            else if (action == "start-maintenance")
            {
                result = ParentCommandApplier.Apply(_state, new ParentCommand
                {
                    Type = ParentCommandType.StartMaintenanceMode,
                    IntValue = ParseInt(Get(form, "minutes"))
                });
            }
            else if (action == "end-maintenance")
            {
                result = ParentCommandApplier.Apply(_state, new ParentCommand
                {
                    Type = ParentCommandType.EndMaintenanceMode
                });
            }
            else if (action == "sync-on" || action == "sync-off")
            {
                result = ParentCommandApplier.Apply(_state, new ParentCommand
                {
                    Type = ParentCommandType.SetSyncStatus,
                    BoolValue = action == "sync-on"
                });
            }
            else if (action == "set-pin")
            {
                result = ParentCommandApplier.Apply(_state, new ParentCommand
                {
                    Type = ParentCommandType.SetEmergencyPin,
                    Value = Get(form, "pin")
                });
            }
            else if (action == "set-child-user")
            {
                result = ParentCommandApplier.Apply(_state, new ParentCommand
                {
                    Type = ParentCommandType.SetChildWindowsUser,
                    Value = Get(form, "childUser")
                });
            }
            else if (action == "demote-child-user")
            {
                result = ParentCommandApplier.Apply(_state, new ParentCommand
                {
                    Type = ParentCommandType.DemoteChildWindowsUser,
                    Value = Get(form, "childUser")
                });
            }
            else if (action == "app-control-off" || action == "app-control-audit" || action == "app-control-enforce")
            {
                result = ParentCommandApplier.Apply(_state, new ParentCommand
                {
                    Type = ParentCommandType.SetApplicationControlMode,
                    Value = action == "app-control-off" ? "off" : action == "app-control-audit" ? "audit" : "enforce"
                });
            }
            else if (action == "add-app")
            {
                result = ParentCommandApplier.Apply(_state, new ParentCommand
                {
                    Type = ParentCommandType.AddAllowedApplication,
                    Value = Get(form, "appPath"),
                    DisplayName = Get(form, "appName")
                });
            }
            else if (action == "grant-app")
            {
                result = ParentCommandApplier.Apply(_state, new ParentCommand
                {
                    Type = ParentCommandType.GrantTemporaryApplication,
                    Value = Get(form, "appPath"),
                    DisplayName = Get(form, "appName"),
                    IntValue = ParseInt(Get(form, "minutes"))
                });
            }
            else if (action == "remove-app")
            {
                result = ParentCommandApplier.Apply(_state, new ParentCommand
                {
                    Type = ParentCommandType.RemoveAllowedApplication,
                    Value = Get(form, "appPath")
                });
            }
            else if (action == "allow-task-manager")
            {
                result = ParentCommandApplier.Apply(_state, new ParentCommand
                {
                    Type = ParentCommandType.GrantTaskManagerAccess,
                    IntValue = ParseInt(Get(form, "minutes"))
                });
            }
            else if (action == "block-task-manager")
            {
                result = ParentCommandApplier.Apply(_state, new ParentCommand
                {
                    Type = ParentCommandType.BlockTaskManagerNow
                });
            }
            else if (action == "approve-request-15" || action == "approve-request-60" || action == "approve-request-always")
            {
                result = ParentCommandApplier.Apply(_state, new ParentCommand
                {
                    Type = ParentCommandType.ApproveAccessRequest,
                    Value = Get(form, "requestId"),
                    IntValue = action == "approve-request-15" ? 15 :
                        action == "approve-request-60" ? 60 : (int?)null
                });
            }
            else if (action == "deny-request")
            {
                result = ParentCommandApplier.Apply(_state, new ParentCommand
                {
                    Type = ParentCommandType.DenyAccessRequest,
                    Value = Get(form, "requestId")
                });
            }
            else if (action == "set-app-category")
            {
                result = ParentCommandApplier.Apply(_state, new ParentCommand
                {
                    Type = ParentCommandType.SetApplicationCategory,
                    Value = Get(form, "appPath"),
                    DisplayName = Get(form, "appName"),
                    ActivityCategory = ParseActivityCategory(Get(form, "category")),
                    BoolValue = Get(form, "countsScreenTime") == "on"
                });
            }
            else if (action == "set-site-category")
            {
                result = ParentCommandApplier.Apply(_state, new ParentCommand
                {
                    Type = ParentCommandType.SetSiteCategory,
                    Value = Get(form, "domain"),
                    DisplayName = Get(form, "siteName"),
                    ActivityCategory = ParseActivityCategory(Get(form, "category")),
                    BoolValue = Get(form, "countsScreenTime") == "on"
                });
            }
            else if (action == "set-daily-screen-limit")
            {
                result = ParentCommandApplier.Apply(_state, new ParentCommand
                {
                    Type = ParentCommandType.SetDailyScreenTimeLimit,
                    IntValue = ParseInt(Get(form, "minutes"))
                });
            }
            else if (action == "set-category-limit")
            {
                result = ParentCommandApplier.Apply(_state, new ParentCommand
                {
                    Type = ParentCommandType.SetCategoryTimeLimit,
                    ActivityCategory = ParseActivityCategory(Get(form, "category")),
                    IntValue = ParseInt(Get(form, "dailyMinutes")),
                    Schedule = Get(form, "sessionMinutes")
                });
            }
            else if (action == "add-self-task" || action == "add-verified-task")
            {
                result = ParentCommandApplier.Apply(_state, new ParentCommand
                {
                    Type = ParentCommandType.AddDailyTask,
                    DisplayName = Get(form, "title"),
                    DailyTaskType = action == "add-self-task" ? DailyTaskType.SelfReport : DailyTaskType.VerifiedApplicationTime,
                    Value = Get(form, "appPath"),
                    ActivityCategory = ParseActivityCategory(Get(form, "category")),
                    IntValue = ParseInt(Get(form, "requiredMinutes")),
                    Schedule = Get(form, "rewardMinutes"),
                    RewardCategory = ParseActivityCategory(Get(form, "rewardCategory"))
                });
            }
            else if (action == "set-language")
            {
                result = ParentCommandApplier.Apply(_state, new ParentCommand
                {
                    Type = ParentCommandType.SetUiLanguage,
                    Value = Get(form, "language")
                });
            }
            else
            {
                result = new ParentCommandResult { Error = "Unknown command." };
            }

            if (!string.IsNullOrEmpty(result.Error))
            {
                WriteHtml(context, RenderPage(context, result.Error));
                return;
            }

            if (result.Changed)
            {
                GuardStateStorage.Save(_state);
                if (action != "set-language")
                {
                    _requestApply();
                }
            }

            WriteHtml(context, RenderPage(context, result.Changed ? "Saved." : "Nothing changed."));
        }

        private string RenderPage(HttpListenerContext context, string message)
        {
            bool configured = ParentAdminAuth.IsConfigured(_state);
            bool signedIn = IsSignedIn(context);
            var body = configured
                ? (signedIn ? RenderDashboard(message) : RenderLogin(message))
                : RenderSetup(message);
            var autoRefresh = configured && signedIn
                ? "<script>setInterval(function(){var e=document.activeElement;var t=e&&e.tagName;if(t==='INPUT'||t==='SELECT'||t==='TEXTAREA'){return;}window.location.reload();},15000);</script>"
                : "";

            return "<!doctype html><html lang=\"" + Html(Language) + "\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
                   "<title>" + Html(L("Guard: родительский кабинет", "Guard Parent Cabinet")) + "</title>" +
                   "<style>" +
                   "body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f4f6f8;color:#1d2733}" +
                   "main{max-width:760px;margin:32px auto;background:white;padding:28px;border:1px solid #d6dde5;border-radius:8px}" +
                   "h1{margin:0 0 18px;font-size:26px} h2{margin-top:28px;font-size:18px}" +
                   "form{margin:14px 0} label{display:block;margin:12px 0 6px;font-weight:600}" +
                   "input,select{width:100%;box-sizing:border-box;padding:10px;font-size:16px;border:1px solid #b8c2cc;border-radius:6px}" +
                   "button{padding:10px 14px;font-size:15px;border:0;border-radius:6px;background:#1769aa;color:white;cursor:pointer}" +
                   ".row{display:flex;gap:8px;align-items:end}.row input{flex:1}.muted{color:#667485}.msg{padding:10px;background:#eef7ee;border:1px solid #bddabd;border-radius:6px}" +
                   ".danger button{background:#b42318}.list{padding-left:20px}.badge{display:inline-block;padding:4px 8px;background:#eef2f6;border-radius:999px}" +
                   ".split{display:grid;grid-template-columns:1fr 1fr;gap:12px}.app,.request{border-top:1px solid #e1e7ee;padding:12px 0}.path{font-family:Consolas,monospace;font-size:13px;word-break:break-all;color:#46515c}" +
                   ".actions{display:flex;gap:8px;flex-wrap:wrap}.actions form{margin:0}.language{display:flex;gap:8px;align-items:end;justify-content:flex-end}.language select{max-width:180px}" +
                   "</style></head><body><main>" + body + "</main>" + autoRefresh + "</body></html>";
        }

        private string RenderReauth(Dictionary<string, string> form, string message)
        {
            var hidden = string.Join("", form
                .Where(item => !string.Equals(item.Key, "parentPassword", StringComparison.OrdinalIgnoreCase))
                .Select(item => "<input type=\"hidden\" name=\"" + Html(item.Key) + "\" value=\"" + Html(item.Value) + "\">"));

            return "<!doctype html><html lang=\"" + Html(Language) + "\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
                   "<title>" + Html(L("Подтвердите пароль родителя", "Confirm parent password")) + "</title>" +
                   "<style>body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f4f6f8;color:#1d2733}main{max-width:520px;margin:32px auto;background:white;padding:28px;border:1px solid #d6dde5;border-radius:8px}h1{margin:0 0 18px;font-size:26px}label{display:block;margin:12px 0 6px;font-weight:600}input{width:100%;box-sizing:border-box;padding:10px;font-size:16px;border:1px solid #b8c2cc;border-radius:6px}button{padding:10px 14px;font-size:15px;border:0;border-radius:6px;background:#1769aa;color:white;cursor:pointer}.msg{padding:10px;background:#fff5e8;border:1px solid #e2bf8a;border-radius:6px}.muted{color:#667485}</style>" +
                   "</head><body><main>" +
                   Header(L("Подтвердите пароль родителя", "Confirm parent password"), message) +
                   "<p class=\"muted\">" + Html(L("Это действие может ослабить защиту, поэтому Guard ещё раз спрашивает пароль родителя.",
                       "This action can weaken protection, so Guard asks for the parent password again.")) + "</p>" +
                   "<form method=\"post\" action=\"/command\">" +
                   hidden +
                   "<label>" + Html(L("Пароль родителя", "Parent password")) + "</label><input name=\"parentPassword\" type=\"password\" autocomplete=\"current-password\" required autofocus>" +
                   "<p><button type=\"submit\">" + Html(L("Подтвердить", "Confirm")) + "</button></p></form>" +
                   "</main></body></html>";
        }

        private string RenderSetup(string message)
        {
            return Header(L("Guard: родительский кабинет", "Guard Parent Cabinet"), message) +
                   "<p class=\"muted\">" + Html(L(
                       "Legacy-привязка и создание владельца на детском компьютере временно недоступны. Дождитесь безопасной passkey-настройки Guard v2.",
                       "Legacy pairing and owner creation on the child computer are temporarily unavailable. Wait for Guard v2 passkey provisioning.")) + "</p>";
        }

        private string RenderLogin(string message)
        {
            return Header(L("Guard: родительский кабинет", "Guard Parent Cabinet"), message) +
                   "<form method=\"post\" action=\"/login\">" +
                   "<label>" + Html(L("Пароль родителя", "Parent password")) + "</label><input name=\"password\" type=\"password\" autocomplete=\"current-password\" required>" +
                   "<p class=\"muted\">" + Html(L("Сессия истекает через 5 минут. Опасные действия всегда ещё раз спрашивают пароль.",
                       "Session expires after 5 minutes. Sensitive actions always ask for the password again.")) + "</p>" +
                   "<p><button type=\"submit\">" + Html(L("Войти", "Sign in")) + "</button></p></form>";
        }

        private string RenderLanguageSwitcher()
        {
            var language = Language;
            return "<form method=\"post\" action=\"/command\" class=\"language\">" +
                   "<input type=\"hidden\" name=\"action\" value=\"set-language\">" +
                   "<div><label>" + Html(L("Язык", "Language")) + "</label><select name=\"language\">" +
                   "<option value=\"ru\"" + (language == UiLanguage.Russian ? " selected" : "") + ">Русский</option>" +
                   "<option value=\"en\"" + (language == UiLanguage.English ? " selected" : "") + ">English</option>" +
                   "</select></div>" +
                   "<button type=\"submit\">" + Html(L("Сохранить", "Save")) + "</button></form>";
        }

        private string RenderDashboard(string message)
        {
            var rules = _state.Rules
                .Where(r => r.Id.StartsWith(ParentCommandApplier.BuildDomainRuleId(""), StringComparison.OrdinalIgnoreCase))
                .OrderBy(r => r.Value)
                .ToList();

            var list = rules.Any()
                ? "<ul class=\"list\">" + string.Join("", rules.Select(r =>
                    "<li>" + Html(r.Value) +
                    "<form method=\"post\" action=\"/command\" style=\"display:inline;margin-left:10px\">" +
                    "<input type=\"hidden\" name=\"action\" value=\"remove-domain\">" +
                    "<input type=\"hidden\" name=\"domain\" value=\"" + Html(r.Value) + "\">" +
                    "<button type=\"submit\">" + Html(L("Удалить", "Remove")) + "</button></form></li>")) + "</ul>"
                : "<p class=\"muted\">" + Html(L("Сайтов, заблокированных родителем вручную, пока нет.", "No parent-managed domains yet.")) + "</p>";

            var appControl = _state.AppControl ?? new ApplicationControlSettings();
            var modeText = appControl.Mode == ApplicationControlMode.Enforced
                ? L("запуск приложений только после разрешения", "application allowlist enforced")
                : appControl.Mode == ApplicationControlMode.AuditOnly
                    ? L("режим наблюдения без блокировки", "application allowlist audit")
                    : L("контроль приложений выключен", "application control off");
            var taskManagerText = FormatTaskManagerStatus(appControl);
            var applications = (appControl.AllowedApplications ?? new List<AllowedApplication>())
                .OrderBy(app => app.DisplayName)
                .ToList();
            var appList = applications.Any()
                ? string.Join("", applications.Select(RenderApplication))
                : "<p class=\"muted\">" + Html(L("Разрешённых приложений пока нет.", "No allowed applications yet.")) + "</p>";
            var pendingRequests = AccessRequestApplier.GetPendingRequests(_state);
            var requestList = pendingRequests.Any()
                ? string.Join("", pendingRequests.Select(RenderAccessRequest))
                : "<p class=\"muted\">" + Html(L("Новых запросов на доступ нет.", "No pending access requests.")) + "</p>";
            var siteGrants = DomainAccessGrantApplier.GetActiveGrants(_state, DateTime.UtcNow);
            var siteGrantList = siteGrants.Any()
                ? string.Join("", siteGrants.Select(grant => RenderSiteGrant(grant, _state.ActivitySettings)))
                : "<p class=\"muted\">" + Html(L("Разрешённых сайтов пока нет.", "No active site allowances.")) + "</p>";
            var todayUsage = ActivityAccountingEngine.GetTodayUsage(_state, DateTime.UtcNow);
            var activityList = todayUsage.Any()
                ? string.Join("", todayUsage.Select(RenderActivityUsage))
                : "<p class=\"muted\">" + Html(L("Сегодня активность ещё не записана.", "No activity recorded today yet.")) + "</p>";
            var timeLimitStatus = TimeLimitEngine.GetStatus(_state, DateTime.UtcNow);
            var taskList = RenderDailyTasks(_state);
            var webAccess = _state.WebAccess ?? new WebAccessSettings();
            var webAccessText = webAccess.DefaultDenyEnabled
                ? L("интернет по умолчанию закрыт: открываются только разрешённые сайты", "web default deny: only approved sites open")
                : L("режим запрета интернета по умолчанию выключен", "web default deny off");

            return RenderLanguageSwitcher() +
                   Header(L("Guard: родительский кабинет", "Guard Parent Cabinet"), message) +
                   "<p>" + Html(L("Статус", "Status")) + ": <span class=\"badge\">" +
                   (_state.SyncStatus ? Html(L("блокировка включена", "blocking enabled")) : Html(L("блокировка приостановлена", "blocking paused"))) +
                   "</span></p>" +
                   RenderMaintenanceMode(_state) +
                   "<h2>" + Html(L("Заблокировать сайт вручную", "Add blocked site")) + "</h2><form method=\"post\" action=\"/command\" class=\"row\">" +
                   "<input type=\"hidden\" name=\"action\" value=\"add-domain\">" +
                   "<div style=\"flex:1\"><label>" + Html(L("Домен", "Domain")) + "</label><input name=\"domain\" placeholder=\"youtube.com\" required></div>" +
                   "<button type=\"submit\">" + Html(L("Заблокировать", "Block")) + "</button></form>" +
                   "<h2>" + Html(L("Сайты, заблокированные родителем", "Parent-managed blocked sites")) + "</h2>" + list +
                   "<h2>" + Html(L("Разрешённые сайты", "Allowed sites")) + "</h2>" + siteGrantList +
                   "<h2>" + Html(L("Блокировка", "Blocking")) + "</h2><form method=\"post\" action=\"/command\">" +
                   "<input type=\"hidden\" name=\"action\" value=\"" + (_state.SyncStatus ? "sync-off" : "sync-on") + "\">" +
                   "<button type=\"submit\">" + (_state.SyncStatus ? Html(L("Приостановить блокировку", "Pause blocking")) : Html(L("Включить блокировку", "Enable blocking"))) + "</button></form>" +
                   "<h2>" + Html(L("Доступ к сайтам", "Web access")) + "</h2>" +
                   "<p><span class=\"badge\">" + Html(webAccessText) + "</span></p>" +
                   "<p class=\"muted\">" + Html(L("Любой неизвестный сайт в браузере превращается в запрос к родителю и остаётся закрытым до одобрения.",
                       "Unknown browser domains become access requests and stay blocked until approved.")) + "</p>" +
                   "<h2>" + Html(L("Аварийный PIN", "Emergency PIN")) + "</h2><form method=\"post\" action=\"/command\" class=\"row\">" +
                   "<input type=\"hidden\" name=\"action\" value=\"set-pin\">" +
                   "<div style=\"flex:1\"><label>" + Html(L("PIN из 6 цифр", "6 digit PIN")) + "</label><input name=\"pin\" minlength=\"6\" maxlength=\"6\" pattern=\"[0-9]{6}\" required></div>" +
                   "<button type=\"submit\">" + Html(L("Обновить PIN", "Update PIN")) + "</button></form>" +
                   "<h2>" + Html(L("Учётная запись Windows", "Windows account")) + "</h2>" + RenderAccountHardening(_state) +
                   "<h2>" + Html(L("Приложения", "Applications")) + "</h2>" +
                   "<p>" + Html(L("Статус", "Status")) + ": <span class=\"badge\">" + Html(modeText) + "</span></p>" +
                   "<p><span class=\"badge\">" + Html(taskManagerText) + "</span></p>" +
                   "<div class=\"row\">" +
                   AppModeButton(L("Выкл", "Off"), "app-control-off") +
                   AppModeButton(L("Наблюдение", "Audit"), "app-control-audit") +
                   AppModeButton(L("Блокировать", "Enforce"), "app-control-enforce") +
                   "</div>" +
                   "<h2>" + Html(L("Запросы на доступ", "Access requests")) + "</h2>" + requestList +
                   "<h2>" + Html(L("Диспетчер задач и системные инструменты", "Task Manager and system tools")) + "</h2>" +
                   "<form method=\"post\" action=\"/command\" class=\"row\">" +
                   "<input type=\"hidden\" name=\"action\" value=\"allow-task-manager\">" +
                   "<div style=\"flex:1\"><label>" + Html(L("Минут для обслуживания", "Allow maintenance minutes")) + "</label><input name=\"minutes\" type=\"number\" min=\"1\" max=\"120\" value=\"10\" required></div>" +
                   "<button type=\"submit\">" + Html(L("Разрешить временно", "Allow temporarily")) + "</button></form>" +
                   "<form method=\"post\" action=\"/command\">" +
                   "<input type=\"hidden\" name=\"action\" value=\"block-task-manager\">" +
                   "<button type=\"submit\">" + Html(L("Заблокировать сейчас", "Block now")) + "</button></form>" +
                   "<div class=\"split\">" +
                   "<form method=\"post\" action=\"/command\">" +
                   "<input type=\"hidden\" name=\"action\" value=\"add-app\">" +
                   "<label>" + Html(L("Название приложения", "App name")) + "</label><input name=\"appName\" placeholder=\"Minecraft\">" +
                   "<label>" + Html(L("Путь к exe", "Exe path")) + "</label><input name=\"appPath\" placeholder=\"C:\\Program Files\\App\\App.exe\" required>" +
                   "<p><button type=\"submit\">" + Html(L("Разрешить всегда", "Allow always")) + "</button></p></form>" +
                   "<form method=\"post\" action=\"/command\">" +
                   "<input type=\"hidden\" name=\"action\" value=\"grant-app\">" +
                   "<label>" + Html(L("Название приложения", "App name")) + "</label><input name=\"appName\" placeholder=\"Game\">" +
                   "<label>" + Html(L("Путь к exe", "Exe path")) + "</label><input name=\"appPath\" placeholder=\"C:\\Games\\Game.exe\" required>" +
                   "<label>" + Html(L("Минуты", "Minutes")) + "</label><input name=\"minutes\" type=\"number\" min=\"1\" max=\"1440\" value=\"60\" required>" +
                   "<p><button type=\"submit\">" + Html(L("Разрешить временно", "Allow temporarily")) + "</button></p></form>" +
                   "</div>" +
                   "<h2>" + Html(L("Разрешённые приложения", "Allowed applications")) + "</h2>" + appList +
                   "<h2>" + Html(L("Лимиты времени", "Time limits")) + "</h2>" + RenderTimeLimits(_state.ActivitySettings, timeLimitStatus) +
                   "<h2>" + Html(L("Ежедневные задачи", "Daily tasks")) + "</h2>" + taskList +
                   "<h2>" + Html(L("Активность сегодня", "Today activity")) + "</h2>" + activityList +
                   "<form method=\"post\" action=\"/logout\" class=\"danger\"><button type=\"submit\">" + Html(L("Выйти", "Sign out")) + "</button></form>";
        }

        private static string AppModeButton(string text, string action)
        {
            return "<form method=\"post\" action=\"/command\" style=\"margin:0\">" +
                   "<input type=\"hidden\" name=\"action\" value=\"" + Html(action) + "\">" +
                   "<button type=\"submit\">" + Html(text) + "</button></form>";
        }

        private string RenderMaintenanceMode(GuardState state)
        {
            var maintenance = state.MaintenanceMode ?? new MaintenanceModeState();
            var status = FormatMaintenanceStatus(maintenance);
            if (maintenance.IsActive)
            {
                var until = maintenance.UntilUtc.HasValue
                    ? L("до ", "until ") + maintenance.UntilUtc.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm")
                    : L("активен", "active");
                return "<h2>" + Html(L("Режим обслуживания", "Maintenance mode")) + "</h2>" +
                       "<p><span class=\"badge\">" + Html(status) + "</span> <span class=\"badge\">" + Html(until) + "</span></p>" +
                       "<form method=\"post\" action=\"/command\" class=\"danger\">" +
                       "<input type=\"hidden\" name=\"action\" value=\"end-maintenance\">" +
                       "<button type=\"submit\">" + Html(L("Завершить обслуживание", "End maintenance now")) + "</button></form>";
            }

            return "<h2>" + Html(L("Режим обслуживания", "Maintenance mode")) + "</h2>" +
                   "<form method=\"post\" action=\"/command\" class=\"row\">" +
                   "<input type=\"hidden\" name=\"action\" value=\"start-maintenance\">" +
                   "<div style=\"flex:1\"><label>" + Html(L("Минуты полного доступа", "Unlock all minutes")) + "</label><input name=\"minutes\" type=\"number\" min=\"1\" max=\"480\" value=\"30\" required></div>" +
                   "<button type=\"submit\">" + Html(L("Временно открыть всё", "Unlock all temporarily")) + "</button></form>";
        }

        private string RenderApplication(AllowedApplication app)
        {
            var until = app.AllowedUntilUtc.HasValue
                ? L("до ", "until ") + Html(app.AllowedUntilUtc.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm"))
                : L("всегда", "always");
            var expired = app.AllowedUntilUtc.HasValue && app.AllowedUntilUtc.Value <= DateTime.UtcNow
                ? L(" истекло", " expired")
                : "";

            return "<div class=\"app\">" +
                   "<strong>" + Html(app.DisplayName) + "</strong> <span class=\"badge\">" + until + Html(expired) + "</span>" +
                   "<div class=\"path\">" + Html(app.FilePath) + "</div>" +
                   "<form method=\"post\" action=\"/command\">" +
                   "<input type=\"hidden\" name=\"action\" value=\"remove-app\">" +
                   "<input type=\"hidden\" name=\"appPath\" value=\"" + Html(app.FilePath) + "\">" +
                   "<button type=\"submit\">" + Html(L("Удалить", "Remove")) + "</button></form></div>";
        }

        private string RenderAccountHardening(GuardState state)
        {
            var selectedUser = state.ChildWindowsUserName ?? "";
            var shownUser = string.IsNullOrWhiteSpace(selectedUser) ? Environment.UserName : selectedUser;
            var status = string.IsNullOrWhiteSpace(selectedUser)
                ? new AccountHardeningStatus
                {
                    ChildUserName = "",
                    CouldReadAdministrators = true,
                    Reason = L("Сначала выберите детского пользователя Windows.", "Select the child Windows user first.")
                }
                : AccountHardeningEngine.BuildLocalStatus(selectedUser);

            var adminList = status.AdministratorUsers.Any()
                ? "<p class=\"muted\">" + Html(L("Администраторы", "Administrators")) + ": " + Html(string.Join(", ", status.AdministratorUsers)) + "</p>"
                : "";
            var demoteButton = status.CanDemoteChild
                ? "<form method=\"post\" action=\"/command\" class=\"danger\">" +
                  "<input type=\"hidden\" name=\"action\" value=\"demote-child-user\">" +
                  "<input type=\"hidden\" name=\"childUser\" value=\"" + Html(selectedUser) + "\">" +
                  "<button type=\"submit\">" + Html(L("Сделать ребёнка обычным пользователем", "Convert child to standard user")) + "</button></form>"
                : "";

            return "<form method=\"post\" action=\"/command\" class=\"row\">" +
                   "<input type=\"hidden\" name=\"action\" value=\"set-child-user\">" +
                   "<div style=\"flex:1\"><label>" + Html(L("Детский пользователь Windows", "Child Windows user")) + "</label><input name=\"childUser\" value=\"" + Html(shownUser) + "\" required></div>" +
                   "<button type=\"submit\">" + Html(L("Сохранить пользователя", "Save user")) + "</button></form>" +
                   "<p><span class=\"badge\">" + Html(DisplayMessage(status.Reason)) + "</span></p>" +
                   adminList +
                   demoteButton;
        }

        private string RenderAccessRequest(AccessRequest request)
        {
            var requestedAt = request.RequestedAtUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
            var type = request.Type == AccessRequestType.Application ? L("Приложение", "Application") : L("Сайт", "Website");
            return "<div class=\"request\">" +
                   "<strong>" + Html(request.DisplayName) + "</strong> <span class=\"badge\">" + Html(type) + "</span>" +
                   "<div class=\"path\">" + Html(request.Target) + "</div>" +
                   "<p class=\"muted\">" + Html(L("Запрошено", "Requested")) + " " + Html(requestedAt) +
                   " · " + Html(L("попыток", "attempts")) + ": " + request.AttemptCount +
                   (string.IsNullOrWhiteSpace(request.Source) ? "" : " · " + Html(L("источник", "source")) + ": " + Html(request.Source)) +
                   "</p>" +
                   "<div class=\"actions\">" +
                   RequestActionButton(request.Id, "approve-request-15", L("15 мин", "15 min")) +
                   RequestActionButton(request.Id, "approve-request-60", L("60 мин", "60 min")) +
                   RequestActionButton(request.Id, "approve-request-always", L("Всегда", "Always")) +
                   RequestActionButton(request.Id, "deny-request", L("Отклонить", "Deny"), danger: true) +
                   "</div></div>";
        }

        private string RenderSiteGrant(DomainAccessGrant grant, ActivitySettings settings)
        {
            var until = grant.IsPermanent || !grant.AllowedUntilUtc.HasValue
                ? L("всегда", "always")
                : L("до ", "until ") + Html(grant.AllowedUntilUtc.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm"));
            var rule = settings?.SiteRules?.FirstOrDefault(item =>
                string.Equals(
                    DomainAccessGrantApplier.NormalizeDomainInput(item.Domain),
                    grant.Domain,
                    StringComparison.OrdinalIgnoreCase));
            var category = rule?.Category ?? ActivityCategory.Video;
            var countsAsScreenTime = rule?.CountsAsScreenTime ?? true;
            var name = rule != null && !string.IsNullOrWhiteSpace(rule.DisplayName)
                ? rule.DisplayName
                : grant.DisplayName;

            return "<div class=\"request\">" +
                   "<strong>" + Html(name) + "</strong> <span class=\"badge\">" + Html(until) + "</span>" +
                   "<div class=\"path\">" + Html(grant.Domain) + "</div>" +
                   RenderSiteCategoryForm(grant.Domain, name, category, countsAsScreenTime) +
                   "<form method=\"post\" action=\"/command\" class=\"danger\">" +
                   "<input type=\"hidden\" name=\"action\" value=\"remove-site-grant\">" +
                   "<input type=\"hidden\" name=\"domain\" value=\"" + Html(grant.Domain) + "\">" +
                   "<button type=\"submit\">" + Html(L("Отозвать", "Revoke")) + "</button></form></div>";
        }

        private string RenderActivityUsage(ActivityUsageEntry entry)
        {
            if (ActivityAccountingEngine.IsSiteActivityKey(entry.FilePath))
            {
                var domain = ActivityAccountingEngine.GetDomainFromSiteActivityKey(entry.FilePath);
                return "<div class=\"app\">" +
                       "<strong>" + Html(entry.DisplayName) + "</strong> " +
                       "<span class=\"badge\">" + Html(CategoryText(entry.Category)) + "</span> " +
                       "<span class=\"badge\">" + Html(FormatDuration(entry.ActiveSeconds)) + "</span>" +
                       "<div class=\"path\">" + Html(domain) + "</div>" +
                       RenderSiteCategoryForm(domain, entry.DisplayName, entry.Category, entry.CountsAsScreenTime) +
                       "</div>";
            }

            return "<div class=\"app\">" +
                   "<strong>" + Html(entry.DisplayName) + "</strong> " +
                   "<span class=\"badge\">" + Html(CategoryText(entry.Category)) + "</span> " +
                   "<span class=\"badge\">" + Html(FormatDuration(entry.ActiveSeconds)) + "</span>" +
                   "<div class=\"path\">" + Html(entry.FilePath) + "</div>" +
                   "<form method=\"post\" action=\"/command\" class=\"row\">" +
                   "<input type=\"hidden\" name=\"action\" value=\"set-app-category\">" +
                   "<input type=\"hidden\" name=\"appPath\" value=\"" + Html(entry.FilePath) + "\">" +
                   "<input type=\"hidden\" name=\"appName\" value=\"" + Html(entry.DisplayName) + "\">" +
                   "<div style=\"flex:1\"><label>" + Html(L("Категория", "Category")) + "</label><select name=\"category\">" +
                   RenderCategoryOptions(entry.Category) +
                   "</select></div>" +
                   "<label><input type=\"checkbox\" name=\"countsScreenTime\"" + (entry.CountsAsScreenTime ? " checked" : "") + "> " + Html(L("Экранное время", "Screen time")) + "</label>" +
                   "<button type=\"submit\">" + Html(L("Сохранить", "Save")) + "</button></form></div>";
        }

        private string RenderSiteCategoryForm(string domain, string displayName, ActivityCategory selected, bool countsAsScreenTime)
        {
            return "<form method=\"post\" action=\"/command\" class=\"row\">" +
                   "<input type=\"hidden\" name=\"action\" value=\"set-site-category\">" +
                   "<input type=\"hidden\" name=\"domain\" value=\"" + Html(domain) + "\">" +
                   "<input type=\"hidden\" name=\"siteName\" value=\"" + Html(displayName) + "\">" +
                   "<div style=\"flex:1\"><label>" + Html(L("Категория", "Category")) + "</label><select name=\"category\">" +
                   RenderCategoryOptions(selected) +
                   "</select></div>" +
                   "<label><input type=\"checkbox\" name=\"countsScreenTime\"" + (countsAsScreenTime ? " checked" : "") + "> " + Html(L("Экранное время", "Screen time")) + "</label>" +
                   "<button type=\"submit\">" + Html(L("Сохранить", "Save")) + "</button></form>";
        }

        private string RenderTimeLimits(ActivitySettings settings, TimeLimitStatus status)
        {
            var dailyMinutes = settings?.DailyScreenTimeLimitMinutes ?? 0;
            var screenBadge = status.DailyScreenTimeLimitSeconds > 0
                ? FormatDuration(status.DailyScreenTimeUsedSeconds) + " / " + FormatDuration(status.DailyScreenTimeLimitSeconds)
                : FormatDuration(status.DailyScreenTimeUsedSeconds) + " " + L("использовано", "used");
            var categoryRows = status.Categories.Any()
                ? string.Join("", status.Categories.Select(item =>
                    "<p><span class=\"badge\">" + Html(CategoryText(item.Category)) + "</span> " +
                    Html(FormatDuration(item.UsedSeconds) + " / " + FormatDuration(item.DailyLimitSeconds)) +
                    (item.IsExceeded ? " <span class=\"badge\">" + Html(L("лимит исчерпан", "limit reached")) + "</span>" : "") +
                    "</p>"))
                : "<p class=\"muted\">" + Html(L("Лимиты по категориям пока не заданы.", "No category limits set.")) + "</p>";

            return "<p>" + Html(L("Экранное время", "Screen time")) + ": <span class=\"badge\">" + Html(screenBadge) + "</span></p>" +
                   "<form method=\"post\" action=\"/command\" class=\"row\">" +
                   "<input type=\"hidden\" name=\"action\" value=\"set-daily-screen-limit\">" +
                   "<div style=\"flex:1\"><label>" + Html(L("Минут экранного времени в день, 0 = выключено", "Daily screen minutes, 0 = off")) + "</label><input name=\"minutes\" type=\"number\" min=\"0\" max=\"1440\" value=\"" + dailyMinutes + "\" required></div>" +
                   "<button type=\"submit\">" + Html(L("Сохранить", "Save")) + "</button></form>" +
                   categoryRows +
                   "<form method=\"post\" action=\"/command\" class=\"row\">" +
                   "<input type=\"hidden\" name=\"action\" value=\"set-category-limit\">" +
                   "<div style=\"flex:1\"><label>" + Html(L("Категория", "Category")) + "</label><select name=\"category\">" +
                   RenderCategoryOptions(ActivityCategory.Video) +
                   "</select></div>" +
                   "<div style=\"flex:1\"><label>" + Html(L("Минут в день", "Daily minutes")) + "</label><input name=\"dailyMinutes\" type=\"number\" min=\"0\" max=\"1440\" value=\"60\" required></div>" +
                   "<div style=\"flex:1\"><label>" + Html(L("Минут за раз", "Session minutes")) + "</label><input name=\"sessionMinutes\" type=\"number\" min=\"0\" max=\"1440\" value=\"15\" required></div>" +
                   "<button type=\"submit\">" + Html(L("Сохранить", "Save")) + "</button></form>";
        }

        private string RenderDailyTasks(GuardState state)
        {
            var tasks = DailyTaskEngine.GetActiveTasks(state);
            var list = tasks.Any()
                ? string.Join("", tasks.Select(RenderDailyTask))
                : "<p class=\"muted\">" + Html(L("Ежедневных задач пока нет.", "No daily tasks yet.")) + "</p>";

            return list +
                   "<div class=\"split\">" +
                   "<form method=\"post\" action=\"/command\">" +
                   "<input type=\"hidden\" name=\"action\" value=\"add-self-task\">" +
                   "<label>" + Html(L("Задача по честному отчёту", "Self-report task")) + "</label><input name=\"title\" placeholder=\"" + Html(L("10 приседаний", "10 squats")) + "\" required>" +
                   "<label>" + Html(L("Минут награды", "Reward minutes")) + "</label><input name=\"rewardMinutes\" type=\"number\" min=\"0\" max=\"1440\" value=\"10\" required>" +
                   "<label>" + Html(L("Категория награды", "Reward category")) + "</label><select name=\"rewardCategory\">" + RenderCategoryOptions(ActivityCategory.Game) + "</select>" +
                   "<p><button type=\"submit\">" + Html(L("Добавить задачу", "Add task")) + "</button></p></form>" +
                   "<form method=\"post\" action=\"/command\">" +
                   "<input type=\"hidden\" name=\"action\" value=\"add-verified-task\">" +
                   "<label>" + Html(L("Задача с проверкой приложения", "Verified app task")) + "</label><input name=\"title\" placeholder=\"" + Html(L("Симулятор дрона", "Drone simulator")) + "\" required>" +
                   "<label>" + Html(L("Путь к exe", "Exe path")) + "</label><input name=\"appPath\" placeholder=\"C:\\Games\\DroneSim.exe\" required>" +
                   "<label>" + Html(L("Нужно активных минут", "Required active minutes")) + "</label><input name=\"requiredMinutes\" type=\"number\" min=\"1\" max=\"1440\" value=\"15\" required>" +
                   "<label>" + Html(L("Категория задачи", "Task category")) + "</label><select name=\"category\">" + RenderCategoryOptions(ActivityCategory.UsefulTraining) + "</select>" +
                   "<label>" + Html(L("Минут награды", "Reward minutes")) + "</label><input name=\"rewardMinutes\" type=\"number\" min=\"0\" max=\"1440\" value=\"10\" required>" +
                   "<label>" + Html(L("Категория награды", "Reward category")) + "</label><select name=\"rewardCategory\">" + RenderCategoryOptions(ActivityCategory.Game) + "</select>" +
                   "<p><button type=\"submit\">" + Html(L("Добавить задачу", "Add task")) + "</button></p></form>" +
                   "</div>";
        }

        private string RenderDailyTask(DailyTask task)
        {
            var detail = task.Type == DailyTaskType.SelfReport
                ? L("честный отчёт", "self-report")
                : L("проверяется ", "verified ") + task.RequiredActiveMinutes + " " + L("мин", "min");
            return "<div class=\"app\">" +
                   "<strong>" + Html(task.Title) + "</strong> " +
                   "<span class=\"badge\">" + Html(detail) + "</span> " +
                   "<span class=\"badge\">+" + task.RewardMinutes + " " + Html(L("мин", "min")) + " " + Html(CategoryText(task.RewardCategory)) + "</span>" +
                   (string.IsNullOrWhiteSpace(task.ApplicationPath) ? "" : "<div class=\"path\">" + Html(task.ApplicationPath) + "</div>") +
                   "</div>";
        }

        private string RenderCategoryOptions(ActivityCategory selected)
        {
            var values = new[]
            {
                ActivityCategory.Uncategorized,
                ActivityCategory.Study,
                ActivityCategory.Video,
                ActivityCategory.Game,
                ActivityCategory.UsefulTraining,
                ActivityCategory.Communication,
                ActivityCategory.System
            };

            return string.Join("", values.Select(value =>
                "<option value=\"" + Html(value.ToString()) + "\"" +
                (value == selected ? " selected" : "") +
                ">" + Html(CategoryText(value)) + "</option>"));
        }

        private string FormatDuration(int seconds)
        {
            var minutes = Math.Max(0, (int)Math.Round(seconds / 60.0));
            if (minutes < 60)
            {
                return minutes + " " + L("мин", "min");
            }

            return (minutes / 60) + " " + L("ч", "h") + " " + (minutes % 60) + " " + L("мин", "min");
        }

        private static string RequestActionButton(string requestId, string action, string text, bool danger = false)
        {
            return "<form method=\"post\" action=\"/command\"" + (danger ? " class=\"danger\"" : "") + ">" +
                   "<input type=\"hidden\" name=\"action\" value=\"" + Html(action) + "\">" +
                   "<input type=\"hidden\" name=\"requestId\" value=\"" + Html(requestId) + "\">" +
                   "<button type=\"submit\">" + Html(text) + "</button></form>";
        }

        private string Header(string title, string message)
        {
            return "<h1>" + Html(title) + "</h1>" +
                   (string.IsNullOrWhiteSpace(message) ? "" : "<p class=\"msg\">" + Html(DisplayMessage(message)) + "</p>");
        }

        private string FormatTaskManagerStatus(ApplicationControlSettings settings)
        {
            var utcNow = DateTime.UtcNow;
            if (settings != null &&
                settings.BlockTaskManager &&
                settings.TaskManagerAllowedUntilUtc.HasValue &&
                settings.TaskManagerAllowedUntilUtc.Value > utcNow)
            {
                return L("Диспетчер задач и системные инструменты разрешены до ",
                         "Task Manager and system tools are allowed until ") +
                       settings.TaskManagerAllowedUntilUtc.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
            }

            if (ApplicationControlApplier.IsTaskManagerBlocked(settings, utcNow))
            {
                return L("Диспетчер задач и системные инструменты заблокированы",
                         "Task Manager and system tools are blocked");
            }

            return L("Диспетчер задач и системные инструменты разрешены",
                     "Task Manager and system tools are allowed");
        }

        private string FormatMaintenanceStatus(MaintenanceModeState maintenance)
        {
            if (maintenance == null || !maintenance.IsActive)
            {
                return L("режим защиты", "protection mode");
            }

            if (!maintenance.UntilUtc.HasValue)
            {
                return L("режим обслуживания активен", "maintenance mode active");
            }

            var remaining = maintenance.UntilUtc.Value - DateTime.UtcNow;
            if (remaining <= TimeSpan.Zero)
            {
                return L("режим обслуживания завершается", "maintenance mode expiring");
            }

            var minutesLeft = Math.Max(1, (int)Math.Ceiling(remaining.TotalMinutes));
            return L("режим обслуживания, осталось ", "maintenance mode, ") +
                   minutesLeft +
                   L(" мин", " min left");
        }

        private string CategoryText(ActivityCategory category)
        {
            switch (category)
            {
                case ActivityCategory.Study:
                    return L("Учёба", "Study");
                case ActivityCategory.Video:
                    return L("Видео", "Video");
                case ActivityCategory.Game:
                    return L("Игры", "Game");
                case ActivityCategory.UsefulTraining:
                    return L("Полезное обучение", "Useful training");
                case ActivityCategory.Communication:
                    return L("Общение", "Communication");
                case ActivityCategory.System:
                    return L("Система", "System");
                default:
                    return L("Без категории", "Uncategorized");
            }
        }

        private string DisplayMessage(string message)
        {
            if (!UiLanguage.IsRussian(Language))
            {
                return message;
            }

            switch (message)
            {
                case "Cabinet is already configured.":
                    return "Кабинет уже настроен.";
                case "Pairing code is invalid or expired.":
                    return "Код привязки неверный или истёк.";
                case "Passwords do not match.":
                    return "Пароли не совпадают.";
                case "Password must be at least 12 characters.":
                    return "Пароль должен быть не короче 12 символов.";
                case "Cabinet configured.":
                    return "Кабинет настроен.";
                case "Signed in.":
                    return "Вход выполнен.";
                case "Wrong password.":
                    return "Неверный пароль.";
                case "Signed out.":
                    return "Вы вышли.";
                case "Please sign in first.":
                    return "Сначала войдите в кабинет.";
                case "Parent password is required for this action.":
                    return "Для этого действия нужен пароль родителя.";
                case "Wrong parent password.":
                    return "Неверный пароль родителя.";
                case "Unknown command.":
                    return "Неизвестная команда.";
                case "Saved.":
                    return "Сохранено.";
                case "Nothing changed.":
                    return "Ничего не изменилось.";
                case "Invalid domain.":
                    return "Неверный домен.";
                case "Invalid PIN.":
                    return "Неверный PIN.";
                case "Sync status is missing.":
                    return "Не указан статус блокировки.";
                case "Invalid application control mode.":
                    return "Неверный режим контроля приложений.";
                case "Activity category is missing.":
                    return "Не выбрана категория активности.";
                case "Task type is missing.":
                    return "Не выбран тип задачи.";
                case "Child Windows user is missing.":
                    return "Не указан детский пользователь Windows.";
                case "Maintenance mode must be from 1 to 480 minutes.":
                    return "Режим обслуживания можно включить на 1-480 минут.";
                case "Select the child Windows user first.":
                    return "Сначала выберите детского пользователя Windows.";
                case "No unknown Windows users detected.":
                    return "Неизвестные пользователи Windows не найдены.";
                case "Could not read local Windows users.":
                    return "Не удалось прочитать локальных пользователей Windows.";
                case "Could not read local administrators.":
                    return "Не удалось прочитать локальных администраторов.";
                case "No separate trusted administrator account is available.":
                    return "Нет отдельной доверенной учётной записи администратора.";
                case "Windows user name is not safe.":
                    return "Имя пользователя Windows небезопасно.";
                case "Windows user was not found.":
                    return "Пользователь Windows не найден.";
                case "Windows user cannot be disabled safely.":
                    return "Этого пользователя Windows нельзя безопасно отключить.";
                case "Windows user cannot be removed from administrators safely.":
                    return "Этого пользователя Windows нельзя безопасно убрать из администраторов.";
                default:
                    return message;
            }
        }

        private void SignIn(HttpListenerContext context)
        {
            var token = NewToken();
            lock (_sessions) _sessions.Add(token, DateTime.UtcNow);
            context.Response.Headers.Add("Set-Cookie", $"{SessionCookieName}={token}; Path=/; Max-Age=300; HttpOnly; SameSite=Strict");
        }

        private bool IsSignedIn(HttpListenerContext context)
        {
            var token = GetSessionToken(context);
            if (string.IsNullOrEmpty(token)) return false;
            lock (_sessions) return _sessions.IsValid(token!, DateTime.UtcNow);
        }

        private static string? GetSessionToken(HttpListenerContext context)
        {
            return context.Request.Cookies[SessionCookieName]?.Value;
        }

        private static async Task<Dictionary<string, string>> ReadForm(HttpListenerRequest request)
        {
            using (var reader = new System.IO.StreamReader(request.InputStream, request.ContentEncoding ?? Encoding.UTF8))
            {
                var body = await reader.ReadToEndAsync();
                return body.Split('&')
                    .Where(part => part.Length > 0)
                    .Select(part => part.Split(new[] { '=' }, 2))
                    .ToDictionary(
                        parts => WebUtility.UrlDecode(parts[0] ?? "") ?? "",
                        parts => parts.Length > 1 ? WebUtility.UrlDecode(parts[1] ?? "") ?? "" : "");
            }
        }

        private static void WriteHtml(HttpListenerContext context, string html)
        {
            context.Response.ContentType = "text/html; charset=utf-8";
            WriteBytes(context, Encoding.UTF8.GetBytes(html));
        }

        private static void WriteText(HttpListenerContext context, string text)
        {
            context.Response.ContentType = "text/plain; charset=utf-8";
            WriteBytes(context, Encoding.UTF8.GetBytes(text));
        }

        private static void WriteBytes(HttpListenerContext context, byte[] bytes)
        {
            context.Response.ContentLength64 = bytes.Length;
            context.Response.OutputStream.Write(bytes, 0, bytes.Length);
            context.Response.OutputStream.Close();
        }

        private static string Get(Dictionary<string, string> form, string key)
        {
            return form.TryGetValue(key, out var value) ? value : "";
        }

        private static int ParseInt(string value)
        {
            return int.TryParse(value, out var result) ? result : 0;
        }

        private static ActivityCategory? ParseActivityCategory(string value)
        {
            return Enum.TryParse<ActivityCategory>(value, ignoreCase: true, out var category)
                ? category
                : (ActivityCategory?)null;
        }

        private static string Html(string? value)
        {
            return WebUtility.HtmlEncode(value ?? "");
        }

        private static string NewToken()
        {
            var bytes = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }
            return Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');
        }

        private static List<string> GetLanUrls(int port)
        {
            var urls = new List<string> { $"http://localhost:{port}/" };
            try
            {
                var host = Dns.GetHostName();
                foreach (var ip in Dns.GetHostAddresses(host)
                    .Where(ip => ip.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(ip)))
                {
                    urls.Add($"http://{ip}:{port}/");
                }
            }
            catch
            {
            }

            return urls.Distinct().ToList();
        }
    }
}
