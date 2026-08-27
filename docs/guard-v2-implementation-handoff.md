# Guard v2: prompt для первой execution-сессии

Ниже находится канонический prompt для отдельного чата, который начинает реализацию Guard v2. Первый инкремент намеренно ограничен P0 containment и безопасной исходной точкой.

```text
Мы переходим из проектирования в исполнение Guard v2.

Рабочий проект:
C:\Yandex.Disk\Projects\guard-windows-client

Работай по-русски и соблюдай локальный AGENTS.md. Иван не программист, поэтому решения и блокеры объясняй простыми словами. Не возвращайся к повторному проектированию уже принятых требований без найденного технического противоречия.

Перед любым изменением application code прочитай полностью:
1. C:\Yandex.Disk\Projects\guard-windows-client\AGENTS.md
2. C:\Yandex.Disk\Projects\guard-windows-client\.codex\memory\project.md
3. C:\Yandex.Disk\Projects\guard-windows-client\docs\guard-v2-development-plan.md
4. C:\Yandex.Disk\Projects\guard-windows-client\.codex\review-loop\runs\guard-v2-security-ux-audit-20260722\report.md
5. C:\Yandex.Disk\Projects\guard-windows-client\docs\guard-v2-implementation-handoff.md

Режим этой сессии: исполнение. Канонический план уже одобрен. Цель первой сессии не «переписать весь Guard v2», а закончить первый безопасный инкремент: Guard v2 Foundation / P0 containment.

Обязательный preflight и GitHub checkpoint:
- Проверь branch, git status, remote и GitHub auth.
- Рабочее дерево уже содержит много более ранних изменений Guard. Считай их пользовательскими: не откатывай, не удаляй и не перезаписывай.
- Разберись, какие изменения являются проверенным текущим MVP baseline, а какие являются конфликтными копиями Яндекс.Диска, generated binaries или посторонними файлами.
- Безопасно проверь отсутствие secrets/private data, не печатая значения секретов.
- До первой правки application code создай и push отдельную checkpoint-ветку `codex/checkpoint-YYYYMMDD-HHMM-guard-v2-foundation` с доказанно относящимся к проекту baseline snapshot. Не включай конфликтные копии `*копия с компьютера LG*`, временные артефакты и секреты.
- Запиши checkpoint branch и commit SHA в canonical plan/worklog.
- Затем создай отдельную рабочую ветку `codex/guard-v2-foundation` из того же baseline.
- Если безопасно отделить baseline невозможно или remote/auth недоступны, не меняй application code. Задай Ивану один точный вопрос о блокере. Не соглашайся молча на local-only checkpoint.

Scope первой реализации:
1. Закрыть child-visible first-pairing takeover: детская сессия и первый сетевой клиент не должны получить возможность назначить родительский пароль или стать владельцем устройства. Пока новый passkey setup ceremony ещё не построен, непривязанный Guard должен fail closed, а опасное legacy provisioning не должно быть доступно ребёнку.
2. Полностью убрать известный fallback emergency PIN `123456`. Отсутствующий/неинициализированный родительский фактор означает отказ, а не дефолтный секрет. Disable, uninstall, cleaner и другие привилегированные пути обязаны fail closed.
3. Сохранить запрет email/SMS/TOTP recovery и server-driven PIN changes. Не добавлять новый PIN или секрет, показываемый на детском компьютере.
4. Проверить все пути, способные отключить Guard, сменить владельца, ослабить AppControl или удалить защиту. Они должны требовать доказанного родительского владения; незащищённые legacy-пути отключить.
5. Не строить облако, PWA, browser proxy и новую LocalSystem-службу в этом инкременте. Но изменения не должны усложнять их последующее добавление.
6. Добавить focused regression tests минимум для: first-caller takeover, unprovisioned device fail-closed, unset/default PIN rejection, cleaner/disable rejection, remote PIN rejection и отсутствия email-code recovery.
7. Обновить документацию текущего состояния: явно указать, какие возможности временно недоступны до нового безопасного provisioning.

Инженерные ограничения:
- Используй существующие паттерны и минимальный scope. Не делай общий рефакторинг.
- Все системные действия тестируй через mocks/interfaces. Не запускай guard.exe, installer, cleaner, helper, AppLocker, firewall, hosts, registry, scheduled tasks или account changes на живом компьютере.
- Не устанавливай Visual Studio Build Tools, Developer Pack, SDK или новые пакеты без прямого согласия Ивана.
- Не изменяй и не пересобирай Output/Guard-Setup-v1.0.0.exe в этой сессии.
- Не логируй PIN, pairing secret, recovery data, device id или raw payload.
- Делай небольшие связанные commits и push рабочей ветки после успешных gates.

Обязательные проверки:
- `dotnet msbuild guard.sln /restore /p:Configuration=Release /p:Platform="Any CPU"`
- `Guard.Tests\bin\Release\net48\Guard.Tests.exe`
- `git diff --check`
- Проверка отсутствия vulnerable NuGet packages, если доступна без установки новых инструментов.
- Self-review по всем P0-путям и повторный focused security review изменённого diff.

Готовность инкремента:
- ребёнок не может выполнить первичную привязку или назначить родительский пароль;
- значение `123456` и отсутствие PIN никогда не разрешают отключение/удаление;
- email/SMS/TOTP и legacy server payload не меняют родительскую аутентификацию;
- все regression tests и Release build проходят;
- checkpoint и рабочие commits доступны на GitHub;
- canonical plan, worklog и project memory обновлены фактическим результатом;
- никакие защитные политики не применялись к живой Windows Ивана.

После достижения этих gates остановись. Дай Ивану короткий отчёт: что закрыто, branch/commits, проверки, остаточные риски и следующий рекомендуемый инкремент (LocalSystem service boundary). Не начинай второй инкремент в этой же сессии без нового прямого указания.
```
