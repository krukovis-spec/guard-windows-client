# Guard Windows Client - инструкции для Codex

## Контекст проекта

- Корень проекта: `C:\Yandex.Disk\Projects\guard-windows-client`.
- Это open-source Windows-клиент Guard под `.NET Framework 4.8`.
- Текущий upstream: `https://github.com/ganjie/guard-windows-client.git`, ветка `main`.
- Проект сейчас является клиентом сервиса `https://guard.alexweb.app`, а не полностью автономным parental-control приложением.

## Как работать с Иваном

- Отвечать по-русски, коротко и по делу.
- Иван не программист: объяснять развилки простыми словами и рекомендовать лучший следующий шаг.
- Перед существенными изменениями давать короткий план с проверкой результата.
- Если нужна установка Visual Studio Build Tools, Inno Setup, NuGet-пакетов или запуск приложения с правами администратора - сначала явно спросить.

## Обязательный preflight для будущего Codex

1. Прочитать этот `AGENTS.md`.
2. Прочитать `.codex/memory/project.md`, если он есть.
3. Открыть глобальную wiki-карту инструментов:
   `C:\Yandex.Disk\knowledge-base\my_knowledge_base\wiki\concepts\Codex-plugins-stack.md`.
4. Так как это Windows desktop-проект, открыть:
   `C:\Yandex.Disk\knowledge-base\my_knowledge_base\wiki\concepts\windows-desktop-patterns.md`.
5. Проверить текущий git status:
   ```powershell
   $git='C:\Users\kruko\AppData\Local\GitHubDesktop\app-3.5.8\resources\app\git\cmd\git.exe'
   & $git -C 'C:\Yandex.Disk\Projects\guard-windows-client' status -sb
   ```

## Архитектура

- `guard.sln` - solution Visual Studio 2022.
- `guard/` - основное WinForms/tray-приложение, формы, синхронизация с API, применение правил.
- `Guard.Core/` - общие модели, состояние, DPAPI storage, scheduled task, cleanup helpers.
- `Guard.Cleaner/` - uninstaller/cleanup/PIN flow.
- `GuardStartHelper/` - helper для автозапуска/watchdog.
- `GuardInstaller.iss` - Inno Setup installer.
- `Output/Guard-Setup-v1.0.0.exe` - готовый upstream installer, не считать исходником.

## Опасные зоны

Не запускать без отдельного подтверждения Ивана и желательно без VM:

- `Output\Guard-Setup-v1.0.0.exe`
- `Guard.Cleaner.exe`
- `StartHelperG.exe`
- собранный `guard.exe`
- любые команды/код, которые меняют `hosts`, firewall, scheduled tasks или registry.

Почему: приложение требует admin-права и может менять:

- `C:\Windows\System32\drivers\etc\hosts`
- Windows Firewall rules с префиксами `GuardBlock-Cat`, `GuardBlock-Ads`, `GuardBlock-Ads-Batch-`, `GuardBlock-Rules`
- scheduled task `Helper Start Up Task for guard`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\GuardHelper`
- DPAPI state files:
  - `%APPDATA%\Guard\state.dat`
  - `%USERPROFILE%\Documents\Guard\state.dat`
  - `%WINDIR%\System32\drivers\etc\savedBU\state.dat`
- disable flag `session.lock` рядом с exe.

Для тестов и ревью системные действия мокать/оборачивать интерфейсами. Не проверять их на живой системе Ивана.

## Сборка

Проект смешанный:

- `guard/guard.csproj` и `Guard.Core/Guard.Core.csproj` - SDK-style `net48`.
- `Guard.Cleaner` и `GuardStartHelper` - старые `.csproj` `ToolsVersion=15.0`.

На 2026-06-06 на ПК обнаружены:

- `C:\Program Files\dotnet\dotnet.exe` - есть, .NET SDK `8.0.421`.
- `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe` - есть, версия `4.8.9221.0`.
- Visual Studio 2022 Build Tools MSBuild - не найден.
- .NET Framework 4.8 reference assemblies / Developer Pack - не найдены; `dotnet msbuild guard.sln /p:Configuration=Release /p:Platform="Any CPU"` падает с `MSB3644`.
- Inno Setup найден: `C:\Users\kruko\AppData\Local\Programs\Inno Setup 6\ISCC.exe`.

Рекомендуемый путь:

1. Сначала пробовать открыть `guard.sln` в Visual Studio 2022 или Build Tools с workload `.NET desktop development`.
2. Если нужен CLI, сначала проверить без запуска приложения:
   ```powershell
   Set-Location 'C:\Yandex.Disk\Projects\guard-windows-client'
   dotnet msbuild guard.sln /restore /p:Configuration=Release /p:Platform="Any CPU"
   ```
3. Если `dotnet msbuild` падает на старых `.csproj` или reference assemblies - поставить Visual Studio Build Tools или .NET Framework 4.8 Developer Pack, а не чинить код вслепую.
4. Инсталлятор собирать только после успешной Release-сборки и отдельной проверки `GuardInstaller.iss`.

## Текущие внешние зависимости и привязки

Жестко зашитые внешние URL:

- `https://guard.alexweb.app/api/device/assign` в `guard/AssignForm.cs`
- `https://guard.alexweb.app/checker/ping` в `guard/DeviceUpdater.cs`
- trusted time APIs в `guard/TrueTimeHelper.cs`

Если Иван хочет "под себя", сначала выбрать стратегию:

1. Оставить клиентом `guard.alexweb.app` - меньше разработки, но зависимость от чужого сервера.
2. Сделать свой сервер/API - больше работы, зато контроль данных.
3. Сделать локальный режим без сервера - лучший первый MVP для Ивана, если цель домашний parental control на одном ПК.

Моя рекомендация: начать с локального режима, потому что он меньше зависит от чужой инфраструктуры и проще проверяется в Codex. Не просто заменить URL: сначала вынести endpoint/config layer и режимы работы.

## Что допиливать первым

1. Зафиксировать базовую сборку: понять, чем проект реально собирается на ПК Ивана.
2. Добавить тестовый слой для чистой логики:
   - `InputSanitizer`
   - `ScheduleHelper` / `SchedulerEngine`
   - `RuleParser`
   - JSON parse models из `InstructionsModel`
3. Вынести системные действия (`hosts`, firewall, `schtasks`, registry, network reset) за интерфейсы, чтобы можно было тестировать без admin-прав.
4. Вынести API endpoints и time providers в настройки.
5. Только после этого менять UX, installer, PIN/uninstall flow и автозапуск.

## Кодовые правила

- Не делать большие рефакторинги до baseline build.
- Не форматировать соседние файлы без причины.
- Не логировать PIN, assign code, device id и сырые server payloads в новые логи.
- Любые строки, приходящие из API или локального config, валидировать перед использованием в `hosts`, `netsh`, `schtasks` или файловых путях.
- Не добавлять sleep/debounce "на всякий случай"; только под конкретную гонку.
- Для русских `.md` читать/писать UTF-8.

## Проверка перед финальным ответом

Минимальный gate после изменений:

1. `git status -sb`.
2. Сборка или честное объяснение, почему сборка не запускалась.
3. Для logic changes - тесты или маленький проверочный harness.
4. Для installer/system changes - не запускать на рабочей системе без подтверждения Ивана.
5. После существенной работы запустить `$project-memory` gate и обновить только полезную память.
