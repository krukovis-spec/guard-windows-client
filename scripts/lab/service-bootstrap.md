# Проверка настоящей службы в disposable VM

Это тест M0/M3, **не installer v2 для семьи и не проверка M1**. Он нужен до полноценного мастера установки: впервые проверить настоящий SCM/LocalSystem, системное хранилище, административный pipe, снятие одноразового startup flag и сохранение identity после обычного перезапуска службы.

## Границы

- Единственная цель: `GuardV2-Lab-20260930`, VM ID `8f088b63-9193-4ecc-bb20-415ef11fd4c8`, BIOS UUID `236ea6ef-9cc6-4295-9934-6f7497f9d262`, 80 GB-диск внутри `%LOCALAPPDATA%\GuardV2Lab\VM\Virtual Hard Disks`, Gen2/Secure Boot/vTPM. Внутри снова проверяются UUID, Hyper-V manufacturer/model, имя не совпадает с хостом и elevated administrator.
- На хосте только Hyper-V/PowerShell Direct, публикация временного пакета и результат в `GuardV2Lab\Access`. Права администратора нужны для Hyper-V. Служба Guard, политики, firewall, hosts и аккаунты хоста не изменяются. Не перезапускает хост и не включает выключенную VM автоматически.
- Отказывается перезаписывать существующую службу `Guard`, папки Guard в Program Files/ProgramData. Наличие защищённой папки проверяется через её доступного родителя, а не интерпретируется как отсутствие при запрете чтения самой папки.
- Пакет содержит test-only origin `https://guard-lab.invalid` и фиктивный публичный signer pin. Ни сетевой привязки, ни административного relay-токена, ни реального телефонного ключа здесь нет. Он никогда не применяется как семейный release.
- До любых гостевых изменений создаётся новый снимок текущего состояния. После теста, включая ошибку, выполняются мягкое выключение только закреплённой VM, восстановление **этого** снимка, загрузка и проверка отсутствия новых Guard-файлов/службы. Только после подтверждения восстановления тестовый снимок удаляется; исходный `clean-windows-20260930` не удаляется. При неудаче recovery скрипт сообщает FAIL и сохраняет снимок; принудительного выключения нет.

## Запуск

1. Обычный терминал: `scripts/lab/Build-ServiceLabPackage.ps1`. Он публикует self-contained service/probe в новую папку `%TEMP%\GuardServiceLab-<guid>`, создаёт manifest всех файлов и возвращает путь/его SHA256. Не запускает Guard. `win-x64` restore может обновить RID-раздел существующего NuGet lock; версии зависимостей не меняются.
2. После проверки безопасности и подтверждения UAC запустить `Invoke-ServiceBootstrapLab.ps1 -PackageRoot <этот-путь> -ManifestSha256 <этот-хеш>` в повышенном PowerShell. Секреты не передаются аргументами: используется уже сохранённая user-DPAPI гостевая учётная запись из `Access\guest-credential.xml`; пароль не выводится и не сохраняется повторно. Нет очереди произвольных повышенных команд.
3. Проверить **новый** `Access\service-bootstrap-<runId>.json`: нужны `Status=PASS`, `Experiment.Status=PASS`, одинаковые descriptor SHA256 до/после рестарта и `SnapshotRecovery=BOOT_VERIFIED`. Код процесса тоже должен быть 0. Старые отчёты/тайм-аут наблюдения не доказывают завершение; проверять исходный процесс.
4. После завершения удалить только собственную проверенную временную папку пакета; не удалять чужие файлы/VM/основной recovery snapshot. При отменённом UAC гостевые изменения не начинаются, отчёт эксперимента не создаётся.

Guest сначала проверяет pinned manifest и каждый файл; потом создаёт normal own-process automatic LocalSystem service с одноразовым initialization flag. `WaitNamedPipe` здесь только ждёт появления endpoint; **аутентификацию** выполняет настоящий `GuardSetupQueryClient`. При наличии bootstrap flag клиент обязан отказать. После stop/изменения SCM path/normal start тот же клиент и `SetupInspection` проверяют состояние/ACL и public export; второй normal restart обязан сохранить точное описание.

Смена `PathName` использует CIM, а не fragile nested quotes в `sc.exe` под Windows PowerShell 5.1. Другие настройки/права/политики не меняются. У лабораторной регистрации обычный service DACL: это не защита от остановки администратором, не M8 и не повод показывать Protected.

## Безопасные проверки без VM

`scripts/lab/Test-LabSafety.ps1` парсит все скрипты и проверяет отказ guest-скриптов на хосте **до установки/доступа к пакетам**. Обычный `Guard.Windows.Ipc.Tests` не включает live-mode. Только явный `--installed-service-lab inspect|reject-bootstrap` включает read-only проверку установленной службы, дополнительно требуя имя лабораторного guest и elevated administrator; по умолчанию safe suite остаётся прежней. При запуске этого режима на хосте ожидается exit 1 до IPC.

На 01.10.2026: self-contained package/manifest (439 файлов), safe host guards и обычный IPC harness проверены. Первый запрос UAC завершился отменой до получения PID, без гостевого отчёта; реальное выполнение и восстановление этим новым маршрутом **NOT RUN**. Экран WPF, диалог сохранения, реальная биометрия и M1 остаются отдельными gates.

Основа маршрута: [Microsoft PowerShell Direct](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/powershell-direct), [WaitNamedPipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-waitnamedpipew), [CIM Win32_Service.Change](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/change-method-in-class-win32-service).
