# Guard v2 Foundation: состояние P0 containment

Дата: 2026-07-22.

Этот инкремент временно закрывает небезопасный legacy control plane до появления новой `LocalSystem`-службы и passkey provisioning. Он не является полной реализацией Guard v2.

## Что теперь закрыто

- Непривязанный компьютер не запускает LAN-кабинет, не создаёт и не показывает код первой привязки и не позволяет первому сетевому клиенту назначить родительский пароль.
- Legacy Assign API, child-side pairing/email UI и remote updater отключены независимо от сохранённого `AllowLegacyRemoteServer`.
- Legacy telemetry/log sender также остаётся локальным и не отправляет `DeviceId` или сообщения на старый сервер.
- Email/SMS/TOTP, child-visible pairing code и legacy server payload не могут создать или восстановить родительское владение.
- Пустой PIN и известное значение `123456` всегда дают отказ. Значение по умолчанию больше не подставляется.
- Диагностическое окно больше не сбрасывает привязку, не отключает автозапуск и не завершает Guard. Кнопка закрытия закрывает только окно диагностики.
- Диагностический summary больше не выводит `AssignCode`, `DeviceId`, raw error log, rules, URLs, IPs и другие сырые части state.
- Удалены неавторизованные `CleanAndClose`, `ShutdownApplication`, boolean-bypass в `DisableApp` и destructive action в main loop.
- Cleaner не доверяет файлу `uninstall.ok`, не выполняет cleanup из legacy/direct режимов и не удаляет защиту автоматически после повторных ошибок запуска.
- Cleaner принимает только точный режим `/authorize-and-clean`, проверяет результат каждой стадии cleanup и возвращает ненулевой код при ошибке. Inno запускает destructive cleanup только на шаге `usUninstall`, после подтверждения удаления; ошибка запуска, авторизации или cleanup вызывает `Abort` до удаления binaries. Временный disable-флаг снимается и запрашивается восстановление Guard.
- Cleanup scheduled task различает присутствующую задачу, явно подтверждённое отсутствие и неоднозначную ошибку запроса. Access denied и неизвестный ненулевой результат дают отказ, а не ложный успех.

## Что временно недоступно

- новая первичная привязка;
- LAN-кабинет родителя, включая ранее настроенные экземпляры;
- привязка к `guard.alexweb.app` и получение правил со старого сервера;
- pairing по email и любые коды восстановления;
- reset/disable/startup controls из диагностического окна;
- удаление через `guard.exe /uninstall` или прямой запуск Cleaner.

До безопасного provisioning остаются только два legacy-маршрута, оба требуют уже сохранённый пользовательский шестизначный PIN, отличный от `123456`:

1. `Отключить Guard` в tray-меню.
2. Удаление через стандартный раздел Windows `Установленные приложения`; installer вызывает один режим Cleaner `authorize-and-clean` без промежуточного bearer-файла.

Если у старой установки PIN пустой или равен `123456`, Guard намеренно отказывает в отключении и удалении. Новый секрет на детском компьютере не создаётся. Миграция такой установки должна выполняться родителем из отдельной Windows admin account после появления безопасного recovery/migration flow; инструкции обхода в клиент не добавляются.

## Остаточные границы

- Защита ещё работает в интерактивном процессе и CurrentUser-хранилище; граница `LocalSystem` относится к следующему инкременту.
- Исходный legacy LAN-код пока сохранён для миграции, но запуск сервера дополнительно hard-disabled policy и отсутствует в startup path.
- Системное поведение installer/Cleaner должно проверяться только в disposable Windows VM. В этой сессии Guard, Cleaner, installer, helper и Windows-политики не запускались.
- Cleanup системных политик не является транзакцией: при сбое возможен частичный результат. P0 не сообщает ложный успех и не удаляет binaries, но полный rollback и lifecycle-проверка остаются VM-gate.
- Существующий generated installer в `Output` не изменялся и не пересобирался.

## Проверка

- Application commit: `3e7e384d26864a5976da85652f160e0dd7da67ab`.
- Release build: пройден.
- Safe logic harness: 45/45 checks пройдены.
- Focused P0 tests: first-caller takeover, unprovisioned fail-closed, missing/default PIN, exact Cleaner modes, structured cleanup failures и exit codes, firewall post-delete verification, scheduled-task absent/error classification, safe diagnostics, telemetry quarantine, remote PIN/legacy updater и email-code recovery.
- Inno syntax/package compile: пройден на Inno Setup 6.7.3 в исключённый review-only каталог; созданный installer не запускался, пользовательский `Output` не менялся.
- NuGet vulnerability audit, masked secret scan, UTF-8/mojibake check и staged diff check пройдены. Независимый review принял code/security delta без оставшихся P0/P1.
