# Guard v2: канонический план разработки

Статус: исполнение M0–M9 разрешено Иваном. P0 containment завершён; интеграция и приёмка продукта продолжаются в `codex/guard-v2-integrated`. Готовой системы пока нет.

Последнее обновление: 2026-10-01.

Актуальный маршрут исполнения — раздел «Подробный план завершения M0–M9» ниже. Исторические Stage 0–7 и старые количества тестов описывают сделанные foundations, а не готовность продукта. Один канонический план остаётся в этом файле.

## Cloudflare relay — проверено 2026-09-26

- Выпущен отдельный account-owned токен `Guard relay deployment` без срока действия, `Specified Workers: guard-relay` / `Individual Workers Editor`. Новая PowerShell-сессия получила HTTP 200 для проверки токена и `guard-relay`, HTTP 403 для `voicepaste-api`. Локальная operational copy сохранена через DPAPI CurrentUser с ACL только пользователя вне Git. 2026-09-29 Иван подтвердил сохранение master copy в защищённом поле `API` Bitwarden; скриншот показал созданную запись, точные байты Bitwarden отдельно не считывались. После переноса буфер обмена уже содержал другие данные.
- Код `relay/worker` прошёл 15/15 тестов, typecheck и production `npm audit` без уязвимостей. Wrangler загрузил код и миграцию Durable Object, но завершился с кодом 1 при последующем чтении account-wide `workers/subdomain` без соответствующего права. Внешний endpoint уже отдаёт ответы нового кода: `/` → 404 `not_found`, mailbox без ключа → 401, bootstrap без секрета → 403, parent BFF без настройки → 503. Это подтверждает публикацию, но не готовый пользовательский сценарий. Ради успешного завершающего запроса Wrangler права токена до всего аккаунта не расширять.
- `BOOTSTRAP_ADMIN_TOKEN`, `SESSION_SECRET`, `PARENT_INVITE_SECRET` и RP-настройки ещё не заданы; реальные enrollment, решения и телефонная биометрия не проверены. На основном ПК системная защита не запускалась.
- 2026-09-29 устранено несовпадение PWA-ссылки на Android-запрос с intent filter/parser приложения; PWA 26 тестов и сборка, Android unit-test task и debug APK прошли с уже установленным JDK 17. Это только передача locator: Android пока не получает/проверяет запрос и не подписывает решение. Проверка списка Hyper-V ВМ через терминал отказала в доступе; одноразовая read-only UAC-попытка не вернула инвентарь, поэтому VM-gate остаётся открытым.

## Продолжение реализации — уточнения 2026-09-23

Иван поручил доделать продукт внимательно; к совместным испытаниям приглашать только после готовности интегрированной сборки. Предыдущая русификация закончена, новая рабочая ветка — `codex/guard-completion`. Перед изменениями кода создан и отправлен checkpoint `codex/checkpoint-20260923-2221-guard-completion` на `bd8e7a8ed024c23b1402eeebeec71532bbda0e30`; база чистая.

- Сохраняется строгий default-deny: никакие пользовательские приложения, сайты, установщики и изменение защитных настроек не разрешаются без решения родителя. Не блокируются необходимые для загрузки Windows и работы самого Guard компоненты из проверенного минимального базового набора; произвольное расширение этого набора запрещено.
- Для ребёнка каждый новый запрещённый объект даёт понятный запрос. Повторы объединяются, технические зависимости сайта/приложения показываются проверенным пакетом, не отдельным уведомлением на каждый процесс или CDN. Родитель видит точный объект, ожидающие решения, действующие разрешения и статус защиты.
- Управление с телефона: QR открывает конкретный короткоживущий запрос, но не является ключом отключения. Любое включение/временная пауза/обслуживание и изменение аккаунтов требуют подписи зарегистрированным родительским устройством после свежей сильной биометрии. Утечка/повтор QR не меняют права. Из ребёнка нельзя повторно назначить владельца.
- Быстрое отключение реализуется ограниченной по времени паузой/обслуживанием с явным сроком и автоматическим возвратом; не бессрочной кнопкой «открыть всё». Полное удаление — отдельная подтверждаемая операция с проверенным восстановлением ОС.
- Новое обязательное требование: выход из детского аккаунта, вход в другой, создание пользователя и добавление в администраторы не должны быть обходом. Требуется машинная, а не только per-child политика; неизвестная/изменённая учётная запись не получает доступ. Скрытие кнопок смены пользователя не считается границей защиты.
- 2026-09-24 Иван одобрил: все повседневные аккаунты стандартные, обычные решения с телефона после отпечатка, отдельный аварийный локальный администратор с независимым случайным паролем в Bitwarden и offline recovery. Конкретный обнаруженный в семье обход — восстановление пароля административного Microsoft-аккаунта через почту. Readiness должна отвергать любой повседневный/cloud-linked администраторский аккаунт; восстановление Microsoft-аккаунта не должно предоставлять административные права на защищённом ПК. У recovery-admin не должно быть доступных ребёнку security questions, reset disk или альтернативного облачного пути. Существующие аккаунты не преобразовывать без подтверждения при установке, последний recovery-admin не блокировать.
- Усиленное требование Ивана: ограничения должны охватывать неизвестные/новые аккаунты, включая новый административный, а не зависеть от одного SID ребёнка. Простая AppLocker-политика и LocalSystem-служба не доказывают стойкость против уже полученных полных прав Windows. Для anti-tamper требуется отдельный VM-прототип подписанной machine-wide App Control for Business политики + Secure Boot, с ключом изменения вне защищаемого ПК, защищённой загрузкой и BitLocker. До успешного обходного/rollback-теста это требование считается открытым, не обещанием абсолютной защиты. Подписанные политики могут вызвать boot failure; на основном компьютере не применять. Основания (проверено 2026-09-24): https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/use-signed-policies-to-protect-appcontrol-against-tampering и https://support.microsoft.com/en-us/accounts-billing/security/change-or-reset-your-microsoft-account-password-in-windows.
- 2026-09-24 Иван повторно поручил завершать весь продукт; узкие параметры спрашивать по мере необходимости, не останавливать безопасную реализацию из-за необязательных уточнений. Совместные испытания предлагать после готовности интегрированной сборки, не после отдельных foundations.
- Основной компьютер остаётся вне live-тестов. Автоматические проверки выполняются сейчас, привилегированные интеграционные действия — только в одноразовой VM. Финальное включение на семейном ПК и проверка реального отпечатка — отдельная совместная приёмка.

## Подробный план завершения M0–M9

Это план предстоящей реализации и её приёмки, составленный по исходникам на `a53cdad` в `codex/guard-completion`. В ходе планирования изменяются только документы. Сегодня сборки и тесты повторно не запускались; приведённые ниже прежние результаты имеют собственные даты. Разработку выполняет один Codex, используя существующие модули и проверки.

### Какой результат считаем работающим приложением

- Родитель устанавливает Guard в поддерживаемую Windows, привязывает свой Android по QR, сохраняет Recovery Kit, проходит проверку готовности и включает защиту.
- Неизвестное приложение блокируется до выполнения его кода, неизвестный сайт — до получения содержимого. На компьютере можно запросить разрешение; повторные попытки объединяются. Базовый набор для загрузки Windows, Guard и подключения к relay минимален и проверен.
- На телефоне родитель видит проверенные название, компьютер, аккаунт, объект и срок. Выбирает решение, подтверждает свежим отпечатком; компьютер применяет именно это решение и возвращает подписанное подтверждение результата. Состояния «отправлено», «получено компьютером» и «применено» различаются.
- Доступ можно дать постоянно, временно, по расписанию/дневной квоте или запретить. Есть отзыв разрешения, ограниченная пауза/обслуживание и автоматическое возвращение защиты. QR и push только открывают запрос; сами по себе ничего не разрешают.
- Политика действует на весь компьютер, включая другой или новый аккаунт. Изменение аккаунтов и попытки удалить/остановить Guard обнаруживаются. Стойкость при уже полученных полных правах администратора принимается отдельно по M1 и T09; наличие службы не считается её доказательством.
- Потеря сети, выключенный телефон, недоступное облако, перезапуск UI или Windows не превращаются в разрешение. Ранее действующие права сохраняются только в пределах их срока; квоты и отзыв не обходятся сменой аккаунта или времени.
- Подготовлены установка, обновление, восстановление и штатное удаление, русская инструкция, подписанные сборки для выбранного режима распространения и доказательства прохождения M9.

Целевой первый комплект: Windows 11 Pro x64, Edge и затем Chrome, Android родителя с сильной биометрией, родительский PWA и отдельный Guard Worker. iPhone approval-клиент, Windows Home, Яндекс Браузер и агент для телефона ребёнка не входят в этот выпуск. Бесплатный закрытый пилот и публичный релиз — разные точки приёмки; покупать сертификаты, магазинные аккаунты или хостинг заранее не требуется.

### Фактическая исходная точка и разрывы

| Участок | Что уже есть | Что нужно довести до реального использования |
|---|---|---|
| Windows | `src/Guard.Service`, `Guard.Windows`, модели, codecs, storage, IPC, readiness и политика | `GuardServiceHost` подключает `BoundaryOnlyPolicyReconciler`, `NoProxyIdentityProvider`, неполные readiness probes; реальные store/reconcile/relay/app/web adapters не соединены |
| Привязка | `SetupCoordinator`, admin begin/bind, Android `EnrollmentQrParser` | Завершение enrollment через внутренний outbound transport, проверка attestation и владения ключом, доверенный обмен device/view/approval keys, защита от незавершённой/повторной привязки |
| Детский ПК | Безопасные application/site request use cases и ограниченные payload | Нет `Guard.Child` и работающего захвата блокировок v2; старый tray не должен вернуть себе полномочия |
| Android | Реальные .NET/Kotlin vectors, Keystore helpers, outbox, coordinator; 18 JVM-тестов и debug APK прошли 29 сентября | `MainActivity` — оболочка; нет сканера настройки, сети, проверенной карточки, вызова биометрии и отправки/приёма результата. Три `RealDeviceSecurityTest` — `@Ignore` и пустые тела, аппаратного доказательства нет |
| PWA | RU/EN, passkey DTO, BFF transport, ограничения доверия; 26 тестов и build прошли 29 сентября | `window.guardParentSnapshotVerifier` не подключён; регистрация вызывается без параметров, обязательных для BFF; default inbox limit сервера 20 больше клиентского максимума 16; нет полноценного кабинета и QR-перехода |
| Relay | Worker опубликован, bounded mailbox, WebAuthn BFF, SQLite DO; 15 тестов прошли 26 сентября | Нет production RP/секретов и serving PWA assets; locator создаётся, но native redemption не реализован; нет рабочего provisioning клиентов и FCM. Документированный sequence-hint contract нужно сверить с фактическим `finalize` |
| Системная защита | AppLocker/web policy planners, парсеры, readiness и reconciliation contracts | Нет полного production enforcement, low-privilege proxy, расширения, WFP и защищённого цикла обновления правил |
| Поставка | Legacy Inno source, существующие тестовые harness | Нет установщика v2, updater/recovery lifecycle, CI и принятого VM-стенда. Старый `Output/Guard-Setup-v1.0.0.exe` не является поставкой v2 |

29 v2 harness-проектов и 45 legacy checks уже существуют; это не 29 сквозных тестов. Их переиспользуем. Новые проверки добавляем для перечисленных ниже границ и ошибок, а не ради процента покрытия.

### M0. Воспроизводимая база и изолированный стенд

Старт исполнения 2026-09-29: согласованный baseline и план зафиксированы коммитом `a46b73d628ecb5128f1069578f1e184483d6b0bf` и отправлены в GitHub как `codex/checkpoint-20260929-2325-guard-integrated`. Рабочая ветка: `codex/guard-v2-integrated`. На основной Windows приложение и политики не запускались.

Проверка 2026-09-29: Release solution build PASS; новый `scripts/run-safe-tests.ps1 -SkipBuild` выполнил все 29 v2 console harness и legacy P0 checks PASS; PWA 27/27 + build PASS, Worker 15/15 + typecheck PASS, Android 18/18 JVM + debug APK PASS. Повторная VM-приёмка M0 ещё **NOT RUN**: elevated `Get-VM` вернул пустой список, следующий UAC для read-only switch inventory был отменён. Не повторять его без ответа Ивана. Загрузка официального Windows 11 Enterprise Evaluation ISO (90 дней) остановлена на 1,72/7,66 ГиБ, частичный файл сохранён в `D:\GuardV2Lab`; это не подмена требуемого финального теста на Windows 11 Pro и не семейная лицензия.

Продолжение 2026-09-30: Иван разрешил UAC для лаборатории. `GuardV2-Lab-20260930` создана с Generation 2, Secure Boot, vTPM, динамическим диском и ProductionOnly snapshots; её файлы перенесены на C: после неожиданного сокращения свободного места D:. Microsoft Enterprise Eval 26H2 ISO полностью скачан, размер и SHA-256 записаны в `.codex/memory/worklog.md`, образ подключён к VM. Официальный PDF Microsoft с хешами пока для 25H2; сверки с корректным официальным хешем **нет**. При первом старте был пропущен короткий запрос нажать клавишу для загрузки DVD; Иван затем разрешил перезапустить только VM. Snapshot и recovery **NOT RUN**. На основной Windows Guard/политики не запускались.

Позднее 2026-09-30: образ Windows развернут на строго проверенном пустом VHDX этой VM (GPT/EFI/MSR/NTFS); физические диски не затронуты. Первый `bcdboot` вернул код 1, а дальнейшая диагностика — 183 / `c0000035`; повтор с `/c` и после резервирования/переименования BCD с `/c /offline` не исправил конфликт. `bcdedit` считает новый BCD некорректным. Исходный BCD сохранён, точный VHDX отсоединён от хоста, S:/W: исчезли, VM выключена. Для обычной установки Windows с DVD Ивану нужно вручную нажать `Пуск` и пробел на кратком запросе загрузки: Computer Use видит, но не управляет повышенным VMConnect. Release, safe suites, PWA/Worker и offline Android build повторно прошли; это не меняет статуса M0/M1 и не является готовой системой.

Итог 2026-09-30: неудачный offline BCD заменён чистой установкой Windows 11 Enterprise Evaluation с ISO на единственный 80-ГиБ диск VM; локальный `GuardLabAdmin` дошёл до рабочего стола. Hyper-V подтвердил Generation 2, Secure Boot, vTPM и ProductionOnly; снимок `clean-windows-20260930` создан, восстановлен после штатного выключения и повторно загружен до экрана входа. Это проверка возврата VM, а не доказательство защиты Guard. Имя ISO содержит 26H2, но `setup.exe` и watermark гостя показывают build 26100; точный выпуск ещё не подтверждён. M0 остаётся частичным: recovery-носитель, тестовые аккаунты, официальный хеш этой версии и финальная приёмка на Windows 11 Pro открыты; M1 ещё не выполнялся. На основной Windows Guard/политики не запускались.

Автоматический доступ 2026-09-30: после вставки Иваном настоящего пароля в защищённое окно PowerShell Direct успешно подключился как `DESKTOP-8C2FU3H\GuardLabAdmin`. Повторный ввод не нужен. Проверенная DPAPI CurrentUser-копия находится вне Git в `%LOCALAPPDATA%\GuardV2Lab\Access\guest-credential.xml`, каталог доступен только пользователю/SYSTEM. Guest baseline PASS: EnterpriseEval / 26H2 / CIM build 26300.9457, Secure Boot и TPM готовы, один включённый локальный администратор, эффективные AppLocker rules пусты, WinRE включён. BitLocker FullyEncrypted, но Protection Off: защищённую загрузку с шифрованием не считать принятой. Watermark/setup 26100 не определяют актуальную сборку гостя; официальный хеш именно этой версии ISO ещё не сверён.

`scripts/lab/Get-GuestBaseline.ps1` и `Test-AppLockerFeasibility.ps1` проверяют UUID/виртуальное оборудование/роль администратора/отличие от host до guest probes или изменений. `scripts/lab/Test-LabSafety.ps1` на Windows PowerShell 5.1 PASS: синтаксис, отказ на host, две безвредные marker-программы с разными SHA-256, bounded process/sentinel self-tests, удаление временных бинарников. `Invoke-AppLockerLab.ps1` закрепляет единственную выделенную VM и диск, проверяет текущий WMI BIOSGUID, выполняет эксперимент только через PowerShell Direct и возвращает clean snapshot с повторным подключением. Первые два прогона остановились на ошибках harness (чтение результата процесса, затем XML-порядок rules/extensions); оба завершились `SnapshotRecovery=BOOT_VERIFIED`. После исправлений третий прогон завершился PASS и снова `BOOT_VERIFIED`; отключение окна VMConnect при этом ожидаемо, повторный интерактивный вход для автоматизации не нужен.

**Результат:** можно безопасно собрать точную версию и повторить проверки на отдельной тестовой Windows.

1. После команды начать: проверить статус/remote и безопасный diff, создать и push свежий checkpoint текущего кода вместе с согласованным планом. Старый checkpoint сохранить. Новую ветку `codex/guard-v2-integrated` создать от этой базы; пользовательские изменения не включать без установленного scope.
2. Зафиксировать команды уже установленного .NET/JDK/Android SDK/Node/Inno в проектной инструкции. JDK Guard: `%LOCALAPPDATA%\GuardDev\jdk-17.0.19+10`; явно задавать `GRADLE_USER_HOME`, чтобы новая сессия не искала `C:\.gradle`. Не переустанавливать рабочие инструменты без причины.
3. Добавить один короткий runner безопасных проверок с явным списком существующих harness. `dotnet test` сам по себе недостаточен: эти .NET проекты — console harness. VM/phone suites должны запускаться отдельными явными командами, не из обычного build/test.
4. Подтвердить Hyper-V read-only запросом с явным JSON-результатом даже при нуле ВМ; прошлое отсутствие вывода не считать установленным стендом. Создать выделенную Generation 2 Windows 11 Pro VM с vTPM/Secure Boot, тестовыми аккаунтами, чистым snapshot и recovery-носителем. Проверять VM id и guest identity перед любой изменяющей командой. Не выполнять guest-скрипт локально при ошибке удалённого соединения.
5. Подготовить безвредные тестовые EXE/MSI/script/DLL/MSIX, локальные HTTP/HTTPS/WebSocket/DNS endpoints, фиктивные родительские/детские данные и средства сетевого сбоя. Все попытки обхода — только на этом стенде. Реальные семейные данные и пароли в fixtures не использовать.

**Приёмка:** чистая сборка + существующие safe suites, список их фактически выполненных проверок; восстановление VM из snapshot проверено. M0 не включает защиту на основном ПК. Тесты: T01, T04, T20.

### M1. Проверить осуществимость защиты всех аккаунтов

**Результат:** выбран и доказан на VM системный механизм, совместимый с телефонными разрешениями и автоматическим отзывом.

VM-прототип AppLocker 2026-09-30 — **эксперимент PASS, строгая защита НЕ ПРИНЯТА**. Среда: EnterpriseEval 26H2 / 26300.9457, elevated локальный администратор, Everyone `S-1-1-0`, service enforcement включён, без `Administrators:*`. Использован только LAB-набор широких Windows/Program Files paths для сохранения загрузки; это не production-каталог. Фактически проверено на безвредных EXE:

| Проверка T07–T09 (частично) | Наблюдение |
|---|---|
| Без policy и AuditOnly | marker v1 запускается |
| Default-deny | marker v1 не запускается, Win32 1260 |
| Exact hash grant | marker v1 запускается, иной hash v2 заблокирован |
| Удаление grant | новый запуск v1 заблокирован |
| Уже запущенный v1 после отзыва | продолжает работать; завершён только тестовым runner |
| Повышенный администратор очищает policy | успешно; v1 и v2 снова запускаются |
| Очистка + clean snapshot restore | пустая effective policy, fresh PowerShell Direct session, `BOOT_VERIFIED` |

Evidence: commit `4044748`, `scripts/lab/Invoke-AppLockerLab.ps1`, очищенный результат в `%LOCALAPPDATA%\GuardV2Lab\Access\applocker-result.json`; пароль в отчёт/Git не входит. Signed App Control, новые/стандартные аккаунты, DLL/script/MSI/MSIX, остановка служб и независимое истечение TTL **NOT RUN**. Следующий обязательный шаг — unsigned/audit → signed machine-wide App Control прототип с off-PC signer и проверенным recovery, затем совместимость динамических прав/отзыва. Не заменять его молча AppLocker-only режимом.

Unsigned App Control 2026-09-30 — **эксперимент PASS, строгая защита НЕ ПРИНЯТА**: native DefaultWindows LAB ONLY, UMCI, без проверки script enforcement. Audit разрешил marker и дал событие CodeIntegrity 3076 с точным policy id; enforced запретил запуск и дал 3077. Native CiTool подтвердил `IsEnforced=true`, `IsAuthorized=true`, `IsSignedPolicy=false`. Elevated администратор снял политику, marker снова запустился. После удаления и восстановления snapshot fresh-session probe подтвердил исходные 14 native policies и пустой AppLocker. Отчёт: `%LOCALAPPDATA%\GuardV2Lab\Access\appcontrol-result.json`. Общий marker helper повторно проверен реальным AppLocker прогоном, оба эксперимента завершились EXIT 0 / `BOOT_VERIFIED`.

Автономное исполнение разрешено Иваном 2026-09-30: продолжать весь одобренный M0–M9 без команды «продолжай» после каждого инкремента, сохранять проверенные commits/push. Ограничения VM-only, реальные аппаратные/биометрические gates и остановка перед семейной установкой/расходами/публичным выпуском сохраняются; UAC не обходить. Прерванный VMConnect не означает отказ PowerShell Direct.

Signed-прототип 2026-09-30 — **эксперимент PASS, строгая M1 защита ещё НЕ ПРИНЯТА**. Причина прежнего неактивного файла подтверждена сравнением на VM: BCL создавала `SignedData.version=3`; Windows приняла вариант `version=1`. ASN.1 parser меняет только точный unsigned version field; подпись, policy OID, signer и byte-identical content повторно проверяются до записи. Источник совместимости: [разработчик AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/About-Code-Integrity-Policy-Signing). RSA-3072 остаётся ephemeral в памяти host, без certificate store/export private key или ключа в VM. Higher-version signed recovery подготовлен заранее, но остаётся на host до санкционированного возврата. Guest EFI подключается адресно по единственной GPT system partition/volume GUID.

- Audit после первого reboot разрешает marker и даёт точное policy-specific событие 3076; enforced после следующего reboot блокирует marker и даёт 3077. Native CiTool подтверждает signed/authorized/enforced policy; audit flags сами по себе не считаются доказательством режима.
- Elevated admin `CiTool --remove-policy` отклонён (`-2147023250`); marker остаётся заблокирован. Это одна конкретная tamper-проверка, не доказательство всех способов обхода/всех аккаунтов.
- Higher-version signed recovery → reboot → адресное удаление PASS, marker снова разрешён. Clean snapshot восстановлен, fresh-session boot/inventory PASS: те же 14 native policies и пустой AppLocker. Лабораторные signing artifacts удалены. Отчёт: `%LOCALAPPDATA%\GuardV2Lab\Access\signed-appcontrol-result.json`, EXIT 0 / `BOOT_VERIFIED`.
- Следующий gate: exact dynamic grants/revoke и независимый TTL при остановке службы; другие аккаунты, strict catalog, Safe Mode/offline recovery и production signer остаются открытыми. Широкая native база/troubleshooting/script-disabled options — LAB ONLY, не готовая поставка.

Dynamic grant-прототип, уточнено 2026-09-30 21:46 — **выдача/отзыв работают в LAB compatibility-профиле; независимое expiry FAIL, строгая M1 защита НЕ ПРИНЯТА**. Подписанная base policy: v3 grant, v4 revoke, заранее подготовленный v5 recovery остаётся вне guest. Причина прежнего отказа подтверждена сравнением: SHA-256-only правило оставляло marker заблокированным и после reboot; совпадение Authenticode SHA-256 из события 3077 ещё не определяло использованный алгоритм. Связанное через ActivityID событие 3089 показало SHA-1. Сохранение обоих native full-file SHA-1/SHA-256 правил (без page hashes/path/publisher расширений) разрешило v1, сохранив запрет v2. Это **только диагностическая совместимость**, не принятая реализация строгой product FileSha256 identity. Native Authenticode и flat file SHA-256 нельзя смешивать. Маршрут проверки: [сопоставление 3077/3089 у Microsoft](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/appcontrol-debugging-and-troubleshooting), [выбор видов хеша](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create#more-information-about-hashes).

| Проверка последнего signed compatibility-прогона | Факт |
|---|---|
| Выдача без reboot / другой файл | v1 Allowed / v2 Blocked |
| После reboot и внешнего срока 5 секунд, Guard/reconciler отсутствует | v1 остаётся Allowed; `NativeOnlyTtlGate=FAIL` |
| Подписанный отзыв / следующий reboot | v1 Blocked / Blocked |
| Signed recovery/removal и clean snapshot | PASS / `BOOT_VERIFIED`, исходные 14 native policies; signing artifacts удалены |

Итоговый report — `FAIL`, phase `native-only-expiry`, EXIT 1. Не считать постоянное правило истекающим lease и не выдавать этот опыт за crash-test установленной службы. Runner сохраняет отдельные pre/post-boot наблюдения даже при отказе выдачи, но не превращает их в успех; expiry оценивается только после реально успешной выдачи, иначе `NOT_RUN`. Основной компьютер не менялся. Следующее M1 действие — обосновать механизм независимого истечения/отзыва и строгой SHA-256 identity; не повторять уже закрытую диагностику хеша и reboot, не ослаблять требования до user-mode таймера/watchdog.

1. Составить минимальную базу разрешённых компонентов Windows/Guard. Проверить App Control for Business как машинный слой и AppLocker как возможный слой динамических ограничений. Ни `Administrators:*`, ни «разрешить всё подписанное Microsoft», ни широкие writable-path правила не допускаются как готовое решение.
2. Проверить пересечение правил: разрешение AppLocker не должно предполагаться способным отменить запрет App Control. Для неизвестного приложения доказать полный путь добавления точного разрешения в выбранные слои и его удаления.
3. Подписанные политики Windows требуют PKCS#7/RSA; текущая подпись решения Guard — P-256/ECDSA. Это разные полномочия и форматы. Выбрать проверяемый путь подписи/обновления policy с закрытым ключом вне защищаемого ПК; не помещать policy signer в недоверенный relay и не подписывать на телефоне непроверенный бинарник «по хешу». Статическую защитную базу и динамические права исследовать раздельно. Дополнительный RSA-ключ или другой доверенный signer добавлять только после этого прототипа.
4. Отдельно проверить остановку службы, Application Identity/BFE/proxy и уже выданные временные права. AppLocker allow, оставшийся на диске, не истечёт только потому, что истёк объект в .NET. Нужен доказанный механизм закрытия доступа в установленный срок; watchdog и запись retry-marker сами по себе доказательством не являются.
5. Проверить стандартного ребёнка, второго стандартного пользователя, новый аккаунт и специально созданного тестового администратора. Разделить запрет опасного действия, его обнаружение и реальное сохранение политики. Успешный notification не означает предотвращённый обход.
6. Проверить Secure Boot/BitLocker, загрузку/reboot, Safe Mode, попытки внешней загрузки и санкционированный откат подписанной политики. Сначала unsigned/audit испытание правил, затем signed/enforced в VM с recovery; не оставлять troubleshooting fail-open options в принятом строгом профиле.
7. Закрыть совместимость Android: код ECDH использует `PURPOSE_AGREE_KEY` (API 31), хотя `minSdk` сейчас 30. Рекомендуемая база — Android 12/API 31+ с доказанным hardware key support. Проверить телефон Ивана перед утверждением минимума; software-key/PIN fallback автоматически не добавлять.
8. Проверить минимальную установку/удержание управляемого Edge-расширения на обычной Windows 11 Pro без domain/MDM и режима разработчика. Если нужен подписанный store-пакет, заранее установить доступный маршрут закрытого пилота; не обнаруживать это только после готовности web UI.

**Приёмка:** конкретная policy/schema, разделение ключей, проверенная процедура возврата Windows и матрица T07–T09. Если полный администратор снимает ограничение или crash оставляет временный allow без срока, усиленное требование остаётся блокирующим. Codex продолжает независимые работы с UI/обменом, но не помечает строгую защиту готовой и не заменяет её молча режимом «только стандартный ребёнок». Это техническая развилка, которую нужно показать Ивану с результатом прототипа.

Проверка документации после signed-policy опыта: [Microsoft защищает anti-malware службы через ELAM и специальные требования подписи](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-), а не произвольным флагом у обычной .NET-службы. Поэтому PPL не считать уже доступным решением Guard. Короткоживущий сертификат/статическая policy также не доказывают закрытие уже работающего процесса, требуемое T17; job object без доказанного запрета всех обходных запусков не закрывает всю модель. Это исключение неподтверждённых упрощений, не доказательство общей невозможности и не разрешение на разработку/покупку драйвера. M1 остаётся открытым; независимый M2 продолжается в рамках уже принятой приёмки ниже.

### M2. Соединить хранилище, облачный обмен и веб-вход

**Результат:** подготовленные клиенты обмениваются зашифрованными сообщениями через отдельный Guard relay; сервер не выдаёт разрешений.

1. Подключить реальные HTTPS transport/outbox/inbox workers в `Guard.Service`, используя существующие canonical codecs/crypto. Таймауты, bounded polling/backoff, cancellation и лимиты очередей обязательны; polling не должен постоянно держать телефон активным.
2. Согласовать `FileAuthoritativeStateStore`, `FileRelayTransactionStore` и application/web desired state: один authoritative writer, однозначный commit для cursor/replay floor/request outcome/desired policy/receipt. Если физически несколько файлов, durable intent и восстановление должны давать тот же результат после сбоя. Ack — только после durable commit, `Applied` — после проверки фактически применённой policy.
3. Настроить Guard Worker secrets и RP exact origin, PWA assets в одном origin. Master secrets — Bitwarden, operational copy — существующий DPAPI-маршрут вне Git. Токен deployment не выдаётся устройствам; VoicePaste не затрагивается. Проверить безопасные role/recipient-scoped mailbox credentials и их отзыв.
4. Исправить договорённость PWA↔BFF регистрации: выдавать ограниченный одноразовый билет после доверенного enrollment, а не встраивать глобальный invite/admin secret в JS. Добавить выдачу/отзыв view-device authority отдельно от approval authority.
5. Довести locator: authenticated redemption на правильном mailbox/recipient, срок, привязка к конкретному запросу; подмена или повтор locator не создают решение. Полученный запрос Android всё равно расшифровывает и проверяет сам.
6. Согласовать paging/inbox limits, request/frame identifiers и sequence hints между TypeScript/.NET/Kotlin; устранить несовпадение 16/20. Relay hints никогда не продвигают локальный replay floor без подписанной квитанции компьютера.

**Приёмка:** реальный .NET sender → HTTPS Worker → Kotlin receiver и обратная подписанная квитанция на синтетических данных; рестарт каждого процесса не теряет/не повторяет эффект. PWA входит через WebAuthn и не получает approval signing capability. Тесты: T02–T04, T12–T14, T16. Применение системной policy в этой проверке ещё не подменяется успехом доставки.

PWA↔BFF registration, 2026-09-30: глобальный invite удалён из активного контракта. Только mailbox admin в доверенном off-device provisioning выдаёт 256-bit билет на точные mailbox/view recipient/username; browser передаёт только билет, не выбирает привязку. SHA-256-only хранение билета, 5 минут вместе с WebAuthn ceremony, atomic одноразовое погашение, 64 outstanding максимум, замена/отзыв неиспользованного билета. Legacy challenges без ticket binding отказывают; failed/expired ceremony действительно удаляется до ошибки, не восстанавливается rollback транзакции. PWA transport/form согласованы, RU/EN объяснение, поле очищается при отправке, URL/storage не используются; отсутствие snapshot verifier по-прежнему блокирует вход. Worker 25/25 + typecheck, PWA 28/28 + build PASS; проверены race/replay/expiry/роль/подмена привязки/quota и реальные криптографические WebAuthn test fixtures. НЕ DEPLOYED, реальный passkey/телефон/доверенное enrollment ещё не проверены. Полный отзыв view-device/passkey/session и подключение выдачи билета к проверенному enrollment остаются M2/M8 gates; admin credential не передаётся клиентам.

Проверяемая часть M2, 2026-09-30: `Guard.Service/HttpRelayTransport` использует стандартный .NET HTTPS, существующие GRF1 codecs и `IRelayTransactionStore`. Нет автоматических redirects/proxy/cookies/decompression; общий deadline включает чтение body, responses/JSON/pages ограничены. Outbox отправляет те же durable bytes и сохраняет delivery cursor только через CAS после соответствующего ответа; потерянный ответ/проигранный CAS оставляют безопасный повтор. Inbox принимает только ordered Approval frames своего mailbox/recipient, 16 на страницу, JS-safe cursors и точный nextCursor; ack берётся только из загруженного committed state, server hints не меняют replay floor/policy. Общая Release-сборка, 29 v2 harnesses + 45 legacy checks PASS; service harness теперь содержит 26 проверок. Это fault-handler проверки, не реальный HTTPS Worker↔телефон exchange. Adapter пока не включён в production startup: нужны доверенное enrollment/config, согласование файловых aggregates, inbox crypto/coordinator, retry/backoff loop и deployment/provisioning recipient-scoped credentials. `Applied` не создаётся из HTTP success; M2 остаётся открытым.

Предыдущая часть M2 локально проверена: Worker credentials закрепляют собственный inbox/ack recipient и явные publish recipients; approval role дополнительно закрепляет signing key/epoch и доверенные PWA view links для locator. Права чтения не становятся правами подписи; browser не выбирает view→native связь. Additive/idempotent SQLite migration сохраняет admin для перепровизии, но старые non-admin credentials без scope и locators без view binding отказывают. Endpoints имеют точные пути; контролируются JS-safe cursor/time, quota и реальные streaming bytes с deadline. Publication floor переживает expiry/delete, hash-only tombstone даёт точный duplicate после receiver ack и при заполненной очереди; чужие bytes конфликтуют. Signing-intent/finalize остаются недоверенными availability hints, не проверкой терминальной квитанции. На этом этапе Worker 19/19 + typecheck, PWA 27/27 + build PASS. Новая schema/auth ещё НЕ DEPLOYED; production credentials/журнал внешних подключений не изменены. Контракт: `relay/worker/README.md`. Более поздний registration-ticket контракт описан выше; trusted enrollment, настоящая crypto-inbox транзакция и exchange остаются открытыми.

Согласование device outbox, 2026-09-30: локальный queue cursor отделён от wire cursor каждого получателя. Один tracked request может в одном CAS сохранить до восьми независимо зашифрованных phone/view frames; durable recipient heads (до 128) не удаляются при delivery ack. Следующие номера строго +1, JS-safe для wire; HTTPS до отправки сопоставляет recipient/cursor/ID/kind с exact durable bytes. Schema 2 сериализует heads канонически, общий journal commitment защищает их вместе с aggregate. Schema 1 читается только для нетронутого enrollment; историческое состояние отказывает без reset/изменения файлов — migration/re-enrollment остаётся отдельным lifecycle gate. Проверки на реальных временных файлах: fanout, частичный ack, reopen, неизменные retry bytes, отказ переноса/пропуска floors, лимиты/overflow; HTTP fault-handler — потерянный ответ после принятия одной копии и точный duplicate retry. 19 relay-state и 26 service checks, общая Release-сборка + 29 v2 harnesses/45 legacy checks PASS. Это ещё не живой exchange/startup; Android-отправителям нескольких родителей потребуется согласованное выделение wire cursor общего device inbox, не смешивать его с authority/key approval sequence.

M1 focused runs выполнены после подтверждений UAC Иваном: `Invoke-AppLockerLab.ps1 -SignedAppControl -SignedGrantsOnly` пропускает только доказанный audit этап при сохранённом signed-base/recovery evidence и неизменных Build/UBR. Выдача/отзыв подтверждены для LAB SHA-1/SHA-256 compatibility-профиля, но последнее независимое expiry завершилось FAIL; recovery/boot PASS. Подробные результаты и следующий технический gate — в M1 выше. Это больше не блокер доступа/UAC; пароль повторно не нужен. Product enforcement/строгая identity/реальный service-loss остаются открытыми.

### M3. Закончить первичную привязку и Android-подтверждение

Устранён блокер M2→M3, 2026-09-30: Worker frame/auth/BFF и Windows HTTP-клиент отвергали реальные идентификаторы ключей `p256:…`. Теперь все пути, включая PWA transport/crypto, проверяют канонический контракт 16–128 ASCII-символов `A-Za-z0-9._:-` без нормализации регистра; BOM/разделители/Unicode/неверная длина отклоняются. Служебный global-auth DO `guard:bff:auth:v1` отдельно закрыт для mailbox/bootstrap, хотя теперь подходит под грамматику. Worker 43 tests/typecheck, PWA 71 tests/build, Windows HTTP publish/poll/ack с настоящим вычисленным fingerprint PASS; роли, чужой ключ/регистр, retry, persisted cursor/ack и signing intents проверены на том же формате. Изменение локальное, НЕ DEPLOYED; зашифрованный enrollment transport и подписанное согласование результата всё ещё следующий шаг.

**Результат:** родитель способен безопасно связать чистую VM и телефон без ручного копирования технических токенов.

Проверенная часть M3.2, 2026-09-30: `Guard.Windows/Cryptography/AndroidApprovalAttestation.cs` проверяет bounded custom-root X509 chain без AIA/certificate-store writes, отзыв каждого serial, leaf SPKI/challenge/proof, строгий DER, аппаратные TEE/StrongBox и per-operation biometric-only параметры, locked Verified Boot и точный APK signer/package/version. Реальные синтетические CA chains и 31 негативный DER/profile случай PASS. Теперь verifier используется в `NativeEnrollmentCoordinator`, но production startup ещё не подключён. Документация: [Android attestation](https://developer.android.com/privacy-and-security/security-key-attestation), [AOSP schema](https://source.android.com/docs/security/features/keystore/attestation). Доверенные roots и status нельзя принимать из relay claim. Конкретный Google source теперь реализован и проверен ниже; production composition, release identity/root-update flow и физическая Google-backed chain ещё открыты. Строгий профиль отказывает expired certificates, включая legacy factory chains; исключение Google не принято/не реализовано, RKP expiry отменять нельзя. M3 целиком остаётся открытым.

1. Собрать setup UI с проверкой readiness; QR появляется только в подтверждённой локальной elevated setup session. В native-scanned transcript связать точный relay, enrollment id, device identity/public keys, epochs, challenge и родительские ключи. Завершение идёт по внутреннему outbound path; открытого ParentRelay pipe не появляется.
2. Реализовать сканирование QR, lifecycle незавершённой привязки и генерацию раздельных approval/decryption keys на Android. Локальная служба Windows проверяет chain/attestation challenge/boot state/key properties и доказательство владения approval key; самоутверждения телефона или relay не являются доказательством. Простая проверка формы P-256 ключа не заменяет attestation. Источник доверенных корней и обновление списка отзыва должны быть проверяемыми.
3. Одноразово закрепить доверие через CAS, подтвердить тот же компьютер на телефоне и результат на Windows. Валидный attested claim + владение QR ещё не выбирают родителя: копию живого QR может использовать второй настоящий телефон. Перед CAS исходная elevated setup session должна явно подтвердить тот же полный claim, который показывает нужный телефон; запрещены «первый ответ стал владельцем», незаметная замена pending candidate и короткий код без отдельно проверенного commitment protocol. Хранить точный offer/pending digest; повторно проверить текущий challenge/срок при commit. Обрыв, два телефона, повтор QR и повтор setup после установки не должны приводить к чужому владельцу или потере существующего ключа.
4. Показать и подтвердить сохранение отдельного Recovery Kit; Windows хранит verifier, Android не оставляет Kit в backup/логах/уведомлениях. При незавершённом сохранении не объявлять setup законченным.
5. Подключить в `MainActivity` сеть, проверенный snapshot, карточку объекта/срока, `BiometricPrompt`, `ApprovalCoordinator` и `FileApprovalOutbox`. Ошибка биометрии, отмена, отсутствие аппаратного ключа или неверная подпись запроса не открывают подписание.
6. Подключить view key PWA: ключ просмотра и доверие к компьютеру выдаются через доверенную привязку; браузер не хранит approval key. Кабинет выполняет настоящую расшифровку/проверку, а не только получает флаг `verified` от сервера.

Проверенная часть M3.6, 2026-09-30: `parent/pwa/src/relay-receive.ts` реализует настоящий receive-only HPKE/ECDSA на встроенном WebCrypto, по [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) и [W3C Web Cryptography](https://www.w3.org/TR/webcrypto/). Общий публичный .NET/Kotlin fixture расшифрован, подпись компьютера проверена над исходными GRDE bytes. Доверенная привязка закрепляет mailbox/recipient/device/key/epochs; принимается только неизвлекаемый ECDH P-256 ключ просмотра с deriveBits, не ключ разрешений. Проверяются канонические GRF1/GRDE/GRRQ, UTF8/NFC/controls, лимиты/enum, точные int64 revisions и время до/после async crypto. Весь повреждённый batch отклоняется, а не превращается в «нет запросов»; комментарий ребёнка и срок показываются безопасным текстом. `main.ts` сам создаёт конкретный verifier из `guardParentViewEnrollment`, прежний подставляемый callback удалён. Доверенная выдача/хранение/отзыв enrollment ещё не реализованы, поэтому обычный вход остаётся закрытым; relay/login не являются источником доверенного ключа. PWA 69/69 + typecheck/build и .NET relay crypto 9/9 PASS. Проверены подмена каждого wire byte/все усечения, ключи/epochs/сроки, настоящие зашифрованные и подписанные некорректные payloads, запрет signing/export у view key. Это локальные криптографические проверки, не реальный браузер/телефон/deploy/exchange; durable replay/resolution ledger и защита часов остаются открытыми. M3 полностью не принят.

Проверенная часть M3.1–M3.3, 2026-09-30: общий GREO/GREC/QR-v2 связывает relay/device/mailbox/epochs/раздельные ключи/срок; QR proof — MAC всего claim, не публичный secret hash. `NativeEnrollmentCoordinator` теперь сохраняет offer, attested candidate, зашифрованный challenge decryption-ключу телефона и hash отдельного секрета исходной elevated session в том же protected authoritative state/journal. Первый валидный claim только закрепляется; второй телефон не подменяет его. Телефон доказывает расшифровку, затем исходная setup session подтверждает полный claim hash и точную версию. Проверки attestation/MAC/signature/сроков повторяются после crypto и перед атомарной публикацией файла. В одном CAS появляются owner+binding и удаляется setup challenge; обычный reducer/commit не может потерять подтверждённую привязку. Старый raw-secret CompleteAsync теперь всегда отказывает. Schema 1 читается без reset, но старые keys не становятся attested enrollment.

Проверки M3: реальные временные файлы/journal, reopen, два настоящих синтетических ключа/цепочки, QR/proof replay, чужой local secret/role/hash/version, конкурирующие CAS, expiry во время status await/crypto/file publication, revoked/cancelled и отсутствие временных файлов после отказа PASS. Общий публичный HPKE fixture Windows→Kotlin даёт точный proof; подмена claim/key/ciphertext/размеров отклоняется. Android 23 JVM tests/debug APK и .NET-проверка настоящих JCA enrollment/approval signatures PASS. После финальной проверки времени полный safe script EXIT0: Release-сборка, 29 v2 harnesses и 45 legacy checks PASS. Это НЕ физическая биометрия и НЕ приёмка M3. Остаются encrypted claim/chain transport, trusted release APK identity и подключение Google source, originating comparison UI, scanner/биометрия, Recovery Kit и view bootstrap. Контракт/команды: `protocol/guard-relay-v1.md`, `parent/android/README.md`. Основной ПК, VM и deployment не менялись.

Источник доверия M3.2, 2026-09-30: `GoogleAndroidAttestationSource` загружает два текущих официальных RSA-4096/P-384 root из встроенного PEM с pinned DER SHA256 и получает status только с `android.googleapis.com/attestation/status`. Штатный TLS, без redirects/proxy/cookies; 1 MiB streaming/20 секунд; Cache-Control/Date/Age и время передачи/monotonic residence не дают новому GET продлить старый ответ. Нет stale-if-error, 304/heuristic fallback или дискового кэша. Дубликаты raw headers проверяются до typed normalization .NET (найденная регрессия исправлена). Общая Release-сборка/29 v2/45 legacy PASS; crypto regression после финального cancellation guard PASS; два настоящих clean-process HTTPS smoke PASS, без регистрации телефона. Public connection/команда `--check-google-source` задокументированы в `protocol/guard-relay-v1.md` и wiki connection journal. Далее: source + trusted APK release identity в setup composition, encrypted transport и originating/phone comparison UI; состояние Android ceremony описано ниже. Root rotation требует проверенного release update; системная защита trust store/часов и совместимость legacy factory chains не объявлены решёнными.

Android lifecycle M3.2, 2026-09-30: `AndroidEnrollmentCeremony` сохраняет PREPARED offer до генерации раздельных ключей с именами от полного offer hash. `PendingEnrollmentStore` в `noBackupFilesDir` сохраняет claim/chain/MAC, затем точную подпись до отправки; не сохраняет QR secret/hash-key. READY/SIGNED возобновляются без QR, PREPARED просит тот же QR. Потерянные ключи после claim не регенерируются, чужой callback/повторная подпись/отмена/expiry/наблюдённый rollback/повреждение файла отказывают. Только `StrongBoxUnavailableException` допускает TEE fallback при отсутствии оставленного ключа; проверяются местные профили обоих ключей, не вместо проверки Windows. Локальная отмена сохраняет ключи: это НЕ remote revoke/подтверждение owner; Windows могла успеть выполнить CAS. Лимит восемь сохранённых попыток требует будущего подписанного согласования результата/очистки, автоматического удаления нет. Проверены настоящие временные файлы, restart, конкурирующие записи, повреждения и expiry после подписи/перед rename: Android 30 JVM tests, debug/instrumentation APK и lint PASS (13 предупреждений настроек/версий, без ошибок), Kotlin→.NET signature interop PASS; общая Release/29 v2/45 legacy PASS. Физический hardware/restart/no-unauth-sign тест написан и скомпилирован, но NOT RUN; интерактивные биометрические gates остаются открыты. Следующий связанный шаг — encrypted enrollment transport и signed completion reconciliation, затем подключение scanner/биометрии/comparison UI и Recovery Kit. MainActivity пока shell; приложение и политики на основном ПК не запускались.

**Приёмка:** clean setup и одна проверенная карточка на Android/PWA, свежая аппаратная подпись и её проверка .NET. Реальные тесты отпечатка заменяют пустые `@Ignore` placeholders. Инженерная проверка телефона на этом этапе ещё не означает приглашение к семейному использованию. Тесты: T05–T06, T13–T16.

Зашифрованная граница M3, 2026-09-30: `NativeEnrollmentExchange` принимает GREX claim/chain/proof/query и вызывает настоящий durable coordinator; не имеет маршрута local-confirm. Kotlin шифрует HPKE существующим фиксированным suite; ответы Windows отдельно подписаны и связаны с полными offer/claim hashes, свежим nonce, version и сроком до минуты. Три исхода строго различаются: требуется proof телефона, требуется исходное локальное подтверждение, owner уже сохранён. Проверены реальные синтетические attestation/file/CAS, restart, exact retry, запрос после истечения QR, tamper/expiry/cancellation и предел chain 64 KiB без увеличения обычного GRF1. Kotlin проверяет реальные .NET ответы, .NET независимо расшифровывает Kotlin claim/proof/query; Android 34 JVM tests/debug APK/lint PASS. Физическая биометрия и live relay НЕ проверены. Следующий шаг: scoped GREX endpoint/credentials + HTTP delivery, durable Android outstanding nonce/result/active-owner reconciliation, затем setup/scanner/биометрия/Recovery Kit. Текущий возвращаемый verified result ещё не активирует владельца; основная система всё ещё не готова.

Сетевой инкремент M3, 2026-10-01: в существующем mailbox реализован отдельный bounded GREX requests/replies path; device credential открывает ровно offer hash, phone capability выводится domain-separated HMAC из QR proof key и полного offer hash (.NET/Kotlin interop). Только hash capability и непрозрачные bytes сохраняются на relay; нет approval/admin прав и изменения owner. Проверены настоящий HTTP→Durable Object→SQLite путь в локальном Worker runner, точные bytes Kotlin/.NET, роли/чужой offer/mailbox, retry/reopen/конкурирующие nonce, >64 KiB chain без расширения GRF1, квоты и отзыв/expiry при медленном body. Срок отправки новых claim/proof до QR expiry; query результата ещё 24 часа, отдельный обмен хранится до двух минут. Deadline не продлевается повторным provisioning. После окна нужен явный recovery/reconciliation, не удаление локальных ключей. Внешнего deploy нет. Durable Android nonce/result/active-owner, сохранение capability без QR secret, клиентское HTTP wiring и setup UI остаются следующей связанной частью; серверные тесты не означают готовности телефона или M3 целиком.

Проверка сборки 2026-10-01: interop обнаружил, что `Guard.RelayState.Tests`/`Guard.Windows.RelayCrypto.Tests` не входили в solution, а safe script запускал прежние DLL с `--no-build`. Оба проекта включены в Release build; скрипт теперь заранее отказывает, если любой разрешённый harness не входит в эту конфигурацию. После исправления свежие Release/29 harnesses/45 legacy и обе .NET↔Kotlin проверки PASS; Worker 51/typecheck, Android 34/debug/lint PASS. Прежний общий build сам по себе не доказывал свежесть этих двух DLL (отдельные project builds остаются валидным evidence).

Android delivery M3, 2026-10-01: GEN2 существующего no-backup файла сохраняет scoped capability без QR secret/proof key, точные GREX bytes/nonce до отправки и подписанный результат одновременно с погашением запроса. GEN1 читается без reset; без capability нужен исходный живой QR/recovery. Retry byte-identical, после минуты новый nonce; после expiry/отмены только query, не новые ключи/claim. Confirmed binding восстанавливается по заново проверенной сохранённой подписи на исходный момент приёма и существующим Keystore-ключам; не означает текущих разрешений/Recovery Kit/Protected. HTTPS-клиент выполняет один POST/GET, exact pinned endpoint, no redirects/proxy/cache/cookies, 20s absolute cancellation/disconnect и 414-byte response cap. Проверены реальные файлы/JCA, restart, три стадии, nonce/version/outcome substitution, old reply без погашения нового запроса, rollback, expiry после fsync, GEN1 и сетевые ошибки: 41 JVM, debug/instrumentation APK, lint (0 ошибок/13 прежних предупреждений), обе .NET interop проверки PASS. HTTP контролировался fake-соединением; физическая биометрия и полный сетевой путь не проверены. Следующий шаг — Windows provisioning/poll/reply composition и setup/scanner/biometric UI, затем Recovery Kit и view bootstrap. Облако/основной ПК не менялись.

Windows delivery M3, 2026-10-01: `NativeEnrollmentRelay` использует прежний pinned `HttpRelayTransport` для provisioning/poll/reply/reject и настоящий `NativeEnrollmentExchange`; один сериализованный проход без новой базы/фонового планировщика. После неизвестного HTTP исхода снова poll, а не повторная шифровка уже отвеченного nonce; commit кандидата/owner предшествует ответу. Только доказанный отказ входящего crypto/claim удаляет одно сообщение; сбои attestation source, storage и сети оставляют его для retry. Повторная проверка после await выявляет даже замену setup/confirmation secrets при прежнем offer. QR показывается только после provisioning, исходное локальное подтверждение остаётся обязательным. Реальные file/CAS/attestation с управляемым HTTP: lost response до/после публикации, restart, hostile GCM/curve/candidate, concurrent calls, retention и смена session PASS; transport bounds/roles/JSON/binary/cancellation PASS. Общий свежий Release +29 v2 harnesses/45 legacy PASS, после последней малой правки повторные Crypto/Service и Kotlin→.NET exchange PASS. Production startup остаётся закрыт: следующий шаг — доверенные persistent device keys/config/release identity и setup/scanner/biometric UI; далее Recovery Kit/view bootstrap и реальный телефон. Worker не развёрнут, основной ПК/VM не менялись; M1 admin-resistant expiry не закрыт.

Постоянная Windows identity M3, 2026-10-01: `DeviceIdentityStore` сохраняет раздельные P-256 signing/encryption keys и случайный device ID одним bounded DPAPI record с отдельным purpose. Фиксированные `device.identity`/`.pending` включены в прежнюю SYSTEM-only ACL-проверку; service composition не пишет файлы. Явный bootstrap под существующим writer lease сначала атомарно сохраняет ключи, потом создаёт state. Полный key record без state возобновляет прерванный первый bootstrap без смены ключей; недописанный `.pending`, любой state/backup/journal при повторной инициализации и отсутствующий/повреждённый ключ при normal startup отказывают без reset. Service load/commit сверяют device ID и обе роли/публичные ключи с enrollment; ключи не входят в IPC/state DTO. Реальные временные файлы + DPAPI CurrentUser тестового пользователя проверили reopen, прежнюю подпись/HPKE, конкурентный writer, потерю/чужую identity, повреждения/размеры/purpose, malformed plaintext, одинаковые ключи, guard/cancellation после flush и очистку plaintext. Свежий Release +29 v2 harnesses/45 legacy PASS; после финального cancellation guard повторные Crypto/Service PASS. SYSTEM ACL/служба/power-cut в VM в этом инкременте НЕ проверены. Это не TPM/non-exportable storage/admin-resistance/защита совместного rollback; старый state без ключей требует отдельной migration/recovery, не автоматической генерации. Далее — доверенные relay/config/release identity и setup UI.

Доверенная конфигурация M3, 2026-10-01: `EnrollmentDeploymentTrust` читает relay origin/Android APK signer SHA256/min-version только из metadata сборки службы; неполный набор MSBuild properties останавливает сборку, отсутствие всего набора запрещает enrollment без fallback. `device.relay` — отдельный bounded purpose-separated DPAPI record с точными device ID/key IDs/mailbox/epochs/сроком device credential. Импорт внутренний, до IPC под writer lease, сам читает текущий pristine state; повторная запись/установка после начала setup запрещена. Общий `ProtectedServiceRecord` переиспользует прежнюю immutable publication и очистку plaintext. `ServiceNativeEnrollment.OpenAsync` связывает persistent identity, конфигурацию, реальные Google roots/status, coordinator и HTTP, но ещё не подключён к installer/setup UI. Проверены реальные временные файлы/DPAPI, reopen, подмена origin/roles/keys/epochs, expiry, malformed/duplicate/unknown JSON, wrong purpose, отсутствие pins/lease, отмена и guard после flush. Свежие Release/29 v2 harnesses/45 legacy PASS, после финального чтения актуального state повторный Crypto PASS; частичный набор release pins дал ожидаемый build error. Это не реальный выпуск: APK signer/endpoint ещё не заданы, trusted off-PC provisioning/import workflow не готов, облако/телефон/VM не менялись. JSON `role=device` сам по себе не доказывает роль opaque token — сервер проверяет её при открытии enrollment; admin/bootstrap credentials нельзя передавать установщику. Далее — этот provisioning workflow, исходный setup/scanner/biometric UI и Recovery Kit/view bootstrap; M1 остаётся открытым.

### M4. Первый законченный сценарий — приложение

**Результат:** неизвестная тестовая программа реально заблокирована в VM, разрешена с телефона на 15 минут и снова закрыта по сроку.

1. Подключить production inventory/Authenticode/PFN/hash extraction, защищённый каталог базовых компонентов и policy sink, доказанный в M1. Для unpackaged grant — exact SHA-256, для packaged — exact PFN; publisher/product/root служат доказательствами происхождения, не широким allow.
2. Создать непривилегированный `Guard.Child` с автозапуском в защищаемых сессиях, Windows blocked-launch event reader, bounded observation → request IPC, дедупликацией и понятными статусами. Child path/title/publisher не считаются доверенными данными.
3. Провести путь блокировка → локальная durable очередь → relay → native verification/choice/biometric → .NET command validation → durable desired state → реальное применение → проверка effect → receipt → обновление статуса на телефоне/ПК.
4. Заменить production `BoundaryOnlyPolicyReconciler` только после подключения готовых sinks; не убирать fail-closed readiness ради зелёной демонстрации. После рестарта policy сверяется до выдачи статуса готовности.
5. Доказать, что разрешена именно нужная программа: замена файла между проверкой и применением, другое содержимое по тому же пути, другое приложение того же издателя и будущая неизвестная версия не наследуют grant. Закрыть DLL/plugin/child-process варианты в рамках проверенного пакета.

**Приёмка:** в VM выполняется E01 ниже с реальным Worker и подписью телефона; EXE пишет тестовый marker только после разрешения. После expiry/revoke новый запуск и продолжение уже запущенной программы обрабатываются по принятой политике. Тесты: T02–T05, T08–T09, T12, T15–T17. Это первый работающий сценарий, ещё не весь продукт.

### M5. Второй законченный сценарий — сайт

**Результат:** Edge остаётся открытым, запрещённый сайт показывает запрос; после решения сайт открывается, после срока соединение закрывается.

1. Создать `Guard.Proxy` под отдельной низкопривилегированной identity: bounded HTTP/CONNECT, проверка DNS/IP/портов, pinning разрешённого назначения, отсутствие HTTPS interception. Подключить существующие domain/PSL/bundle parsers и signed-catalog floors к настоящему storage.
2. Реализовать machine-managed Edge policies, WFP/network closure и проверку effective policy. Proxy, BFE/WFP и браузер должны давать наблюдаемое доказательство готовности; не выводить его из желаемого registry value.
3. Сделать managed extension и локальный authenticated request bridge к службе. Расширение показывает блокировку до навигации, связывает top-level сайт с техническими запросами и не является единственным сетевым барьером. CSP/extension permissions минимальны; native host не исполняет произвольные команды.
4. Соединить site request с уже работающей цепочкой M4. Default scope — exact canonical host; subtree/service bundle только после явной проверки и подписи. Реклама/CDN/соседний tenant не открываются автоматически.
5. Отключить или закрыть обходы через QUIC, внешние DNS/DoH/proxy/VPN, unsupported browser и прямой выход браузера. Учесть сетевые возможности разрешённых приложений, WebView и системных посредников. Оставить только необходимые служебные endpoints, без универсального разрешения всему HTTPS.
6. Повторить адаптер и реальную браузерную матрицу для Chrome; проверить способ установки/обновления расширения, доступный на unmanaged Windows в закрытом пилоте. Публичная публикация расширения — отдельное действие после готовности пакета.

**Приёмка:** E02 в Edge и Chrome, T10–T11 и соответствующие T17; при crash proxy/extension или изменении сети запрещённые байты не проходят. Разрешённые HTTPS/WebSocket/download/OAuth сценарии работают без собственного корневого TLS-сертификата.

### M6. Все решения, сроки, обслуживание и аккаунты

**Результат:** ежедневное использование не требует ручной правки политик, смена аккаунта не обнуляет правила.

1. Соединить четыре решения для приложений/сайтов: всегда; на 15/60 минут, до конца дня или текущей сессии; расписание+дневная квота; запрет до завтра/на 7 дней/до изменения. Если current wire не выражает вариант, версионировать контракт и общие vectors; не прятать иной смысл под старым полем `minutes`.
2. Реализовать durable usage/quota и доверенную модель времени. Считать foreground без idle, многопользовательские сессии и вкладки без двойного счёта, часовой пояс задаётся родителем. Фоновая музыка/видео в первом выпуске не расходуют квоту; это явно написано в UI. Sleep/reboot/rollback часов не увеличивают остаток.
3. Реализовать signed revoke и pause/maintenance на 15/30/60 минут: точный scope, recovery-admin SID и deadline, автозавершение по таймеру/reboot/logout. Дневной аккаунт ребёнка не получает admin tools из-за обслуживания другой сессии. «Включить защиту сейчас» завершает действующую паузу.
4. Установка/обновление приложения в maintenance создаёт список точных новых identities для отдельного родительского решения. Не выдавать автоматический permanent allow всем новым EXE или всем файлам издателя.
5. Довести inventory/monitor учётных записей и recovery-admin pinning: повседневные accounts стандартные; cloud-linked/directory/nested admin, новое членство/включение account, неизвестный SID и смена recovery account дают проверяемую реакцию. Восстановление почты Microsoft не должно менять локальные права. Опасные изменения через Guard требуют подписи; внешние изменения Windows покрываются системой M1.

**Приёмка:** E03–E06 и T07–T09, T17–T18. Ни TTL, ни квота, ни обслуживание не зависят только от работающего окна/таймера UI. Последний recovery path нельзя автоматически уничтожить ради исправления readiness.

### M7. Кабинет, QR и уведомления для повседневной работы

**Результат:** родитель понимает, что запросили, что разрешено и действительно ли компьютер применил решение.

1. Довести разделы «Запросы», «Сегодня», «Ребёнок/устройства», «Разрешения», «Безопасность». Desktop — постоянная левая навигация, mobile — компактная; русские тексты, keyboard/screen-reader/zoom, отсутствие технических токенов и внутренних терминов в обычном потоке.
2. Кнопка на телефоне открывает native проверенную карточку. На другом экране — короткоживущий QR, видимый срок и безопасная повторная генерация locator. Разрешение clipboard не является условием открытия приложения; предусмотрены отсутствие Android-приложения, истёкшая ссылка и отмена.
3. Добавить FCM opaque wake-up и переход к запросу, runtime notification permission, объединение повторов и backoff. Для этого потребуется отдельный Guard Firebase project/config; его credentials не брать из другого приложения. Push не содержит названий/домена/решения/секретов и не разрешает действие с lock screen.
4. Подписанный свежий статус компьютера, last-seen и ошибка применения показываются отдельно от связи с relay. После потери связи статус становится «Неизвестно/компьютер не отвечает», а не сохраняет зелёную надпись «Защищён».
5. Проверить versioned deployment PWA/service worker, страницу offline и обновление кабинета без устаревших assets. Offline PWA не создаёт новое разрешение. Очередь запросов остаётся доступным источником истины при задержанном push.
6. После завершения функциональности выполнить единый визуальный проход по всем пользовательским экранам Guard: Windows setup/детские окна, Android и родительский PWA. Решение Ивана от 2026-09-30: визуальный ориентир — Codex; закруглённые панели, карточки и кнопки, сопоставимые размеры шрифтов, элементов управления и отступы. Основной текст и рабочие подписи на светлом фоне — чёрные, чёткие, без бледно-серых надписей. Приглушённый вторичный текст допустим в меню настроек, только при достаточной читаемости. Сохранить системное масштабирование текста, заметный фокус и доступность; не переносить брендинг Codex. Это отложенное оформление перед M9, не переключение с текущей функциональной реализации.

**Приёмка:** родитель проходит ежедневные действия без ручного ввода ключей и без обязательного браузерного clipboard; T13–T16, T19 и E01–E04. Отказ push разрешений не отключает защиту и не скрывает запросы при открытии кабинета. После визуального прохода проверить реальные экраны Windows, Android и PWA при обычном и увеличенном тексте: контрастные подписи, отсутствие обрезания и единое оформление кнопок/панелей. Стиль сверить с доступным визуальным образцом Codex, а не объявлять совпадение размеров без проверки.

### M8. Установка, обновление, восстановление и удаление

**Результат:** продукт можно безопасно установить, обслужить и восстановить без ручного «почистить всё».

1. Сделать installer v2 с точным manifest файлов, проверкой платформы, service registration/DACL/recovery/identity, proxy/child/extension и пошаговым setup. Старые PIN, state, server ownership и allow-листы не импортируются как доверенные. Legacy-файлы/правила обрабатываются адресно; чужие firewall/registry данные сохраняются.
2. Ввести подписанный update manifest и package verification, version/epoch rollback floor, staging, atomic activation и rollback к проверенной версии. Crash на каждом шаге не должен оставлять unrestricted окно или несколько authoritative writers. APK подписывается постоянным release key; обычное обновление сохраняет trust/outbox.
3. Реализовать восстановление по 256-bit Recovery Kit: локальная elevated процедура, rate limits, durable delay, отзыв всех прежних epochs/keys/sessions/mailbox credentials/pending commands и безопасная новая привязка при сохранении запретной базовой политики. Предлагаемая задержка — 24 часа; закрепить точное значение в этом плане до реализации recovery. Перестановка часов/перезагрузка не сокращает задержку. При потере телефона оператор должен иметь понятный offline маршрут.
4. Проверить и согласовать удаление подписанной Windows policy: требуемые signer/reboot/recovery шаги, отсутствие конфликта со штатным uninstaller. Удаление требует свежего родительского разрешения либо принятой recovery ceremony. Старый Cleaner не становится альтернативным обходом.
5. Cleanup ведёт журнал этапов, проверяет их effect и снимает только свои ограничения. При частичной неудаче сообщает точный шаг и оставляет работающий путь восстановления; не удаляет бинарники, необходимые для завершения. Удаление аккаунтов/пользовательских файлов в cleanup не входит.
6. Подготовить CI для safe suites и сборки, supply-chain/secret scans, SBOM, hashes и release manifest. Signing keys остаются вне Git/логов и не выдаются CI чужих PR. VM tests запускаются на отдельном одноразовом guest с явной целью; GitHub-hosted runner не принимается за семейный Windows-стенд.

**Приёмка:** чистая установка, обновление с N−1, неудачное обновление, recovery и штатное удаление проходят T18/T20 и E07–E09. Для VM допустим test certificate внутри VM; способ доверия подписанной сборке семейного пилота документируется отдельно. Наличие публичного Windows-сертификата не доказывает защиту от администратора.

### M9. Полная приёмка и пакет для совместного теста

**Результат:** все части работают вместе; можно пригласить Ивана к контролируемому семейному тесту.

1. Из чистого checkout воспроизвести сборку, выполнить все safe suites и полную матрицу на чистой и обновлённой VM, затем на реальном Android. Не учитывать skipped/manual placeholders как PASS.
2. Выполнить все E01–E10 ниже с доказательствами: версии, VM/phone model/OS, command ids, ожидаемая/фактическая policy, signed receipt, exit/network marker и очищенные логи. Секреты и семейные данные в отчёт не включать.
3. Провести 24-часовой прогон, 30 последовательных решений, конфликтные решения двух родительских устройств, 10 reboot/reconnect циклов и серии потери связи. Это ограниченный reliability gate, не обещание вечной бесперебойной работы. Цель на стабильной тестовой сети: запрос и применение каждого обычного решения укладываются в 30 секунд; отдельно записать задержки и причины исключений.
4. Проверить self-review изменённого security-critical кода и реальные обходы. Любой воспроизведённый unauthorized grant, повторное permissive effect, утечка ключа, зависший allow без deadline, необратимая блокировка Windows или обход M1 блокируют приёмку. Некритичные UI-дефекты допустимы только с явным описанием влияния.
5. Подготовить один комплект: Windows installer, подписанный Android APK, URL кабинета, версии/хеши, короткая русская инструкция «установить → привязать → запросить → разрешить → вернуть защиту → восстановить/удалить», поддерживаемые платформы, остаточные ограничения и recovery-памятка. Не включать production secrets в комплект.
6. Commit/push результата, проверить доступность точного SHA в GitHub, обновить план/память фактическими PASS/FAIL/NOT RUN. После этого сообщить «Готово к совместному тесту». Установка на основной/семейный ПК — отдельное согласованное действие с сохранённым recovery, а не автоматическое следствие зелёных unit-тестов.

### Карта тестов, которые сохранить, дополнить или написать

У каждого ID есть проверяемые утверждения. **U** — безопасная автоматическая проверка логики, **I** — интеграция реальных компонентов без системного enforcement, **V** — disposable Windows VM, **P** — физический Android, **B** — настоящий браузер. Имитатор подписей/биометрии полезен в U, но не закрывает V/P. Новый тест помещается в ближайший существующий harness; отдельный проект создаётся только при необходимости изоляции платформы.

| ID / этап | Что проверяем | Что переиспользуем и что добавить |
|---|---|---|
| T01 · M0/M8 | P0: first-caller takeover, пустой/`123456` PIN, legacy provisioning/email recovery/remote PIN, прямой Cleaner/diagnostic bypass; сборка не включает старую authority | Сохранить 45 `Guard.Tests` checks (U); добавить v2 installer/migration regression (V), чтобы закрытый код не вернулся в поставку |
| T02 · M2–M6 | Межъязыковая точность bytes и подписи; request/revision/device/key/epoch/target/expiry binding; неверный ключ, один изменённый байт, replay, неизвестный enum/version, size/overflow/Unicode/DER; wire-версии новых maintenance/recovery решений | `Guard.Protocol`, `Guard.RelayProtocol`, `Guard.Windows.RelayCrypto`, Kotlin vectors и relay frame tests (U/I); добавить TypeScript view decryption и полный трёхсторонний exchange без fake verifier |
| T03 · M2/M4/M8 | Единственный writer/CAS; обрыв до/после state replace, journal, desired policy, receipt и ack; повтор доставки; disk full/read-only/corruption; missing state не запускает незаметный reset; rollback state, journal и их совместной копии | `Guard.Storage`, `Guard.RelayState`, `Guard.Windows.Storage` (U); fault-injection на реальных файлах и power-cut guest (V). Совместный rollback требует отдельного доказанного witness/TPM решения, не зелёного теста одного файла |
| T04 · M0/M2/M4 | Production DI использует реальные adapters; SCM/System boundary, bootstrap однократный, child pipe не публикуется до policy/readiness; сбой probe даёт Unknown/отказ; crash и restart восстанавливают работу без permissive окна | `Guard.Service`, readiness/service-health suites (U); добавить production composition integration и настоящий lifecycle SCM (V) |
| T05 · M3/M4 | Подмена роли/SID из payload, UAC non-elevated token, integrity/session/pipe impersonation, nested groups, неправильный pipe; child не вызывает setup/parent/recovery; oversized/partial/slow frames, flood, cancellation, handle leaks | `Guard.Windows.Ipc`, `Guard.V2`, request-protocol suites (U); реальные разные Windows tokens и конкурентные сессии (V) |
| T06 · M3 | Setup QR: чужой relay/device/transcript/key, expiry, screenshot/replay, два claimant, cancelled/half-finished enrollment, restart, повтор после привязки; поддельная/revoked attestation, чужой challenge и software key; secret не попадает в BFF/логи | `SetupCeremony`/`Guard.V2` и `EnrollmentQrParser` checks (U); native scan → real service trust commit (I/V/P), сохранение существующего ключа при ошибке |
| T07 · M1/M6 | Все ordinary accounts стандартные, recovery SID закреплён; cloud-linked/local/domain/Entra/nested admin, disabled→enabled, новый пользователь/администратор, смена account/token, восстановление Microsoft password; последний recovery account и unknown result | `Guard.Windows.Accounts`/readiness (U); machine-wide enforcement и монитор в нескольких сессиях VM (V). Проверить block, alert и итоговую policy отдельно |
| T08 · M1/M4 | До запуска заблокированы EXE/portable/MSI/MSIX/DLL/scripts/macros/interpreters/WSL/LOLBins; копия/rename, file swap/TOCTOU, reparse/hardlink/network/removable path, DLL/plugin side-load; exact grant не открывает другое приложение, updater или новую версию | `ApplicationIdentity`, `AppControlPolicy`, `ApplicationControl`, `ApplicationRequests` (U); безвредный marker corpus и real apply/readback/launch (V), включая уже открытый процесс после отзыва |
| T09 · M1/M6 | Stop/delete/reconfigure service, taskkill, ACL/file/state replacement, снятие AppLocker/App Control/WFP/browser rules, proxy spoof, Safe Mode/recovery/external boot; стандартный и тестовый elevated admin; outage при действующем TTL и повторная загрузка | SelfProtection contracts (U); отдельная attack matrix (V), firmware/BitLocker recovery drill на выделенном стенде. Не подменять результат «заблокировано» записью «обнаружено» |
| T10 · M5 | DNS canonical/IDN/PSL/trailing-dot/IPv4/IPv6/encoded host/ports, exact vs subtree, чужой CDN tenant, revoked/rolled-back catalog; HTTP/CONNECT malformed headers, smuggling, duplicate Host, большие/медленные запросы, DNS rebinding/private IP и смена адреса после проверки | `Guard.WebPolicy`, `Guard.WebProxyProtocol`, `Guard.WebsiteRequestProtocol` (U); настоящий proxy + test DNS/HTTP endpoints (I/V). Отклонение до открытия upstream socket |
| T11 · M5 | Edge и Chrome: top-level/subresource/redirect/OAuth/WebSocket/download/private mode; QUIC/DoH/IPv6/direct IP/custom proxy/VPN/portable browser/WebView; захват localhost port, пропавшее расширение, изменённая policy, crash proxy/BFE/network reconnect; нет выхода в обход | `Guard.BrowserPolicy`, `Guard.WebProtection`, `Guard.WebControl` (U); managed browsers + packet/sentinel capture внутри VM (V/B), проверка update браузера и policy refresh |
| T12 · M2 | Bootstrap/role/recipient isolation, token expiry/revoke, cursor bounds/ordering, duplicate frame/id collision, lost ack, quota/rate limit, TTL/paging, transient 5xx/timeouts, unavailable Worker; locator чужого mailbox/истёк/повтор; relay полностью недоверен | Существующие Worker tests (U/I); интеграция real .NET/Kotlin transport с fault server и изолированным mailbox в Guard Worker. Ни один relay hint не даёт grant/sequence advancement без локальной проверки |
| T13 · M2/M3 | WebAuthn origin/RP/challenge/replay/counter, failed ceremony одноразовая, credential/session revoke/TTL; CSRF/SameSite/CORS; scoped регистрация/view-device enrollment вместо глобального секрета в браузере | `webauthn.test.ts`, PWA passkey/transport tests (U/I); реальный browser passkey/login/logout/expired session (B/P), без выдачи approval capability |
| T14 · M3/M7 | PWA не показывает непроверенные/подменённые snapshots; view key не подписывает решения; plaintext/keys/tokens не в URLs/cache/logs; XSS/compromised view/переставленный locator не дают native blind signing; inbox >16, paging и two tabs не теряют запросы | PWA security/transport/domain suites (U); настоящий verifier + BFF + браузер (I/B), доступ с новой/отозванной view-сессии |
| T15 · M3 | Android supported API и hardware ECDH/signing; strong biometric success, cancel, wrong fingerprint, lockout, PIN/pattern/password fallback, повтор подписи без нового prompt, enrollment-change invalidation, TEE/StrongBox/unsupported device, attestation mismatch | JVM suites (U) сохранить; вместо трёх пустых ignored androidTests — исполнимые instrumentation tests плюс явный manual protocol физического прикосновения (P). Эмулятор не закрывает аппаратные проверки |
| T16 · M2/M3/M7 | Outbox commit до send; те же байты после crash/rotation/process death/reboot; offline retry; interim receipt не Applied, чужая/поддельная/дублированная terminal receipt; два решения/два родителя; backup/restore/app reinstall не клонируют authority; Doze/FCM delay/notification refusal | `FileApprovalOutbox`/receipt checks (U); реальная сеть, lifecycle и private/no-backup storage (I/P), следующий sequence только после проверенной terminal receipt |
| T17 · M4–M6 | Все 4 решения; TTL/session/end-of-day/schedule/quota, forbid durations; parent-pinned timezone/DST/clock rollback/sleep/reboot, idle/foreground/multiple sessions/tabs; revoke/expiry закрывают текущий процесс/туннель, не только новые; обновление приложения не наследует allow | `Guard.Policy`, application/web reconciliation и безопасная legacy accounting логика (U); production scheduler/usage и clock-fault/reboot/connected tunnel cases (V/B). Установить и измерить допустимую задержку закрытия в M1 |
| T18 · M6/M8 | Scoped maintenance + logout/reboot/expiry; crash/update rollback; fresh install/N−1 upgrade/tampered package/downgrade; repair не сбрасывает владельца; Kit wrong/replay/delay/time rollback/lost phone/epoch revocation; uninstall direct/legacy/partial failure; чужие данные целы | `Guard.Service`/storage/legacy cleanup pure tests (U); новые installer/update/recovery cases с snapshot и проверкой реальных effects (V/P), отдельная процедура возврата подписанной policy |
| T19 · M7/M9 | Русский по умолчанию и EN parity; клавиатура, focus, screen reader, 200% zoom, 360px mobile/desktop; request flood grouping, понятные причины/сроки, QR expiry/missing app/clipboard denial, offline/pending/applied/error/last-seen; никакого ложного Protected | PWA i18n/domain tests (U); browser и Windows child/Android UI сценарии (B/V/P), проверка реального пользовательского пути без технических токенов |
| T20 · M0/M8/M9 | Clean checkout build, lockfiles/dependency verification, NuGet/npm/Gradle vulnerabilities, secret scan, licenses/SBOM, signatures/hashes/update signer, release manifest; bounded RAM/disk/queues/logs/threads и polling на idle/нагрузке; чистое удаление тестовых ресурсов | Существующие builds/audits (U/I) + минимальный CI/runner; длительный прогон (V/P). Пять прежних high findings в dev tooling требуют свежей оценки/исправления, production audit не выдавать за full audit |

### Сквозные сценарии приёмки

Во всех сценариях проверяем конечный доступ (process/network marker), durable policy и подписанный статус устройства. Одного HTTP 200, снимка UI или зелёного unit-теста недостаточно.

| ID | Действия и ожидаемый результат |
|---|---|
| E01 · приложение | Чистая VM → установка/QR/setup → blocked test app → один объединённый запрос → отпечаток «15 минут» → приложение запускается → срок заканчивается → доступ закрыт; файл другого hash по тому же пути остаётся закрыт |
| E02 · сайт | Edge, затем Chrome → blocked HTTPS сайт → страница запроса без закрытия браузера → решение → сайт и только проверенные зависимости работают → expiry/revoke закрывает также открытый туннель; соседний домен/прямой маршрут остаётся закрыт |
| E03 · решения | На app и site пройти always, временное/session/end-day, daily quota+schedule и deny с выбранным сроком; смена Windows account и часов не обнуляет решение/остаток; родитель видит точные сроки |
| E04 · сбои связи | До подписи выключить сеть — нового решения нет; после подписи оборвать доставку/ack/receipt — повторены те же байты, один effect; телефон/Windows/Worker перезапускаются, статусы честные, разрешённое окно не становится бессрочным |
| E05 · обслуживание | Отпечаток на scoped 15-minute maintenance → вход recovery-admin → установка/обновление → список новых identities → отдельное разрешение → возврат защиты по кнопке, таймеру, logout и reboot; детская параллельная сессия не получает admin bypass |
| E06 · аккаунты и tamper | Смена на другой/новый account, тестовый новый admin, попытки stop/delete/policy tamper/Safe Mode → ожидаемый результат M1 подтверждён фактически; родитель видит событие, неизвестная policy не объявляется готовой |
| E07 · обновление | Принятая N−1 с owner/grants/outbox → валидный update сохраняет trust → повреждённый/старый пакет отказан → power-cut при активации восстанавливает проверенную версию без свободного доступа |
| E08 · потерянный телефон | Старый Android недоступен → локальная recovery ceremony с Kit/задержкой → новый телефон → старые ключи/сессии/решения отвергнуты; защита не отключалась. Отдельно проверить второй заранее зарегистрированный approval device |
| E09 · удаление | Неавторизованный запуск uninstaller/Cleaner отказан → свежее разрешение/принятая recovery → свой policy/service/proxy/extension cleanup подтверждён → Windows и сеть работают, чужие данные сохранены; отказ на промежуточном шаге имеет проверенный recovery |
| E10 · длительная работа | 24 часа, 30 решений, 10 reboot/reconnect и конфликт двух родителей; нет пропавших запросов, двух применённых конфликтных решений, unbounded storage/CPU и неопределённого статуса, скрытого за «Защищён» |

### Порядок запуска проверок и доказательства

1. Для каждого изменения сначала его T-группы и ближайшая интеграция. После их PASS — соответствующий E-сценарий. Полный regression выполнять на границе интеграционного этапа и release candidate; повторять неизменённый набор без новой причины не нужно.
2. Safe baseline: `dotnet msbuild guard.sln /restore /p:Configuration=Release /p:Platform="Any CPU"`; затем `Guard.Tests\bin\Release\net48\Guard.Tests.exe` и явный allowlist 29 `tests/*/*.csproj` console harness через `dotnet run -c Release --no-launch-profile`. Нельзя заменять их запуск запуском `Guard.Service.exe`, Guard/installer/Cleaner.
3. PWA: в `parent/pwa` — `npm ci`, `npm test`, `npm run build`. Worker: в `relay/worker` — `npm ci`, `npm test`, `npm run typecheck`. Lockfile менять только осмысленно. Production и full dependency audit фиксируются раздельно.
4. Android: задать `JAVA_HOME`, `ANDROID_HOME`, `GRADLE_USER_HOME`; `gradlew.bat :app:testDebugUnitTest :app:assembleDebug`. Cross-language verification — существующий `Guard.Windows.RelayCrypto.Tests --verify-android` с generated public test vector. Instrumentation и fingerprint checks выполняются отдельно на конкретном устройстве; `@Ignore`/нет устройства = NOT RUN.
5. Все privileged Windows проверки запускаются только адресно в disposable guest. Перед запуском сохраняется snapshot/VM id; после — guest results и проверка восстановления. На host допустимы сборка, чистая логика, работа с Git и управление выделенной VM; применение защитных политик к host запрещено.
6. В этом плане у этапа записывать: commit SHA, сборка/версия, T/E IDs, среда, PASS/FAIL/NOT RUN, краткий результат и ссылка на очищенный отчёт. `NOT RUN`, mock-only и ручная проверка без evidence не считаются PASS. Подробные generated отчёты не превращать в новый канонический план.
7. Код фиксировать малыми связанными commits и push после соответствующих проверок. Откат функции — `git revert`, база — сохранённый checkpoint. Не коммитить secrets, личные данные, generated installer или чужие изменения автоматически.

### Зависимости от Ивана и стоп-условия

- Для составления этого плана дополнительных действий не требуется. Команда запустить разработку разрешит M0 и последующие уже описанные действия; повторно спрашивать разрешение на обычные сборки/правки/тесты не нужно.
- На M0 может понадобиться UAC для Hyper-V и доступный Windows 11 Pro ISO/лицензия стенда. Команда должна заранее быть конкретной и ограниченной выделенной VM. На M3/M9 потребуется модель/версия Android, установка подписанного APK и физическое подтверждение отпечатком; Codex не может имитировать палец родителя.
- На M2/M7 возможен интерактивный вход в Cloudflare/Firebase, если нужное действие недоступно уже разрешённому Guard-токену. Не расширять его на VoicePaste и не просить переносить секрет в чат. Настройка бесплатных ресурсов не означает разрешения на оплату.
- Публичный домен, публично доверенная подпись и публикация в магазинах остаются отдельными решениями перед публичным выпуском. Они не задерживают code/VM разработку. Семейная установка требует готового комплекта M9 и отдельного явного начала теста.
- Если M1 опровергнет обещанную стойкость к полному администратору, если аппаратная биометрия телефона не подходит, либо recovery не позволяет безопасно вернуть Windows, представить Ивану конкретные варианты и последствия. Не снимать требование, не подменять биометрию PIN и не объявлять проект завершённым.

### Проверенные платформенные ограничения и источники

- 2026-09-29: Microsoft указывает, что App Control применяется ко всем пользователям машины. Это основание исследовать его для нового аккаунта; отсюда не следует автоматическая защита любого сервиса или произвольного динамического grant. [Обзор App Control и AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol-and-applocker-overview).
- 2026-09-29: подписанные base/supplemental policies используют PKCS#7/RSA, ECDSA не поддерживается; anti-tamper требует Secure Boot и вступает в силу после reboot. Ошибки могут нарушить загрузку, поэтому M1 обязательно проверяет recovery. [Подписанные политики Microsoft](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/use-signed-policies-to-protect-appcontrol-against-tampering).
- 2026-09-29: `KeyProperties.PURPOSE_AGREE_KEY` появился в API 31; текущий `minSdk=30` не является доказательством совместимости аппаратного ECDH на Android 11. [Android KeyProperties](https://developer.android.com/reference/android/security/keystore/KeyProperties#PURPOSE_AGREE_KEY).
- 2026-09-29: Microsoft прямо указывает, что на автономном ПК локальный администратор полностью управляет AppLocker policy. Signed App Control при Secure Boot сильнее: изменение требует признанного signer, а произвольная подмена может привести к отказу загрузки. Из этого **не** следует автоматическое истечение ранее подписанного supplemental allow, когда Guard-служба остановлена. Это открытый M1 gate, а не доказанная защита всех случаев. [AppLocker security considerations](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/security-considerations-for-applocker), [App Control with VBS](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/introduction-to-virtualization-based-security-and-appcontrol), [signed policy requirements](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/use-signed-policies-to-protect-appcontrol-against-tampering).

### Текущий статус нового маршрута

| Этап | Статус | Условие перехода |
|---|---|---|
| M0 | Частично: safe baseline, guest baseline, PowerShell Direct и snapshot restore/boot PASS; recovery-media, официальный ISO hash и финальный Pro gate открыты | Проверенный disposable guest с полным recovery |
| M1 | Signed base audit/enforce/admin-remove/recovery experiment PASS; dynamic grant FAIL, TTL/revoke NOT RUN; следующий focused run ждёт UAC | Принятая матрица системной защиты и совместимый dynamic approval path |
| M2 | .NET transport/fanout, Worker scopes/retry/cursor и PWA↔BFF одноразовые registration tickets проверены локально; schema ещё не deployed | Trusted enrollment/полный view-session revoke, реальный encrypted exchange, shared Android wire cursors и durable receipts |
| M3 | Foundations есть; сценарий открыт | Доверенная привязка и реальная аппаратная подпись |
| M4–M8 | Не приняты | Соответствующие T/E и наблюдаемый пользовательский результат |
| M9 | Не начат | Все обязательные группы прошли, комплект пригоден для совместного теста |

## Проверенный инкремент 2026-09-24 — обмен и защита конфигурации аккаунтов

- Коммиты рабочей ветки: `3d2c936` (Android, точные квитанции, очередь, interop), `8d1c94f` (аккаунтная readiness), `f9da083` (исправленные зависимости). Документация и память фиксируются следующим связанным commit; это не merge/release.
- Android build-блокер исправлен. Вместо синтетического невалидного P-256 ключа добавлен общий публичный interop-вектор: настоящий .NET HPKE + device signature → Kotlin, Kotlin/JCA approval signature → .NET. Проверены подписанные промежуточная и терминальная квитанции, точный device-key ID/epoch, exclusive expiry и отклонение недопустимых точек/переполненных времён/DER.
- Добавлена атомарная файловая очередь Android в app-private/no-backup storage: те же байты при повторе, сохранение sequence, запрет следующего решения до подписанной точной терминальной квитанции, отказ при повреждении и защита конкурирующих экземпляров одного процесса. Перепривязка не уничтожает существующий ключ без отдельного recovery.
- Существующая production readiness проверяет `USER_INFO_24` (без чтения/журналирования адреса почты). Интернет-привязанный или дополнительный включённый администратор блокирует готовность; неизвестный источник входа — `Unknown`. Это не полноценный monitor/enforcement: привязка recovery-SID, внешние группы/domain/Entra, защита security questions/reset media и реакция на изменения остаются обязательными. На хосте аккаунты не читались этим кодом и не изменялись.
- Сборка Release без предупреждений, 29 v2 harness, 45 legacy checks, 18 Android tests + APK, PWA 26 tests/build, relay 15 tests/typecheck — PASS. PWA full audit и relay production audit чистые после Vitest 4.1.11, nanoid 3.3.18 и SimpleWebAuthn 13.3.3. В Cloudflare dev dependencies остаются 5 high findings через sharp/undici; полную очистку не заявлять, несовместимый `audit fix --force` не запускать.
- Self-review: закрыты гонка нескольких экземпляров outbox и усечение слишком большого DER integer; добавлены проверки. Это self-review текущего delta, не независимый аудит всей системы. Публичные тестовые ключи не являются enrollment/recovery secrets и не попадают в APK.
- Внешние gates на момент 2026-09-24: Hyper-V module и `vmms` есть, но `Get-VM`/`Get-VMHost` возвращают отказ в доступе текущему сеансу. Cloudflare тогда ещё не был подключён; актуальный статус подключения и публикации — выше. Тестовая VM по-прежнему требует разрешённого доступа; системную защиту на хосте не запускать.
- Главный результат продукта всё ещё открыт: native enrollment, карточка/биометрия/сеть, authoritative receipt/reconciliation, машинное enforcement, child UI и installer/recovery не соединены. К совместному семейному тесту пока не приглашать. Не превращать перечисленные PASS в отметку «всё приложение готово».

## Текущая проверка готовности и русификация (история 2026-09-23)

- Рабочий корень: `C:\Projects\guard-windows-client` (старые пути на Яндекс.Диске ниже — история).
- Запрос 2026-09-23: проверить завершённость проекта, перевести существующий интерфейс на русский и описать фактически доступное использование. Это не реализация всех оставшихся этапов в рамках русификации.
- Безопасная база: чистый `a55ca79fa5db700d8fc7de50d357a7c7514b25b3`, checkpoint `codex/checkpoint-20260923-2155-guard-russian-ui` отправлен в GitHub до изменений кода. Рабочая ветка: `codex/guard-russian-ui`.
- Проверка исходников: релиз не готов. `Guard.Service` использует `BoundaryOnlyPolicyReconciler`; часть readiness probes возвращает `Unknown`. Production AppLocker/WFP/proxy и детский UI не соединены со службой. В PWA отсутствует адаптер проверки/расшифровки запросов, Android `MainActivity` — оболочка, push использует `NoopWakeAdapter`.
- В истории есть foundations Stage 6: Android, PWA, подписанный relay protocol, HPKE, transaction state и Cloudflare worker. Это не доказательство рабочего сценария «запрос ребёнка → отпечаток родителя → реальное разрешение».
- Gate текущей задачи: русские тексты существующих экранов, честный README, Release-сборка и безопасные тесты; без установки/запуска Guard, Cleaner, службы и системных политик. Старый installer не пересобирается и не распространяется.
- Результат: переведены оставшиеся тексты Windows/Cleaner, сводка диагностики, исходник Inno и Android-оболочка. Русский PWA явно сообщает о незавершённости; отсутствие verifier больше не выглядит как успешно проверенный пустой список. Не менялись PIN authorization, cleanup sequence, IPC, подписи или enforcement.
- Implementation commit русификации: `b57739a`; документация и результаты проверки сохранены следующим связанным commit в той же ветке. Self-review diff: системные/криптографические правила не менялись, исходный installer и зависимости не обновлялись, новые тексты не содержат секретов.
- Проверки 2026-09-23: Release solution PASS (.NET SDK 10.0.303), 45 legacy checks PASS, все 29 отдельных v2 harness PASS, PWA 26/26 PASS + production build PASS; в браузере проверены RU→EN→RU, disabled-вход без verifier и загрузка после обновления кэша. NuGet audit и PWA production audit чистые.
- При browser-check воспроизведён пустой экран после пересборки: старый service worker кэшировал HTML со ссылкой на удалённый hashed bundle. Теперь кэшируются только manifest/icon, HTML/scripts и API идут в сеть; добавлена воспроизводимая проверка fetch handler. Офлайн-оболочка с согласованными версиями bundles остаётся будущим gate. Для уже сломанного preview одноразовый query `/?verify=ru-v2` обновляет worker; возврат на обычный URL проверен.
- Найденные блокеры вне русификации: Android `:app:compileDebugKotlin` падает на существующем `ByteArray.ifEmpty` в `RelayReceive.kt:125` (тот же код в checkpoint); Android tests/APK не приняты. Полный PWA npm audit: 3 dev findings (2 moderate Vitest/mocker, 1 high nanoid); зависимости автоматически не обновлялись. Worker/deployment, VM enforcement и биометрия на телефоне в этой проверке не запускались.
- Следующий инкремент реализации должен отдельно устранить build-блокер Android и соединить один сквозной сценарий; принимать его только по работающему результату, а не числу foundation-модулей. До семейного пилота остаются Stage 3–7 production/VM gates.

## Журнал исполнения

- 2026-07-22: доказанный MVP baseline прошёл Release-сборку и 35/35 безопасных logic-тестов.
- Checkpoint: ветка `codex/checkpoint-20260722-1920-guard-v2-foundation`, commit `381afa54a067665b2977389d582ec3166bc8a4ef`, push подтверждён на `krukovis-spec/guard-windows-client`.
- Рабочая ветка первого инкремента: `codex/guard-v2-foundation`, создана из того же checkpoint commit.
- В checkpoint намеренно не включены изменённый generated installer `Output/Guard-Setup-v1.0.0.exe`, `.gstack` и конфликтные копии Яндекс.Диска `*копия с компьютера LG*`; локальные пользовательские файлы не удалялись и не откатывались.
- P0 containment зафиксирован application commit `3e7e384d26864a5976da85652f160e0dd7da67ab`: legacy LAN/remote provisioning и telemetry заморожены, PIN fallback удалён, destructive diagnostic/Cleaner bypasses закрыты, cleanup получил fail-fast result/exit contract, Inno запускает cleanup только после подтверждения uninstall, неоднозначные ошибки scheduled-task query дают отказ, safe harness расширен с 35 до 45 проверок.
- Независимый security-review принял кодовый delta без оставшихся P0/P1; точный staged allowlist и `git diff --cached --check` подтвердили отсутствие пользовательского installer, конфликтных копий и review-артефактов в commit.
- Текущее поведение и временно недоступные функции описаны в `docs/guard-v2-p0-containment.md`.
- 2026-07-23 перед новым application-code increment создан и push безопасный checkpoint `codex/checkpoint-20260723-0041-guard-v2-implementation` на commit `6bfcb15e50f05b9110e6c0227c927be683a5f293`.
- Рабочая ветка дальнейшей реализации: `codex/guard-v2-implementation`, создана из того же commit. Пользовательский `Output`, `.gstack`, review-артефакты и конфликтные копии Яндекс.Диска не включены и не откатывались.
- Foundation системной границы зафиксирован commit `de4db2d`: отдельные `Contracts`, `Domain`, `Protocol`, `Application`, строгие bounded codecs, canonical signed commands, атомарный setup CAS с привязкой публичного ключа, commit-before-effect, replay/sequence guards, fail-closed readiness, app/site policy identity и maintenance leases.
- Финальный Release build прошёл; 45 legacy и 39 новых безопасных проверок дают 84/84 PASS. Независимый security/correctness re-review не оставил P0/P1/P2. Ветка `codex/guard-v2-implementation` push в GitHub.
- Иван отдельно разрешил toolchain gate: установлен официальный `.NET SDK 10.0.302`, репозиторий закреплён на нём через `global.json`, а `Guard.Service` использует официальный `Microsoft.Extensions.Hosting.WindowsServices` `10.0.10` с lock-файлом. Архитектурного понижения до .NET 8 не было.
- Stage 2 зафиксирован implementation commit `078ffa1`: `.NET 10` Windows Service composition root, SCM/`LocalSystem` execution gate, SYSTEM-only `%ProgramData%\Guard\v2`, DPAPI-protected atomic authoritative store с CAS и hash-chained version journal, production ECDSA P-256 verifier, раздельные named pipes с token/SID/integrity/DACL validation и свежая admin-only церемония привязки точного SID ребёнка.
- Release solution build, NuGet vulnerability audit и 159/159 безопасных проверок прошли. Два независимых финальных security/correctness review приняли точный staged tree без P0/P1/P2. Guard, служба, installer, Cleaner и системные механизмы на живом компьютере не запускались.
- Кодовая часть Stage 2 завершена. Её Windows tamper-resistance gate остаётся VM-only: SCM/LocalSystem bootstrap, ProgramData ACL/DPAPI/reparse races, реальный named-pipe token/UAC, nested local groups, restart cutover, crash/power-loss и child tamper matrix. Совместный offline rollback одновременно state и journal требует будущего TPM/remote witness.
- Stage 3 code-only зафиксирован implementation commit `15b8b60`: admin-only observational `GetReadiness`, строгий bounded wire contract, Windows 11 Pro-only и Secure Boot read probes, повторная проверка стандартного child SID, bounded inventory отдельного локального администратора, ProgramData ACL recheck, query-only SCM adapter и полный pure self-protection/install contract.
- Release solution build, NuGet vulnerability audit и 192/192 безопасных проверок прошли. Code-review-loop завершился чистым первым проходом после трёх небольших hardening fixes; независимый security/correctness review не нашёл P0/P1/P2.
- Stage 3 намеренно не выдаёт ложную готовность: BitLocker, managed browsers и полный service-boundary proof остаются `Unknown`, пока не появятся доказанные адаптеры. SCM DACL/recovery/service SID/install-root, реальные account/Secure Boot probes, stop/delete, Safe Mode и escalation matrix остаются disposable-VM gate. На живом компьютере Guard и системные механизмы не запускались.

## Как ведётся этот план

- Этот файл является главным источником требований, решений, этапов и открытых вопросов Guard v2.
- Каждая рекомендация Codex и каждое уточнение Ивана добавляются сюда в том же ходе разговора.
- Если Иван не возражает и переходит к следующему пункту, рекомендация считается принятой.
- Более позднее уточнение Ивана заменяет прежнее решение во всех связанных документах.
- Старый `parental-control-roadmap.md` хранит историю MVP и не определяет архитектуру Guard v2.
- Перед реализацией план проходит инженерный review. Затем создаются GitHub checkpoint безопасной исходной базы и отдельная рабочая ветка по правилам `AGENTS.md`.
- Установщик, собранный Guard и действия с AppLocker, firewall, `hosts`, реестром, задачами и Windows-аккаунтами не запускаются на рабочем компьютере без отдельного согласования.

## Цель продукта

После установки родитель включает защиту один раз. С этого момента всё неизвестное запрещено по умолчанию:

- неизвестное приложение не запускается;
- неизвестный сайт не открывается;
- ребёнок видит понятное объяснение и кнопку `Запросить разрешение`;
- запрос сразу появляется у родителя;
- только решение родителя создаёт разрешение;
- родителю не нужно заранее составлять длинные списки приложений и сайтов.

Guard строит белый список из реальных потребностей ребёнка, а не заставляет родителя угадывать их заранее.

## Основные принципы

1. `Default deny`: запрещено всё, что не разрешено явно.
2. `Request first`: основной экран родителя начинается с новых запросов, а не с настроек и списков блокировок.
3. `Fail closed`: сбой интерфейса, облака, расширения или перезапуск компьютера не выключает защиту.
4. `No email recovery`: коды из почты не используются для входа, смены PIN, перепривязки или отключения Guard.
5. `No secret in child session`: ребёнок не видит родительский PIN, pairing secret, recovery code или кнопку сброса родительской защиты. Одноразовые setup-данные показываются только в подтверждённой локальной admin setup session и не сохраняются в детском UI/логах.
6. `No HTTPS interception`: Guard не расшифровывает содержимое HTTPS, не устанавливает корневой сертификат и не записывает вводимый текст.
7. `Privacy by design`: сервер-посредник не должен получать больше данных о ребёнке, чем необходимо для доставки запроса и решения.
8. Интерфейс по умолчанию русский. Английский остаётся вторым языком и переключается в настройках родителя.

## Первый запуск

Целевой путь должен занимать несколько минут:

1. Родитель входит в отдельную локальную учётную запись администратора Windows и запускает установщик.
2. Guard устанавливает системную службу и показывает одноразовый QR-код настройки.
3. Родитель сканирует QR нативным Android-приложением, регистрирует аппаратный ключ подтверждений со свежей сильной биометрией и сохраняет Recovery Kit. Отдельный passkey служит для входа в кабинет и не заменяет ключ разрешений.
4. Guard предлагает выбрать Windows-пользователя ребёнка для отображения запросов, проверяет все повседневные аккаунты и отдельного recovery-admin. Системная политика охватывает машину, включая неизвестные новые аккаунты.
5. Проверка готовности показывает: редакцию Windows, Secure Boot, BitLocker, отдельного родительского администратора, состояние службы и поддерживаемые браузеры.
6. Родитель выбирает уже установленные базовые приложения, которые нужны сразу, или оставляет список пустым.
7. Кнопка `Включить защиту` включает строгий режим. После этого неизвестные приложения и сайты запрашиваются ребёнком.

Setup QR действует один раз и несколько минут. После привязки новый setup QR нельзя получить из детской сессии. Перепривязка требует подписи уже зарегистрированного approval-устройства после свежей биометрии либо отдельной процедуры восстановления; обычной passkey-сессии кабинета недостаточно.

## Установка и обслуживание приложений

Постоянной команды `Разблокировать всё` не будет. Она слишком легко превращает временное обслуживание в незаметно оставленную дыру.

Вместо неё вводится режим `Обслуживание`:

- включается только после подписи зарегистрированным родительским approval-устройством со свежей сильной биометрией;
- родитель выбирает 15, 30 или 60 минут;
- на компьютере постоянно виден обратный отсчёт;
- защита автоматически возвращается по таймеру, после перезагрузки, выхода родителя или ручного завершения;
- Guard записывает, какие приложения были установлены или обновлены;
- при завершении Guard предлагает разрешить обнаруженные приложения ребёнку постоянно, по расписанию или пока не будет принято решение.

Для обычной установки родитель может войти в свою локальную администраторскую учётную запись или ввести её пароль в UAC. Пароль администратора не хранится в Guard.

## Запрос приложения

1. Ребёнок запускает неизвестное приложение.
2. Windows блокирует запуск до выполнения кода приложения.
3. Детский интерфейс Guard показывает название, издателя, значок и кнопку `Запросить разрешение`.
4. Ребёнок при желании добавляет короткую причину. Повторные клики объединяются в один запрос.
5. В родительском кабинете появляются компьютер, ребёнок, приложение, издатель, путь, подпись и время запроса.
6. После решения разрешение доставляется на компьютер, и ребёнок может повторить запуск.

Постоянное разрешение выдаётся не только по пути к `.exe`:

- для любого unpackaged приложения исполняемое разрешение привязано к точному SHA-256; издатель, продукт, подпись и безопасная область установки показывают проверенное происхождение;
- для неподписанного приложения также используется точный хеш, и родитель видит предупреждение;
- для MSIX/UWP используется точная package family identity из подтверждённой службой инвентаризации;
- браузеры и сложные программы разрешаются как проверенный пакет из основного процесса, updater и обязательных helper-процессов;
- обновление не должно случайно разрешать любую программу того же издателя.

## Запрос сайта

1. Родитель сначала разрешает сам браузер как приложение.
2. В поддерживаемом управляемом браузере все сайты по умолчанию закрыты.
3. При переходе на неизвестный сайт страница не загружается. Вместо неё открывается страница Guard с названием сайта и кнопкой `Запросить разрешение`.
4. Ребёнок отправляет запрос и остаётся на странице ожидания. Браузер не закрывается целиком.
5. После решения страница автоматически повторяет переход или предлагает кнопку `Открыть`.

Под словом «сайт» Guard понимает сервис, а не каждый технический hostname. Например, разрешение YouTube должно включать минимально необходимый набор доменов YouTube и видеодоставки, но не открывать весь Google. Для этого нужны проверяемые пакеты сервисов.

Для неизвестного сайта начальный scope — точный canonical host. Поддомены или пакет связанных доменов открываются только в явно подтверждённом scope или проверенном подписанном service bundle; весь registrable domain автоматически не разрешается. Сторонние рекламные и отслеживающие домены остаются закрыты. Если без дополнительного домена функция не работает, связанные технические запросы группируются в один понятный запрос для решения родителя.

## Варианты решения родителя

Для приложения и сайта показываются четыре основных решения:

1. `Разрешить всегда`.
2. `Разрешить на время`: до закрытия, на 15 минут, на час или до конца дня.
3. `Разрешать ежедневно`: расписание плюс дневной лимит, например 60 минут в день.
4. `Запретить`.

Запрет может иметь срок `до завтра`, `на 7 дней` или `пока родитель не изменит решение`, чтобы один и тот же запрос не повторялся бесконечно.

Дневной лимит в первом выпуске считает foreground-использование без idle. Фоновая музыка/видео не расходуют квоту; эта граница явно показана в интерфейсе. Отдельный достоверный учёт media playback относится к будущему расширению.

## Родительский кабинет и телефон

Основной родительский интерфейс: адаптивный сайт/PWA, устанавливаемый на главный экран телефона. Это даёт один интерфейс для Android, iPhone и компьютера и позволяет быстрее выпустить надёжный MVP.

Обычные passkey на Android и iPhone допускают системный PIN, pattern, пароль или код устройства как fallback, поэтому они не доказывают требуемую Guard свежую биометрию родителя. В строгом режиме PWA может показывать запросы и выполнять неразрешающие действия, но не подписывает `Allow`, отключение защиты, обслуживание или recovery. Эти команды подтверждает небольшое нативное `Guard Parent Approval`-приложение: его отдельный ключ хранится в Secure Enclave/Android Keystore, требует биометрию для каждой подписи и не разрешает device-credential fallback. При отсутствии поддерживаемой сильной биометрии нужно другое зарегистрированное approval-устройство. Обычный FIDO2-ключ с PIN не считается эквивалентом biometric-only; аппаратную альтернативу можно добавить только после отдельной проверки её свойств.

Основные разделы:

- `Запросы`: новые запросы, ожидающие решения;
- `Сегодня`: активность, оставшееся время и недавние решения;
- `Ребёнок`: устройства и базовые правила;
- `Разрешения`: приложения, сайты, расписания и лимиты;
- `Безопасность`: родители, passkeys, восстановление, состояние защиты и попытки обхода.

На компьютере используется постоянная левая навигация и отдельная прокрутка рабочей области. На телефоне навигация становится нижней или выдвижной.

Push-уведомление сообщает о новом запросе, но не содержит кода, секрета и кнопки мгновенного разрешения на заблокированном экране. Для решения родитель открывает запрос, видит точный объект и подтверждает подпись в approval-модуле свежей сильной биометрией. Даже если ребёнку дали разблокированный телефон, открытая сессия кабинета сама по себе не позволяет выдать разрешение.

Нативный approval-модуль проверяется на реальных Android и iPhone: каждая разрешающая подпись должна требовать свежую сильную биометрию, ключ должен инвалидироваться при изменении набора биометрии, а PIN/код телефона не должен становиться fallback. Полный кабинет при этом не дублируется: он остаётся в PWA.

Первой родительской платформой выбран Android: у Ивана есть реальное устройство с отпечатком пальца. Маленький approval-клиент реализуется нативно на Kotlin и использует Android Keystore с `AUTH_BIOMETRIC_STRONG`; общий интерфейс запросов остаётся в PWA. iPhone-клиент добавляется позже отдельным нативным адаптером после появления доступного Mac/Xcode и реального iPhone.

Основание:

- Apple passkey допускает код устройства, если Face ID/Touch ID недоступны: https://developer.apple.com/news/?id=21mnmxow
- Apple Secure Enclave поддерживает `biometryCurrentSet` для ключа подписи: https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset
- Android passkey использует любой экранный unlock, включая PIN/pattern/password: https://developer.android.com/identity/passkeys
- Android Keystore позволяет привязать операцию ключа только к `AUTH_BIOMETRIC_STRONG`: https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder

Источником истины остаётся папка `Запросы`, потому что push может быть задержан или отключён системой телефона.

## Аутентификация и восстановление

Основной способ входа:

- passkey, хранящийся на телефоне родителя;
- passkey подтверждает владение родительской учётной записью, но сам по себе не разрешает опасные команды.

Основной способ подтверждения разрешающей команды:

- отдельный device-bound ключ подписи в Secure Enclave/Android Keystore;
- свежий отпечаток пальца или Face ID на каждую подпись без fallback на PIN/код устройства;
- повторная проверка точного объекта, устройства и срока решения перед подписью.

Google Authenticator, Яндекс Ключ, TOTP, SMS и почтовые коды не используются ни для ежедневных решений, ни как штатный способ восстановления. В Guard не будет родительского PIN-кода, который нужно запоминать, вводить или можно подсмотреть.

Перед биометрическим подтверждением экран обязательно показывает точный объект и срок решения: например, `YouTube — разрешить на 60 минут`. Разрешить доступ прямо из push-уведомления или без открытия карточки запроса нельзя.

Восстановление без почтовых кодов:

- второе заранее зарегистрированное approval-устройство родителя или другого доверенного взрослого;
- второй passkey/FIDO2 для входа в кабинет сам по себе не восстанавливает разрешающие полномочия Guard; для них нужен trusted approval path или Recovery Kit;
- отдельный случайно сгенерированный Guard Recovery Kit не менее 256 бит: master copy хранится как защищённая запись в Bitwarden, а вторая копия — распечатанной и запечатанной вне телефона и детского компьютера;
- мастер-пароль Bitwarden никогда не передаётся Guard и не становится Guard-паролем; человек не придумывает recovery secret вручную;
- применение Recovery Kit требует физического доступа, отдельной локальной elevated admin ceremony, задержки, отзыва прежних родительских ключей и уведомления всех ещё зарегистрированных устройств;

Родительская учётная запись администратора на детском Windows-компьютере должна быть локальной, отдельной и не связанной с почтовым восстановлением Microsoft. Она используется только для обслуживания. Повседневные решения принимаются в кабинете.

## Доставка запросов

- Служба Guard устанавливает только исходящее TLS-соединение с облачным relay. Входящий порт на домашнем роутере не открывается.
- Запросы сохраняются локально и повторно отправляются после восстановления сети.
- Постоянные и ещё действующие временные разрешения работают без интернета.
- Новый удалённый запрос невозможно одобрить офлайн; ребёнок видит честный статус `Ожидаем интернет`.
- Команды родителя подписываются, имеют срок действия, номер последовательности и защиту от повторного воспроизведения.
- Relay хранит минимум метаданных. Названия приложений, домены и причины запросов по возможности передаются сквозным шифрованием между устройством и родительскими устройствами.
- Для разработки и закрытого семейного пилота используется отдельный Guard Worker в существующем Cloudflare-аккаунте, с собственным SQLite Durable Object и `workers.dev`; Android push использует бесплатный FCM. Guard не переиспользует VoicePaste database/namespace и получает отдельный минимально scoped token.
- Подключение Cloudflare повторяет проверенный маршрут VoicePaste: отдельный токен Guard передаётся Wrangler только через временную `CLOUDFLARE_API_TOKEN`, master copy хранится в Bitwarden, локальная operational copy — через DPAPI CurrentUser с ACL текущего пользователя вне Git; browser OAuth не является основным маршрутом. Проверено 2026-09-26: аккаунт `7135a2335784ee593d8942ef1d79525f` также содержит `voicepaste-api`; `guard-relay` использует тот же account и отдельный Worker. Токен VoicePaste не переиспользовать. Выпущен account-owned token `Guard relay deployment` без срока действия, с областью `Specified Workers: guard-relay` и ролью `Individual Workers Editor`; 2026-09-29 Иван подтвердил запись master copy в Bitwarden. Аккаунтный `Workers Admin` затронул бы и VoicePaste и не подходит для постоянного хранения.
- Имеющийся shared hosting REG.RU подтверждён для SFTP-статики и загрузок, но не считается надёжной средой для постоянно работающего relay, authoritative state или ключей. При необходимости он используется только для публичного landing/download mirror; PWA и relay остаются в одном версионируемом Cloudflare deployment.
- Превышение бесплатной квоты должно fail closed: существующие локальные разрешения продолжают действовать, новые удалённые запросы показывают `Ожидаем сервис`, а защита не отключается.
- Официальные free-tier границы проверены по Cloudflare Workers/D1/Durable Objects и Firebase pricing; перед публичным релизом capacity/SLA оцениваются повторно.

## Защита приложений

- Ребёнок работает только под стандартным Windows-пользователем.
- Привилегированную политику, состояние и ключи хранит служба `LocalSystem`, а не tray-процесс ребёнка.
- Детский интерфейс общается со службой через ограниченный named pipe и не может выполнить родительскую команду.
- Динамические разрешения приложений строятся на AppLocker. Отдельный более жёсткий слой защищает сам Guard и критические системные инструменты от изменения.
- Блокируются portable-приложения, Store/MSIX, MSI, скрипты, PowerShell, `cmd`, WSL, интерпретаторы, макросы, планировщик, сервисные утилиты и известные системные программы, через которые можно запустить произвольный код.
- Изменение состава локальных администраторов, остановка службы, удаление расширения, изменение browser policy и попытки отключить защиту создают событие безопасности для родителя.

Точный набор AppLocker/App Control for Business правил утверждается только после VM-прототипа: ошибка здесь может либо оставить обход, либо заблокировать Windows.

## Защита сайтов

Текущий механизм Guard через чтение адресной строки и закрытие браузера не подходит для Guard v2.

Целевая схема:

- разрешены только поддерживаемые управляемые браузеры;
- первый поддерживаемый браузер: Microsoft Edge; второй — Google Chrome; Яндекс Браузер рассматривается позже;
- неподдерживаемые браузеры автоматически блокируются как приложения;
- локальная служба принудительно задаёт браузеру localhost proxy и запрещает обход proxy;
- proxy видит домен HTTPS-туннеля, но не расшифровывает содержимое страницы;
- управляемое расширение показывает красивую страницу запроса и проверяет разрешение до навигации;
- служба проверяет наличие и исправность расширения и browser policy;
- QUIC, внешние DoH, VPN, Tor, внешние proxy и portable-браузеры блокируются или управляются, иначе они превращаются в обход;
- WFP-слой ограничивает сетевой выход браузеров и известных инструментов обхода, но не используется для чтения содержимого трафика.

Такой слой нужно проверять на обычных страницах, инкогнито, WebSocket, загрузках, OAuth-переходах, YouTube, CDN, IPv6, DoH, QUIC, VPN и после обновления браузера.

## Что берём у конкурентов

### Kaspersky Safe Kids

Ближе всего к нужному сценарию: ребёнок может запросить запрещённое приложение или сайт, родитель получает запрос в мобильном приложении или на портале и нажимает Allow/Deny. Недостаток для нашей задачи: разрешённый объект превращается в постоянное исключение. Guard добавляет временные решения и дневные квоты.

Источник: https://support.kaspersky.com/ksk/win/en-us/134467.htm

### Qustodio

Полезный принцип: поддерживать конкретные браузеры и автоматически блокировать неподдерживаемые. Есть родительское мобильное приложение и веб-кабинет. Недостаток: основная модель построена вокруг заранее заданных категорий и правил, а не вокруг строгого белого списка из запросов ребёнка.

Источники:

- https://help.qustodio.com/hc/en-us/articles/360005216737-How-do-I-block-or-allow-websites-using-Qustodio
- https://help.qustodio.com/hc/en-us/articles/360005225958-Qustodio-system-requirements-and-supported-platforms

### Microsoft Family Safety

Полезны мобильное управление, запрос дополнительного времени и лимиты приложений. Но веб-фильтрация на Windows привязана к Edge, другие браузеры приходится блокировать, а временные лимиты для отдельных сайтов официально не поддерживаются. Guard должен сохранить простоту семейного кабинета, но не ограничиваться одним браузером.

Источники:

- https://support.microsoft.com/en-US/family-safety/get-the-microsoft-family-safety-app
- https://support.microsoft.com/en-US/family-safety/set-app-and-game-limits

### Apple Ask to Buy и Google Family Link

Полезна сама механика: ребёнок инициирует понятный запрос, родитель видит объект и решает на своём устройстве. Эти решения хорошо работают внутри собственных магазинов и экосистем, но не дают нужного контроля произвольных Windows-приложений и сайтов.

Источники:

- https://support.apple.com/en-euro/105055
- https://support.google.com/families/answer/15077835

## Целевая архитектура

1. `Guard.Service`: .NET 10 LTS Windows Service под `LocalSystem`, политика, состояние, криптографические ключи, события безопасности и связь с relay.
2. `Guard.Child`: непривилегированный интерфейс детской сессии, окна блокировки, запросы и статусы.
3. `Guard.Parent Web/PWA`: запросы, решения, правила, безопасность, русский и английский языки.
4. `Guard Relay`: доставка зашифрованных запросов и подписанных решений через исходящее соединение устройства.
5. `Guard Browser Extension`: управляемое расширение поддерживаемого Chromium-браузера.
6. `Guard Local Proxy`: доменная политика без расшифровки HTTPS.
7. Хранилище `%ProgramData%\Guard`: атомарные записи, ACL только для службы, журнал и защита от отката состояния.

Проверенные чистые модели текущего проекта для запросов, разрешений, лимитов, задач и учёта активности можно переносить. Tray/watchdog, LAN HTTP-кабинет, child-visible pairing, известный PIN и UI-Automation web enforcement заменяются.

### Исполнительные границы после P0

Миграция идёт по strangler-схеме: новая архитектура создаётся рядом с quarantined legacy-клиентом и поэтапно забирает ответственность. Старый `guard.exe` и `Guard.Core` не превращаются в службу и не становятся источником истины для Guard v2.

- `Guard.Contracts`: версионированные DTO для IPC и relay, bounded frames и закрытая схема без polymorphic deserialization.
- `Guard.Domain`: чистые неизменяемые модели, решения и переходы состояния без Windows/API/UI зависимостей.
- `Guard.Application`: use cases и порты для хранилища, времени, криптографии, Windows policy, relay и аудита.
- `Guard.Windows`: привилегированные адаптеры ACL, account readiness, AppLocker, browser policy и сетевого containment.
- `Guard.Service`: единственный composition root и authoritative writer состояния, ключей и desired policy под `LocalSystem`.
- `Guard.Child`: непривилегированный UI детской сессии, зависящий только от разрешённого child IPC contract.
- `Guard.Proxy`: отдельный низкопривилегированный процесс локального domain proxy; он не работает под `LocalSystem` и не расшифровывает TLS.
- `Guard.Relay`, parent PWA и browser extension остаются отдельными внешними компонентами. Extension отвечает за UX, но не является enforcement authority.

Обязательные security invariants:

1. Только служба меняет authoritative state и применяет privileged policy; двух активных writers не бывает.
2. Child, admin/setup и proxy используют разные named pipes с явными DACL. Роль, SID, путь, publisher и package identity из payload не считаются доказательством: служба проверяет client token и разрешает identity сама.
3. `%ProgramData%\Guard` использует service-only ACL, атомарный commit/replace, шифрование с аутентификацией, durable sequence/idempotency state и журнал изменений. После crash desired state повторно сверяется с фактической policy.
4. Setup QR короткоживущий и одноразовый, создаётся только из подтверждённой admin setup session. Детская сессия не может запросить новый QR или parent verb.
5. Legacy PIN, pairing code, `DeviceId`, cabinet session и ownership secret автоматически не мигрируются. Старые allow-grants допускаются только как недоверенный preview для нового родительского подтверждения.
6. App approval строится по проверенной службой identity: publisher/product/secure install root или SHA-256 fallback; child-selected path сам по себе ничего не разрешает.
7. Relay переносит opaque payload. Любая разрешающая команда связана с точным device/request, имеет expiry, sequence и nonce, подписана родительским ключом и записывается как принятая до применения эффекта.

Первоначальный порядок cutover дал существующие foundations. Оставшуюся интеграцию выполнять по M0–M9: ранняя проверка machine-wide защиты, доверенный обмен/привязка, реальные app/site сценарии, полный UX и lifecycle; новый no-op scaffold сам по себе не считается этапом.

Target остаётся `.NET 10 LTS`; официальный SDK `10.0.302` установлен после отдельного разрешения Ивана и закреплён через `global.json`. `Guard.Service` использует официальный `Microsoft.Extensions.Hosting.WindowsServices` `10.0.10`; установленный ранее SDK `8.0.422` не стал молчаливым архитектурным понижением.

## Модель угроз

Строгий режим целится в Windows 11 Pro на устройстве с Secure Boot и BitLocker. Ребёнок является стандартным пользователем, имеет физический доступ к включённому компьютеру и может искать публичные инструкции по обходу.

Guard должен выдерживать:

- перезагрузку, Safe Mode и попытки внешней загрузки при правильно настроенном UEFI;
- portable apps, переименование и копирование `.exe`;
- Store, MSI, скрипты, WSL, PowerShell и LOLBins;
- другой браузер, инкогнито, DoH, QUIC, VPN, proxy и Tor;
- остановку процессов, службы и автозапуска;
- изменение системного времени;
- повтор запросов и повтор старых команд;
- доступ ребёнка к разблокированному телефону без биометрического подтверждения родителя;
- попытку сбросить родительский PIN/пароль через почту;
- отсутствие интернета и сбой облачного relay.

Абсолютная защита невозможна, если ребёнок знает пароль администратора, может сбросить UEFI/BitLocker или родитель сам подтверждает непонятную операцию. Мастер настройки обязан показать эти границы простыми словами.

## Исторические этапы 0–7 и принятые базовые решения

Далее сохранена история первоначального разбиения. Для новой execution-сессии последовательность, тесты и критерии готовности определяются M0–M9 выше; прежний code-only PASS не закрывает production/VM/phone gate.

### Базовые решения первого релиза

- Первый строгий релиз поддерживает Windows 11 Pro. Windows Home можно добавить позже только как честно обозначенный ослабленный режим после отдельного исследования.
- Браузерный порядок: Microsoft Edge как первый технический эталон, Google Chrome как второй адаптер, Яндекс Браузер после подтверждения управляемых policy/extension-механизмов. Неподдерживаемый браузер остаётся заблокированным как приложение.
- Родительский кабинет сначала реализуется как PWA, но разрешающие и опасные команды строгого режима подписывает компактное нативное `Guard Parent Approval`-приложение. Оно не дублирует весь кабинет и добавляется на используемую родителем мобильную платформу до включения удалённых разрешений.
- В первом релизе дневной лимит считает активное foreground-использование без idle-времени. Фоновая музыка/видео не расходуют лимит до появления отдельной достоверной модели media playback.
- Эти решения не мешают Ивану позже изменить приоритет браузера, добавить Home или отдельный медиалимит; архитектура должна оставлять такие адаптеры заменяемыми.

### Этап 0. Зафиксировать спецификацию

- Утвердить пользовательские сценарии, модель угроз, второй браузер и границы первого релиза.
- Превратить открытые вопросы в проверяемые технические spike-задачи.
- Gate: продуктовый, UX и инженерный review плана без P0-противоречий.

### Этап 1. Устранить опасные обходы текущей версии

- Убрать child-side claim первого pairing и известный emergency PIN.
- Отключить email recovery и опасные локальные reset-пути.
- Заморозить распространение неподписанного текущего установщика.
- Gate: тесты доказывают, что детская сессия не может стать родителем или отключить Guard.

### Этап 2. Создать системную границу

- Новая служба, безопасное хранилище, restricted IPC и новый setup ceremony.
- Gate: ребёнок не читает и не изменяет состояние, ключи или родительские команды.
- Статус 2026-07-23: code-only реализация завершена в `078ffa1`; build, 159/159 safe tests, audit и два независимых review прошли.
- Остаток gate: только disposable Windows 11 Pro VM; на рабочем компьютере служба не устанавливалась и не запускалась.

### Этап 3. Защитить Windows-аккаунты и сам Guard

- Стандартный ребёнок, отдельный локальный администратор, контроль admin group, Secure Boot и BitLocker readiness.
- Защита от удаления и отключения обязательна: стандартный ребёнок не должен иметь права остановить, перенастроить или удалить службу, заменить файлы/состояние Guard, снять browser/network policy либо обойти авторизованный uninstall через legacy Cleaner. Обновление, обслуживание и удаление выполняются только по отдельному родительскому ceremony и подписанному release-path.
- Gate: матрица попыток остановки, удаления, Safe Mode и account escalation на VM.
- Статус 2026-07-23: code-only readiness и self-protection contracts завершены в `15b8b60`; build, 192/192 safe tests, audit, code-review-loop и независимый review прошли.
- Остаток gate: BitLocker/browser adapters, полный SCM/install-root/DACL/recovery/service-SID observer и вся tamper/account matrix проверяются только в disposable Windows 11 Pro VM. До этого `CanEnableProtection` остаётся `false`.

### Этап 4. Реализовать default-deny приложений

- Идентичность приложений, AppLocker grants, maintenance mode, updater bundles и child request UI.
- Gate: разрешённое приложение работает и обновляется, а все известные пути произвольного запуска остаются закрыты.
- Статус 2026-07-24: code-only foundation завершён в `35c79ca`. Добавлены exact SHA-256/PFN grants, default-deny для EXE/MSI/Script/Appx/DLL, service-attested inventory и updater candidates, maintenance discovery, минимальный child request payload и durable commit/reconcile workflow.
- Проверка: Release build без предупреждений; 236/236 safe checks, включая 44/44 Stage 4; NuGet audit чист; code-review-loop исправил три P1 и завершился чистым pass 1; независимый финальный review не нашёл оставшихся P0/P1/P2 в code-only scope.
- Остаток gate: production store/scheduler, криптографически проверенный immutable catalog, Authenticode/PFN extraction, AppLocker sink, service/child wiring, updater carry-forward и точная атака-матрица реализуются и принимаются только в disposable Windows 11 Pro VM. Текущий production composition не может применить эту политику.

### Этап 5. Реализовать default-deny сайтов

- Local proxy, managed extension, browser policies, service bundles и защита от сетевых обходов.
- Gate: тестовая матрица браузеров, протоколов и сервисов проходит без HTTPS interception.
- Статус 2026-07-24: code-only foundation завершён в `b685072`. Добавлены strict canonical DNS host/PSL scopes, подписанный `guard.web-bundle.v2` с monotonic acceptance floors, безопасный HTTP/CONNECT parser, exact Edge/Chrome policy plans, fail-closed readiness, разделение сетевого enforcement и extension UX, минимальный website-request protocol, durable audit outbox и atomic desired-state/reconcile workflow.
- Проверка: warning-free Release build; 321/321 safe checks, включая 85/85 Stage 5; NuGet audit чист; code-review-loop исправил двенадцать findings и завершился чисто; независимые protocol/state/security reviews не нашли оставшихся P0/P1/P2 в code-only scope.
- Остаток gate: production adapters для localhost proxy/listeners, DNS rebinding/private-IP checks, browser registry/effective-policy attestation, extension publication, WFP filters, подписанного catalog/PSL verifier, authoritative stores/scheduler/audit dispatcher и service wiring. Crash/recovery и browser/network bypass matrix принимаются только в disposable Windows 11 Pro VM; текущий production composition не может включить web enforcement.

### Этап 6. Добавить удалённый кабинет и мобильное подтверждение

- Relay, PWA, passkeys, push, четыре решения, офлайн-очередь, русский и английский интерфейсы.
- На первом Windows-релизе Android/iPhone используются как устройства родителя: общий кабинет остаётся PWA, а компактный approval-модуль хранит отдельный ключ подписи в аппаратно защищённом хранилище и требует свежую сильную биометрию на каждую разрешающую или опасную команду без PIN/device-credential fallback.
- Первый approval-клиент — нативный Android/Kotlin на реальном устройстве Ивана; dev/closed-pilot relay — отдельные Cloudflare Workers Free + SQLite Durable Objects/D1, push — FCM без платы, development endpoint — `workers.dev`.
- Полноценный Guard-агент для телефона ребёнка не нужен для первого Windows-релиза и остаётся отдельным будущим продуктом.
- Relay, PWA, WebAuthn-сессия и FCM считаются недоверенными для разрешающих действий. Relay хранит только bounded opaque routing metadata и E2E-ciphertext; FCM передаёт только непривилегированный wake-up locator. Отказ, повтор, перестановка, quota exhaustion или полный захват relay не должны расширять локальную политику.
- Первичная привязка родителя начинается только локальным elevated setup и QR, который сканирует нативный Android-клиент, а не PWA. Одноразовый setup secret, Recovery Kit и private keys никогда не передаются relay/PWA. Claim криптографически связывается со всем enrollment transcript и принимается локальной службой ровно один раз через CAS.
- Windows публикует device-signed immutable request snapshot: точный request id/revision, device/authority epoch, canonical target identity, bounded structured evidence, policy revision, expiry и случайный 256-bit decision challenge. Android сам расшифровывает и проверяет этот snapshot, показывает родителю фактический объект и подписывает structured decision только после свежей `AUTH_BIOMETRIC_STRONG`; blind-signing hash или текста из PWA запрещён.
- Replay floor хранится отдельно для каждой пары `authorityEpoch + approval key id`. Один approval key использует stop-and-wait: пока нет device-signed terminal receipt для sequence `N`, он повторяет те же подписанные байты и не выпускает `N+1`. Два противоречивых решения одного запроса разрешаются локальным CAS: первое exact решение завершает запрос, второе получает `AlreadyResolved` и не меняет политику.
- Первый пилот использует bounded HTTPS polling вместо обязательного WebSocket. Windows долговечно ставит исходящие запросы в локальную очередь, relay ack отправляется только после локального commit; потерянный ack даёт signature-verified idempotent receipt, а не повторный effect. Полностью новое offline approval на Android не создаётся, но ранее подписанный envelope можно безопасно повторить.
- Wire-форматы имеют versioned canonical binary codecs и общие golden vectors для .NET/Kotlin/TypeScript. E2E-профиль: RFC 9180 HPKE Base mode `DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM`; внутреннее сообщение сначала подписывается отправителем, затем шифруется каждому локально авторизованному recipient key. PWA view key и Android approval signing key являются разными полномочиями.
- Recovery Kit — ровно 32 случайных байта с checksum/удобной кодировкой. Windows хранит только salted domain-separated verifier, связанный с device/recovery epoch. Recovery остаётся локальной elevated delayed ceremony: после атомарного повышения epoch отзываются прежние parent/view keys, sessions, relay credentials и pending commands, а default-deny enforcement не отключается. Точная задержка и rollback-resistant elapsed-time закрываются до release в disposable VM.
- Gate: запрос и решение проходят через внешний интернет, повтор старой команды отклоняется, PWA не может самостоятельно создать разрешающую подпись, PIN/device credential и email code нигде не дают право разрешить или отключить защиту.

### Этап 7. Подготовить выпуск

- Authenticode, CI, SBOM, подписанные обновления, rollback и Windows VM E2E security suite.
- Иван разрешил создать disposable Hyper-V Windows 11 Pro VM и выполнять все live Guard/SCM/AppLocker/WFP/browser/installer/Cleaner проверки только внутри неё. На основном компьютере запрет системных действий сохраняется.
- До приобретения публично доверенной подписи VM использует отдельный test certificate/CA, доверенный только внутри disposable VM; это проверяет механику подписи, но не считается публичным release gate.
- Gate: подписанный installer, чистая установка/обновление/удаление и атака-матрица Windows 11 проходят в VM до теста на семейном компьютере.

## Принятые решения

| Дата | Решение | Основание |
|---|---|---|
| 2026-07-22 | Вести один living plan и обновлять его в том же ходе разговора | Прямое требование Ивана |
| 2026-07-22 | Не менять application code до явного перехода к исполнению | Режим проектирования |
| 2026-07-22 | Всё неизвестное запрещено по умолчанию, ребёнок формирует запрос | Прямое требование Ивана |
| 2026-07-22 | Отдельные запросы на приложение и на сайты внутри разрешённого браузера | Прямое требование Ивана |
| 2026-07-22 | Четыре решения: всегда, временно, ежедневная квота, запрет | Прямое требование Ивана |
| 2026-07-22 | Русский язык по умолчанию, английский переключаемый | Прямое требование Ивана |
| 2026-07-22 | PWA и облачный relay как первый удалённый родительский интерфейс | Рекомендация без возражений |
| 2026-07-22 | Passkey со свежим отпечатком/Face ID; TOTP и родительский PIN не используются | Прямое уточнение Ивана и защита от подсмотренного кода |
| 2026-07-22 | Никаких email-кодов для Guard recovery | Подтверждённый семейный сценарий обхода |
| 2026-07-22 | Временное `Обслуживание` вместо постоянного `Разблокировать всё` | Автоматическое восстановление защиты |
| 2026-07-22 | Строгая база: Windows 11 Pro, стандартный ребёнок, Secure Boot и BitLocker | Принятая рекомендация по модели угроз |
| 2026-07-22 | Поддерживаемые браузеры управляются, остальные блокируются как приложения | Проверенный конкурентный и технический паттерн |
| 2026-07-22 | Первый строгий релиз: Windows 11 Pro; Edge, затем Chrome, затем проверка Яндекс Браузера | Снижение риска первой реализации |
| 2026-07-22 | PWA реализуется первой; нативное приложение требуется только при провале biometric security gate | Быстрая проверка на Android/iPhone без ослабления защиты |
| 2026-07-22 | План одобрен для исполнения; первый инкремент ограничен checkpoint и P0 containment | Прямой переход Ивана к реализации |
| 2026-07-23 | Продолжить реализацию всех этапов плана по отдельным проверяемым инкрементам | Прямое указание Ивана |
| 2026-07-23 | Strangler migration: новая служба — единственный authoritative writer; legacy `guard.exe` остаётся quarantined до cutover | Security review системной границы |
| 2026-07-23 | Отдельные child/admin/proxy IPC и низкопривилегированный proxy; payload identity никогда не считается доверием | Модель угроз LocalSystem и named-pipe ACL |
| 2026-07-23 | Установить официальный `.NET SDK 10.0.302` и использовать `Microsoft.Extensions.Hosting.WindowsServices` `10.0.10` с lock-файлом | Прямое разрешение Ивана и воспроизводимый production toolchain |
| 2026-07-23 | Bootstrap authoritative state разрешён только явным CLI-флагом после подтверждённых SCM+`LocalSystem`; существующие или повреждённые артефакты никогда не сбрасываются | Fail-closed storage boundary |
| 2026-07-23 | Во время активного admin setup challenge можно атомарно привязать проверенный стандартный child SID; exact-SID child pipe появляется только после перезапуска службы | Закрывает свежую установку без child-side ownership claim |
| 2026-07-23 | Public ParentRelay pipe не создаётся; родительские команды позже принимаются только внутренним outbound relay path | Минимизация привилегированной IPC-поверхности |
| 2026-07-24 | PWA остаётся общим кабинетом, но строгие `Allow`/disable/maintenance/recovery подписывает компактный Android/iPhone approval-модуль с biometric-only аппаратным ключом | Официальные passkey Android/iPhone допускают PIN/код устройства и не проходят Guard biometric-only gate |
| 2026-07-24 | Unpackaged-приложение получает исполняемый grant только по exact SHA-256, packaged app — по exact PFN; publisher/product/root остаются service-attested provenance | AppLocker publisher-rule нельзя безопасно объединить с обязательным secure-root условием без расширения allow |
| 2026-07-24 | Desired revoke коммитится до проверки каталога; перед каждым apply сохраняется deadline `min(now+1m, natural deadline)`, который снимается только после успеха | Сбой catalog/scheduler/sink не должен терять revoke или оставлять старый allow без bounded retry |
| 2026-07-24 | Web default-deny доверяет только canonical host и exact/subtree scope из подписанного `guard.web-bundle.v2`; catalog и bundle защищены monotonic floors | Child payload, DNS ambiguity и rollback старого bundle не должны расширять разрешение |
| 2026-07-24 | Website decision атомарно коммитит desired state и bounded reconcile intent; все исходы запроса имеют durable idempotent audit intent | Crash, cancellation или недоступный sink не должны терять revoke, retry или security audit |
| 2026-07-24 | Защита от остановки, подмены и удаления Guard — обязательный release gate, но абсолютная защита при известном admin/recovery key или физическом offline-доступе не обещается | Реалистичная Windows threat boundary: standard child, Secure Boot, BitLocker и disposable-VM tamper matrix |
| 2026-07-24 | Первый Windows-релиз использует Android/iPhone только для родительского PWA и biometric-only approval; child Android/iOS agent вынесен в отдельный будущий продукт | Мобильный child control требует самостоятельной архитектуры MDM/VPN/OS policy и не нужен для защиты Windows-ПК |
| 2026-07-24 | Иван разрешил создать disposable Hyper-V Windows 11 Pro VM; live системные проверки выполняются только в guest, основной компьютер остаётся недопустимой целью | Явное разрешение Ивана и изоляция рискованных SCM/AppLocker/WFP/installer/tamper тестов |
| 2026-07-24 | Первый native approval-клиент — Android/Kotlin с `AUTH_BIOMETRIC_STRONG` на реальном телефоне Ивана; iPhone откладывается до Mac/Xcode и устройства | Доступный Android с отпечатком позволяет закрыть biometric-only gate без ожидания Apple toolchain |
| 2026-07-24 | Восстановление использует отдельный случайный 256-bit Guard Recovery Kit в Bitwarden плюс запечатанную offline-копию; мастер-пароль Bitwarden не передаётся Guard | Человеческий пароль создаёт слабую и повторно используемую Guard-authority, а отдельный key сохраняет понятный recovery |
| 2026-07-24 | Dev/closed pilot не требует новых платежей: отдельные Cloudflare Workers Free + SQLite Durable Objects/D1, `workers.dev` и FCM; REG.RU только optional static mirror | Существующий REG.RU проверен для SFTP-статики, а бесплатные Cloudflare/FCM квоты достаточны для одного семейного пилота |
| 2026-07-24 | Stage 6 использует native-scanned transcript-bound enrollment, device-signed exact request snapshots, per-key replay floors/stop-and-wait, opaque FCM и отдельные view/approval authorities | Захват relay/PWA либо перестановка очереди не должны позволять blind signing, чужую привязку, replay или permissive command без свежей биометрии |
| 2026-07-24 | Первый pilot transport — bounded HTTPS polling; relay ack только после local commit, redelivery завершается signature-verified idempotent receipt | Упрощает бесплатный вертикальный сценарий и сохраняет commit-before-effect при offline/retry/crash |
| 2026-09-29 | Сначала подробный план M0–M9 и карта T01–T20/E01–E10, затем новая команда запуска разработки | Прямой запрос Ивана; code-only foundations не равны рабочему приложению |
| 2026-09-29 | До основной интеграции доказать совместимость machine-wide signed protection, динамических разрешений и их отзыва при crash/admin tamper | Найденный разрыв P-256/RSA и отсутствие production enforcement; техническая приёмка M1 |

## Открытые решения

- Какой публичный Guard-domain и production hosting/SLA используются после закрытого бесплатного пилота.
- Когда добавлять iPhone-клиент и какой Mac/Xcode build route использовать.
- Какой публично доверенный Windows signing service/certificate и какие store accounts покупать перед release.
- До реализации recovery закрепить задержку (рекомендация M8 — 24 часа) и механизм, который не позволит сократить её сменой часов/перезагрузкой.
- В M1 выбрать и доказать policy signing/update/revocation path вне защищаемого ПК; аппаратную совместимость Android проверить на конкретном телефоне.

Первые три вопроса не блокируют code/VM разработку и закрытый пилот без новых платежей. Последние два — конкретные технические/продуктовые условия соответствующих M1/M8 gates; их нельзя выдавать за уже решённые.

## Не входит в первый релиз

- скрытая запись экрана, клавиатуры, переписки или содержимого страниц;
- расшифровка HTTPS и установка собственного корневого сертификата;
- Android/iOS-клиент для устройства ребёнка;
- macOS и Linux;
- замена Microsoft Defender или полноценный антивирус;
- обещание абсолютной защиты при доступе ребёнка к паролю администратора или ключам восстановления устройства.

## Связанные материалы

- Аудит безопасности и UX: `../.codex/review-loop/runs/guard-v2-security-ux-audit-20260722/report.md`
- Исторический MVP roadmap: `parental-control-roadmap.md`
- Историческая инструкция MVP: `parent-mvp-checklist.md`
- Проектная память: `../.codex/memory/project.md`
