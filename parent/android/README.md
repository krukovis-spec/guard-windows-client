# Guard — родитель для Android

Это незавершённый компонент Guard v2. Главный экран переведён на русский, но пока только распознаёт ссылку на запрос и предупреждает, что разрешение не выдано. Привязка компьютера, загрузка карточки и подтверждение отпечатком с этого экрана не подключены.

Минимальная версия для текущего криптографического маршрута — Android 12 (API 31): аппаратный ECDH-ключ использует `KeyProperties.PURPOSE_AGREE_KEY`, которого нет в API 30. Совместимость и сильный отпечаток конкретного телефона родителя ещё должны быть проверены физически; программный ключ или PIN не подставляются автоматически.

Проверка 2026-09-24: прежняя ошибка `ByteArray.ifEmpty` исправлена; 18 JVM-тестов и сборка debug APK проходят. Реальные зашифрованные запрос и квитанции .NET проверяются без подставного verifier; подпись решения Kotlin/JCA независимо проверяется .NET. Общий вектор `protocol/test-vectors/relay-exchange-v1.properties` содержит только публичные тестовые ключи и никогда не используется приложением.

`FileApprovalOutbox` сохраняет точные подписанные байты и номер решения атомарно. Создавать его можно только в `Context.noBackupFilesDir`, одним процессом приложения. Подписанная промежуточная квитанция не снимает ожидание; терминальная квитанция должна совпадать с точным решением. Проверены повторное открытие, конфликт параллельной записи, повреждение файла и повтор квитанции. Реальный crash/power-loss ещё не проверен. Повторная обычная привязка не перезаписывает существующий ключ родителя.

## Незавершённая привязка — 2026-09-30

`AndroidEnrollmentCeremony` сохраняет исходный offer в `noBackupFilesDir/enrollment` **до** создания раздельных Keystore-ключей. Имена зависят от полного хеша offer; старый общий ключ не перезаписывается и не удаляется. После сбоя до сохранения claim нужен тот же QR; после сохранения claim повторное сканирование не требуется. Подпись из свежего biometric CryptoObject сначала атомарно сохраняется вместе с точными claim/chain/MAC, затем может быть отправлена. Повторная отправка использует ту же подпись. Сам QR-секрет и его hash-key на диск не записываются.

Потерянный ключ после сохранения claim не создаётся заново; несовпадение ключа, срока, callback, повреждение файла и откат ниже сохранённого времени останавливают попытку. Это не защищённые аппаратные часы и не подтверждение владельца: Windows остаётся окончательной проверяющей стороной. Локальная отмена сохраняет запись и ключи, потому что компьютер мог уже завершить привязку; она **не означает отзыв на Windows**. До реализации подписанного согласования результата и безопасной очистки хранится максимум восемь попыток, без автоматического удаления истёкших. Это открытый lifecycle gate, не готовый пользовательский сценарий.

Keystore повторяет генерацию в TEE только при `StrongBoxUnavailableException` и отсутствии частично созданного ключа. Остальные ошибки не маскируются. Проверяются hardware/profile обоих ключей; для подписания требуется per-operation strong biometric без PIN. По [Android KeyInfo](https://developer.android.com/reference/android/security/keystore/KeyInfo#getUserAuthenticationValidityDurationSeconds()) этот режим читается как `-1`, хотя задаётся builder-значением `0`. Проверка Google chain, challenge и APK identity выполняется отдельно на Windows.

Локальные проверки: 34 JVM-теста, debug APK; `lintDebug` и `assembleDebugAndroidTest`. Физический `RealDeviceSecurityTest.hardwareProfilesAndRestartKeepSameKeys` больше не пустой: создаёт два уникальных тестовых alias, проверяет неизменность ключей и отказ подписи без биометрии, затем удаляет только их. Он **ещё не запускался на телефоне** и не заменяет успешный интерактивный отпечаток, его отмену/смену и проверку chain вне телефона. Подключение этой ceremony к экрану, scanner и relay ещё впереди.

`EnrollmentExchange` уже шифрует полный claim/chain, proof и запрос состояния для Windows. Ответ Windows зашифрован и подписан; проверяются offer/claim, отдельный случайный номер текущего запроса, срок и точное состояние. «Ожидается подтверждение на компьютере» не превращается в «привязка завершена». После истечения QR разрешён запрос о ранее сохранённом результате, без смены ключей. Межъязыковые проверки реального HPKE/подписей проходят в обе стороны. Сетевой слой ещё должен атомарно сохранять ожидаемый nonce до отправки и результат перед активацией владельца; сейчас проверенный ответ сам по себе не создаёт active-owner запись и не снимает лимит восьми попыток. Это необходимый следующий шаг, не готовая привязка через интернет.

Безопасная проверка из корня репозитория (JDK 17 и Android SDK должны быть установлены):

```powershell
$env:JAVA_HOME='C:\Users\kruko\AppData\Local\GuardDev\jdk-17.0.19+10'
$env:ANDROID_HOME='C:\Users\kruko\AppData\Local\Android\Sdk'
Push-Location parent/android
.\gradlew.bat :app:testDebugUnitTest :app:assembleDebug --offline --console=plain
Pop-Location
dotnet run --project tests/Guard.Windows.RelayCrypto.Tests -c Release --no-launch-profile
dotnet run --project tests/Guard.Windows.RelayCrypto.Tests -c Release --no-launch-profile -- --verify-android parent/android/app/build/test-interop/android-approval.hex
dotnet run --project tests/Guard.Windows.RelayCrypto.Tests -c Release --no-launch-profile -- --verify-android-enrollment parent/android/app/build/test-interop/android-enrollment.txt
dotnet run --project tests/Guard.Windows.Crypto.Tests -c Release --no-launch-profile -- --verify-android-exchange parent/android/app/build/test-interop/android-enrollment-exchange.txt
```

Debug APK создаётся в `app/build/outputs/apk/debug/app-debug.apk`. Это не готовый клиент управления защитой; он не устанавливался на телефон. Аппаратная подпись через `BIOMETRIC_STRONG`, подключение сети и регистрация доверия должны быть проверены в связанном сценарии.

До пилота обязательны проверка аппаратного хранения ключа, сильной биометрии без кода телефона, отзыва ключа при добавлении отпечатка и восстановления очереди подтверждений на реальном устройстве. Полная русская инструкция и статус проекта: [README](../../README.md).
