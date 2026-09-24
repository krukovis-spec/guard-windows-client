# Guard — родитель для Android

Это незавершённый компонент Guard v2. Главный экран переведён на русский, но пока только распознаёт ссылку на запрос и предупреждает, что разрешение не выдано. Привязка компьютера, загрузка карточки и подтверждение отпечатком с этого экрана не подключены.

Проверка 2026-09-24: прежняя ошибка `ByteArray.ifEmpty` исправлена; 18 JVM-тестов и сборка debug APK проходят. Реальные зашифрованные запрос и квитанции .NET проверяются без подставного verifier; подпись решения Kotlin/JCA независимо проверяется .NET. Общий вектор `protocol/test-vectors/relay-exchange-v1.properties` содержит только публичные тестовые ключи и никогда не используется приложением.

`FileApprovalOutbox` сохраняет точные подписанные байты и номер решения атомарно. Создавать его можно только в `Context.noBackupFilesDir`, одним процессом приложения. Подписанная промежуточная квитанция не снимает ожидание; терминальная квитанция должна совпадать с точным решением. Проверены повторное открытие, конфликт параллельной записи, повреждение файла и повтор квитанции. Реальный crash/power-loss ещё не проверен. Повторная обычная привязка не перезаписывает существующий ключ родителя.

Безопасная проверка из корня репозитория (JDK 17 и Android SDK должны быть установлены):

```powershell
$env:JAVA_HOME='C:\Users\kruko\AppData\Local\GuardDev\jdk-17.0.19+10'
$env:ANDROID_HOME='C:\Users\kruko\AppData\Local\Android\Sdk'
Push-Location parent/android
.\gradlew.bat :app:testDebugUnitTest :app:assembleDebug --offline --console=plain
Pop-Location
dotnet run --project tests/Guard.Windows.RelayCrypto.Tests -c Release --no-launch-profile
dotnet run --project tests/Guard.Windows.RelayCrypto.Tests -c Release --no-launch-profile -- --verify-android parent/android/app/build/test-interop/android-approval.hex
```

Debug APK создаётся в `app/build/outputs/apk/debug/app-debug.apk`. Это не готовый клиент управления защитой; он не устанавливался на телефон. Аппаратная подпись через `BIOMETRIC_STRONG`, подключение сети и регистрация доверия должны быть проверены в связанном сценарии.

До пилота обязательны проверка аппаратного хранения ключа, сильной биометрии без кода телефона, отзыва ключа при добавлении отпечатка и восстановления очереди подтверждений на реальном устройстве. Полная русская инструкция и статус проекта: [README](../../README.md).
