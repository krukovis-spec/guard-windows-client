# Kernel lease experiment — LAB ONLY

Не является рабочей защитой Guard или частью installer. Не запускать на основном ПК.
Разрешение Ивана от 2026-10-06: официальный EWDK и временные Secure Boot off / test-signing
только для закреплённой `GuardV2-Lab-20260930`, с восстановлением исходного состояния.

## Проверяемый вопрос

Может ли документированный kernel process callback отклонять новые запуски и завершать
уже работающий marker после 20 секунд, без Guard-службы и независимо от перевода часов?
Только два basename: `GuardKernelLabAllowed.exe` и `GuardKernelLabDenied.exe`.
Первый разрешается единственным вызовом lab-only IOCTL; второй не разрешается.
По умолчанию, после загрузки и после срока оба запрещены. Повтор IOCTL не продлевает lease.
Отдельный kernel thread наблюдает monotonic interrupt time с шагом 100 мс;
завершает сохранённый referenced process object, не процесс с переиспользованным PID.
Вызов завершения — вне callback/lock на PASSIVE_LEVEL.

Это **не** exact-hash identity, hardware-backed phone authority или защита от администратора.
Переименование marker обходит basename-фильтр. В исходном lease-варианте администратор вправе выгрузить lab driver;
тест должен зафиксировать обход, а не скрыть его. Подпись — тестовая, Secure Boot выключен.
Ни успешная сборка, ни PASS этого опыта не закрывают M1. Сон/возобновление и строгий
production signing/boot/anti-tamper остаются отдельными непроверенными условиями.

## Изоляция и восстановление

Дополнительный **DenyUnload** опыт (06.10.2026): при сборке `Build-KernelLabPackage.ps1 -DenyUnload`
обычная unload entry point отсутствует. Это отдельный вариант non-PnP legacy software driver,
а не рекомендация убрать обязательный unload у PnP/WDM драйвера. Cleanup ошибки инициализации
сохранён. [Документация поля DRIVER_OBJECT.DriverUnload](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_driver_object).
Manifest v2 связывает вариант `Lease`/`DenyUnload` с допустимыми фазами runner; старый v1 — только Lease.

- Реальный отчёт `Access/kernel-lease-4180db0eee3242f4a1dd8fbdd3357b9c.json`,
  15:37:58 UTC, PASS/exit 0. Manifest `72DF6E2CD414BBF8E521411D784962C05413014EA2D4D7D3457B6E1B71442E2C`.
- `sc stop` повышенного администратора отказал (1052); драйвер Running, оба marker запрещены.
  Но `start=disabled` принят; до reboot запрет сохраняется, после reboot драйвер Stopped/Disabled
  и обе программы выполняются без grant. `AdministratorDisableThenReboot=BYPASS_CONFIRMED`.
- `M1Accepted=false`: это измеренный boot-bypass, не принятая защита администратора. Lease/TTL не повторён.
  Оба варианта собраны `/W4 /WX` + пустой `/analyze DEFECTS`; исходная lease-конфигурация сохранена.
- Recovery BOOT_VERIFIED, Secure Boot ON/test-signing OFF/no Guard/data/lab driver; собственный
  snapshot `29818ddb-41f8-4891-85ca-6464ca0c02b7` удалён, исходный clean сохранён.
  Удаление четырёх новых временных build/package-каталогов отклонено policy терминала;
  они остались в TEMP, проверка от них больше не зависит. ISO EWDK отсоединён, кэш сохранён.
- Не повторять этот опыт без изменения защищённой boot-модели. Отключение Unload само по себе
  не обеспечивает обязательное присутствие драйвера, сохранность бинарника/конфигурации или доверенные grants.

- Driver не входит в solution, publish, installer или service composition.
- Host только собирает исходники; kernel binary не устанавливается/запускается на host.
- Host-runner проверяет VM ID, BIOS UUID, TPM, единственный диск 80 ГиБ и его корень,
  исходный Secure Boot, наличие `clean-windows-20260930`; до изменений делает собственный snapshot.
- Guest probe и одноразовый controller проверяют BIOS UUID; probe дополнительно host mismatch,
  Hyper-V model/manufacturer и elevation. Безопасный `Test-LabSafety.ps1` проверяет отказ на host.
- Credential остаётся в существующей DPAPI-копии вне Git. Приватный lab signing key создаётся
  только внутри guest. На host сертификаты доверия не устанавливаются.
- В опыте: default deny, однократные 20 секунд, повторный arm отказан, второй marker запрещён,
  работающий первый завершён с `C0000022`, часы переведены назад, поздний запуск запрещён,
  admin unload обход измерен, reload/reboot снова default deny без восстановления lease.
- `finally` восстанавливает собственный snapshot, исходный Secure Boot template/ON,
  проверяет новую загрузку без test-signing/драйвера/Guard. Только после этого удаляет собственный
  snapshot; исходный clean snapshot сохраняется. Если recovery не подтверждён — FAIL,
  snapshot ID сохраняется в `Access/kernel-lease-<run>.json`, успех не объявляется.

## Проверки и источники

EWDK `br_release_svc_im.28000.2526`, VS Build Tools 18.3.0 / MSVC 14.50.35717:
официальный ISO лежит вне Git в `%LOCALAPPDATA%\GuardDev\EWDK-28000.260714\`.
Размер 19 785 189 376 байт; локально вычисленный SHA-256
`A2928191A0E975D0BE6CA911BF3F11CA00E93C161BCEA6B922B248CBB833358F`.
Это идентификатор скачанного файла, не утверждение о независимо опубликованной checksum.
Authenticode компилятора, MSBuild и SignTool проверен: Microsoft, Valid.
После read-only mount (буква может измениться):

```powershell
./scripts/lab/kernel/Build-KernelLabPackage.ps1 -EwdkRoot 'F:\' -SignToolPath 'F:\Program Files\Windows Kits\10\bin\10.0.28000.0\x64\signtool.exe'
```

Сборка создаёт новые TEMP-каталоги и не исполняет драйвер. MSB8029 предупреждает только об
инкрементальной сборке в TEMP; здесь каждый build использует новый каталог. C-компиляция `/W4 /WX`
и MSVC `/analyze` прошли; отчёт `<DEFECTS></DEFECTS>`. Уточнены SAL-типы worker/dispatch;
неподдерживаемые IRP остаются у стандартного invalid-request handler Windows.
PE x64/Native, Integrity Check и NX подтверждены. В первой сборке отсутствовал kernel macro
`PROCESS_TERMINATE`; используется его документированная минимальная маска `0x0001`, не ALL_ACCESS.

Последний живой опыт 2026-10-06 **PASS**, но строгая защита M1 **НЕ ПРИНЯТА**:

- Source `bd95978`; `Access/kernel-lease-02399e1db8c6496e8ff005fde72c7e38.json`,
  11:31:46 UTC, реальный exit 0. Начальный запрет, однократная выдача, отказ повторной выдачи
  и запрет второго marker подтверждены. Первый работающий marker завершён через **20,606 с**
  с `C0000022`, без Guard user-mode службы и при наблюдаемом переводе часов назад на 30 минут.
- После срока повторный запуск запрещён; reload и reboot не восстанавливают lease.
- `AdministratorUnload=BYPASS_CONFIRMED`: администратор выгрузил драйвер и запустил запрещённый
  marker. Это не защита от администратора; `M1Accepted=false`, sleep/resume `NOT_RUN`.
- `SnapshotRecovery=BOOT_VERIFIED`: Secure Boot ON/test-signing OFF, Guard/data/lab driver
  отсутствуют, исходный BitLocker Off не изменён. Собственный snapshot удалён, clean snapshot сохранён.
- Следующий этап — граница anti-tamper/boot, exact image identity, доверенные kernel grants,
  сон/возобновление и выпускная подпись. Закрытый marker-only TTL не повторять без нового основания.

Предыдущие неуспешные опыты и исправления:

- Исходный `937ba1ff…`: recovery завершён после подтверждения UAC, `BOOT_VERIFIED`, собственный
  snapshot удалён. Повторное присвоение даже прежнего Secure Boot template запрещено при vTPM;
  runner теперь только проверяет шаблон и восстанавливает флаг ON/OFF.
- `b844471d…`: точный отказ — `Import-Certificate` в `LocalMachine\TrustedPublisher`, строка 80.
  Этот лишний импорт удалён: non-PnP test-mode driver не устанавливает PnP-пакет. Root остаётся
  только для явной проверки Authenticode; приватный ключ и доверие существуют лишь в guest.
- `a43bf5f0…`: после исправления импорта потерян PowerShell Direct (`Hyper-V socket target exited`).
  При разборе обнаружен недопустимый `KeQueryInterruptTimePrecise(NULL)`: выходной указатель обязателен.
  Во всех трёх местах заменён на `KeQueryInterruptTime()`; его tick-точность достаточна для 20 секунд
  и 100-мс worker, перевод часов не меняет счётчик. Dump не сохранён, поэтому причина обрыва не доказана
  анализом crash dump. Две проверки регрессии добавлены в существующий safety harness.
- Оба повторных опыта восстановлены: `BOOT_VERIFIED`, Secure Boot ON, test-signing OFF, Guard и lab
  driver отсутствуют, собственные snapshot удалены. Исходный clean snapshot сохранён.
- Первое приглашение UAC после исправления вернуло отмену до старта runner. После нового «готов»
  Иван подтвердил запуск; исправленный таймер и финальная `/analyze` сборка проверены выше.

Испытанный пакет (сохранён для следующего ограниченного этапа): `%TEMP%\GuardKernelLab-21749175cd46412da686ae05f0f2b762`.
Manifest SHA-256: `46F087471B22C59018E533C1410DA5034085C5DF823942C9898B5F920EE2F508`.
Запуск — существующий `Invoke-KernelLeaseLab.ps1` с этими `-PackageRoot` и `-ManifestSha256`,
из повышенного PowerShell после подтверждения Ивана. Host Guard/driver не запускать.

Безопасная проверка сценариев: `scripts/lab/Test-LabSafety.ps1`.
Сборка и живой результат фиксируются в worklog после фактического выполнения.
`Test-KernelLease.ps1` и `Invoke-KernelLeaseLab.ps1` нельзя запускать напрямую на host как guest probe.

Документированные API:
[process notification](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex),
[creation status](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_ps_create_notify_info),
[interrupt time](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kequeryinterrupttime),
[обязательный указатель Precise API](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kequeryinterrupttimeprecise),
[test-signing](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option),
[Trusted Publishers для PnP](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/trusted-publishers-certificate-store),
[process object handle](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-obopenobjectbypointer),
[termination](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-zwterminateprocess),
[secure device](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdmsec/nf-wdmsec-wdmlibiocreatedevicesecure),
[EWDK](https://learn.microsoft.com/en-us/windows-hardware/drivers/develop/using-the-enterprise-wdk).
