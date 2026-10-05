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
Переименование marker обходит basename-фильтр. Администратор вправе выгрузить этот lab driver;
тест должен зафиксировать обход, а не скрыть его. Подпись — тестовая, Secure Boot выключен.
Ни успешная сборка, ни PASS этого опыта не закрывают M1. Сон/возобновление и строгий
production signing/boot/anti-tamper остаются отдельными непроверенными условиями.

## Изоляция и восстановление

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
прошла; PE x64/Native, Integrity Check и NX подтверждены. В первой сборке отсутствовал kernel macro
`PROCESS_TERMINATE`; используется его документированная минимальная маска `0x0001`, не ALL_ACCESS.

Первый живой опыт 2026-10-06: FAIL до получения результата TTL, `E_ACCESSDENIED` внутри guest probe.
Теперь probe сообщает ограниченные phase/type/id/line вместо потери места ошибки.
Recovery первоначально остановился после применения snapshot: повторное присвоение даже того же
Secure Boot template запрещено Hyper-V после инициализации vTPM. Runner исправлен: шаблон только
проверяется, возвращается лишь ON/OFF. Повторный опыт допустим только после BOOT_VERIFIED recovery.

Безопасная проверка сценариев: `scripts/lab/Test-LabSafety.ps1`.
Сборка и живой результат фиксируются в worklog после фактического выполнения.
`Test-KernelLease.ps1` и `Invoke-KernelLeaseLab.ps1` нельзя запускать напрямую на host как guest probe.

Документированные API:
[process notification](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex),
[creation status](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_ps_create_notify_info),
[interrupt time](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kequeryinterrupttimeprecise),
[process object handle](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-obopenobjectbypointer),
[termination](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-zwterminateprocess),
[secure device](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdmsec/nf-wdmsec-wdmlibiocreatedevicesecure),
[EWDK](https://learn.microsoft.com/en-us/windows-hardware/drivers/develop/using-the-enterprise-wdk).
