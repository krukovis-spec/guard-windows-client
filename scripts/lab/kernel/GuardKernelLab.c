// LAB ONLY: no production identity, phone authority, persistence or tamper protection.
// Only these two deliberately named marker executables are affected. Never load on the host.
#include <ntifs.h>
#include <wdmsec.h>

#define LAB_DEVICE_TYPE 0x8337
#define LAB_ARM CTL_CODE(LAB_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define LAB_PROCESS_LIMIT 64
#define LAB_LEASE_TICKS (20ULL * 10000000ULL)
// Documented PROCESS_TERMINATE access mask (winnt.h); WDK ntifs.h does not publish its name.
#define LAB_PROCESS_TERMINATE 0x0001UL

static FAST_MUTEX Gate;
static KEVENT StopEvent;
static HANDLE WorkerHandle;
static PDEVICE_OBJECT LabDevice;
static PEPROCESS Tracked[LAB_PROCESS_LIMIT];
static ULONGLONG Deadline;
static BOOLEAN Armed;
static BOOLEAN LinkCreated;
static UNICODE_STRING LinkName = RTL_CONSTANT_STRING(L"\\DosDevices\\GuardKernelLab");
static const GUID DeviceClass = {0xb512c786, 0x8c8d, 0x4449, {0xb8,0x74,0xe1,0x60,0x5f,0x98,0x13,0x28}};

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD LabUnload;
DRIVER_DISPATCH LabDispatch;

static ULONG MarkerKind(PCUNICODE_STRING image)
{
    UNICODE_STRING name;
    UNICODE_STRING allowed = RTL_CONSTANT_STRING(L"GuardKernelLabAllowed.exe");
    UNICODE_STRING denied = RTL_CONSTANT_STRING(L"GuardKernelLabDenied.exe");
    USHORT start;
    if (image == NULL || image->Buffer == NULL || image->Length % sizeof(WCHAR) != 0) return 0;
    start = (USHORT)(image->Length / sizeof(WCHAR));
    while (start > 0 && image->Buffer[start - 1] != L'\\') --start;
    name.Buffer = image->Buffer + start;
    name.Length = (USHORT)(image->Length - start * sizeof(WCHAR));
    name.MaximumLength = name.Length;
    // ponytail: basename matching deliberately confines this experiment; NOT an application identity.
    if (RtlEqualUnicodeString(&name, &allowed, TRUE)) return 1;
    if (RtlEqualUnicodeString(&name, &denied, TRUE)) return 2;
    return 0;
}

static VOID ProcessChanged(PEPROCESS process, HANDLE processId, PPS_CREATE_NOTIFY_INFO info)
{
    ULONG i;
    PEPROCESS released = NULL;
    UNREFERENCED_PARAMETER(processId);
    if (info == NULL) {
        ExAcquireFastMutex(&Gate);
        for (i = 0; i < LAB_PROCESS_LIMIT; ++i) {
            if (Tracked[i] == process) { released = Tracked[i]; Tracked[i] = NULL; break; }
        }
        ExReleaseFastMutex(&Gate);
        if (released != NULL) ObDereferenceObject(released);
        return;
    }
    i = MarkerKind(info->ImageFileName);
    if (i == 0 || !NT_SUCCESS(info->CreationStatus)) return;
    ExAcquireFastMutex(&Gate);
    if (i != 1 || !Armed || KeQueryInterruptTimePrecise(NULL) >= Deadline) {
        info->CreationStatus = STATUS_ACCESS_DENIED;
    } else {
        for (i = 0; i < LAB_PROCESS_LIMIT && Tracked[i] != NULL; ++i) { }
        if (i == LAB_PROCESS_LIMIT) info->CreationStatus = STATUS_INSUFFICIENT_RESOURCES;
        else { ObReferenceObject(process); Tracked[i] = process; }
    }
    ExReleaseFastMutex(&Gate);
}

static VOID ExpiryWorker(PVOID context)
{
    LARGE_INTEGER delay;
    PEPROCESS expired[LAB_PROCESS_LIMIT];
    UNREFERENCED_PARAMETER(context);
    delay.QuadPart = -1000000LL; // 100ms observation granularity; not a real-time guarantee.
    while (KeWaitForSingleObject(&StopEvent, Executive, KernelMode, FALSE, &delay) == STATUS_TIMEOUT) {
        ULONG i, count = 0;
        ExAcquireFastMutex(&Gate);
        if (Armed && KeQueryInterruptTimePrecise(NULL) >= Deadline) {
            for (i = 0; i < LAB_PROCESS_LIMIT; ++i) {
                if (Tracked[i] != NULL) { ObReferenceObject(Tracked[i]); expired[count++] = Tracked[i]; }
            }
        }
        ExReleaseFastMutex(&Gate);
        // PASSIVE_LEVEL, outside notification and lock: exit callbacks cannot deadlock on Gate.
        for (i = 0; i < count; ++i) {
            HANDLE handle = NULL;
            if (NT_SUCCESS(ObOpenObjectByPointer(expired[i], OBJ_KERNEL_HANDLE, NULL,
                    LAB_PROCESS_TERMINATE, *PsProcessType, KernelMode, &handle))) {
                (VOID)ZwTerminateProcess(handle, STATUS_ACCESS_DENIED);
                ZwClose(handle);
            }
            // The referenced process object, never a recycled PID, is the termination target.
            ObDereferenceObject(expired[i]);
        }
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

_Use_decl_annotations_
NTSTATUS LabDispatch(PDEVICE_OBJECT device, PIRP irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    UNREFERENCED_PARAMETER(device);
    if (stack->MajorFunction == IRP_MJ_CREATE) {
        status = stack->FileObject->FileName.Length == 0 ? STATUS_SUCCESS : STATUS_OBJECT_NAME_NOT_FOUND;
    } else if (stack->MajorFunction == IRP_MJ_CLOSE || stack->MajorFunction == IRP_MJ_CLEANUP) {
        status = STATUS_SUCCESS;
    } else if (stack->MajorFunction == IRP_MJ_DEVICE_CONTROL && irp->RequestorMode == UserMode &&
            stack->Parameters.DeviceIoControl.IoControlCode == LAB_ARM &&
            stack->Parameters.DeviceIoControl.InputBufferLength == 0 &&
            stack->Parameters.DeviceIoControl.OutputBufferLength == 0) {
        ExAcquireFastMutex(&Gate);
        if (Armed) status = STATUS_ACCESS_DENIED;
        else {
            Deadline = KeQueryInterruptTimePrecise(NULL) + LAB_LEASE_TICKS;
            Armed = TRUE;
            status = STATUS_SUCCESS;
        }
        ExReleaseFastMutex(&Gate);
    }
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

_Use_decl_annotations_
VOID LabUnload(PDRIVER_OBJECT driver)
{
    ULONG i;
    UNREFERENCED_PARAMETER(driver);
    KeSetEvent(&StopEvent, IO_NO_INCREMENT, FALSE);
    (VOID)ZwWaitForSingleObject(WorkerHandle, FALSE, NULL);
    ZwClose(WorkerHandle);
    (VOID)PsSetCreateProcessNotifyRoutineEx(ProcessChanged, TRUE);
    for (i = 0; i < LAB_PROCESS_LIMIT; ++i) if (Tracked[i] != NULL) ObDereferenceObject(Tracked[i]);
    if (LinkCreated) IoDeleteSymbolicLink(&LinkName);
    IoDeleteDevice(LabDevice);
}

_Use_decl_annotations_
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath)
{
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\GuardKernelLab");
    UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    OBJECT_ATTRIBUTES attributes;
    ULONG i;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(registryPath);
    ExInitializeFastMutex(&Gate);
    KeInitializeEvent(&StopEvent, NotificationEvent, FALSE);
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i) driver->MajorFunction[i] = LabDispatch;
    status = IoCreateDeviceSecure(driver, 0, &deviceName, LAB_DEVICE_TYPE,
        FILE_DEVICE_SECURE_OPEN, FALSE, &sddl, &DeviceClass, &LabDevice);
    if (!NT_SUCCESS(status)) return status;
    status = PsSetCreateProcessNotifyRoutineEx(ProcessChanged, FALSE);
    if (!NT_SUCCESS(status)) { IoDeleteDevice(LabDevice); return status; }
    InitializeObjectAttributes(&attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = PsCreateSystemThread(&WorkerHandle, SYNCHRONIZE, &attributes, NULL, NULL, ExpiryWorker, NULL);
    if (!NT_SUCCESS(status)) {
        (VOID)PsSetCreateProcessNotifyRoutineEx(ProcessChanged, TRUE);
        IoDeleteDevice(LabDevice);
        return status;
    }
    driver->DriverUnload = LabUnload;
    status = IoCreateSymbolicLink(&LinkName, &deviceName);
    if (!NT_SUCCESS(status)) { LabUnload(driver); return status; }
    LinkCreated = TRUE;
    LabDevice->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
