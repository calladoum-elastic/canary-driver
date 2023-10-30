// clang-format off
#include "MinifilterDriver.hpp"

#include "../Common/Log.hpp"
// clang-format on


NTSTATUS
static inline CompleteRequest(_In_ PIRP Irp, _In_ NTSTATUS Status, _In_ ULONG_PTR Information)
{
    Irp->IoStatus.Status      = Status;
    Irp->IoStatus.Information = Information;
    ::IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}


NTSTATUS
IrpNotImplementedHandler(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    CompleteRequest(Irp, STATUS_NOT_IMPLEMENTED, 0);
    return STATUS_NOT_IMPLEMENTED;
}


NTSTATUS
HandleIoSetEventPointer(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack)
{
    NTSTATUS Status = STATUS_SUCCESS;

    UINT32 dwInputLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
    if ( dwInputLength != sizeof(HANDLE) )
    {
        return STATUS_INVALID_PARAMETER;
    }

    PHANDLE pHandle = (PHANDLE)Irp->AssociatedIrp.SystemBuffer;
    HANDLE hEvent   = *pHandle;
    PKEVENT pKernelNotifEvent {nullptr};

    dbg(L"Lookup for handle 0x%lx", hEvent);

    Status = ::ObReferenceObjectByHandle(
        hEvent,
        EVENT_ALL_ACCESS,
        *ExEventObjectType,
        UserMode,
        (PVOID*)&pKernelNotifEvent,
        nullptr);
    if ( !NT_SUCCESS(Status) )
    {
        return Status;
    }

    dbg(L"Event handle set to 0x%x", hEvent);

    PVOID pOldEvent = InterlockedExchangePointer((PVOID*)&Context->ActivityEvent, (PVOID)pKernelNotifEvent);
    if ( pOldEvent )
    {
        ObDereferenceObject(pOldEvent);
    }

    return Status;
}

NTSTATUS
DriverDeviceControlRoutine(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS Status                 = STATUS_SUCCESS;
    PIO_STACK_LOCATION CurrentStack = IoGetCurrentIrpStackLocation(Irp);
    NT_ASSERT(CurrentStack);

    const ULONG dwIoctlCode     = CurrentStack->Parameters.DeviceIoControl.IoControlCode;
    PVOID InputBuffer           = Irp->AssociatedIrp.SystemBuffer;
    const ULONG InputBufferLen  = CurrentStack->Parameters.DeviceIoControl.InputBufferLength;
    PVOID OutputBuffer          = Irp->AssociatedIrp.SystemBuffer;
    const ULONG OutputBufferLen = CurrentStack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG dwDataWritten         = 0;

    switch ( dwIoctlCode )
    {
    case IOCTL_SET_ACTIVITY_EVENT_VALUE:
        Status = HandleIoSetEventPointer(Irp, CurrentStack);
        break;

    case IOCTL_GET_SUSPENDED_PROCESS_ID:
    {
        if ( OutputBufferLen >= sizeof(ULONG) )
        {
            Status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }

        PULONG ptr = (PULONG)OutputBuffer;
        *ptr       = Context->LastPid;
        break;
    }

    default:
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    dbg(L"IoctlDispatch(0x%08x) returned with Status=0x%x", dwIoctlCode, Status);
    if ( !NT_SUCCESS(Status) )
    {
        err(L"IOCTL %#x returned %#lx", dwIoctlCode, Status);
        dwDataWritten = 0;
    }

    return CompleteRequest(Irp, Status, dwDataWritten);
}


NTSTATUS
DriverCleanup(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    return CompleteRequest(Irp, STATUS_SUCCESS, 0);
}


NTSTATUS
CreateDeviceObject(_In_ PDRIVER_OBJECT DriverObject)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PDEVICE_OBJECT DeviceObject {nullptr};

    for ( auto i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++ )
    {
        DriverObject->MajorFunction[i] = IrpNotImplementedHandler;
    }

    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControlRoutine;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP]        = DriverCleanup;

    Status = ::IoCreateDevice(
        DriverObject,
        0,
        &Context->DeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        false,
        &DeviceObject);
    if ( !NT_SUCCESS(Status) )
    {
        err(L"Error creating device object (0x%08X)", Status);
        return Status;
    }

    ok(L"Device '%wZ' successfully created", Context->DeviceName);

    Status = ::IoCreateSymbolicLink(&Context->DeviceSymLink, &Context->DeviceName);
    if ( !NT_SUCCESS(Status) )
    {
        err(L"IoCreateSymbolicLink() failed: 0x%08X", Status);
        return Status;
    }

    ok(L"Symlink for '%wZ' created as '%wZ'", Context->DeviceName, Context->DeviceSymLink);

    DeviceObject->Flags |= DO_DIRECT_IO;
    DeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);

    Context->DeviceObject = DeviceObject;
    Context->DriverObject = DriverObject;

    return Status;
}


NTSTATUS
DestroyDeviceObject()
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    dbg(L"Unloading '%wZ'...", Context->DeviceName);
    ::IoDeleteSymbolicLink(&Context->DeviceSymLink);
    ::IoDeleteDevice(Context->DeviceObject);

    return Status;
}
