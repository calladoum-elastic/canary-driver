#include "MinifilterDriver.hpp"

#include "../Common/Log.hpp"
#include "../Common/Utils.hpp"

#pragma prefast(disable : __WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, MinifilterDriverUnload)
#pragma alloc_text(PAGE, MinifilterDriverInstanceSetup)
#endif

#define MAGIC_FILENAME_PATTERN L"*\\123456890_CANARYMAGIC_123456890.DOC"

GlobalContext* Context {nullptr};

namespace Comms
{
NTSTATUS
HandleIoSetEventPointer(PHANDLE pHandle)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
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
PortConnectCallback(
    PFLT_PORT ClientPort,
    PVOID ServerPortCookie,
    PVOID ConnectionContext,
    ULONG SizeOfContext,
    PVOID* ConnectionPortCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionPortCookie);

    // TODO (maybe) handle multiple clients
    if ( Context->CommunicationClientPorts[0] )
    {
        return STATUS_ALREADY_REGISTERED;
    }

    info(L"New connection from %p", ClientPort);
    Context->CommunicationClientPorts[0] = ClientPort;
    return STATUS_SUCCESS;
}


void
PortDisconnectCallback(PVOID ConnectionCookie)
{
    if ( (uptr)Context->CommunicationClientPorts[0] != (uptr)ConnectionCookie )
        return;

    ::FltCloseClientPort(Context->FilterHandle, &Context->CommunicationClientPorts[0]);
    Context->CommunicationClientPorts[0] = nullptr;
}

NTSTATUS
PortMessageCallback(
    PVOID PortCookie,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength,
    PULONG ReturnOutputBufferLength)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(PortCookie);

    uptr cursor                     = (uptr)InputBuffer;
    ULONG ExpectedInputBufferLength = InputBufferLength;

    if ( ExpectedInputBufferLength < sizeof(u32) )
        return STATUS_BUFFER_TOO_SMALL;

    ExpectedInputBufferLength -= sizeof(u32);
    cursor += sizeof(u32);

    u32 code = *((u32*)InputBuffer);


    switch ( code )
    {
    case Comms::Ioctl::SetActivityEvent:
    {
        dbg(L"Handling Comms::Ioctl::SetActivityEvent");
        if ( ExpectedInputBufferLength < sizeof(HANDLE) )
            return STATUS_BUFFER_TOO_SMALL;

        ExpectedInputBufferLength -= sizeof(HANDLE);
        PHANDLE phEvent = (PHANDLE)cursor;
        cursor += sizeof(HANDLE);
        Status                    = HandleIoSetEventPointer(phEvent);
        *ReturnOutputBufferLength = 0;
        break;
    }

    case Comms::Ioctl::GetSuspendedPid:
    {
        dbg(L"Handling Comms::Ioctl::GetSuspendedPid");
        if ( ExpectedInputBufferLength != 0 )
            return STATUS_INVALID_BUFFER_SIZE;

        dbg(L"InLen=%d OutLen=%d", InputBufferLength, OutputBufferLength);
        if ( OutputBufferLength < sizeof(ULONG) )
            return STATUS_BUFFER_TOO_SMALL;

        auto ptr                  = static_cast<PULONG>(OutputBuffer);
        *ptr                      = Context->LastPid;
        *ReturnOutputBufferLength = sizeof(ULONG);
        Status                    = STATUS_SUCCESS;
        break;
    }

    default:
        return STATUS_INVALID_PARAMETER;
    }

    return Status;
}

} // namespace Comms

static NTSTATUS
SuspendProcessById(ULONG ProcessId)
{
    CLIENT_ID ClientId {.UniqueProcess = UlongToHandle(ProcessId)};
    OBJECT_ATTRIBUTES ObjectAttributes {.Length = sizeof(OBJECT_ATTRIBUTES), .Attributes = OBJ_KERNEL_HANDLE};
    HANDLE ProcessHandle {nullptr};
    PVOID Object {nullptr};

    NTSTATUS Status = ::ZwOpenProcess(&ProcessHandle, PROCESS_ALL_ACCESS, &ObjectAttributes, &ClientId);
    if ( !NT_SUCCESS(Status) )
    {
        return Status;
    }

    Status = ::ObReferenceObjectByHandle(ProcessHandle, GENERIC_ALL, *PsProcessType, 0, &Object, 0i64);
    if ( NT_SUCCESS(Status) )
    {
        //
        // Process object found, suspend it, and notify the change to the UM process
        //
        Status           = ::PsSuspendProcess(Object);
        Context->LastPid = ProcessId;
        ::KeSetEvent(Context->ActivityEvent, 2, false);
        ::ObDereferenceObject(Object);
    }

    ::ZwClose(ProcessHandle);
    return Status;
}

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    OBJECT_ATTRIBUTES oa {};
    UNICODE_STRING name = RTL_CONSTANT_STRING(PORT_PATH_WIDE);
    PSECURITY_DESCRIPTOR sd {nullptr};

    dbg(L"Creating driver global context");
    Context = new GlobalContext();
    if ( !Context )
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }
    ok(L"Context created");

    Context->FilePathPattern = RTL_CONSTANT_STRING(MAGIC_FILENAME_PATTERN);
    ok(L"Filtering write access to file pattern: '%wZ'", Context->FilePathPattern);

    Status = ::FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if ( !NT_SUCCESS(Status) )
    {
        err(L"FltBuildDefaultSecurityDescriptor() failed=%08X", Status);
        goto Cleanup;
    }

    InitializeObjectAttributes(&oa, &name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, sd);


    //
    // Register the filter
    //
    Status = ::FltRegisterFilter(DriverObject, &Context->FilterRegistrationTable, &Context->FilterHandle);
    if ( !NT_SUCCESS(Status) )
    {
        err(L"FltRegisterFilter() failed=%08X", Status);
        goto Cleanup;
    }


    //
    // Create the communication port
    //
    Status = ::FltCreateCommunicationPort(
        Context->FilterHandle,
        &Context->CommunicationServerPort,
        &oa,
        nullptr,
        Comms::PortConnectCallback,
        Comms::PortDisconnectCallback,
        Comms::PortMessageCallback,
        1);
    if ( !NT_SUCCESS(Status) )
    {
        err(L"FltCreateCommunicationPort() failed=%08X", Status);
        goto Cleanup;
    }


    //
    // Start filtering
    //
    Status = ::FltStartFiltering(Context->FilterHandle);
    if ( !NT_SUCCESS(Status) )
    {
        err(L"FltStartFiltering() failed=%08X", Status);
        goto Cleanup;
    }

    ok(L"Loaded fs filter %S", DEVICE_NAME);

Cleanup:
    if ( sd )
    {
        ::FltFreeSecurityDescriptor(sd);
    }

    if ( !NT_SUCCESS(Status) )
    {
        Context->Cleanup();
        delete Context;
        ok(L"Context deleted");
    }

    return Status;
}


NTSTATUS
MinifilterDriverUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    if ( Context )
    {
        Context->Cleanup();
        delete Context;
        ok(L"Context deleted");
    }

    return STATUS_SUCCESS;
}


NTSTATUS
MinifilterDriverInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    return STATUS_SUCCESS;
}


FLT_PREOP_CALLBACK_STATUS
MinifilterDriverDefaultCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{

    const PUNICODE_STRING pFilename = &FltObjects->FileObject->FileName;
    ok(L"IRP=%lu, File='%wZ'", Data->Iopb->MajorFunction, pFilename);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
MinifilterDriverPreCreateOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);


    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


FLT_POSTOP_CALLBACK_STATUS
MinifilterDriverPostCreateOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    return FLT_POSTOP_FINISHED_PROCESSING;
}


///
/// @brief This handler suspends a process who has a thread that attempts to write to our canary file
///
/// @param [in] FltObjects
/// @return FLT_PREOP_CALLBACK_STATUS
///
static FLT_PREOP_CALLBACK_STATUS
SuspendProcessOnCanaryWrite(_In_ PCFLT_RELATED_OBJECTS FltObjects)
{
    if ( ::KeGetCurrentIrql() > PASSIVE_LEVEL )
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Ignore SYSTEM
    //
    if ( ::PsIsSystemThread(::PsGetCurrentThread()) )
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Check whether the file name matches an expression, if not exit quickly
    //
    NTSTATUS Status                 = STATUS_UNSUCCESSFUL;
    const PUNICODE_STRING pFilename = &FltObjects->FileObject->FileName;
    if ( ::FsRtlIsNameInExpression(&Context->FilePathPattern, pFilename, TRUE, NULL) == FALSE )
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Suspend the process
    //
    const ULONG TargetPid = HandleToUlong(::PsGetCurrentProcessId());
    ok(L"Write access to canary detected - Suspending process PID=%lu", TargetPid);
    Status = SuspendProcessById(TargetPid);
    if ( !NT_SUCCESS(Status) )
    {
        err(L"SuspendProcessById(%lu)=%08X", TargetPid, Status);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Notify the usermode process the pid has changed
    //
    Context->LastPid = TargetPid;
    ::KeSetEvent(Context->ActivityEvent, 2, false);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
MinifilterDriverPreWriteOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(CompletionContext);
    return SuspendProcessOnCanaryWrite(FltObjects);
}

FLT_PREOP_CALLBACK_STATUS
MinifilterDriverPreCreateSectionOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(CompletionContext);

    return SuspendProcessOnCanaryWrite(FltObjects);
}
