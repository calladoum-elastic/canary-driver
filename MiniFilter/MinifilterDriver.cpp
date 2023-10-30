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

static NTSTATUS
SuspendProcessById(ULONG ProcessId)
{
    NTSTATUS Status {STATUS_UNSUCCESSFUL};
    CLIENT_ID ClientId {};
    OBJECT_ATTRIBUTES ObjectAttributes {};
    HANDLE ProcessHandle {};


    ObjectAttributes.Length     = sizeof(OBJECT_ATTRIBUTES);
    ObjectAttributes.Attributes = OBJ_KERNEL_HANDLE;
    ClientId.UniqueProcess      = UlongToHandle(ProcessId);
    Status                      = ::ZwOpenProcess(&ProcessHandle, 0x1FFFFFu, &ObjectAttributes, &ClientId);
    if ( NT_SUCCESS(Status) )
    {
        PVOID Object {nullptr};
        Status = ::ObReferenceObjectByHandle(ProcessHandle, GENERIC_ALL, *PsProcessType, 0, &Object, 0i64);
        if ( NT_SUCCESS(Status) )
        {
            Status = ::PsSuspendProcess(Object);
            ::ObDereferenceObject(Object);
        }
        ::ZwClose(ProcessHandle);
        return Status;
    }
    return Status;
}

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    dbg(L"Creating driver global context");
    Context = new GlobalContext();
    if ( !Context )
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }
    ok(L"Context created");

    Status = CreateDeviceObject(DriverObject);
    if ( !NT_SUCCESS(Status) )
    {
        goto Cleanup;
    }

    info(L"Loading %S", DEVICE_NAME);
    Context->FilePathPattern = RTL_CONSTANT_STRING(MAGIC_FILENAME_PATTERN);
    ok(L"Filtering write access to file pattern: '%wZ'", Context->FilePathPattern);

    Status = ::FltRegisterFilter(DriverObject, &Context->FilterRegistrationTable, &Context->FilterHandle);
    if ( !NT_SUCCESS(Status) )
    {
        err(L"FltRegisterFilter() failed=%08X", Status);
        goto Cleanup;
    }

    Status = ::FltStartFiltering(Context->FilterHandle);
    if ( !NT_SUCCESS(Status) )
    {
        err(L"FltStartFiltering() failed=%08X", Status);
        ::FltUnregisterFilter(Context->FilterHandle);
        goto Cleanup;
    }

    ok(L"Loaded fs filter %S", DEVICE_NAME);

Cleanup:
    if ( !NT_SUCCESS(Status) )
    {
        delete Context;
    }

    return Status;
}


NTSTATUS
MinifilterDriverUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    if ( Context != nullptr )
    {
        if ( Context->DeviceObject != nullptr )
        {
            DestroyDeviceObject();
        }

        if ( Context->FilterHandle != nullptr )
        {
            ::FltUnregisterFilter(Context->FilterHandle);
            ok(L"Unloaded FS filter %S", DEVICE_NAME);
            Context->FilterHandle = nullptr;
        }

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
    if ( Context->ActivityEvent )
    {
        LONG PrevState {};
        ::ZwSetEvent(Context->ActivityEvent, &PrevState);
    }

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

    //
    // Ignore if there's no write access
    //
    // if ( true )
    // {
    //     return FLT_PREOP_SUCCESS_NO_CALLBACK;
    // }

    return SuspendProcessOnCanaryWrite(FltObjects);
}
