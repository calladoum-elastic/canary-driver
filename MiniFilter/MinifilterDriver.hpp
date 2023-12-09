#pragma once

#include <dontuse.h>
#include <fltKernel.h>

#include "../Common/Constants.hpp"
#include "../Common/Utils.hpp"

#define DRIVER_CONTEXT_TAG 'CaDr'
#define DRIVER_TAG DRIVER_CONTEXT_TAG


EXTERN_C_START

NTKERNELAPI
NTSTATUS
ZwQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_ PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength);


NTKERNELAPI
NTSTATUS
NTAPI
MmCopyVirtualMemory(
    PEPROCESS SourceProcess,
    PVOID SourceAddress,
    PEPROCESS TargetProcess,
    PVOID TargetAddress,
    SIZE_T BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T ReturnSize);


NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS* Process);

NTKERNELAPI
NTSTATUS
PsSuspendProcess(_In_ PVOID Object);


DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);

NTSTATUS
MinifilterDriverUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

NTSTATUS
MinifilterDriverInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);

FLT_PREOP_CALLBACK_STATUS
MinifilterDriverPreCreateOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

FLT_PREOP_CALLBACK_STATUS
MinifilterDriverPreWriteOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

FLT_PREOP_CALLBACK_STATUS
MinifilterDriverDefaultCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

FLT_PREOP_CALLBACK_STATUS
MinifilterDriverPreCreateSectionOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);
EXTERN_C_END


struct GlobalContext
{
    Utils::KQueuedSpinLock ContextLock;
    PFLT_FILTER FilterHandle {nullptr};
    UNICODE_STRING FilePathPattern {};
    PKEVENT ActivityEvent {nullptr};
    PDRIVER_OBJECT DriverObject {nullptr};
    ULONG LastPid {0};
    PFLT_PORT CommunicationServerPort {nullptr};
    PFLT_PORT CommunicationClientPorts[1] = {0};

    const FLT_OPERATION_REGISTRATION Callbacks[6] = {
        // {IRP_MJ_CREATE, 0, MinifilterDriverDefaultCallback},
        // {IRP_MJ_CLOSE, 0, MinifilterDriverDefaultCallback},

        // For WriteFile
        {IRP_MJ_WRITE, 0, MinifilterDriverPreWriteOperation}, // happens on NtWriteFile()

        // For SectionMapping
        {IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
         0,
         MinifilterDriverPreCreateSectionOperation}, // happens on NtCreateSection(SECTION_MAP_WRITE)

        {IRP_MJ_OPERATION_END}};

    const FLT_REGISTRATION FilterRegistrationTable = {
        sizeof(FLT_REGISTRATION),      //  Size
        FLT_REGISTRATION_VERSION,      //  Version
        0,                             //  Flags
        nullptr,                       //  Context
        Callbacks,                     //  Operation callbacks
        MinifilterDriverUnload,        //  MiniFilterUnload
        MinifilterDriverInstanceSetup, //  InstanceSetup
        nullptr,                       //  InstanceQueryTeardown
        nullptr,                       //  InstanceTeardownStart
        nullptr,                       //  InstanceTeardownComplete
        nullptr,                       //  GenerateFileName
        nullptr,                       //  GenerateDestinationFileName
        nullptr                        //  NormalizeNameComponent
    };

    void
    Cleanup()
    {
        Utils::KLock ScopedLock {ContextLock};

        if ( CommunicationServerPort )
        {
            ::FltCloseCommunicationPort(CommunicationServerPort);
            CommunicationServerPort = nullptr;
        }

        if ( CommunicationClientPorts[0] )
        {
            ::FltCloseCommunicationPort(CommunicationClientPorts[0]);
            CommunicationClientPorts[0] = nullptr;
        }

        if ( FilterHandle )
        {
            ::FltUnregisterFilter(FilterHandle);
            FilterHandle = nullptr;
        }

        ok(L"Context cleanup ok");
    }

    static void*
    operator new(usize sz)
    {
        void* Memory = ::ExAllocatePoolWithTag(NonPagedPoolNx, sz, DRIVER_CONTEXT_TAG);
        if ( Memory )
        {
            dbg(L"Allocated GlobalContext at %p", Memory);
            ::RtlSecureZeroMemory(Memory, sz);
        }
        return Memory;
    }

    static void
    operator delete(void* mem)
    {
        dbg(L"Deallocating GlobalContext at %p", mem);
        ::ExFreePoolWithTag(mem, DRIVER_CONTEXT_TAG);
        mem = nullptr;
        return;
    }
};

extern GlobalContext* Context;
