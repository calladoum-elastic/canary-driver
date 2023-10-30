// clang-format off
#include <windows.h>
#include <minidumpapiset.h>

#include <stdio.h>

#include <algorithm>
#include <string>
#include <iostream>
#include <vector>
#include <filesystem>
// clang-format on

#include "../Common/Constants.hpp"
#include "Resource.h"
#include "wil/resource.h"


#ifdef _DEBUG
#define dbg(fmt, ...) ::wprintf(L"[=] " fmt L"\n", __VA_ARGS__)
#else
#define dbg(fmt, ...)
#endif // _DEBUG

#define ok(fmt, ...) ::wprintf(L"[+] " fmt L"\n", __VA_ARGS__)
#define info(fmt, ...) ::wprintf(L"[*] " fmt L"\n", __VA_ARGS__)
#define warn(fmt, ...) ::wprintf(L"[!] " fmt L"\n", __VA_ARGS__)
#define err(fmt, ...) ::wprintf(L"[-] " fmt L"\n", __VA_ARGS__)
#define perror(x) err(L"%s failed with Status=0x%lx", x, ::GetLastError())


auto GenerateRandomString = [](const size_t len) -> std::wstring
{
    std::wstring out;
    out.resize(len);
    const static std::wstring_view charset = L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::srand(::time(nullptr));
    for ( auto i = 0; i < len; i++ )
    {
        out[i] = charset[std::rand() % charset.length()];
    }
    return out;
};

struct GlobalContext
{
    const std::wstring ServiceName {L"MinifilterDriver"};
    const std::wstring ServiceDescription {L"MinifilterDriver"};
    std::filesystem::path DriverInfTempPath {std::filesystem::temp_directory_path() / L"MinifilterDriver.inf"};
    std::filesystem::path DriverTempPath {std::filesystem::temp_directory_path() / L"MinifilterDriver.sys"};
    wil::unique_schandle hSCManager;
    wil::unique_schandle hService;
    wil::unique_handle hActivityEvent {::CreateEventW(nullptr, true, false, nullptr)};
    wil::unique_handle hDevice;

    GlobalContext() = default;
} Context;


namespace Driver
{
bool
Extract()
{
    dbg(L"Extracting driver from resources...");

    HRSRC DriverRsc = ::FindResourceW(nullptr, MAKEINTRESOURCEW(IDR_DRIVER), MAKEINTRESOURCEW(DRIVER_DATAFILE));
    if ( !DriverRsc )
    {
        perror(L"FindResource()");
        return false;
    }

    DWORD dwDriverSize = ::SizeofResource(nullptr, DriverRsc);
    if ( !dwDriverSize )
    {
        perror(L"SizeofResource()");
        return false;
    }

    HGLOBAL hgDriverRsc = ::LoadResource(nullptr, DriverRsc);
    if ( !hgDriverRsc )
    {
        perror(L"LoadResource()");
        return false;
    }

    info(L"Driver extracted to '%s'", Context.DriverTempPath.wstring().c_str());

    // replace with InstallHinfSection
    // RUNDLL32.EXE SETUPAPI.DLL,InstallHinfSection DefaultInstall 132 c:\users\user\desktop\minifilterdriver.inf

    wil::unique_handle hDriverFile(::CreateFileW(
        Context.DriverTempPath.wstring().c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));
    if ( !hDriverFile )
    {
        perror(L"CreateFile()");
        return false;
    }

    DWORD dwWritten;
    if ( !::WriteFile(hDriverFile.get(), hgDriverRsc, dwDriverSize, &dwWritten, nullptr) )
    {
        perror(L"WriteFile()");
        return false;
    }

    if ( dwWritten != dwDriverSize )
    {
        err(L"Incomplete driver file dump");
        return false;
    }

    dbg(L"Driver written in '%s'", Context.DriverTempPath.wstring().c_str());
    return true;
}


bool
Load()
{
    dbg(L"Loading driver '%s'", Context.DriverTempPath.c_str());

    //
    // Get a handle to the service control manager
    //
    {
        wil::unique_schandle hSCManager(::OpenSCManagerW(L"", SERVICES_ACTIVE_DATABASEW, SC_MANAGER_CREATE_SERVICE));
        if ( !hSCManager )
        {
            perror(L"OpenSCManager()");
            return false;
        }

        Context.hSCManager = std::move(hSCManager);
    }

    //
    // Get a handle to the service
    //
    {
        wil::unique_schandle hServiceCreate(::CreateServiceW(
            Context.hSCManager.get(),
            Context.ServiceName.c_str(),
            Context.ServiceDescription.c_str(),
            SERVICE_START | DELETE | SERVICE_STOP,
            SERVICE_FILE_SYSTEM_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_IGNORE,
            Context.DriverTempPath.c_str(),
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr));
        if ( !hServiceCreate )
        {
            if ( ::GetLastError() != ERROR_SERVICE_EXISTS )
            {
                //
                // Failure can mean the service already registered, if so just open it simply get a handle to it
                //
                perror(L"CreateService()");
                return false;
            }

            //
            // Try to open the service instead
            //
            wil::unique_schandle hServiceOpen(::OpenServiceW(
                Context.hSCManager.get(),
                Context.ServiceName.c_str(),
                SERVICE_START | DELETE | SERVICE_STOP));
            {
                if ( !hServiceOpen )
                {
                    perror(L"OpenService()");
                    return false;
                }
            }
            Context.hService = std::move(hServiceOpen);
        }
        else
        {
            Context.hService = std::move(hServiceCreate);
        }
    }

    if ( !Context.hService )
    {
        err(L"nope");
        return false;
    }

    //
    // Start the service
    //
    dbg(L"Starting service '%s'", Context.ServiceName.c_str());

    if ( !::StartServiceW(Context.hService.get(), 0, nullptr) )
    {
        perror(L"StartService()");
        return false;
    }

    ok(L"Service '%s' started successfully.", Context.ServiceName.c_str());
    return true;
}


bool
Open()
{
    wil::unique_handle hFile {::CreateFileW(
        L"\\\\.\\" DEVICE_NAME_WIDE,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr)};
    if ( !hFile )
    {
        return false;
    }

    Context.hDevice = std::move(hFile);
    return true;
}

bool
Ioctl(ULONG Code, PVOID InputData, size_t InputDataLength, PVOID OutputData = nullptr, size_t OutputDataLength = 0)
{
    DWORD dwBytesReturned {0};
    return ::DeviceIoControl(
        Context.hDevice.get(),
        Code,
        InputData,
        InputDataLength,
        OutputData,
        OutputDataLength,
        &dwBytesReturned,
        (LPOVERLAPPED) nullptr);
}
} // namespace Driver


int
MainLoop()
{
    // TODO ctrl-c handler

    while ( true )
    {

        //
        // Wait for an event
        //
        ::WaitForSingleObject(Context.hActivityEvent.get(), INFINITE);

        //
        // Get the pid
        //
        ULONG Pid {0};
        if ( !Driver::Ioctl(IOCTL_GET_SUSPENDED_PROCESS_ID, nullptr, 0, &Pid, sizeof(Pid)) )
        {
            continue;
        }

        //
        // Mem dump the process
        //
        wil::unique_handle hProcess {
            ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE, false, Pid)};
        if ( !hProcess )
        {
            perror(L"OpenProcess()");
            continue;
        }


        const std::wstring DumpFilePath {std::filesystem::temp_directory_path() / (GenerateRandomString(12) + L".dmp")};
        wil::unique_handle hDumpFile {::CreateFileW(
            DumpFilePath.c_str(),
            GENERIC_ALL,
            FILE_SHARE_READ,
            nullptr,
            FILE_ATTRIBUTE_NORMAL,
            CREATE_ALWAYS,
            nullptr)};

        MINIDUMP_EXCEPTION_INFORMATION ExceptionParam {};
        MINIDUMP_USER_STREAM_INFORMATION UserStreamParam {};

        if ( ::MiniDumpWriteDump(
                 hProcess.get(),
                 Pid,
                 hDumpFile.get(),
                 (MINIDUMP_TYPE)(MINIDUMP_TYPE::MiniDumpNormal | MINIDUMP_TYPE::MiniDumpWithDataSegs |
                                 MINIDUMP_TYPE::MiniDumpWithHandleData | MINIDUMP_TYPE::MiniDumpWithFullMemory),
                 &ExceptionParam,
                 &UserStreamParam,
                 nullptr) )
        {
            perror(L"MiniDumpWriteDump()");
        }
        else
        {
            ok(L"Successfully dumped PID=%lu into '%s'", Pid, DumpFilePath.c_str());
        }
    }

    return 0;
}


int
wmain(int argc, const wchar_t* argv)
{

    if ( !Driver::Extract() )
    {
        err(L"Driver extraction failed");
        return -1;
    }

    if ( !Driver::Load() )
    {
        err(L"Driver loading failed");
        return -1;
    }

    if ( !Driver::Open() )
    {
        err(L"Driver open failed");
        return -1;
    }

    if ( !Driver::Ioctl(IOCTL_SET_ACTIVITY_EVENT_VALUE, Context.hActivityEvent.addressof(), sizeof(HANDLE)) )
    {
        err(L"Driver ioctl failed");
        return -1;
    }

    return MainLoop();
}
