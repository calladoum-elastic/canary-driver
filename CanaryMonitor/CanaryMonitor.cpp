// clang-format off
#include "Common.hpp"

#include <minidumpapiset.h>
#include <fltuser.h>
#include <ConsoleApi.h>

#include <stdio.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <iostream>
#include <tuple>
#include <string>
#include <vector>

#include <wil/resource.h>
// clang-format on

#include "../Common/Constants.hpp"
#include "Resource.h"

#define dbg(fmt, ...) ::wprintf(L"[=] " fmt L"\n", __VA_ARGS__)
#define ok(fmt, ...) ::wprintf(L"[+] " fmt L"\n", __VA_ARGS__)
#define info(fmt, ...) ::wprintf(L"[*] " fmt L"\n", __VA_ARGS__)
#define warn(fmt, ...) ::wprintf(L"[!] " fmt L"\n", __VA_ARGS__)
#define err(fmt, ...) ::wprintf(L"[-] " fmt L"\n", __VA_ARGS__)
#define perror(x) err(L"%s failed with Status=0x%lx", x, ::GetLastError())

const static std::wstring DumpPrefix = L"CanaryMonitor_";

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
    wil::unique_handle hShutdownEvent {::CreateEventW(nullptr, true, false, nullptr)};
    wil::unique_handle hPort;

    GlobalContext() = default;

    ~GlobalContext();

} Context;


namespace Driver
{
bool
Extract()
{
    dbg(L"Extracting driver from resources...");

    const std::array<std::tuple<int, int, std::filesystem::path&>, 2> Resources = {{
        {IDR_DRIVER, DRIVER_DATAFILE, Context.DriverTempPath},
        {IDR_DRIVER_INF, DRIVER_DATAFILE_INF, Context.DriverInfTempPath},
    }};

    for ( auto const& [i, j, path] : Resources )
    {
        HRSRC hrRsc = ::FindResourceW(nullptr, MAKEINTRESOURCEW(i), MAKEINTRESOURCEW(j));
        if ( !hrRsc )
        {
            perror(L"FindResource()");
            return false;
        }

        DWORD dwRsrcSize = ::SizeofResource(nullptr, hrRsc);
        if ( !dwRsrcSize )
        {
            perror(L"SizeofResource()");
            return false;
        }

        HGLOBAL hgRsc = ::LoadResource(nullptr, hrRsc);
        if ( !hgRsc )
        {
            perror(L"LoadResource()");
            return false;
        }

        ok(L"Resource %d extracted", i);

        // TODO huge race here but osef

        wil::unique_handle hDriverFile(::CreateFileW(
            path.wstring().c_str(),
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
        if ( !::WriteFile(hDriverFile.get(), hgRsc, dwRsrcSize, &dwWritten, nullptr) )
        {
            perror(L"WriteFile()");
            return false;
        }

        if ( dwWritten != dwRsrcSize )
        {
            err(L"Incomplete file write");
            return false;
        }

        dbg(L"File written to '%s'", path.wstring().c_str());
    }

    return true;
}

bool
Install()
{
    dbg(L"Installing FsDriver '%s'", Context.DriverInfTempPath.wstring().c_str());

    const std::wstring path =
        std::format(L"syssetup,SetupInfObjectInstallAction DefaultInstall 128 {}", Context.DriverInfTempPath.wstring());

    ::ShellExecuteW(nullptr, L"open", L"c:\\windows\\system32\\rundll32.exe", path.c_str(), nullptr, SW_HIDE);

    ::Sleep(500);
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
            if ( !hServiceOpen )
            {
                perror(L"OpenService()");
                return false;
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
    wil::unique_handle hPort {[&]()
                              {
                                  HANDLE port {nullptr};
                                  auto hRes =
                                      ::FilterConnectCommunicationPort(PORT_PATH_WIDE, 0, nullptr, 0, nullptr, &port);
                                  return (hRes != S_OK) ? nullptr : port;
                              }()};
    if ( !hPort )
    {
        perror(L"FilterConnectCommunicationPort()");
        return false;
    }

    ok(L"CommPort open as %p", hPort.get());
    Context.hPort = std::move(hPort);
    return true;
}

bool
Ioctl(UINT32 Code, PVOID InputData, DWORD InputDataLength, PVOID OutputData = nullptr, size_t OutputDataLength = 0)
{
    u32 MessageSize = InputDataLength + sizeof(UINT32);
    auto Message    = std::make_unique<u8[]>(MessageSize);
    ::memset(Message.get(), 0, MessageSize);
    ::memcpy(Message.get(), &Code, sizeof(UINT32));
    if ( InputDataLength )
        ::memcpy(Message.get() + sizeof(UINT32), InputData, InputDataLength);

    DWORD dwBytesReturned {0};
    auto hRes = ::FilterSendMessage(
        Context.hPort.get(),
        Message.get(),
        MessageSize,
        OutputData,
        OutputDataLength,
        &dwBytesReturned);
    if ( hRes != S_OK )
    {
        err(L"FilterSendMessage() failed with %08x", hRes);
        return false;
    }

    return true;
}


bool
Uninstall()
{
    SERVICE_STATUS ServiceStatus {};
    return TRUE == ::ControlService(Context.hService.get(), SERVICE_CONTROL_STOP, &ServiceStatus);
}

} // namespace Driver

GlobalContext::~GlobalContext()
{
    if ( hService )
    {
        dbg("Stopping driver");
        if ( !Driver::Uninstall() )
        {
            err(L"Failed to uninstall");
        }
    }
}

BOOL
HandlerRoutine(DWORD CtrlType)
{
    switch ( CtrlType )
    {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
        break;

    default:
        err(L"Unknown CtrlType=%x", CtrlType);
        return FALSE;
    }

    dbg(L"Received ShutDown event");
    if ( !::SetEvent(Context.hShutdownEvent.get()) )
    {
        perror(L"SetEvent()");
    }

    return TRUE;
}


int
MainLoop()
{
    info(L"Starting main loop...");

    const std::array Handles {
        Context.hShutdownEvent.get(),
        Context.hActivityEvent.get(),
    };

    while ( true )
    {
        //
        // Wait for an event
        //
        dbg(L"Waiting for event");
        DWORD dwRes = ::WaitForMultipleObjects(Handles.size(), Handles.data(), false, INFINITE) - WAIT_OBJECT_0;
        switch ( dwRes )
        {
        case WAIT_TIMEOUT:
        case WAIT_FAILED:
            err(L"Received event=%x, leaving", dwRes);
            return -1;
        case 0:
            ok(L"Received termination event");
            return 0;
        default:
            break;
        }

        ok(L"Received activity event");

        //
        // Reset the event
        //
        ::ResetEvent(Context.hActivityEvent.get());

        //
        // Get the culprit pid
        //
        ULONG Pid {0};
        if ( !Driver::Ioctl(Comms::Ioctl::GetSuspendedPid, nullptr, 0, &Pid, sizeof(Pid)) )
        {
            continue;
        }

        ok(L"Suspended Target PID = %#x", Pid);

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

        const std::wstring DumpFilePath {
            std::filesystem::temp_directory_path() / (DumpPrefix + GenerateRandomString(12) + L".dmp")};
        wil::unique_handle hDumpFile {::CreateFileW(
            DumpFilePath.c_str(),
            GENERIC_WRITE,
            0,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr)};
        if ( !hDumpFile )
        {
            perror(L"CreateFileW()");
            continue;
        }

        MINIDUMP_EXCEPTION_INFORMATION ExceptionParam {};
        MINIDUMP_USER_STREAM_INFORMATION UserStreamParam {};

        if ( !::MiniDumpWriteDump(
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
            continue;
        }

        ok(L"Successfully dumped PID=%lu into '%s'", Pid, DumpFilePath.c_str());
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

    if ( !Driver::Install() )
    {
        err(L"Driver installation failed");
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

    if ( !Driver::Ioctl(Comms::Ioctl::SetActivityEvent, Context.hActivityEvent.addressof(), sizeof(HANDLE)) )
    {
        err(L"Driver ioctl failed");
        return -1;
    }

    ok(L"Handshake with driver done...");

    if ( !::SetConsoleCtrlHandler((PHANDLER_ROUTINE)HandlerRoutine, true) )
    {
        perror(L"SetConsoleCtrlHandler()");
        return -1;
    }

    auto bRes = MainLoop();

    if ( !::SetConsoleCtrlHandler((PHANDLER_ROUTINE)HandlerRoutine, false) )
    {
        perror(L"SetConsoleCtrlHandler()");
    }

    return bRes;
}
