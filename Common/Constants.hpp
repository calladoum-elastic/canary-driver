#pragma once

#pragma region Ioctls
namespace Comms::Ioctl
{
const static inline UINT32 SetActivityEvent = 0x801;
const static inline UINT32 GetSuspendedPid  = 0x802;
} // namespace Comms::Ioctl
#pragma endregion


#pragma region Driver
#define DEVICE_NAME "MinifilterDriver"
#define DEVICE_NAME_WIDE L"MinifilterDriver"
#define PORT_PATH "\\" DEVICE_NAME
#define PORT_PATH_WIDE L"\\" DEVICE_NAME_WIDE
#define DEVICE_PATH_WIDE L"\\Device\\" DEVICE_NAME_WIDE
#define DOS_DEVICE_PATH_WIDE L"\\??\\" DEVICE_NAME_WIDE
#pragma endregion
