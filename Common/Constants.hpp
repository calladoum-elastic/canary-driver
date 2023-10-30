#pragma once

#pragma region Ioctls
#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) (                 \
               ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method)
#endif // CTL_CODE

#define IOCTL_SET_ACTIVITY_EVENT_VALUE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_SUSPENDED_PROCESS_ID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#pragma endregion


#pragma region Driver
#define DEVICE_NAME "MinifilterDriver"
#define DEVICE_NAME_WIDE L"MinifilterDriver"
#define DEVICE_PATH_WIDE L"\\Device\\" DEVICE_NAME_WIDE
#define DOS_DEVICE_PATH_WIDE L"\\??\\" DEVICE_NAME_WIDE
#pragma endregion
