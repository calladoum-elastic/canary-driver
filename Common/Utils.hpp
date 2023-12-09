#pragma once

#include <ntddk.h>

#include "../Common/Log.hpp"

//
// Types
//

///
/// Static types
///
using u8  = UINT8;
using u16 = UINT16;
using u32 = UINT32;
using u64 = UINT64;

using i8  = INT8;
using i16 = INT16;
using i32 = INT32;
using i64 = INT64;

using usize = size_t;
using uptr  = ULONG_PTR;

#ifndef countof
#define countof(arr) ((sizeof(arr)) / (sizeof(arr[0])))
#endif


///
/// Compile-time types
///
template<typename C, usize S = sizeof(C)>
class GenericBuffer
{
public:
    constexpr GenericBuffer(const C* str) noexcept
    {
        auto i       = 0;
        const C* ptr = str;
        for ( ptr = str, i = 0; i < S + 1; i++ )
        {
            m_buffer[i] = ptr[i];
        }
    }

    constexpr usize
    size() const noexcept
    {
        return m_size;
    }

    constexpr
    operator C*() noexcept
    {
        return m_buffer;
    }

    constexpr
    operator const C*() const noexcept
    {
        return m_buffer;
    }

    const C*
    get() const noexcept
    {
        return m_buffer;
    }


private:
    C m_buffer[S + 1] = {0};
    usize m_size      = S;
};

using basic_string  = GenericBuffer<char>;
using basic_wstring = GenericBuffer<wchar_t>;


namespace Utils
{

template<typename T>
class KLock
{
public:
    KLock(T& lock) : m_Lock(lock)
    {
        m_Lock.Lock();
    }

    ~KLock()
    {
        m_Lock.Unlock();
    }

private:
    T& m_Lock;
};


class KQueuedSpinLock
{
public:
    KQueuedSpinLock()
    {
        KeInitializeSpinLock(&m_SpinLock);
    }

    ~KQueuedSpinLock()
    {
    }

    void
    Lock()
    {
        ::KeAcquireInStackQueuedSpinLock(&m_SpinLock, &m_LockQueueHandle);
    }

    void
    Unlock()
    {
        ::KeReleaseInStackQueuedSpinLock(&m_LockQueueHandle);
    }

private:
    KSPIN_LOCK m_SpinLock                = 0;
    KLOCK_QUEUE_HANDLE m_LockQueueHandle = {0};
};

} // namespace Utils
