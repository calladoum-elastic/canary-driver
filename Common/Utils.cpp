#pragma once

#include "Utils.hpp"

#include "Log.hpp"


Utils::KMutex::KMutex()
{
    dbg(L"KMutex::Init(%p)", &m_Mutex);
    ::KeInitializeMutex(&m_Mutex, 0);
}


void
Utils::KMutex::Lock()
{
    dbg(L"KMutex::Locking(%p)", &m_Mutex);
    ::KeWaitForSingleObject(&m_Mutex, Executive, KernelMode, false, nullptr);
    dbg(L"KMutex::Locked(%p)", &m_Mutex);
}


void
Utils::KMutex::Unlock()
{
    dbg(L"KMutex::Unlocking(%p)", &m_Mutex);
    if ( !::KeReleaseMutex(&m_Mutex, true) )
    {
        ::KeWaitForSingleObject(&m_Mutex, Executive, KernelMode, false, nullptr);
    }
    dbg(L"KMutex::Unlocked(%p)", &m_Mutex);
}


Utils::KQueuedSpinLock::KQueuedSpinLock()
{
    ::KeInitializeSpinLock(&m_SpinLock);
}


Utils::KQueuedSpinLock::~KQueuedSpinLock()
{
}


void
Utils::KQueuedSpinLock::Lock()
{
    ::KeAcquireInStackQueuedSpinLock(&m_SpinLock, &m_LockQueueHandle);
}


void
Utils::KQueuedSpinLock::Unlock()
{
    ::KeReleaseInStackQueuedSpinLock(&m_LockQueueHandle);
}
