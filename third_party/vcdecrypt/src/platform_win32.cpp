/*
 * Native Win32 implementations of the VeraCrypt Platform threading/sync
 * primitives (Mutex, SyncEvent, Thread) and SystemLog, for the standalone
 * vcdecrypt module. VeraCrypt's tree only ships Unix (pthread) implementations
 * of these; this file provides the Windows counterparts so the module builds
 * on Windows. It is compiled only on Windows (see CMakeLists.txt).
 *
 * The class layouts match Platform/Mutex.h, Platform/SyncEvent.h and
 * Platform/Thread.h (the TC_WINDOWS branch).
 *
 * Governed by the Apache License 2.0 (see License.txt).
 */

#include "Platform/Mutex.h"
#include "Platform/SyncEvent.h"
#include "Platform/Thread.h"
#include "Platform/SystemLog.h"
#include "Platform/SystemException.h"

#include <process.h>

namespace VeraCrypt
{
	// ----- Mutex (CRITICAL_SECTION) -----------------------------------------
	Mutex::Mutex ()
	{
		InitializeCriticalSection (&SystemMutex);
		Initialized = true;
	}

	Mutex::~Mutex ()
	{
		Initialized = false;
		DeleteCriticalSection (&SystemMutex);
	}

	void Mutex::Lock ()
	{
		EnterCriticalSection (&SystemMutex);
	}

	void Mutex::Unlock ()
	{
		LeaveCriticalSection (&SystemMutex);
	}

	// ----- SyncEvent (auto-reset event) -------------------------------------
	SyncEvent::SyncEvent ()
	{
		SystemSyncEvent = CreateEvent (nullptr, FALSE /* auto-reset */, FALSE, nullptr);
		if (SystemSyncEvent == nullptr)
			throw SystemException (SRC_POS, (uint64) GetLastError());
		Initialized = true;
	}

	SyncEvent::~SyncEvent ()
	{
		Initialized = false;
		if (SystemSyncEvent != nullptr)
			CloseHandle (SystemSyncEvent);
	}

	void SyncEvent::Reset ()
	{
		ResetEvent (SystemSyncEvent);
	}

	void SyncEvent::Signal ()
	{
		SetEvent (SystemSyncEvent);
	}

	void SyncEvent::Wait ()
	{
		if (WaitForSingleObject (SystemSyncEvent, INFINITE) != WAIT_OBJECT_0)
			throw SystemException (SRC_POS, (uint64) GetLastError());
	}

	// ----- Thread -----------------------------------------------------------
	void Thread::Start (ThreadProcPtr threadProc, void *parameter)
	{
		DWORD threadId;
		SystemHandle = CreateThread (nullptr, MinThreadStackSize, threadProc,
		                             parameter, 0, &threadId);
		if (SystemHandle == nullptr)
			throw SystemException (SRC_POS, (uint64) GetLastError());
	}

	void Thread::Join () const
	{
		WaitForSingleObject (SystemHandle, INFINITE);
		CloseHandle (SystemHandle);
	}

	void Thread::Detach () const
	{
		CloseHandle (SystemHandle);
	}

	void Thread::Sleep (uint32 milliSeconds)
	{
		::Sleep (milliSeconds);
	}

	// ----- SystemLog --------------------------------------------------------
	void SystemLog::WriteDebug (const string &debugMessage)
	{
		OutputDebugStringA ((debugMessage + "\n").c_str());
	}

	void SystemLog::WriteError (const string &errorMessage)
	{
		OutputDebugStringA ((string ("Error: ") + errorMessage + "\n").c_str());
	}
}
