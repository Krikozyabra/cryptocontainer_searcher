/*
 Windows backend for TrueCrypt::SyncEvent — an auto-reset event.
 (Header stores a single HANDLE SystemSyncEvent under TC_WINDOWS.)
*/

#include "Platform/Windows/System.h"
#include "Platform/SyncEvent.h"
#include "Platform/SystemException.h"

namespace TrueCrypt
{
	SyncEvent::SyncEvent ()
	{
		// auto-reset, initially non-signaled
		SystemSyncEvent = CreateEventW (nullptr, FALSE, FALSE, nullptr);
		throw_sys_if (SystemSyncEvent == nullptr);
		Initialized = true;
	}

	SyncEvent::~SyncEvent ()
	{
		if (Initialized)
			CloseHandle (SystemSyncEvent);
		Initialized = false;
	}

	void SyncEvent::Signal ()
	{
		SetEvent (SystemSyncEvent);
	}

	void SyncEvent::Wait ()
	{
		throw_sys_if (WaitForSingleObject (SystemSyncEvent, INFINITE) != WAIT_OBJECT_0);
	}
}
