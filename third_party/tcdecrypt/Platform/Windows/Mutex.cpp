/*
 Windows backend for TrueCrypt::Mutex — a recursive lock (the Unix version uses
 PTHREAD_MUTEX_RECURSIVE; CRITICAL_SECTION is recursive by default).
*/

#include "Platform/Windows/System.h"
#include "Platform/Mutex.h"

namespace TrueCrypt
{
	Mutex::Mutex ()
	{
		InitializeCriticalSection (&SystemMutex);
		Initialized = true;
	}

	Mutex::~Mutex ()
	{
		if (Initialized)
			DeleteCriticalSection (&SystemMutex);
		Initialized = false;
	}

	void Mutex::Lock ()
	{
		EnterCriticalSection (&SystemMutex);
	}

	void Mutex::Unlock ()
	{
		LeaveCriticalSection (&SystemMutex);
	}
}
