/*
 Windows backend for TrueCrypt::Thread (CreateThread / WaitForSingleObject).
 Only used if the encryption thread pool is started; the read-only decrypt path
 runs single-threaded and never reaches these.
*/

#include "Platform/Windows/System.h"
#include "Platform/Thread.h"
#include "Platform/SystemException.h"

namespace TrueCrypt
{
	void Thread::Start (ThreadProcPtr threadProc, void *parameter)
	{
		SystemHandle = CreateThread (nullptr, MinThreadStackSize, threadProc, parameter, 0, nullptr);
		throw_sys_if (SystemHandle == nullptr);
	}

	void Thread::Join () const
	{
		WaitForSingleObject (SystemHandle, INFINITE);
		CloseHandle (SystemHandle);
	}

	void Thread::Sleep (uint32 milliSeconds)
	{
		::Sleep (milliSeconds);
	}
}
