/*
 Windows backend for TrueCrypt::Time.
 GetCurrent() returns 100ns ticks since 1601-01-01 — which is exactly the
 Windows FILETIME epoch, so GetSystemTimeAsFileTime maps directly.
*/

#include "Platform/Windows/System.h"
#include "Platform/Time.h"

namespace TrueCrypt
{
	uint64 Time::GetCurrent ()
	{
		FILETIME ft;
		GetSystemTimeAsFileTime (&ft);
		return ((uint64) ft.dwHighDateTime << 32) | (uint64) ft.dwLowDateTime;
	}
}
