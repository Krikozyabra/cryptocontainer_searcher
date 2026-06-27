/*
 Windows backend for TrueCrypt::SystemInfo. Not on the decrypt path; minimal.
*/

#include "Platform/Windows/System.h"
#include "Platform/SystemInfo.h"

namespace TrueCrypt
{
	wstring SystemInfo::GetPlatformName ()
	{
		return L"Windows";
	}

	vector <int> SystemInfo::GetVersion ()
	{
		return vector <int> ();
	}

	bool SystemInfo::IsVersionAtLeast (int, int, int)
	{
		return true;
	}
}
