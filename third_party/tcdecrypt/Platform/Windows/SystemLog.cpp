/*
 Windows backend for TrueCrypt::SystemLog. Routes to OutputDebugString.
*/

#include "Platform/Windows/System.h"
#include "Platform/SystemLog.h"

namespace TrueCrypt
{
	void SystemLog::WriteDebug (const string &debugMessage)
	{
		OutputDebugStringA ((string ("TrueCrypt: ") + debugMessage + "\n").c_str());
	}

	void SystemLog::WriteError (const string &errorMessage)
	{
		OutputDebugStringA ((string ("TrueCrypt error: ") + errorMessage + "\n").c_str());
	}
}
