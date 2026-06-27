/*
 Minimal SecurityToken stub for tcdecrypt.

 The real Common/SecurityToken.h drags in the full PKCS#11 smartcard stack.
 The Volume library only touches it in Keyfile.cpp to (a) ask whether a keyfile
 path refers to a security-token-hosted keyfile and (b) read such a keyfile's
 bytes. For a minimal file-keyfile-only decryptor we stub both: paths are never
 token paths, so plain files are always used.

 This header is on the include path *before* the real Common/, so it shadows it.
*/

#ifndef TC_HEADER_Common_SecurityToken_STUB
#define TC_HEADER_Common_SecurityToken_STUB

#include <string>
#include <vector>
#include "Platform/PlatformBase.h"

namespace TrueCrypt
{
	struct SecurityTokenKeyfile
	{
		SecurityTokenKeyfile () { }
		SecurityTokenKeyfile (const std::wstring &) { }
	};

	class SecurityToken
	{
	public:
		static bool IsKeyfilePathValid (const std::wstring &securityTokenKeyfilePath)
		{
			(void) securityTokenKeyfilePath;
			return false;
		}

		static void GetKeyfileData (const SecurityTokenKeyfile &keyfile, std::vector <byte> &keyfileData)
		{
			(void) keyfile;
			(void) keyfileData;
			// Never reached: IsKeyfilePathValid() always returns false.
		}
	};
}

#endif
