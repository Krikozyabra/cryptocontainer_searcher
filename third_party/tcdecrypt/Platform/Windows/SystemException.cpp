/*
 Windows backend for TrueCrypt::SystemException.
 Captures GetLastError() (instead of errno) and renders it with FormatMessageW.
*/

#include "Platform/Windows/System.h"
#include "Platform/SerializerFactory.h"
#include "Platform/SystemException.h"
#include "Platform/StringConverter.h"

namespace TrueCrypt
{
	SystemException::SystemException ()
		: ErrorCode (GetLastError())
	{
	}

	SystemException::SystemException (const string &message)
		: Exception (message), ErrorCode (GetLastError())
	{
	}

	SystemException::SystemException (const string &message, const string &subject)
		: Exception (message, StringConverter::ToWide (subject)), ErrorCode (GetLastError())
	{
	}

	SystemException::SystemException (const string &message, const wstring &subject)
		: Exception (message, subject), ErrorCode (GetLastError())
	{
	}

	void SystemException::Deserialize (shared_ptr <Stream> stream)
	{
		Exception::Deserialize (stream);
		Serializer sr (stream);
		sr.Deserialize ("ErrorCode", ErrorCode);
	}

	bool SystemException::IsError () const
	{
		return ErrorCode != 0;
	}

	void SystemException::Serialize (shared_ptr <Stream> stream) const
	{
		Exception::Serialize (stream);
		Serializer sr (stream);
		sr.Serialize ("ErrorCode", ErrorCode);
	}

	wstring SystemException::SystemText () const
	{
		wchar_t *buffer = nullptr;
		DWORD len = FormatMessageW (
			FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			nullptr, (DWORD) ErrorCode,
			MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPWSTR) &buffer, 0, nullptr);

		wstring text;
		if (len && buffer)
			text.assign (buffer, len);
		if (buffer)
			LocalFree (buffer);
		return text;
	}

#define TC_EXCEPTION(TYPE) TC_SERIALIZER_FACTORY_ADD(TYPE)
#undef TC_EXCEPTION_NODECL
#define TC_EXCEPTION_NODECL(TYPE) TC_SERIALIZER_FACTORY_ADD(TYPE)

	TC_SERIALIZER_FACTORY_ADD_EXCEPTION_SET (SystemException);
}
