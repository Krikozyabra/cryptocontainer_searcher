/*
 Windows backend for TrueCrypt::FilesystemPath.

 GetType() drives IsFile()/IsDirectory()/IsDevice(), which Volume::Open and
 Keyfile consult. Device detection keys off the Windows raw-device prefixes
 (\\.\ and \\?\). ToHostDriveOfPartition() is whole-disk system-encryption
 only and is not reached for file-hosted volumes, so it throws NotImplemented.
*/

#include "Platform/Windows/System.h"
#include "Platform/FilesystemPath.h"
#include "Platform/SystemException.h"
#include "Platform/StringConverter.h"

namespace TrueCrypt
{
	void FilesystemPath::Delete () const
	{
		wstring p = Path;
		throw_sys_sub_if (DeleteFileW (p.c_str()) == 0, Path);
	}

	UserId FilesystemPath::GetOwner () const
	{
		// Windows has no POSIX uid; return a default-constructed owner.
		return UserId();
	}

	FilesystemPathType::Enum FilesystemPath::GetType () const
	{
		wstring path = Path;

		// Raw device paths (\\.\PhysicalDrive0, \\.\X:) — treat as block devices.
		if (path.compare (0, 4, L"\\\\.\\") == 0 || path.compare (0, 4, L"\\\\?\\") == 0)
			return FilesystemPathType::BlockDevice;

		DWORD attrs = GetFileAttributesW (path.c_str());
		throw_sys_sub_if (attrs == INVALID_FILE_ATTRIBUTES, Path);

		if (attrs & FILE_ATTRIBUTE_DIRECTORY)
			return FilesystemPathType::Directory;

		return FilesystemPathType::File;
	}

	FilesystemPath FilesystemPath::ToBaseName () const
	{
		wstring path = Path;
		size_t pos = path.find_last_of (L"\\/");
		if (pos == wstring::npos)
			return Path;
		return Path.substr (pos + 1);
	}

	FilesystemPath FilesystemPath::ToHostDriveOfPartition () const
	{
		throw NotImplemented (SRC_POS);
	}
}
