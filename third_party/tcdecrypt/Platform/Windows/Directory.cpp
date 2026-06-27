/*
 Windows backend for TrueCrypt::Directory (FindFirstFile/FindNextFile).
 Enables directory-keyfile support on Windows.
*/

#include "Platform/Windows/System.h"
#include "Platform/Directory.h"
#include "Platform/SystemException.h"

namespace TrueCrypt
{
	void Directory::Create (const DirectoryPath &path)
	{
		wstring p = path;
		throw_sys_sub_if (CreateDirectoryW (p.c_str(), nullptr) == 0, p);
	}

	DirectoryPath Directory::AppendSeparator (const DirectoryPath &path)
	{
		wstring p (path);
		if (!p.empty())
		{
			wchar_t last = p[p.size() - 1];
			if (last != L'\\' && last != L'/')
				return p + L'\\';
		}
		return p;
	}

	FilePathList Directory::GetFilePaths (const DirectoryPath &path, bool regularFilesOnly)
	{
		wstring pattern = wstring (AppendSeparator (path)) + L"*";

		WIN32_FIND_DATAW fd;
		HANDLE h = FindFirstFileW (pattern.c_str(), &fd);
		throw_sys_sub_if (h == INVALID_HANDLE_VALUE, wstring (path));

		FilePathList files;
		do
		{
			if (wcscmp (fd.cFileName, L".") == 0 || wcscmp (fd.cFileName, L"..") == 0)
				continue;

			bool isDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
			if (regularFilesOnly && isDir)
				continue;

			files.push_back (shared_ptr <FilePath> (
				new FilePath (wstring (AppendSeparator (path)) + fd.cFileName)));
		}
		while (FindNextFileW (h, &fd));

		FindClose (h);
		return files;
	}
}
