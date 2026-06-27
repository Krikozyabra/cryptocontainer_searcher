/*
 Windows backend for TrueCrypt::File.

 The cross-platform header (Platform/File.h) types the Windows file handle as
 FILE*, so this backend is implemented on top of the C stdio API (_wfopen,
 _fseeki64, fread/fwrite, _commit) — fully portable across MSVC and MinGW and
 sufficient for file-hosted volumes. Whole-disk/partition device access (sector
 size, partition start offset) is not supported here and throws NotImplemented;
 it is not exercised when decrypting a file container.
*/

#include <stdio.h>
#include <sys/stat.h>
#if defined(_MSC_VER) || defined(__MINGW32__)
#	include <io.h>   // _commit, _fileno   // <-- added
#endif
#include "Platform/Windows/System.h"
#include "Platform/File.h"

#if defined(_MSC_VER)
#	define TC_FSEEK  _fseeki64
#	define TC_FTELL  _ftelli64
#	define TC_FILENO _fileno
#	define TC_COMMIT _commit
#else
// MinGW provides these names.
#	define TC_FSEEK  fseeko64
#	define TC_FTELL  ftello64
#	define TC_FILENO fileno
#	define TC_COMMIT _commit
#endif

namespace TrueCrypt
{
	void File::Close ()
	{
		if_debug (ValidateState());

		if (!SharedHandle)
		{
			if (FileHandle != nullptr)
				fclose (FileHandle);
			FileHandle = nullptr;
			FileIsOpen = false;
		}
	}

	void File::Delete ()
	{
		Close();
		Path.Delete();
	}

	void File::Flush () const
	{
		if_debug (ValidateState());
		throw_sys_sub_if (fflush (FileHandle) != 0, wstring (Path));
		// Best-effort durability; ignore failures (e.g. read-only handles).
		TC_COMMIT (TC_FILENO (FileHandle));
	}

	uint32 File::GetDeviceSectorSize () const
	{
		// Raw device volumes are not supported by this file-stdio backend.
		throw NotImplemented (SRC_POS);
	}

	uint64 File::GetPartitionDeviceStartOffset () const
	{
		throw NotImplemented (SRC_POS);
	}

	uint64 File::Length () const
	{
		if_debug (ValidateState());

		int64 current = TC_FTELL (FileHandle);
		throw_sys_sub_if (current == -1, wstring (Path));
		throw_sys_sub_if (TC_FSEEK (FileHandle, 0, SEEK_END) != 0, wstring (Path));
		int64 length = TC_FTELL (FileHandle);
		throw_sys_sub_if (length == -1, wstring (Path));
		throw_sys_sub_if (TC_FSEEK (FileHandle, current, SEEK_SET) != 0, wstring (Path));
		return (uint64) length;
	}

	void File::Open (const FilePath &path, FileOpenMode mode, FileShareMode shareMode, FileOpenFlags flags)
	{
		const wchar_t *modeStr;
		switch (mode)
		{
		case CreateReadWrite: modeStr = L"w+b"; break;
		case CreateWrite:     modeStr = L"wb";  break;
		case OpenRead:        modeStr = L"rb";  break;
		case OpenWrite:       modeStr = L"r+b"; break; // open existing for writing
		case OpenReadWrite:   modeStr = L"r+b"; break;
		default:
			throw ParameterIncorrect (SRC_POS);
		}

		wstring wpath = path;
#if defined(_MSC_VER)
		FileHandle = _wfopen (wpath.c_str(), modeStr);
#else
		// MinGW: _wfopen is available via <wchar.h>/<stdio.h>.
		FileHandle = _wfopen (wpath.c_str(), modeStr);
#endif
		throw_sys_sub_if (FileHandle == nullptr, wstring (path));

		Path = path;
		mFileOpenFlags = flags;
		FileIsOpen = true;
		(void) shareMode; // sharing is handled by the OS default for stdio
	}

	uint64 File::Read (const BufferPtr &buffer) const
	{
		if_debug (ValidateState());
		size_t bytesRead = fread (buffer, 1, buffer.Size(), FileHandle);
		throw_sys_sub_if (bytesRead == 0 && ferror (FileHandle), wstring (Path));
		return bytesRead;
	}

	uint64 File::ReadAt (const BufferPtr &buffer, uint64 position) const
	{
		if_debug (ValidateState());
		SeekAt (position);
		return Read (buffer);
	}

	void File::SeekAt (uint64 position) const
	{
		if_debug (ValidateState());
		throw_sys_sub_if (TC_FSEEK (FileHandle, (int64) position, SEEK_SET) != 0, wstring (Path));
	}

	void File::SeekEnd (int offset) const
	{
		if_debug (ValidateState());
		throw_sys_sub_if (TC_FSEEK (FileHandle, (int64) offset, SEEK_END) != 0, wstring (Path));
	}

	void File::Write (const ConstBufferPtr &buffer) const
	{
		if_debug (ValidateState());
		throw_sys_sub_if (fwrite (buffer, 1, buffer.Size(), FileHandle) != buffer.Size(), wstring (Path));
	}

	void File::WriteAt (const ConstBufferPtr &buffer, uint64 position) const
	{
		if_debug (ValidateState());
		SeekAt (position);
		Write (buffer);
	}
}
