/*
 Copyright (c) 2008-2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Platform_PlatformBase
#define TC_HEADER_Platform_PlatformBase

#include <cstddef>
#include <list>
#include <algorithm>
#include <list>
#include <locale>
#include <map>
#include <memory>
#include <new>
#include <sstream>
#include <stdexcept>
#include <string>
#include <typeinfo>
#include <vector>

#ifndef _MSC_VER
#include <inttypes.h>
#endif

// NOTE: a blanket `using namespace std;` was used here originally. Under C++17
// that drags `std::byte` into the global namespace, which then clashes with
// TrueCrypt's own global `byte` typedef (defined below / in Common/Tcdefs.h),
// making the bare name `byte` ambiguous across the whole crypto codebase.
// Import only the std names the code actually relies on instead — notably
// *excluding* `byte` — so the build is C++17-clean without touching every
// crypto header.
using std::string;
using std::wstring;
using std::vector;
using std::list;
using std::map;
using std::pair;
using std::make_pair;
using std::shared_ptr;
using std::stringstream;
using std::wstringstream;
using std::istringstream;
using std::ostringstream;
using std::wistringstream;
using std::wostringstream;
using std::exception;
using std::runtime_error;
using std::type_info;
using std::bad_alloc;
using std::locale;
using std::min;
using std::max;
using std::swap;
using std::find;
using std::sort;

#ifdef nullptr
#undef nullptr
#endif

#if !(defined(_MSC_VER) && _MSC_VER >= 1600)
#define nullptr 0
#endif

namespace TrueCrypt
{
#ifdef _MSC_VER
#	ifndef TC_INT_TYPES_DEFINED
	typedef __int8 int8;
	typedef __int16 int16;
	typedef __int32 int32;
	typedef __int64 int64;
	typedef unsigned __int8 byte;
	typedef unsigned __int16 uint16;
	typedef unsigned __int32 uint32;
	typedef unsigned __int64 uint64;
#	endif
#else
	typedef int8_t int8;
	typedef int16_t int16;
	typedef int32_t int32;
	typedef int64_t int64;
	typedef uint8_t byte;
	typedef uint16_t uint16;
	typedef uint32_t uint32;
	typedef uint64_t uint64;
#endif

	// std::auto_ptr was removed in C++17. The Volume code uses a handful of
	// auto_ptr instances with classic transfer-of-ownership-on-copy semantics
	// (e.g. EncryptionThreadPool). Provide a minimal, behaviour-compatible
	// replacement in the TrueCrypt namespace so those translation units build
	// under C++17 without a wider rewrite. Move-on-copy is exactly the legacy
	// auto_ptr contract those call sites rely on.
	template <class T>
	class auto_ptr
	{
	public:
		explicit auto_ptr (T *p = nullptr) : Ptr (p) { }
		auto_ptr (auto_ptr &other) : Ptr (other.release()) { }
		template <class U> auto_ptr (auto_ptr <U> &other) : Ptr (other.release()) { }
		~auto_ptr () { delete Ptr; }

		auto_ptr &operator= (auto_ptr &other) { reset (other.release()); return *this; }
		template <class U> auto_ptr &operator= (auto_ptr <U> &other) { reset (other.release()); return *this; }

		T &operator* () const { return *Ptr; }
		T *operator-> () const { return Ptr; }
		T *get () const { return Ptr; }

		T *release () { T *p = Ptr; Ptr = nullptr; return p; }
		void reset (T *p = nullptr) { if (Ptr != p) { delete Ptr; Ptr = p; } }

	private:
		T *Ptr;
	};
}

#if (defined(_WIN32) || defined(_WIN64)) && !defined(TC_WINDOWS)
#	define TC_WINDOWS
#endif

#if defined(_DEBUG) && !defined(DEBUG)
#	define DEBUG
#endif

#ifndef TC_TO_STRING
#	define TC_TO_STRING2(n) #n
#	define TC_TO_STRING(n) TC_TO_STRING2(n)
#endif

#define TC_JOIN_ARGS(a,b) a##b
#define TC_JOIN(a,b) TC_JOIN_ARGS(a,b)

#ifdef __GNUC__
	template <class T> string GetFunctionName (T pos)
	{
		string s (pos);
		size_t p = s.find ('(');
		if (p == string::npos)
			return s;
		s = s.substr (0, p);
		p = s.find_last_of (" ");
		if (p == string::npos)
			return s;
		return s.substr (p + 1);
	}
#	define SRC_POS (GetFunctionName (__PRETTY_FUNCTION__) += ":" TC_TO_STRING(__LINE__))
#	define TC_UNUSED_VAR __attribute__ ((unused))
#else
#	define SRC_POS (__FUNCTION__ ":" TC_TO_STRING(__LINE__))
#	define TC_UNUSED_VAR
#endif

#ifdef trace_point
#	undef trace_point
#endif

#ifdef trace_msg
#	undef trace_msg
#endif

#ifdef DEBUG
#	define if_debug(...) __VA_ARGS__

#	ifdef TC_WINDOWS
#		define trace_point OutputDebugStringA ((string (SRC_POS) + "\n").c_str())
#		define trace_msg(stream_args) do { stringstream s; s << (SRC_POS) << ": " << stream_args << endl; OutputDebugStringA (s.str().c_str()); } while (0)
#		define trace_msgw(stream_args) do { wstringstream s; s << (SRC_POS) << L": " << stream_args << endl; OutputDebugStringW (s.str().c_str()); } while (0)
#	else
#		include <iostream>
#		define trace_point cerr << (SRC_POS) << endl
#		define trace_msg(stream_args) cerr << (SRC_POS) << ": " << stream_args << endl
#		define trace_msgw(stream_args) cerr << (SRC_POS); wcerr << L": " << stream_args << endl
#	endif

#	include "Platform/SystemLog.h"
#	define trace_log_point SystemLog::WriteError (SRC_POS)
#	define trace_log_msg(stream_args) do { stringstream s; s << (SRC_POS) << ": " << stream_args; SystemLog::WriteError (s.str()); } while (0)

#else
#	define if_debug(...)
#	define trace_point
#	define trace_msg(...)
#	define trace_msgw(...)
#	define trace_log_point
#	define trace_log_msg(...)
#endif

#define trace_val(VAL) trace_msg (#VAL << '=' << (VAL));

#define array_capacity(arr) (sizeof (arr) / sizeof ((arr)[0]))

#endif // TC_HEADER_Platform_PlatformBase
