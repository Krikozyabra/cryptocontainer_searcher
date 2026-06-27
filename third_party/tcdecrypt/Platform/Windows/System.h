/*
 Windows backend for the TrueCrypt cross-platform Platform/ layer.

 Platform/System.h includes this file under TC_WINDOWS (so Thread.h, Mutex.h and
 SyncEvent.h can reference HANDLE / CRITICAL_SECTION / WINAPI). It wraps
 <windows.h> and tames the macros that collide with the portable C++ code
 (notably min/max, which break <algorithm>, and a few others).
*/

#ifndef TC_HEADER_Platform_Windows_System
#define TC_HEADER_Platform_Windows_System

#ifndef WIN32_LEAN_AND_MEAN
#	define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#	define NOMINMAX            // keep std::min / std::max usable
#endif

#include <windows.h>

// <windows.h> defines these as macros; the TrueCrypt sources use the same
// identifiers as ordinary names. Undefine them so the C++ code compiles.
#ifdef min
#	undef min
#endif
#ifdef max
#	undef max
#endif
#ifdef Yield
#	undef Yield
#endif
#ifdef GetObject
#	undef GetObject
#endif

#endif // TC_HEADER_Platform_Windows_System
