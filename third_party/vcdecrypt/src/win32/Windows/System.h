/*
 * Minimal Windows platform header for vcdecrypt.
 *
 * VeraCrypt's Platform/System.h includes "Windows/System.h", which is part of
 * VeraCrypt's (not-shipped-here) Windows app tree. For the standalone vcdecrypt
 * module we only need <windows.h> for the CRITICAL_SECTION / HANDLE / thread
 * primitives referenced by Mutex.h, SyncEvent.h and Thread.h. This header is
 * placed on the include path only for Windows builds (see CMakeLists.txt).
 *
 * Governed by the Apache License 2.0 (see License.txt).
 */

#ifndef VCDECRYPT_WINDOWS_SYSTEM_H
#define VCDECRYPT_WINDOWS_SYSTEM_H

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <windows.h>

#endif /* VCDECRYPT_WINDOWS_SYSTEM_H */
