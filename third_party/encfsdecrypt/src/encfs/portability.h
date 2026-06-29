/*****************************************************************************
 * portability.h
 *
 * Small compatibility shim that lets the portable subset of libencfs (the
 * crypto / config / block-IO primitives used for *decryption*) build on
 * non-POSIX platforms such as Windows/MSVC, without pulling in FUSE.
 *
 * It is included by encfs.h when ENCFS_NO_FUSE is defined. On POSIX systems it
 * simply forwards to the normal system headers, so the behaviour there is
 * unchanged.
 *****************************************************************************/

#ifndef _encfs_portability_incl_
#define _encfs_portability_incl_

#if !defined(_WIN32)

// ---- POSIX: behave exactly as before -------------------------------------
#include <sys/types.h>
#include <unistd.h>

#else  // _WIN32

// ---- Windows / MSVC ------------------------------------------------------
// Use lowercase header names: MSVC is case-insensitive, but MinGW-w64 (also a
// valid Windows target) is case-sensitive.
#include <basetsd.h>
#include <cstdint>
#include <io.h>
#include <sys/stat.h>
#include <sys/types.h>

// The two Windows toolchains differ in which POSIX types their CRT already
// provides, so define each only where it is missing.
//
//   - MinGW-w64 supplies ssize_t, off_t, mode_t and dev_t already (off_t is
//     widened to 64-bit by _FILE_OFFSET_BITS=64, which the build sets).
//   - MSVC supplies none of these portably.

#if defined(_MSC_VER)
#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
typedef SSIZE_T ssize_t;
#endif
// MSVC's <sys/stat.h> uses a 32-bit off_t; widen it for 64-bit file offsets.
#ifdef off_t
#undef off_t
#endif
typedef int64_t off_t;
#ifndef _MODE_T_DEFINED
typedef unsigned short mode_t;
#endif
typedef int dev_t;
#endif  // _MSC_VER

// uid_t / gid_t are absent on both Windows toolchains.
#ifndef _UID_T_DEFINED
#define _UID_T_DEFINED
typedef int uid_t;
typedef int gid_t;
#endif

// ---- pthread mutex shim (used by SSL_Cipher.cpp / MemoryPool.cpp) --------
// Backed by a Win32 critical section. Only the mutex subset encfs uses.
#include <windows.h>  // lowercase: portable across MSVC and MinGW

typedef CRITICAL_SECTION pthread_mutex_t;
#define PTHREAD_MUTEX_INITIALIZER \
  {}

static __inline int pthread_mutex_init(pthread_mutex_t *m, const void *attr) {
  (void)attr;
  InitializeCriticalSection(m);
  return 0;
}
static __inline int pthread_mutex_destroy(pthread_mutex_t *m) {
  DeleteCriticalSection(m);
  return 0;
}
static __inline int pthread_mutex_lock(pthread_mutex_t *m) {
  EnterCriticalSection(m);
  return 0;
}
static __inline int pthread_mutex_unlock(pthread_mutex_t *m) {
  LeaveCriticalSection(m);
  return 0;
}

// ---- mlock / munlock shim (SSL_Cipher.cpp pins key memory) ---------------
// Best-effort: VirtualLock if available, otherwise a no-op. Decryption is
// correct either way; this only affects whether key bytes can be paged out.
static __inline int mlock(const void *addr, size_t len) {
  return VirtualLock((LPVOID)addr, len) ? 0 : 0;
}
static __inline int munlock(const void *addr, size_t len) {
  return VirtualUnlock((LPVOID)addr, len) ? 0 : 0;
}

// <windows.h> (pulled in above and by easylogging++) defines `interface` as a
// macro for COM (== struct). encfs has a virtual method named interface(), so
// the macro must be removed or every FileIO/Cipher header fails to compile.
#ifdef interface
#undef interface
#endif

#endif  // _WIN32

#endif  // _encfs_portability_incl_
