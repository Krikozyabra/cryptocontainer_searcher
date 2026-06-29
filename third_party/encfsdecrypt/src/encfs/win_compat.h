/*****************************************************************************
 * win_compat.h
 *
 * Intentionally has NO include guard.
 *
 * On Windows, <windows.h> / <combaseapi.h> define `interface` as a COM macro
 * (== struct). encfs declares a virtual method named interface() on several
 * classes. Because <windows.h> can be (re)included by a translation unit AFTER
 * a guarded header has already run, a one-time #undef in a normal header is not
 * enough -- the macro can be reinstated before the next class declaration.
 *
 * This header re-clears the macro every time it is included, so each header
 * that declares interface() can include it immediately beforehand and be sure
 * the keyword is available.
 *****************************************************************************/

#if defined(_WIN32) && defined(interface)
#undef interface
#endif
