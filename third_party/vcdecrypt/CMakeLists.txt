# ---------------------------------------------------------------------------
# vcdecrypt - minimal, cross-platform (Linux + Windows) VeraCrypt container
# decryption library, built with CMake so it can be imported into other projects.
#
# Usage from a parent project:
#
#   add_subdirectory(path/to/vcdecrypt)
#   target_link_libraries(my_app PRIVATE vcdecrypt::vcdecrypt)
#
# or, after `cmake --install`:
#
#   find_package(vcdecrypt CONFIG REQUIRED)
#   target_link_libraries(my_app PRIVATE vcdecrypt::vcdecrypt)
#
# The library reuses VeraCrypt's own crypto/volume code (pure-C reference
# implementations; all hand-written assembly and SIMD intrinsics are disabled)
# so the exact same source set compiles on Linux and Windows with one toolchain
# path. It does its own std::ifstream file I/O and therefore does NOT depend on
# VeraCrypt's Unix-only Platform::File layer. Public API: include/vcdecrypt.hpp.
# ---------------------------------------------------------------------------
cmake_minimum_required(VERSION 3.16)

project(vcdecrypt LANGUAGES C CXX)

option(VCDECRYPT_BUILD_SHARED "Build vcdecrypt as a shared library" OFF)

# VeraCrypt source tree lives one level up (../src relative to this file).
set(VC_SRC "${CMAKE_CURRENT_SOURCE_DIR}")
if(NOT EXISTS "${VC_SRC}/Volume/VolumeHeader.cpp")
    message(FATAL_ERROR
        "VeraCrypt sources not found at ${VC_SRC}. "
        "vcdecrypt expects to live alongside the VeraCrypt 'src' directory.")
endif()

# ---------------------------------------------------------------------------
# Source selection
# ---------------------------------------------------------------------------

# Volume layer: the decrypt-relevant subset (no Volume.cpp -> it pulls the
# Unix-only Platform::File layer; we replace it with our own I/O).
set(VC_VOLUME_SRC
    "${VC_SRC}/Volume/Cipher.cpp"
    "${VC_SRC}/Volume/EncryptionAlgorithm.cpp"
    "${VC_SRC}/Volume/EncryptionMode.cpp"
    "${VC_SRC}/Volume/EncryptionModeXTS.cpp"
    "${VC_SRC}/Volume/EncryptionThreadPool.cpp"
    "${VC_SRC}/Volume/Hash.cpp"
    "${VC_SRC}/Volume/Pkcs5Kdf.cpp"
    "${VC_SRC}/Volume/VolumeException.cpp"
    "${VC_SRC}/Volume/VolumeHeader.cpp"
    "${VC_SRC}/Volume/VolumeLayout.cpp"
    "${VC_SRC}/Volume/VolumePassword.cpp"
)

# Platform layer: only the portable (.cpp at the Platform root) files. The
# file-I/O (FileCommon.cpp + Unix/File.cpp) is deliberately excluded; we do our
# own std::ifstream I/O instead.
set(VC_PLATFORM_SRC
    "${VC_SRC}/Platform/Buffer.cpp"
    "${VC_SRC}/Platform/Exception.cpp"
    "${VC_SRC}/Platform/Memory.cpp"
    "${VC_SRC}/Platform/Serializable.cpp"
    "${VC_SRC}/Platform/Serializer.cpp"
    "${VC_SRC}/Platform/SerializerFactory.cpp"
    "${VC_SRC}/Platform/StringConverter.cpp"
)

# Thread/sync primitives needed by EncryptionThreadPool. On Linux we reuse
# VeraCrypt's own pthread implementations; on Windows we provide our own native
# Win32 implementations (vcdecrypt does not ship Windows versions of these).
if(WIN32)
    set(VC_THREAD_SRC
        "${CMAKE_CURRENT_SOURCE_DIR}/src/platform_win32.cpp"
        "${VC_SRC}/Platform/Unix/SystemException.cpp")
else()
    set(VC_THREAD_SRC
        "${VC_SRC}/Platform/Unix/Mutex.cpp"
        "${VC_SRC}/Platform/Unix/SyncEvent.cpp"
        "${VC_SRC}/Platform/Unix/Thread.cpp"
        "${VC_SRC}/Platform/Unix/SystemException.cpp"
        "${VC_SRC}/Platform/Unix/SystemLog.cpp"
    )
endif()

# Common layer: byte-order + CRC + GF multiply helpers + PKCS5/Argon2 entry points.
set(VC_COMMON_SRC
    "${VC_SRC}/Common/Crc.c"
    "${VC_SRC}/Common/Endian.c"
    "${VC_SRC}/Common/GfMul.c"
    "${VC_SRC}/Common/Pkcs5.c"
)

# Crypto primitives: portable C reference implementations only.
set(VC_CRYPTO_SRC
    "${VC_SRC}/Crypto/Aescrypt.c"
    "${VC_SRC}/Crypto/Aeskey.c"
    "${VC_SRC}/Crypto/Aestab.c"
    "${VC_SRC}/Crypto/SerpentFast.c"
    "${VC_SRC}/Crypto/SerpentFast_simd.cpp"   # SIMD-guarded; empty without SSE2
    "${VC_SRC}/Crypto/Twofish.c"
    "${VC_SRC}/Crypto/Camellia.c"
    "${VC_SRC}/Crypto/kuznyechik.c"
    "${VC_SRC}/Crypto/kuznyechik_simd.c"      # SIMD-guarded; empty without SSE2
    "${VC_SRC}/Crypto/Sha2.c"
    "${VC_SRC}/Crypto/Whirlpool.c"
    "${VC_SRC}/Crypto/Streebog.c"
    "${VC_SRC}/Crypto/blake2s.c"
    "${VC_SRC}/Crypto/cpu.c"
)

# Argon2id (single-threaded reference path).
set(VC_ARGON2_SRC
    "${VC_SRC}/Crypto/Argon2/src/argon2.c"
    "${VC_SRC}/Crypto/Argon2/src/core.c"
    "${VC_SRC}/Crypto/Argon2/src/ref.c"
    # opt_sse2/opt_avx2 provide fill_segment_sse2/avx2; when SSE2/AVX2 are
    # disabled their #else branch routes those back to fill_segment_ref.
    "${VC_SRC}/Crypto/Argon2/src/opt_sse2.c"
    "${VC_SRC}/Crypto/Argon2/src/opt_avx2.c"
    "${VC_SRC}/Crypto/Argon2/src/blake2/blake2b.c"
)

set(VCDECRYPT_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/vcdecrypt_cpp.cpp"   # C++ (PIMPL) API
    ${VC_VOLUME_SRC}
    ${VC_PLATFORM_SRC}
    ${VC_THREAD_SRC}
    ${VC_COMMON_SRC}
    ${VC_CRYPTO_SRC}
    ${VC_ARGON2_SRC}
)

# ---------------------------------------------------------------------------
# The library target
# ---------------------------------------------------------------------------
if(VCDECRYPT_BUILD_SHARED)
    add_library(vcdecrypt SHARED ${VCDECRYPT_SOURCES})
else()
    add_library(vcdecrypt STATIC ${VCDECRYPT_SOURCES})
endif()
add_library(vcdecrypt::vcdecrypt ALIAS vcdecrypt)

set_target_properties(vcdecrypt PROPERTIES
    CXX_STANDARD 14
    CXX_STANDARD_REQUIRED ON
    C_STANDARD 11
    POSITION_INDEPENDENT_CODE ON
)

# Public include dir (our API) + private VeraCrypt include roots.
target_include_directories(vcdecrypt
    PUBLIC
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
        "$<INSTALL_INTERFACE:include>"
    PRIVATE
        "${VC_SRC}"                       # so "Common/..", "Volume/..", "Platform/.." resolve
        "${VC_SRC}/Crypto"                # so Common/Crypto.h finds "Aes.h" etc.
        "${VC_SRC}/Common"
        "${VC_SRC}/Crypto/Argon2/include"
        "${VC_SRC}/Crypto/Argon2/src"
)

# On Windows, expose our minimal Windows/System.h (used by Mutex.h etc.).
if(WIN32)
    target_include_directories(vcdecrypt PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src/win32")
endif()

# ---------------------------------------------------------------------------
# Compile definitions: force the portable, no-ASM / no-intrinsics code paths so
# the identical source set builds on Linux and Windows.
# ---------------------------------------------------------------------------
target_compile_definitions(vcdecrypt PRIVATE
    CRYPTOPP_DISABLE_ASM=1
    CRYPTOPP_DISABLE_AESNI=1
    CRYPTOPP_DISABLE_SSE2=1
    CRYPTOPP_DISABLE_SSSE3=1
    CRYPTOPP_DISABLE_SSE4=1
    CRYPTOPP_DISABLE_SHANI=1
    CRYPTOPP_DISABLE_ARM_AES=1
    CRYPTOPP_DISABLE_ARM_SHA=1
    ARGON2_NO_THREADS=1                  # single-threaded Argon2 (VeraCrypt uses parallelism=1)
)

if(WIN32)
    target_compile_definitions(vcdecrypt PRIVATE TC_WINDOWS=1 _CRT_SECURE_NO_WARNINGS=1)
else()
    target_compile_definitions(vcdecrypt PRIVATE TC_UNIX=1)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_compile_definitions(vcdecrypt PRIVATE TC_LINUX=1)
    endif()
    find_package(Threads REQUIRED)
    target_link_libraries(vcdecrypt PUBLIC Threads::Threads)
endif()

# Keep the (unused) SIMD-guarded translation units quiet / harmless.
if(MSVC)
    target_compile_options(vcdecrypt PRIVATE /wd4146 /wd4267 /wd4244)
else()
    target_compile_options(vcdecrypt PRIVATE -fno-strict-aliasing -w)
endif()

# ---------------------------------------------------------------------------
# Install rules (so downstream projects can find_package it)
# ---------------------------------------------------------------------------
include(GNUInstallDirs)
install(TARGETS vcdecrypt EXPORT vcdecryptTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/include/vcdecrypt.hpp"
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT vcdecryptTargets
    NAMESPACE vcdecrypt::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/vcdecrypt)
