cmake_minimum_required(VERSION 3.10)
project(tcdecrypt LANGUAGES C CXX)

option(TCDECRYPT_BUILD_CLI "Build the tcdecrypt command-line tool" OFF)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)

get_filename_component(TC_ROOT "${CMAKE_CURRENT_SOURCE_DIR}" ABSOLUTE)

# ---------------------------------------------------------------------------
# Crypto primitives (C) — portable AES + the other ciphers/hashes.
# ---------------------------------------------------------------------------
set(CRYPTO_SRC
    ${TC_ROOT}/Crypto/Aeskey.c
    ${TC_ROOT}/Crypto/Aestab.c
    ${TC_ROOT}/Crypto/Aescrypt.c
    ${TC_ROOT}/Crypto/Blowfish.c
    ${TC_ROOT}/Crypto/Cast.c
    ${TC_ROOT}/Crypto/Des.c
    ${TC_ROOT}/Crypto/Rmd160.c
    ${TC_ROOT}/Crypto/Serpent.c
    ${TC_ROOT}/Crypto/Sha1.c
    ${TC_ROOT}/Crypto/Sha2.c
    ${TC_ROOT}/Crypto/Twofish.c
    ${TC_ROOT}/Crypto/Whirlpool.c
)

# ---------------------------------------------------------------------------
# Common helpers (C).
# ---------------------------------------------------------------------------
set(COMMON_SRC
    ${TC_ROOT}/Common/Crc.c
    ${TC_ROOT}/Common/Endian.c
    ${TC_ROOT}/Common/GfMul.c
    ${TC_ROOT}/Common/Pkcs5.c
)

# ---------------------------------------------------------------------------
# Platform abstraction (C++) — OS-independent part.
# ---------------------------------------------------------------------------
set(PLATFORM_SRC
    ${TC_ROOT}/Platform/Buffer.cpp
    ${TC_ROOT}/Platform/Exception.cpp
    ${TC_ROOT}/Platform/Event.cpp
    ${TC_ROOT}/Platform/FileCommon.cpp
    ${TC_ROOT}/Platform/MemoryStream.cpp
    ${TC_ROOT}/Platform/Memory.cpp
    ${TC_ROOT}/Platform/Serializable.cpp
    ${TC_ROOT}/Platform/Serializer.cpp
    ${TC_ROOT}/Platform/SerializerFactory.cpp
    ${TC_ROOT}/Platform/StringConverter.cpp
    ${TC_ROOT}/Platform/TextReader.cpp
)

# ...and the OS-specific backend.
if(WIN32)
    list(APPEND PLATFORM_SRC
        ${TC_ROOT}/Platform/Windows/Directory.cpp
        ${TC_ROOT}/Platform/Windows/File.cpp
        ${TC_ROOT}/Platform/Windows/FilesystemPath.cpp
        ${TC_ROOT}/Platform/Windows/Mutex.cpp
        ${TC_ROOT}/Platform/Windows/SyncEvent.cpp
        ${TC_ROOT}/Platform/Windows/SystemException.cpp
        ${TC_ROOT}/Platform/Windows/SystemInfo.cpp
        ${TC_ROOT}/Platform/Windows/SystemLog.cpp
        ${TC_ROOT}/Platform/Windows/Thread.cpp
        ${TC_ROOT}/Platform/Windows/Time.cpp
    )
else()
    list(APPEND PLATFORM_SRC
        ${TC_ROOT}/Platform/Unix/Directory.cpp
        ${TC_ROOT}/Platform/Unix/File.cpp
        ${TC_ROOT}/Platform/Unix/FilesystemPath.cpp
        ${TC_ROOT}/Platform/Unix/Mutex.cpp
        ${TC_ROOT}/Platform/Unix/SyncEvent.cpp
        ${TC_ROOT}/Platform/Unix/SystemException.cpp
        ${TC_ROOT}/Platform/Unix/SystemInfo.cpp
        ${TC_ROOT}/Platform/Unix/SystemLog.cpp
        ${TC_ROOT}/Platform/Unix/Thread.cpp
        ${TC_ROOT}/Platform/Unix/Time.cpp
    )
endif()

# ---------------------------------------------------------------------------
# Volume library (C++) — the decryption logic.
# ---------------------------------------------------------------------------
set(VOLUME_SRC
    ${TC_ROOT}/Volume/Cipher.cpp
    ${TC_ROOT}/Volume/EncryptionAlgorithm.cpp
    ${TC_ROOT}/Volume/EncryptionMode.cpp
    ${TC_ROOT}/Volume/EncryptionModeCBC.cpp
    ${TC_ROOT}/Volume/EncryptionModeLRW.cpp
    ${TC_ROOT}/Volume/EncryptionModeXTS.cpp
    ${TC_ROOT}/Volume/EncryptionTest.cpp
    ${TC_ROOT}/Volume/EncryptionThreadPool.cpp
    ${TC_ROOT}/Volume/Hash.cpp
    ${TC_ROOT}/Volume/Keyfile.cpp
    ${TC_ROOT}/Volume/Pkcs5Kdf.cpp
    ${TC_ROOT}/Volume/Volume.cpp
    ${TC_ROOT}/Volume/VolumeException.cpp
    ${TC_ROOT}/Volume/VolumeHeader.cpp
    ${TC_ROOT}/Volume/VolumeInfo.cpp
    ${TC_ROOT}/Volume/VolumeLayout.cpp
    ${TC_ROOT}/Volume/VolumePassword.cpp
)

# ===========================================================================
# The reusable module: a static library.
# ===========================================================================
add_library(tcdecrypt_core STATIC
    ${CMAKE_CURRENT_SOURCE_DIR}/tcdecrypt.cpp   # public API wrapper
    ${CRYPTO_SRC}
    ${COMMON_SRC}
    ${PLATFORM_SRC}
    ${VOLUME_SRC}
)

# Include paths consumers also need (so `add_subdirectory` + link just works):
#  - the stub dir first, to shadow Common/SecurityToken.h (drops PKCS#11)
#  - the tree root (resolves "Platform/Platform.h", "Common/Crypto.h", ...)
#  - this dir (the public tcdecrypt.hpp)
target_include_directories(tcdecrypt_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/stub
    ${TC_ROOT}
    ${CMAKE_CURRENT_SOURCE_DIR}
)
# Internal include paths used by the TrueCrypt sources (bare "Volume.h",
# "Aes.h", "Common/Crypto.h" → "Aes.h"). PUBLIC so the CLI (main.cpp, which uses
# internals for its --create test mode) and any consumer that opts to touch the
# internals can build; downstream code that only uses tcdecrypt.hpp ignores them.
target_include_directories(tcdecrypt_core PUBLIC
    ${TC_ROOT}/Volume
    ${TC_ROOT}/Crypto
)

target_compile_definitions(tcdecrypt_core PRIVATE
    hmac_sha512=tc_hmac_sha512
    derive_key_sha512=tc_derive_key_sha512
    hmac_whirlpool=tc_hmac_whirlpool
    derive_key_whirlpool=tc_derive_key_whirlpool
    get_pkcs5_iteration_count=tc_get_pkcs5_iteration_count
    serpent_set_key=tc_serpent_set_key
)

# OS selection macros for the TrueCrypt sources.
if(WIN32)
    target_compile_definitions(tcdecrypt_core PUBLIC TC_WINDOWS)
else()
    target_compile_definitions(tcdecrypt_core PUBLIC TC_UNIX)
    if(APPLE)
        target_compile_definitions(tcdecrypt_core PUBLIC TC_MACOSX)
    else()
        target_compile_definitions(tcdecrypt_core PUBLIC TC_LINUX)
    endif()
endif()
target_compile_definitions(tcdecrypt_core PRIVATE TC_PROTOTYPE)

# Quiet the legacy TrueCrypt warnings (not our code to fix).
if(NOT MSVC)
    target_compile_options(tcdecrypt_core PRIVATE -w)
endif()

# Threads on POSIX; Windows brings its own threading API.
if(NOT WIN32)
    find_package(Threads REQUIRED)
    target_link_libraries(tcdecrypt_core PUBLIC Threads::Threads)
endif()

# ===========================================================================
# The CLI front-end.
# ===========================================================================
if(TCDECRYPT_BUILD_CLI)
    add_executable(tcdecrypt ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp)
    target_link_libraries(tcdecrypt PRIVATE tcdecrypt_core)
    if(NOT MSVC)
        target_compile_options(tcdecrypt PRIVATE -w)
    endif()
endif()
