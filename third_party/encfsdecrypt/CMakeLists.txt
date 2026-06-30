# ===========================================================================
#  encfsdecrypt — self-contained, cross-platform EncFS folder-decryption lib
# ===========================================================================
#
#  Builds ONE static library target: `encfs_decrypt`.
#
#  It decrypts a whole EncFS (V6 / .encfs6.xml) folder given the password, with
#  no FUSE and no POSIX-only filesystem dependency, so it compiles on Linux and
#  Windows (GCC / Clang / MSVC / MinGW-w64) alike.
#
#  External dependency: OpenSSL (libcrypto). tinyxml2 and easylogging++ are
#  vendored inside this folder, so the only thing you must provide is OpenSSL.
#
#  Typical use (handled for you by cmake/EncfsDecrypt.cmake):
#      add_subdirectory(third_party/encfsdecrypt)
#      target_link_libraries(your_app PRIVATE encfs_decrypt)
#
#  The public header is include/encfs_decrypt.h.
# ===========================================================================

cmake_minimum_required(VERSION 3.15)
project(encfsdecrypt CXX)

set(ENCFSDECRYPT_ROOT ${CMAKE_CURRENT_SOURCE_DIR})

# --- sources --------------------------------------------------------------
set(_module_sources
  ${ENCFSDECRYPT_ROOT}/src/encfs_decrypt.cpp
  ${ENCFSDECRYPT_ROOT}/src/PortableFileIO.cpp
)

set(_encfs_core_sources
  ${ENCFSDECRYPT_ROOT}/src/encfs/Cipher.cpp
  ${ENCFSDECRYPT_ROOT}/src/encfs/SSL_Cipher.cpp
  ${ENCFSDECRYPT_ROOT}/src/encfs/CipherKey.cpp
  ${ENCFSDECRYPT_ROOT}/src/encfs/Interface.cpp
  ${ENCFSDECRYPT_ROOT}/src/encfs/base64.cpp
  ${ENCFSDECRYPT_ROOT}/src/encfs/ConfigVar.cpp
  ${ENCFSDECRYPT_ROOT}/src/encfs/XmlReader.cpp
  ${ENCFSDECRYPT_ROOT}/src/encfs/MemoryPool.cpp
  ${ENCFSDECRYPT_ROOT}/src/encfs/Error.cpp
  ${ENCFSDECRYPT_ROOT}/src/encfs/autosprintf.cpp
  ${ENCFSDECRYPT_ROOT}/src/encfs/NameIO.cpp
  ${ENCFSDECRYPT_ROOT}/src/encfs/BlockNameIO.cpp
  ${ENCFSDECRYPT_ROOT}/src/encfs/StreamNameIO.cpp
  ${ENCFSDECRYPT_ROOT}/src/encfs/NullNameIO.cpp
  ${ENCFSDECRYPT_ROOT}/src/encfs/NullCipher.cpp
  ${ENCFSDECRYPT_ROOT}/src/encfs/FileIO.cpp
  ${ENCFSDECRYPT_ROOT}/src/encfs/BlockFileIO.cpp
  ${ENCFSDECRYPT_ROOT}/src/encfs/CipherFileIO.cpp
  ${ENCFSDECRYPT_ROOT}/src/encfs/MACFileIO.cpp
)

set(_vendor_sources
  ${ENCFSDECRYPT_ROOT}/vendor/easyloggingpp/easylogging++.cc
  ${ENCFSDECRYPT_ROOT}/vendor/tinyxml2/tinyxml2.cpp
)

add_library(encfs_decrypt STATIC
  ${_module_sources}
  ${_encfs_core_sources}
  ${_vendor_sources}
)

# --- C++ standard ---------------------------------------------------------
target_compile_features(encfs_decrypt PUBLIC cxx_std_17)
set_target_properties(encfs_decrypt PROPERTIES CXX_STANDARD_REQUIRED ON)

# --- compile definitions --------------------------------------------------
target_compile_definitions(encfs_decrypt PUBLIC
  ENCFS_NO_FUSE          # drop the FUSE surface from the encfs headers
  _FILE_OFFSET_BITS=64   # 64-bit file offsets
)

target_compile_definitions(encfs_decrypt PRIVATE
  ELPP_THREAD_SAFE
  ELPP_NO_DEFAULT_LOG_FILE   # don't open/create a default log file
  ELPP_DISABLE_LOG_FILE_FROM_ARG
)
# --- include directories --------------------------------------------------
# PUBLIC: the consumer needs the public header dir.
target_include_directories(encfs_decrypt PUBLIC
  ${ENCFSDECRYPT_ROOT}/include
)
# PRIVATE: everything the implementation + core sources include by bare name.
target_include_directories(encfs_decrypt PRIVATE
  ${ENCFSDECRYPT_ROOT}/src            # PortableFileIO.h, encfs_decrypt.h (also public)
  ${ENCFSDECRYPT_ROOT}/src/encfs      # encfs core headers + static config.h
  ${ENCFSDECRYPT_ROOT}/src            # intl/gettext.h via "intl/gettext.h"
)
target_include_directories(encfs_decrypt SYSTEM PRIVATE
  ${ENCFSDECRYPT_ROOT}/vendor/easyloggingpp
  ${ENCFSDECRYPT_ROOT}/vendor/tinyxml2
)

# --- dependencies ---------------------------------------------------------
find_package(OpenSSL REQUIRED)
target_link_libraries(encfs_decrypt PUBLIC OpenSSL::Crypto)

find_package(Threads REQUIRED)
target_link_libraries(encfs_decrypt PUBLIC Threads::Threads)

# std::filesystem needs an extra lib on older GCC (< 9).
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND
    CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0)
  target_link_libraries(encfs_decrypt PUBLIC stdc++fs)
endif()

# easylogging++ wants threading enabled on all platforms.
target_compile_definitions(encfs_decrypt PRIVATE ELPP_THREAD_SAFE)

# Quieten third-party warnings that would otherwise spam consumer builds.
if (MSVC)
  target_compile_options(encfs_decrypt PRIVATE /w)
else()
  target_compile_options(encfs_decrypt PRIVATE -w)
endif()

# --- optional example -----------------------------------------------------
option(ENCFSDECRYPT_BUILD_EXAMPLE "Build the decrypt_example program" OFF)
if (ENCFSDECRYPT_BUILD_EXAMPLE)
  add_executable(decrypt_example ${ENCFSDECRYPT_ROOT}/example/decrypt_example.cpp)
  target_link_libraries(decrypt_example PRIVATE encfs_decrypt)
endif()
