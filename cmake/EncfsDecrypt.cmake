# EncfsDecrypt.cmake
#
# Defines the imported-style target `encfs::decrypt` for the cross-platform
# EncFS folder-decryption library that lives (vendored, source form) under
# third_party/encfsdecrypt/.
#
# Place this file in your project's cmake/ directory (the one already on your
# CMAKE_MODULE_PATH) and `include(EncfsDecrypt)` from your top-level
# CMakeLists.txt, exactly as you do today. After that:
#
#     target_link_libraries(your_app PRIVATE encfs::decrypt)
#
# The vendored library builds from source together with your project, so there
# are no prebuilt artifacts to match to your toolchain. Its only external
# dependency is OpenSSL (libcrypto); tinyxml2 + easylogging++ are bundled.
#
# Override the source location with -DENCFSDECRYPT_DIR=... if you do not use the
# default third_party/encfsdecrypt path.

if (TARGET encfs::decrypt)
  return()  # already configured
endif()

set(ENCFSDECRYPT_DIR "${CMAKE_SOURCE_DIR}/third_party/encfsdecrypt"
    CACHE PATH "Path to the vendored encfsdecrypt source subtree")

if (NOT EXISTS "${ENCFSDECRYPT_DIR}/CMakeLists.txt")
  message(FATAL_ERROR
    "EncfsDecrypt: no CMakeLists.txt at '${ENCFSDECRYPT_DIR}'.\n"
    "Copy the 'encfsdecrypt' folder into third_party/ (or set ENCFSDECRYPT_DIR).")
endif()

# Build the vendored library (defines target `encfs_decrypt`).
add_subdirectory("${ENCFSDECRYPT_DIR}" "${CMAKE_BINARY_DIR}/encfsdecrypt")

# Expose it under the conventional namespaced name.
add_library(encfs::decrypt ALIAS encfs_decrypt)

message(STATUS "EncfsDecrypt: encfs::decrypt configured from ${ENCFSDECRYPT_DIR}")
