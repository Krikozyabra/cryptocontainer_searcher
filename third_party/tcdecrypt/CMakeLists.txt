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

# tcdecrypt and vcdecrypt both vendor TrueCrypt/VeraCrypt's C crypto sources,
# which export the SAME plain-C global symbols (twofish_set_key, aes_encrypt,
# sha512, ...). When both static libraries are linked into one binary the linker
# keeps only one definition per name and silently cross-wires the calls. Because
# the two copies use DIFFERENT struct layouts (e.g. TwofishInstance), a call from
# vcdecrypt that resolves to tcdecrypt's twofish_set_key writes past the end of
# the key schedule and crashes (SEGV in twofish_set_key). Prefix every clashing
# C symbol in THIS library with `tc_` so the two crypto cores stay separate.
target_compile_definitions(tcdecrypt_core PRIVATE
    # already-renamed PKCS5 / serpent entry points
    hmac_sha512=tc_hmac_sha512
    derive_key_sha512=tc_derive_key_sha512
    hmac_whirlpool=tc_hmac_whirlpool
    derive_key_whirlpool=tc_derive_key_whirlpool
    get_pkcs5_iteration_count=tc_get_pkcs5_iteration_count
    serpent_set_key=tc_serpent_set_key
    # Twofish (the one that crashed)
    twofish_set_key=tc_twofish_set_key
    twofish_encrypt=tc_twofish_encrypt
    twofish_decrypt=tc_twofish_decrypt
    # AES
    aes_init=tc_aes_init
    aes_encrypt=tc_aes_encrypt
    aes_decrypt=tc_aes_decrypt
    aes_encrypt_key256=tc_aes_encrypt_key256
    aes_decrypt_key256=tc_aes_decrypt_key256
    # SHA-256 / SHA-512
    sha256=tc_sha256
    sha256_begin=tc_sha256_begin
    sha256_end=tc_sha256_end
    sha256_hash=tc_sha256_hash
    sha512=tc_sha512
    sha512_begin=tc_sha512_begin
    sha512_end=tc_sha512_end
    sha512_hash=tc_sha512_hash
    # Whirlpool
    WHIRLPOOL_init=tc_WHIRLPOOL_init
    WHIRLPOOL_add=tc_WHIRLPOOL_add
    WHIRLPOOL_finalize=tc_WHIRLPOOL_finalize
    # CRC32
    GetCrc32=tc_GetCrc32
    crc32int=tc_crc32int
    crc32_selftests=tc_crc32_selftests
    # GF(2^128) multiply helpers (GfMul.c)
    Gf128MulBy64Tab=tc_Gf128MulBy64Tab
    Gf128Tab64Init=tc_Gf128Tab64Init
    GfMul128=tc_GfMul128
    GfMul128Tab=tc_GfMul128Tab
    GfMulSelfTest=tc_GfMulSelfTest
    MirrorBits128=tc_MirrorBits128
    MirrorBits64=tc_MirrorBits64
    MirrorBytes16=tc_MirrorBytes16
    MirrorBytes32=tc_MirrorBytes32
    MirrorBytes64=tc_MirrorBytes64
    mul_x=tc_mul_x
    mul_x64=tc_mul_x64
    mul_lex8=tc_mul_lex8
    mul_lex8_64=tc_mul_lex8_64
    mul_bex8=tc_mul_bex8
    mul_bex8_64=tc_mul_bex8_64
    bsw_32=tc_bsw_32
    compile_4k_table64=tc_compile_4k_table64
    compile_8k_table=tc_compile_8k_table
    move_block_aligned=tc_move_block_aligned
    move_block_aligned64=tc_move_block_aligned64
    xor_block_aligned=tc_xor_block_aligned
    xor_block_aligned64=tc_xor_block_aligned64
    # CRC table + AES lookup-table generators/data (Aestab.c)
    crc_32_tab=tc_crc_32_tab
    t_fl=tc_t_fl
    t_fn=tc_t_fn
    t_il=tc_t_il
    t_im=tc_t_im
    t_in=tc_t_in
    t_rc=tc_t_rc
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
