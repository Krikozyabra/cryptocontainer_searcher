set(TARGET crypto_utils)

set(SRC_LIST
    src/crypto_search.cpp
    src/crypto_decrypt.cpp
)

set(LINK_LIBS
    entropy
    nlohmann_json::nlohmann_json
    tcdecrypt_core
    vcdecrypt::vcdecrypt
    gpgutil
    encfs::decrypt
    Tyfe
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(CRYPTSETUP REQUIRED IMPORTED_TARGET libcryptsetup)

    # Append Linux-only source file
    list(APPEND SRC_LIST src/luksdecrypt.cpp)

    # Append Linux-only library
    list(APPEND LINK_LIBS PkgConfig::CRYPTSETUP)
endif()

add_library(${TARGET} ${SRC_LIST})

target_include_directories(${TARGET}
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(${TARGET}
    PRIVATE
    ${LINK_LIBS}
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_compile_definitions(${TARGET} PRIVATE SUPPORT_LUKS)
endif()
