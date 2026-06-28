cmake_minimum_required(VERSION 3.15)
project(gpgdecrypt CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(gpgdecrypt STATIC
    gpgdecrypt.cpp
    gpgdecrypt.h
)

target_include_directories(gpgdecrypt PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

if(WIN32)
    set(GPG4WIN_HINTS
        "C:/Program Files/GnuPG"
        "C:/Program Files (x86)/GnuPG"
    )

    find_path(GPGME_INCLUDE_DIR
        NAMES gpgme.h
        HINTS ${GPG4WIN_HINTS}
        PATH_SUFFIXES include
    )

    find_library(GPGME_LIBRARY
        NAMES gpgme libgpgme-11 libgpgme
        HINTS ${GPG4WIN_HINTS}
        PATH_SUFFIXES lib
    )
    find_library(GPG_ERROR_LIBRARY
        NAMES gpg-error libgpg-error-0 libgpg-error-6 libgpg-error
        HINTS ${GPG4WIN_HINTS}
        PATH_SUFFIXES lib
    )

    if(GPGME_INCLUDE_DIR AND GPGME_LIBRARY)
        target_include_directories(gpgdecrypt PRIVATE ${GPGME_INCLUDE_DIR})
        target_link_libraries(gpgdecrypt PUBLIC ${GPGME_LIBRARY})
        if(GPG_ERROR_LIBRARY)
            target_link_libraries(gpgdecrypt PUBLIC ${GPG_ERROR_LIBRARY})
        endif()
    else()
        message(FATAL_ERROR "GPGME not found. Please install Gpg4win.")
    endif()
else()
    # Unix (Linux / macOS) using PkgConfig
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(GPGME REQUIRED gpgme IMPORTED_TARGET)

    # Explicitly look up the gpg-error package
    pkg_check_modules(GPG_ERROR gpg-error IMPORTED_TARGET)
    
    if(GPG_ERROR_FOUND)
        # Link both targets PUBLICLY so they propagate down to crypto_search
        target_link_libraries(gpgdecrypt PUBLIC PkgConfig::GPGME PkgConfig::GPG_ERROR)
    else()
        # Fallback to standard library name if gpg-error.pc is missing
        target_link_libraries(gpgdecrypt PUBLIC PkgConfig::GPGME gpg-error)
    endif()
endif()
