cmake_minimum_required(VERSION 3.15)
project(gpgutil CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(gpgutil STATIC
    gpgutil.cpp
    gpgutil.hpp
)

target_include_directories(gpgutil PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Сначала пробуем найти GPGME через PkgConfig (подходит для Linux, macOS и Windows MSYS2 UCRT64)
find_package(PkgConfig QUIET)

if(PkgConfig_FOUND)
    pkg_check_modules(GPGME REQUIRED gpgme IMPORTED_TARGET)
    target_link_libraries(gpgutil PUBLIC PkgConfig::GPGME)

    pkg_check_modules(GPG_ERROR gpg-error IMPORTED_TARGET)
    if(GPG_ERROR_FOUND)
        target_link_libraries(gpgutil PUBLIC PkgConfig::GPG_ERROR)
    else()
        target_link_libraries(gpgutil PUBLIC gpg-error)
    endif()

    if(WIN32)
        set(DEVELOPER_BIN_DIR "${GPGME_PREFIX}/bin" CACHE INTERNAL "Path to developer's bin directory")
    endif()

else()
    if(WIN32)
        set(GPG4WIN_HINTS
            "C:/Program Files/Gpg4win"
            "C:/Program Files (x86)/Gpg4win"
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
            target_include_directories(gpgutil PRIVATE ${GPGME_INCLUDE_DIR})
            target_link_libraries(gpgutil PUBLIC ${GPGME_LIBRARY})
            if(GPG_ERROR_LIBRARY)
                target_link_libraries(gpgutil PUBLIC ${GPG_ERROR_LIBRARY})
            endif()
        else()
            message(FATAL_ERROR "GPGME not found. Please install Gpg4win or configure PKG_CONFIG_PATH.")
        endif()
    else()
        message(FATAL_ERROR "PkgConfig not found. Cannot build on Unix without PkgConfig.")
    endif()
endif()