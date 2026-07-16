cmake_minimum_required(VERSION 3.15)
project(gpgutil CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(gpgutil STATIC
    gpgutil.cpp
    gpgutil.hpp
)

# Force 64-bit file offsets. This perfectly aligns the 'off_t' size 
# inside GpgME::Data with the precompiled MSYS2 UCRT64 libraries.
target_compile_definitions(gpgutil PUBLIC _FILE_OFFSET_BITS=64)

target_include_directories(gpgutil PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

find_package(PkgConfig QUIET)
# This successfully finds GpgmeppConfig.cmake provided by MSYS2
find_package(Gpgmepp REQUIRED)

if(PkgConfig_FOUND)
    message(STATUS "PkgConfig found for gpgdecrypt")
    pkg_check_modules(GPGME REQUIRED gpgme IMPORTED_TARGET)
    
    # We directly link the CMake target (Gpgmepp) found by find_package() 
    # instead of asking pkg-config for it, because MSYS2 doesn't bundle gpgmepp.pc
    target_link_libraries(gpgutil PUBLIC 
        PkgConfig::GPGME 
        Gpgmepp
    )

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
        
        # GPGMEPP (the C++ wrapper library) Windows fallback
        find_library(GPGMEPP_LIBRARY
            NAMES gpgmepp libgpgmepp-6 libgpgmepp
            HINTS ${GPG4WIN_HINTS}
            PATH_SUFFIXES lib
        )

        find_library(GPG_ERROR_LIBRARY
            NAMES gpg-error libgpg-error-0 libgpg-error-6 libgpg-error
            HINTS ${GPG4WIN_HINTS}
            PATH_SUFFIXES lib
        )

        if(GPGME_INCLUDE_DIR AND GPGME_LIBRARY AND GPGMEPP_LIBRARY)
            target_include_directories(gpgutil PRIVATE ${GPGME_INCLUDE_DIR})
            target_link_libraries(gpgutil PUBLIC ${GPGME_LIBRARY} ${GPGMEPP_LIBRARY})
            if(GPG_ERROR_LIBRARY)
                target_link_libraries(gpgutil PUBLIC ${GPG_ERROR_LIBRARY})
            endif()
        else()
            message(FATAL_ERROR "GPGME or GPGMEPP not found. Please install Gpg4win or configure PKG_CONFIG_PATH.")
        endif()
    else()
        message(FATAL_ERROR "PkgConfig not found. Cannot build on Unix without PkgConfig.")
    endif()
endif()