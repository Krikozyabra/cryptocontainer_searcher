cmake_minimum_required(VERSION 3.24)
project(find_cryptocontainers LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

set(TCDECRYPT_BUILD_CLI OFF CACHE BOOL "" FORCE)

cmake_policy(SET CMP0135 NEW)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(EncfsDecrypt)   # defines the encfs::decrypt imported target

include(FetchContent)

if(TEST)
    message(STATUS "Configuring build with tests turned on")
    find_program(CRYPTSETUP_BIN NAMES cryptsetup REQUIRED)
    find_program(VERACRYPT_BIN NAMES veracrypt REQUIRED)
    find_program(ENCFS_BIN NAMES encfs REQUIRED)
    find_program(GPG_BIN NAMES gpg REQUIRED)
    find_program(FUSE_BIN NAMES fusermount fusermount3 REQUIRED)
    # Fetch Catch2 from GitHub
    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG        v3.4.0
    )

    FetchContent_MakeAvailable(Catch2)
endif()

# Fetch JsonParser from GitHub
set(JSON_BuildTests OFF CACHE INTERNAL "") 
FetchContent_Declare(
  json
  URL "${CMAKE_CURRENT_SOURCE_DIR}/third_party/json.tar.xz" 
)

FetchContent_MakeAvailable(json)


# Find dependencies required by the entropy library
find_package(Threads REQUIRED)
if(LOG)
    message(STATUS "Configuring build with loggging turnen on")
	add_compile_definitions(SPDLOG_COMPILED_LIB SPDLOG_SHARED_LIB)
    add_compile_definitions("LOG_ENABLED")
    find_package(spdlog REQUIRED)
endif()

# Add the external libraries
add_subdirectory(third_party/entropy)
add_subdirectory(third_party/tcdecrypt)
add_subdirectory(third_party/vcdecrypt EXCLUDE_FROM_ALL)
add_subdirectory(third_party/Tyfe)
add_subdirectory(crypto_utils)

# Define executable, referencing main.cpp
add_executable(crypto_search main.cpp)

# Link everything together
set(BUILD_LIBRARIES
    crypto_utils
    Threads::Threads
    nlohmann_json::nlohmann_json
)

if(LOG)
    list(APPEND BUILD_LIBRARIES
        spdlog::spdlog
    )
endif()

target_link_libraries(crypto_search PRIVATE
    ${BUILD_LIBRARIES}
)

if(WIN32)
    message(STATUS "Configuring Windows build with full static linking...")
    if(MSVC)
        # Portably configure static linking for MSVC
        set_target_properties(crypto_search PROPERTIES
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
        )
    else()
        # For MinGW or other GCC-like compilers on Windows
        target_link_options(crypto_search PRIVATE -static -static-libgcc -static-libstdc++)
    endif()
elseif(UNIX AND NOT APPLE)
    message(STATUS "Configuring Linux build with semi-static linking...")
    target_link_options(crypto_search PRIVATE -static-libgcc -static-libstdc++)

endif()

install(TARGETS crypto_search RUNTIME DESTINATION "bin")

if(WIN32)
set(GPG_PORTABLE_SRC "${CMAKE_CURRENT_SOURCE_DIR}/third_party/gpg_portable")

if(EXISTS "${GPG_PORTABLE_SRC}")
    set(GPG_PORTABLE_DST "$<TARGET_FILE_DIR:crypto_search>/gpg_portable")

    add_custom_command(TARGET crypto_search POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E rm -rf "${GPG_PORTABLE_DST}"
        COMMAND ${CMAKE_COMMAND} -E copy_directory
                "${GPG_PORTABLE_SRC}" "${GPG_PORTABLE_DST}"
        COMMAND ${CMAKE_COMMAND} -E rm -f
                "${GPG_PORTABLE_DST}/home/pubring.kbx.lock"
                "${GPG_PORTABLE_DST}/home/trustdb.gpg.lock"
                "${GPG_PORTABLE_DST}/home/gnupg_spawn_keyboxd_sentinel.lock"
        COMMENT "Copying portable GnuPG engine next to crypto_search"
        VERBATIM
    )

    install(DIRECTORY "${GPG_PORTABLE_SRC}/"
            DESTINATION "bin/gpg_portable"
            PATTERN "*.lock" EXCLUDE
            PATTERN "gnupg_spawn_keyboxd_sentinel.lock" EXCLUDE)
else()
    message(WARNING "third_party/gpg_portable not found; the portable GnuPG "
                    "engine will not be bundled next to crypto_search.")
endif()
endif()

if(TEST)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(CRYPTSETUP REQUIRED IMPORTED_TARGET libcryptsetup)

    # Append Linux-only library
    list(APPEND BUILD_LIBRARIES PkgConfig::CRYPTSETUP)
    
    # Enable testing
    enable_testing()

    # Define test executable
    add_executable(unit_tests 
        tests/test_search.cpp
    )

    # Link the test executable with Catch2 and other dependencies
    target_link_libraries(unit_tests PRIVATE 
        Catch2::Catch2WithMain
        ${BUILD_LIBRARIES}
    )

    # Register the test executable with CTest
    add_test(NAME RunUnitTests COMMAND unit_tests)
endif()
