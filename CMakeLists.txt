cmake_minimum_required(VERSION 3.15)
project(find_cryptocontainers LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

# Find dependencies required by the entropy library
find_package(Threads REQUIRED)

# Add the external libraries
add_subdirectory(third_party/entropy)
add_subdirectory(crypto_utils)

# Define executable, referencing main.cpp
add_executable(crypto_search main.cpp)

# Link everything together
target_link_libraries(crypto_search PRIVATE 
    crypto_utils
    entropy
    Threads::Threads
)

if(WIN32)
    message(STATUS "Configuring Windows build with full static linking...")
    target_link_options(crypto_search PRIVATE -static -static-libgcc -static-libstdc++)

elseif(UNIX AND NOT APPLE)
    message(STATUS "Configuring Linux build with semi-static linking...")
    target_link_options(crypto_search PRIVATE -static-libgcc -static-libstdc++)

endif()

# Enable testing
enable_testing()

# Fetch Catch2 from GitHub
include(FetchContent)
FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        v3.4.0
)
FetchContent_MakeAvailable(Catch2)

# Define test executable
add_executable(unit_tests 
    tests/test_search.cpp
)

# Link the test executable with Catch2 and other dependencies
target_link_libraries(unit_tests PRIVATE 
    Catch2::Catch2WithMain
    crypto_utils
    entropy
    Threads::Threads
)

# Register the test executable with CTest
add_test(NAME RunUnitTests COMMAND unit_tests)
