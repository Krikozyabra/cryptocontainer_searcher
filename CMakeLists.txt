cmake_minimum_required(VERSION 3.15)
project(find_cryptocontainers LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

# 1. Tell CMake to look for static Boost libraries
set(Boost_USE_STATIC_LIBS ON)

# Find dependencies required by the entropy library
find_package(Boost 1.61.0 REQUIRED COMPONENTS filesystem)
find_package(Threads REQUIRED)

# 2. Add the entropy directory from the third_party folder
add_subdirectory(third_party/entropy)

# 3. Define your executable, referencing main.cpp in the src directory
add_executable(crypto_search src/main.cpp)

# 4. Link everything together
target_link_libraries(crypto_search PRIVATE 
    entropy
    Boost::filesystem
    Threads::Threads
)

if(WIN32)
    message(STATUS "Configuring Windows build with full static linking...")
    target_link_options(crypto_search PRIVATE -static -static-libgcc -static-libstdc++)

elseif(UNIX AND NOT APPLE)
    message(STATUS "Configuring Linux build with semi-static linking...")
    target_link_options(crypto_search PRIVATE -static-libgcc -static-libstdc++)

endif()
