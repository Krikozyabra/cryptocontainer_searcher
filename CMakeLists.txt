cmake_minimum_required(VERSION 3.15)
project(find_cryptocontainers LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

add_executable(crypto_search main.cpp)

if(WIN32)
	message(STATUS "Configurion Windows build with full static linking...")
	target_link_options(crypto_search PRIVATE -static -static-libgcc -static-libstdc++)

elseif(UNIX AND NOT APPLE)
	message(STATUS "Configuring Linux build with semi-static linking...")
	target_link_options(crypto_search PRIVATE -static-libgcc -static-libstdc++)

endif()
