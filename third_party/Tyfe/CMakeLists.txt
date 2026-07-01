set(TARGET Tyfe)

add_library(${TARGET} INTERFACE)

target_include_directories(${TARGET}
    INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_sources(${TARGET}
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include/${TARGET}/Tyfe.hpp
)
