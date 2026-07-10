set(TARGET windows_utils)

set(SRC_LIST
    src/drive_manager.cpp
)

set(LINK_LIBS
    virtdisk.lib
)

add_library(${TARGET} ${SRC_LIST})

target_include_directories(${TARGET}
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(${TARGET}
    PRIVATE
    ${LINK_LIBS}
)
