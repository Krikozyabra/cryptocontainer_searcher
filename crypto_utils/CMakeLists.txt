set(TARGET crypto_utils)

add_library(${TARGET}
    src/crypto_search.cpp
    src/crypto_decrypt.cpp
)

target_include_directories(${TARGET}
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(${TARGET}
    PRIVATE
    entropy
    nlohmann_json::nlohmann_json
)
