cmake_minimum_required(VERSION 3.20)

project(
    ByteGuardCrypto
    VERSION 1.0.0
    DESCRIPTION "ByteGuard — Modulo C++ di Cifratura/Decifratura Forense"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(nlohmann_json INTERFACE)
target_include_directories(nlohmann_json
    INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)
add_library(nlohmann_json::nlohmann_json ALIAS nlohmann_json)

add_executable(ByteGuardCrypto)

target_sources(ByteGuardCrypto
    PRIVATE
        src/main.cpp
        src/ByteGuardCrypto.cpp
)

target_include_directories(ByteGuardCrypto
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(ByteGuardCrypto
    PRIVATE
        nlohmann_json::nlohmann_json
)

# Abilitazione dei flag di diagnostica in base al compilatore rilevato (MSVC vs GCC/Clang).
if(MSVC)
    target_compile_options(ByteGuardCrypto PRIVATE /W4 /utf-8)
else()
    target_compile_options(ByteGuardCrypto PRIVATE -Wall -Wextra -Wpedantic)
endif()
