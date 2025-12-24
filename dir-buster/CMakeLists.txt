cmake_minimum_required(VERSION 3.15)
project(dirbuster LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(CURL REQUIRED)
find_package(Threads REQUIRED)

add_library(dirbuster SHARED
    src/dir_buster.cpp
    src/http_client.cpp
    src/bindings.cpp
)

target_include_directories(dirbuster PUBLIC ${PROJECT_SOURCE_DIR}/include)

target_link_libraries(dirbuster
    PUBLIC
        CURL::libcurl
        Threads::Threads
)

add_executable(dir_buster src/main.cpp)
target_link_libraries(dir_buster PRIVATE dirbuster)

set_target_properties(dirbuster PROPERTIES
    OUTPUT_NAME "dirbuster"
    PREFIX "libr"
)
