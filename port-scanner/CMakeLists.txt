cmake_minimum_required(VERSION 3.10)
project(librpscan)

# C++ Standard and Compiler Flags
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -Wall -Wextra")

# Support for both Make and Ninja generators
if(CMAKE_BUILD_TYPE STREQUAL "")
  set(CMAKE_BUILD_TYPE Release)
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Generator: ${CMAKE_GENERATOR}")

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# Find tinyxml2 package
find_package(tinyxml2 REQUIRED)

# Source files
set(SOURCES
    src/nmap_executor.cpp
    src/parser.cpp
    src/scan_functions.cpp
    src/accessors.cpp
)

# Create shared library
add_library(librpscan SHARED ${SOURCES})

# Include directories for the library
target_include_directories(librpscan PUBLIC 
    ${CMAKE_SOURCE_DIR}/include
)

# Link against tinyxml2
target_link_libraries(librpscan PUBLIC tinyxml2)

# Set output directory for the shared object
set_target_properties(librpscan PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    LIBRARY_OUTPUT_NAME "rpscan"
)

# Compiler warnings
if(MSVC)
  target_compile_options(librpscan PRIVATE /W4)
else()
  target_compile_options(librpscan PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Print build info
message(STATUS "Building librpscan shared library")
message(STATUS "tinyxml2 found at: ${tinyxml2_DIR}")
message(STATUS "Include directory: ${CMAKE_SOURCE_DIR}/include")
message(STATUS "Output library: ${CMAKE_BINARY_DIR}/lib/librpscan.so")
