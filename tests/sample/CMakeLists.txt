cmake_minimum_required(VERSION 3.16)
project(ghidra_bridge_sample LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Keep the code close to the source so the MCP tests can find known names and calls.
set(SAMPLE_FLAGS -O0 -g -fno-inline -fno-omit-frame-pointer)

add_executable(sample_mixed
  src/main.c
  src/checksum.c
  src/records.c
  src/shapes.cpp
  src/bridge.cpp
)
target_include_directories(sample_mixed PRIVATE include)
target_compile_options(sample_mixed PRIVATE ${SAMPLE_FLAGS})
