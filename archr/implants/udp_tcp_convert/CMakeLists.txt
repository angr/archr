cmake_minimum_required (VERSION 2.22)
project (udp_to_tcp)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Socket
add_library(udp_to_tcp SHARED udp_to_tcp.c)
target_link_libraries(udp_to_tcp dl pthread)
