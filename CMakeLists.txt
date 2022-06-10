
cmake_minimum_required(VERSION 2.8)

project(vlan_tagger)

set(SOURCE_EXE vlan_tagger.c)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/..)

include_directories(interface)
include_directories(ip_pool)


add_executable(vlan_tagger ${SOURCE_EXE})

add_subdirectory(interface)
add_subdirectory(ip_pool)

target_link_libraries(vlan_tagger interface ip_pool)

set(SOURCE_EXE autotest.c)

add_executable(autotest ${SOURCE_EXE})

