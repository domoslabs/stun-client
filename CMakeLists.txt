cmake_minimum_required(VERSION 3.0)
project(stun)
set(CMAKE_CXX_STANDARD 11)
#add_compile_options(-Wall -Wextra -Werror)
include(ExternalProject)
find_package(PkgConfig)
# Find the jsoncpp library


if (${jsoncpp_FOUND})
    MESSAGE(STATUS "jsoncpp found via CMake")
else (${jsoncpp_FOUND})
    MESSAGE(STATUS "jsoncpp not found via CMake, trying pkg-config")
    pkg_search_module(JSONCPP REQUIRED jsoncpp)
endif (${jsoncpp_FOUND})


ExternalProject_Add(
        stun_msg
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party/stun-msg
        PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/third-party/stun-msg
        INSTALL_COMMAND ""
        BUILD_IN_SOURCE 1
)
add_executable(stun main.cpp)

add_dependencies(stun stun_msg)
target_include_directories(
        stun
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/third-party/stun-msg/include
        PRIVATE ${JSONCPP_INCLUDE_DIRS}
)
target_link_libraries(
        stun PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/third-party/stun-msg/libstunmsg.a
        ${JSONCPP_LIBRARIES}
)