cmake_minimum_required(VERSION 3.0)
project(stun-client)
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


add_subdirectory(third-party/stun-msg)
add_executable(stun-client src/main.cpp)
target_include_directories(
        stun-client
        PRIVATE include
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/third-party
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/third-party/stun-msg/include
        PRIVATE ${JSONCPP_INCLUDE_DIRS}
)
target_link_libraries(
        stun-client PRIVATE
        stunmsg
        ${JSONCPP_LIBRARIES}
)
install(TARGETS stun-client)