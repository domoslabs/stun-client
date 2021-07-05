cmake_minimum_required(VERSION 3.19)
project(stun)

set(CMAKE_CXX_STANDARD 11)

add_executable(stun main.cpp stun.cpp stun.h)