cmake_minimum_required(VERSION 3.6)
project(Lab2_TDTS06)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -W")

set(SOURCE_FILES main.c)
add_executable(Lab2_TDTS06 ${SOURCE_FILES})