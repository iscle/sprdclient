cmake_minimum_required(VERSION 3.27)
project(sprdclient C)

set(CMAKE_C_STANDARD 11)

add_executable(sprdclient main.c)
target_link_libraries(sprdclient usb-1.0)
