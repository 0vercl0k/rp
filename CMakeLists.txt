# unix => cd build/ && cmake .. && make
cmake_minimum_required(VERSION 2.6)
project(ROPGadget-pp)

# set(CMAKE_BUILD_TYPE Release)
set(CMAKE_BUILD_TYPE Debug)
set(EXECUTABLE_OUTPUT_PATH ../bin/)

include_directories("./src/inc/")

file(
 GLOB_RECURSE
 ropgadget_pp_files
 ./src/*
)

add_executable(
 rp
 ${ropgadget_pp_files}
)
