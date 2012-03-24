# unix => cd build/ && cmake .. && make
cmake_minimum_required(VERSION 2.6)
project(ROPGadget-pp)

# set(CMAKE_BUILD_TYPE Release)
set(CMAKE_BUILD_TYPE Debug)
set(EXECUTABLE_OUTPUT_PATH ../bin/)

if(WIN32)
    set(EXTENSION_LIBRARY .lib)
endif(WIN32)

if(UNIX)
    set(EXTENSION_LIBRARY .a)
endif(UNIX)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(NAME_LIBRARY "BeaEngine64${EXTENSION_LIBRARY}")
else()
    set(NAME_LIBRARY "BeaEngine32${EXTENSION_LIBRARY}")
endif(CMAKE_SIZEOF_VOID_P EQUAL 8)



if(CMAKE_COMPILER_IS_GNUCXX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")
endif(CMAKE_COMPILER_IS_GNUCXX)

include_directories("./src/inc/")
include_directories("./lib/beaengine/inc/")

file(
    GLOB_RECURSE
    ropgadget_pp_files
    ./src/*
)

add_executable(
    rp
    ${ropgadget_pp_files}
)

add_library(beaengine STATIC IMPORTED)
set_property(
    TARGET beaengine PROPERTY
    IMPORTED_LOCATION ../lib/beaengine/bin/${NAME_LIBRARY}
)

target_link_libraries(
    rp
    beaengine
)

if(WIN32)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /NODEFAULTLIB:crt64.lib")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /NODEFAULTLIB:crt.lib")
endif(WIN32)
