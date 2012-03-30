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
    set(BEA_LIBRARY "BeaEngine64${EXTENSION_LIBRARY}")
    set(ARGTABLE_LIBRARY "argtable2.x64${EXTENSION_LIBRARY}")
else()
    set(BEA_LIBRARY "BeaEngine32${EXTENSION_LIBRARY}")
    set(ARGTABLE_LIBRARY "argtable2.x86${EXTENSION_LIBRARY}")
endif(CMAKE_SIZEOF_VOID_P EQUAL 8)

#if(MSVC)
    # link the CRT 
#    foreach(flag_var CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO)
#        if(${flag_var} MATCHES "/MD")
#            string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
#        endif(${flag_var} MATCHES "/MD")

#        if(${flag_var} MATCHES "/MDd")
#            string(REGEX REPLACE "/MDd" "/MTd" ${flag_var} "${${flag_var}}")
#        endif(${flag_var} MATCHES "/MDd")
#    endforeach(flag_var)
#endif(MSVC)

if(CMAKE_COMPILER_IS_GNUCXX)
    # an optimized static striped binary !
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -static -s")
endif(CMAKE_COMPILER_IS_GNUCXX)

include_directories("./src/inc/")
include_directories("./lib/beaengine/inc/")
include_directories("./lib/argtable2/inc/")

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
    IMPORTED_LOCATION ../lib/beaengine/bin/${BEA_LIBRARY}
)

add_library(argtable2 STATIC IMPORTED)
set_property(
    TARGET argtable2 PROPERTY
    IMPORTED_LOCATION ../lib/argtable2/bin/${ARGTABLE_LIBRARY}
)

target_link_libraries(
    rp
    beaengine
    argtable2
)

if(WIN32)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /NODEFAULTLIB:crt64.lib")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /NODEFAULTLIB:crt.lib")
endif(WIN32)
