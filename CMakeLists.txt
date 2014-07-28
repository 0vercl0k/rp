# unix => cd build/ && cmake .. && make
cmake_minimum_required(VERSION 2.6)
project(rp++)

option (optX86BUILD "Generate an x86 executable" OFF)


set(CMAKE_BUILD_TYPE Release)
# set(CMAKE_BUILD_TYPE Debug)
set(EXECUTABLE_OUTPUT_PATH ../bin/)

set(RP_NAME "rp")

if(WIN32)
    set(RP_PLAT "win")
    set(EXTENSION_LIBRARY lib)
endif()

if(UNIX)
    if(${CMAKE_SYSTEM_NAME} STREQUAL FreeBSD)
        set(RP_PLAT "fbsd")
    elseif(${CMAKE_SYSTEM_NAME} STREQUAL Darwin)
        set(RP_PLAT "osx")
    else()
        set(RP_PLAT "lin")
    endif()
    set(EXTENSION_LIBRARY a)
endif()

if(FBSD)
    set(RP_PLAT "fbsd")
    set(EXTENSION_LIBRARY a)
endif()

set(RP_NAME "${RP_NAME}-${RP_PLAT}")

if(CMAKE_SIZEOF_VOID_P EQUAL 8 AND NOT(optX86BUILD))
    set(FLAG_CXX "-m64")
    set(RP_NAME "${RP_NAME}-x64")
    set(BEA_LIBRARY "BeaEngine.x64.${RP_PLAT}.${EXTENSION_LIBRARY}")
    set(ARGTABLE_LIBRARY "argtable2.x64.${RP_PLAT}.${EXTENSION_LIBRARY}")
    set(CAPSTONE_LIBRARY "capstone.x64.${RP_PLAT}.${EXTENSION_LIBRARY}")
else()
    set(FLAG_CXX "-m32")
    set(RP_NAME "${RP_NAME}-x86")
    set(BEA_LIBRARY "BeaEngine.x86.${RP_PLAT}.${EXTENSION_LIBRARY}")
    set(ARGTABLE_LIBRARY "argtable2.x86.${RP_PLAT}.${EXTENSION_LIBRARY}")
    set(CAPSTONE_LIBRARY "capstone.x86.${RP_PLAT}.${EXTENSION_LIBRARY}")
endif()

if(MSVC)
    # link the CRT 
    foreach(flag_var CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO)
        if(${flag_var} MATCHES "/MD")
            string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
        endif()

        if(${flag_var} MATCHES "/MDd")
            string(REGEX REPLACE "/MDd" "/MTd" ${flag_var} "${${flag_var}}")
        endif()
    endforeach()
endif()

if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -O2 -static -s -std=c++0x ${FLAG_CXX}")
endif()

include_directories("./src/inc/")
include_directories("./lib/beaengine/inc/")
include_directories("./lib/argtable2/inc/")
include_directories("./lib/capstone/inc/")

file(
    GLOB_RECURSE
    ropgadget_pp_files
    ./src/*
)

add_executable(
    ${RP_NAME}
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

add_library(capstone STATIC IMPORTED)
set_property(
    TARGET capstone PROPERTY
    IMPORTED_LOCATION ../lib/capstone/bin/${CAPSTONE_LIBRARY}
)

target_link_libraries(
    ${RP_NAME}
    beaengine
    argtable2
    capstone
)

if(WIN32)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /NODEFAULTLIB:crt64.lib")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /NODEFAULTLIB:crt.lib")
endif()
