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
endif(WIN32)

if(UNIX)
    if(${CMAKE_SYSTEM_NAME} STREQUAL FreeBSD)
        set(RP_PLAT "fbsd")
    elseif(${CMAKE_SYSTEM_NAME} STREQUAL Darwin)
        set(RP_PLAT "osx")
    else()
        set(RP_PLAT "lin")
    endif()
    set(EXTENSION_LIBRARY a)
endif(UNIX)

if(FBSD)
    set(RP_PLAT "fbsd")
    set(EXTENSION_LIBRARY a)
endif(FBSD)

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
endif(CMAKE_SIZEOF_VOID_P EQUAL 8 AND NOT(optX86BUILD))

if(MSVC)
    # link the CRT 
    foreach(flag_var CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO)
        if(${flag_var} MATCHES "/MD")
            string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
        endif(${flag_var} MATCHES "/MD")

        if(${flag_var} MATCHES "/MDd")
            string(REGEX REPLACE "/MDd" "/MTd" ${flag_var} "${${flag_var}}")
        endif(${flag_var} MATCHES "/MDd")
    endforeach(flag_var)
endif(MSVC)

if(CMAKE_COMPILER_IS_GNUCXX)
    # an optimized secure static striped binary !
    # btw if you want a full secure binary, disable the -static option (with static you can have only partial relro & no cookie)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -O2 -static -s -Wl,-z,relro,-z,now -fstack-protector-all ${FLAG_CXX}")
endif(CMAKE_COMPILER_IS_GNUCXX)

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
endif(WIN32)
