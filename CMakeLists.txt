# unix => cd build/ && cmake .. && make
cmake_minimum_required(VERSION 2.8.0)
project(rp++)

option (optX86BUILD "Generate an x86 executable" OFF)


set(CMAKE_BUILD_TYPE Release)
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

set(RP_NAME "${RP_NAME}-${RP_PLAT}")

if(CMAKE_SIZEOF_VOID_P EQUAL 8 AND NOT(optX86BUILD))
    set(FLAG_CXX "-m64")
    set(RP_NAME "${RP_NAME}-x64")
else()
    set(FLAG_CXX "-m32")
    set(RP_NAME "${RP_NAME}-x86")
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

        set(${flag_var} "${${flag_var}} /D_CRT_SECURE_NO_WARNINGS /DCAPSTONE_HAS_X86 /DCAPSTONE_HAS_ARM /DCAPSTONE_X86_ATT_DISABLE /DCAPSTONE_USE_SYS_DYN_MEM")
    endforeach()

    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /NODEFAULTLIB:crt64.lib")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /NODEFAULTLIB:crt.lib")
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -O2 -fPIC -std=c++11 -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security -fstack-protector -DCAPSTONE_HAS_X86 -DCAPSTONE_HAS_ARM -DCAPSTONE_X86_ATT_DISABLE -DCAPSTONE_USE_SYS_DYN_MEM -DCAPSTONE_STATIC ${FLAG_CXX}")
    set(CMAKE_C_FLAGS "${CMAKE_CXX_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lpthread")
endif()

include_directories("./src/inc/")
include_directories("./lib/beaengine/include/")
include_directories("./lib/capstone/include/")
include_directories("./lib/argtable3/")

file(
    GLOB_RECURSE
    ropgadget_pp_files
    ./src/*
)

file(
    GLOB_RECURSE
    capstone_pp_files_arch
    ./lib/capstone/arch/*.c
    ./lib/capstone/arch/*.h
)

file(
    GLOB
    capstone_pp_files
    ./lib/capstone/*.c
    ./lib/capstone/*.h
)

# Filters for VS solution
source_group("capstone" FILES ${capstone_pp_files_arch} ${capstone_pp_files})
source_group("argtable3" FILES "./lib/argtable3/argtable3.c" "./lib/argtable3/argtable3.h")
source_group("beaengine" FILES "./lib/beaengine/src/BeaEngine.c")

set(Boost_USE_STATIC_LIBS ON) # only find static libs
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME    OFF)
find_package(Boost)
if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
    add_executable(
        ${RP_NAME}
        ${ropgadget_pp_files}
        ${capstone_pp_files_arch} ${capstone_pp_files}
        "./lib/beaengine/src/BeaEngine.c"
        "./lib/argtable3/argtable3.c" "./lib/argtable3/argtable3.h"
    )

  target_link_libraries(${RP_NAME} ${Boost_LIBRARIES})
else()
    message(SEND_ERROR "find_package could not find boost159 - please install it!")
endif()
