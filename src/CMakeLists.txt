# Axel '0vercl0k' Souchet - January 13 2022
cmake_minimum_required(VERSION 3.16.0)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)

project(rp++)
include_directories(${CMAKE_CURRENT_LIST_DIR}/third_party/fmt/include)
include_directories(${CMAKE_CURRENT_LIST_DIR}/third_party/beaengine/include)
include_directories(${CMAKE_CURRENT_LIST_DIR}/third_party/capstone/include)
include_directories(${CMAKE_CURRENT_LIST_DIR}/third_party/CLI11)

add_compile_definitions(FMT_HEADER_ONLY BEA_ENGINE_STATIC CAPSTONE_HAS_ARM CAPSTONE_USE_SYS_DYN_MEM)

if(WIN32)
    set(RP_PLAT "win")
    add_compile_definitions(NOMINMAX)
elseif(UNIX)
    if(${CMAKE_SYSTEM_NAME} STREQUAL FreeBSD)
        set(RP_PLAT "fbsd")
    elseif(${CMAKE_SYSTEM_NAME} STREQUAL Darwin)
        set(RP_PLAT "osx")
    else()
        set(RP_PLAT "lin")
    endif()
 endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(RP_PLAT "rp-${RP_PLAT}-x64")
else()
    set(RP_PLAT "rp-${RP_PLAT}-x86")
endif()

file(
    GLOB
    rp_files
    rp/*.cpp
    third_party/capstone/arch/ARM/*.c
    third_party/capstone/*.c
)

add_executable(
    ${RP_PLAT}
    ${rp_files}
    "third_party/beaengine/src/BeaEngine.c"
)

if(UNIX)
    find_package(Threads)
    target_link_libraries(${RP_PLAT} ${CMAKE_THREAD_LIBS_INIT})
endif()