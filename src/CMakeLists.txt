# Axel '0vercl0k' Souchet - January 13 2022
cmake_minimum_required(VERSION 3.16.0)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)

project(rp++)

#
# rp++ can be built in two flavours out of the *same* core:
#
#   * OFF (default) - the upstream standalone command line executable.
#   * ON            - a WinDBG extension DLL (rp.dll) that simply consumes the
#                     rp++ core and forwards its output to the debugger.
#
# The rp++ core (everything under rp/ except the entry point) is compiled
# untouched in both cases; only the entry point changes - rp/main.cpp for the
# executable, windbg/rp_windbg.cpp for the extension.
#
option(RP_WINDBG_EXT "Build rp++ as a WinDBG extension DLL instead of the standalone executable" OFF)

if(RP_WINDBG_EXT)
    # windbgext.hpp relies on std::expected.
    set(CMAKE_CXX_STANDARD 23)
endif()

include_directories(${CMAKE_CURRENT_LIST_DIR}/rp)
include_directories(${CMAKE_CURRENT_LIST_DIR}/third_party/fmt/include)
include_directories(${CMAKE_CURRENT_LIST_DIR}/third_party/beaengine/include)
include_directories(${CMAKE_CURRENT_LIST_DIR}/third_party/capstone/include)
include_directories(${CMAKE_CURRENT_LIST_DIR}/third_party/CLI11)

add_compile_definitions(FMT_HEADER_ONLY FMT_UNICODE=0 BEA_ENGINE_STATIC CAPSTONE_HAS_ARM CAPSTONE_HAS_ARM64 CAPSTONE_USE_SYS_DYN_MEM)

if(WIN32)
    set(RP_PLAT "win")
    add_compile_definitions(NOMINMAX)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
elseif(UNIX)
    if(${CMAKE_SYSTEM_NAME} STREQUAL FreeBSD)
        set(RP_PLAT "fbsd")
    elseif(${CMAKE_SYSTEM_NAME} STREQUAL Darwin)
        set(RP_PLAT "osx")
    else()
        set(RP_PLAT "lin")
    endif()
 endif()

set(RP_PLAT "rp-${RP_PLAT}")

#
# The rp++ core: every rp/*.cpp except the standalone entry point (main.cpp),
# plus the third-party disassembly engines.
#
file(
    GLOB
    rp_files
    rp/*.cpp
    third_party/capstone/arch/AArch64/*.c
    third_party/capstone/arch/ARM/*.c
    third_party/capstone/*.c
)
list(REMOVE_ITEM rp_files "${CMAKE_CURRENT_LIST_DIR}/rp/main.cpp")
list(APPEND rp_files "third_party/beaengine/src/BeaEngine.c")

if(RP_WINDBG_EXT)
    #
    # WinDBG extension DLL. The extension is a pure consumer of the core and
    # depends on the DbgEng API, so it is Windows only.
    #
    if(NOT WIN32)
        message(FATAL_ERROR "RP_WINDBG_EXT is only supported on Windows (it links against DbgEng).")
    endif()

    include_directories(${CMAKE_CURRENT_LIST_DIR}/third_party/windbgext)

    add_library(
        rp
        SHARED
        ${rp_files}
        "windbg/rp_windbg.cpp"
    )

    set_target_properties(rp PROPERTIES PREFIX "" OUTPUT_NAME "rp")
    target_link_libraries(rp dbgeng.lib)
else()
    #
    # Upstream standalone executable.
    #
    add_executable(
        ${RP_PLAT}
        ${rp_files}
        "rp/main.cpp"
    )

    if(UNIX)
        find_package(Threads)
        target_link_libraries(${RP_PLAT} ${CMAKE_THREAD_LIBS_INIT})
        if(${RP_PLAT} STREQUAL "rp-osx")
        else()
            target_link_libraries(${RP_PLAT} -static)
        endif()
    endif()
endif()
