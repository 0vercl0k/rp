// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#if defined(__i386__) || defined(_M_IX86)
#define ARCH_X86
#elif defined(__amd64__) || defined(_M_X64)
#define ARCH_X64
#else
#error Platform not supported.
#endif

#if defined(WIN32) || defined(WIN64) || defined(_WIN32) || defined(_WIN64)
#define WINDOWS

#define SYSTEM_PLATFORM "Windows"
#define strcasecmp _stricmp
#if defined ARCH_X86
#define WINDOWS_X86
#elif defined ARCH_X64
#define WINDOWS_X64
#endif
#elif defined(linux) || defined(__linux) || defined(__FreeBSD__) ||            \
    defined(__FreeBSD_kernel__) || defined(__MACH__)
#define LINUX

#if defined(linux) || defined(__linux)
#define SYSTEM_PLATFORM "Linux"
#elif defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
#define SYSTEM_PLATFORM "FreeBSD"
#elif defined(__MACH__)
#define SYSTEM_PLATFORM "Mac OSX"
#else
#error An error occured
#endif

#if defined ARCH_X86
#define LINUX_X86
#elif defined ARCH_X64
#define LINUX_X64
#endif

#else
#error Platform not supported.
#endif

#ifdef WINDOWS
#undef UNICODE
#endif

#ifdef LINUX
#endif

#define x86Version uint32_t
#define x64Version uint64_t
