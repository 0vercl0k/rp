#ifndef PLATFORM_H
#define PLATFORM_H

/*
    Wanna check the macro defined by your compiler on a specific platform ?
    $ touch dummy
    $ cpp -dM dummy
*/

#if defined (__i386__) || defined (_M_IX86)
	#define ARCH_X86
#elif defined (__ia64__) || defined(__amd64__) || defined (_M_IA64) || defined(_M_X64)
	#define ARCH_X64
#else
	#error Platform not supported.
#endif

#if defined (WIN32) || defined (WIN64) || defined (_WIN32) || defined (_WIN64)
	#define WINDOWS

	#if defined ARCH_X86
		#define WINDOWS_X86
	#elif defined ARCH_X64
		#define WINDOWS_X64
	#endif
#elif defined (linux) || defined (__linux) || defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || defined(__MACH__)
	#define LINUX

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

#define x86Version unsigned int
#define x64Version unsigned long long


/* This type will have the same size that your CPU registers */
#ifdef ARCH_X86
#define ptr_t unsigned int
#else
#define ptr_t unsigned long long
#endif

#endif
