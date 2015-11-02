/*
    This file is part of rp++.

    Copyright (C) 2014, Axel "0vercl0k" Souchet <0vercl0k at tuxfamily.org>
    All rights reserved.

    rp++ is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    rp++ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with rp++.  If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef PLATFORM_H
#define PLATFORM_H

/*
    Wanna check the macro defined by your compiler on a specific platform ?
    $ touch dummy
    $ cpp -dM dummy
*/

#if defined (__i386__) || defined (_M_IX86)
    #define ARCH_X86
#elif defined(__amd64__) || defined(_M_X64)
    #define ARCH_X64
#else
    #error Platform not supported.
#endif

#if defined (WIN32) || defined (WIN64) || defined (_WIN32) || defined (_WIN64)
    #define WINDOWS

    #define SYSTEM_PLATFORM "Windows"
	#define strcasecmp _stricmp
    #if defined ARCH_X86
        #define WINDOWS_X86
    #elif defined ARCH_X64
        #define WINDOWS_X64
    #endif
#elif defined (linux) || defined (__linux) || defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || defined(__MACH__)
    #define LINUX

    #if defined (linux) || defined (__linux)
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
#define x64Version unsigned long long

#endif
