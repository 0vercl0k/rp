#ifndef MAIN_HPP
#define MAIN_HPP

#include "platform.h"

/*
    If you don't want any colors if your shell, you can disable it in coloshell.hpp -- just comment the #define
*/

#define MAXIMUM_INSTRUCTION_PER_GADGET 20  // it defines the maximum number of instruction per gadget

#define NUM_V "0.3"

#ifdef ARCH_X64
#define VERSION_TMP NUM_V " x64 built the " __DATE__ " " __TIME__
#else
#define VERSION_TMP NUM_V " x86 built the " __DATE__ " " __TIME__
#endif

#ifdef WINDOWS
#define VERSION_TM VERSION_TMP " for Windows"
#else
#define VERSION_TM VERSION_TMP " for Unix"
#endif

#ifdef _DEBUG
#define VERSION VERSION_TM " (Debug)"
#else
#define VERSION VERSION_TM " (Release)"
#endif

#endif
