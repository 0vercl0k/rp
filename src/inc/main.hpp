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
#ifndef MAIN_HPP
#define MAIN_HPP

// Using Visual Leak Detector (https://vld.codeplex.com/releases) to track memory leaks
// #include "vld.h"
#include "platform.h"

/*
	If you don't want any colors if your shell, you can disable it in coloshell.hpp -- just comment the #define
*/

#define MAXIMUM_INSTRUCTION_PER_GADGET 20  // it defines the maximum number of instruction per gadget

#define NUM_V "2.0-beta"

#ifdef ARCH_X64
#define VERSION_TMP NUM_V " x64 built the " __DATE__ " " __TIME__
#else
#define VERSION_TMP NUM_V " x86 built the " __DATE__ " " __TIME__
#endif

#define VERSION_TM VERSION_TMP " for " SYSTEM_PLATFORM

#ifdef _DEBUG
#define VERSION VERSION_TM " (Debug)"
#else
#define VERSION VERSION_TM " (Release)"
#endif

#endif
