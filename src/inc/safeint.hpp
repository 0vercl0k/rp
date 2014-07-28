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
#ifndef SAFE_INT
#define SAFE_INT

#include "rpexception.hpp"

#define SafeAddU32(a, b) SafeInt::Add<unsigned int>(a, b)
#define SafeAddU64(a, b) SafeInt::Add<unsigned long long>(a, b)

/*
    The purpose of this class is to avoid integer overflow ; if one is detected, an exception is raised
*/
struct SafeInt
{
    template<class T>
    static inline T Add(const T a, const T b)
    {
        T result = a + b;
        if(result < a)
            RAISE_EXCEPTION("Integer overflow detected.");

        return result;
    }
};

#endif
