#ifndef SAFE_INT
#define SAFE_INT

#include "rpexception.hpp"

/*
    The purpose of this class is to avoid integer overflow ; if one is detected, an exception is raised
*/
class SafeInt
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