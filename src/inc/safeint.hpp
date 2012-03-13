#ifndef SAFE_INT
#define SAFE_INT

#include "rpexception.hpp"

/*
    The purpose of this class is to avoid integer overflow ; if one is detected, an exception is raised
*/
class SafeInt
{
    static inline unsigned long long Add(const unsigned long long a, const unsigned long long b);
};

#endif