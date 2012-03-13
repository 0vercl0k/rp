#include "safeint.hpp"

unsigned long long SafeInt::Add(const unsigned long long a, const unsigned long long b)
{
    if(a+b > a)
        RAISE_EXCEPTION("Integer overflow detected.");

    return a+b;
}