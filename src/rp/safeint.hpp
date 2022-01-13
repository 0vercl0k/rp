// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "rpexception.hpp"
#include <numeric>

// The purpose of this class is to avoid integer overflow ; if one is detected,
// an exception is raised
template <class T>
typename std::enable_if<std::is_unsigned<T>::value, T>::type
SafeIntAdd(const T a, const T b) {
  if (a > (std::numeric_limits<T>::max() - b)) {
    RAISE_EXCEPTION("Integer-overflow detected.");
  }

  return a + b;
}
