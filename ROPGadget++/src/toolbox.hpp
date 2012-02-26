#ifndef TOOLBOX_H
#define TOOLBOX_H

#include <string>

/* Choose your verbosity level */
enum VerbosityLevel
{
    VERBOSE_LEVEL_1 = 0,
    VERBOSE_LEVEL_2 = 1,
    VERBOSE_LEVEL_3 = 2
};

std::string verbosity_to_string(VerbosityLevel lvl);

#endif