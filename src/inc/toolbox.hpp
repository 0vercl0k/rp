#ifndef TOOLBOX_H
#define TOOLBOX_H

#include <string>
#include <fstream>

/* Choose your verbosity level */
enum VerbosityLevel
{
    VERBOSE_LEVEL_1 = 1,
    VERBOSE_LEVEL_2 = 2,
    VERBOSE_LEVEL_3 = 3
};

std::string verbosity_to_string(VerbosityLevel lvl);

std::streampos get_file_size(std::ifstream &file);

unsigned char * string_to_hex(const char* hex, unsigned int * size);

#endif