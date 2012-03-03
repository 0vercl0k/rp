#include "toolbox.hpp"

std::string verbosity_to_string(VerbosityLevel lvl)
{
    std::string s("");

    switch(lvl)
    {
        case VERBOSE_LEVEL_1:
        {
            s = "VERBOSE_LEVEL_1";
            break;
        }

        case VERBOSE_LEVEL_2:
        {
            s = "VERBOSE_LEVEL_2";
            break;
        }

        case VERBOSE_LEVEL_3:
        {
            s = "VERBOSE_LEVEL_3";
            break;
        }
    }

    return s;
}

std::streampos get_file_size(std::ifstream &file)
{
    std::streampos backup = file.tellg();

    file.seekg(0, std::ios::beg);
    std::streampos fsize = file.tellg();

    file.seekg(0, std::ios::end );
    fsize = file.tellg() - fsize;
    
    file.seekg(backup);
    return fsize;
}
