#include "toolbox.hpp"
#include "rpexception.hpp"

#include <cstring>
#include <cstdlib>

std::string verbosity_to_string(const VerbosityLevel lvl)
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

bool is_hex_char(char c)
{
    return (
        (c >= '0' && c <= '9') ||
        (c >= 'a' && c <= 'f') ||
        (c >= 'A' && c <= 'F')
    );
}

unsigned char * string_to_hex(const char* hex, unsigned int * size)
{
    unsigned char *buffer = NULL;
    unsigned int len = (unsigned int)std::strlen(hex);

    if(len == 0 || len % 4 != 0)
    {
        *size = 0;
        return NULL;
    }

    *size = len / 4;
    
    buffer = new (std::nothrow) unsigned char[sizeof(char) * (*size)];
    if(buffer == NULL)
        RAISE_EXCEPTION("Cannot allocate buffer");

    for(unsigned int i = 0; i < len - 3; i += 4)
    {
        if(
           hex[i] == '\\' && hex[i + 1] == 'x' &&
           is_hex_char(hex[i + 2]) && is_hex_char(hex[i + 3])
        )
        {
            unsigned int byte = std::strtoul(&hex[i + 2], NULL, 16);
            buffer[i / 4] = byte;
        }
        else
            RAISE_EXCEPTION("Your hex values aren't formated correctly");
    }

    return buffer;
}