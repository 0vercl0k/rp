#include "elf_struct.hpp"

std::string type_to_str(const unsigned int p_type)
{
    std::string ret("unknown type");

    switch(p_type)
    {
    case 0:
        ret = "NULL";
        break;

    case 1:
        ret = "LOAD";
        break;

    case 2:
        ret = "DYNAMIC";
        break;

    case 3:
        ret = "INTERP";
        break;

    case 4:
        ret = "NOTE";
        break;

    case 5:
        ret = "SHLIB";
        break;

    case 6:
        ret = "PHDR";
        break;

    case 7:
        ret = "TLS";
        break;

    case 8:
        ret = "NUM";
        break;

    case 0x60000000:
        ret = "LOOS";
        break;

    case 0x6fffffff:
        ret = "HIOS";
        break;

    case 0x70000000:
        ret = "LOPROC";
        break;

    case 0x7fffffff:
        ret = "HIPROC";
        break;

    case 0x6474e550:
        ret = "EH_FRAME";
        break;

    case 0x6474e551:
        ret = "STACK";
        break;

    case 0x6474e552:
        ret = "RELRO";
        break;

    case  0x65041580:
        ret = "PAX_FLAGS";
        break;
    }

    return ret;
}

std::string flags_to_str(const unsigned int p_flags)
{
    std::string ret(3, '-');

    if(p_flags & 4)
        ret[0] = 'r';

    if(p_flags & 2)
        ret[1] = 'w';

    if(p_flags & 1)
        ret[2] = 'x';

    return ret;
}