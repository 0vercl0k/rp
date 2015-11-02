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
#include "elf_struct.hpp"

std::string type_to_str(const uint32_t p_type)
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

std::string flags_to_str(const uint32_t p_flags)
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
