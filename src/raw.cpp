/*
    This file is part of rp++.

    Copyright (C) 2013, Axel "0vercl0k" Souchet <0vercl0k at tuxfamily.org>
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
#include "raw.hpp"
#include "rpexception.hpp"

Raw::Raw(void)
{
}

Raw::~Raw(void)
{
}

std::string Raw::get_class_name(void) const
{
    return std::string("raw");
}

std::vector<Section*> Raw::get_executables_section(std::ifstream & file)
{
    std::vector<Section*> executable_sections;

    unsigned long long raw_file_size = get_file_size(file);
    
    /* It is a raw file -> we have only one "virtual" section */
    Section *sect = new (std::nothrow) Section(
        ".raw",
        0,
        0,
        raw_file_size
    );

    if(sect == NULL)
        RAISE_EXCEPTION("Cannot allocate sect");
    
    sect->dump(file);
    sect->set_props(Section::Executable);

    executable_sections.push_back(sect);
    
    return executable_sections;
}

unsigned long long Raw::raw_offset_to_va(const unsigned long long absolute_raw_offset, const unsigned long long absolute_raw_offset_section) const
{
    return absolute_raw_offset;
}
