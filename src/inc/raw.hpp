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
#ifndef RAW_HPP
#define RAW_HPP

#include "executable_format.hpp"

class Raw : public ExecutableFormat
{
    public:
        
        explicit Raw(void);

        ~Raw(void);

        CPU* get_cpu(std::ifstream &file)
        {
            /* Don't need this method */
            return NULL;
        }

        std::string get_class_name(void) const;

        std::vector<Section*> get_executables_section(std::ifstream & file);

        unsigned long long raw_offset_to_va(const unsigned long long absolute_raw_offset, const unsigned long long absolute_raw_offset_section) const;
};

#endif
