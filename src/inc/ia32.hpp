/*
    This file is part of rp++.

    Copyright (C) 2012, Axel "0vercl0k" Souchet <0vercl0k at tuxfamily.org>
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
#ifndef IA32_H
#define IA32_H

#include <vector>
#include "cpu.hpp"

class Ia32 : public CPU
{
    public:

        explicit Ia32(void);
        
        ~Ia32(void);

        std::string get_class_name(void) const;
        
        std::multiset<Gadget*> find_gadget_in_memory(const unsigned char *p_memory, const unsigned long long size, const unsigned long long vaddr, const unsigned int depth, unsigned int engine_display_option = 0);

    private:
        
        std::vector<Gadget> m_gadgets;
};

#endif
