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
#include "ia32.hpp"
#include "rpexception.hpp"
#include "bearopgadgetfinder.hpp"

#include <cstring>
#include <list>

Ia32::Ia32(void)
{
}

Ia32::~Ia32(void)
{
}

std::string Ia32::get_class_name(void) const
{
    return std::string("Ia32");
}

std::multiset<Gadget*> Ia32::find_gadget_in_memory(const unsigned char *p_memory, const unsigned long long size, const unsigned long long vaddr, const unsigned int depth, unsigned int engine_display_option)
{  
    BeaRopGadgetFinder bea(BeaRopGadgetFinder::IA32, depth, engine_display_option);
    std::multiset<Gadget*> gadgets = bea.find_rop_gadgets(p_memory, size, vaddr);
    return gadgets;
}
