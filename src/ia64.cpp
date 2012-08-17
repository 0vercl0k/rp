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
#include "ia64.hpp"
#include "bearopgadgetfinder.hpp"

Ia64::Ia64(void)
{
}

Ia64::~Ia64(void)
{
}

std::string Ia64::get_class_name(void) const
{
    return std::string("Ia64");
}

std::multiset<Gadget*> Ia64::find_gadget_in_memory(const unsigned char *p_memory, const unsigned long long size, const unsigned long long vaddr, const unsigned int depth, unsigned int engine_display_option)
{
    BeaRopGadgetFinder bea(BeaRopGadgetFinder::IA64, depth, engine_display_option);
    std::multiset<Gadget*> gadgets = bea.find_rop_gadgets(p_memory, size, vaddr);
    return gadgets;
}
