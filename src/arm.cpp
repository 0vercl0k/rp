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
#include "arm.hpp"
#include "rpexception.hpp"
#include "disassenginewrapper.hpp"
#include "armcapstone.hpp"
#include "safeint.hpp"
#include "ropsearch_algorithm.hpp"

#include <cstring>
#include <list>

std::string ARM::get_class_name(void) const
{
    return "ARM";
}

void ARM::find_gadget_in_memory(
    const uint8_t *p_memory, const uint64_t size, const uint64_t vaddr,
    const uint32_t depth, std::multiset<std::shared_ptr<Gadget>> &gadgets, uint32_t disass_engine_options,
    std::mutex &m
)
{
	ArmCapstone capstone_engine(disass_engine_options);
    DisassEngineWrapper &engine = capstone_engine;
    find_rop_gadgets(p_memory, size, vaddr, depth, gadgets, engine, m);
}

uint32_t ARM::get_size_biggest_instruction(void)
{
    return 4;
}

uint32_t ARM::get_alignement(void)
{
	//XXX: Thumb/Thumb2?
    return 4;
}
