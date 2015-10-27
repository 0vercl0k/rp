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
#ifndef ARM_H
#define ARM_H

#include <vector>
#include "cpu.hpp"

class ARM : public CPU
{
    public:

        std::string get_class_name(void) const;
        
        void find_gadget_in_memory(
			const unsigned char *p_memory,
			const unsigned long long size,
			const unsigned long long vaddr,
			const unsigned int depth,
			std::multiset<std::shared_ptr<Gadget>> &gadgets,
            unsigned int disass_engine_options,
            std::mutex &m
		);

        static unsigned int get_size_biggest_instruction(void);

        static unsigned int get_alignement(void);
};

#endif
