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
#ifndef ARMCAPSTONE_HPP
#define ARMCAPSTONE_HPP

#include "capstone.h"
#include "disassenginewrapper.hpp"


class ArmCapstone : public DisassEngineWrapper
{
    public:
        explicit ArmCapstone(uint32_t thumb_mode);
        ~ArmCapstone();
        InstructionInformation disass(const unsigned char *data, unsigned long long len, unsigned long long vaddr, DisassEngineReturn &ret);
        bool is_valid_ending_instruction(InstructionInformation &instr);
        bool is_valid_instruction(InstructionInformation &instr);
        uint32_t get_size_biggest_instruction(void);
        uint32_t get_alignement(void);

	private:
		csh m_handle;
		bool is_thumb;
};

#endif