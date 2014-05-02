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
#ifndef DISASSENGINEWRAPPER_HPP
#define DISASSENGINEWRAPPER_HPP

#include <string>

struct InstructionInformation
{
    // Generic fields
    std::string disassembly;
    std::string mnemonic;
    unsigned int size;
    unsigned long long address;
    unsigned long long virtual_address_in_memory;

    // BeaEngine fields
    unsigned int bea_branch_type; // This is used by BeaEngine ; and this will hold DISASM.Instruction.BranchType
    unsigned long long bea_addr_value; // This is used by BeaEngine, DISASM.Instruction
};

enum DisassEngineReturn
{
    UnknownInstruction,
    OutOfBlock,
    AllRight
};

class DisassEngineWrapper
{
    public:
        virtual InstructionInformation disass(const unsigned char *data, unsigned long long len, unsigned long long vaddr, DisassEngineReturn &ret) = 0;
        virtual bool is_valid_ending_instruction(InstructionInformation &instr) = 0;
        virtual bool is_valid_instruction(InstructionInformation &instr) = 0;
        virtual unsigned int get_size_biggest_instruction(void) = 0;
        virtual unsigned int get_alignement(void) = 0;
};

#endif