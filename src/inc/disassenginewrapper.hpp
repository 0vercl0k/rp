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
#include <vector>

struct InstructionInformation
{
    // Generic fields
    std::string disassembly;
    std::string mnemonic;
    uint32_t size;
    uintptr_t address;
    uintptr_t virtual_address_in_memory;

    std::vector<uint8_t> bytes;

	// Capstone field
	bool cap_is_branch;
	bool cap_is_valid_ending_instr;

    // BeaEngine fields
    uint32_t bea_branch_type; // This is used by BeaEngine ; and this will hold DISASM.Instruction.BranchType
    uint64_t bea_addr_value; // This is used by BeaEngine, DISASM.Instruction
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
		virtual ~DisassEngineWrapper() { };
        virtual InstructionInformation disass(const uint8_t *data, uint64_t len, uint64_t vaddr, DisassEngineReturn &ret) = 0;
        virtual bool is_valid_ending_instruction(InstructionInformation &instr) const = 0;
        virtual bool is_valid_instruction(InstructionInformation &instr) const = 0;
        virtual uint32_t get_size_biggest_instruction(void) const = 0;
        virtual uint32_t get_alignement(void) const = 0;
};

#endif