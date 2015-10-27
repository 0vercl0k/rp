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
#include "armcapstone.hpp"
#include "arm.hpp"
#include "rpexception.hpp"

ArmCapstone::ArmCapstone(unsigned int thumb_mode)
: is_thumb(true)
{
	cs_mode mode = CS_MODE_THUMB;
	if(thumb_mode == 0)
	{
		mode = CS_MODE_ARM;
		is_thumb = false;
	}

	if(cs_open(CS_ARCH_ARM, mode, &m_handle) != CS_ERR_OK)
		RAISE_EXCEPTION("Apparently no support for ARM in capstone.lib");

	cs_option(m_handle, CS_OPT_DETAIL, CS_OPT_ON);
}

InstructionInformation ArmCapstone::disass(const unsigned char *data, unsigned long long len, unsigned long long vaddr, DisassEngineReturn &ret)
{
	InstructionInformation instr;
	cs_insn *insn = nullptr;

	if(len == 0)
		len = 4;

	size_t count = cs_disasm_ex(m_handle, data, (size_t)len, vaddr, 1, &insn);
	if(count != 1)
	{
		ret = UnknownInstruction;
		goto end;
	}

	instr.address = (uintptr_t)data;
	instr.virtual_address_in_memory = (uintptr_t)vaddr;
	instr.mnemonic = std::string(insn[0].mnemonic);
	instr.disassembly = instr.mnemonic + ' ' + std::string(insn[0].op_str);
	instr.size = insn[0].size;

	instr.cap_is_branch = false;
	instr.cap_is_valid_ending_instr = false;
	if(insn[0].detail != nullptr)
	{
		if(cs_insn_group(m_handle, insn, ARM_GRP_JUMP))
		{
			instr.cap_is_branch = true;
			if(insn[0].detail->arm.op_count == 1)
				if(insn[0].detail->arm.operands[0].type != ARM_OP_IMM)
					instr.cap_is_valid_ending_instr = true;
		}
		else if(instr.mnemonic == "b" || instr.mnemonic == "bl" || instr.mnemonic == "blx" || instr.mnemonic == "cb" || instr.mnemonic == "cbz")
		{
			instr.cap_is_branch = true;
		}
		else if(instr.mnemonic == "swi" || instr.mnemonic == "svc")
		{
			instr.cap_is_branch = true;
			instr.cap_is_valid_ending_instr = true;
		}
		else if(instr.mnemonic == "mov")
		{
			if(insn[0].detail->arm.op_count >= 1)
			{
				if(insn[0].detail->arm.operands[0].type == ARM_OP_REG && insn[0].detail->arm.operands[0].reg == ARM_REG_PC)
				{
					instr.cap_is_branch = true;
					instr.cap_is_valid_ending_instr = true;
				}
			}
		}
		else if(instr.mnemonic == "bx")
		{
			instr.cap_is_branch = true;
			if(insn[0].detail->arm.operands[0].type == ARM_OP_REG)
				instr.cap_is_valid_ending_instr = true;
		}
		else if(instr.mnemonic == "blx")
		{
			instr.cap_is_branch = true;
			instr.cap_is_valid_ending_instr = true;
		}
		else if(instr.mnemonic == "pop")
		{
			bool has_pc = false;
			for(size_t i = 0; i < insn[0].detail->arm.op_count; ++i)
			{
				if(insn[0].detail->arm.operands[i].type == ARM_OP_REG && insn[0].detail->arm.operands[i].reg == ARM_REG_PC)
				{
					has_pc = true;
					break;
				}
			}

			if(has_pc)
			{
				instr.cap_is_branch = true;
				instr.cap_is_valid_ending_instr = true;
			}
		}
	}

	ret = AllRight;

	end:
	if(insn != nullptr)
		cs_free(insn, count);

	return instr;
}

bool ArmCapstone::is_valid_ending_instruction(InstructionInformation &instr)
{
	return instr.cap_is_valid_ending_instr;
}

bool ArmCapstone::is_valid_instruction(InstructionInformation &instr)
{
	return instr.cap_is_branch == false;
}

unsigned int ArmCapstone::get_size_biggest_instruction(void)
{
	return ARM::get_size_biggest_instruction();
}

unsigned int ArmCapstone::get_alignement(void)
{
	if(is_thumb)
		return 2;

	return ARM::get_alignement();
}