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

ArmCapstone::ArmCapstone()
{
	if(cs_open(CS_ARCH_ARM, CS_MODE_ARM, &m_handle) != CS_ERR_OK)
		RAISE_EXCEPTION("Apparently no support for ARM in capstone.lib");

	cs_option(m_handle, CS_OPT_DETAIL, CS_OPT_ON);
}

ArmCapstone::~ArmCapstone()
{
	cs_close(&m_handle);
}

InstructionInformation ArmCapstone::disass(const unsigned char *data, unsigned long long len, unsigned long long vaddr, DisassEngineReturn &ret)
{
	InstructionInformation instr;

	cs_insn *insn = NULL;
	size_t count = cs_disasm_ex(m_handle, data, len, vaddr, 1, &insn);
	if(count != 1)
	{
		ret = UnknownInstruction;
		goto end;
	}

	instr.address = (unsigned long long)data;
	instr.virtual_address_in_memory = vaddr;
	instr.mnemonic = std::string(insn[0].mnemonic);
	instr.disassembly = instr.mnemonic + ' ' + std::string(insn[0].op_str);
	instr.size = insn[0].size;

	if(insn[0].detail != NULL)
	{
		for(size_t i = 0; i < insn[0].detail->groups_count; ++i)
		{
			if(insn[0].detail->groups[i] == ARM_GRP_JUMP)
			{
				instr.cap_is_branch = true;
				break;
			}
		}
	}
	else
	{
		instr.cap_is_branch = false;
	}

	end:
	if(insn != NULL)
		cs_free(insn, count);

	return instr;
}

bool ArmCapstone::is_valid_ending_instruction(InstructionInformation &instr)
{
	return true;//instr.cap_is_branch;
}

bool ArmCapstone::is_valid_instruction(InstructionInformation &instr)
{
	return true;//is_valid_ending_instruction(instr) == false;
}

unsigned int ArmCapstone::get_size_biggest_instruction(void)
{
	return ARM::get_size_biggest_instruction();
}

unsigned int ArmCapstone::get_alignement(void)
{
	return ARM::get_alignement();
}