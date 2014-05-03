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
#include "intelbeaengine.hpp"
#include "x64.hpp"
#include "x86.hpp"

IntelBeaEngine::IntelBeaEngine(E_Arch arch)
: m_arch(arch)
{
    memset(&m_disasm, 0, sizeof(DISASM));

    /* those options are mostly display option for the disassembler engine */
    m_disasm.Options = PrefixedNumeral + NasmSyntax;

    /* this one is to precise what architecture we'll disassemble */
    m_disasm.Archi = m_arch;
}

InstructionInformation IntelBeaEngine::disass(const unsigned char *data, unsigned long long len, unsigned long long vaddr, DisassEngineReturn &ret)
{
    InstructionInformation instr;
    m_disasm.EIP = (UIntPtr)data;
    m_disasm.VirtualAddr = vaddr;
    m_disasm.SecurityBlock = (unsigned int)len;
 
    int len_instr = Disasm(&m_disasm);
    if(len_instr == OUT_OF_BLOCK)
    {
        ret = OutOfBlock;
        goto end;
    }

    /* OK this one is an unknow opcode, goto the next one */
    if(len == UNKNOWN_OPCODE)
    {
        ret = UnknownInstruction;
        goto end;
    }

    ret = AllRight;
    

    instr.address = m_disasm.EIP;
    instr.virtual_address_in_memory = m_disasm.VirtualAddr;
    instr.disassembly = std::string(m_disasm.CompleteInstr);
    instr.mnemonic = std::string(m_disasm.Instruction.Mnemonic);
    instr.size = len_instr;

    instr.bea_branch_type = m_disasm.Instruction.BranchType;
    instr.bea_addr_value = m_disasm.Instruction.AddrValue;
    
    end:
    return instr;
}

bool IntelBeaEngine::is_valid_ending_instruction(InstructionInformation &instr)
{
    /*
        Work Around, BeaEngine in x64 mode disassemble "\xDE\xDB" as an instruction without disassembly
        Btw, this is not the only case!
    */
    if(instr.disassembly != "")
    {
        unsigned int branch_type = instr.bea_branch_type;
        unsigned long long addr_value = instr.bea_addr_value;

        std::string mnemonic = instr.mnemonic;
        const char *mnemonic_s = mnemonic.c_str();

        std::string disass = instr.disassembly;
        const char *disass_s = disass.c_str();

        bool is_good_branch_type = (
            /* We accept all the ret type instructions (except retf/iret) */
            (branch_type == RetType && (strncmp(mnemonic_s, "retf", 4) != 0) && (strncmp(mnemonic_s, "iretd", 5) != 0)) || 

            /* call reg32 / call [reg32] */
            (branch_type == CallType && addr_value == 0) ||

            /* jmp reg32 / jmp [reg32] */
            (branch_type == JmpType && addr_value == 0) ||

            /* int 0x80 & int 0x2e */
            ((strncmp(disass_s, "int 0x80", 8) == 0) || (strncmp(disass_s, "int 0x2e", 8) == 0) || (strncmp(disass_s, "syscall", 7) == 0))
        );

        return (
            is_good_branch_type && 

            /* Yeah, entrance isn't allowed to the jmp far/call far */
            disass.find("far") == std::string::npos
        );
    }

    return false;
}

bool IntelBeaEngine::is_valid_instruction(InstructionInformation &instr)
{
    Int32 branch_type = instr.bea_branch_type;

    return (
        /*
            Work Around, BeaEngine in x64 mode disassemble "\xDE\xDB" as an instruction without disassembly
            Btw, this is not the only case!
        */
        instr.disassembly != "" &&
        branch_type != RetType && 
        branch_type != JmpType &&
        branch_type != CallType &&
        branch_type != JE &&
        branch_type != JB &&
        branch_type != JC &&
        branch_type != JO &&
        branch_type != JA &&
        branch_type != JS &&
        branch_type != JP &&
        branch_type != JL &&
        branch_type != JG &&
        branch_type != JNE &&
        branch_type != JNB &&
        branch_type != JNC &&
        branch_type != JNO &&
        branch_type != JECXZ &&
        branch_type != JNA &&
        branch_type != JNS &&
        branch_type != JNP &&
        branch_type != JNL &&
        branch_type != JNG &&
        branch_type != JNB &&
        instr.disassembly.find("far") == std::string::npos
    );
}

unsigned int IntelBeaEngine::get_size_biggest_instruction(void)
{
    if(m_arch == x86)
        return x86::get_size_biggest_instruction();
    else
        return x64::get_size_biggest_instruction();
}

unsigned int IntelBeaEngine::get_alignement(void)
{
    if(m_arch == x86)
        return x86::get_alignement();
    else
        return x64::get_alignement();
}