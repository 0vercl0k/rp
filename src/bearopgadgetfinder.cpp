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
#include "bearopgadgetfinder.hpp"
#include "safeint.hpp"

#include <iostream>
#include <cstring>

BeaRopGadgetFinder::BeaRopGadgetFinder(E_Arch arch, unsigned int depth, unsigned int engine_display_option)
: m_opts(PrefixedNumeral + NasmSyntax), m_arch(arch), m_depth(depth)
{
}

BeaRopGadgetFinder::~BeaRopGadgetFinder(void)
{
}

void BeaRopGadgetFinder::init_disasm_struct(DISASM* d)
{
    memset(d, 0, sizeof(DISASM));

    /* those options are mostly display option for the disassembler engine */
    d->Options = m_opts;

    /* this one is to precise what architecture we'll disassemble */
    d->Archi = m_arch;
}

void BeaRopGadgetFinder::find_all_gadget_from_ret(const unsigned char* data, unsigned long long vaddr, const DISASM* ending_instr_disasm, unsigned int len_ending_instr, std::multiset<std::shared_ptr<Gadget>, Gadget::Sort> &gadgets)
{
    DISASM dis;

    init_disasm_struct(&dis);

    /*
        We go back, trying to create the longuest gadget possible with the longuest instructions
        "On INTEL processors, (in IA-32 or intel 64 modes), instruction never exceeds 15 bytes." -- beaengine.org
    */
    dis.EIP         = (UIntPtr)(ending_instr_disasm->EIP - m_depth*15); // /!\ Warning to pointer arith
    dis.VirtualAddr = ending_instr_disasm->VirtualAddr - m_depth*15;

    /* going back yeah, but not too much :)) */
    if(dis.EIP < (UIntPtr)data)
    {
        dis.EIP = (UIntPtr)data;
        dis.VirtualAddr = vaddr;
    }

    while(dis.EIP < ending_instr_disasm->EIP)
    {
        std::list<Instruction> list_of_instr;

        /* save where we were in memory */
        UIntPtr saved_eip  = dis.EIP;
        UInt64 saved_vaddr = dis.VirtualAddr;

        bool is_a_valid_gadget = false;

        /* now we'll try to find suitable sequence */
        for(unsigned int nb_ins = 0; nb_ins < m_depth; nb_ins++)
        {
            int len_instr = Disasm(&dis);

            /* if the instruction isn't valid, let's try the process one byte after */
            if(len_instr == UNKNOWN_OPCODE || is_valid_instruction(&dis) == false)
                break;

            list_of_instr.push_back(Instruction(
                std::string(dis.CompleteInstr),
                std::string(dis.Instruction.Mnemonic),
                dis.EIP - (UIntPtr)data,
                len_instr
            ));
            
            dis.EIP += len_instr;
            dis.VirtualAddr += len_instr;

            /* if the address of the latest instruction found points on the ending one, we have a winner */
            if(dis.EIP == ending_instr_disasm->EIP)
            {
                is_a_valid_gadget = true;
                /* NB: I reach the ending instruction without depth instruction */
                break;
            }

            /* if we point after the ending one, it's not a valid sequence */
            if(dis.EIP > ending_instr_disasm->EIP)
                break;
        }

        if(is_a_valid_gadget)
        {
            /* we have a valid gadget, time to build it ; add the instructions found & finally add the ending instruction */
            
            /* Don't forget to include the ending instruction in the chain of instruction */
            list_of_instr.push_back(Instruction(
                std::string(ending_instr_disasm->CompleteInstr),
                std::string(ending_instr_disasm->Instruction.Mnemonic),
                ending_instr_disasm->EIP - (UIntPtr)data,
                len_ending_instr
            ));


            std::shared_ptr<Gadget> gadget = std::make_shared<Gadget>();

            /* Now we populate our gadget with the instructions previously found.. */
            gadget->add_instructions(list_of_instr, vaddr);

            gadgets.insert(gadget);
        }

        /* goto the next byte */
        dis.EIP = saved_eip + 1;
        dis.VirtualAddr = saved_vaddr + 1;
    }
}

bool BeaRopGadgetFinder::is_valid_ending_instruction(DISASM* ending_instr_d)
{
    /*
        Work Around, BeaEngine in x64 mode disassemble "\xDE\xDB" as an instruction without disassembly
        Btw, this is not the only case!
    */
    if(ending_instr_d->CompleteInstr[0] != 0)
    {
        Int32 branch_type = ending_instr_d->Instruction.BranchType;
        UInt64 addr_value = ending_instr_d->Instruction.AddrValue;
        char *mnemonic = ending_instr_d->Instruction.Mnemonic, *completeInstr = ending_instr_d->CompleteInstr;

        bool is_good_branch_type = (
            /* We accept all the ret type instructions (except retf/iret) */
            (branch_type == RetType && strncmp(mnemonic, "retf", 4) != 0 && strncmp(mnemonic, "iretd", 4) != 0) || 

            /* call reg32 / call [reg32] */
            (branch_type == CallType && addr_value == 0) ||

            /* jmp reg32 / jmp [reg32] */
            (branch_type == JmpType && addr_value == 0) ||

            /* int 0x80 & int 0x2e */
            (strncmp(completeInstr, "int 0x80", 8) == 0 || strncmp(completeInstr, "int 0x2e", 8) == 0 || strncmp(completeInstr, "syscall", 7) == 0)
        );

        return (
            is_good_branch_type && 

            /* Yeah, entrance isn't allowed to the jmp far/call far */
            strstr(completeInstr, "far") == NULL
        );
    }

    return false;
}

bool BeaRopGadgetFinder::is_valid_instruction(DISASM *ending_instr_d)
{
    Int32 branch_type = ending_instr_d->Instruction.BranchType;

    return (
        /*
            Work Around, BeaEngine in x64 mode disassemble "\xDE\xDB" as an instruction without disassembly
            Btw, this is not the only case!
        */
        ending_instr_d->CompleteInstr[0] != 0 &&
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
        strstr(ending_instr_d->CompleteInstr, "far") == NULL
    );
}

void BeaRopGadgetFinder::find_rop_gadgets(const unsigned char* data, unsigned long long size, unsigned long long vaddr, std::multiset<std::shared_ptr<Gadget>, Gadget::Sort> &merged_gadgets)
{
    DISASM dis;

    init_disasm_struct(&dis);

    for(unsigned long long offset = 0; offset < size; ++offset)
    {
        dis.EIP = (UIntPtr)(data + offset);
        dis.VirtualAddr = SafeAddU64(vaddr, offset);
        dis.SecurityBlock = (UInt32)(size - offset);
        
        int len = Disasm(&dis);

        /* OK this one is an unknow opcode, goto the next one */
        /* Or this instruction is too long (goes out of boundary) */
        if(len == UNKNOWN_OPCODE || len == OUT_OF_BLOCK)
            continue;

        if(is_valid_ending_instruction(&dis))
        {
            DISASM ret_instr;

            /* Okay I found a RET ; now I can build the gadget */
            memcpy(&ret_instr, &dis, sizeof(DISASM));
            
            /* Do not forget to add the ending instruction only -- we give to the user all gadget with < depth instruction */
            std::list<Instruction> only_ending_instr;

            only_ending_instr.push_back(Instruction(
                std::string(ret_instr.CompleteInstr),
                std::string(ret_instr.Instruction.Mnemonic),
                offset,
                len
            ));

            std::shared_ptr<Gadget> gadget_with_one_instr = std::make_shared<Gadget>();

            /* the gadget will only have 1 ending instruction */
            gadget_with_one_instr->add_instructions(only_ending_instr, vaddr);
            merged_gadgets.insert(gadget_with_one_instr);

            /* if we want to see gadget with more instructions */
            if(m_depth > 0)
            {
                find_all_gadget_from_ret(
                    data, vaddr,
                    &ret_instr,
                    len, merged_gadgets
                );
            }
        }
    }
}
