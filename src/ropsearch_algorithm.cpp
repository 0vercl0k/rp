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
#include "ropsearch_algorithm.hpp"
#include "safeint.hpp"

#include <iostream>
#include <cstring>

void find_all_gadget_from_ret(
    const unsigned char* data,
    unsigned long long vaddr,
    const InstructionInformation &ending_instr_disasm,
    unsigned int depth,
    std::multiset<std::shared_ptr<Gadget>, Gadget::Sort> &gadgets,
    DisassEngineWrapper &disass_engine
)
{
    unsigned int alignement = disass_engine.get_alignement();
    unsigned int size_biggest_instruction = disass_engine.get_size_biggest_instruction();

    // We go back, trying to create the longuest gadget possible with the longuest instructions
    unsigned long long EIP         = ending_instr_disasm.address - (depth * size_biggest_instruction);
    unsigned long long VirtualAddr = ending_instr_disasm.virtual_address_in_memory - (depth * size_biggest_instruction);

    /* going back yeah, but not too much :)) */
    if(EIP < (unsigned long long)data)
    {
        EIP = (unsigned long long)data;
        VirtualAddr = vaddr;
    }

    while(EIP < ending_instr_disasm.address)
    {
        std::list<Instruction> list_of_instr;

        /* save where we were in memory */
        unsigned long long saved_eip  = EIP;
        unsigned long long saved_vaddr = VirtualAddr;

        bool is_a_valid_gadget = false;

        /* now we'll try to find suitable sequence */
        for(unsigned int nb_ins = 0; nb_ins < depth; nb_ins++)
        {
            DisassEngineReturn ret;
            InstructionInformation instr = disass_engine.disass(
                (const unsigned char*)EIP,
                0,
                VirtualAddr,
                ret
            );
                

            /* if the instruction isn't valid, ends this function */
            if(ret == UnknownInstruction || disass_engine.is_valid_instruction(instr) == false)
                break;

            list_of_instr.push_back(Instruction(
                std::string(instr.disassembly),
                std::string(instr.mnemonic),
                EIP - (unsigned long long)data,
                instr.size
            ));
            
            EIP += instr.size;
            VirtualAddr += instr.size;

            /* if the address of the latest instruction found points on the ending one, we have a winner */
            if(EIP == ending_instr_disasm.address)
            {
                is_a_valid_gadget = true;
                /* NB: I reach the ending instruction without depth instruction */
                break;
            }

            /* if we point after the ending one, it's not a valid sequence */
            if(EIP > ending_instr_disasm.address)
                break;
        }

        if(is_a_valid_gadget)
        {
            /* we have a valid gadget, time to build it ; add the instructions found & finally add the ending instruction */
            
            /* Don't forget to include the ending instruction in the chain of instruction */
            list_of_instr.push_back(Instruction(
                std::string(ending_instr_disasm.disassembly),
                std::string(ending_instr_disasm.mnemonic),
                ending_instr_disasm.address - (unsigned long long)data,
                ending_instr_disasm.size
            ));


            std::shared_ptr<Gadget> gadget = std::make_shared<Gadget>();

            /* Now we populate our gadget with the instructions previously found.. */
            gadget->add_instructions(list_of_instr, vaddr);

            gadgets.insert(gadget);
        }

        /* goto the next aligned-byte */
        EIP = saved_eip + alignement;
        VirtualAddr = saved_vaddr + alignement;
    }
}

void find_rop_gadgets(
    const unsigned char* data,
    unsigned long long size,
    unsigned long long vaddr,
    unsigned int depth,
    std::multiset<std::shared_ptr<Gadget>, Gadget::Sort> &merged_gadgets,
    DisassEngineWrapper &disass_engine
)
{
    unsigned int alignement = disass_engine.get_alignement();
    for(unsigned long long offset = 0; offset < size; offset += alignement)
    {
        DisassEngineReturn ret;
        InstructionInformation instr = disass_engine.disass(
            data + offset,
            size - offset,
            SafeAddU64(vaddr, offset),
            ret
        );

        /* OK either this is an unknow opcode & we goto the next one 
         Or the instruction encountered is too long & we also goto the next one in that case */
        if(ret == UnknownInstruction || ret == OutOfBlock)
            continue;

        if(disass_engine.is_valid_ending_instruction(instr))
        {
            /* Okay I found a RET ; now I can build the gadget */
            InstructionInformation ret_instr(instr);
            
            /* Do not forget to add the ending instruction only -- we give to the user all gadget with < depth instruction */
            std::list<Instruction> only_ending_instr;

            only_ending_instr.push_back(Instruction(
                std::string(ret_instr.disassembly),
                std::string(ret_instr.mnemonic),
                offset,
                ret_instr.size
            ));

            std::shared_ptr<Gadget> gadget_with_one_instr = std::make_shared<Gadget>();

            /* the gadget will only have 1 ending instruction */
            gadget_with_one_instr->add_instructions(only_ending_instr, vaddr);
            merged_gadgets.insert(gadget_with_one_instr);

            /* if we want to see gadget with more instructions */
            if(depth > 0)
            {
                find_all_gadget_from_ret(
                    data, vaddr,
                    ret_instr,
                    depth,
                    merged_gadgets,
                    disass_engine
                );
            }
        }
    }
}