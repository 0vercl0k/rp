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
#include "gadget.hpp"
#include "coloshell.hpp"
#include "toolbox.hpp"

Gadget::Gadget()
: m_size(0)
{
}

Gadget::~Gadget(void)
{
}

std::string Gadget::get_disassembly(void) const
{
    return m_disassembly;
}

unsigned int Gadget::get_size(void) const
{
    return m_size;
}

void Gadget::add_instructions(std::list<Instruction> &instrs, unsigned long long va_section)
{
    for(const auto &instr : instrs)
    {
        /* 
         * If we haven't any offset yet, it means this instruction is the first one added
         * thus, the offset of the gadget
         * 
         * XXX: Yeah I'm aware that passing the va_section is a bit weird
         */
        if(m_offsets.size() == 0)
        {
            m_offsets.push_back(instr.get_offset());
            m_va_sections.push_back(va_section);
        }
        
        std::shared_ptr<Instruction> instr_copy = std::make_shared<Instruction>(instr);

        /* We build our gadget instruction per instruction */
        m_instructions.push_back(instr_copy);

        /* Don't forget to increment the size */
        m_size += instr.get_size();

        /* Build the disassembly instruction per instruction */
        m_disassembly += instr.get_disassembly() + " ; ";
    }
}

unsigned long long Gadget::get_first_offset(void) const
{
    return m_instructions.front()->get_offset();
}

unsigned long long Gadget::get_first_va_section(void) const
{
    return m_va_sections.front();
}

unsigned long long Gadget::get_first_absolute_address(void) const
{
    return get_first_offset() + get_first_va_section();
}

size_t Gadget::get_nb(void) const
{
    return m_offsets.size();
}

void Gadget::add_new_one(unsigned long long offset, unsigned long long va_section)
{
    m_offsets.push_back(offset);
    m_va_sections.push_back(va_section);
}

std::list<std::shared_ptr<Instruction>> Gadget::get_instructions(void)
{
    std::list<std::shared_ptr<Instruction>> instrs(m_instructions);
    /* We don't want the ending instruction in the list */
    instrs.pop_back();

    return instrs;
}

std::shared_ptr<Instruction> Gadget::get_ending_instruction(void)
{
    return m_instructions.back();
}
