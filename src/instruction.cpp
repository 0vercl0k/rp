/*
    This file is part of rp++.

    Copyright (C) 2013, Axel "0vercl0k" Souchet <0vercl0k at tuxfamily.org>
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
#include "instruction.hpp"

Instruction::Instruction(std::string disass, std::string mnemonic, unsigned long long offset, unsigned int size)
: m_disass(disass), m_mnemonic(mnemonic), m_offset(offset), m_size(size)
{
}

Instruction::~Instruction(void)
{
}

unsigned long long Instruction::get_absolute_address(const unsigned char* va_section)
{
    return (unsigned long long)va_section + m_offset;
}

unsigned int Instruction::get_size(void) const
{
    return m_size;
}

unsigned long long Instruction::get_offset(void) const
{
    return m_offset;
}

std::string Instruction::get_disassembly(void) const
{
    return m_disass;
}

std::string Instruction::get_mnemonic(void) const
{
    return m_mnemonic;
}
