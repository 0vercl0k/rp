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
#include "instruction.hpp"

Instruction::Instruction(const std::string &disass, unsigned int size, std::vector<unsigned char> b)
: m_disass(std::move(disass)), m_size(size)
{
    for (auto i : b)
        bytes.push_back(i);
}

Instruction::~Instruction()
{
}

unsigned int Instruction::get_size(void) const
{
    return m_size;
}

const std::string &Instruction::get_disassembly(void) const
{
    return m_disass.get();
}

void Instruction::print_bytes(void)
{
    for (size_t i = 0; i < m_size; ++i)
        printf("\\x%.2x", bytes.at(i));
}