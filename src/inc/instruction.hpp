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
#ifndef INSTRUCTION_HPP
#define INSTRUCTION_HPP

#include <string>
#include <boost/flyweight.hpp>

/*! \class Instruction
 *
 *  Each instruction instance holds a disassembly, an offset (where we can find it in memory) and a size
 */
class Instruction
{
    public:
        
        /*!
         *  \brief Build an instruction
         *   
         *  \param disass: The disassembly of the instruction
         *  \param mnemonic: The mnemonic of the instruction
         *  \param offset: A raw offset (relative to a section) where you can find this instruction
         *  \param size: It is the size of the instruction
         */
        explicit Instruction(const std::string &disass, unsigned int size);

        /*!
         *  \brief Obtain the absolute address of the instruction thanks to the VA of the section where it was found
         *
         *  \return the VA of the instruction
         */
        /*unsigned long long get_absolute_address(const unsigned char* va_section);*/

        /*!
         *  \brief Get the size of the instruction
         *
         *  \return the size of the instruction
         */
        unsigned int get_size(void) const;

        /*!
         *  \brief Get the disassembly of the instruction
         *
         *  \return the disassembly of the instruction
         */
        const std::string &get_disassembly(void) const;

    private:

        boost::flyweight<std::string> m_disass; /*!< the disassembly of the instruction */
        
        unsigned int m_size; /*!< the size of the instruction */
};

#endif
