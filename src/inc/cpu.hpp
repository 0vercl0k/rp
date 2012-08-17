/*
    This file is part of rp++.

    Copyright (C) 2012, Axel "0vercl0k" Souchet <0vercl0k at tuxfamily.org>
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
#ifndef CPU_H
#define CPU_H

#include <string>
#include <set>

#include "gadget.hpp"

/*! \class CPU
 *
 *  A CPU is an important class that compose a part of the Program class.
 */
class CPU
{
    public:

        explicit CPU(void);
        
        virtual ~CPU(void);

        /*!
         *  \brief Obtain the name of the class (useful when you use the polymorphism)
         *   
         *  \return the name of the class
         */
        virtual std::string get_class_name(void) const = 0;
        

        /*!
         *  \brief Each CPU class is able to find all gadgets in [p_memory, p_memory+size]
         *   NB: The vaddr field is actually used by the BeaEngine when it disassembles something like jmp instruction, it needs the original virtual address to
         *   give you disassemble correctly (indeed jmp instruction are relative)
         *
         *  \param p_memory: It is a pointer on the memory where you want to find rop gadget
         *  \param size: It is the size of the p_memory
         *  \param vaddr: It is the real virtual address of the memory which will be disassembled (see the previous remark)
         *  \param depth: It is the number of maximum instructions contained by a gadget
         *  \param engine_display_option: Pass display options to the dissassembly engine
         *
         *  \return A list of the Gadget instance
         */
        virtual std::multiset<Gadget*> find_gadget_in_memory(const unsigned char *p_memory, const unsigned long long size, const unsigned long long vaddr, const unsigned int depth, unsigned int engine_display_option = 0) = 0;

        /*! The different architectures RP++ handles */
        enum E_CPU
        {
            CPU_IA32, /*!< Ia32 */
            CPU_IA64, /*!< Ia64 */
            CPU_UNKNOWN /*!< unknown cpu */
        };
};

#endif
