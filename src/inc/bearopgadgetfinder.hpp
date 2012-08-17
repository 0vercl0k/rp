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
#ifndef BEADISASSEMBLER_HPP
#define BEADISASSEMBLER_HPP

#define BEA_USE_STDCALL
#define BEA_ENGINE_STATIC

#include "BeaEngine.h"
#include "instruction.hpp"
#include "gadget.hpp"

#include <set>

/*! \class BeaRopGadgetFinder
 *
 *  This class aims to find gadgets thanks to the BeaEngine library which is written by BeaTriX: http://www.beaengine.org/
 *  You can use this class to find either x86 gadgets, or x64 gadgets.
 */
class BeaRopGadgetFinder
{
    public:

        /*! The different architectures BeaRopGadgetFinder handles */
        enum E_Arch
        {
            IA32 = 0,
            IA64 = 64
        };

        /*!
         *  \brief BeaRopGadgetFinder instanciation requires to precise the depth of the research and the architecture
         *   
         *  \param arch: Which architecture is used by the code ?
         *  \param depth: It means the maximum number of instructions which can composed a gadget (the ending instruction doesn't count)
         *  \param engine_display_option: You can pass several display options to BeaEngine
         */
        explicit BeaRopGadgetFinder(E_Arch arch, unsigned int depth, unsigned int engine_display_option = 0);
        
        ~BeaRopGadgetFinder(void);

        /*!
         *  \brief Look for rop gadget in a specific data buffer
         *  the section it will research in (in order to display gadget with their VA)
         *
         *  \param data: It is the where the code is in memory
         *  \param size: It is the size of the code
         *  \param vaddr: It's the *real* virtual address of the data (BeaEngine needs it to disassemble correctly instruction with relative offset, like jmp)
         *
         *  \return the whole gadgets found in [data, data+size] ; it tries to find gadget with depth instruction (less or equal to depth to be exact)
         */
        std::multiset<Gadget*> find_rop_gadgets(const unsigned char* data, unsigned long long size, unsigned long long vaddr);

    private:

        /*!
         *  \brief Find all possible gadget from a specific ending instruction (it returns backward to find good instruction sequences)
         *
         *  \param data: It is the where the code is in memory
         *  \param size: It is the size of the code
         *  \param ending_instr_disasm: It is the DISASM structure of your ending instruction which contains several info like VA, disassembly, etc.
         *  \param len_ending_instr: It is the len of the ending instruction ; this len is returned by Disasm()
         *
         *  \return the whole gadgets found in [data, data+size] ; it tries to find gadget with depth instruction (less or equal to depth to be exact)
         */
        std::multiset<Gadget*> find_all_gadget_from_ret(const unsigned char* data, unsigned long long vaddr, const DISASM* ending_instr, unsigned int len_ending_instr);
        
         /*!
         *  \brief Is it a valid ending instruction ?
         *
         *  \param ending_instr_d: It is the DISASM structure of your ending instruction
         *
         *  \return true if the ending instruction is validated else false
         */
        bool is_valid_ending_instruction(DISASM* ending_instr_d);

        bool is_valid_ending_instruction_nasm(DISASM* ending_instr_d);
        bool is_valid_ending_instruction_att(DISASM* ending_instr_d);
        
        /*!
         *  \brief Is it a valid instruction ?
         *
         *  \param ending_instr_d: It is the DISASM structure of your instruction
         *
         *  \return true if the instruction is validated else false
         */
        bool is_valid_instruction(DISASM *ending_instr_d);
        
        /*!
         *  \brief Correctly initialize a DISASM structure
         *
         *  \param d: It is the DISASM structure you want to initialize
         */
        void init_disasm_struct(DISASM* d);


        UInt64 m_opts; /*!< options passed to the BeaEngine*/

        UInt32 m_arch; /*!< architecture the BeaEngine will use to disassemble*/

        unsigned int m_depth; /*!< the maximum number of instruction that can composed a gadget*/

        unsigned long long m_vaddr; /*!< the real virtual address of the data you want to disassemble*/
};

#endif
