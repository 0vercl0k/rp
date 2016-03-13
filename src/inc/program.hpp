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
#ifndef PROGRAM_HPP
#define PROGRAM_HPP

#include <string>
#include <fstream>
#include <string>
#include <set>

#include "cpu.hpp"
#include "executable_format.hpp"

/*! \class Program
 *
 *  A program is the combination between two things: a CPU which will be used by the disassembler, 
 *  and an ExecutableFormat in order to correctly extract the code (to find cool stuff in)
 */
class Program
{
    public:

       /*!
         *  \brief Program instanciation requires a path where it can find your binary
         *   
         *  \param program_path: The path of your binary
         */
        explicit Program(const std::string & program_path, CPU::E_CPU arch = CPU::CPU_UNKNOWN);
        
        ~Program(void);

        /*!
         *  \brief Display information concerning the executable format (section address, entry point, stuff like that)
         *   
         *  \param lvl: Set the verbosity level you want
         */
        void display_information(VerbosityLevel lvl = VERBOSE_LEVEL_1);

        /*!
         *  \brief Find all the rop gadgets
         *   
         *  \param depth: Set the depth of the research (don't forget the ending instruction doesn't count -- so if you want only ending instruction, depth = 0)
         *  \param gadgets: The gadgets found
         *  \param disass_engine_options: Options you want to pass to the disassembly engine
		 *
         */
        void find_gadgets(uint32_t depth, std::multiset<std::shared_ptr<Gadget>> &gadgets, uint32_t disass_engine_options, size_t n_max_thread);

        /*!
         *  \brief Find hex values in the section of the program
         *   
         *  \param hex_values: It is a pointer on where it can find the bytes to find in memory
         *  \param size: It is the size of the buffer hex_values
         */
        void search_and_display(const uint8_t *hex_values, uint32_t size);

        /*!
         *  \brief Get the base address of the program
         *   
         *  \return size: Base address of the program
         */
        uint64_t get_image_base_address(void);

    private:
        
        std::shared_ptr<CPU> m_cpu; /*!< a pointer on the CPU used by your program*/
        
        std::shared_ptr<ExecutableFormat> m_exformat; /*!< a pointer on the ExecutableFormat used by your program*/
        
        std::ifstream m_file; /*!< the file descriptor*/
};

#endif
