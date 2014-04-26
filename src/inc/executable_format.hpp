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
#ifndef EXECUTABLE_FORMAT_H
#define EXECUTABLE_FORMAT_H

#include <string>
#include <fstream>
#include <iostream>
#include <vector>
#include <memory>

#include "cpu.hpp"
#include "toolbox.hpp"
#include "section.hpp"
#include "rpexception.hpp"

/*! \class ExecutableFormat
 *
 *  An ExecutableFormat is the second part composing a Program instance ; it is required to parse correctly the binary file, to know
 *  where you can find its executable sections, etc.
 */
class ExecutableFormat
{
    public:

        /* The format RP++ handles */
        enum E_ExecutableFormat
        {
            FORMAT_PE,
            FORMAT_ELF,
            FORMAT_UNKNOWN
        };

        explicit ExecutableFormat(void);

        virtual ~ExecutableFormat(void);

        /*!
         *  \brief Obtain the CPU ; for that it parses the executable format of your binary
         *   
         *  \return a pointer on the correct CPU
         */
        virtual std::shared_ptr<CPU> get_cpu(std::ifstream &file) = 0;

        /*!
         *  \brief Display information concerning the executable format: where sections begin, entry point, etc.
         *
         *  \param lvl: Set a verbosity level
         */
        virtual void display_information(const VerbosityLevel lvl) const
        {
            std::cout << "Verbose level: " << verbosity_to_string(lvl) << std::endl;
        }

        /*!
         *  \brief Retrieve the name of the class, useful when using polymorphism
         *
         *  \return the class name
         */
        virtual std::string get_class_name(void) const = 0;

        /*!
         *  \brief Get the executable sections of you binary ; it is where we will look for gadgets
         *
         *  \param file: it is a file handle on your binary file
         *
         *  \return A vector of Section instances
         */
        virtual std::vector<std::shared_ptr<Section>> get_executables_section(std::ifstream & file) = 0;

        /*!
         *  \brief Give you a PE/ELF instance (based mostly on the magic signature) 
         *
         *  \param magic_dword: It is a dword that allows to deduce which ExecutableFormat is used by the binary
         *
         *  \return A pointer on the correct ExecutableFormat deduced thanks to the magic_dword argument
         */
        static std::shared_ptr<ExecutableFormat> GetExecutableFormat(unsigned int magic_dword);

    private:

        /*!
         *  \brief Fill the structures you need, parse your executable format to extract the useful information 
         *
         *  \param file: It is your binary file
         *
         *  \return The CPU type used in your binary file
         */
        virtual CPU::E_CPU extract_information_from_binary(std::ifstream &file)
        {
            RAISE_EXCEPTION("This method should not be called ; you're doing it wrong!");
            return CPU::CPU_UNKNOWN;
        }
};

#endif
