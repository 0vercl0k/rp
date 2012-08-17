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
#ifndef ELF_H
#define ELF_H

#include "executable_format.hpp"
#include "elf_struct.hpp"
#include "rpexception.hpp"

class Elf : public ExecutableFormat
{
    public:

        explicit Elf(void);
        
        ~Elf(void);

        CPU* get_cpu(std::ifstream &file);

        void display_information(const VerbosityLevel lvl) const;

        std::string get_class_name(void) const;

        std::vector<Section*> get_executables_section(std::ifstream & file);

    private:

        CPU::E_CPU extract_information_from_binary(std::ifstream &file);

        template<class T>
        void init_properly_ELFLayout(void)
        {
            m_ELFLayout = new (std::nothrow) ELFLayout<T>;
            if(m_ELFLayout == NULL)
                RAISE_EXCEPTION("m_ELFLayout allocation failed");
        }

        ExecutableLinkingFormatLayout* m_ELFLayout;
        CPU::E_CPU m_CPU;
};

#endif
