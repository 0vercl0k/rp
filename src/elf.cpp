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
#include "elf.hpp"

#include "x86.hpp"
#include "x64.hpp"

#include <iostream>

Elf::Elf(void)
{
}

Elf::~Elf(void)
{   
    if(m_ELFLayout != NULL)
        delete m_ELFLayout;
}

std::string Elf::get_class_name(void) const
{
    return std::string("Elf");
}

void Elf::display_information(const VerbosityLevel lvl) const
{
    ExecutableFormat::display_information(lvl);
    std::cout << "Elf Information:" << std::endl;
    m_ELFLayout->display(lvl);
}

CPU::E_CPU Elf::extract_information_from_binary(std::ifstream &file)
{
    unsigned char buf[EI_NIDENT] = {0};
    CPU::E_CPU cpu = CPU::CPU_UNKNOWN;
    std::cout << "Loading ELF information.." << std::endl;

    /* Remember where the caller was in the file */
    std::streampos off = file.tellg();

    file.seekg(0, std::ios::beg);
    file.read((char*)buf, EI_NIDENT);

    switch(buf[EI_CLASS])
    {
        case ELFCLASS32:
        {
            cpu = CPU::CPU_x86;
            init_properly_ELFLayout<x86Version>();
            break;
        }

        case ELFCLASS64:
        {
            cpu = CPU::CPU_x64;
            init_properly_ELFLayout<x64Version>();
            break;
        }

        default:
            RAISE_EXCEPTION("Cannot determine the CPU type");
    }

    /* Filling the structure now !*/
    m_ELFLayout->fill_structures(file);

    /* Set correctly the pointer */
    file.seekg(off);
    return cpu;
}

CPU* Elf::get_cpu(std::ifstream &file)
{
    CPU* cpu(NULL);
    CPU::E_CPU cpu_type = CPU::CPU_UNKNOWN;

    cpu_type = extract_information_from_binary(file);

    switch(cpu_type)
    {
        case CPU::CPU_x86:
        {
            cpu = new (std::nothrow) x86();
            break;
        }

        case CPU::CPU_x64:
        {
            cpu = new (std::nothrow) x64();
            break;
        }

        default:
            RAISE_EXCEPTION("Cannot determine the CPU type");
    }
    
    if(cpu == NULL)
        RAISE_EXCEPTION("Cannot allocate a cpu");

    return cpu;
}

std::vector<Section*> Elf::get_executables_section(std::ifstream & file)
{
    return m_ELFLayout->get_executable_section(file);
}
