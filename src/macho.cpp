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
#include "macho.hpp"
#include "x86.hpp"
#include "x64.hpp"

Macho::Macho(void)
{
}

Macho::~Macho(void)
{
}

std::shared_ptr<CPU> Macho::get_cpu(std::ifstream &file)
{
    std::shared_ptr<CPU> cpu(nullptr);
    RP_MACH_HEADER<x86Version> header32;

    std::cout << "Loading Mach-O information.." << std::endl;

    /* Remember where the caller was in the file */
    std::streampos off = file.tellg();

    file.seekg(0, std::ios::beg);
    file.read((char*)&header32, sizeof(RP_MACH_HEADER<x86Version>));

    switch(header32.cputype)
    {
        case CPU_TYPE_x86_64:
        {
            cpu = std::make_shared<x64>();
            init_properly_macho_layout<x64Version>();
            break;
        }

        case CPU_TYPE_I386:
        {
            cpu = std::make_shared<x86>();
            init_properly_macho_layout<x86Version>();
            break;
        }

        default:
            RAISE_EXCEPTION("Cannot determine which architecture is used in this Mach-O file");
    }

    file.seekg(off);

    if(cpu == nullptr)
        RAISE_EXCEPTION("Cannot allocate cpu");

    /* Now we can fill the structure */
    m_MachoLayout->fill_structures(file);

    return cpu;
}

std::string Macho::get_class_name(void) const
{
    return std::string("Mach-o");
}

std::vector<std::shared_ptr<Section>> Macho::get_executables_section(std::ifstream & file)
{
    return m_MachoLayout->get_executable_section(file);
}

unsigned long long Macho::raw_offset_to_va(const unsigned long long absolute_raw_offset, const unsigned long long absolute_raw_offset_section) const
{
    unsigned long long r = 0;
    return r;
}

CPU::E_CPU Macho::extract_information_from_binary(std::ifstream &file)
{
    return CPU::CPU_UNKNOWN;
}

void Macho::display_information(const VerbosityLevel lvl) const
{
    ExecutableFormat::display_information(lvl);
    m_MachoLayout->display(lvl);
}

unsigned long long Macho::get_image_base_address(void)
{
    return m_MachoLayout->get_image_base_address();
}