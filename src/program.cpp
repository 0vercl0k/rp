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
#include "program.hpp"

#include <iostream>
#include <map>
#include <sstream>

#include "executable_format.hpp"
#include "raw.hpp"
#include "x86.hpp"
#include "x64.hpp"
#include "section.hpp"
#include "coloshell.hpp"
#include "rpexception.hpp"
#include "toolbox.hpp"

Program::Program(const std::string & program_path, CPU::E_CPU arch)
: m_cpu(NULL), m_exformat(NULL)
{
    unsigned int magic_dword = 0;

    std::cout << "Trying to open '" << program_path << "'.." << std::endl;
    m_file.open(program_path.c_str(), std::ios::binary);
    if(m_file.is_open() == false)
        RAISE_EXCEPTION("Cannot open the file");

    /* If we know the CPU in the constructor, it is a raw file */
    if(arch != CPU::CPU_UNKNOWN)
    {
        m_exformat = std::make_shared<Raw>();
        
        switch(arch)
        {
            case CPU::CPU_x86:
                m_cpu = std::make_shared<x86>();
                break;

            case CPU::CPU_x64:
                m_cpu = std::make_shared<x64>();
                break;

            default:
                RAISE_EXCEPTION("Don't know your architecture");
        }
    }
    /* This isn't a raw file, we have to determine the executable format and the cpu */
    else
    {
        m_file.read((char*)&magic_dword, sizeof(magic_dword));

        m_exformat = ExecutableFormat::GetExecutableFormat(magic_dword);
        if(m_exformat == NULL)
            RAISE_EXCEPTION("GetExecutableFormat fails");

        m_cpu = m_exformat->get_cpu(m_file);
        if(m_cpu == NULL)
            RAISE_EXCEPTION("get_cpu fails");
    }


    std::cout << "FileFormat: " << m_exformat->get_class_name() << ", Arch: " << m_cpu->get_class_name() << std::endl;
}

Program::~Program(void)
{
    if(m_file.is_open())
        m_file.close();
}

void Program::display_information(VerbosityLevel lvl)
{
    m_exformat->display_information(lvl);
}

void Program::find_gadgets(unsigned int depth, std::multiset<std::shared_ptr<Gadget>, Gadget::Sort> &gadgets_found)
{
    unsigned long long counter = 0;

    /* To do a ROP gadget research, we need to know the executable section */
    std::vector<std::shared_ptr<Section>> executable_sections = m_exformat->get_executables_section(m_file);
    if(executable_sections.size() == 0)
        std::cout << "It seems your binary haven't executable sections." << std::endl;

    /* Walk the executable sections */
    for(std::vector<std::shared_ptr<Section>>::iterator it_sec = executable_sections.begin(); it_sec != executable_sections.end(); ++it_sec)
    {
        std::cout << "in " << (*it_sec)->get_name() << std::endl;
        unsigned long long va_section = (*it_sec)->get_vaddr();

        m_cpu->find_gadget_in_memory(
            (*it_sec)->get_section_buffer(),
            (*it_sec)->get_size(),
            va_section,
            depth,
            gadgets_found
        );

        std::cout << (gadgets_found.size() - counter) << " found." << std::endl << std::endl;
        counter = gadgets_found.size();

        /* 
            XXX: 
                If at&t syntax is enabled, BeaEngine doesn't seem to handle the prefix:
                \xf0\x00\x00 => addb %al, (%eax) ; -- and in intel -- lock add byte [eax], al ; ret  ;

                It will introduce differences between the number of unique gadgets found!
        */
    }
}

void Program::search_and_display(const unsigned char* hex_values, unsigned int size)
{
    std::vector<std::shared_ptr<Section>> executable_sections = m_exformat->get_executables_section(m_file);
    if(executable_sections.size() == 0)
        std::cout << "It seems your binary haven't executable sections." << std::endl;

    for(std::vector<std::shared_ptr<Section>>::iterator it = executable_sections.begin(); it != executable_sections.end(); ++it)
    {
        std::list<unsigned long long> ret = (*it)->search_in_memory(hex_values, size);
        for(std::list<unsigned long long>::iterator it2 = ret.begin(); it2 != ret.end(); ++it2)
        {
            unsigned long long va_section = (*it)->get_vaddr();
            unsigned long long va = va_section + *it2;
            
            display_offset_lf(va, hex_values, size); 
        }
    }
}

unsigned long long Program::get_image_base_address(void)
{
    return m_exformat->get_image_base_address();
}