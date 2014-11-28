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
#include <future>
#include <queue>
#include <mutex>
#include <thread>

#include "executable_format.hpp"
#include "raw.hpp"
#include "x86.hpp"
#include "x64.hpp"
#include "arm.hpp"
#include "section.hpp"
#include "coloshell.hpp"
#include "rpexception.hpp"
#include "toolbox.hpp"

Program::Program(const std::string & program_path, CPU::E_CPU arch)
: m_cpu(nullptr), m_exformat(nullptr)
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

			case CPU::CPU_ARM:
				m_cpu = std::make_shared<ARM>();
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
        if(m_exformat == nullptr)
            RAISE_EXCEPTION("GetExecutableFormat fails");

        m_cpu = m_exformat->get_cpu(m_file);
        if(m_cpu == nullptr)
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

void Program::find_gadgets(unsigned int depth, std::multiset<std::shared_ptr<Gadget>> &gadgets_found, unsigned int disass_engine_options, size_t n_max_thread)
{
    /* To do a ROP gadget research, we need to know the executable section */
    std::vector<std::shared_ptr<Section>> executable_sections = m_exformat->get_executables_section(m_file);
    if(executable_sections.size() == 0)
        std::cout << "It seems your binary haven't executable sections." << std::endl;

    std::queue<std::shared_ptr<Section>> jobs_queue;
    for (auto &executable_section : executable_sections)
        jobs_queue.push(executable_section);

    std::vector<std::future<void>> thread_pool;
    std::mutex m;
    while (jobs_queue.size() != 0)
    {
        if (thread_pool.size() < n_max_thread)
        {
            std::shared_ptr<Section> section = jobs_queue.front();
            unsigned long long va_section = section->get_vaddr();
            thread_pool.emplace_back(
                std::async(
                    std::launch::async,
                    &CPU::find_gadget_in_memory, m_cpu,
                    section->get_section_buffer(),
                    section->get_size(),
                    va_section,
                    depth,
                    std::ref(gadgets_found),
                    disass_engine_options,
                    std::ref(m)
                )
            );
            jobs_queue.pop();
        }
        else
        {
            // Wait for a thread to finish
            for (auto &it = thread_pool.begin(); it != thread_pool.end();)
            {
                if (it->wait_for(std::chrono::milliseconds(1)) == std::future_status::ready)
                {
                    it->get();
                    it = thread_pool.erase(it);
                }
                else
                    it++;
            }
        }
    }

    // Wait for potentially unfinished threads
    for (std::future<void> &f : thread_pool)
            f.get();

    // XXX: 
    //     If at&t syntax is enabled, BeaEngine doesn't seem to handle the prefix:
    //     \xf0\x00\x00 => addb %al, (%eax) ; -- and in intel -- lock add byte [eax], al ; ret  ;
    //
    //     It will introduce differences between the number of unique gadgets found!

}

void Program::search_and_display(const unsigned char* hex_values, unsigned int size)
{
    std::vector<std::shared_ptr<Section>> executable_sections = m_exformat->get_executables_section(m_file);
    if(executable_sections.size() == 0)
        std::cout << "It seems your binary haven't executable sections." << std::endl;

    for(auto &executable_section : executable_sections)
    {
        std::list<unsigned long long> offsets = executable_section->search_in_memory(hex_values, size);
        for(auto &offset : offsets)
        {
            unsigned long long va_section = executable_section->get_vaddr();
            unsigned long long va = va_section + offset;
            
            display_offset_lf(va, hex_values, size); 
        }
    }
}

unsigned long long Program::get_image_base_address(void)
{
    return m_exformat->get_image_base_address();
}