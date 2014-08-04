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
#include "pe.hpp"

#include "x86.hpp"
#include "x64.hpp"
#include "arm.hpp"

#include <iostream>
#include <cstring>

PE::PE(void)
{
}

PE::~PE(void)
{
}

std::string PE::get_class_name(void) const
{
    return std::string("PE");
}

void PE::display_information(const VerbosityLevel lvl) const
{
    ExecutableFormat::display_information(lvl);
    std::cout << "PE Information:" << std::endl;
    m_pPELayout->display(lvl);
}

CPU::E_CPU PE::extract_information_from_binary(std::ifstream &file)
{
    RP_IMAGE_DOS_HEADER imgDosHeader {0};
    RP_IMAGE_NT_HEADERS32 imgNtHeaders32 {0};
    CPU::E_CPU cpu = CPU::CPU_UNKNOWN;

    std::cout << "Loading PE information.." << std::endl;

    /* Remember where the caller was in the file */
    std::streampos off = file.tellg();

    file.seekg(0, std::ios::beg);
    file.read((char*)&imgDosHeader, sizeof(RP_IMAGE_DOS_HEADER));

    file.seekg(imgDosHeader.e_lfanew, std::ios::beg);
    /* 
     * Yeah, in fact, we don't know yet if it is a x86/x64 PE ; 
     * so just we grab the signature field, FILE_HEADER and the field Magic 
     */
    file.read((char*)&imgNtHeaders32, sizeof(unsigned int) + sizeof(RP_IMAGE_FILE_HEADER) + sizeof(unsigned int));
    
    if(imgNtHeaders32.Signature != RP_IMAGE_NT_SIGNATURE)
        RAISE_EXCEPTION("This file doesn't seem to be a correct PE (bad IMAGE_NT_SIGNATURE)");

    switch(imgNtHeaders32.OptionalHeader.Magic)
    {
        case RP_IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        {
			switch(imgNtHeaders32.FileHeader.Machine)
			{
				case RP_IMAGE_FILE_MACHINE_I386:
				{
					cpu = CPU::CPU_x86;
					break;
				}

				case RP_IMAGE_FILE_MACHINE_ARMTHUMB2LE:
				{
					cpu = CPU::CPU_ARM;
					break;
				}

				default:
					RAISE_EXCEPTION("Cannot determine the CPU type");
			}
			break;
        }

        case RP_IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        {
            cpu = CPU::CPU_x64;
            break;
        }

        default:
            RAISE_EXCEPTION("Cannot determine the CPU type");
    }
   
	/* Ok, now we can allocate the good version of the PE Layout */
	/* The 32bits version there! */
	if(cpu == CPU::CPU_x64)
		init_properly_PELayout<x64Version>();
	else
		init_properly_PELayout<x86Version>();

    /* Now we can fill the structure */
    std::memcpy(&m_pPELayout->imgDosHeader, &imgDosHeader, m_pPELayout->get_image_dos_header_size());

    m_pPELayout->fill_nt_structures(file);

    file.seekg(off);
    return cpu;
}

std::shared_ptr<CPU> PE::get_cpu(std::ifstream &file)
{
    std::shared_ptr<CPU> cpu(nullptr);
    CPU::E_CPU cpu_type = CPU::CPU_UNKNOWN;

    cpu_type = extract_information_from_binary(file);

    switch(cpu_type)
    {
        case CPU::CPU_x86:
        {
            cpu = std::make_shared<x86>();
            break;
        }

        case CPU::CPU_x64:
        {
            cpu = std::make_shared<x64>();
            break;
        }

		case CPU::CPU_ARM:
		{
			cpu = std::make_shared<ARM>();
			break;
		}

        default:
            RAISE_EXCEPTION("Cannot determine the CPU type");
    }
    
    return cpu;
}

std::vector<std::shared_ptr<Section>> PE::get_executables_section(std::ifstream & file)
{
    std::vector<std::shared_ptr<Section>> exec_sections;

    for(auto &sectionheader : m_pPELayout->imgSectionHeaders)
    {
        if(sectionheader->Characteristics & RP_IMAGE_SCN_MEM_EXECUTE)
        {
			//XXX: g++ + std::make_shared + packed struct
            std::shared_ptr<Section> tmp(new Section(
                sectionheader->get_name().c_str(),
                sectionheader->PointerToRawData,
                /* in the PE, this field is a RVA, so we need to add it the image base to have a VA */
                m_pPELayout->get_image_base_address() + sectionheader->VirtualAddress,
                sectionheader->SizeOfRawData
            ));
            
            tmp->dump(file);

            tmp->set_props(Section::Executable);

            exec_sections.push_back(tmp);
        }
    }
    return exec_sections;
}

unsigned long long PE::get_image_base_address(void)
{
    return m_pPELayout->get_image_base_address();
}