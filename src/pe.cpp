#include "pe.hpp"

#include "ia32.hpp"
#include "ia64.hpp"

#include <iostream>
#include <cstring>

PE::PE(void)
{
}

PE::~PE(void)
{
    if(m_pPELayout != NULL)
        delete m_pPELayout;
}

std::string PE::get_class_name(void) const
{
    return std::string("PE");
}

void PE::display_information(VerbosityLevel lvl)
{
    ExecutableFormat::display_information(lvl);
    std::cout << "PE Information:" << std::endl;
    m_pPELayout->display(lvl);
}

CPU::E_CPU PE::extract_information_from_binary(std::ifstream &file)
{
    RP_IMAGE_DOS_HEADER imgDosHeader = {0};
    RP_IMAGE_NT_HEADERS32 imgNtHeaders32 = {0};
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
        throw std::string("This file doesn't seem to be a correct PE (bad IMAGE_NT_SIGNATURE)");

    switch(imgNtHeaders32.OptionalHeader.Magic)
    {
        case RP_IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        {
            cpu = CPU::CPU_IA32;
            /* Ok, now we can allocate the good version of the PE Layout */
            /* The 32bits version there! */
            init_properly_PELayout<x86Version>();
            break;
        }

        case RP_IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        {
            cpu = CPU::CPU_IA64;
            init_properly_PELayout<x64Version>();
            break;
        }

        default:
            throw std::string("Cannot determine the CPU type");
    }
    
    /* Now we can fill the structure */
    std::memcpy(&m_pPELayout->imgDosHeader, &imgDosHeader, m_pPELayout->get_image_dos_header_size());

    m_pPELayout->fill_nt_structures(file);

    file.seekg(off);
    return cpu;
}

CPU* PE::get_cpu(std::ifstream &file)
{
    CPU* cpu(NULL);
    CPU::E_CPU cpu_type = CPU::CPU_UNKNOWN;

    cpu_type = extract_information_from_binary(file);

    switch(cpu_type)
    {
        case CPU::CPU_IA32:
        {
            cpu = new Ia32();
            break;
        }

        case CPU::CPU_IA64:
        {
            cpu = new Ia64();
            break;
        }

        default:
            throw std::string("Cannot determine the CPU type");
    }
    
    return cpu;
}

std::vector<Section*> PE::get_executables_section(void)
{
    std::vector<Section*> exec_sections;
    return exec_sections;
}