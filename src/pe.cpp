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
    for(std::vector<RP_IMAGE_SECTION_HEADER*>::iterator it = m_pPELayout->imgSectionHeaders.begin();
        it != m_pPELayout->imgSectionHeaders.end();
        ++it)
        delete *it;

    m_pPELayout->imgSectionHeaders.clear();

    if(m_pPELayout != NULL)
        delete m_pPELayout;
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
            cpu = new (std::nothrow) Ia32();
            break;
        }

        case CPU::CPU_IA64:
        {
            cpu = new (std::nothrow) Ia64();
            break;
        }

        default:
            throw std::string("Cannot determine the CPU type");
    }
    
    return cpu;
}

std::vector<Section*> PE::get_executables_section(std::ifstream & file)
{
    std::vector<Section*> exec_sections;

    for(std::vector<RP_IMAGE_SECTION_HEADER*>::iterator it = m_pPELayout->imgSectionHeaders.begin();
        it != m_pPELayout->imgSectionHeaders.end();
        ++it)
    {
        if((*it)->Characteristics & RP_IMAGE_SCN_MEM_EXECUTE)
        {
            Section *tmp = new (std::nothrow) Section(
                file,
                (const char*)(*it)->Name,
                (*it)->PointerToRawData,
                (*it)->SizeOfRawData,
                Section::Executable
            );

            if(tmp == NULL)
                throw std::string("Cannot allocate a section");

            exec_sections.push_back(tmp);
        }
    }
    return exec_sections;
}

unsigned long long PE::raw_offset_to_va(const unsigned long long absolute_raw_offset, const unsigned long long absolute_raw_offset_section) const
{
    for(std::vector<RP_IMAGE_SECTION_HEADER*>::iterator it = m_pPELayout->imgSectionHeaders.begin();
        it != m_pPELayout->imgSectionHeaders.end();
        ++it)
    {
        if(absolute_raw_offset >= (*it)->PointerToRawData && 
            absolute_raw_offset <= ((*it)->PointerToRawData + (*it)->SizeOfRawData))
        {
            return m_pPELayout->get_image_base() + (*it)->VirtualAddress + (absolute_raw_offset - absolute_raw_offset_section);
        }
    }

    return 0;
}