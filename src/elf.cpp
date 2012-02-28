#include "elf.hpp"

#include "ia32.hpp"
#include "ia64.hpp"

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

void Elf::display_information(VerbosityLevel lvl)
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
            cpu = CPU::CPU_IA32;
            init_properly_ELFLayout<x86Version>();
            break;
        }

        case ELFCLASS64:
        {
            cpu = CPU::CPU_IA64;
            init_properly_ELFLayout<x64Version>();
            break;
        }

        default:
            throw std::string("Cannot determine the CPU type");
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

    std::cout << "Ehdr: " << sizeof(Elf32_Ehdr) << " " << sizeof(Elf64_Ehdr) << std::endl;
    std::cout << "Phdr: " << sizeof(Elf32_Phdr) << " " << sizeof(Elf64_Phdr) << std::endl;
    std::cout << "Shdr: " << sizeof(Elf32_Shdr) << " " << sizeof(Elf64_Shdr) << std::endl;

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
