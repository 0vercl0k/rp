#include "macho.hpp"
#include "ia32.hpp"
#include "ia64.hpp"

Macho::Macho(void)
{
}

Macho::~Macho(void)
{
}

CPU* Macho::get_cpu(std::ifstream &file)
{
    CPU *cpu(NULL);
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
            cpu = new (std::nothrow) Ia64();
            init_properly_macho_layout<x64Version>();
            break;
        }

        case CPU_TYPE_I386:
        {
            cpu = new (std::nothrow) Ia32();
            init_properly_macho_layout<x86Version>();
            break;
        }

        default:
            RAISE_EXCEPTION("Cannot determine which architecture is used in this Mach-O file");
    }

    file.seekg(off);

    if(cpu == NULL)
        RAISE_EXCEPTION("Cannot allocate cpu");

    /* Now we can fill the structure */
    m_MachoLayout->fill_structures(file);

    return cpu;
}

std::string Macho::get_class_name(void) const
{
    return std::string("Mach-o");
}

std::vector<Section*> Macho::get_executables_section(std::ifstream & file)
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
