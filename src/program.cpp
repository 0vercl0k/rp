#include "program.hpp"

#include <iostream>
#include <map>

#include "pe.hpp"
#include "elf.hpp"
#include "section.hpp"
#include "coloshell.hpp"
#include "rpexception.hpp"

Program::Program(const std::string & program_path)
: m_cpu(NULL), m_exformat(NULL)
{
    unsigned int magic_dword = 0;

    std::cout << "Trying to open '" << program_path << "'.." << std::endl;
    m_file.open(program_path.c_str(), std::ios::binary);
    if(m_file.is_open() == false)
        RAISE_EXCEPTION("Cannot open the file");

    m_file.read((char*)&magic_dword, sizeof(magic_dword));

    ExecutableFormat::E_ExecutableFormat guessed_format = ExecutableFormat::FindExecutableFormat(magic_dword);
    if(guessed_format == ExecutableFormat::FORMAT_UNKNOWN)
        RAISE_EXCEPTION("Do not know the executable format of your file");

    switch(guessed_format)
    {
        case ExecutableFormat::FORMAT_PE:
        {
            m_exformat = new (std::nothrow) PE();
            break;
        }

        case ExecutableFormat::FORMAT_ELF:
        {
            m_exformat = new (std::nothrow) Elf();
            break;
        }
    }

    if(m_exformat == NULL)
        RAISE_EXCEPTION("Cannot allocate an executable format");

    m_cpu = m_exformat->get_cpu(m_file);

    std::cout << "FileFormat: " << m_exformat->get_class_name() << ", Arch: " << m_cpu->get_class_name() << std::endl;
}

Program::~Program(void)
{
    if(m_file.is_open())
        m_file.close();
    
    if(m_exformat != NULL)
        delete m_exformat;

    if(m_cpu != NULL)
        delete m_cpu;
}

void Program::display_information(VerbosityLevel lvl)
{
    m_exformat->display_information(lvl);
}

void Program::find_and_display_gadgets(void)
{
    std::cout << std::endl << "Wait a few seconds, rp++ is researching gadgets.." << std::endl;

    /* To do a ROP gadget research, we need to know the executable section */
    std::vector<Section*> executable_sections = m_exformat->get_executables_section(m_file);

    /* Walk the executable sections */
    for(std::vector<Section*>::iterator it = executable_sections.begin(); it != executable_sections.end(); ++it)
    {
        std::cout << "in " << (*it)->get_name() << ".. ";

        /* Let the cpu do the research (BTW we use a std::map in order to keep only unique gadget) */
        std::map<std::string, Gadget*> gadgets_found = m_cpu->find_gadget_in_memory(
            (*it)->get_section_buffer(),
            (*it)->get_size()
        );

        std::cout << std::dec << gadgets_found.size() << " unique gadgets found" << std::endl;

        /* Now we walk the gadgets found */
       
        /*for(std::map<std::string, Gadget*>::iterator it2 = gadgets_found.begin(); it2 != gadgets_found.end(); ++it2)
        {
            unsigned long long absolute_offset_section = (*it)->get_offset();
            unsigned long long absolute_offset_gadget = absolute_offset_section + it2->second->get_offset();
        */
            /* Do not forget that VA != PA */
        /*    unsigned long long va = m_exformat->raw_offset_to_va(absolute_offset_gadget, absolute_offset_section);
            
            display_gadget_lf(va, it2);
        }
        */
    }
}