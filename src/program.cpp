#include "program.hpp"

#include <iostream>

#include "pe.hpp"
#include "elf.hpp"

Program::Program(const std::string & program_path)
: m_cpu(NULL), m_exformat(NULL)
{
    unsigned int magic_dword = 0;

    std::cout << "Trying to open '" << program_path << "'.." << std::endl;
    m_file.open(program_path.c_str(), std::ios::binary);
    if(m_file.is_open() == false)
        throw std::string("Cannot open the file");

    m_file.read((char*)&magic_dword, sizeof(magic_dword));

    ExecutableFormat::E_ExecutableFormat guessed_format = ExecutableFormat::FindExecutableFormat(magic_dword);
    if(guessed_format == ExecutableFormat::FORMAT_UNKNOWN)
        throw std::string("Do not know the executable format of your file");

    switch(guessed_format)
    {
        case ExecutableFormat::FORMAT_PE:
        {
            m_exformat = new PE();
            break;
        }

        case ExecutableFormat::FORMAT_ELF:
        {
            m_exformat = new Elf();
            break;
        }
    }

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