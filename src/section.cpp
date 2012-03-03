#include "section.hpp"
#include "toolbox.hpp"

Section::Section(std::ifstream &file, const char *name, const unsigned int offset, const unsigned int size, const Properties props)
: m_name(name), m_size(size), m_props(props), m_section(NULL)
{
    /* I don't want ANY of this int overflow crap. */
    if((offset + size) < offset)
        throw std::string("Integer overflow spotted!");

    /* NB: std::streampos performs unsigned check */
    if((offset+size) >= get_file_size(file))
        throw std::string("Your file seems to be fucked up");

    std::streampos backup = file.tellg();

    file.seekg(offset, std::ios::beg);
    m_section = new unsigned char[m_size];
    file.read((char*)m_section, m_size);

    file.seekg(backup);
}

Section::~Section(void)
{
    if(m_section != NULL)
        delete [] m_section;
}

std::string Section::get_name(void) const
{
    return m_name;
}

unsigned int Section::get_size(void) const
{
    return m_size;
}

unsigned char* Section::get_section_buffer(void) const
{
    return m_section;
}