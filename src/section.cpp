#include "section.hpp"
#include "toolbox.hpp"

Section::Section(std::ifstream &file, const char *name, const unsigned long long offset, const unsigned long long size, const Properties props)
: m_name(name), m_offset(offset), m_size(size), m_props(props), m_section(NULL)
{
    /* I don't want ANY of this int overflow crap. */
    if((offset + size) < offset)
        throw std::string("Integer overflow spotted!");

    /* NB: std::streampos performs unsigned check */
    unsigned long long fsize = get_file_size(file);
    if((offset+size) >= fsize)
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

unsigned long long Section::get_size(void) const
{
    return m_size;
}

unsigned char* Section::get_section_buffer(void) const
{
    return m_section;
}

const unsigned long long Section::get_offset(void) const
{
    return m_offset;
}