#include "section.hpp"

Section::Section(const char *name, const unsigned int offset, const unsigned int size, const Properties props)
: m_name(name), m_size(size), m_props(props), m_section(NULL)
{
    m_section = new unsigned char[m_size];
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