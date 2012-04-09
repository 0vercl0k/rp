#include "section.hpp"
#include "toolbox.hpp"
#include "rpexception.hpp"
#include "safeint.hpp"

#include <cstring>

Section::Section(std::ifstream &file, const char *name, const unsigned long long offset, const unsigned long long size, const Properties props)
: m_name(name), m_offset(offset), m_size(size), m_props(props), m_section(NULL)
{
    /* NB: std::streampos performs unsigned check */
    unsigned long long fsize = get_file_size(file);
    if(SafeAddU64(offset, size) > fsize)
        RAISE_EXCEPTION("Your file seems to be fucked up");

    std::streampos backup = file.tellg();

    file.seekg((unsigned int)offset, std::ios::beg);
    m_section = new (std::nothrow) unsigned char[(unsigned int)m_size];
    if(m_section == NULL)
        RAISE_EXCEPTION("Cannote allocate a section.");

    file.read((char*)m_section, (unsigned int)m_size);

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

std::list<unsigned long long> Section::search_in_memory(const unsigned char *val, const unsigned int size)
{
    std::list<unsigned long long> val_found;

    for(unsigned long long offset = 0; offset < m_size; ++offset)
        if(std::memcmp(m_section + offset, val, size) == 0)
            val_found.push_back(offset);

    return val_found;
}
