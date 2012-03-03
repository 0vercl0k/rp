#include "section.hpp"

Section::Section(const unsigned int offset, const unsigned int size, const Properties props)
: m_offset(offset), m_size(size), m_props(props)
{
}

Section::~Section(void)
{
}