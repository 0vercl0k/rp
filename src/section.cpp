/*
    This file is part of rp++.

    Copyright (C) 2014, Axel "0vercl0k" Souchet <0vercl0k at tuxfamily.org>
    All rights reserved.

    rp++ is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    rp++ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with rp++.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "section.hpp"
#include "toolbox.hpp"
#include "rpexception.hpp"
#include "safeint.hpp"

#include <cstring>

Section::Section(const char *name, const uint64_t offset, const uint64_t vaddr, const uint64_t size)
: m_name(name), m_offset(offset), m_size(size), m_vaddr(vaddr)
{
}

std::string Section::get_name(void) const
{
    return m_name;
}

uint64_t Section::get_size(void) const
{
    return m_size;
}

const uint8_t* Section::get_section_buffer(void) const
{
    return m_section.data();
}

const uint64_t Section::get_offset(void) const
{
    return m_offset;
}

std::list<uint64_t> Section::search_in_memory(const uint8_t *val, const uint32_t size)
{
    std::list<uint64_t> val_found;

    for(uint64_t offset = 0; offset < m_size; ++offset)
        if(std::memcmp(m_section.data() + offset, val, size) == 0)
            val_found.push_back(offset);

    return val_found;
}

void Section::set_props(Properties props)
{
    m_props = props;
}

void Section::dump(std::ifstream &file)
{
    /* NB: std::streampos performs unsigned check */
    uint64_t fsize = get_file_size(file);
    if(SafeAddU64(m_offset, m_size) > fsize)
        RAISE_EXCEPTION("Your file seems to be fucked up");

    std::streampos backup = file.tellg();

    file.seekg((uint32_t)m_offset, std::ios::beg);
    m_section.resize((uint32_t)m_size);

    file.read((char*)m_section.data(), (uint32_t)m_size);

    file.seekg(backup);
}

uint64_t Section::get_vaddr(void) const
{
    return m_vaddr;
}
