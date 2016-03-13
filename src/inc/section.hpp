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
#ifndef SECTION_HPP
#define SECTION_HPP

#include <string>
#include <list>
#include <fstream>
#include <vector>

/*! \class Section
 *
 *   Each binary is divided in section, actually it is a chunk of the binary of a specific size which contains code or data
 */
class Section
{
    public:
        
        /*! The different rights a section can have ; those rights are usually combined by an OR operation */
        enum Properties
        {
            Readable, /*!< the section is readable*/
            Writeable, /*!< the section is writeable*/
            Executable /*!< the section is executable*/
        };

        /*!
         *  \brief The constructor will make a copy of the memory in its own buffer
         *   
         *  \param name: The name of the section
         *  \param offset: It is the offset in file where you can find the section
         *  \param vaddr: Virtual address of the section
         *  \param size: It is the size of the section
         */
        explicit Section(const char *name, const uint64_t offset, const uint64_t vaddr, const uint64_t size);
        
        /*!
         *  \brief Get the name of the section
         *   
         *  \return the name of the section
         */
        std::string get_name(void) const;

        /*!
         *  \brief Get the size of the section
         *   
         *  \return the size of the section
         */
        uint64_t get_size(void) const;

        /*!
         *  \brief Get the content of the section (it's the internal copy)
         *   
         *  \return a pointer on the buffer
         */
        const uint8_t *get_section_buffer(void) const;

        /*!
         *  \brief Get the (raw) offset of the section ; in other word, where it was found in the binary
         *   
         *  \return the offset where the section was found in the binary
         */
        const uint64_t get_offset(void) const;

        /*!
         *  \brief Search in memory a sequence of bytes
         *   
         *  \param val: A pointer on the bytes you want to search
         *  \param size: The size of the buffer
         *
         *  \return a list of offset (relative to the section) where it found the sequence of bytes
         */
        std::list<uint64_t> search_in_memory(const uint8_t *val, const uint32_t size);
        
        /*!
         *  \brief Dump the raw section of your file
         *   
         *  \param file: The file
         */
        void dump(std::ifstream &file);

        /*!
         *  \brief Set the properties of the section
         *   
         *  \param props: The properties of the section
         */
        void set_props(Properties props);

        uint64_t get_vaddr(void) const;

    private:

        std::string m_name; /*!< the name of the section*/
        
        const uint64_t m_offset; /*!< the raw offset of the section*/
        
        const uint64_t m_size; /*!< the size of the section of the section*/
        
        Properties m_props; /*!< the properties of the section*/
        
        std::vector<uint8_t> m_section; /*!< the section content*/

        uint64_t m_vaddr; /* !< the virtual address of the section*/
};

#endif
