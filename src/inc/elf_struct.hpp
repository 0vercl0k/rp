/*
    This file is part of rp++.

    Copyright (C) 2013, Axel "0vercl0k" Souchet <0vercl0k at tuxfamily.org>
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
#ifndef ELF_STRUCT_H
#define ELF_STRUCT_H

#include "platform.h"
#include "toolbox.hpp"
#include "coloshell.hpp"
#include "section.hpp"
#include "rpexception.hpp"

#include <iostream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <string>
#include <cstring>

/* Information extracted from winnt.h ; a bit of template-kung-fu and here it goes ! */

#define EI_NIDENT       16

#ifdef WINDOWS
#pragma pack(push)
#pragma pack(1)
#endif

template<class T>
struct Elf_Ehdr
{
    unsigned char  e_ident[EI_NIDENT];
    unsigned short e_type;
    unsigned short e_machine;
    unsigned int   e_version;
    T              e_entry;  /* Entry point */
    T              e_phoff;
    T              e_shoff;
    unsigned int   e_flags;
    unsigned short e_ehsize;
    unsigned short e_phentsize;
    unsigned short e_phnum;
    unsigned short e_shentsize;
    unsigned short e_shnum;
    unsigned short e_shstrndx;

    void display(VerbosityLevel lvl = VERBOSE_LEVEL_1) const
    {
        w_yel_lf("-> ELF_Ehdr:");

        display_short_hex_field_lf(e_phoff);
        display_short_hex_field_lf(e_shoff);

        display_short_hex_field_lf(e_flags);

        display_short_hex_2fields_lf(e_phentsize, e_phnum);
        display_short_hex_2fields_lf(e_shentsize, e_shnum);
        display_short_hex_2fields_lf(e_shstrndx, e_ehsize);
    }
}
#ifdef LINUX
__attribute__((packed))
#endif
;


typedef Elf_Ehdr<x86Version> Elf32_Ehdr;
typedef Elf_Ehdr<x64Version> Elf64_Ehdr;

#define EI_OSABI 7
#define EI_CLASS 4

#define ELFCLASS32 1
#define ELFCLASS64 2

template<class T>
struct Elf_Phdr
{}
#ifdef LINUX
__attribute__((packed))
#endif
;

std::string type_to_str(const unsigned int p_type);

std::string flags_to_str(const unsigned int p_flags);

template<>
struct Elf_Phdr<x86Version>
{
    unsigned int p_type;
    unsigned int p_offset;
    unsigned int p_vaddr;
    unsigned int p_paddr;
    unsigned int p_filesz;
    unsigned int p_memsz;
    unsigned int p_flags;
    unsigned int p_align;

    void display(VerbosityLevel lvl = VERBOSE_LEVEL_1) const
    {
        w_yel_lf("-> Elf_Phdr32: ");
        std::cout << "    " << type_to_str(p_type) << " " << flags_to_str(p_flags) << std::endl;

        if(lvl > VERBOSE_LEVEL_1)
        {
            display_hex_2fields_lf(p_vaddr, p_filesz);
        }

        if(lvl > VERBOSE_LEVEL_2)
        {
            display_hex_2fields_lf(p_align, p_flags);
        }

        display_hex_2fields_lf(p_offset, p_paddr);
    }
}
#ifdef LINUX
__attribute__((packed))
#endif
;

template<>
struct Elf_Phdr<x64Version>
{
    unsigned int       p_type;
    unsigned int       p_flags;
    unsigned long long p_offset;
    unsigned long long p_vaddr;
    unsigned long long p_paddr;
    unsigned long long p_filesz;
    unsigned long long p_memsz;
    unsigned long long p_align;

    void display(VerbosityLevel lvl = VERBOSE_LEVEL_1) const
    {
        w_yel_lf("-> Elf_Phdr64:"); 
        std::cout << "    " << type_to_str(p_type) << " " << flags_to_str(p_flags) << std::endl;

        if(lvl > VERBOSE_LEVEL_1)
        {
            display_short_hex_2fields_lf(p_vaddr, p_filesz);
        }

        if(lvl > VERBOSE_LEVEL_2)
        {
            display_short_hex_2fields_lf(p_align, p_flags);
        }

        display_short_hex_2fields_lf(p_offset, p_paddr);
    }
}
#ifdef LINUX
__attribute__((packed))
#endif
;

typedef Elf_Phdr<x86Version> Elf32_Phdr;
typedef Elf_Phdr<x64Version> Elf64_Phdr;

template<class T>
struct Elf_Shdr
{
    unsigned int sh_name;
    unsigned int sh_type;
    T            sh_flags;
    T            sh_addr;
    T            sh_offset;
    T            sh_size;
    unsigned int sh_link;
    unsigned int sh_info;
    T            sh_addralign;
    T            sh_entsize;
}
#ifdef LINUX
__attribute__((packed))
#endif
;

typedef Elf_Shdr<x86Version> Elf32_Shdr;
typedef Elf_Shdr<x64Version> Elf64_Shdr;

#ifdef WINDOWS
#pragma pack(pop)
#endif

template<class T>
struct Elf_Shdr_Abstraction
{
    Elf_Shdr<T> header;
    std::string name;

    void display(VerbosityLevel lvl = VERBOSE_LEVEL_1) const
    {
        /* remove the warning C4100 with /W4 */
        lvl = VERBOSE_LEVEL_1;

        std::cout << "0x" << std::setw(15) << std::setfill(' ') << std::left << header.sh_addr;
        std::cout << "0x" << std::setw(15) << std::setfill(' ') << std::left << header.sh_size;
        std::cout << std::setw(30) << std::setfill(' ') << std::left << name << std::endl;
        
        /* 
        if(lvl > VERBOSE_LEVEL_1)
        {
            std::cout << std::hex << "\t sh_type: " << header.sh_type << std::endl;
            std::cout << std::hex << "\t sh_flags: " <<header.sh_flags << std::endl;
            std::cout << std::hex << "\t sh_offset: " << header.sh_offset << std::endl;
        }

        if(lvl > VERBOSE_LEVEL_2)
        {
            std::cout << std::hex << "\t sh_link: " << header.sh_link << std::endl;
            std::cout << std::hex << "\t sh_info: " << header.sh_info << std::endl;
            std::cout << std::hex << "\t sh_addralign: " << header.sh_addralign << std::endl;
            std::cout << std::hex << "\t sh_entsize: " << header.sh_entsize << std::endl;
        }
        */
    }
};

typedef Elf_Shdr_Abstraction<x86Version> Elf_Shdr32_Abstraction;
typedef Elf_Shdr_Abstraction<x64Version> Elf_Shdr64_Abstraction;

struct ExecutableLinkingFormatLayout
{
    virtual ~ExecutableLinkingFormatLayout(void)
    {}
    
    virtual void fill_structures(std::ifstream &file) = 0;
    virtual void display(VerbosityLevel lvl = VERBOSE_LEVEL_1) const = 0;
    virtual std::vector<Section*> get_executable_section(std::ifstream &file) const = 0;
};

#define SHT_SYMTAB      2
#define SHT_STRTAB      3

template<class T>
struct ELFLayout : public ExecutableLinkingFormatLayout
{
    Elf_Ehdr<T> elfHeader;
    std::vector<Elf_Phdr<T>*> elfProgramHeaders;
    std::vector<Elf_Shdr_Abstraction<T>*> elfSectionHeaders;
    T offset_string_table, size_string_table;

    typedef typename std::vector<Elf_Phdr<T>*>::const_iterator iter_elf_phdr;
    typedef typename std::vector<Elf_Shdr_Abstraction<T>*>::const_iterator iter_shdr_abs;


    ~ELFLayout(void)
    {
        for(iter_elf_phdr it = elfProgramHeaders.begin();
            it != elfProgramHeaders.end();
            ++it)
            delete *it;

        for(iter_shdr_abs it = elfSectionHeaders.begin();
            it != elfSectionHeaders.end();
            ++it)
            delete *it;
    }

    void display(VerbosityLevel lvl = VERBOSE_LEVEL_1) const
    {
        unsigned int i = 0;
        elfHeader.display(lvl);

        for(iter_elf_phdr it = elfProgramHeaders.begin();
            it != elfProgramHeaders.end();
            ++it)
                (*it)->display(lvl);

        w_yel_lf("-> Elf Headers:");
        std::cout << std::setw(12) << std::setfill(' ') << std::left;
        w_gre("id");
        std::cout << std::setw(17) << std::setfill(' ') << std::left;
        w_gre("addr");
        std::cout << std::setw(17) << std::setfill(' ') << std::left;
        w_gre("size");
        std::cout << std::setw(32) << std::setfill(' ') << std::left;
        w_gre("name");
        std::cout << std::endl << std::setw(70) << std::setfill('-') << "-" << std::endl;

        for(iter_shdr_abs it = elfSectionHeaders.begin();
            it != elfSectionHeaders.end();
            ++it)
        {
            std::cout << "0x" << std::setw(10) << std::setfill(' ') << std::left << i++;
            (*it)->display(lvl);
        }
    }

    T find_string_table(std::ifstream &file)
    {
        
        Elf_Shdr<T> elf_shdr;
        std::streampos off = file.tellg();

        file.seekg((std::streamoff)elfHeader.e_shoff, std::ios::beg);

        for(unsigned int i = 0; i < elfHeader.e_shnum; ++i)
        {
            file.read((char*)&elf_shdr, sizeof(Elf_Shdr<T>));
            if(elf_shdr.sh_addr == 0 && elf_shdr.sh_type == SHT_STRTAB)
            {
                offset_string_table = elf_shdr.sh_offset;
                size_string_table = elf_shdr.sh_size;
                break;
            }
        }

        file.seekg(off);
        return offset_string_table;
    }

    void fill_structures(std::ifstream &file)
    {
        /* Remember where the caller was in the file */
        std::streampos off = file.tellg();
        std::streampos fsize = 0;

        /* 1] Dump the Elf Header */
        file.seekg(0, std::ios::end);
        fsize = file.tellg();
        file.seekg(0, std::ios::beg);
        file.read((char*)&elfHeader, sizeof(Elf_Ehdr<T>));

        /* 2] Goto the first Program Header, and dump them */
        file.seekg((std::streamoff)elfHeader.e_phoff, std::ios::beg);
        for(unsigned int i = 0; i < elfHeader.e_phnum; ++i)
        {
            Elf_Phdr<T>* pElfProgramHeader = new (std::nothrow) Elf_Phdr<T>;
            if(pElfProgramHeader == NULL)
                RAISE_EXCEPTION("Cannot allocate pElfProgramHeader");

            file.read((char*)pElfProgramHeader, sizeof(Elf_Phdr<T>));
            elfProgramHeaders.push_back(pElfProgramHeader);
        }

        /* 3.1] If we want to know the name of the different section, 
         *    we need to find the string table section 
         */
        find_string_table(file);

        /* 3.2] Keep the string table in memory */
        file.seekg((std::streamoff)offset_string_table, std::ios::beg);

        if ((unsigned long long)size_string_table > fsize)
            size_string_table = (unsigned long long)fsize - elfHeader.e_shoff;

        char* string_table_section = new (std::nothrow) char[(unsigned int)size_string_table];
        if(string_table_section == NULL)
            RAISE_EXCEPTION("Cannot allocate string_table_section");


        file.read(string_table_section, (std::streamsize)size_string_table);
        if (!file)
            RAISE_EXCEPTION("Cannot read string_table_section");

        /* 3.3] Goto the first Section Header, and dump them !*/
        file.seekg((std::streamoff)elfHeader.e_shoff, std::ios::beg);
        for(unsigned int i = 0; i < elfHeader.e_shnum; ++i)
        {
            Elf_Shdr_Abstraction<T>* pElfSectionHeader = new (std::nothrow) Elf_Shdr_Abstraction<T>;
            if(pElfSectionHeader == NULL)
                RAISE_EXCEPTION("Cannot allocate pElfSectionHeader");

            file.read((char*)&pElfSectionHeader->header, sizeof(Elf_Shdr<T>));

            /* 3.4] Resolve the name of the section */
            if(pElfSectionHeader->header.sh_name < size_string_table)
            {
                /* Yeah we know where is the string */
                char *name_section = string_table_section + pElfSectionHeader->header.sh_name;
                std::string s(name_section, std::strlen(name_section));
                pElfSectionHeader->name = (s == "") ? std::string("unknown section") : s;
            }

            elfSectionHeaders.push_back(pElfSectionHeader);
        }

        /* Set correctly the pointer */
        file.seekg(off);

        delete[] string_table_section;
    }

    std::vector<Section*> get_executable_section(std::ifstream &file) const
    {
        std::vector<Section*> exec_sections;

        for(iter_elf_phdr it = elfProgramHeaders.begin(); it != elfProgramHeaders.end(); ++it)
        {
            if((*it)->p_flags & 1)
            {
                Section *sec = new (std::nothrow) Section(
                    type_to_str((*it)->p_type).c_str(),
                    (*it)->p_offset,
                    (*it)->p_vaddr,
                    (*it)->p_filesz
                );

                if(sec == NULL)
                    RAISE_EXCEPTION("Cannot alocate a section");
                
                sec->dump(file);
                sec->set_props(Section::Executable);

                exec_sections.push_back(sec);
            }
        }

        return exec_sections;
    }
};

#endif
