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
#ifndef MACHO_STRUCT_HPP
#define MACHO_STRUCT_HPP

#include "platform.h"
#include "toolbox.hpp"
#include "coloshell.hpp"
#include "section.hpp"

#include <cstring>
#include <vector>

#ifdef WINDOWS
#pragma pack(push)
#pragma pack(1)
#endif

#define CPU_TYPE_x86_64 0x1000007
#define CPU_TYPE_I386   7

template<class T>
struct RP_MACH_HEADER
{};

template<>
struct RP_MACH_HEADER<x86Version>
{
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;

    void display(VerbosityLevel lvl) const
    {
        w_yel_lf("-> mach_header32:");
        
        display_hex_2fields_lf(ncmds, sizeofcmds);

        if(lvl > VERBOSE_LEVEL_1)
        {
            display_hex_field_lf(cpusubtype);
        }

        if(lvl > VERBOSE_LEVEL_2)
        {
            display_hex_2fields_lf(magic, cpusubtype);
            display_hex_2fields_lf(filetype, flags);
        }
    }
}
#ifdef LINUX
__attribute__((packed))
#endif
;

template<>
struct RP_MACH_HEADER<x64Version>
{
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;

    void display(VerbosityLevel lvl) const
    {
        w_yel_lf("-> mach_header64:");

        display_hex_2fields_lf(ncmds, sizeofcmds);

        if(lvl > VERBOSE_LEVEL_1)
        {
            display_hex_field_lf(cpusubtype);
        }

        if(lvl > VERBOSE_LEVEL_2)
        {
            display_hex_2fields_lf(magic, cpusubtype);
            display_hex_2fields_lf(filetype, flags);
            display_hex_field_lf(reserved);
        }
    }
}
#ifdef LINUX
__attribute__((packed))
#endif
;

#define LC_SEGMENT    1
#define LC_SEGMENT_64 0x19

struct RP_LOAD_COMMAND
{
    uint32_t cmd;
    uint32_t cmdsize;
}
#ifdef LINUX
__attribute__((packed))
#endif
;

template<class T>
struct RP_SEGMENT_COMMAND
{
    //RP_LOAD_COMMAND command;

    uint8_t segname[16];
    T             vmaddr;
    T             vmsize;
    T             fileoff;
    T             filesize;
    uint32_t      maxprot;
    uint32_t      initprot;
    uint32_t      nsects;
    uint32_t      flags;

    explicit RP_SEGMENT_COMMAND()
    {}

    void display(VerbosityLevel lvl) const
    {
        w_yel_lf("-> segment_command");
        std::cout << "    " << segname << std::endl;

        if(lvl > VERBOSE_LEVEL_1)
        {
            display_hex_field_lf(vmaddr);
            display_hex_field_lf(vmsize);
            display_hex_field_lf(fileoff);
            display_hex_field_lf(filesize);
        }

        if(lvl > VERBOSE_LEVEL_2)
        {
            display_hex_2fields_lf(maxprot, initprot);
            display_hex_2fields_lf(nsects, flags);
        }
    }
}
#ifdef LINUX
__attribute__((packed))
#endif
;

using SegmentCommand32 = RP_SEGMENT_COMMAND<x86Version>;
using SegmentCommand64 = RP_SEGMENT_COMMAND<x64Version>;

#define S_ATTR_PURE_INSTRUCTIONS 0x80000000
#define S_ATTR_SOME_INSTRUCTIONS 0x400

template<class T>
struct RP_SECTION
{
};

template<>
struct RP_SECTION<x86Version>
{
    uint8_t sectname[16];
    uint8_t segname[16];
    uint32_t      addr;
    uint32_t      size;
    uint32_t      offset;
    uint32_t      align;
    uint32_t      reloff;
    uint32_t      nreloc;
    uint32_t      flags;
    uint32_t      reserved1;
    uint32_t      reserved2;

    explicit RP_SECTION()
    {}

    void display(VerbosityLevel lvl) const
    {
        w_yel_lf("-> section32");
        std::cout << "    " << segname << "." << sectname << std::endl;

        if(lvl > VERBOSE_LEVEL_1)
        {
            display_hex_2fields_lf(addr, size);
            display_hex_2fields_lf(offset, align);
        }

        if(lvl > VERBOSE_LEVEL_2)
        {
            display_hex_2fields_lf(reloff, nreloc);
            display_hex_2fields_lf(flags, reserved1);
        }
    }
}
#ifdef LINUX
__attribute__((packed))
#endif
;

template<>
struct RP_SECTION<x64Version>
{
    uint8_t      sectname[16];
    uint8_t      segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t           offset;
    uint32_t           align;
    uint32_t           reloff;
    uint32_t           nreloc;
    uint32_t           flags;
    uint32_t           reserved1;
    uint32_t           reserved2;
    uint32_t           reserved3;

    explicit RP_SECTION()
    {}

    void display(VerbosityLevel lvl) const
    {
        w_yel_lf("-> section64");
        std::cout << "    " << segname << "." << sectname << std::endl;

        if(lvl > VERBOSE_LEVEL_1)
        {
            display_hex_field_lf(addr);
            display_hex_field_lf(size);
            display_hex_2fields_lf(offset, align);
        }

        if(lvl > VERBOSE_LEVEL_2)
        {
            display_hex_2fields_lf(reloff, nreloc);
            display_hex_2fields_lf(flags, reserved1);
            display_hex_2fields_lf(reserved2, reserved3);
        }
    }
}
#ifdef LINUX
__attribute__((packed))
#endif
;

#ifdef WINDOWS
#pragma pack(pop)
#endif

struct MachoLayout
{  
    virtual void fill_structures(std::ifstream &file)  = 0;
    virtual uint32_t get_size_mach_header(void) const = 0;
    virtual void display(VerbosityLevel lvl = VERBOSE_LEVEL_1) const = 0;
    virtual std::vector<std::shared_ptr<Section>> get_executable_section(std::ifstream &file) = 0;
    virtual uint64_t get_image_base_address(void) = 0;
};

template<class T>
struct MachoArchLayout : public MachoLayout
{
    uint64_t base;
    RP_MACH_HEADER<T> header;
    std::vector<std::shared_ptr<RP_SEGMENT_COMMAND<T>>> seg_commands;
    std::vector<std::shared_ptr<RP_SECTION<T>>> sections;

    explicit MachoArchLayout()
    : MachoLayout(), base(0)
    {}

    uint32_t get_size_mach_header(void) const
    {
        return sizeof(RP_MACH_HEADER<T>);
    }

    void fill_structures(std::ifstream &file)
    {
        bool is_all_section_walked = false;
        std::streampos off = file.tellg();

        /* 1] Fill the header structure */
        file.seekg(0, std::ios::beg);
        file.read((char*)&header, sizeof(RP_MACH_HEADER<T>));

        /* 2] The load commands now */
        for(uint32_t i = 0; i < header.ncmds; ++i)
        {
            RP_LOAD_COMMAND loadcmd {0};

            file.read((char*)&loadcmd, sizeof(RP_LOAD_COMMAND));
            switch(loadcmd.cmd)
            {
                case LC_SEGMENT:
                case LC_SEGMENT_64:
                {
                    std::shared_ptr<RP_SEGMENT_COMMAND<T>> seg_cmd = std::make_shared<RP_SEGMENT_COMMAND<T>>();

                    file.read((char*)seg_cmd.get(), sizeof(RP_SEGMENT_COMMAND<T>));
                    seg_commands.push_back(seg_cmd);

                    if(strcasecmp((char*)seg_cmd->segname, "__TEXT") == 0)
                        // If this is the __text segment, we populate the base address of the program
                        base = uint64_t(seg_cmd->vmaddr);

                    /* 
                       Directly following a segment_command data structure is an array of section data 
                       structures, with the exact count determined by the nsects field of the segment_command
                       structure.
                    */
                    for(uint32_t j = 0; j < seg_cmd->nsects; ++j)
                    {
                        std::shared_ptr<RP_SECTION<T>> sect = std::make_shared<RP_SECTION<T>>();

                        file.read((char*)sect.get(), sizeof(RP_SECTION<T>));
                        sections.push_back(sect);
                    }

                    break;
                }

                default:
                {
                    /* 
                        XXX: We assume that all SEGMENT_HEADER[_64] are in first, and they are all contiguous
                        The proper way should be add cases for each COMMAND possible, and increment the file pointer of the size of the COMMAND read
                    */ 
                    is_all_section_walked = true;
                    break;
                }
            }

            if(is_all_section_walked)
                break;
        }

		file.seekg(off);
    }

    std::vector<std::shared_ptr<Section>> get_executable_section(std::ifstream &file)
    {
        std::vector<std::shared_ptr<Section>> exc_sect;

        for(auto &section : sections)
        {
            if(section->flags & S_ATTR_PURE_INSTRUCTIONS || section->flags & S_ATTR_SOME_INSTRUCTIONS)
            {
				// XXX: Hum g++ doesn't like make_shared + section being a packed structure
                std::shared_ptr<Section> s(new Section(
                    (char*)section->sectname,
                    section->offset,
                    section->addr,
                    section->size
                ));

                s->dump(file);

                s->set_props(Section::Executable);

                exc_sect.push_back(s);
            }
        }
        return exc_sect;
    }

    void display(VerbosityLevel lvl = VERBOSE_LEVEL_1) const
    {
        header.display(lvl);

        for(auto &segcommand : seg_commands)
            segcommand->display(lvl);

        for(auto &section : sections)
            section->display(lvl);
    }

    uint64_t get_image_base_address(void)
    {
        return base;
    }
};

#endif
