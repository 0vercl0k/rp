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
#ifndef MACHO_STRUCT_HPP
#define MACHO_STRUCT_HPP

#include "platform.h"
#include "toolbox.hpp"
#include "coloshell.hpp"
#include "section.hpp"

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
    unsigned int magic;
    unsigned int cputype;
    unsigned int cpusubtype;
    unsigned int filetype;
    unsigned int ncmds;
    unsigned int sizeofcmds;
    unsigned int flags;

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
    unsigned int magic;
    unsigned int cputype;
    unsigned int cpusubtype;
    unsigned int filetype;
    unsigned int ncmds;
    unsigned int sizeofcmds;
    unsigned int flags;
    unsigned int reserved;

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
    unsigned int cmd;
    unsigned int cmdsize;
}
#ifdef LINUX
__attribute__((packed))
#endif
;

template<class T>
struct RP_SEGMENT_COMMAND
{
    //RP_LOAD_COMMAND command;

    unsigned char segname[16];
    T             vmaddr;
    T             vmsize;
    T             fileoff;
    T             filesize;
    unsigned int maxprot;
    unsigned int initprot;
    unsigned int nsects;
    unsigned int flags;

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

typedef RP_SEGMENT_COMMAND<x86Version> SegmentCommand32;
typedef RP_SEGMENT_COMMAND<x64Version> SegmentCommand64;

#define S_ATTR_PURE_INSTRUCTIONS 0x80000000
#define S_ATTR_SOME_INSTRUCTIONS 0x400

template<class T>
struct RP_SECTION
{
};

template<>
struct RP_SECTION<x86Version>
{
    unsigned char sectname[16];
    unsigned char segname[16];
    unsigned int  addr;
    unsigned int  size;
    unsigned int  offset;
    unsigned int  align;
    unsigned int  reloff;
    unsigned int  nreloc;
    unsigned int  flags;
    unsigned int  reserved1;
    unsigned int  reserved2;

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
    unsigned char      sectname[16];
    unsigned char      segname[16];
    unsigned long long addr;
    unsigned long long size;
    unsigned int       offset;
    unsigned int       align;
    unsigned int       reloff;
    unsigned int       nreloc;
    unsigned int       flags;
    unsigned int       reserved1;
    unsigned int       reserved2;
    unsigned int       reserved3;

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
    virtual ~MachoLayout(void)
    {};

    virtual void fill_structures(std::ifstream &file)  = 0;
    virtual unsigned int get_size_mach_header(void) const = 0;
    virtual void display(VerbosityLevel lvl = VERBOSE_LEVEL_1) const = 0;
    virtual std::vector<Section*> get_executable_section(std::ifstream &file) = 0;
};

template<class T>
struct MachoArchLayout : public MachoLayout
{
    RP_MACH_HEADER<T> header;
    std::vector<RP_SEGMENT_COMMAND<T>*> seg_commands;
    std::vector<RP_SECTION<T>*> sections;

    typedef typename std::vector<RP_SECTION<T>*>::const_iterator iter_rp_section;
    typedef typename std::vector<RP_SEGMENT_COMMAND<T>*>::const_iterator iter_rp_segment;

    ~MachoArchLayout(void)
    {
        for(iter_rp_segment it = seg_commands.begin(); it != seg_commands.end(); ++it)
            delete *it;

        for(iter_rp_section it = sections.begin(); it != sections.end(); ++it)
            delete *it;
    }

    unsigned int get_size_mach_header(void) const
    {
        return sizeof(RP_MACH_HEADER<T>);
    }

    void fill_structures(std::ifstream &file)
    {
        bool is_all_section_walked = false;
        std::streampos off = file.tellg();

        if (off == -1)
            RAISE_EXCEPTION("Error while using file.tellg().");

        /* 1] Fill the header structure */
        file.seekg(0, std::ios::beg);
        file.read((char*)&header, sizeof(RP_MACH_HEADER<T>));

        /* 2] The load commands now */
        for(unsigned int i = 0; i < header.ncmds; ++i)
        {
            RP_LOAD_COMMAND loadcmd = {0, 0};

            file.read((char*)&loadcmd, sizeof(RP_LOAD_COMMAND));
            switch(loadcmd.cmd)
            {
                case LC_SEGMENT:
                case LC_SEGMENT_64:
                {
                    RP_SEGMENT_COMMAND<T>* seg_cmd = new (std::nothrow) RP_SEGMENT_COMMAND<T>;
                    if(seg_cmd == NULL)
                        RAISE_EXCEPTION("Cannot allocate seg_cmd");

                    file.read((char*)seg_cmd, sizeof(RP_SEGMENT_COMMAND<T>));
                    seg_commands.push_back(seg_cmd);

                    /* 
                       Directly following a segment_command data structure is an array of section data 
                       structures, with the exact count determined by the nsects field of the segment_command
                       structure.
                    */
                    for(unsigned int j = 0; j < seg_cmd->nsects; ++j)
                    {
                        RP_SECTION<T>* sect = new (std::nothrow) RP_SECTION<T>;
                        if(sect == NULL)
                            RAISE_EXCEPTION("Cannot allocate sect");

                        file.read((char*)sect, sizeof(RP_SECTION<T>));
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
    }

    std::vector<Section*> get_executable_section(std::ifstream &file)
    {
        std::vector<Section*> exc_sect;

        for(iter_rp_section it = sections.begin(); it != sections.end(); ++it)
        {
            if((*it)->flags & S_ATTR_PURE_INSTRUCTIONS || (*it)->flags & S_ATTR_SOME_INSTRUCTIONS)
            {
                Section *s = new Section(
                    (char*)(*it)->sectname,
                    (*it)->offset,
                    (*it)->addr,
                    (*it)->size
                );

                if(s == NULL)
                    RAISE_EXCEPTION("Cannot allocate s");
                
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

        for(iter_rp_segment it = seg_commands.begin(); it != seg_commands.end(); ++it)
            (*it)->display(lvl);

        for(iter_rp_section it = sections.begin(); it != sections.end(); ++it)
            (*it)->display(lvl);
    }
};

#endif
