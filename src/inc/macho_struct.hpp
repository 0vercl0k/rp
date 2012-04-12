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
#define LC_SEGMENT_64 19

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
            display_hex_2fields_lf(vmaddr, vmsize);
            display_hex_2fields_lf(fileoff, filesize);
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
    unsigned char sectname[16];
    unsigned char segname[16];
    T             addr;
    T             size;
    unsigned int  offset;
    unsigned int  align;
    unsigned int  reloff;
    unsigned int  nreloc;
    unsigned int  flags;
    unsigned int  reserved1;
    unsigned int  reserved2;

    void display(VerbosityLevel lvl) const
    {
        w_yel_lf("-> section");
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

typedef RP_SECTION<x86Version> Section32;
typedef RP_SECTION<x64Version> Section64;

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
        std::streampos off = file.tellg();

        /* 1] Fill the header structure */
        file.seekg(0, std::ios::beg);
        file.read((char*)&header, sizeof(RP_MACH_HEADER<T>));

        /* 2] The load commands now */
        for(unsigned int i = 0; i < header.ncmds; ++i)
        {
            RP_LOAD_COMMAND loadcmd = {0};

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
            }
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
                    file,
                    (char*)(*it)->sectname,
                    (*it)->offset,
                    (*it)->size,
                    Section::Executable
                );

                if(s == NULL)
                    RAISE_EXCEPTION("Cannot allocate s");
                
                std::cout << (*it)->sectname << " is executable" << std::endl;
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
